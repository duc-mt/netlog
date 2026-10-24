// ==============================================================================
// Package triage: auto-triage engine (gate orchestration, SSH exec, incidents).
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         eng, _ := triage.New(cfg); eng.Handle(ctx, signal, device); eng.Close()
// Notes:         Go package implementation
// ==============================================================================
// Package triage reacts to anomaly signals by reconnecting to the affected
// device and capturing a small set of strictly read-only diagnostics before
// the evidence (neighbour tables, interface state) changes, then writing an
// IncidentReport under data/incidents/.
//
// Three gates are enforced in code, in this order, and none can be relaxed by
// configuration:
//
//	GATE 1  allowlist   every command passes Check (see allowlist.go), else the
//	                    whole triage is dropped.
//	GATE 2  cooldown    one triage per (device, event type) per cooldown period
//	                    (see cooldown.go); during cooldown no SSH session opens.
//	GATE 3  resource    SSH connect <= 5s, each command <= 5s, <= 50 KB of
//	        caps        output per command (truncated, not an error), <= 4
//	                    commands per run, <= 3 concurrent triage sessions.
//
// A gate failure aborts the triage silently (one log line, no retry).
package triage

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"netlog/internal/collector"
	"netlog/internal/credentials"
	"netlog/internal/inventory"
	"netlog/internal/pipeline"
	"netlog/internal/sshclient"
	"netlog/internal/store"
	"netlog/internal/vendor"
)

// GATE 3 limits. They are constants, not settings.
const (
	MaxConnectTimeout = 5 * time.Second
	MaxCommandTimeout = 5 * time.Second
	MaxOutputBytes    = 50 * 1024
	MaxCommands       = 4
	MaxConcurrent     = 3
)

// vyosWrapper is prepended (after GATE 1) to VyOS operational commands, which
// are not shell commands and only work through the op-mode wrapper when run
// over a non-interactive SSH exec channel. It is a constant of the binary.
const vyosWrapper = "/opt/vyatta/bin/vyatta-op-cmd-wrapper "

// Hook is the placeholder for external alerting (Telegram, webhook, ...).
// netlog ships no implementation; it is called after an incident file has
// been written.
type Hook interface {
	OnIncident(report collector.IncidentReport, path string)
}

type nopHook struct{}

func (nopHook) OnIncident(collector.IncidentReport, string) {}

// Config configures an Engine.
type Config struct {
	// DataDir is the netlog data directory; incidents go to <DataDir>/incidents.
	DataDir string

	// SSH carries the host-key callback and algorithm settings. Its timeouts
	// are clamped to the GATE 3 caps.
	SSH sshclient.Options

	// CredStore, JumpEnabled and JumpDefaultHost configure the connection,
	// exactly as for the collector.
	CredStore       *credentials.Store
	JumpEnabled     bool
	JumpDefaultHost string

	// Logger receives triage progress and suppression notices. Nil disables.
	Logger collector.Logger

	// Hook is called with each finished incident. Nil means no-op.
	Hook Hook

	// Now overrides the clock (tests). Nil means time.Now.
	Now func() time.Time
}

// Engine runs auto-triage. It is safe for concurrent use.
type Engine struct {
	cfg      Config
	log      collector.Logger
	hook     Hook
	now      func() time.Time
	dialer   *collector.Dialer
	cooldown *Cooldown
	sshOpts  sshclient.Options
	sem      chan struct{}
	wg       sync.WaitGroup
}

type nopLogger struct{}

func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}

func clamp(d, limit time.Duration) time.Duration {
	if d <= 0 || d > limit {
		return limit
	}
	return d
}

// New creates an Engine. A problem loading the persisted cooldown file is
// logged and does not fail construction.
func New(cfg Config) (*Engine, error) {
	if cfg.CredStore == nil {
		return nil, fmt.Errorf("triage: credential store is required")
	}
	if cfg.DataDir == "" {
		return nil, fmt.Errorf("triage: data directory is required")
	}
	var log collector.Logger = nopLogger{}
	if cfg.Logger != nil {
		log = cfg.Logger
	}
	var hook Hook = nopHook{}
	if cfg.Hook != nil {
		hook = cfg.Hook
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	opts := cfg.SSH
	opts.ConnectTimeout = clamp(opts.ConnectTimeout, MaxConnectTimeout)
	opts.CommandTimeout = clamp(opts.CommandTimeout, MaxCommandTimeout)

	cd, err := NewCooldown(store.CooldownPath(cfg.DataDir))
	if err != nil {
		log.Warn("triage: %v", err)
	}
	cd.now = now

	return &Engine{
		cfg:  cfg,
		log:  log,
		hook: hook,
		now:  now,
		dialer: collector.NewDialer(collector.DialerConfig{
			SSH:             opts,
			CredStore:       cfg.CredStore,
			JumpEnabled:     cfg.JumpEnabled,
			JumpDefaultHost: cfg.JumpDefaultHost,
		}),
		cooldown: cd,
		sshOpts:  opts,
		sem:      make(chan struct{}, MaxConcurrent),
	}, nil
}

// Handle processes one signal. GATE 1 and GATE 2 are evaluated before it
// returns, so a rejected or cooled-down signal never opens a connection; an
// accepted one continues asynchronously (GATE 3 applies there). Use Wait to
// block until in-flight triages finish.
func (e *Engine) Handle(ctx context.Context, sig pipeline.TriageSignal, dev inventory.Device) {
	host := dev.Hostname
	event := sig.Entry.Event

	key, ok := vendor.CanonicalKey(dev.Vendor)
	if !ok {
		key = "generic"
	}

	cmds := Commands(key, sig.Playbook, sig.Entry)
	if len(cmds) == 0 {
		e.log.Info("triage %s: %s skipped, no %q playbook for vendor %s", host, event, sig.Playbook, key)
		return
	}

	// GATE 1: allowlist. Any failure aborts the whole triage.
	for _, c := range cmds {
		if err := Check(c); err != nil {
			e.log.Warn("triage %s: %s aborted by allowlist gate: %v", host, event, err)
			return
		}
	}

	// GATE 2: cooldown. No SSH session is opened while cooling down.
	if allowed, remaining := e.cooldown.Allow(host, event); !allowed {
		e.log.Info("triage %s: %s suppressed, in cooldown for another %s", host, event, remaining.Round(time.Second))
		return
	}

	// GATE 3 (part): at most MaxCommands per run.
	if len(cmds) > MaxCommands {
		cmds = cmds[:MaxCommands]
	}

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.run(ctx, sig, dev, key, cmds)
	}()
}

// Wait blocks until every triage started by Handle has finished.
func (e *Engine) Wait() { e.wg.Wait() }

// Close waits for in-flight triages and releases bastion connections.
func (e *Engine) Close() {
	e.Wait()
	e.dialer.CloseJumps()
}

// run executes an accepted triage: connect, run the commands, write the report.
func (e *Engine) run(ctx context.Context, sig pipeline.TriageSignal, dev inventory.Device, vendorKey string, cmds []string) {
	// A triage runs on its own goroutine, where an unrecovered panic (a bug,
	// or a hook that misbehaves) would take the whole monitor down.
	defer func() {
		if r := recover(); r != nil {
			e.log.Error("triage %s: internal error: %v", dev.Hostname, r)
		}
	}()

	// GATE 3: concurrency. Waiting here does not hold a device connection.
	select {
	case e.sem <- struct{}{}:
		defer func() { <-e.sem }()
	case <-ctx.Done():
		return
	}

	started := e.now().UTC()
	report := collector.IncidentReport{
		ID:          collector.EntryID(dev.Hostname, sig.Playbook+started.Format(time.RFC3339Nano))[:8],
		Timestamp:   started,
		Hostname:    dev.Hostname,
		TriggerLog:  sig.Entry,
		Playbook:    sig.Playbook,
		Diagnostics: []collector.DiagCmd{},
	}

	client, err := e.dialer.Dial(ctx, dev)
	if err != nil {
		// The failure is itself evidence ("device unreachable at 10:22"), so
		// it is recorded in the incident rather than dropped.
		report.Diagnostics = append(report.Diagnostics, collector.DiagCmd{Command: "(connect)", Error: err.Error()})
	} else {
		defer client.Close()
		for _, cmd := range cmds {
			if ctx.Err() != nil {
				break
			}
			report.Diagnostics = append(report.Diagnostics, e.exec(ctx, client, vendorKey, cmd))
		}
	}
	report.TriageHints = buildHints(sig, report.Diagnostics)

	path, err := store.WriteIncident(store.IncidentsDir(e.cfg.DataDir), report)
	if err != nil {
		e.log.Error("triage %s: writing incident %s: %v", dev.Hostname, report.ID, err)
		return
	}
	e.log.Info("triage %s: %s captured %d diagnostic command(s) -> %s", dev.Hostname, sig.Entry.Event, len(report.Diagnostics), path)
	e.hook.OnIncident(report, path)
}

// exec runs one gated command and returns its DiagCmd. The command recorded
// in the report is the logical command that passed GATE 1; the form sent to
// the device may differ only by the fixed VyOS wrapper prefix and by moving a
// trailing "| head N" to the client, where it is applied to the output
// (several platforms, IOS among them, have no "head" filter).
func (e *Engine) exec(ctx context.Context, client *ssh.Client, vendorKey, logical string) collector.DiagCmd {
	base, head := splitHead(logical)
	wire := base
	if vendorKey == "vyos" {
		wire = vyosWrapper + base
	}

	start := time.Now()
	out, err := sshclient.RunCommand(ctx, client, wire, e.sshOpts)
	d := collector.DiagCmd{Command: logical, DurationMs: time.Since(start).Milliseconds()}
	if head > 0 {
		out = firstLines(out, head)
	}
	d.Output = truncateOutput(out, MaxOutputBytes)
	if err != nil {
		d.Error = err.Error()
	}
	return d
}

// splitHead separates a trailing "| head N" stage from a command.
func splitHead(cmd string) (base string, n int) {
	i := strings.LastIndex(cmd, "|")
	if i < 0 {
		return cmd, 0
	}
	stage := strings.Fields(cmd[i+1:])
	if len(stage) != 2 || stage[0] != "head" {
		return cmd, 0
	}
	var lines int
	if _, err := fmt.Sscanf(stage[1], "%d", &lines); err != nil || lines <= 0 {
		return cmd, 0
	}
	return strings.TrimSpace(cmd[:i]), lines
}

// firstLines returns at most n lines of s.
func firstLines(s string, n int) string {
	lines := strings.SplitAfter(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[:n], "")
}

// truncateOutput enforces the per-command output cap without erroring: it
// cuts at a rune boundary and appends a marker saying how much was dropped.
func truncateOutput(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + fmt.Sprintf("\n[output truncated: %d more bytes omitted]", len(s)-cut)
}

// buildHints turns the signal's annotations and a few well-known message
// patterns into reader-friendly triage hints. It never returns nil.
func buildHints(sig pipeline.TriageSignal, diags []collector.DiagCmd) []string {
	hints := []string{}
	hints = append(hints, sig.Annotations...)

	if sig.Entry.Category == collector.CategoryFault && len(sig.Annotations) == 0 {
		hints = append(hints, "No CONFIG_CHANGE was seen on this device in the 10 minutes before the event in the logs netlog collected; a physical-layer or remote-end cause is more likely than a local change.")
	}

	raw := strings.ToLower(sig.Entry.Raw)
	switch {
	case strings.Contains(raw, "dead timer") || strings.Contains(raw, "inactivitytimer") || strings.Contains(raw, "neighbor was inactive"):
		hints = append(hints, "OSPF dead timer expired: hellos stopped arriving, so check the link and the neighbor first. If an adjacency keeps failing to reach FULL, check for an MTU mismatch.")
	case strings.Contains(raw, "hold timer") || strings.Contains(raw, "hold time expired"):
		hints = append(hints, "BGP hold timer expired: keepalives stopped arriving; check the transport path and the peer's control-plane load.")
	case strings.Contains(raw, "peer closed the session") || strings.Contains(raw, "notification received"):
		hints = append(hints, "The BGP peer closed the session deliberately; check the remote router's logs for the reason.")
	}

	for _, d := range diags {
		if d.Command == "(connect)" {
			hints = append(hints, "netlog could not reconnect to the device to collect diagnostics ("+d.Error+"); the device may be unreachable.")
			break
		}
	}
	return hints
}
