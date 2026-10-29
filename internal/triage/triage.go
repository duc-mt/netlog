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
//	                    commands per run (the neighbour-table command of a
//	                    link-fault triage counts), <= 3 concurrent triage
//	                    sessions, <= 5 peer triages queued or running.
//
// A gate failure aborts the triage silently (one log line, no retry).
//
// Two features build on the gates without bypassing them:
//
//   - Topology-aware peer triage (topology.go): a link-fault triage also reads
//     the CDP/LLDP table and, when the remote end is in Config.Inventory,
//     starts one secondary triage there. The peer's commands pass GATE 1, its
//     (device, event) pair is subject to GATE 2 and it takes a GATE 3 slot. A
//     peer triage never starts another one.
//   - Config-diff capture (configdiff.go): the config_change playbook runs a
//     read-only comparison command and stores its output in the incident.
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

	// MaxPeerTriage bounds the peer triages that are queued or running at
	// once, so a network-wide link storm cannot pile up goroutines (and, once
	// they reach their turn, SSH sessions) on the neighbours of every failed
	// link. A peer that does not fit is skipped and noted in the incident.
	MaxPeerTriage = 5
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

	// Hook is called with each finished incident, except config_change
	// captures, which are evidence only. Nil means no-op.
	Hook Hook

	// Inventory enables topology-aware peer triage: a neighbour found in a
	// link-fault device's CDP/LLDP table is triaged too when it is listed
	// here. Nil or empty disables peer triage.
	Inventory []inventory.Device

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
	peerSem  chan struct{}
	wg       sync.WaitGroup
}

// job is one accepted triage, ready to run.
type job struct {
	sig       pipeline.TriageSignal
	dev       inventory.Device
	vendorKey string
	cmds      []string // playbook commands, each already through GATE 1
	topo      []string // neighbour-table commands (link faults only), through GATE 1

	// Set for a peer triage: the incident ID and start time were fixed when
	// the parent was written, so the parent can name the peer's incident.
	peer    bool
	id      string
	started time.Time
	origin  string // human-readable description of the parent, for the hints
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
		peerSem:  make(chan struct{}, MaxPeerTriage),
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
		// A config change on a platform without a comparison command is
		// routine and would otherwise log once per change.
		if !isConfigDiff(sig.Playbook) {
			e.log.Info("triage %s: %s skipped, no %q playbook for vendor %s", host, event, sig.Playbook, key)
		}
		return
	}

	// Link faults also read the neighbour table, when peers can be resolved.
	var topo []string
	if len(e.cfg.Inventory) > 0 && isLinkFault(sig.Playbook) {
		topo = TopologyCommands(key)
	}

	// GATE 1: allowlist. Any failure aborts the whole triage.
	for _, c := range append(append([]string{}, cmds...), topo...) {
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

	// GATE 3 (part): at most MaxCommands per run, the neighbour-table
	// command included.
	if len(topo) >= MaxCommands {
		topo = nil
	}
	if len(cmds) > MaxCommands-len(topo) {
		cmds = cmds[:MaxCommands-len(topo)]
	}

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.run(ctx, job{sig: sig, dev: dev, vendorKey: key, cmds: cmds, topo: topo})
	}()
}

// isLinkFault reports whether the playbook is one that benefits from looking
// at the other end of the link.
func isLinkFault(playbook string) bool {
	return playbook == pipeline.PlaybookLinkDown || playbook == pipeline.PlaybookLinkFlap
}

// Wait blocks until every triage started by Handle has finished.
func (e *Engine) Wait() { e.wg.Wait() }

// Close waits for in-flight triages and releases bastion connections.
func (e *Engine) Close() {
	e.Wait()
	e.dialer.CloseJumps()
}

// run executes an accepted triage: connect, run the commands, write the report.
func (e *Engine) run(ctx context.Context, j job) {
	dev, sig := j.dev, j.sig

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

	started, id := j.started, j.id
	if id == "" {
		started = e.now().UTC()
		id = incidentID(dev.Hostname, sig.Playbook, started)
	}
	report := collector.IncidentReport{
		ID:          id,
		Timestamp:   started,
		Hostname:    dev.Hostname,
		TriggerLog:  sig.Entry,
		Playbook:    sig.Playbook,
		Diagnostics: []collector.DiagCmd{},
	}

	var peerNote string
	client, err := e.dialer.Dial(ctx, dev)
	if err != nil {
		// The failure is itself evidence ("device unreachable at 10:22"), so
		// it is recorded in the incident rather than dropped.
		report.Diagnostics = append(report.Diagnostics, collector.DiagCmd{Command: "(connect)", Error: err.Error()})
	} else {
		defer client.Close()
		for _, cmd := range j.cmds {
			if ctx.Err() != nil {
				break
			}
			report.Diagnostics = append(report.Diagnostics, e.exec(ctx, client, j.vendorKey, cmd))
		}
		var topoOut []collector.DiagCmd
		for _, cmd := range j.topo {
			if ctx.Err() != nil {
				break
			}
			d := e.exec(ctx, client, j.vendorKey, cmd)
			report.Diagnostics = append(report.Diagnostics, d)
			topoOut = append(topoOut, d)
		}
		// A peer triage never starts another one: two devices that name each
		// other as neighbours would otherwise triage in a loop.
		if len(topoOut) > 0 && !j.peer {
			peerNote = e.spawnPeer(ctx, j, &report, topoOut)
		}
	}

	report.TriageHints = buildHints(sig, report.Diagnostics)
	if j.peer && j.origin != "" {
		report.TriageHints = append(report.TriageHints, j.origin)
	}
	if peerNote != "" {
		report.TriageHints = append(report.TriageHints, peerNote)
	}
	if isConfigDiff(sig.Playbook) {
		report.ConfigDiff = configDiffOf(report.Diagnostics)
		report.TriageHints = append(report.TriageHints, configDiffHint(report.ConfigDiff))
	}

	path, err := store.WriteIncident(store.IncidentsDir(e.cfg.DataDir), report)
	if err != nil {
		e.log.Error("triage %s: writing incident %s: %v", dev.Hostname, report.ID, err)
		return
	}
	e.log.Info("triage %s: %s captured %d diagnostic command(s) -> %s", dev.Hostname, sig.Entry.Event, len(report.Diagnostics), path)
	if !isConfigDiff(sig.Playbook) {
		e.hook.OnIncident(report, path)
	}
}

// incidentID derives the 8-character incident ID from device, playbook and
// start time (the same derivation as always; spawnPeer uses it to name a peer
// incident before that incident exists).
func incidentID(host, playbook string, started time.Time) string {
	return collector.EntryID(host, playbook+started.Format(time.RFC3339Nano))[:8]
}

// spawnPeer reads the neighbour on the faulted interface out of the topology
// command's output and, if it is an inventory device, starts a secondary
// triage there. It records the link in the parent report (PeerIncidentID,
// PeerDevice) and returns a one-line note for the parent's hints.
func (e *Engine) spawnPeer(ctx context.Context, j job, report *collector.IncidentReport, topoOut []collector.DiagCmd) string {
	iface := pipeline.ExtractInterface(j.sig.Entry.Raw)
	if iface == "" {
		return "Peer triage skipped: no interface could be read from the triggering log line."
	}
	var neighbors []Neighbor
	for _, d := range topoOut {
		neighbors = append(neighbors, ParseNeighbors(family(j.vendorKey), d.Output)...)
	}
	n, ok := FindNeighbor(neighbors, iface)
	if !ok {
		return fmt.Sprintf("Peer triage skipped: no CDP/LLDP neighbour is listed on %s (no neighbour, or the table was truncated).", iface)
	}
	peerDev, ok := FindPeer(e.cfg.Inventory, n, j.dev.Hostname)
	if !ok {
		return fmt.Sprintf("Peer triage skipped: neighbour %s (%s) is not in the inventory.", n.RemoteName, n.RemotePort)
	}

	pkey, known := vendor.CanonicalKey(peerDev.Vendor)
	if !known {
		pkey = "generic"
	}
	psig := j.sig
	psig.Entry.Hostname = peerDev.Hostname
	psig.Entry.IP = peerDev.Address
	psig.Entry.Object = n.RemotePort
	psig.Entry.Raw = fmt.Sprintf("peer-triggered: Interface %s, changed state to down (remote end of %s %s)", n.RemotePort, j.dev.Hostname, iface)
	psig.Annotations = []string{"Peer triage: this device is the remote end of the faulted link."}

	pcmds := Commands(pkey, psig.Playbook, psig.Entry)
	if len(pcmds) == 0 {
		return fmt.Sprintf("Peer triage skipped: no %q playbook for %s (%s).", psig.Playbook, peerDev.Hostname, pkey)
	}
	if len(pcmds) > MaxCommands {
		pcmds = pcmds[:MaxCommands]
	}
	// GATE 1 for the peer's commands. The interface name is an advertisement
	// from the neighbour, which is why it is checked like any other input.
	for _, c := range pcmds {
		if err := Check(c); err != nil {
			e.log.Warn("triage %s: peer triage of %s aborted by allowlist gate: %v", j.dev.Hostname, peerDev.Hostname, err)
			return fmt.Sprintf("Peer triage of %s skipped: a command failed the allowlist gate.", peerDev.Hostname)
		}
	}

	// The peer slot is taken before the cooldown so that a refusal here does
	// not use up the peer's cooldown period.
	select {
	case e.peerSem <- struct{}{}:
	default:
		e.log.Warn("triage %s: peer triage of %s skipped, %d peer triages already queued or running", j.dev.Hostname, peerDev.Hostname, MaxPeerTriage)
		return fmt.Sprintf("Peer triage of %s skipped: %d peer triages are already queued or running.", peerDev.Hostname, MaxPeerTriage)
	}
	event := psig.Entry.Event
	if allowed, remaining := e.cooldown.Allow(peerDev.Hostname, event); !allowed {
		<-e.peerSem
		e.log.Info("triage %s: peer triage of %s suppressed, in cooldown for another %s", j.dev.Hostname, peerDev.Hostname, remaining.Round(time.Second))
		return fmt.Sprintf("Peer triage of %s skipped: that device was triaged for %s within the cooldown period; see its own incident.", peerDev.Hostname, event)
	}

	started := e.now().UTC()
	pid := incidentID(peerDev.Hostname, psig.Playbook, started)
	report.PeerIncidentID = pid
	report.PeerDevice = peerDev.Hostname

	pj := job{
		sig: psig, dev: peerDev, vendorKey: pkey, cmds: pcmds,
		peer: true, id: pid, started: started,
		origin: fmt.Sprintf("Started by the link fault on %s %s (incident %s).", j.dev.Hostname, iface, report.ID),
	}
	e.wg.Add(1) // safe: the caller is itself counted in e.wg
	go func() {
		defer e.wg.Done()
		defer func() { <-e.peerSem }()
		e.run(ctx, pj)
	}()
	return fmt.Sprintf("Peer triage started on %s %s (incident %s).", peerDev.Hostname, n.RemotePort, pid)
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
