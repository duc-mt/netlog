// ==============================================================================
// Package main implements the netlog command: network log monitor and auto-triage.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         netlog collect|monitor|query|timeline|incidents|report|status [flags]
// Notes:         Go package implementation
// ==============================================================================
// netlog polls network devices over SSH, normalizes their log buffers into
// one structure, detects anomalies and, when something breaks, reconnects to
// capture strictly read-only diagnostics before the evidence is lost. It
// needs no configuration change on any device: the device list comes from
// inventory.csv and credentials from a .env file or NETLOG_* environment
// variables.
//
//	netlog collect   poll every device once, store, triage, exit (cron-friendly)
//	netlog monitor   the same on a loop, until SIGINT/SIGTERM
//	netlog query     search stored events
//	netlog timeline  cross-device chronology with causal annotation
//	netlog incidents list triage reports, or show one
//	netlog report    rankings, rollups and week-over-week trends
//	netlog status    per-device collection health (failing, stale, silent)
//
// The collect/monitor pipeline, per device and in this order: fetch the log
// buffer -> parse -> drop already-seen lines (watermark) -> correct for clock
// skew -> classify -> append to data/logs -> detect anomalies -> auto-triage.
// The watermark only advances after the entries are safely on disk.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"netlog/internal/collector"
	"netlog/internal/credentials"
	"netlog/internal/diagnose"
	"netlog/internal/inventory"
	"netlog/internal/notifier"
	"netlog/internal/parser"
	"netlog/internal/pipeline"
	"netlog/internal/query"
	"netlog/internal/report"
	"netlog/internal/sshclient"
	"netlog/internal/store"
	"netlog/internal/triage"
)

const version = "1.0.0"

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run dispatches a subcommand and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "init", "-init", "--init":
		return cmdInit(args[1:], stdout, stderr)
	case "collect":
		return cmdCollect(args[1:], stdout, stderr, false)
	case "monitor":
		return cmdCollect(args[1:], stdout, stderr, true)
	case "query":
		return cmdQuery(args[1:], stdout, stderr)
	case "timeline":
		return cmdTimeline(args[1:], stdout, stderr)
	case "incidents":
		return cmdIncidents(args[1:], stdout, stderr)
	case "report":
		return cmdReport(args[1:], stdout, stderr)
	case "status":
		return cmdStatus(args[1:], stdout, stderr)
	case "telegram-test":
		return cmdTelegramTest(args[1:], stdout, stderr)
	case "diagnose":
		return cmdDiagnose(args[1:], stdout, stderr)
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, "netlog", version)
		return exitOK
	case "help", "-h", "-help", "--help":
		printUsage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "netlog: unknown command %q\n\n", args[0])
		printUsage(stderr)
		return exitUsage
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `netlog - network log monitor and auto-triage (reads device logs over SSH; changes nothing)

Usage:
  netlog init      [flags]   initialize sample inventory.csv and .env templates
  netlog collect   [flags]   poll all devices once, store logs, triage, exit
  netlog monitor   [flags]   poll on an interval until SIGINT/SIGTERM
  netlog query     [flags]   search stored events
  netlog timeline  [flags]   cross-device chronological view
  netlog incidents [flags]   list auto-triage reports, or show one with --id
  netlog report    [flags]   rankings and trends: noisy devices, changes, watchlist
  netlog status    [flags]   per-device collection health: failing, stale, silent
  netlog diagnose  <device> [flags]  one-shot health check: SSH, alarms, BGP/OSPF, CRC errors, optical DDM
  netlog telegram-test [flags] send a test notification to verified Telegram configuration
  netlog version

Run "netlog <command> -h" for a command's flags.

Examples:
  netlog collect --dry-run                                        test connectivity and clock skew
  netlog collect --inventory inventory.csv --env-file .env --data-dir data
  netlog monitor --interval 2m --data-dir data
  netlog diagnose core-gw-1 --raw                                 quick triage of one device
  netlog query --category CONFIG --since 24h
  netlog query --severity CRITICAL --since today --format json
  netlog timeline --from "2026-10-20 10:10:00" --to "2026-10-20 10:25:00"
  netlog incidents --since 24h
  netlog incidents --id a1b2c3d4
  netlog report                                                   last 7 days, with week-over-week delta
  netlog report --since 24h --top 5 --format json
  netlog status                                                   which devices could not be polled, and since when
  netlog status --stale-after 1h --fail                           exit 1 if any device needs attention (for cron / monitoring)

Timestamps that devices print without a time zone are read in this host's
local zone (set TZ to change it); any zone difference is absorbed by the
per-poll clock-skew measurement.
`)
}

// ==============================================================================
// Logging
// ==============================================================================

// stderrLogger writes timestamped lines to stderr, which is where cron and
// systemd expect a tool's diagnostics ("netlog collect >> netlog.log 2>&1").
// It deliberately does not use internal/logging: that package creates one
// backup_run_*.log file per process, which would mean one file per cron run
// here, and its summary code is tied to backup results.
type stderrLogger struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *stderrLogger) emit(level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s %-5s %s\n", time.Now().Format(time.RFC3339), level, cleanLog(fmt.Sprintf(format, args...)))
}

// cleanLog neutralises control characters in a log message. Messages embed
// text taken from device logs, which is untrusted: a crafted line must not be
// able to forge extra log lines (CR/LF) or drive the terminal (ESC).
func cleanLog(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return '?'
		}
		return r
	}, s)
}

func (l *stderrLogger) Info(format string, args ...any)  { l.emit("INFO", format, args...) }
func (l *stderrLogger) Warn(format string, args ...any)  { l.emit("WARN", format, args...) }
func (l *stderrLogger) Error(format string, args ...any) { l.emit("ERROR", format, args...) }

// colorEnabled reports whether w is an interactive terminal that should get
// ANSI colour.
func colorEnabled(w io.Writer, noColor bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// ==============================================================================
// collect / monitor
// ==============================================================================

type collectOpts struct {
	inventory      string
	envFile        string
	dataDir        string
	concurrency    int
	connectTimeout time.Duration
	commandTimeout time.Duration
	knownHosts     string
	interval       time.Duration

	// SSH and bastion settings: older network gear needs legacy algorithms,
	// and some devices are only reachable through a jump host.
	knownHostsPolicy      string
	insecureIgnoreHostKey bool
	legacyAlgorithms      bool
	jumpEnabled           bool
	jumpHost              string
	retentionDays         int
	afterHoursStart       int
	afterHoursEnd         int
	dryRun                bool
	noColor               bool
}

func envInt(key string, def int) int {
	if s := os.Getenv(key); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 0 && v <= 23 {
			return v
		}
	}
	return def
}

func (o *collectOpts) register(fs *flag.FlagSet, monitor bool) {
	fs.StringVar(&o.inventory, "inventory", "inventory.csv", "path to the device inventory CSV")
	fs.StringVar(&o.envFile, "env-file", ".env", "path to an optional .env file with NETLOG_USERNAME / NETLOG_PASSWORD")
	fs.StringVar(&o.dataDir, "data-dir", "data", "base directory for logs/, incidents/ and state files")
	fs.IntVar(&o.concurrency, "concurrency", 10, "number of devices polled in parallel")
	fs.DurationVar(&o.connectTimeout, "connect-timeout", 5*time.Second, "SSH dial timeout")
	fs.DurationVar(&o.commandTimeout, "command-timeout", 5*time.Second, "SSH command timeout")
	fs.StringVar(&o.knownHosts, "known-hosts", "known_hosts", "path to the known_hosts file (\"\" = the user's ~/.ssh/known_hosts)")
	fs.StringVar(&o.knownHostsPolicy, "known-hosts-policy", "accept-new", "host key policy: strict (reject unknown/changed), accept-new (learn new, reject changed) or update (learn new, replace changed)")
	fs.BoolVar(&o.insecureIgnoreHostKey, "insecure-ignore-host-key", false, "DANGEROUS: skip host key verification entirely")
	fs.BoolVar(&o.legacyAlgorithms, "legacy-algorithms", true, "allow legacy SSH algorithms as a fallback for older network gear")
	fs.BoolVar(&o.jumpEnabled, "jump", true, "enable jump host / bastion routing (false = connect everything directly)")
	fs.StringVar(&o.jumpHost, "jump-host", "", "global default bastion host[:port]")
	fs.IntVar(&o.retentionDays, "retention-days", 0, "delete daily log files older than this many days (0 = keep everything)")
	fs.IntVar(&o.afterHoursStart, "after-hours-start", envInt("NETLOG_AFTER_HOURS_START", pipeline.DefaultAfterHoursStart), "first hour (0-23) of after-hours change window")
	fs.IntVar(&o.afterHoursEnd, "after-hours-end", envInt("NETLOG_AFTER_HOURS_END", pipeline.DefaultAfterHoursEnd), "first hour (0-23) after which changes are no longer after-hours")
	fs.BoolVar(&o.noColor, "no-color", false, "disable coloured output")
	if !monitor {
		fs.BoolVar(&o.dryRun, "dry-run", false, "test connectivity, authentication and clock skew without saving logs or running triage")
	}
	if monitor {
		fs.DurationVar(&o.interval, "interval", collector.DefaultInterval, "polling interval; devices start staggered across the first part of it")
	}
}

func (o *collectOpts) validate(monitor bool) error {
	switch {
	case monitor && o.dryRun:
		return errors.New("--dry-run is not supported with monitor")
	case o.concurrency < 1:
		return errors.New("--concurrency must be at least 1")
	case o.connectTimeout <= 0 || o.commandTimeout <= 0:
		return errors.New("--connect-timeout and --command-timeout must be positive")
	case o.dataDir == "":
		return errors.New("--data-dir must not be empty")
	case o.retentionDays < 0:
		return errors.New("--retention-days must not be negative")
	case o.afterHoursStart < 0 || o.afterHoursStart > 23 || o.afterHoursEnd < 0 || o.afterHoursEnd > 23:
		return errors.New("--after-hours-start and --after-hours-end must be between 0 and 23")
	case monitor && o.interval < 10*time.Second:
		return errors.New("--interval must be at least 10s")
	}
	return nil
}

func cmdCollect(args []string, stdout, stderr io.Writer, monitor bool) int {
	name := "collect"
	if monitor {
		name = "monitor"
	}
	fs := flag.NewFlagSet("netlog "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o collectOpts
	o.register(fs, monitor)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "netlog %s: unexpected argument %q\n", name, fs.Arg(0))
		return exitUsage
	}
	if err := o.validate(monitor); err != nil {
		fmt.Fprintf(stderr, "netlog %s: %v\n", name, err)
		return exitUsage
	}

	log := &stderrLogger{w: stderr}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if o.dryRun {
		return runDryRun(ctx, o, log, stdout, stderr)
	}

	a, err := newApp(o, log)
	if err != nil {
		log.Error("%v", err)
		if _, statErr := os.Stat(o.inventory); os.IsNotExist(statErr) || strings.Contains(err.Error(), "no such file") {
			fmt.Fprintf(stderr, "\nTip: Run 'netlog init' (or './run init') to create sample inventory.csv and .env templates.\n\n")
		}
		return exitError
	}
	defer a.close()

	if !monitor {
		st := a.cycle(ctx)
		a.engine.Wait()
		if ctx.Err() != nil {
			log.Warn("interrupted before the cycle finished")
			return exitError
		}
		// Individual device failures are normal and exit 0, but a cycle in
		// which not one device could be polled (wrong credentials, network
		// down, empty vendor support) must not look like success to cron.
		if st.polled == 0 {
			log.Error("no device could be polled")
			return exitError
		}
		return exitOK
	}

	log.Info("netlog monitor started: %d device(s), interval %s", len(a.devices), o.interval)
	for ctx.Err() == nil {
		began := time.Now()
		_ = a.cycle(ctx)

		wait := o.interval - time.Since(began)
		if wait < 0 {
			log.Warn("cycle took %s, longer than the %s interval; starting the next one immediately (lower --concurrency pressure or raise --interval)",
				time.Since(began).Round(time.Second), o.interval)
			wait = 0
		}
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
	log.Info("shutting down: waiting for in-flight triage")
	return exitOK
}

// app holds everything a collect/monitor run needs.
type app struct {
	opts    collectOpts
	log     *stderrLogger
	devices []inventory.Device

	collector  *collector.Collector
	marks      *pipeline.Watermarks
	health     *store.Health // per-device poll health, for "netlog status" and the report
	classifier *pipeline.Classifier
	detector   *pipeline.Detector
	writer     *store.JSONLWriter
	engine     *triage.Engine
	telegram   *notifier.TelegramNotifier

	loc *time.Location

	warnedMu sync.Mutex
	warnedAt map[string]time.Time

	// failing remembers each device's last poll error so a persistent
	// failure is logged once, and its recovery once, instead of every cycle.
	// Only the single result-processing goroutine touches it.
	failing map[string]string

	unlock func() // releases the data-directory lock
}

func newApp(o collectOpts, log *stderrLogger) (*app, error) {
	devices, warns := inventory.Load(o.inventory)
	for _, w := range warns {
		if len(devices) == 0 {
			return nil, w
		}
		log.Warn("inventory: %v", w)
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("inventory %q contains no devices (tip: run 'netlog init' to create sample inventory.csv and .env templates)", o.inventory)
	}
	seen := make(map[string]bool, len(devices))
	for _, d := range devices {
		if seen[d.Hostname] {
			log.Warn("inventory: hostname %q appears more than once; watermarks and cooldowns are keyed by hostname, so use unique names", d.Hostname)
		}
		seen[d.Hostname] = true
	}

	if o.jumpHost != "" {
		os.Setenv(credentials.EnvJumpHost, o.jumpHost)
	}
	creds, err := credentials.NewStore(o.envFile)
	if err != nil {
		return nil, fmt.Errorf("loading credentials: %w", err)
	}

	hostKeys, err := hostKeyCallback(o, log)
	if err != nil {
		return nil, err
	}
	sshOpts := sshclient.Options{
		ConnectTimeout:   o.connectTimeout,
		CommandTimeout:   o.commandTimeout,
		HostKeyCallback:  hostKeys,
		LegacyAlgorithms: o.legacyAlgorithms,
	}

	if err := os.MkdirAll(o.dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating data directory: %w", err)
	}
	// One collector per data directory: each run keeps its watermarks in
	// memory and rewrites the state file, so two overlapping runs (a slow
	// cron job still going when the next starts) would overwrite each other's
	// progress and store duplicates.
	release, err := lockDataDir(o.dataDir)
	if err != nil {
		return nil, err
	}
	state, err := store.LoadState(store.StatePath(o.dataDir))
	if err != nil {
		release()
		return nil, err
	}
	writer, err := store.NewJSONLWriter(o.dataDir)
	if err != nil {
		release()
		return nil, err
	}
	// Health is diagnostics only: a bad file is reported and replaced, and
	// never stops collection.
	health, err := store.LoadHealth(store.HealthPath(o.dataDir))
	if err != nil {
		log.Warn("%v", err)
	}

	interval := o.interval
	if interval <= 0 {
		interval = collector.DefaultInterval
	}
	coll := collector.New(collector.Config{
		Concurrency:     o.concurrency,
		Interval:        interval,
		SSH:             sshOpts,
		CredStore:       creds,
		JumpEnabled:     o.jumpEnabled,
		JumpDefaultHost: o.jumpHost,
		ClockParser:     pipeline.ParseDeviceClock,
		Logger:          log,
	})

	tg := notifier.NewTelegram(notifier.ConfigFromStore(creds), log)
	if tg != nil {
		log.Info("telegram alerts enabled (chat_id: %s)", creds.Get("TELEGRAM_CHAT_ID"))
	}

	engine, err := triage.New(triage.Config{
		DataDir:         o.dataDir,
		SSH:             sshOpts,
		CredStore:       creds,
		JumpEnabled:     o.jumpEnabled,
		JumpDefaultHost: o.jumpHost,
		Logger:          log,
		Hook:            tg,
	})
	if err != nil {
		if tg != nil {
			tg.Close()
		}
		_ = writer.Close()
		release()
		return nil, err
	}

	// Seed the anomaly windows from the last few minutes of stored events, so
	// a cron-driven "collect" (a new process every run) still sees flaps,
	// login bursts and config changes that straddle two runs.
	det := pipeline.NewDetector(pipeline.DetectorConfig{})
	if recent, err := query.LoadTail(o.dataDir, query.Filter{Since: time.Now().Add(-primeWindow)}, primeTailBytes); err != nil {
		log.Warn("priming anomaly detector from stored logs: %v", err)
	} else {
		det.Prime(recent)
	}

	return &app{
		opts:      o,
		log:       log,
		devices:   devices,
		collector: coll,
		marks:     pipeline.NewWatermarks(state),
		health:    health,
		classifier: pipeline.NewClassifierWithOptions(pipeline.ClassifierOptions{
			Location:        time.Local,
			AfterHoursStart: o.afterHoursStart,
			AfterHoursEnd:   o.afterHoursEnd,
		}),
		detector: det,
		writer:   writer,
		engine:   engine,
		telegram: tg,
		loc:      time.Local,
		warnedAt: make(map[string]time.Time),
		failing:  make(map[string]string),
		unlock:   release,
	}, nil
}

// How much stored history seeds the detector at startup: the longest window
// any rule uses is the 10-minute config correlation, plus margin.
const (
	primeWindow    = 15 * time.Minute
	primeTailBytes = 16 << 20 // read at most the last 16 MiB of each daily file
)

// hostKeyCallback builds the SSH host key verifier from the flags.
func hostKeyCallback(o collectOpts, log *stderrLogger) (ssh.HostKeyCallback, error) {
	if o.insecureIgnoreHostKey {
		log.Warn("host key verification disabled via --insecure-ignore-host-key; connections are vulnerable to MITM")
		return ssh.InsecureIgnoreHostKey(), nil //nolint:gosec // explicit opt-in via CLI flag
	}
	path := o.knownHosts
	if path == "" {
		path = sshclient.DefaultKnownHostsFile()
	}
	cb, err := sshclient.KnownHostsCallback(path, sshclient.KnownHostsPolicy(o.knownHostsPolicy))
	if err != nil {
		return nil, fmt.Errorf("loading known_hosts %q: %w", path, err)
	}
	return cb, nil
}

func (a *app) close() {
	if a.telegram != nil {
		a.telegram.Close()
	}
	a.engine.Close()
	if err := a.marks.Save(); err != nil {
		a.log.Warn("saving watermarks: %v", err)
	}
	_ = a.writer.Close()
	a.unlock()
}

// errAlreadyRunning is returned when another netlog already holds the data
// directory's lock.
var errAlreadyRunning = errors.New("another netlog collect/monitor is already running on this data directory")

// warnEvery logs a warning for key at most once per `every` (once per run if
// every is zero), so a condition that persists across polls (unparseable
// log format, repeated gaps) does not repeat on every cycle.
func (a *app) warnEvery(key string, every time.Duration, format string, args ...any) {
	a.warnedMu.Lock()
	last, seen := a.warnedAt[key]
	due := !seen || (every > 0 && time.Since(last) >= every)
	if due {
		a.warnedAt[key] = time.Now()
	}
	a.warnedMu.Unlock()
	if due {
		a.log.Warn(format, args...)
	}
}

// maxPlausibleSkew is the largest clock error that is still believable as a
// real clock error plus a time-zone difference (zones span at most 14 hours).
// A measured skew beyond it points at a mis-set device clock or a clock
// reading that was misparsed.
const maxPlausibleSkew = 24 * time.Hour

type cycleStats struct {
	polled, failed, entries, signals int
}

// cycle polls every device once and runs each result through the pipeline.
func (a *app) cycle(ctx context.Context) cycleStats {
	began := time.Now()
	if a.opts.retentionDays > 0 {
		if n, err := store.Prune(a.opts.dataDir, a.opts.retentionDays, began); err != nil {
			a.log.Warn("retention: %v", err)
		} else if n > 0 {
			a.log.Info("retention: removed %d log file(s) older than %d days", n, a.opts.retentionDays)
		}
	}

	var st cycleStats
	for res := range a.collector.Run(ctx, a.devices) {
		a.safeProcess(ctx, res, &st)
	}
	if err := a.marks.Save(); err != nil {
		a.log.Warn("saving watermarks: %v", err)
	}
	if err := a.health.Save(); err != nil {
		a.log.Warn("saving collection health: %v", err)
	}
	a.log.Info("cycle complete: %d/%d device(s) polled (%d failed), %d new log entr%s, %d triage signal(s), %s",
		st.polled, len(a.devices), st.failed, st.entries, plural(st.entries, "y", "ies"), st.signals,
		time.Since(began).Round(100*time.Millisecond))
	return st
}

// safeProcess isolates one device's result: a bug triggered by one odd log
// buffer must cost that device's poll, not the whole monitor.
func (a *app) safeProcess(ctx context.Context, r collector.Result, st *cycleStats) {
	defer func() {
		if p := recover(); p != nil {
			st.failed++
			a.health.Failed(r.Device.Hostname, time.Now(), fmt.Sprintf("internal error: %v", p), false)
			a.log.Error("%s: internal error while processing the poll result: %v", r.Device.Hostname, p)
		}
	}()
	a.process(ctx, r, st)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// process runs one device's poll result through the pipeline. Results arrive
// one at a time on a single goroutine, so the pipeline stages need no locking.
func (a *app) process(ctx context.Context, r collector.Result, st *cycleStats) {
	host := r.Device.Hostname

	if r.Err != nil {
		st.failed++
		a.health.Failed(host, time.Now(), r.Err.Error(), errors.Is(r.Err, collector.ErrUnsupportedVendor))
		// Log a failure when it first appears or changes, not every cycle.
		if msg := r.Err.Error(); a.failing[host] != msg {
			a.failing[host] = msg
			if errors.Is(r.Err, collector.ErrUnsupportedVendor) {
				a.log.Warn("%s: %v (device skipped)", host, r.Err)
			} else {
				a.log.Warn("%s: poll failed: %v", host, r.Err)
				if a.telegram != nil {
					a.telegram.SendDeviceHealth(host, false, msg)
				}
			}
		}
		return
	}
	st.polled++
	a.health.Succeeded(host, time.Now())
	if _, was := a.failing[host]; was {
		delete(a.failing, host)
		a.log.Info("%s: poll recovered", host)
		if a.telegram != nil {
			a.telegram.SendDeviceHealth(host, true, "")
		}
	}

	// Stage 2 (parse). Stage 1 (watermark) needs entries to compare, so
	// parsing comes first; the watermark then discards everything seen before.
	parsed := parser.Parse(r.VendorKey, r.Raw, r.Device, parser.Options{Ref: r.FetchedAt, Location: a.loc})
	if len(parsed) == 0 {
		if n := nonEmptyLines(r.Raw); n >= 5 {
			a.health.SetUnparseable(host, time.Now(), true)
			a.warnEvery("noparse:"+host, 0, "%s: %d lines of log output but none could be parsed as %s; check the device's log timestamp format (Cisco/Ruijie need 'service timestamps log datetime')", host, n, r.VendorKey)
		}
		return
	}
	a.health.SetUnparseable(host, time.Now(), false)

	// A line cannot be dated after "now" on the device. Such lines come from
	// a clock that was stepped forward and back; keeping them would drag the
	// watermark into the future and hide every genuine later line. The
	// device's "now" is the fetch time plus the measured skew (zero if the
	// skew is unknown, which widens the tolerance accordingly).
	deviceNow := r.FetchedAt
	if r.SkewOK {
		deviceNow = deviceNow.Add(time.Duration(r.SkewMs) * time.Millisecond)
	}
	var dropped int
	if parsed, dropped = pipeline.DropFuture(parsed, deviceNow, pipeline.FutureTolerance(r.VendorKey, r.SkewOK)); dropped > 0 {
		a.warnEvery("future:"+host, time.Hour, "%s: ignored %d log line(s) dated in the future (device clock stepped?)", host, dropped)
	}
	if r.SkewOK && (time.Duration(r.SkewMs)*time.Millisecond > maxPlausibleSkew || time.Duration(r.SkewMs)*time.Millisecond < -maxPlausibleSkew) {
		a.warnEvery("skew:"+host, 0, "%s: device clock differs from this host by %s, more than any time-zone difference explains; its timestamps are being corrected by that amount, so check the device's clock and timezone settings", host, (time.Duration(r.SkewMs) * time.Millisecond).Round(time.Minute))
	}

	if a.marks.PossibleGap(host, parsed) {
		a.warnEvery("gap:"+host, time.Hour, "%s: every line in the fetched log buffer is newer than the last poll, so events in between were probably missed; the device logs faster than it is polled for its buffer size (poll more often or enlarge the device's log buffer)", host)
	}

	fresh := a.marks.Filter(host, parsed)
	if len(fresh) == 0 {
		return
	}
	pipeline.Normalize(fresh, r.SkewMs, r.SkewOK)
	a.classifier.ClassifyAll(fresh)

	// Advance the watermark over the full batch (including own-session lines)
	// before suppressing them.  This ensures suppressed entries are never
	// re-presented on the next poll, while also never hitting disk.
	a.marks.Advance(host, fresh)
	if err := a.marks.Save(); err != nil {
		a.log.Warn("%s: saving watermark: %v", host, err)
	}

	// Drop PAM / systemd session-tracking lines generated by our own SSH
	// polling sessions; they carry no diagnostic value.
	fresh = pipeline.SuppressOwn(fresh)
	if len(fresh) == 0 {
		return
	}

	// Store entries; a failed write leaves the watermark already advanced, so
	// the batch is lost rather than retried.  Acceptable: these lines would
	// reappear on the next poll only if the device still has them in its
	// buffer, which is the normal retry path for transient write errors.
	if err := a.writer.Append(fresh); err != nil {
		a.log.Error("%s: storing %d entries: %v", host, len(fresh), err)
		return
	}
	st.entries += len(fresh)
	a.health.NewLogs(host, time.Now())

	// Stage 4: anomaly detection runs after the commit, so a retried batch
	// cannot double-count toward a flap or brute-force threshold.
	var signals []pipeline.TriageSignal
	for _, e := range fresh {
		signals = append(signals, a.detector.Observe(e)...)
	}
	var derived []collector.LogEntry
	for _, s := range signals {
		if s.Derived {
			derived = append(derived, s.Entry)
		}
	}
	if err := a.writer.Append(derived); err != nil {
		a.log.Warn("%s: storing derived events: %v", host, err)
	}

	for _, s := range signals {
		st.signals++
		a.log.Info("%s: %s detected (%s): %s", host, s.Entry.Event, s.Playbook, s.Entry.Summary)
		a.engine.Handle(ctx, s, r.Device)
	}
}

func nonEmptyLines(s string) int {
	n := 0
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}

// ==============================================================================
// query
// ==============================================================================

var (
	validCategories = []string{"CONFIG", "AUTH", "FAULT", "SECURITY", "SYSTEM"}
	validSeverities = []string{"INFO", "WARNING", "ERROR", "CRITICAL"}
)

func oneOf(v string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(v, a) {
			return true
		}
	}
	return false
}

func cmdQuery(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("netlog query", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		host     = fs.String("host", "", "filter by hostname (substring)")
		user     = fs.String("user", "", "filter by user")
		category = fs.String("category", "", "CONFIG | AUTH | FAULT | SECURITY | SYSTEM")
		severity = fs.String("severity", "", "INFO | WARNING | ERROR | CRITICAL")
		event    = fs.String("event", "", "filter by event type (substring)")
		since    = fs.String("since", "24h", "time window: 30m, 2h, 24h, 7d, or today")
		format   = fs.String("format", "table", "output format: table | json")
		dataDir  = fs.String("data-dir", "data", "netlog data directory")
		noColor  = fs.Bool("no-color", false, "disable coloured output")
	)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *category != "" && !oneOf(*category, validCategories) {
		fmt.Fprintf(stderr, "netlog query: --category must be one of %s\n", strings.Join(validCategories, ", "))
		return exitUsage
	}
	if *severity != "" && !oneOf(*severity, validSeverities) {
		fmt.Fprintf(stderr, "netlog query: --severity must be one of %s\n", strings.Join(validSeverities, ", "))
		return exitUsage
	}
	if *format != "table" && *format != "json" {
		fmt.Fprintf(stderr, "netlog query: --format must be table or json\n")
		return exitUsage
	}
	from, err := query.ParseSince(*since, time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "netlog query: %v\n", err)
		return exitUsage
	}

	entries, err := query.Load(*dataDir, query.Filter{
		Host: *host, User: *user, Category: *category, Severity: *severity, Event: *event,
		Since: from, Until: time.Now(),
	})
	if err != nil {
		fmt.Fprintf(stderr, "netlog query: %v\n", err)
		return exitError
	}
	query.SortNewestFirst(entries)

	if *format == "json" {
		err = query.WriteJSON(stdout, entries)
	} else {
		err = query.WriteTable(stdout, entries, query.Style{Color: colorEnabled(stdout, *noColor)})
	}
	if err != nil {
		fmt.Fprintf(stderr, "netlog query: %v\n", err)
		return exitError
	}
	return exitOK
}

// ==============================================================================
// timeline
// ==============================================================================

func cmdTimeline(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("netlog timeline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		fromS   = fs.String("from", "", `window start: "2006-01-02 15:04:05" (local) or RFC 3339 (default: one hour ago)`)
		toS     = fs.String("to", "", "window end, same formats (default: now)")
		dataDir = fs.String("data-dir", "data", "netlog data directory")
		all     = fs.Bool("all", false, "include unclassified (UNKNOWN) events")
		noColor = fs.Bool("no-color", false, "disable coloured output")
	)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}

	now := time.Now()
	from, to := now.Add(-time.Hour), now
	var err error
	if *fromS != "" {
		if from, err = query.ParseTime(*fromS, time.Local); err != nil {
			fmt.Fprintf(stderr, "netlog timeline: --from: %v\n", err)
			return exitUsage
		}
	}
	if *toS != "" {
		if to, err = query.ParseTime(*toS, time.Local); err != nil {
			fmt.Fprintf(stderr, "netlog timeline: --to: %v\n", err)
			return exitUsage
		}
	}
	if to.Before(from) {
		fmt.Fprintln(stderr, "netlog timeline: --to is before --from")
		return exitUsage
	}

	// Load a correlation window of history before --from so a fault at the
	// very start of the window can still be tied to the change that preceded it.
	entries, err := query.Load(*dataDir, query.Filter{Since: from.Add(-query.CorrelationWindow), Until: to})
	if err != nil {
		fmt.Fprintf(stderr, "netlog timeline: %v\n", err)
		return exitError
	}
	rows := query.BuildTimeline(entries, query.TimelineOptions{From: from, IncludeUnknown: *all})
	if err := query.WriteTimeline(stdout, rows, query.Style{Color: colorEnabled(stdout, *noColor)}); err != nil {
		fmt.Fprintf(stderr, "netlog timeline: %v\n", err)
		return exitError
	}
	return exitOK
}

// ==============================================================================
// incidents
// ==============================================================================

func cmdIncidents(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("netlog incidents", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		since   = fs.String("since", "24h", "list incidents from this window: 30m, 2h, 24h, 7d, or today")
		id      = fs.String("id", "", "show one full incident report by ID prefix")
		format  = fs.String("format", "text", "output format when viewing by --id: text or json")
		dataDir = fs.String("data-dir", "data", "netlog data directory")
		noColor = fs.Bool("no-color", false, "disable coloured output")
	)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "netlog incidents: --format must be text or json\n")
		return exitUsage
	}
	dir := store.IncidentsDir(*dataDir)

	if *id != "" {
		report, err := store.FindIncident(dir, *id)
		if err != nil {
			fmt.Fprintf(stderr, "netlog incidents: %v\n", err)
			return exitError
		}
		if *format == "json" {
			err = query.WriteIncidentJSON(stdout, report)
		} else {
			err = query.WriteIncidentDetail(stdout, report, query.Style{Color: colorEnabled(stdout, *noColor)})
		}
		if err != nil {
			fmt.Fprintf(stderr, "netlog incidents: %v\n", err)
			return exitError
		}
		return exitOK
	}

	from, err := query.ParseSince(*since, time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "netlog incidents: %v\n", err)
		return exitUsage
	}
	reports, err := store.ListIncidents(dir, from)
	if err != nil {
		fmt.Fprintf(stderr, "netlog incidents: %v\n", err)
		return exitError
	}
	if err := query.WriteIncidentList(stdout, reports, query.Style{Color: colorEnabled(stdout, *noColor)}); err != nil {
		fmt.Fprintf(stderr, "netlog incidents: %v\n", err)
		return exitError
	}
	return exitOK
}

// ==============================================================================
// report
// ==============================================================================

func cmdReport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("netlog report", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		since   = fs.String("since", "7d", "time window: 30m, 2h, 24h, 7d, or today")
		top     = fs.Int("top", report.DefaultTop, "rows shown in the noisy-device and watchlist rankings")
		compare = fs.Bool("compare", false, "force the week-over-week delta on or off (default: on only when --since is exactly 7d)")
		format  = fs.String("format", "table", "output format: table | json")
		dataDir = fs.String("data-dir", "data", "netlog data directory")
		noColor = fs.Bool("no-color", false, "disable coloured output")
	)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *format != "table" && *format != "json" {
		fmt.Fprintf(stderr, "netlog report: --format must be table or json\n")
		return exitUsage
	}
	if *top < 1 {
		fmt.Fprintf(stderr, "netlog report: --top must be at least 1\n")
		return exitUsage
	}
	now := time.Now()
	from, err := query.ParseSince(*since, now)
	if err != nil {
		fmt.Fprintf(stderr, "netlog report: %v\n", err)
		return exitUsage
	}

	// The delta compares the window with the equal-length one before it. It
	// defaults to on for exactly one week; an explicit --compare either way wins.
	window := now.Sub(from)
	doCompare := window == report.Week
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "compare" {
			doCompare = *compare
		}
	})
	if window <= 0 {
		doCompare = false
	}

	// Load back to the start of the previous window when it is needed.
	loadFrom := from
	if doCompare {
		loadFrom = from.Add(-window)
	}
	// Collection health is what netlog last saw of each device, not a
	// property of the window. A bad health file is worth a warning only.
	health, err := store.LoadHealth(store.HealthPath(*dataDir))
	if err != nil {
		fmt.Fprintf(stderr, "netlog report: warning: %v\n", err)
	}

	// Stream the logs into the report: memory stays proportional to the
	// number of devices and sources, not to the volume of history.
	b := report.NewBuilder(report.Options{
		Since: from, Until: now, Top: *top, Compare: doCompare,
		Label:   strings.ToLower(strings.TrimSpace(*since)),
		Devices: report.DeviceStatuses(health.All(), nil, now, store.DefaultStaleAfter, store.DefaultSilentAfter),
	})
	if err := query.Scan(*dataDir, query.Filter{Since: loadFrom, Until: now}, b.AddEntry); err != nil {
		fmt.Fprintf(stderr, "netlog report: %v\n", err)
		return exitError
	}
	incidents, err := store.ListIncidents(store.IncidentsDir(*dataDir), from)
	if err != nil {
		fmt.Fprintf(stderr, "netlog report: %v\n", err)
		return exitError
	}
	for _, inc := range incidents {
		b.AddIncident(inc)
	}
	rep := b.Build()
	if *format == "json" {
		err = report.WriteJSON(stdout, rep)
	} else {
		err = report.WriteTable(stdout, rep, query.Style{Color: colorEnabled(stdout, *noColor)})
	}
	if err != nil {
		fmt.Fprintf(stderr, "netlog report: %v\n", err)
		return exitError
	}
	return exitOK
}

// ==============================================================================
// status
// ==============================================================================

func cmdStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("netlog status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		invPath     = fs.String("inventory", "inventory.csv", "path to the device inventory CSV (devices in it that were never polled are listed)")
		dataDir     = fs.String("data-dir", "data", "netlog data directory")
		staleAfter  = fs.Duration("stale-after", store.DefaultStaleAfter, "report a device as STALE when nothing has tried to poll it for this long")
		silentAfter = fs.Duration("silent-after", store.DefaultSilentAfter, "report a device as SILENT when it is reachable but has produced no new log line for this long")
		format      = fs.String("format", "table", "output format: table | json")
		failOnBad   = fs.Bool("fail", false, "exit 1 when any device is not OK (for cron and monitoring)")
		noColor     = fs.Bool("no-color", false, "disable coloured output")
	)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "netlog status: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	if *format != "table" && *format != "json" {
		fmt.Fprintf(stderr, "netlog status: --format must be table or json\n")
		return exitUsage
	}
	if *staleAfter <= 0 || *silentAfter <= 0 {
		fmt.Fprintf(stderr, "netlog status: --stale-after and --silent-after must be positive\n")
		return exitUsage
	}

	health, err := store.LoadHealth(store.HealthPath(*dataDir))
	if err != nil {
		fmt.Fprintf(stderr, "netlog status: warning: %v\n", err)
	}

	// The inventory adds the devices that were never polled. Without it the
	// command still reports everything netlog has recorded.
	var hostnames []string
	devices, warns := inventory.Load(*invPath)
	if len(devices) == 0 && len(warns) > 0 {
		fmt.Fprintf(stderr, "netlog status: inventory not read (%v); listing recorded devices only\n", warns[0])
	}
	for _, d := range devices {
		hostnames = append(hostnames, d.Hostname)
	}

	rows := report.DeviceStatuses(health.All(), hostnames, time.Now(), *staleAfter, *silentAfter)
	if *format == "json" {
		err = report.WriteDeviceStatusJSON(stdout, rows)
	} else {
		err = report.WriteDeviceStatus(stdout, rows, query.Style{Color: colorEnabled(stdout, *noColor)})
	}
	if err != nil {
		fmt.Fprintf(stderr, "netlog status: %v\n", err)
		return exitError
	}
	if *failOnBad {
		for _, r := range rows {
			if r.Status != string(store.StatusOK) {
				return exitError
			}
		}
	}
	return exitOK
}

// ==============================================================================
// telegram-test
// ==============================================================================

func cmdTelegramTest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("telegram-test", flag.ContinueOnError)
	fs.SetOutput(stderr)
	envFile := fs.String("env-file", ".env", "path to .env file")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	creds, err := credentials.NewStore(*envFile)
	if err != nil {
		fmt.Fprintf(stderr, "netlog telegram-test: error loading credentials from %s: %v\n", *envFile, err)
		return exitError
	}

	cfg := notifier.ConfigFromStore(creds)
	if !cfg.Enabled {
		fmt.Fprintf(stderr, "netlog telegram-test: TELEGRAM_ENABLED is not set to true in environment or %s\n", *envFile)
		return exitError
	}
	if cfg.BotToken == "" || cfg.ChatID == "" {
		fmt.Fprintf(stderr, "netlog telegram-test: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set\n")
		return exitError
	}

	log := &stderrLogger{w: stderr}
	tn := notifier.NewTelegram(cfg, log)
	if tn == nil {
		fmt.Fprintf(stderr, "netlog telegram-test: failed to initialize Telegram notifier\n")
		return exitError
	}
	defer tn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	testMsg := fmt.Sprintf("🔔 <b>[NETLOG TEST] Telegram Alert Verification</b>\n\n• <b>Source:</b> <code>netlog</code>\n• <b>Timestamp:</b> %s\n• <b>Status:</b> Telegram notifier initialized successfully!\n• <b>Chat ID:</b> <code>%s</code>",
		time.Now().Format("2006-01-02 15:04:05 MST"), cfg.ChatID)

	fmt.Fprintf(stdout, "Sending test notification to Telegram chat %s...\n", cfg.ChatID)
	if err := tn.SendSync(ctx, testMsg); err != nil {
		fmt.Fprintf(stderr, "netlog telegram-test: FAILED: %v\n", err)
		return exitError
	}

	fmt.Fprintln(stdout, "SUCCESS: Test notification delivered to Telegram.")
	return exitOK
}

// ==============================================================================
// diagnose
// ==============================================================================

// findDevice resolves name against the inventory: exact hostname or address
// (case-insensitive) first, then a unique hostname prefix.
func findDevice(devices []inventory.Device, name string) (inventory.Device, error) {
	var prefix []inventory.Device
	for _, d := range devices {
		if strings.EqualFold(d.Hostname, name) || d.Address == name {
			return d, nil
		}
		if strings.HasPrefix(strings.ToLower(d.Hostname), strings.ToLower(name)) {
			prefix = append(prefix, d)
		}
	}
	switch len(prefix) {
	case 1:
		return prefix[0], nil
	case 0:
		return inventory.Device{}, fmt.Errorf("device %q not found in inventory", name)
	}
	names := make([]string, len(prefix))
	for i, d := range prefix {
		names[i] = d.Hostname
	}
	return inventory.Device{}, fmt.Errorf("device %q is ambiguous: %s", name, strings.Join(names, ", "))
}

func cmdDiagnose(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("netlog diagnose", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: netlog diagnose [flags] <device-name>")
		fs.PrintDefaults()
	}
	var o collectOpts
	var (
		iface   = fs.String("interface", "", "limit the CRC and optical checks to one interface")
		raw     = fs.Bool("raw", false, "print the verbatim device output under each check")
		failBad = fs.Bool("fail", false, "exit 1 when the device is unreachable or any check needs attention")
	)
	fs.StringVar(&o.inventory, "inventory", "inventory.csv", "path to the device inventory CSV")
	fs.StringVar(&o.envFile, "env-file", ".env", "path to an optional .env file with NETLOG_USERNAME / NETLOG_PASSWORD")
	fs.DurationVar(&o.connectTimeout, "connect-timeout", 5*time.Second, "SSH dial timeout")
	fs.DurationVar(&o.commandTimeout, "command-timeout", 5*time.Second, "SSH command timeout")
	fs.StringVar(&o.knownHosts, "known-hosts", "known_hosts", "path to the known_hosts file (\"\" = the user's ~/.ssh/known_hosts)")
	fs.StringVar(&o.knownHostsPolicy, "known-hosts-policy", "accept-new", "host key policy: strict, accept-new or update")
	fs.BoolVar(&o.insecureIgnoreHostKey, "insecure-ignore-host-key", false, "DANGEROUS: skip host key verification entirely")
	fs.BoolVar(&o.legacyAlgorithms, "legacy-algorithms", true, "allow legacy SSH algorithms as a fallback for older network gear")
	fs.BoolVar(&o.jumpEnabled, "jump", true, "enable jump host / bastion routing")
	fs.StringVar(&o.jumpHost, "jump-host", "", "global default bastion host[:port]")
	fs.BoolVar(&o.noColor, "no-color", false, "disable coloured output")

	// The device name may come before or after the flags.
	var names []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return exitOK
			}
			return exitUsage
		}
		if fs.NArg() == 0 {
			break
		}
		names = append(names, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(names) != 1 {
		fmt.Fprintln(stderr, "netlog diagnose: exactly one <device-name> is required")
		return exitUsage
	}
	if *iface != "" && !diagnose.ValidInterface(*iface) {
		fmt.Fprintf(stderr, "netlog diagnose: invalid --interface %q\n", *iface)
		return exitUsage
	}

	devices, warns := inventory.Load(o.inventory)
	if len(devices) == 0 {
		for _, w := range warns {
			fmt.Fprintf(stderr, "netlog diagnose: inventory: %v\n", w)
		}
		fmt.Fprintf(stderr, "netlog diagnose: inventory %q contains no devices (tip: run 'netlog init')\n", o.inventory)
		return exitError
	}
	dev, err := findDevice(devices, names[0])
	if err != nil {
		fmt.Fprintf(stderr, "netlog diagnose: %v\n", err)
		return exitError
	}

	log := &stderrLogger{w: stderr}
	if o.jumpHost != "" {
		os.Setenv(credentials.EnvJumpHost, o.jumpHost)
	}
	creds, err := credentials.NewStore(o.envFile)
	if err != nil {
		fmt.Fprintf(stderr, "netlog diagnose: loading credentials: %v\n", err)
		return exitError
	}
	hostKeys, err := hostKeyCallback(o, log)
	if err != nil {
		fmt.Fprintf(stderr, "netlog diagnose: %v\n", err)
		return exitError
	}
	sshOpts := sshclient.Options{
		ConnectTimeout:   o.connectTimeout,
		CommandTimeout:   o.commandTimeout,
		HostKeyCallback:  hostKeys,
		LegacyAlgorithms: o.legacyAlgorithms,
	}
	if sshOpts.ConnectTimeout <= 0 || sshOpts.ConnectTimeout > triage.MaxConnectTimeout {
		sshOpts.ConnectTimeout = triage.MaxConnectTimeout
	}
	dialer := collector.NewDialer(collector.DialerConfig{
		SSH:             sshOpts,
		CredStore:       creds,
		JumpEnabled:     o.jumpEnabled,
		JumpDefaultHost: o.jumpHost,
	})
	defer dialer.CloseJumps()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	rep := diagnose.Run(ctx, dialer, dev, diagnose.Options{
		Interface:      *iface,
		CommandTimeout: o.commandTimeout,
		SSH:            sshOpts,
	})
	diagnose.Render(stdout, rep, diagnose.RenderOptions{Color: colorEnabled(stdout, o.noColor), Raw: *raw})
	if *failBad && !rep.Healthy() {
		return exitError
	}
	return exitOK
}
