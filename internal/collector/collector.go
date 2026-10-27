// ==============================================================================
// Package collector implements the netlog polling engine and shared data model.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         imported by cmd/netlog and the other internal/netlog packages
// Notes:         Go package implementation
// ==============================================================================
// Package collector is the first stage of netlog. It owns three things:
//
//  1. The shared data model (LogEntry, IncidentReport, DiagCmd) that every
//     other netlog package imports, so there is exactly one definition of a
//     normalized log record.
//  2. A Dialer that turns an inventory.Device into an authenticated SSH
//     session -- direct or through a bastion -- reusing internal/sshclient
//     and internal/credentials. The triage engine reuses the same Dialer, so
//     there is a single connection path in the whole binary.
//  3. A Collector: a bounded worker pool that polls every device once, with
//     a staggered start schedule so a fleet of devices is never hit with
//     simultaneous SSH logins (VTY exhaustion, lockout rules), and captures
//     each device's clock skew so logs from different devices can later be
//     placed on one coherent timeline.
//
// The collector deliberately does no parsing. It returns raw log text plus
// the measured skew; parsing, dedup and classification belong to the parser
// and pipeline packages, which keeps this package free of import cycles.
package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"netlog/internal/credentials"
	"netlog/internal/errcat"
	"netlog/internal/inventory"
	"netlog/internal/sshclient"
	"netlog/internal/vendor"
)

// ==============================================================================
// Data model
// ==============================================================================

// Category values for LogEntry.Category.
const (
	CategoryConfig   = "CONFIG"
	CategoryAuth     = "AUTH"
	CategoryFault    = "FAULT"
	CategorySecurity = "SECURITY"
	CategorySystem   = "SYSTEM"
)

// Severity values for LogEntry.Severity.
const (
	SeverityInfo     = "INFO"
	SeverityWarning  = "WARNING"
	SeverityError    = "ERROR"
	SeverityCritical = "CRITICAL"
)

// LogEntry is one normalized, deduplicated log record from any vendor.
type LogEntry struct {
	ID        string    `json:"id"`        // SHA256(hostname+raw)[:12]
	Timestamp time.Time `json:"timestamp"` // UTC, clock-skew corrected
	DeviceTS  time.Time `json:"device_ts"` // as reported by device
	SkewMs    int64     `json:"skew_ms"`

	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	Vendor   string `json:"vendor"`

	Category string `json:"category"` // CONFIG | AUTH | FAULT | SECURITY | SYSTEM
	Severity string `json:"severity"` // INFO | WARNING | ERROR | CRITICAL
	Facility string `json:"facility"`

	User      string `json:"user,omitempty"`
	SourceIP  string `json:"src_ip,omitempty"`
	SessionID string `json:"session,omitempty"`

	Event   string `json:"event"`
	Summary string `json:"summary"`
	Raw     string `json:"raw"`

	// Object is what a state-change event is about: the interface of a
	// LINK_DOWN/LINK_UP, the neighbor or peer address of an OSPF/BGP event.
	// The classifier sets it so a later "up" can be paired with the matching
	// "down" (outage durations) without every consumer re-parsing Raw. Empty
	// for other events, for entries stored before the field existed, and
	// whenever the line does not name the object.
	Object string `json:"object,omitempty"`
}

// IncidentReport is the auto-triage output: the log line that triggered the
// triage plus the read-only diagnostics captured from the device.
type IncidentReport struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Hostname    string    `json:"hostname"`
	TriggerLog  LogEntry  `json:"trigger_log"`
	Playbook    string    `json:"playbook"`
	Diagnostics []DiagCmd `json:"diagnostics"`
	TriageHints []string  `json:"triage_hints"`
}

// DiagCmd is one diagnostic command executed during triage and what it returned.
type DiagCmd struct {
	Command    string `json:"command"`
	Output     string `json:"output"`
	DurationMs int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

// EntryID returns the stable dedup key for a log line: the first 12 hex
// characters of SHA-256 over the hostname and the raw line. A NUL byte
// separates the two inputs so ("ab","c") and ("a","bc") cannot collide.
func EntryID(hostname, raw string) string {
	sum := sha256.Sum256([]byte(hostname + "\x00" + raw))
	return hex.EncodeToString(sum[:])[:12]
}

// ==============================================================================
// Per-vendor commands
// ==============================================================================

// ErrUnsupportedVendor is returned (wrapped) when a device's vendor is known
// to the vendor registry but netlog has no log-fetch command for it.
var ErrUnsupportedVendor = errors.New("netlog has no log fetch command for this vendor")

// fetchPlan describes how to pull the log buffer from one platform.
type fetchPlan struct {
	// Interactive runs Commands inside one PTY shell session, in order.
	// It is only used where the commands share per-session state (the
	// FortiOS log filter is per-CLI-session, so the filter and the display
	// must run in the same session).
	Interactive bool
	Commands    []string

	// CheckPointGaia uses Gaia expert-mode handling.
	CheckPointGaia bool

	// Prompt matches the device's CLI prompt (the last line of the output
	// once a command has finished). Interactive plans wait for it instead of
	// guessing from silence, which would return an empty log page whenever
	// the device takes longer than a moment to render it.
	Prompt *regexp.Regexp
}

// fortiPrompt matches "FGT-01 # ", "FGT-01 $ " and VDOM forms such as
// "FGT-01 (root) # ".
var fortiPrompt = regexp.MustCompile(`^[\w.-]+(?: \([\w./-]+\))? [#$] ?$`)

// logPlans maps a canonical vendor key (see vendor.CanonicalKey) to its log
// fetch plan. None of these commands modify device state.
var logPlans = map[string]fetchPlan{
	"vyos":          {Commands: []string{"/opt/vyatta/bin/vyatta-op-cmd-wrapper show log tail 100"}},
	"cisco_ios":     {Commands: []string{"show logging"}},
	"cisco_asa":     {Commands: []string{"show logging"}},
	"cisco_sb":      {Commands: []string{"show logging"}},
	"huawei_vrp":    {Commands: []string{"display logbuffer"}},
	"juniper_junos": {Commands: []string{"show log messages | last 100"}},
	"fortigate":     {Interactive: true, Commands: []string{"execute log filter category 1", "execute log display"}, Prompt: fortiPrompt},
	"aruba":         {Commands: []string{"show logging"}},
	"ruijie":        {Commands: []string{"show logging"}},
	"mikrotik":      {Commands: []string{"/log print"}},

	// pfSense 2.5+ keeps plain-text syslog files.
	// Check Point Gaia can land in clish, so it uses CheckPointGaia expert mode handling.
	"pfsense":         {Commands: []string{"tail -q -n 300 /var/log/system.log /var/log/auth.log"}},
	"checkpoint_gaia": {CheckPointGaia: true, Commands: []string{"tail -n 300 /var/log/messages"}},
	"arista":          {Commands: []string{"show logging last 100 lines"}},
	"paloalto":        {Commands: []string{"show log system"}},
	"generic":         {Commands: []string{"show logging"}},
}

// defaultClockCommand is used for any vendor without an explicit entry in
// clockCommands (Cisco ASA, Cisco SB, PAN-OS, ...). Skew capture is
// best-effort, so a wrong guess only costs one failed exec.
const defaultClockCommand = "show clock"

// clockCommands maps a canonical vendor key to the command that prints the
// device's current time.
var clockCommands = map[string]string{
	"cisco_ios":       "show clock",
	"arista":          "show clock",
	"aruba":           "show clock",
	"ruijie":          "show clock",
	"huawei_vrp":      "display clock",
	"vyos":            "date",
	"pfsense":         "date",
	"checkpoint_gaia": "date",
	"juniper_junos":   "show system uptime",
	"mikrotik":        "/system clock print",
	"fortigate":       "get system status",
	"generic":         "show clock",
}

// clockCommandFor returns the clock command for a canonical vendor key.
func clockCommandFor(vendorKey string) string {
	if cmd, ok := clockCommands[vendorKey]; ok {
		return cmd
	}
	return defaultClockCommand
}

// resolvePlan maps a device's inventory vendor string to its canonical key
// and log fetch plan. A vendor name the registry does not know at all falls
// back to "generic" (matching the registry's own fallback role); a vendor the
// registry knows but netlog cannot read logs from is an error, so we never
// send a wrong command to, say, a pfSense console menu.
func resolvePlan(dev inventory.Device) (string, fetchPlan, error) {
	key, ok := vendor.CanonicalKey(dev.Vendor)
	if !ok {
		key = "generic"
	}
	plan, ok := logPlans[key]
	if !ok {
		return key, fetchPlan{}, fmt.Errorf("%w: %q", ErrUnsupportedVendor, dev.Vendor)
	}
	return key, plan, nil
}

// ==============================================================================
// SSH dialer (shared with the triage engine)
// ==============================================================================

// DialerConfig controls how a Dialer connects.
type DialerConfig struct {
	// SSH carries the timeouts, host-key callback and algorithm settings.
	SSH sshclient.Options

	// CredStore resolves per-device and per-bastion credentials. Required.
	CredStore *credentials.Store

	// JumpEnabled turns bastion routing on. When false every device is
	// dialled directly, regardless of inventory or environment settings.
	JumpEnabled bool

	// JumpDefaultHost is a global default bastion host[:port] used for
	// devices whose inventory entry names no jump host.
	JumpDefaultHost string
}

// Dialer opens authenticated SSH connections to inventory devices. It caches
// one client per bastion for the lifetime of a poll cycle, and remembers
// bastions that failed so a dead bastion costs one connect timeout, not one
// per device behind it. It is safe for concurrent use.
type Dialer struct {
	cfg DialerConfig

	mu     sync.Mutex
	jumps  map[string]*ssh.Client // keyed by "host:port"
	failed map[string]error       // bastions that failed this cycle
}

// NewDialer returns a Dialer for the given configuration.
func NewDialer(cfg DialerConfig) *Dialer {
	return &Dialer{
		cfg:    cfg,
		jumps:  make(map[string]*ssh.Client),
		failed: make(map[string]error),
	}
}

// Dial connects and authenticates to dev, directly or via its bastion. The
// caller owns the returned client and must Close it.
func (d *Dialer) Dial(ctx context.Context, dev inventory.Device) (*ssh.Client, error) {
	if d.cfg.CredStore == nil {
		return nil, errors.New("collector: credential store is required")
	}
	port := dev.Port
	if port <= 0 {
		port = 22
	}

	creds := d.cfg.CredStore.ForGroup(dev.CredentialGroup)
	auth := sshclient.AuthOptions{
		Username: creds.Username,
		Password: creds.Password,
		KeyFile:  creds.KeyFile,
	}

	jumpAddr := d.jumpAddr(dev)
	if jumpAddr == "" {
		client, err := sshclient.ConnectWithAuth(ctx, dev.Address, port, auth, d.cfg.SSH)
		if err != nil {
			return nil, errcat.Classify(dev.Hostname, "connect", err)
		}
		return client, nil
	}

	jump, err := d.jumpClient(ctx, dev, jumpAddr, auth)
	if err != nil {
		return nil, errcat.Classify(dev.Hostname, "connect-jump", fmt.Errorf("bastion %s: %w", jumpAddr, err))
	}
	client, err := sshclient.ConnectViaJumpWithAuth(ctx, jump, dev.Address, port, auth, d.cfg.SSH)
	if err != nil {
		// The failure may be the device's, or the bastion session may have
		// died since it was cached (a long-running monitor outlives many
		// idle timeouts). Forget a dead session so the next dial reconnects
		// instead of failing against the same corpse forever.
		d.dropIfDead(jumpAddr, jump)
		return nil, errcat.Classify(dev.Hostname, "connect", err)
	}
	return client, nil
}

// bastionProbeTimeout bounds the liveness probe of a cached bastion session.
const bastionProbeTimeout = 3 * time.Second

// dropIfDead closes and forgets the cached bastion client c for addr if it no
// longer answers a keepalive.
func (d *Dialer) dropIfDead(addr string, c *ssh.Client) {
	alive := make(chan bool, 1)
	go func() {
		// OpenSSH answers unknown global requests with a failure reply,
		// which still proves the session is up; only a transport error
		// means it is gone.
		_, _, err := c.SendRequest("keepalive@openssh.com", true, nil)
		alive <- err == nil
	}()
	select {
	case ok := <-alive:
		if ok {
			return
		}
	case <-time.After(bastionProbeTimeout):
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.jumps[addr] == c {
		delete(d.jumps, addr)
	}
	_ = c.Close()
}

// CloseJumps closes every cached bastion connection and clears the failed-
// bastion memory. Call it at the end of each poll cycle so a long-running
// monitor never holds on to a stale bastion session.
func (d *Dialer) CloseJumps() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for addr, c := range d.jumps {
		_ = c.Close()
		delete(d.jumps, addr)
	}
	clear(d.failed)
}

// jumpAddr returns the effective bastion address for dev, or "" for a
// direct connection. Priority: the inventory jump_host
// name (resolved through NETLOG_JUMP_<NAME>_HOST, else used verbatim as
// host[:port]), then the global default host, then NETLOG_JUMP_HOST.
func (d *Dialer) jumpAddr(dev inventory.Device) string {
	if !d.cfg.JumpEnabled {
		return ""
	}
	if dev.JumpHost != "" {
		if h := d.cfg.CredStore.ForJumpHost(dev.JumpHost).Host; h != "" {
			return h
		}
		return dev.JumpHost
	}
	if d.cfg.JumpDefaultHost != "" {
		return d.cfg.JumpDefaultHost
	}
	return d.cfg.CredStore.JumpDefaults().Host
}

// jumpClient returns the cached bastion client for addr, connecting on first
// use. The mutex is held across the connect on purpose: concurrent workers
// behind the same bastion wait for one login instead of opening a burst of
// them, and a failure is remembered so the waiters fail fast.
func (d *Dialer) jumpClient(ctx context.Context, dev inventory.Device, addr string, devAuth sshclient.AuthOptions) (*ssh.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if c, ok := d.jumps[addr]; ok {
		return c, nil
	}
	if err, ok := d.failed[addr]; ok {
		return nil, err
	}

	var jc credentials.JumpCredentials
	if dev.JumpHost != "" {
		jc = d.cfg.CredStore.ForJumpHost(dev.JumpHost)
	} else {
		jc = d.cfg.CredStore.JumpDefaults()
	}
	auth := sshclient.AuthOptions{Username: jc.Username, Password: jc.Password, KeyFile: jc.KeyFile}
	if auth.Username == "" {
		auth = devAuth // last resort: the bastion accepts the device credentials
	}

	host, port := splitHostPort(addr)
	c, err := sshclient.ConnectJumpHostWithAuth(ctx, host, port, auth, d.cfg.SSH)
	if err != nil {
		// A cancelled context is not the bastion's fault; do not poison the cache.
		if ctx.Err() == nil {
			d.failed[addr] = err
		}
		return nil, err
	}
	d.jumps[addr] = c
	return c, nil
}

// splitHostPort parses "host[:port]", defaulting the port to 22.
func splitHostPort(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 22
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		port = 22
	}
	return host, port
}

// ==============================================================================
// Collector
// ==============================================================================

// DefaultInterval is the polling interval used for the stagger window when
// Config.Interval is zero (and by one-shot collect runs).
const DefaultInterval = 2 * time.Minute

// staggerPerDevice is the start-time spacing budget per device.
const staggerPerDevice = 3 * time.Second

// Logger is the subset of *logging.Logger the collector uses. Defining it
// here keeps the package testable and independent of the logging package's
// backup-specific summary code.
type Logger interface {
	Info(format string, args ...any)
	Warn(format string, args ...any)
	Error(format string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}

// ClockParser converts the output of a vendor's clock command into an
// absolute instant. vendorKey is the canonical vendor key; ref is the
// server-side time at which the command executed, which a parser may use to
// supply a missing year or to resolve a zone-less reading. The pipeline's
// normalizer provides the implementation, because device-clock parsing is
// vendor-specific and the pipeline already imports this package.
type ClockParser func(vendorKey, output string, ref time.Time) (time.Time, error)

// Config controls a Collector.
type Config struct {
	// Concurrency bounds simultaneous SSH sessions. Values below 1 mean 1.
	Concurrency int

	// Interval is the polling interval. It sets the width of the stagger
	// window (see StaggerOffsets). Zero means DefaultInterval.
	Interval time.Duration

	// SSH carries timeouts, host-key callback and algorithm settings.
	SSH sshclient.Options

	// CredStore resolves SSH credentials. Required.
	CredStore *credentials.Store

	// JumpEnabled and JumpDefaultHost configure bastion routing; see
	// DialerConfig.
	JumpEnabled     bool
	JumpDefaultHost string

	// ClockParser, when set, enables clock-skew capture. When nil the
	// collector skips the clock command and every Result reports SkewOK=false.
	ClockParser ClockParser

	// WarnOnSkewFailure controls whether clock skew capture errors emit a WARN
	// message. Defaults to false so routine log polling isn't flooded with warnings
	// when platforms drop the secondary channel after log retrieval.
	WarnOnSkewFailure bool

	// Logger receives collector diagnostics. Nil disables them.
	Logger Logger
}

// Result is the outcome of polling one device.
type Result struct {
	Device inventory.Device

	// VendorKey is the canonical vendor key used for this poll; downstream
	// parsers dispatch on it.
	VendorKey string

	// Raw is the unmodified log output. Empty on error. An empty buffer on
	// a healthy device is not an error.
	Raw string

	// FetchedAt is the server-side UTC time the log fetch completed. Parsers
	// use it to infer the year for syslog timestamps that carry none.
	FetchedAt time.Time

	// SkewMs is device clock minus server clock, in milliseconds (positive
	// means the device is ahead). Valid only when SkewOK is true. The
	// normalizer subtracts it from device timestamps.
	SkewMs int64
	SkewOK bool

	// SkewErr explains why skew capture failed (SkewOK=false). It never
	// fails the poll.
	SkewErr error

	Duration time.Duration

	// Err is non-nil when the device could not be polled.
	Err error
}

// Collector polls devices over SSH.
type Collector struct {
	cfg    Config
	log    Logger
	dialer *Dialer

	skewWarned sync.Map // hostname -> struct{}: warn once per device
}

// New returns a Collector for cfg.
func New(cfg Config) *Collector {
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	var log Logger = nopLogger{}
	if cfg.Logger != nil {
		log = cfg.Logger
	}
	return &Collector{
		cfg: cfg,
		log: log,
		dialer: NewDialer(DialerConfig{
			SSH:             cfg.SSH,
			CredStore:       cfg.CredStore,
			JumpEnabled:     cfg.JumpEnabled,
			JumpDefaultHost: cfg.JumpDefaultHost,
		}),
	}
}

// StaggerOffsets returns the start offset for each of n devices:
//
//	stagger  = min(interval/2, n * 3s)
//	offset[i] = i * (stagger / n)
//
// so the whole fleet starts inside one stagger window and no two devices
// start together. A non-positive interval is treated as DefaultInterval.
func StaggerOffsets(n int, interval time.Duration) []time.Duration {
	if n <= 0 {
		return nil
	}
	if interval <= 0 {
		interval = DefaultInterval
	}
	stagger := time.Duration(n) * staggerPerDevice
	if half := interval / 2; half < stagger {
		stagger = half
	}
	step := stagger / time.Duration(n)

	offsets := make([]time.Duration, n)
	for i := range offsets {
		offsets[i] = time.Duration(i) * step
	}
	return offsets
}

// Run polls every device once and streams one Result per device on the
// returned channel, which is closed when the cycle is finished. The channel
// is buffered to len(devices), so a slow or departed consumer can never
// block a worker. Results arrive in completion order, not inventory order.
//
// Devices are started on the StaggerOffsets schedule, at most
// Config.Concurrency at a time. If ctx is cancelled, devices not yet started
// are not polled and produce no Result; polls in flight are aborted at the
// next SSH timeout boundary.
func (c *Collector) Run(ctx context.Context, devices []inventory.Device) <-chan Result {
	out := make(chan Result, len(devices))

	go func() {
		defer close(out)
		defer c.dialer.CloseJumps()

		offsets := StaggerOffsets(len(devices), c.cfg.Interval)
		start := time.Now()
		sem := make(chan struct{}, c.cfg.Concurrency)
		var wg sync.WaitGroup

	dispatch:
		for i, dev := range devices {
			if !sleepUntil(ctx, start.Add(offsets[i])) {
				break dispatch
			}
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				break dispatch
			}

			wg.Add(1)
			go func(dev inventory.Device) {
				defer wg.Done()
				defer func() { <-sem }()
				out <- c.pollOne(ctx, dev)
			}(dev)
		}
		wg.Wait()
	}()

	return out
}

// sleepUntil waits until t. It reports false if ctx ended first.
func sleepUntil(ctx context.Context, t time.Time) bool {
	d := time.Until(t)
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// pollOne fetches the log buffer and clock reading from a single device. The
// recover is defense in depth: a bug while handling one
// device must surface as that device's error, not crash the whole run.
func (c *Collector) pollOne(ctx context.Context, dev inventory.Device) (res Result) {
	started := time.Now()
	res.Device = dev
	defer func() {
		if r := recover(); r != nil {
			res.Err = fmt.Errorf("panic while polling %s: %v", dev.Hostname, r)
		}
		res.Duration = time.Since(started)
	}()

	key, plan, err := resolvePlan(dev)
	res.VendorKey = key
	if err != nil {
		res.Err = err // rejected before dialling: no SSH session is opened
		return res
	}

	client, err := c.dialer.Dial(ctx, dev)
	if err != nil {
		res.Err = err
		return res
	}
	defer client.Close()

	raw, err := c.runPlanForDev(ctx, client, plan, dev, c.cfg.SSH)
	if err != nil {
		res.Err = errcat.Classify(dev.Hostname, "command", err)
		return res
	}
	res.Raw = raw
	res.FetchedAt = time.Now().UTC()

	c.captureClockSkew(ctx, client, dev, key, &res)
	return res
}

// minInteractiveTimeout is the floor for the deadline of an interactive
// (PTY) plan. sshclient.RunInteractive applies one deadline to the whole
// session, and after each command it waits for the output to go quiet (1.5s
// settle), so a two-command FortiOS plan needs well over the 5s that suits a
// single exec command, even on a fast link.
var minInteractiveTimeout = 15 * time.Second

func runPlan(ctx context.Context, client *ssh.Client, plan fetchPlan, opts sshclient.Options) (string, error) {
	return runPlanWithCreds(ctx, client, plan, "", opts)
}

func (c *Collector) runPlanForDev(ctx context.Context, client *ssh.Client, plan fetchPlan, dev inventory.Device, opts sshclient.Options) (string, error) {
	expertPass := ""
	if c.cfg.CredStore != nil {
		creds := c.cfg.CredStore.ForGroup(dev.CredentialGroup)
		expertPass = creds.ExpertPassword
	}
	return runPlanWithCreds(ctx, client, plan, expertPass, opts)
}

// runPlanWithCreds executes a fetch plan on an open connection.
func runPlanWithCreds(ctx context.Context, client *ssh.Client, plan fetchPlan, expertPassword string, opts sshclient.Options) (string, error) {
	if plan.CheckPointGaia {
		timeout := opts.CommandTimeout
		if timeout < minInteractiveTimeout {
			timeout = minInteractiveTimeout
		}
		intOpts := opts
		intOpts.CommandTimeout = timeout
		return sshclient.RunInteractiveGaia(ctx, client, plan.Commands, expertPassword, intOpts)
	}
	if plan.Interactive {
		timeout := opts.CommandTimeout
		if timeout < minInteractiveTimeout {
			timeout = minInteractiveTimeout
		}
		intOpts := opts
		intOpts.CommandTimeout = timeout
		return sshclient.RunInteractivePrompt(ctx, client, plan.Commands, plan.Prompt, intOpts)
	}

	var b strings.Builder
	for _, cmd := range plan.Commands {
		out, err := sshclient.RunCommand(ctx, client, cmd, opts)
		b.WriteString(out)
		if err != nil {
			return b.String(), err
		}
		if out != "" && !strings.HasSuffix(out, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}

// captureClockSkew runs the vendor's clock command right after the log fetch
// and measures how far the device clock is from the server clock:
//
//	mid  = before + (after-before)/2      server time at the device's reading
//	skew = deviceTime - mid               positive: device is ahead
//
// Halving the round trip assumes symmetric latency, which is the standard
// SNTP-style approximation. Precision is bounded by the device's clock
// resolution (usually one second), so sub-second skew is noise. Any failure
// leaves SkewOK=false and never fails the poll.
func (c *Collector) captureClockSkew(ctx context.Context, client *ssh.Client, dev inventory.Device, vendorKey string, res *Result) {
	if c.cfg.ClockParser == nil {
		return
	}

	cmd := clockCommandFor(vendorKey)
	before := time.Now()
	out, err := sshclient.RunCommand(ctx, client, cmd, c.cfg.SSH)
	after := time.Now()
	if err != nil {
		c.recordSkewErr(dev, res, fmt.Errorf("clock command %q: %w", cmd, err))
		return
	}

	mid := before.Add(after.Sub(before) / 2)
	deviceTime, err := c.cfg.ClockParser(vendorKey, out, mid)
	if err != nil {
		c.recordSkewErr(dev, res, fmt.Errorf("parsing output of %q: %w", cmd, err))
		return
	}

	res.SkewMs = deviceTime.Sub(mid).Milliseconds()
	res.SkewOK = true
}

// recordSkewErr stores a skew failure on the result and optionally warns once per
// device if WarnOnSkewFailure is configured.
func (c *Collector) recordSkewErr(dev inventory.Device, res *Result, err error) {
	res.SkewErr = err
	if c.cfg.WarnOnSkewFailure {
		if _, seen := c.skewWarned.LoadOrStore(dev.Hostname, struct{}{}); !seen {
			c.log.Warn("%s: clock skew unavailable, timestamps left uncorrected: %v", dev.Hostname, err)
		}
	}
}

// atPrompt reports whether the output currently ends at the device prompt.
func atPrompt(out string, prompt *regexp.Regexp) bool {
	return sshclient.AtPrompt(out, prompt)
}
