// ==============================================================================
// Package pipeline: anomaly detector (Stage 4).
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         signals := detector.Observe(entry)
// Notes:         Go package implementation
// ==============================================================================
// The detector watches the classified entry stream of each device through
// small in-memory sliding windows and emits TriageSignals for the auto-triage
// engine:
//
//   - LINK_DOWN: a signal per event; three or more on the same interface
//     within 5 minutes collapse into one LINK_FLAP signal and further
//     individual signals for that interface are suppressed for 10 minutes.
//   - OSPF_ADJ_DOWN, BGP_PEER_DOWN: signal immediately.
//   - VRRP_TRANSITION, STP_TCN, HIGH_CPU: signal (these have playbooks).
//   - LOGIN_FAILURE: five or more from one source IP within 30 seconds emit
//     a BRUTE_FORCE_ATTEMPT signal. Separately, failures from one source IP
//     on three or more different devices within 10 minutes emit a
//     PASSWORD_SPRAY_ATTEMPT signal: a spray that tries one or two passwords
//     per device never reaches the per-device threshold, and only the
//     fleet-wide view sees it.
//   - CONFIG_CHANGE / AFTER_HOURS_CHANGE: no signal, but remembered so any
//     FAULT within 10 minutes is annotated with the probable cause.
//
// Stale history never triggers triage: on a device's first poll the whole log
// buffer is "new", but an incident from yesterday cannot be diagnosed by
// connecting now. Entries older than MaxSignalAge still feed the windows
// (so flaps and correlations inside the buffer are seen) but emit nothing.
//
// Windows live in memory. In monitor mode they persist across polls; in
// one-shot collect mode they cover the single batch being processed.
package pipeline

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	"netlog/internal/collector"
)

// Playbook names carried by a TriageSignal.
const (
	PlaybookLinkDown       = "link_down"
	PlaybookLinkFlap       = "link_flap"
	PlaybookOSPFAdjDown    = "ospf_adj_down"
	PlaybookBGPPeerDown    = "bgp_peer_down"
	PlaybookVRRPTransition = "vrrp_transition"
	PlaybookSTPTCN         = "stp_tcn"
	PlaybookHighCPU        = "high_cpu"
	PlaybookOpticsAlarm    = "optics_alarm"
	PlaybookBruteForce     = "brute_force"
	PlaybookConfigDiff     = "config_diff"
)

// Signal priorities.
const (
	PriorityLow      = 1
	PriorityMedium   = 2
	PriorityHigh     = 3
	PriorityCritical = 4
)

// TriageSignal asks the triage engine to capture diagnostics for an event.
type TriageSignal struct {
	// Entry is the triggering log entry. For derived signals (LINK_FLAP,
	// BRUTE_FORCE_ATTEMPT) it is a synthesized entry whose Raw is the line
	// that completed the pattern.
	Entry collector.LogEntry

	// Playbook names the diagnostic playbook to run.
	Playbook string

	// Priority is 1 (low) to 4 (critical).
	Priority int

	// Annotations are human-readable findings such as the probable cause
	// from config/fault correlation. They are copied into the incident's
	// triage hints.
	Annotations []string

	// Derived is true when Entry was synthesized by the detector rather than
	// parsed from the device; the caller should store it as an event of its
	// own so it shows up in queries and timelines.
	Derived bool
}

// DetectorConfig tunes the detector. Zero values take the documented defaults.
type DetectorConfig struct {
	FlapThreshold     int           // LINK_DOWN count that makes a flap (default 3)
	FlapWindow        time.Duration // window for the flap count (default 5m)
	FlapSuppress      time.Duration // individual-signal suppression after a flap (default 10m)
	BruteThreshold    int           // failures that make a brute-force attempt (default 5)
	BruteWindow       time.Duration // window for the failure count (default 30s)
	SprayDevices      int           // distinct devices one source must fail on (default 3)
	SprayWindow       time.Duration // window for that count (default 10m)
	CorrelationWindow time.Duration // config-change-to-fault window (default 10m)
	MaxSignalAge      time.Duration // oldest entry that may emit a signal (default 15m)
	Now               func() time.Time
}

func (c *DetectorConfig) setDefaults() {
	if c.FlapThreshold <= 0 {
		c.FlapThreshold = 3
	}
	if c.FlapWindow <= 0 {
		c.FlapWindow = 5 * time.Minute
	}
	if c.FlapSuppress <= 0 {
		c.FlapSuppress = 10 * time.Minute
	}
	if c.BruteThreshold <= 0 {
		c.BruteThreshold = 5
	}
	if c.BruteWindow <= 0 {
		c.BruteWindow = 30 * time.Second
	}
	if c.SprayDevices <= 0 {
		c.SprayDevices = 3
	}
	if c.SprayWindow <= 0 {
		c.SprayWindow = 10 * time.Minute
	}
	if c.CorrelationWindow <= 0 {
		c.CorrelationWindow = 10 * time.Minute
	}
	if c.MaxSignalAge <= 0 {
		c.MaxSignalAge = 15 * time.Minute
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

type configChange struct {
	user string
	at   time.Time
}

type deviceState struct {
	linkDowns  map[string][]time.Time // interface -> recent LINK_DOWN times
	flapUntil  map[string]time.Time   // interface -> suppress individual signals until
	loginFails map[string][]time.Time // source IP -> recent LOGIN_FAILURE times
	lastConfig *configChange
}

// Detector turns classified entries into triage signals. It is not safe for
// concurrent use; feed it from one goroutine in chronological order per
// device.
type Detector struct {
	cfg     DetectorConfig
	devices map[string]*deviceState
	spray   map[string]*sprayTally // source IP -> recent failures across all devices
	lastGC  time.Time
	priming bool
}

// sprayHit is one failed login seen from a source address.
type sprayHit struct {
	host string
	at   time.Time
}

// sprayTally is the recent failures from one source address, over every
// device. newest is the latest failure time seen; hits older than
// newest-SprayWindow are dropped. Devices are polled one after another, so
// one device's batch can be fed before an older line of another device: a
// hit up to SprayWindow older than newest is still accepted, anything older
// is ignored (it cannot be part of a window that ends at newest).
type sprayTally struct {
	newest time.Time
	hits   []sprayHit
}

// gcInterval is how often idle detector state is swept. Without it, a
// long-running monitor would keep one entry per source IP that ever failed a
// login (internet scanners produce thousands) and per interface that ever
// went down.
const gcInterval = 10 * time.Minute

// NewDetector returns a Detector.
func NewDetector(cfg DetectorConfig) *Detector {
	cfg.setDefaults()
	return &Detector{cfg: cfg, devices: make(map[string]*deviceState), spray: make(map[string]*sprayTally)}
}

func (d *Detector) state(host string) *deviceState {
	s := d.devices[host]
	if s == nil {
		s = &deviceState{
			linkDowns:  make(map[string][]time.Time),
			flapUntil:  make(map[string]time.Time),
			loginFails: make(map[string][]time.Time),
		}
		d.devices[host] = s
	}
	return s
}

// Observe feeds one classified entry to the detector and returns the signals
// it produces (usually none).
func (d *Detector) Observe(e collector.LogEntry) []TriageSignal {
	d.maybeGC()
	sigs := d.observe(e)
	if d.priming {
		return nil
	}
	return sigs
}

// Prime replays recent, already-stored entries into the detector's windows
// without emitting any signal. A one-shot "netlog collect" is a fresh process
// each time, so without priming the 5-minute flap window, the 30-second
// brute-force window and the 10-minute config-change correlation would all
// start empty on every cron run and never see events from the previous one.
// Entries need not be sorted.
func (d *Detector) Prime(entries []collector.LogEntry) {
	sorted := make([]collector.LogEntry, len(entries))
	copy(sorted, entries)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Timestamp.Before(sorted[j].Timestamp) })

	d.priming = true
	defer func() { d.priming = false }()
	for _, e := range sorted {
		d.Observe(e)
	}
}

// maybeGC sweeps state whose window has long expired.
func (d *Detector) maybeGC() {
	now := d.cfg.Now()
	if !d.lastGC.IsZero() && now.Sub(d.lastGC) < gcInterval {
		return
	}
	d.lastGC = now

	for host, st := range d.devices {
		for k, times := range st.linkDowns {
			if len(times) == 0 || times[len(times)-1].Before(now.Add(-d.cfg.FlapWindow)) {
				delete(st.linkDowns, k)
			}
		}
		for k, until := range st.flapUntil {
			if until.Before(now) {
				delete(st.flapUntil, k)
			}
		}
		for k, times := range st.loginFails {
			if len(times) == 0 || times[len(times)-1].Before(now.Add(-d.cfg.BruteWindow)) {
				delete(st.loginFails, k)
			}
		}
		if st.lastConfig != nil && st.lastConfig.at.Before(now.Add(-d.cfg.CorrelationWindow)) {
			st.lastConfig = nil
		}
		if len(st.linkDowns) == 0 && len(st.flapUntil) == 0 && len(st.loginFails) == 0 && st.lastConfig == nil {
			delete(d.devices, host)
		}
	}
	for ip, t := range d.spray {
		if t.newest.Before(now.Add(-d.cfg.SprayWindow)) {
			delete(d.spray, ip)
		}
	}
}

func (d *Detector) observe(e collector.LogEntry) []TriageSignal {
	st := d.state(e.Hostname)
	ts := e.Timestamp
	fresh := d.cfg.Now().Sub(ts) <= d.cfg.MaxSignalAge

	switch e.Event {
	case EventConfigChange, EventAfterHoursChange:
		st.lastConfig = &configChange{user: e.User, at: ts}
		if !fresh {
			return nil
		}
		prio := PriorityLow
		if e.Event == EventAfterHoursChange {
			prio = PriorityMedium
		}
		return []TriageSignal{d.signal(st, e, PlaybookConfigDiff, prio, false)}

	case EventLinkFlap:
		// A previously reported flap (replayed from storage): restore its
		// suppression so the same flap is not reported twice across runs.
		key := ExtractInterface(e.Raw)
		if key == "" {
			key = "?"
		}
		st.flapUntil[key] = ts.Add(d.cfg.FlapSuppress)
		st.linkDowns[key] = nil
		return nil

	case EventPasswordSpray:
		// A previously reported spray (replayed from storage): forget the
		// failures that made it, so the same spray is not reported twice
		// across runs.
		delete(d.spray, e.SourceIP)
		return nil

	case EventLoginFailure:
		return d.observeLoginFailure(st, e, fresh)

	case EventLinkDown:
		return d.observeLinkDown(st, e, fresh)

	case EventOSPFAdjDown:
		return d.simple(st, e, fresh, PlaybookOSPFAdjDown, PriorityHigh)
	case EventBGPPeerDown:
		return d.simple(st, e, fresh, PlaybookBGPPeerDown, PriorityHigh)
	case EventVRRPTransition:
		return d.simple(st, e, fresh, PlaybookVRRPTransition, PriorityMedium)
	case EventSTPTCN:
		return d.simple(st, e, fresh, PlaybookSTPTCN, PriorityLow)
	case EventOpticsAlarm:
		return d.simple(st, e, fresh, PlaybookOpticsAlarm, PriorityMedium)
	case EventHighCPU:
		return d.simple(st, e, fresh, PlaybookHighCPU, PriorityMedium)
	}
	return nil
}

func (d *Detector) simple(st *deviceState, e collector.LogEntry, fresh bool, playbook string, prio int) []TriageSignal {
	if !fresh {
		return nil
	}
	return []TriageSignal{d.signal(st, e, playbook, prio, false)}
}

// signal builds a TriageSignal and attaches the config-correlation note.
func (d *Detector) signal(st *deviceState, e collector.LogEntry, playbook string, prio int, derived bool) TriageSignal {
	s := TriageSignal{Entry: e, Playbook: playbook, Priority: prio, Derived: derived}
	if e.Category == collector.CategoryFault {
		if note := d.correlate(st, e.Timestamp); note != "" {
			s.Annotations = append(s.Annotations, note)
		}
	}
	return s
}

// correlate implements CONFIG_FAULT_CORRELATION.
func (d *Detector) correlate(st *deviceState, faultAt time.Time) string {
	cc := st.lastConfig
	if cc == nil {
		return ""
	}
	delta := faultAt.Sub(cc.at)
	if delta < 0 || delta > d.cfg.CorrelationWindow {
		return ""
	}
	user := cc.user
	if user == "" {
		user = "unknown user"
	}
	return fmt.Sprintf("CONFIG_CHANGE by %s at %s UTC (%s before) preceded this fault",
		user, cc.at.UTC().Format("15:04:05"), shortDuration(delta))
}

// shortDuration renders d to whole seconds without Go's trailing "0s":
// 42s, 1m30s, 5m (not 5m0s).
func shortDuration(d time.Duration) string {
	s := d.Round(time.Second).String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	return s
}

func (d *Detector) observeLinkDown(st *deviceState, e collector.LogEntry, fresh bool) []TriageSignal {
	iface := ExtractInterface(e.Raw)
	key := iface
	if key == "" {
		key = "?"
	}
	ts := e.Timestamp

	// Slide the window and record this event.
	window := pruneBefore(st.linkDowns[key], ts.Add(-d.cfg.FlapWindow))
	window = append(window, ts)
	st.linkDowns[key] = window

	if until, ok := st.flapUntil[key]; ok && ts.Before(until) {
		return nil // already reported as a flap; stay quiet
	}

	if len(window) >= d.cfg.FlapThreshold {
		st.flapUntil[key] = ts.Add(d.cfg.FlapSuppress)
		st.linkDowns[key] = nil
		if !fresh {
			return nil
		}
		flap := e
		flap.ID = collector.EntryID(e.Hostname, "derived:"+EventLinkFlap+":"+e.Raw)
		flap.Event = EventLinkFlap
		name := iface
		if name == "" {
			name = "(interface not identified)"
		}
		flap.Summary = fmt.Sprintf("interface %s flapping: %d link-down events within %s",
			name, len(window), d.cfg.FlapWindow)
		return []TriageSignal{d.signal(st, flap, PlaybookLinkFlap, PriorityHigh, true)}
	}

	if !fresh {
		return nil
	}
	return []TriageSignal{d.signal(st, e, PlaybookLinkDown, PriorityMedium, false)}
}

func (d *Detector) observeLoginFailure(st *deviceState, e collector.LogEntry, fresh bool) []TriageSignal {
	if e.SourceIP == "" {
		return nil // cannot attribute the failure to a source
	}
	sigs := d.observeBurst(st, e, fresh)
	return append(sigs, d.observeSpray(st, e, fresh)...)
}

// observeBurst is the per-device rule: BruteThreshold failures from one
// source on this device within BruteWindow.
func (d *Detector) observeBurst(st *deviceState, e collector.LogEntry, fresh bool) []TriageSignal {
	ts := e.Timestamp
	window := pruneBefore(st.loginFails[e.SourceIP], ts.Add(-d.cfg.BruteWindow))
	window = append(window, ts)
	st.loginFails[e.SourceIP] = window

	if len(window) < d.cfg.BruteThreshold {
		return nil
	}
	st.loginFails[e.SourceIP] = nil
	if !fresh {
		return nil
	}

	bf := e
	bf.ID = collector.EntryID(e.Hostname, "derived:"+EventBruteForce+":"+e.Raw)
	bf.Category = collector.CategorySecurity
	bf.Event = EventBruteForce
	bf.Severity = collector.SeverityCritical
	bf.Summary = fmt.Sprintf("%d failed logins from %s within %s", len(window), e.SourceIP, d.cfg.BruteWindow)
	return []TriageSignal{d.signal(st, bf, PlaybookBruteForce, PriorityCritical, true)}
}

// maxSprayNames bounds how many device names a spray summary lists.
const maxSprayNames = 5

// observeSpray is the fleet-wide rule: one source failing logins on
// SprayDevices distinct devices within SprayWindow. The tally is cleared when
// the rule trips, so a continuing spray is reported again only after another
// SprayDevices devices have been hit.
func (d *Detector) observeSpray(st *deviceState, e collector.LogEntry, fresh bool) []TriageSignal {
	t := d.spray[e.SourceIP]
	if t == nil {
		t = &sprayTally{}
		d.spray[e.SourceIP] = t
	}
	if e.Timestamp.After(t.newest) {
		t.newest = e.Timestamp
	}
	cutoff := t.newest.Add(-d.cfg.SprayWindow)
	if e.Timestamp.Before(cutoff) {
		return nil
	}
	kept := t.hits[:0]
	for _, h := range t.hits {
		if !h.at.Before(cutoff) {
			kept = append(kept, h)
		}
	}
	t.hits = append(kept, sprayHit{host: e.Hostname, at: e.Timestamp})

	seen := make(map[string]struct{}, len(t.hits))
	for _, h := range t.hits {
		seen[h.host] = struct{}{}
	}
	if len(seen) < d.cfg.SprayDevices {
		return nil
	}
	delete(d.spray, e.SourceIP)
	if !fresh {
		return nil
	}

	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	names := strings.Join(hosts, ", ")
	if len(hosts) > maxSprayNames {
		names = strings.Join(hosts[:maxSprayNames], ", ") + fmt.Sprintf(" and %d more", len(hosts)-maxSprayNames)
	}

	sp := e
	sp.ID = collector.EntryID(e.Hostname, "derived:"+EventPasswordSpray+":"+e.Raw)
	sp.Category = collector.CategorySecurity
	sp.Event = EventPasswordSpray
	sp.Severity = collector.SeverityCritical
	sp.Summary = fmt.Sprintf("failed logins from %s on %d devices (%s) within %s", e.SourceIP, len(hosts), names, d.cfg.SprayWindow)
	return []TriageSignal{d.signal(st, sp, PlaybookBruteForce, PriorityHigh, true)}
}

// pruneBefore drops leading times earlier than cutoff (times arrive in order).
func pruneBefore(times []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(times) && times[i].Before(cutoff) {
		i++
	}
	return times[i:]
}

// ==============================================================================
// Interface and peer extraction (shared with the triage playbooks)
// ==============================================================================

// interfacePatterns are tried in order; the first capture wins.
var interfacePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bifName\s+([A-Za-z][\w/.:-]*\d)`),                                                                  // Junos SNMP link trap
	regexp.MustCompile(`(?i)\binterface\s+([A-Za-z][\w/.:-]*\d)\b`),                                                             // Cisco, Huawei, Arista
	regexp.MustCompile(`(?i)\binterface\s+(\d+(?:/\d+)+)\b`),                                                                    // Aruba CX "1/1/24"
	regexp.MustCompile(`\bon\s+([A-Za-z][A-Za-z0-9/.:_-]*\d)\b`),                                                                // OSPF "... on Gi0/1 ..."
	regexp.MustCompile(`\b((?:eth|ens|enp|eno|bond|br|vti|tun|wg|veth|vxlan|dum|lo)\d[\w./:-]*)`),                               // Linux / VyOS
	regexp.MustCompile(`\b(ether\d+|sfp[\w-]*\d+|bridge\d*|vlan\d+)\b`),                                                         // MikroTik
	regexp.MustCompile(`\b([A-Za-z]{2,}-?\d+(?:/\d+)+(?:\.\d+)?)`),                                                              // Gi0/1, ge-0/0/1, 1/0/24
	regexp.MustCompile(`\b((?:igb|ixl|ix|em|re|bge|bce|vtnet|vmx|mlxen|lagg|ovpnc|ovpns|enc|gif|gre|pppoe|ng)\d+(?:\.\d+)?)\b`), // FreeBSD / pfSense
}

var peerPattern = regexp.MustCompile(`(?i)\b(?:neighbor|nbr|peer)(?:\s+address)?[\s=:]+([0-9a-fA-F:.]+)\b`)

// ExtractInterface returns the interface name mentioned in a log line, or ""
// if none can be identified. The result contains only letters, digits and
// "/ . : _ -", so it is safe to substitute into a diagnostic command.
func ExtractInterface(raw string) string {
	for _, re := range interfacePatterns {
		if m := re.FindStringSubmatch(raw); m != nil {
			if name := cleanInterface(m[1]); name != "" {
				return name
			}
		}
	}
	return ""
}

// cleanInterface trims trailing punctuation and cuts FRR-style
// "eth1:10.0.0.1" (interface:address) back to the interface.
func cleanInterface(s string) string {
	s = strings.TrimRight(s, ".:,;")
	if i := strings.IndexByte(s, ':'); i > 0 {
		if net.ParseIP(s[i+1:]) != nil {
			s = s[:i]
		}
	}
	return s
}

// ExtractPeer returns the neighbor/peer IP address (IPv4 or IPv6) mentioned in a log
// line, or "".
func ExtractPeer(raw string) string {
	if m := peerPattern.FindStringSubmatch(raw); m != nil {
		cand := strings.TrimRight(m[1], ".:,;)")
		if ip := net.ParseIP(cand); ip != nil {
			if strings.Contains(cand, ".") || strings.Contains(cand, ":") {
				return cand
			}
		}
	}
	return ""
}
