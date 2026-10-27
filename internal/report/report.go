// ==============================================================================
// Package report: fleet-wide rollups, rankings and trends over stored netlog data.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-24
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         rep := report.Compute(entries, incidents, report.Options{Since: from, Until: now})
// Notes:         Go package implementation
// ==============================================================================
// Package report answers "is my network doing something unusual?", where
// "netlog query" and "netlog timeline" answer "what happened at 10:22:15 on
// SW-LAB?". It aggregates the entries and incident reports that are already
// on disk over a time window into nine sections:
//
//  1. noisy devices          FAULT events per device
//  2. change accountability  CONFIG_CHANGE / AFTER_HOURS_CHANGE per user
//  3. security watchlist     source IPs that hit more than one device
//  4. event volume           a category x UTC-day count matrix
//  5. week-over-week         per-category percent change against the prior window
//  6. triage reach           how many triage runs could not reach the device
//  7. outages                link / OSPF / BGP downs paired with their recovery
//  8. device health          devices netlog cannot poll, or that never log
//  9. classification coverage  the share of each vendor's lines left UNKNOWN
//
// A Builder accumulates a report one entry at a time, so memory is bounded by
// the number of distinct devices, source addresses and users, not by how many
// log lines the window holds. Compute is the same thing over slices. Neither
// performs file I/O, reads a clock or mutates its input: the caller streams
// the data in (query.Scan, store.ListIncidents) and hands over the device
// health it read, which keeps the package testable on in-memory fixtures.
//
// The security watchlist is the one genuinely new computation. It groups by
// source IP across every device and every day in the window, which no single
// device's view, and no single run of the in-memory anomaly detector, can see.
//
// Every ranking has a fully deterministic order (primary key descending, then
// an explicit tie-break), so the output can be diffed and the tests are not
// flaky, and the result does not depend on the order entries arrive in.
// Nothing here classifies or triages; the package deliberately does not
// import internal/pipeline or internal/triage.
package report

import (
	"math"
	"net/netip"
	"sort"
	"strings"
	"time"

	"netlog/internal/collector"
)

// DefaultTop is how many rows the noisy-device and watchlist rankings keep
// when Options.Top is not set.
const DefaultTop = 10

// Week is the window length for which the week-over-week section is computed
// by default.
const Week = 7 * 24 * time.Hour

// UnknownUser is the bucket for change events that carry no user name.
const UnknownUser = "(unknown)"

// Event names Compute reads. They are spelled out rather than imported from
// internal/pipeline, which this package must not depend on (internal/query's
// timeline does the same).
const (
	eventConfigChange     = "CONFIG_CHANGE"
	eventAfterHoursChange = "AFTER_HOURS_CHANGE"
	eventLoginFailure     = "LOGIN_FAILURE"
	eventBruteForce       = "BRUTE_FORCE_ATTEMPT"    // derived: many failures on one device
	eventPasswordSpray    = "PASSWORD_SPRAY_ATTEMPT" // derived: failures on several devices
	eventUnknown          = "UNKNOWN"
)

// connectCommand is the DiagCmd.Command that triage records when it could not
// reconnect to the device, so no diagnostic was collected at all.
const connectCommand = "(connect)"

// maxVolumeDays bounds the rows of the volume matrix, mirroring the scan limit
// in internal/query.
const maxVolumeDays = 3660

// categories is the fixed column order of the volume and delta sections.
var categories = []string{
	collector.CategoryConfig,
	collector.CategoryAuth,
	collector.CategoryFault,
	collector.CategorySecurity,
	collector.CategorySystem,
}

// ==============================================================================
// Data model
// ==============================================================================

// Options selects what Compute reports on.
type Options struct {
	// Since and Until bound the requested window; both ends are inclusive,
	// like query.Filter. A zero value leaves that end open. Incidents and
	// entries outside the window are ignored, so callers may pass more.
	Since time.Time
	Until time.Time

	// Top caps the noisy-device and security-watchlist rankings. Zero or
	// negative means DefaultTop.
	Top int

	// Compare enables the week-over-week section. It compares the window
	// against the equal-length window ending where it begins, which for a
	// 7-day window is [Until-14d, Until-7d) against [Until-7d, Until]. The
	// caller must supply entries back to Since minus the window length. It
	// is ignored unless both Since and Until are set.
	Compare bool

	// Label is how the caller spelled the window ("7d", "today"). It is used
	// in table headings only; when empty it is derived from Since and Until.
	Label string

	// Devices is netlog's current view of each device's collection health,
	// from DeviceStatuses. It is a snapshot of now, not of the window, and is
	// optional: without it the Device Health section is empty.
	Devices []DeviceStatus
}

func (o Options) top() int {
	if o.Top <= 0 {
		return DefaultTop
	}
	return o.Top
}

// Report is the result of Compute or Builder.Build. Each field except Options
// is one section and one key of the JSON output.
type Report struct {
	NoisyDevices         []DeviceFaultCount   `json:"noisy_devices"`
	ChangeAccountability ChangeAccountability `json:"change_accountability"`
	SecurityWatchlist    []WatchedSource      `json:"security_watchlist"`
	VolumeByCategory     VolumeByCategory     `json:"volume_by_category"`
	WeekOverWeek         *WeekOverWeek        `json:"week_over_week"` // null when not computed

	// IncidentClosure is the "Triage Reach" section. Its JSON key predates the
	// name: the section measures whether triage could reach the device, not
	// whether the problem was resolved (that is what Outages is for).
	IncidentClosure IncidentClosure `json:"incident_closure"`

	Outages                Outages          `json:"outages"`
	DeviceHealth           DeviceHealth     `json:"device_health"`
	ClassificationCoverage []VendorCoverage `json:"classification_coverage"`

	// Options is the (normalised) request the report answers. The table
	// writer needs it for headings; it is not part of the JSON output.
	Options Options `json:"-"`
}

// DeviceFaultCount is one row of the noisy-device ranking.
type DeviceFaultCount struct {
	Hostname string `json:"hostname"`
	Count    int    `json:"count"`
}

// UserChangeCount is one row of the change-accountability table.
type UserChangeCount struct {
	User       string   `json:"user"`
	Count      int      `json:"count"`       // CONFIG_CHANGE + AFTER_HOURS_CHANGE
	AfterHours int      `json:"after_hours"` // of which AFTER_HOURS_CHANGE
	Hostnames  []string `json:"hostnames"`   // devices changed by this user
}

// AfterHoursChange is one AFTER_HOURS_CHANGE event.
type AfterHoursChange struct {
	Hostname  string    `json:"hostname"`
	User      string    `json:"user"`
	Timestamp time.Time `json:"timestamp"`
}

// ChangeAccountability answers "who changed what, and who did it at night".
type ChangeAccountability struct {
	Total           int                `json:"total"`
	ByUser          []UserChangeCount  `json:"by_user"`
	AfterHoursCount int                `json:"after_hours_count"`
	AfterHours      []AfterHoursChange `json:"after_hours"` // newest first
}

// WatchedSource is one source IP in the security watchlist.
type WatchedSource struct {
	SourceIP      string `json:"source_ip"`
	DistinctHosts int    `json:"distinct_hosts"` // devices this IP failed to log in to
	Events        int    `json:"events"`         // LOGIN_FAILURE events
	// Detections counts the events netlog derived from those failures
	// (BRUTE_FORCE_ATTEMPT, PASSWORD_SPRAY_ATTEMPT). They are kept apart from
	// Events because each one is a summary of failures already counted there,
	// and adding it in would overstate the attack by one per detection.
	Detections int      `json:"detections"`
	Hostnames  []string `json:"hostnames"`
}

// VolumeByCategory maps a UTC day ("2006-01-02") to the number of events in
// each category on that day. Every day in the window is present and every
// category is present in every day, with zeros filled in. It is empty when the
// window holds no events.
type VolumeByCategory map[string]map[string]int

// CategoryDelta compares one category across the two windows.
type CategoryDelta struct {
	Category string `json:"category"`
	Previous int    `json:"previous"`
	Current  int    `json:"current"`
	Change   int    `json:"change"`
	// ChangePct is (current - previous) / previous * 100, rounded to one
	// decimal. It is nil (JSON null, "n/a" in the table) when previous is 0.
	ChangePct *float64 `json:"change_pct"`
}

// WeekOverWeek is the delta section: the window against the one before it.
type WeekOverWeek struct {
	PreviousFrom time.Time       `json:"previous_from"`
	CurrentFrom  time.Time       `json:"current_from"`
	CurrentTo    time.Time       `json:"current_to"`
	Categories   []CategoryDelta `json:"categories"`
	Total        CategoryDelta   `json:"total"`
}

// UnreachableHost is a device whose triage runs could not reach it.
type UnreachableHost struct {
	Hostname    string `json:"hostname"`
	Unreachable int    `json:"unreachable"` // incidents where reconnecting failed
	Incidents   int    `json:"incidents"`   // all incidents for the device in the window
	// Always is true when every incident for the device was unreachable.
	// A device that is unreachable each time it has an incident is itself a
	// finding.
	Always bool `json:"always"`
}

// IncidentClosure splits the window's incidents by whether triage got its
// diagnostics. The three outcomes are exclusive and sum to Total.
type IncidentClosure struct {
	Total int `json:"total"`

	// Succeeded: every diagnostic command ran without error.
	Succeeded    int     `json:"succeeded"`
	SucceededPct float64 `json:"succeeded_pct"`

	// Unreachable: a "(connect)" diagnostic carries an error, i.e. triage
	// could not reach the device at all.
	Unreachable    int     `json:"unreachable"`
	UnreachablePct float64 `json:"unreachable_pct"`

	// PartialFailure: the device was reached but at least one diagnostic
	// command failed.
	PartialFailure    int     `json:"partial_failure"`
	PartialFailurePct float64 `json:"partial_failure_pct"`

	UnreachableHosts []UnreachableHost `json:"unreachable_hosts"`
}

// Outage is one interval during which a link, OSPF adjacency or BGP session
// was down: from a "down" event to the next "up" event for the same object on
// the same device.
type Outage struct {
	Hostname string     `json:"hostname"`
	Kind     string     `json:"kind"`   // link | ospf | bgp
	Object   string     `json:"object"` // the interface, or the neighbor / peer address
	Down     time.Time  `json:"down"`
	Up       *time.Time `json:"up"` // null while still down at the end of the window
	// DurationSeconds runs from Down to Up. For an outage still open it runs
	// to the end of the window, so it is a lower bound.
	DurationSeconds int64 `json:"duration_seconds"`
	Open            bool  `json:"open"`
}

// Outages summarises the outages in the window.
type Outages struct {
	Total    int `json:"total"`
	Resolved int `json:"resolved"`
	Open     int `json:"open"`

	// MeanSecondsToRecover is the arithmetic mean over resolved outages only
	// (0 when there are none). LongestSeconds is over all of them.
	MeanSecondsToRecover int64 `json:"mean_seconds_to_recover"`
	LongestSeconds       int64 `json:"longest_seconds"`

	// Untracked counts "down" events whose log line names no interface or
	// neighbor, so no recovery can be matched to them.
	Untracked int `json:"untracked"`

	// Longest is the top-N outages by duration, open ones included.
	Longest []Outage `json:"longest"`
}

// VendorCoverage is how much of one vendor's log netlog understands.
type VendorCoverage struct {
	Vendor string `json:"vendor"`
	Lines  int    `json:"lines"`
	// Unclassified counts lines the classifier left as UNKNOWN. A high share
	// means the vendor's log has events netlog has no rule for.
	Unclassified    int     `json:"unclassified"`
	UnclassifiedPct float64 `json:"unclassified_pct"`
}

// ==============================================================================
// Builder
// ==============================================================================

// Compute builds the report for opts from entries and incidents. It is
// NewBuilder, AddEntry for each entry, AddIncident for each incident and
// Build; it does no I/O and does not modify its arguments.
func Compute(entries []collector.LogEntry, incidents []collector.IncidentReport, opts Options) Report {
	b := NewBuilder(opts)
	for _, e := range entries {
		b.AddEntry(e)
	}
	for _, r := range incidents {
		b.AddIncident(r)
	}
	return b.Build()
}

// Builder accumulates a Report one entry at a time. Entries may arrive in any
// order and outside the window (they are ignored), so a caller can stream
// everything query.Scan yields. The window rules are:
//
// Sections 1-4 and 6-9 cover [Since, Until], both ends inclusive. The
// week-over-week section also reads the equal-length window before Since,
// which is half-open, [Since-w, Since), so an event exactly on the boundary
// is counted once, in the later window.
//
// A Builder is not safe for concurrent use.
type Builder struct {
	opts Options

	compare  bool      // week-over-week is wanted and the window is bounded
	prevFrom time.Time // start of the previous window (compare only)
	prev     map[string]int
	cur      map[string]int

	faults map[string]int // FAULT events per device

	changeTotal int
	changes     map[string]*changeTally
	afterHours  []AfterHoursChange

	watch map[string]*watchTally

	volume      map[string]map[string]int
	volumeKnown int       // current-window entries in one of the five categories
	first, last time.Time // earliest / latest current-window entry
	seen        bool

	coverage map[string]*coverageTally

	outageEvents []outageEvent
	untracked    int

	incidents     IncidentClosure
	incidentHosts map[string]*incidentTally
}

type changeTally struct {
	hosts      map[string]struct{}
	total      int
	afterHours int
}

type watchTally struct {
	hosts      map[string]struct{}
	events     int
	detections int
}

type coverageTally struct{ lines, unknown int }

type incidentTally struct{ incidents, unreachable int }

type outageEvent struct {
	host, kind, object string
	at                 time.Time
	up                 bool
}

// outageKinds maps the paired state-change events to the kind of thing that
// went down and whether the event is the recovery.
var outageKinds = map[string]struct {
	kind string
	up   bool
}{
	"LINK_DOWN":     {"link", false},
	"LINK_UP":       {"link", true},
	"OSPF_ADJ_DOWN": {"ospf", false},
	"OSPF_ADJ_UP":   {"ospf", true},
	"BGP_PEER_DOWN": {"bgp", false},
	"BGP_PEER_UP":   {"bgp", true},
}

// NewBuilder returns a Builder for opts.
func NewBuilder(opts Options) *Builder {
	opts.Top = opts.top()
	b := &Builder{
		opts:          opts,
		faults:        make(map[string]int),
		changes:       make(map[string]*changeTally),
		watch:         make(map[string]*watchTally),
		volume:        make(map[string]map[string]int),
		coverage:      make(map[string]*coverageTally),
		incidentHosts: make(map[string]*incidentTally),
	}
	if opts.Compare && !opts.Since.IsZero() && !opts.Until.IsZero() && opts.Until.After(opts.Since) {
		b.compare = true
		b.prevFrom = opts.Since.Add(-opts.Until.Sub(opts.Since))
		b.prev = make(map[string]int, len(categories))
		b.cur = make(map[string]int, len(categories))
	}
	return b
}

// AddEntry feeds one log entry to every section it belongs to.
func (b *Builder) AddEntry(e collector.LogEntry) {
	ts := e.Timestamp
	inCur := inWindow(ts, b.opts.Since, b.opts.Until)

	cat := categoryOf(e)
	if b.compare && isCategory(cat) {
		switch {
		case inCur:
			b.cur[cat]++
		case !ts.Before(b.prevFrom) && ts.Before(b.opts.Since):
			b.prev[cat]++
		}
	}
	if !inCur {
		return
	}

	if !b.seen || ts.Before(b.first) {
		b.first = ts
	}
	if !b.seen || ts.After(b.last) {
		b.last = ts
	}
	b.seen = true

	// 1. noisy devices
	if cat == collector.CategoryFault {
		b.faults[e.Hostname]++
	}

	// 2. change accountability
	switch e.Event {
	case eventConfigChange, eventAfterHoursChange:
		after := e.Event == eventAfterHoursChange
		u := userKey(e.User)
		t := b.changes[u]
		if t == nil {
			t = &changeTally{hosts: make(map[string]struct{})}
			b.changes[u] = t
		}
		if t.hosts == nil {
			t.hosts = make(map[string]struct{})
		}
		if h := strings.TrimSpace(e.Hostname); h != "" {
			t.hosts[h] = struct{}{}
		}
		t.total++
		b.changeTotal++
		if after {
			t.afterHours++
			b.afterHours = append(b.afterHours, AfterHoursChange{Hostname: e.Hostname, User: u, Timestamp: ts.UTC()})
		}
	}

	// 3. security watchlist
	switch e.Event {
	case eventLoginFailure, eventBruteForce, eventPasswordSpray:
		if ip := strings.TrimSpace(e.SourceIP); ip != "" {
			t := b.watch[ip]
			if t == nil {
				t = &watchTally{hosts: make(map[string]struct{})}
				b.watch[ip] = t
			}
			t.hosts[e.Hostname] = struct{}{}
			if e.Event == eventLoginFailure {
				t.events++
			} else {
				t.detections++
			}
		}
	}

	// 4. event volume
	if isCategory(cat) {
		b.volumeKnown++
		day := ts.UTC().Format(dayLayout)
		row := b.volume[day]
		if row == nil {
			row = make(map[string]int, len(categories))
			b.volume[day] = row
		}
		row[cat]++
	}

	// 7. outages
	if k, ok := outageKinds[e.Event]; ok {
		if e.Object == "" {
			if !k.up {
				b.untracked++
			}
		} else {
			b.outageEvents = append(b.outageEvents, outageEvent{host: e.Hostname, kind: k.kind, object: e.Object, at: ts, up: k.up})
		}
	}

	// 9. classification coverage
	v := strings.TrimSpace(e.Vendor)
	if v == "" {
		v = "(unknown)"
	}
	c := b.coverage[v]
	if c == nil {
		c = &coverageTally{}
		b.coverage[v] = c
	}
	c.lines++
	if e.Event == eventUnknown || e.Event == "" {
		c.unknown++
	}
}

// AddIncident feeds one incident report to the triage-reach section.
func (b *Builder) AddIncident(r collector.IncidentReport) {
	if !inWindow(r.Timestamp, b.opts.Since, b.opts.Until) {
		return
	}
	t := b.incidentHosts[r.Hostname]
	if t == nil {
		t = &incidentTally{}
		b.incidentHosts[r.Hostname] = t
	}
	t.incidents++
	b.incidents.Total++
	switch classify(r) {
	case outcomeUnreachable:
		b.incidents.Unreachable++
		t.unreachable++
	case outcomePartial:
		b.incidents.PartialFailure++
	default:
		b.incidents.Succeeded++
	}
}

// Build finishes the report. It can be called more than once.
func (b *Builder) Build() Report {
	return Report{
		NoisyDevices:           b.noisyDevices(),
		ChangeAccountability:   b.changeAccountability(),
		SecurityWatchlist:      b.securityWatchlist(),
		VolumeByCategory:       b.volumeByCategory(),
		WeekOverWeek:           b.weekOverWeek(),
		IncidentClosure:        b.incidentClosure(),
		Outages:                b.outages(),
		DeviceHealth:           buildDeviceHealth(b.opts.Devices),
		ClassificationCoverage: b.classificationCoverage(),
		Options:                b.opts,
	}
}

// ==============================================================================
// Shared helpers
// ==============================================================================

// inWindow reports whether ts lies in [since, until]; a zero bound is open.
func inWindow(ts, since, until time.Time) bool {
	if !since.IsZero() && ts.Before(since) {
		return false
	}
	if !until.IsZero() && ts.After(until) {
		return false
	}
	return true
}

// categoryOf returns the entry's category normalised the way query.Filter
// compares it (case-insensitively).
func categoryOf(e collector.LogEntry) string {
	return strings.ToUpper(strings.TrimSpace(e.Category))
}

func isCategory(c string) bool {
	for _, k := range categories {
		if c == k {
			return true
		}
	}
	return false
}

// lessFold orders strings case-insensitively, falling back to byte order so
// two distinct strings never compare equal.
func lessFold(a, b string) bool {
	la, lb := strings.ToLower(a), strings.ToLower(b)
	if la != lb {
		return la < lb
	}
	return a < b
}

// lessIP orders source addresses numerically ("10.0.0.9" before "10.0.0.10").
// Text that is not an IP address sorts after every address.
func lessIP(a, b string) bool {
	pa, errA := netip.ParseAddr(a)
	pb, errB := netip.ParseAddr(b)
	switch {
	case errA == nil && errB == nil:
		if c := pa.Compare(pb); c != 0 {
			return c < 0
		}
		return a < b
	case errA == nil:
		return true
	case errB == nil:
		return false
	}
	return lessFold(a, b)
}

func limit[T any](s []T, n int) []T {
	if n > 0 && len(s) > n {
		return s[:n]
	}
	return s
}

// round1 rounds to one decimal place and never returns negative zero.
func round1(f float64) float64 {
	r := math.Round(f*10) / 10
	if r == 0 {
		return 0
	}
	return r
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return round1(float64(n) * 100 / float64(total))
}

func userKey(u string) string {
	if strings.TrimSpace(u) == "" {
		return UnknownUser
	}
	return u
}

const dayLayout = "2006-01-02"

// ==============================================================================
// 1. Noisy devices
// ==============================================================================

// noisyDevices ranks devices by FAULT events, most first, ties by hostname.
func (b *Builder) noisyDevices() []DeviceFaultCount {
	out := make([]DeviceFaultCount, 0, len(b.faults))
	for host, n := range b.faults {
		out = append(out, DeviceFaultCount{Hostname: host, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return lessFold(out[i].Hostname, out[j].Hostname)
	})
	return limit(out, b.opts.Top)
}

// ==============================================================================
// 2. Change accountability
// ==============================================================================

// changeAccountability orders users by change count. The (unknown) bucket
// sorts last whatever its count.
func (b *Builder) changeAccountability() ChangeAccountability {
	ca := ChangeAccountability{
		Total:      b.changeTotal,
		ByUser:     make([]UserChangeCount, 0, len(b.changes)),
		AfterHours: append([]AfterHoursChange{}, b.afterHours...),
	}
	ca.AfterHoursCount = len(ca.AfterHours)
	for u, t := range b.changes {
		hosts := make([]string, 0, len(t.hosts))
		for h := range t.hosts {
			hosts = append(hosts, h)
		}
		sort.Slice(hosts, func(i, j int) bool { return lessFold(hosts[i], hosts[j]) })
		ca.ByUser = append(ca.ByUser, UserChangeCount{
			User:       u,
			Count:      t.total,
			AfterHours: t.afterHours,
			Hostnames:  hosts,
		})
	}
	sort.Slice(ca.ByUser, func(i, j int) bool {
		a, c := ca.ByUser[i], ca.ByUser[j]
		if (a.User == UnknownUser) != (c.User == UnknownUser) {
			return c.User == UnknownUser
		}
		if a.Count != c.Count {
			return a.Count > c.Count
		}
		return lessFold(a.User, c.User)
	})
	sort.Slice(ca.AfterHours, func(i, j int) bool {
		a, c := ca.AfterHours[i], ca.AfterHours[j]
		if !a.Timestamp.Equal(c.Timestamp) {
			return a.Timestamp.After(c.Timestamp)
		}
		if a.Hostname != c.Hostname {
			return lessFold(a.Hostname, c.Hostname)
		}
		return lessFold(a.User, c.User)
	})
	return ca
}

// ==============================================================================
// 3. Security watchlist
// ==============================================================================

// securityWatchlist ranks each source IP by how many distinct devices it
// touched, then by failed logins, then by detections, then by address.
func (b *Builder) securityWatchlist() []WatchedSource {
	out := make([]WatchedSource, 0, len(b.watch))
	for ip, t := range b.watch {
		hosts := make([]string, 0, len(t.hosts))
		for h := range t.hosts {
			hosts = append(hosts, h)
		}
		sort.Slice(hosts, func(i, j int) bool { return lessFold(hosts[i], hosts[j]) })
		out = append(out, WatchedSource{SourceIP: ip, DistinctHosts: len(hosts), Events: t.events, Detections: t.detections, Hostnames: hosts})
	}
	sort.Slice(out, func(i, j int) bool {
		a, c := out[i], out[j]
		if a.DistinctHosts != c.DistinctHosts {
			return a.DistinctHosts > c.DistinctHosts
		}
		if a.Events != c.Events {
			return a.Events > c.Events
		}
		if a.Detections != c.Detections {
			return a.Detections > c.Detections
		}
		return lessIP(a.SourceIP, c.SourceIP)
	})
	return limit(out, b.opts.Top)
}

// ==============================================================================
// 4. Event volume by category and day
// ==============================================================================

// volumeByCategory counts events per UTC day and category. Every UTC day from
// the window's start to its end gets a row, including days with no events, so
// a gap in collection is visible rather than silently skipped. A window with
// no events yields an empty (non-nil) map.
func (b *Builder) volumeByCategory() VolumeByCategory {
	vol := VolumeByCategory{}
	if b.volumeKnown == 0 {
		return vol
	}
	// An open end of the window falls back to the first/last entry.
	start, end := b.opts.Since, b.opts.Until
	if start.IsZero() {
		start = b.first
	}
	if end.IsZero() {
		end = b.last
	}

	day := start.UTC().Truncate(24 * time.Hour)
	lastDay := end.UTC().Truncate(24 * time.Hour)
	for n := 0; !day.After(lastDay) && n < maxVolumeDays; n++ {
		row := make(map[string]int, len(categories))
		for _, c := range categories {
			row[c] = b.volume[day.Format(dayLayout)][c]
		}
		vol[day.Format(dayLayout)] = row
		day = day.AddDate(0, 0, 1)
	}
	return vol
}

// ==============================================================================
// 5. Week-over-week delta
// ==============================================================================

// weekOverWeek compares per-category event counts in [Since, Until] with the
// equal-length window before it, [Since-w, Since). It is the only statistic in
// the report: (current - previous) / previous * 100, and nil when previous is
// zero rather than a division by zero or an infinity. It returns nil when the
// comparison was not requested or the window is not fully bounded.
func (b *Builder) weekOverWeek() *WeekOverWeek {
	if !b.compare {
		return nil
	}
	w := &WeekOverWeek{
		PreviousFrom: b.prevFrom.UTC(),
		CurrentFrom:  b.opts.Since.UTC(),
		CurrentTo:    b.opts.Until.UTC(),
		Categories:   make([]CategoryDelta, 0, len(categories)),
	}
	var prevTotal, curTotal int
	for _, c := range categories {
		w.Categories = append(w.Categories, delta(c, b.prev[c], b.cur[c]))
		prevTotal += b.prev[c]
		curTotal += b.cur[c]
	}
	w.Total = delta("TOTAL", prevTotal, curTotal)
	return w
}

func delta(category string, previous, current int) CategoryDelta {
	d := CategoryDelta{Category: category, Previous: previous, Current: current, Change: current - previous}
	if previous != 0 {
		p := round1(float64(current-previous) / float64(previous) * 100)
		d.ChangePct = &p
	}
	return d
}

// ==============================================================================
// 6. Triage reach
// ==============================================================================

type outcome int

const (
	outcomeSucceeded outcome = iota
	outcomeUnreachable
	outcomePartial
)

// classify decides how an incident's triage went. A failed "(connect)" means
// no diagnostics were collected at all, so it outranks a failed command.
func classify(r collector.IncidentReport) outcome {
	failed := false
	for _, d := range r.Diagnostics {
		if d.Error == "" {
			continue
		}
		if d.Command == connectCommand {
			return outcomeUnreachable
		}
		failed = true
	}
	if failed {
		return outcomePartial
	}
	return outcomeSucceeded
}

// incidentClosure reports how many incidents triage could not reach the
// device for, and which devices those were.
func (b *Builder) incidentClosure() IncidentClosure {
	ic := b.incidents
	ic.UnreachableHosts = []UnreachableHost{}
	ic.SucceededPct = pct(ic.Succeeded, ic.Total)
	ic.UnreachablePct = pct(ic.Unreachable, ic.Total)
	ic.PartialFailurePct = pct(ic.PartialFailure, ic.Total)

	for host, t := range b.incidentHosts {
		if t.unreachable == 0 {
			continue
		}
		ic.UnreachableHosts = append(ic.UnreachableHosts, UnreachableHost{
			Hostname: host, Unreachable: t.unreachable, Incidents: t.incidents, Always: t.unreachable == t.incidents,
		})
	}
	sort.Slice(ic.UnreachableHosts, func(i, j int) bool {
		a, c := ic.UnreachableHosts[i], ic.UnreachableHosts[j]
		if a.Unreachable != c.Unreachable {
			return a.Unreachable > c.Unreachable
		}
		return lessFold(a.Hostname, c.Hostname)
	})
	return ic
}

// ==============================================================================
// 7. Outages
// ==============================================================================

// outages pairs every "down" with the next "up" for the same device, kind and
// object. A second "down" while one is open is ignored (Cisco logs both the
// link and the line protocol for one event), as is an "up" with nothing open
// (the outage began before the window). What is still open at the end of the
// window is reported as open.
func (b *Builder) outages() Outages {
	events := append([]outageEvent(nil), b.outageEvents...)
	sort.Slice(events, func(i, j int) bool {
		a, c := events[i], events[j]
		switch {
		case a.host != c.host:
			return a.host < c.host
		case a.kind != c.kind:
			return a.kind < c.kind
		case a.object != c.object:
			return a.object < c.object
		case !a.at.Equal(c.at):
			return a.at.Before(c.at)
		}
		return !a.up && c.up // within one instant a down precedes its up
	})

	end := b.opts.Until
	if end.IsZero() {
		end = b.last
	}

	var all []Outage
	var open *Outage
	flush := func() {
		if open != nil {
			if d := end.Sub(open.Down); d > 0 {
				open.DurationSeconds = int64(d / time.Second)
			}
			open.Open = true
			all = append(all, *open)
			open = nil
		}
	}
	for i, e := range events {
		if i > 0 && (e.host != events[i-1].host || e.kind != events[i-1].kind || e.object != events[i-1].object) {
			flush()
		}
		switch {
		case !e.up && open == nil:
			open = &Outage{Hostname: e.host, Kind: e.kind, Object: e.object, Down: e.at.UTC()}
		case e.up && open != nil:
			up := e.at.UTC()
			open.Up = &up
			open.DurationSeconds = int64(e.at.Sub(open.Down.UTC()) / time.Second)
			all = append(all, *open)
			open = nil
		}
	}
	flush()

	res := Outages{Total: len(all), Untracked: b.untracked, Longest: []Outage{}}
	var sum int64
	for _, o := range all {
		if o.Open {
			res.Open++
		} else {
			res.Resolved++
			sum += o.DurationSeconds
		}
		if o.DurationSeconds > res.LongestSeconds {
			res.LongestSeconds = o.DurationSeconds
		}
	}
	if res.Resolved > 0 {
		res.MeanSecondsToRecover = int64(math.Round(float64(sum) / float64(res.Resolved)))
	}

	sort.Slice(all, func(i, j int) bool {
		a, c := all[i], all[j]
		switch {
		case a.DurationSeconds != c.DurationSeconds:
			return a.DurationSeconds > c.DurationSeconds
		case a.Hostname != c.Hostname:
			return lessFold(a.Hostname, c.Hostname)
		case a.Kind != c.Kind:
			return a.Kind < c.Kind
		case a.Object != c.Object:
			return a.Object < c.Object
		}
		return a.Down.Before(c.Down)
	})
	res.Longest = append(res.Longest, limit(all, b.opts.Top)...)
	return res
}

// ==============================================================================
// 9. Classification coverage
// ==============================================================================

// classificationCoverage reports, per vendor, how many lines the classifier
// left as UNKNOWN, worst first. It is how to tell which vendor's log needs
// more rules.
func (b *Builder) classificationCoverage() []VendorCoverage {
	out := make([]VendorCoverage, 0, len(b.coverage))
	for v, c := range b.coverage {
		out = append(out, VendorCoverage{Vendor: v, Lines: c.lines, Unclassified: c.unknown, UnclassifiedPct: pct(c.unknown, c.lines)})
	}
	sort.Slice(out, func(i, j int) bool {
		a, c := out[i], out[j]
		if a.Unclassified != c.Unclassified {
			return a.Unclassified > c.Unclassified
		}
		return lessFold(a.Vendor, c.Vendor)
	})
	return out
}
