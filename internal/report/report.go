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
// on disk over a time window into six sections:
//
//  1. noisy devices        FAULT events per device
//  2. change accountability CONFIG_CHANGE / AFTER_HOURS_CHANGE per user
//  3. security watchlist   source IPs that hit more than one device
//  4. event volume         a category x UTC-day count matrix
//  5. week-over-week       per-category percent change against the prior window
//  6. incident closure     how many triage runs could not reach the device
//
// Compute is a pure function of its arguments: it performs no file I/O, reads
// no clock and mutates nothing, so it is tested on in-memory fixtures. The
// caller loads the data with query.Load and store.ListIncidents, exactly as
// "netlog query" and "netlog incidents" do. The security watchlist is the one
// genuinely new computation. It groups by source IP across every device and
// every day in the window, which no single device's view, and no single run
// of the in-memory anomaly detector, can see.
//
// Every ranking has a fully deterministic order (primary key descending, then
// an explicit tie-break), so the output can be diffed and the tests are not
// flaky. Nothing here classifies or triages; the package deliberately does not
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
	eventBruteForce       = "BRUTE_FORCE_ATTEMPT"
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
}

func (o Options) top() int {
	if o.Top <= 0 {
		return DefaultTop
	}
	return o.Top
}

// Report is the result of Compute. Each field except Options is one section
// and one key of the JSON output.
type Report struct {
	NoisyDevices         []DeviceFaultCount   `json:"noisy_devices"`
	ChangeAccountability ChangeAccountability `json:"change_accountability"`
	SecurityWatchlist    []WatchedSource      `json:"security_watchlist"`
	VolumeByCategory     VolumeByCategory     `json:"volume_by_category"`
	WeekOverWeek         *WeekOverWeek        `json:"week_over_week"` // null when not computed
	IncidentClosure      IncidentClosure      `json:"incident_closure"`

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
	User       string `json:"user"`
	Count      int    `json:"count"`       // CONFIG_CHANGE + AFTER_HOURS_CHANGE
	AfterHours int    `json:"after_hours"` // of which AFTER_HOURS_CHANGE
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
	SourceIP      string   `json:"source_ip"`
	DistinctHosts int      `json:"distinct_hosts"` // devices this IP failed to log in to
	Events        int      `json:"events"`         // LOGIN_FAILURE + BRUTE_FORCE_ATTEMPT
	Hostnames     []string `json:"hostnames"`
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

// ==============================================================================
// Compute
// ==============================================================================

// Compute builds the report for opts from entries and incidents. It does no
// I/O and does not modify its arguments.
//
// Sections 1-4 and 6 cover [Since, Until]. The week-over-week section also
// reads the equal-length window before Since, which is half-open, [Since-w,
// Since), so an event exactly on the boundary is counted once, in the later
// window.
func Compute(entries []collector.LogEntry, incidents []collector.IncidentReport, opts Options) Report {
	opts.Top = opts.top()

	cur := make([]collector.LogEntry, 0, len(entries))
	for _, e := range entries {
		if inWindow(e.Timestamp, opts.Since, opts.Until) {
			cur = append(cur, e)
		}
	}
	inc := make([]collector.IncidentReport, 0, len(incidents))
	for _, r := range incidents {
		if inWindow(r.Timestamp, opts.Since, opts.Until) {
			inc = append(inc, r)
		}
	}

	rep := Report{
		NoisyDevices:         noisyDevices(cur, opts.Top),
		ChangeAccountability: changeAccountability(cur),
		SecurityWatchlist:    securityWatchlist(cur, opts.Top),
		VolumeByCategory:     volumeByCategory(cur, opts.Since, opts.Until),
		IncidentClosure:      incidentClosure(inc),
		Options:              opts,
	}
	if opts.Compare {
		rep.WeekOverWeek = weekOverWeek(entries, opts.Since, opts.Until)
	}
	return rep
}

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

// ==============================================================================
// 1. Noisy devices
// ==============================================================================

// noisyDevices counts FAULT events per device, most first, ties by hostname.
func noisyDevices(entries []collector.LogEntry, top int) []DeviceFaultCount {
	counts := make(map[string]int)
	for _, e := range entries {
		if categoryOf(e) == collector.CategoryFault {
			counts[e.Hostname]++
		}
	}
	out := make([]DeviceFaultCount, 0, len(counts))
	for host, n := range counts {
		out = append(out, DeviceFaultCount{Hostname: host, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return lessFold(out[i].Hostname, out[j].Hostname)
	})
	return limit(out, top)
}

// ==============================================================================
// 2. Change accountability
// ==============================================================================

func userKey(u string) string {
	if strings.TrimSpace(u) == "" {
		return UnknownUser
	}
	return u
}

// changeAccountability counts CONFIG_CHANGE and AFTER_HOURS_CHANGE events per
// user. The (unknown) bucket sorts last whatever its count.
func changeAccountability(entries []collector.LogEntry) ChangeAccountability {
	type tally struct{ total, afterHours int }
	byUser := make(map[string]*tally)
	ca := ChangeAccountability{ByUser: []UserChangeCount{}, AfterHours: []AfterHoursChange{}}

	for _, e := range entries {
		after := e.Event == eventAfterHoursChange
		if e.Event != eventConfigChange && !after {
			continue
		}
		u := userKey(e.User)
		t := byUser[u]
		if t == nil {
			t = &tally{}
			byUser[u] = t
		}
		t.total++
		ca.Total++
		if after {
			t.afterHours++
			ca.AfterHours = append(ca.AfterHours, AfterHoursChange{Hostname: e.Hostname, User: u, Timestamp: e.Timestamp.UTC()})
		}
	}
	ca.AfterHoursCount = len(ca.AfterHours)

	for u, t := range byUser {
		ca.ByUser = append(ca.ByUser, UserChangeCount{User: u, Count: t.total, AfterHours: t.afterHours})
	}
	sort.Slice(ca.ByUser, func(i, j int) bool {
		a, b := ca.ByUser[i], ca.ByUser[j]
		if (a.User == UnknownUser) != (b.User == UnknownUser) {
			return b.User == UnknownUser
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return lessFold(a.User, b.User)
	})
	sort.Slice(ca.AfterHours, func(i, j int) bool {
		a, b := ca.AfterHours[i], ca.AfterHours[j]
		if !a.Timestamp.Equal(b.Timestamp) {
			return a.Timestamp.After(b.Timestamp)
		}
		if a.Hostname != b.Hostname {
			return lessFold(a.Hostname, b.Hostname)
		}
		return lessFold(a.User, b.User)
	})
	return ca
}

// ==============================================================================
// 3. Security watchlist
// ==============================================================================

// securityWatchlist groups LOGIN_FAILURE and BRUTE_FORCE_ATTEMPT events by
// source IP across the whole fleet and ranks each IP by how many distinct
// devices it touched, then by total events, then by address.
func securityWatchlist(entries []collector.LogEntry, top int) []WatchedSource {
	type tally struct {
		hosts  map[string]struct{}
		events int
	}
	byIP := make(map[string]*tally)
	for _, e := range entries {
		if e.Event != eventLoginFailure && e.Event != eventBruteForce {
			continue
		}
		ip := strings.TrimSpace(e.SourceIP)
		if ip == "" {
			continue
		}
		t := byIP[ip]
		if t == nil {
			t = &tally{hosts: make(map[string]struct{})}
			byIP[ip] = t
		}
		t.hosts[e.Hostname] = struct{}{}
		t.events++
	}

	out := make([]WatchedSource, 0, len(byIP))
	for ip, t := range byIP {
		hosts := make([]string, 0, len(t.hosts))
		for h := range t.hosts {
			hosts = append(hosts, h)
		}
		sort.Slice(hosts, func(i, j int) bool { return lessFold(hosts[i], hosts[j]) })
		out = append(out, WatchedSource{SourceIP: ip, DistinctHosts: len(hosts), Events: t.events, Hostnames: hosts})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.DistinctHosts != b.DistinctHosts {
			return a.DistinctHosts > b.DistinctHosts
		}
		if a.Events != b.Events {
			return a.Events > b.Events
		}
		return lessIP(a.SourceIP, b.SourceIP)
	})
	return limit(out, top)
}

// ==============================================================================
// 4. Event volume by category and day
// ==============================================================================

const dayLayout = "2006-01-02"

// volumeByCategory counts events per UTC day and category. Every UTC day from
// the window's start to its end gets a row, including days with no events, so
// a gap in collection is visible rather than silently skipped. A window with
// no events yields an empty (non-nil) map.
func volumeByCategory(entries []collector.LogEntry, since, until time.Time) VolumeByCategory {
	vol := VolumeByCategory{}
	total := 0
	for _, e := range entries {
		if isCategory(categoryOf(e)) {
			total++
		}
	}
	if total == 0 {
		return vol
	}

	// An open end of the window falls back to the first/last entry.
	start, end := since, until
	if start.IsZero() || end.IsZero() {
		first, last := entries[0].Timestamp, entries[0].Timestamp
		for _, e := range entries[1:] {
			if e.Timestamp.Before(first) {
				first = e.Timestamp
			}
			if e.Timestamp.After(last) {
				last = e.Timestamp
			}
		}
		if start.IsZero() {
			start = first
		}
		if end.IsZero() {
			end = last
		}
	}

	day := start.UTC().Truncate(24 * time.Hour)
	last := end.UTC().Truncate(24 * time.Hour)
	for n := 0; !day.After(last) && n < maxVolumeDays; n++ {
		row := make(map[string]int, len(categories))
		for _, c := range categories {
			row[c] = 0
		}
		vol[day.Format(dayLayout)] = row
		day = day.AddDate(0, 0, 1)
	}

	for _, e := range entries {
		c := categoryOf(e)
		if !isCategory(c) {
			continue
		}
		if row, ok := vol[e.Timestamp.UTC().Format(dayLayout)]; ok {
			row[c]++
		}
	}
	return vol
}

// ==============================================================================
// 5. Week-over-week delta
// ==============================================================================

// weekOverWeek compares per-category event counts in [since, until] with the
// equal-length window before it, [since-w, since). It is the only statistic in
// the report: (current - previous) / previous * 100, and nil when previous is
// zero rather than a division by zero or an infinity. It returns nil when the
// window is not fully bounded.
func weekOverWeek(entries []collector.LogEntry, since, until time.Time) *WeekOverWeek {
	if since.IsZero() || until.IsZero() || !until.After(since) {
		return nil
	}
	prevFrom := since.Add(-until.Sub(since))

	prev := make(map[string]int, len(categories))
	cur := make(map[string]int, len(categories))
	for _, e := range entries {
		c := categoryOf(e)
		if !isCategory(c) {
			continue
		}
		switch {
		case !e.Timestamp.Before(since) && !e.Timestamp.After(until):
			cur[c]++
		case !e.Timestamp.Before(prevFrom) && e.Timestamp.Before(since):
			prev[c]++
		}
	}

	w := &WeekOverWeek{
		PreviousFrom: prevFrom.UTC(),
		CurrentFrom:  since.UTC(),
		CurrentTo:    until.UTC(),
		Categories:   make([]CategoryDelta, 0, len(categories)),
	}
	var prevTotal, curTotal int
	for _, c := range categories {
		w.Categories = append(w.Categories, delta(c, prev[c], cur[c]))
		prevTotal += prev[c]
		curTotal += cur[c]
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
// 6. Incident closure
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
func incidentClosure(incidents []collector.IncidentReport) IncidentClosure {
	type tally struct{ incidents, unreachable int }
	hosts := make(map[string]*tally)
	ic := IncidentClosure{UnreachableHosts: []UnreachableHost{}}

	for _, r := range incidents {
		t := hosts[r.Hostname]
		if t == nil {
			t = &tally{}
			hosts[r.Hostname] = t
		}
		t.incidents++
		ic.Total++
		switch classify(r) {
		case outcomeUnreachable:
			ic.Unreachable++
			t.unreachable++
		case outcomePartial:
			ic.PartialFailure++
		default:
			ic.Succeeded++
		}
	}
	ic.SucceededPct = pct(ic.Succeeded, ic.Total)
	ic.UnreachablePct = pct(ic.Unreachable, ic.Total)
	ic.PartialFailurePct = pct(ic.PartialFailure, ic.Total)

	for host, t := range hosts {
		if t.unreachable == 0 {
			continue
		}
		ic.UnreachableHosts = append(ic.UnreachableHosts, UnreachableHost{
			Hostname: host, Unreachable: t.unreachable, Incidents: t.incidents, Always: t.unreachable == t.incidents,
		})
	}
	sort.Slice(ic.UnreachableHosts, func(i, j int) bool {
		a, b := ic.UnreachableHosts[i], ic.UnreachableHosts[j]
		if a.Unreachable != b.Unreachable {
			return a.Unreachable > b.Unreachable
		}
		return lessFold(a.Hostname, b.Hostname)
	})
	return ic
}
