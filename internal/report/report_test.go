// ==============================================================================
// Package report: tests for Compute, one group per report section.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-24
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package report

import (
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"netlog/internal/collector"
)

// t0 is "now" in these tests; everything is expressed relative to it.
var t0 = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func mk(host, cat, event, user, srcIP string, ts time.Time) collector.LogEntry {
	return collector.LogEntry{
		ID: collector.EntryID(host, fmt.Sprint(event, user, srcIP, ts.UnixNano())), Hostname: host, Category: cat,
		Severity: collector.SeverityInfo, Event: event, User: user, SourceIP: srcIP,
		Summary: event, Raw: event, Timestamp: ts.UTC(), Vendor: "cisco_ios",
	}
}

// fault is a FAULT-category entry that is not a state change, so it never
// takes part in outage pairing (use down/up for that).
func fault(host string, ts time.Time) collector.LogEntry {
	return mk(host, collector.CategoryFault, "HIGH_CPU", "", "", ts)
}

// down and up are the two halves of an outage of one object.
func down(host, event, object string, ts time.Time) collector.LogEntry {
	e := mk(host, collector.CategoryFault, event, "", "", ts)
	e.Object = object
	return e
}

func up(host, event, object string, ts time.Time) collector.LogEntry {
	e := mk(host, collector.CategorySystem, event, "", "", ts)
	e.Object = object
	return e
}

func change(host, user string, ts time.Time) collector.LogEntry {
	return mk(host, collector.CategoryConfig, "CONFIG_CHANGE", user, "", ts)
}

func afterHours(host, user string, ts time.Time) collector.LogEntry {
	return mk(host, collector.CategorySecurity, "AFTER_HOURS_CHANGE", user, "", ts)
}

func loginFail(host, ip string, ts time.Time) collector.LogEntry {
	return mk(host, collector.CategoryAuth, "LOGIN_FAILURE", "", ip, ts)
}

func repeat(n int, f func(i int) collector.LogEntry) []collector.LogEntry {
	out := make([]collector.LogEntry, n)
	for i := range out {
		out[i] = f(i)
	}
	return out
}

func cat(parts ...[]collector.LogEntry) []collector.LogEntry {
	var out []collector.LogEntry
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ==============================================================================
// 1. Noisy devices
// ==============================================================================

func TestNoisyDevices(t *testing.T) {
	cases := []struct {
		name    string
		entries []collector.LogEntry
		top     int
		want    []DeviceFaultCount
	}{
		{"no entries", nil, 10, []DeviceFaultCount{}},
		{"single event", []collector.LogEntry{fault("R1", t0)}, 10, []DeviceFaultCount{{"R1", 1}}},
		{"only FAULT counts", []collector.LogEntry{
			fault("R1", t0), change("R1", "a", t0), loginFail("R1", "1.1.1.1", t0),
		}, 10, []DeviceFaultCount{{"R1", 1}}},
		{"most faults first", cat(
			repeat(1, func(int) collector.LogEntry { return fault("A", t0) }),
			repeat(3, func(int) collector.LogEntry { return fault("B", t0) }),
			repeat(2, func(int) collector.LogEntry { return fault("C", t0) }),
		), 10, []DeviceFaultCount{{"B", 3}, {"C", 2}, {"A", 1}}},
		{"ties break alphabetically", cat(
			repeat(2, func(int) collector.LogEntry { return fault("sw-c", t0) }),
			repeat(2, func(int) collector.LogEntry { return fault("SW-A", t0) }),
			repeat(2, func(int) collector.LogEntry { return fault("sw-b", t0) }),
		), 10, []DeviceFaultCount{{"SW-A", 2}, {"sw-b", 2}, {"sw-c", 2}}},
		{"top truncates after sorting", cat(
			repeat(1, func(int) collector.LogEntry { return fault("A", t0) }),
			repeat(4, func(int) collector.LogEntry { return fault("B", t0) }),
			repeat(3, func(int) collector.LogEntry { return fault("C", t0) }),
			repeat(2, func(int) collector.LogEntry { return fault("D", t0) }),
		), 2, []DeviceFaultCount{{"B", 4}, {"C", 3}}},
		{"category is matched case-insensitively", []collector.LogEntry{
			mk("R1", "fault", "LINK_DOWN", "", "", t0), mk("R1", " Fault ", "LINK_DOWN", "", "", t0),
		}, 10, []DeviceFaultCount{{"R1", 2}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Compute(c.entries, nil, Options{Top: c.top}).NoisyDevices
			if got == nil {
				t.Fatal("must be an empty slice, not nil")
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestTopDefaultsWhenUnset(t *testing.T) {
	entries := repeat(DefaultTop+5, func(i int) collector.LogEntry { return fault(fmt.Sprintf("R%02d", i), t0) })
	for _, top := range []int{0, -3} {
		rep := Compute(entries, nil, Options{Top: top})
		if len(rep.NoisyDevices) != DefaultTop || rep.Options.Top != DefaultTop {
			t.Errorf("Top=%d: got %d rows, Options.Top=%d; want %d", top, len(rep.NoisyDevices), rep.Options.Top, DefaultTop)
		}
	}
}

// ==============================================================================
// 2. Change accountability
// ==============================================================================

func TestChangeAccountability(t *testing.T) {
	entries := cat(
		repeat(2, func(i int) collector.LogEntry { return change("R1", "alice", t0.Add(-time.Duration(i)*time.Hour)) }),
		[]collector.LogEntry{change("R2", "bob", t0.Add(-5*time.Hour))},
		[]collector.LogEntry{afterHours("R2", "bob", t0.Add(-3*time.Hour))},
		repeat(5, func(i int) collector.LogEntry { return change("R3", "", t0.Add(-time.Duration(i)*time.Minute)) }),
		[]collector.LogEntry{afterHours("R9", "  ", t0.Add(-1*time.Hour))}, // blank user counts as unknown
		// Not changes: must be ignored.
		[]collector.LogEntry{fault("R1", t0), loginFail("R1", "9.9.9.9", t0)},
	)
	ca := Compute(entries, nil, Options{}).ChangeAccountability

	wantUsers := []UserChangeCount{
		{"alice", 2, 0, []string{"R1"}}, // alice and bob tie on 2: alphabetical
		{"bob", 2, 1, []string{"R2"}},
		{UnknownUser, 6, 1, []string{"R3", "R9"}}, // the biggest bucket still sorts last
	}
	if !reflect.DeepEqual(ca.ByUser, wantUsers) {
		t.Errorf("ByUser = %+v\nwant     %+v", ca.ByUser, wantUsers)
	}
	if ca.Total != 10 {
		t.Errorf("Total = %d, want 10", ca.Total)
	}
	if ca.AfterHoursCount != 2 || len(ca.AfterHours) != 2 {
		t.Fatalf("after-hours = %d / %d entries, want 2", ca.AfterHoursCount, len(ca.AfterHours))
	}
	// Newest first: the unknown user's change at -1h precedes bob's at -3h.
	if a := ca.AfterHours[0]; a.Hostname != "R9" || a.User != UnknownUser || !a.Timestamp.Equal(t0.Add(-time.Hour)) {
		t.Errorf("AfterHours[0] = %+v", a)
	}
	if a := ca.AfterHours[1]; a.Hostname != "R2" || a.User != "bob" {
		t.Errorf("AfterHours[1] = %+v", a)
	}
}

func TestChangeAccountabilityEmptyAndTies(t *testing.T) {
	ca := Compute(nil, nil, Options{}).ChangeAccountability
	if ca.ByUser == nil || ca.AfterHours == nil || ca.Total != 0 || ca.AfterHoursCount != 0 {
		t.Errorf("empty input: %+v (slices must be non-nil)", ca)
	}

	// Identical timestamps order by hostname, then user.
	ca = Compute([]collector.LogEntry{
		afterHours("R2", "x", t0), afterHours("R1", "y", t0), afterHours("R1", "x", t0),
	}, nil, Options{}).ChangeAccountability
	got := fmt.Sprintf("%s/%s %s/%s %s/%s", ca.AfterHours[0].Hostname, ca.AfterHours[0].User,
		ca.AfterHours[1].Hostname, ca.AfterHours[1].User, ca.AfterHours[2].Hostname, ca.AfterHours[2].User)
	if got != "R1/x R1/y R2/x" {
		t.Errorf("tie order = %q", got)
	}
}

// ==============================================================================
// 3. Security watchlist
// ==============================================================================

func TestSecurityWatchlist(t *testing.T) {
	cases := []struct {
		name    string
		entries []collector.LogEntry
		top     int
		want    []WatchedSource
	}{
		{"no entries", nil, 10, []WatchedSource{}},
		{"empty source ip is skipped", []collector.LogEntry{loginFail("R1", "", t0), loginFail("R1", "  ", t0)}, 10, []WatchedSource{}},
		{"single event", []collector.LogEntry{loginFail("R1", "1.1.1.1", t0)}, 10,
			[]WatchedSource{{"1.1.1.1", 1, 1, 0, []string{"R1"}}}},
		{"distinct hosts outrank total events", cat(
			repeat(9, func(int) collector.LogEntry { return loginFail("R1", "1.1.1.1", t0) }),    // 1 host, 9 events
			[]collector.LogEntry{loginFail("R1", "2.2.2.2", t0), loginFail("R2", "2.2.2.2", t0)}, // 2 hosts, 2 events
		), 10, []WatchedSource{
			{"2.2.2.2", 2, 2, 0, []string{"R1", "R2"}},
			{"1.1.1.1", 1, 9, 0, []string{"R1"}},
		}},
		{"equal hosts: more events first", cat(
			repeat(3, func(int) collector.LogEntry { return loginFail("R1", "1.1.1.1", t0) }),
			repeat(5, func(int) collector.LogEntry { return loginFail("R1", "2.2.2.2", t0) }),
		), 10, []WatchedSource{
			{"2.2.2.2", 1, 5, 0, []string{"R1"}},
			{"1.1.1.1", 1, 3, 0, []string{"R1"}},
		}},
		{"full tie: addresses sort numerically, text last", []collector.LogEntry{
			loginFail("R1", "10.0.0.10", t0), loginFail("R1", "10.0.0.9", t0),
			loginFail("R1", "2001:db8::1", t0), loginFail("R1", "not-an-ip", t0), loginFail("R1", "9.255.255.255", t0),
		}, 10, []WatchedSource{
			{"9.255.255.255", 1, 1, 0, []string{"R1"}},
			{"10.0.0.9", 1, 1, 0, []string{"R1"}},
			{"10.0.0.10", 1, 1, 0, []string{"R1"}},
			{"2001:db8::1", 1, 1, 0, []string{"R1"}},
			{"not-an-ip", 1, 1, 0, []string{"R1"}},
		}},
		// The derived events summarise failures that are already counted as
		// LOGIN_FAILURE entries: they are reported as detections and must not
		// inflate the failure count (one per burst) or the host count.
		{"detections are counted apart from failures", []collector.LogEntry{
			loginFail("R1", "1.1.1.1", t0),
			mk("R1", collector.CategorySecurity, "BRUTE_FORCE_ATTEMPT", "", "1.1.1.1", t0),
			mk("R2", collector.CategorySecurity, "PASSWORD_SPRAY_ATTEMPT", "", "1.1.1.1", t0),
		}, 10, []WatchedSource{{"1.1.1.1", 2, 1, 2, []string{"R1", "R2"}}}},
		{"detections break a tie on failures", []collector.LogEntry{
			loginFail("R1", "1.1.1.1", t0), loginFail("R1", "2.2.2.2", t0),
			mk("R1", collector.CategorySecurity, "BRUTE_FORCE_ATTEMPT", "", "2.2.2.2", t0),
		}, 10, []WatchedSource{{"2.2.2.2", 1, 1, 1, []string{"R1"}}, {"1.1.1.1", 1, 1, 0, []string{"R1"}}}},
		{"a source seen only through a detection is still listed", []collector.LogEntry{
			mk("R1", collector.CategorySecurity, "BRUTE_FORCE_ATTEMPT", "", "1.1.1.1", t0),
		}, 10, []WatchedSource{{"1.1.1.1", 1, 0, 1, []string{"R1"}}}},
		{"other events with a source ip are not logins", []collector.LogEntry{
			mk("R1", collector.CategoryConfig, "CONFIG_CHANGE", "tanvt", "10.10.10.50", t0),
		}, 10, []WatchedSource{}},
		{"top truncates after sorting", []collector.LogEntry{
			loginFail("R1", "3.3.3.3", t0), loginFail("R1", "1.1.1.1", t0), loginFail("R1", "2.2.2.2", t0),
		}, 2, []WatchedSource{{"1.1.1.1", 1, 1, 0, []string{"R1"}}, {"2.2.2.2", 1, 1, 0, []string{"R1"}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Compute(c.entries, nil, Options{Top: c.top}).SecurityWatchlist
			if got == nil {
				t.Fatal("must be an empty slice, not nil")
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got  %+v\nwant %+v", got, c.want)
			}
		})
	}
}

// The watchlist exists to see what one device cannot: the same source across
// devices and across days.
func TestSecurityWatchlistSpansDays(t *testing.T) {
	entries := []collector.LogEntry{
		loginFail("R1", "203.0.113.9", t0.Add(-5*24*time.Hour)),
		loginFail("R2", "203.0.113.9", t0.Add(-2*24*time.Hour)),
		loginFail("R3", "203.0.113.9", t0.Add(-time.Hour)),
	}
	got := Compute(entries, nil, Options{Since: t0.Add(-7 * 24 * time.Hour), Until: t0}).SecurityWatchlist
	if len(got) != 1 || got[0].DistinctHosts != 3 || got[0].Events != 3 {
		t.Errorf("got %+v, want one source on 3 hosts", got)
	}
}

// ==============================================================================
// 4. Event volume by category/day
// ==============================================================================

func TestVolumeByCategory(t *testing.T) {
	since, until := t0.Add(-3*24*time.Hour), t0 // 2026-10-21 12:00 .. 2026-10-24 12:00
	entries := []collector.LogEntry{
		fault("R1", t0.Add(-3*24*time.Hour)), // 10-21
		fault("R1", t0.Add(-3*24*time.Hour+time.Minute)),
		change("R1", "a", t0.Add(-1*24*time.Hour)), // 10-23
		loginFail("R1", "1.1.1.1", t0),             // 10-24
		mk("R1", collector.CategorySystem, "UNKNOWN", "", "", t0.Add(-time.Minute)),
		mk("R1", "BOGUS", "X", "", "", t0), // not one of the five: not counted
	}
	vol := Compute(entries, nil, Options{Since: since, Until: until}).VolumeByCategory

	if len(vol) != 4 {
		t.Fatalf("want a row for every UTC day 10-21..10-24 (including the empty 10-22), got %d: %v", len(vol), vol)
	}
	want := map[string]map[string]int{
		"2026-10-21": {"CONFIG": 0, "AUTH": 0, "FAULT": 2, "SECURITY": 0, "SYSTEM": 0},
		"2026-10-22": {"CONFIG": 0, "AUTH": 0, "FAULT": 0, "SECURITY": 0, "SYSTEM": 0},
		"2026-10-23": {"CONFIG": 1, "AUTH": 0, "FAULT": 0, "SECURITY": 0, "SYSTEM": 0},
		"2026-10-24": {"CONFIG": 0, "AUTH": 1, "FAULT": 0, "SECURITY": 0, "SYSTEM": 1},
	}
	if !reflect.DeepEqual(map[string]map[string]int(vol), want) {
		t.Errorf("got  %v\nwant %v", vol, want)
	}
}

func TestVolumeByCategoryEdges(t *testing.T) {
	if vol := Compute(nil, nil, Options{Since: t0.Add(-24 * time.Hour), Until: t0}).VolumeByCategory; vol == nil || len(vol) != 0 {
		t.Errorf("no events must give an empty, non-nil map, got %#v", vol)
	}

	// Days are UTC days whatever zone the timestamp carries: 23:30 at +07:00
	// is 16:30 UTC the same day, and 02:00 at +07:00 is 19:00 UTC the day before.
	ict := time.FixedZone("ICT", 7*3600)
	entries := []collector.LogEntry{
		fault("R1", time.Date(2026, 10, 23, 23, 30, 0, 0, ict)),
		fault("R1", time.Date(2026, 10, 24, 2, 0, 0, 0, ict)),
		fault("R1", time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)),
		fault("R1", time.Date(2026, 10, 23, 23, 59, 59, 999999999, time.UTC)),
	}
	vol := Compute(entries, nil, Options{Since: time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC), Until: t0}).VolumeByCategory
	if vol["2026-10-23"]["FAULT"] != 3 || vol["2026-10-24"]["FAULT"] != 1 {
		t.Errorf("UTC day boundaries wrong: %v", vol)
	}

	// An open window is bounded by the data itself.
	vol = Compute(entries[:1], nil, Options{}).VolumeByCategory
	if len(vol) != 1 || vol["2026-10-23"]["FAULT"] != 1 {
		t.Errorf("open window: %v", vol)
	}
}

// ==============================================================================
// 5. Week-over-week delta
// ==============================================================================

func pctOf(p *float64) string {
	if p == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.1f", *p)
}

func TestWeekOverWeek(t *testing.T) {
	since := t0.Add(-Week)
	day := 24 * time.Hour
	entries := cat(
		// previous window [t0-14d, t0-7d)
		repeat(4, func(int) collector.LogEntry { return fault("R1", t0.Add(-10*day)) }),
		repeat(3, func(int) collector.LogEntry { return change("R1", "a", t0.Add(-8*day)) }),
		repeat(2, func(int) collector.LogEntry { return loginFail("R1", "1.1.1.1", t0.Add(-9*day)) }),
		// current window [t0-7d, t0]
		repeat(6, func(int) collector.LogEntry { return fault("R1", t0.Add(-2*day)) }),     // 4 -> 6
		repeat(3, func(int) collector.LogEntry { return change("R1", "a", t0.Add(-day)) }), // 3 -> 3
		repeat(1, func(int) collector.LogEntry { return loginFail("R1", "1.1.1.1", t0) }),  // 2 -> 1
		repeat(5, func(int) collector.LogEntry { return afterHours("R1", "a", t0) }),       // 0 -> 5: no baseline
		// outside both windows
		repeat(9, func(int) collector.LogEntry { return fault("R1", t0.Add(-20*day)) }),
	)
	w := Compute(entries, nil, Options{Since: since, Until: t0, Compare: true}).WeekOverWeek
	if w == nil {
		t.Fatal("Compare was requested")
	}
	want := map[string]string{ // category -> previous/current/change/pct
		"CONFIG":   "3/3/0/0.0",
		"AUTH":     "2/1/-1/-50.0",
		"FAULT":    "4/6/2/50.0",
		"SECURITY": "0/5/5/n/a",
		"SYSTEM":   "0/0/0/n/a",
		"TOTAL":    "9/15/6/66.7",
	}
	all := append(append([]CategoryDelta{}, w.Categories...), w.Total)
	if len(all) != len(want) {
		t.Fatalf("got %d rows, want %d", len(all), len(want))
	}
	for i, d := range all {
		got := fmt.Sprintf("%d/%d/%d/%s", d.Previous, d.Current, d.Change, pctOf(d.ChangePct))
		if got != want[d.Category] {
			t.Errorf("%s = %s, want %s", d.Category, got, want[d.Category])
		}
		if i < 5 && d.Category != categories[i] {
			t.Errorf("row %d is %s, want fixed order %s", i, d.Category, categories[i])
		}
	}
	if !w.PreviousFrom.Equal(t0.Add(-14*day)) || !w.CurrentFrom.Equal(since) || !w.CurrentTo.Equal(t0) {
		t.Errorf("windows = %v / %v / %v", w.PreviousFrom, w.CurrentFrom, w.CurrentTo)
	}
}

// With nothing in the earlier window the percentage is undefined: it must be
// reported as n/a (nil), never as a division by zero or +Inf.
func TestWeekOverWeekLastIsZero(t *testing.T) {
	entries := repeat(3, func(int) collector.LogEntry { return fault("R1", t0.Add(-time.Hour)) })
	w := Compute(entries, nil, Options{Since: t0.Add(-Week), Until: t0, Compare: true}).WeekOverWeek
	f := w.Categories[2] // FAULT
	if f.Category != "FAULT" || f.Previous != 0 || f.Current != 3 || f.Change != 3 || f.ChangePct != nil {
		t.Errorf("FAULT = %+v, want 0 -> 3 with n/a", f)
	}
	if w.Total.ChangePct != nil {
		t.Error("total must also be n/a when the previous window is empty")
	}

	// Both windows empty: still no panic, still n/a.
	w = Compute(nil, nil, Options{Since: t0.Add(-Week), Until: t0, Compare: true}).WeekOverWeek
	if w == nil || w.Total.ChangePct != nil || w.Total.Change != 0 {
		t.Errorf("both empty: %+v", w)
	}
}

func TestWeekOverWeekNegativeAndRounding(t *testing.T) {
	entries := cat(
		repeat(3, func(int) collector.LogEntry { return fault("R1", t0.Add(-8*24*time.Hour)) }),
		repeat(2, func(int) collector.LogEntry { return fault("R1", t0.Add(-time.Hour)) }),
	)
	f := Compute(entries, nil, Options{Since: t0.Add(-Week), Until: t0, Compare: true}).WeekOverWeek.Categories[2]
	if f.ChangePct == nil || *f.ChangePct != -33.3 {
		t.Errorf("3 -> 2 should be -33.3%%, got %s", pctOf(f.ChangePct))
	}
}

// A one-event drop from a huge baseline rounds to zero; it must read 0.0%, not
// -0.0% (and must not marshal as the JSON number -0).
func TestDeltaNeverNegativeZero(t *testing.T) {
	d := delta("FAULT", 5000, 4999)
	if d.ChangePct == nil || *d.ChangePct != 0 || math.Signbit(*d.ChangePct) {
		t.Errorf("ChangePct = %v, want +0", pctOf(d.ChangePct))
	}
}

func TestWeekOverWeekWindowBoundaries(t *testing.T) {
	since, until := t0.Add(-Week), t0
	prevFrom := since.Add(-Week)
	cases := []struct {
		name          string
		ts            time.Time
		prev, current int
	}{
		{"exactly at until", until, 0, 1},
		{"just after until", until.Add(time.Nanosecond), 0, 0},
		{"exactly at since: current only, never both", since, 0, 1},
		{"just before since", since.Add(-time.Nanosecond), 1, 0},
		{"exactly at previous start", prevFrom, 1, 0},
		{"just before previous start", prevFrom.Add(-time.Nanosecond), 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := Compute([]collector.LogEntry{fault("R1", c.ts)}, nil, Options{Since: since, Until: until, Compare: true})
			f := rep.WeekOverWeek.Categories[2]
			if f.Previous != c.prev || f.Current != c.current {
				t.Errorf("previous/current = %d/%d, want %d/%d", f.Previous, f.Current, c.prev, c.current)
			}
			// The ranking sections read the same window as the delta's "current".
			wantRanked := c.current
			if got := len(rep.NoisyDevices); got != wantRanked {
				t.Errorf("noisy-device rows = %d, want %d", got, wantRanked)
			}
		})
	}
}

func TestWeekOverWeekOptions(t *testing.T) {
	entries := []collector.LogEntry{fault("R1", t0.Add(-time.Hour))}

	if w := Compute(entries, nil, Options{Since: t0.Add(-Week), Until: t0}).WeekOverWeek; w != nil {
		t.Error("not requested: must be nil")
	}
	for name, o := range map[string]Options{
		"no start":    {Until: t0, Compare: true},
		"no end":      {Since: t0.Add(-Week), Compare: true},
		"empty range": {Since: t0, Until: t0, Compare: true},
		"inverted":    {Since: t0, Until: t0.Add(-time.Hour), Compare: true},
	} {
		if w := Compute(entries, nil, o).WeekOverWeek; w != nil {
			t.Errorf("%s: an unbounded or empty window cannot be compared, got %+v", name, w)
		}
	}

	// Forced on for a 24h window: compares it with the 24h before it.
	entries = []collector.LogEntry{
		fault("R1", t0.Add(-30*time.Hour)), fault("R1", t0.Add(-25*time.Hour)), // previous day
		fault("R1", t0.Add(-time.Hour)), // this day
	}
	w := Compute(entries, nil, Options{Since: t0.Add(-24 * time.Hour), Until: t0, Compare: true}).WeekOverWeek
	if f := w.Categories[2]; f.Previous != 2 || f.Current != 1 || f.ChangePct == nil || *f.ChangePct != -50 {
		t.Errorf("24h compare: %+v", f)
	}
	if !w.PreviousFrom.Equal(t0.Add(-48 * time.Hour)) {
		t.Errorf("PreviousFrom = %v", w.PreviousFrom)
	}
}

// ==============================================================================
// 6. Incident closure
// ==============================================================================

func incident(host string, ts time.Time, diags ...collector.DiagCmd) collector.IncidentReport {
	return collector.IncidentReport{ID: fmt.Sprintf("%s-%d", host, ts.UnixNano()), Timestamp: ts, Hostname: host, Diagnostics: diags}
}

var (
	diagOK       = collector.DiagCmd{Command: "show version", Output: "ok"}
	diagFail     = collector.DiagCmd{Command: "show ip route", Error: "timeout"}
	diagNoConn   = collector.DiagCmd{Command: "(connect)", Error: "dial tcp: i/o timeout"}
	diagConnFine = collector.DiagCmd{Command: "(connect)"}
)

func TestIncidentClassification(t *testing.T) {
	cases := []struct {
		name  string
		diags []collector.DiagCmd
		want  outcome
	}{
		{"all commands succeeded", []collector.DiagCmd{diagOK, diagOK}, outcomeSucceeded},
		{"no diagnostics at all", nil, outcomeSucceeded},
		{"connect entry without an error is not a failure", []collector.DiagCmd{diagConnFine, diagOK}, outcomeSucceeded},
		{"connect failed", []collector.DiagCmd{diagNoConn}, outcomeUnreachable},
		{"connect failure outranks a command failure", []collector.DiagCmd{diagFail, diagNoConn}, outcomeUnreachable},
		{"a command failed on a reachable device", []collector.DiagCmd{diagOK, diagFail}, outcomePartial},
	}
	for _, c := range cases {
		if got := classify(incident("R1", t0, c.diags...)); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestIncidentClosure(t *testing.T) {
	incidents := []collector.IncidentReport{
		incident("SW-A", t0.Add(-1*time.Hour), diagNoConn),
		incident("SW-A", t0.Add(-2*time.Hour), diagNoConn),
		incident("SW-B", t0.Add(-3*time.Hour), diagNoConn),
		incident("SW-B", t0.Add(-4*time.Hour), diagOK),
		incident("SW-B", t0.Add(-5*time.Hour), diagOK, diagOK),
		incident("SW-C", t0.Add(-6*time.Hour), diagOK, diagFail),
		incident("SW-D", t0.Add(-7*time.Hour), diagOK),
	}
	ic := Compute(nil, incidents, Options{}).IncidentClosure

	if ic.Total != 7 || ic.Succeeded != 3 || ic.Unreachable != 3 || ic.PartialFailure != 1 {
		t.Fatalf("counts = %+v", ic)
	}
	if ic.Succeeded+ic.Unreachable+ic.PartialFailure != ic.Total {
		t.Error("the three outcomes must sum to the total")
	}
	if ic.SucceededPct != 42.9 || ic.UnreachablePct != 42.9 || ic.PartialFailurePct != 14.3 {
		t.Errorf("percentages = %v / %v / %v", ic.SucceededPct, ic.UnreachablePct, ic.PartialFailurePct)
	}
	want := []UnreachableHost{
		{"SW-A", 2, 2, true},  // unreachable every time it had an incident
		{"SW-B", 1, 3, false}, // only some of the time
	}
	if !reflect.DeepEqual(ic.UnreachableHosts, want) {
		t.Errorf("UnreachableHosts = %+v, want %+v", ic.UnreachableHosts, want)
	}
}

func TestIncidentClosureEmptyAndOrdering(t *testing.T) {
	ic := Compute(nil, nil, Options{}).IncidentClosure
	if ic.Total != 0 || ic.UnreachableHosts == nil || ic.SucceededPct != 0 {
		t.Errorf("no incidents: %+v (hosts must be a non-nil slice, percentages 0 not NaN)", ic)
	}

	// Equal counts order by hostname.
	ic = Compute(nil, []collector.IncidentReport{
		incident("sw-b", t0, diagNoConn), incident("SW-A", t0, diagNoConn),
	}, Options{}).IncidentClosure
	if len(ic.UnreachableHosts) != 2 || ic.UnreachableHosts[0].Hostname != "SW-A" {
		t.Errorf("tie order: %+v", ic.UnreachableHosts)
	}
}

func TestIncidentsAreWindowed(t *testing.T) {
	incidents := []collector.IncidentReport{
		incident("R1", t0.Add(-time.Hour), diagNoConn),
		incident("R2", t0.Add(-8*24*time.Hour), diagNoConn), // before the window
		incident("R3", t0.Add(time.Hour), diagNoConn),       // after it
	}
	ic := Compute(nil, incidents, Options{Since: t0.Add(-Week), Until: t0}).IncidentClosure
	if ic.Total != 1 || len(ic.UnreachableHosts) != 1 || ic.UnreachableHosts[0].Hostname != "R1" {
		t.Errorf("got %+v", ic)
	}
}

// ==============================================================================
// Whole-report properties
// ==============================================================================

func TestComputeEmptyInput(t *testing.T) {
	for name, rep := range map[string]Report{
		"zero options": Compute(nil, nil, Options{}),
		"bounded":      Compute([]collector.LogEntry{}, []collector.IncidentReport{}, Options{Since: t0.Add(-Week), Until: t0, Compare: true}),
	} {
		if rep.NoisyDevices == nil || rep.SecurityWatchlist == nil || rep.VolumeByCategory == nil ||
			rep.ChangeAccountability.ByUser == nil || rep.ChangeAccountability.AfterHours == nil ||
			rep.IncidentClosure.UnreachableHosts == nil {
			t.Errorf("%s: sections must be empty, not nil: %+v", name, rep)
		}
		if len(rep.NoisyDevices)+len(rep.SecurityWatchlist)+len(rep.VolumeByCategory) != 0 {
			t.Errorf("%s: expected no rows anywhere", name)
		}
	}
	if Compute(nil, nil, Options{}).WeekOverWeek != nil {
		t.Error("week_over_week must be nil unless requested")
	}
}

func TestComputeDoesNotModifyInput(t *testing.T) {
	entries := []collector.LogEntry{fault("B", t0), fault("A", t0.Add(-time.Hour)), change("C", "x", t0)}
	incidents := []collector.IncidentReport{incident("B", t0, diagNoConn), incident("A", t0, diagOK)}
	e0 := append([]collector.LogEntry(nil), entries...)
	i0 := append([]collector.IncidentReport(nil), incidents...)
	Compute(entries, incidents, Options{Since: t0.Add(-Week), Until: t0, Compare: true})
	if !reflect.DeepEqual(entries, e0) || !reflect.DeepEqual(incidents, i0) {
		t.Error("Compute reordered or modified its input")
	}
}

// The report must be a function of the data alone: the order the entries
// arrive in (Load sorts them, but Compute must not depend on that) cannot
// change a single byte. The input is built to be full of ties.
func TestComputeIsDeterministic(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	hosts := []string{"SW-A", "sw-b", "SW-C", "r1", "R2"}
	users := []string{"", "alice", "Bob", "carol"}
	ips := []string{"", "10.0.0.9", "10.0.0.10", "192.0.2.1", "2001:db8::2"}

	var entries []collector.LogEntry
	for i := 0; i < 400; i++ {
		ts := t0.Add(-time.Duration(rnd.Intn(14*24)) * time.Hour) // hour-granular, so timestamps collide
		h := hosts[rnd.Intn(len(hosts))]
		switch rnd.Intn(4) {
		case 0:
			entries = append(entries, fault(h, ts))
		case 1:
			entries = append(entries, change(h, users[rnd.Intn(len(users))], ts))
		case 2:
			entries = append(entries, afterHours(h, users[rnd.Intn(len(users))], ts))
		default:
			entries = append(entries, loginFail(h, ips[rnd.Intn(len(ips))], ts))
		}
	}
	var incidents []collector.IncidentReport
	for i := 0; i < 40; i++ {
		d := diagOK
		if rnd.Intn(2) == 0 {
			d = diagNoConn
		}
		incidents = append(incidents, incident(hosts[rnd.Intn(len(hosts))], t0.Add(-time.Duration(rnd.Intn(7*24))*time.Hour), d))
	}

	opts := Options{Since: t0.Add(-Week), Until: t0, Compare: true, Top: 3}
	want := Compute(entries, incidents, opts)
	for round := 0; round < 25; round++ {
		rnd.Shuffle(len(entries), func(i, j int) { entries[i], entries[j] = entries[j], entries[i] })
		rnd.Shuffle(len(incidents), func(i, j int) { incidents[i], incidents[j] = incidents[j], incidents[i] })
		if got := Compute(entries, incidents, opts); !reflect.DeepEqual(got, want) {
			t.Fatalf("round %d: the report depends on input order\n got: %+v\nwant: %+v", round, got, want)
		}
	}
}

// ==============================================================================
// 7. Outages
// ==============================================================================

var oEnd = t0 // window end

func outages(entries ...collector.LogEntry) Outages {
	return Compute(entries, nil, Options{Since: t0.Add(-Week), Until: oEnd}).Outages
}

func TestOutagePairing(t *testing.T) {
	m := func(min int) time.Time { return t0.Add(-time.Duration(min) * time.Minute) }

	t.Run("one down and its up", func(t *testing.T) {
		o := outages(down("R1", "LINK_DOWN", "Gi0/1", m(60)), up("R1", "LINK_UP", "Gi0/1", m(50)))
		if o.Total != 1 || o.Resolved != 1 || o.Open != 0 || o.MeanSecondsToRecover != 600 || o.LongestSeconds != 600 {
			t.Fatalf("%+v", o)
		}
		x := o.Longest[0]
		if x.Hostname != "R1" || x.Kind != "link" || x.Object != "Gi0/1" || x.Open || x.Up == nil || !x.Up.Equal(m(50)) || !x.Down.Equal(m(60)) || x.DurationSeconds != 600 {
			t.Errorf("outage = %+v", x)
		}
	})

	t.Run("still down at the end of the window", func(t *testing.T) {
		o := outages(down("R1", "BGP_PEER_DOWN", "10.0.0.1", m(30)))
		x := o.Longest[0]
		if o.Open != 1 || o.Resolved != 0 || !x.Open || x.Up != nil || x.Kind != "bgp" || x.DurationSeconds != 1800 {
			t.Errorf("open outage: %+v %+v", o, x)
		}
		if o.MeanSecondsToRecover != 0 {
			t.Error("the mean is over resolved outages only")
		}
		if o.LongestSeconds != 1800 {
			t.Errorf("an open outage counts towards the longest (a lower bound): %d", o.LongestSeconds)
		}
	})

	// Cisco logs the link and the line protocol for one event, a second apart.
	t.Run("a repeated down while open, and a repeated up, are one outage", func(t *testing.T) {
		o := outages(
			down("R1", "LINK_DOWN", "Gi0/1", m(60)), down("R1", "LINK_DOWN", "Gi0/1", m(60).Add(time.Second)),
			up("R1", "LINK_UP", "Gi0/1", m(55)), up("R1", "LINK_UP", "Gi0/1", m(55).Add(time.Second)))
		if o.Total != 1 || o.Resolved != 1 || o.LongestSeconds != 300 {
			t.Errorf("%+v", o)
		}
	})

	t.Run("an up with nothing open is ignored", func(t *testing.T) {
		if o := outages(up("R1", "LINK_UP", "Gi0/1", m(10))); o.Total != 0 {
			t.Errorf("a recovery from before the window is not an outage: %+v", o)
		}
	})

	t.Run("a new down after a recovery is a second outage", func(t *testing.T) {
		o := outages(
			down("R1", "LINK_DOWN", "Gi0/1", m(100)), up("R1", "LINK_UP", "Gi0/1", m(90)),
			down("R1", "LINK_DOWN", "Gi0/1", m(40)), up("R1", "LINK_UP", "Gi0/1", m(20)))
		if o.Total != 2 || o.Resolved != 2 || o.MeanSecondsToRecover != 900 || o.LongestSeconds != 1200 {
			t.Errorf("%+v", o)
		}
	})

	t.Run("device, kind and object are all part of the key", func(t *testing.T) {
		o := outages(
			down("R1", "LINK_DOWN", "Gi0/1", m(60)),
			up("R1", "LINK_UP", "Gi0/2", m(50)),     // other interface
			up("R2", "LINK_UP", "Gi0/1", m(50)),     // other device
			up("R1", "OSPF_ADJ_UP", "Gi0/1", m(50)), // other kind
			up("R1", "BGP_PEER_UP", "Gi0/1", m(50))) // other kind
		if o.Total != 1 || o.Open != 1 || o.Resolved != 0 {
			t.Errorf("nothing here recovers the Gi0/1 link on R1: %+v", o)
		}
	})

	t.Run("a down and up at the same instant: down first", func(t *testing.T) {
		o := outages(up("R1", "LINK_UP", "Gi0/1", m(5)), down("R1", "LINK_DOWN", "Gi0/1", m(5)))
		if o.Total != 1 || o.Resolved != 1 || o.LongestSeconds != 0 {
			t.Errorf("%+v", o)
		}
	})

	t.Run("outside the window", func(t *testing.T) {
		before := t0.Add(-Week).Add(-time.Hour)
		o := outages(down("R1", "LINK_DOWN", "Gi0/1", before), up("R1", "LINK_UP", "Gi0/1", before.Add(time.Minute)))
		if o.Total != 0 {
			t.Errorf("%+v", o)
		}
		// Down inside, up after the window: still open at the window's end.
		o = outages(down("R1", "LINK_DOWN", "Gi0/1", m(30)), up("R1", "LINK_UP", "Gi0/1", t0.Add(time.Hour)))
		if o.Open != 1 {
			t.Errorf("%+v", o)
		}
	})

	t.Run("a mean over resolved outages ignores the open ones", func(t *testing.T) {
		o := outages(
			down("R1", "LINK_DOWN", "Gi0/1", m(200)), up("R1", "LINK_UP", "Gi0/1", m(190)), // 10m
			down("R1", "LINK_DOWN", "Gi0/2", m(180)), up("R1", "LINK_UP", "Gi0/2", m(160)), // 20m
			down("R1", "LINK_DOWN", "Gi0/3", m(120))) // open, 2h
		if o.Total != 3 || o.Resolved != 2 || o.Open != 1 || o.MeanSecondsToRecover != 900 || o.LongestSeconds != 7200 {
			t.Errorf("%+v", o)
		}
	})
}

// A down whose line names no interface or neighbor cannot be matched to a
// recovery: it is counted, not guessed at.
func TestOutagesUntracked(t *testing.T) {
	noObj := mk("R1", collector.CategoryFault, "LINK_DOWN", "", "", t0.Add(-time.Hour))
	noObjUp := mk("R1", collector.CategorySystem, "LINK_UP", "", "", t0.Add(-50*time.Minute))
	o := outages(noObj, noObjUp, noObj, down("R1", "LINK_DOWN", "Gi0/1", t0.Add(-time.Hour)), up("R1", "LINK_UP", "Gi0/1", t0.Add(-55*time.Minute)))
	if o.Untracked != 2 || o.Total != 1 || o.Resolved != 1 {
		t.Errorf("untracked downs are counted (recoveries are not), tracked ones still pair: %+v", o)
	}
}

func TestOutagesLongestIsRankedAndTruncated(t *testing.T) {
	var es []collector.LogEntry
	for i, mins := range []int{5, 40, 40, 15} { // two equal durations on different devices
		host := fmt.Sprintf("R%d", i+1)
		es = append(es, down(host, "LINK_DOWN", "Gi0/1", t0.Add(-5*time.Hour)), up(host, "LINK_UP", "Gi0/1", t0.Add(-5*time.Hour+time.Duration(mins)*time.Minute)))
	}
	o := Compute(es, nil, Options{Since: t0.Add(-Week), Until: t0, Top: 3}).Outages
	if o.Total != 4 || len(o.Longest) != 3 {
		t.Fatalf("total %d, listed %d; want 4 outages, the top 3 listed", o.Total, len(o.Longest))
	}
	got := fmt.Sprintf("%s %s %s", o.Longest[0].Hostname, o.Longest[1].Hostname, o.Longest[2].Hostname)
	if got != "R2 R3 R4" {
		t.Errorf("order = %q, want longest first with ties by hostname", got)
	}
}

func TestOutagesWithAnOpenWindowEndUseTheLatestEntry(t *testing.T) {
	es := []collector.LogEntry{down("R1", "LINK_DOWN", "Gi0/1", t0.Add(-time.Hour)), fault("R2", t0.Add(-10*time.Minute))}
	o := Compute(es, nil, Options{}).Outages
	if o.Open != 1 || o.Longest[0].DurationSeconds != 3000 {
		t.Errorf("an open window ends at the last entry seen: %+v", o)
	}
}

// ==============================================================================
// 9. Classification coverage
// ==============================================================================

func TestClassificationCoverage(t *testing.T) {
	vend := func(v, event string) collector.LogEntry {
		e := mk("R1", collector.CategorySystem, event, "", "", t0)
		e.Vendor = v
		return e
	}
	es := cat(
		repeat(3, func(int) collector.LogEntry { return vend("pfsense", "UNKNOWN") }),
		repeat(1, func(int) collector.LogEntry { return vend("pfsense", "CONFIG_CHANGE") }),
		repeat(2, func(int) collector.LogEntry { return vend("cisco_ios", "UNKNOWN") }),
		repeat(2, func(int) collector.LogEntry { return vend("cisco_ios", "LINK_UP") }),
		repeat(1, func(int) collector.LogEntry { return vend("fortigate", "LOGIN_FAILURE") }),
		repeat(1, func(int) collector.LogEntry { return vend("", "") }), // never classified, vendor unknown
	)
	got := Compute(es, nil, Options{}).ClassificationCoverage
	want := []VendorCoverage{
		{"pfsense", 4, 3, 75},
		{"cisco_ios", 4, 2, 50},
		{"(unknown)", 1, 1, 100}, // an entry with no event was never classified: it counts as unknown
		{"fortigate", 1, 0, 0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	if empty := Compute(nil, nil, Options{}).ClassificationCoverage; empty == nil || len(empty) != 0 {
		t.Errorf("no entries: want an empty, non-nil slice, got %#v", empty)
	}
}

// ==============================================================================
// 8. Device health
// ==============================================================================

func TestDeviceHealthSection(t *testing.T) {
	rows := []DeviceStatus{
		{Hostname: "ok-1", Status: "OK"},
		{Hostname: "silent-1", Status: "SILENT"},
		{Hostname: "failing-2", Status: "FAILING", ConsecutiveFailures: 2},
		{Hostname: "failing-9", Status: "FAILING", ConsecutiveFailures: 9},
		{Hostname: "ok-2", Status: "OK"},
		{Hostname: "pf", Status: "UNSUPPORTED"},
	}
	dh := Compute(nil, nil, Options{Devices: rows}).DeviceHealth
	if dh.Checked != 6 || len(dh.Unhealthy) != 4 {
		t.Fatalf("%+v", dh)
	}
	var order []string
	for _, d := range dh.Unhealthy {
		order = append(order, d.Hostname)
	}
	// Most urgent first; within FAILING the longest run first; healthy devices are not listed.
	if got := strings.Join(order, " "); got != "failing-9 failing-2 silent-1 pf" {
		t.Errorf("order = %s", got)
	}
	if rows[0].Hostname != "ok-1" || rows[2].Hostname != "failing-2" {
		t.Error("the caller's slice must not be reordered")
	}

	if dh := Compute(nil, nil, Options{}).DeviceHealth; dh.Checked != 0 || dh.Unhealthy == nil || len(dh.Unhealthy) != 0 {
		t.Errorf("no health data: %+v (unhealthy must be an empty slice)", dh)
	}
}

// ==============================================================================
// Builder
// ==============================================================================

// Streaming and slices are the same computation, and a Builder can be asked
// for its report more than once.
func TestBuilderEqualsCompute(t *testing.T) {
	day := 24 * time.Hour
	entries := cat(
		repeat(4, func(i int) collector.LogEntry { return fault("R1", t0.Add(-time.Duration(i)*time.Hour)) }),
		[]collector.LogEntry{
			change("R2", "alice", t0.Add(-day)), afterHours("R2", "bob", t0.Add(-2*day)), loginFail("R1", "9.9.9.9", t0.Add(-day)),
			down("R1", "LINK_DOWN", "Gi0/1", t0.Add(-3*day)), up("R1", "LINK_UP", "Gi0/1", t0.Add(-3*day+time.Hour)),
			fault("R1", t0.Add(-9*day)), // previous week
		},
	)
	incidents := []collector.IncidentReport{incident("R1", t0.Add(-time.Hour), diagNoConn)}
	opts := Options{Since: t0.Add(-Week), Until: t0, Compare: true, Top: 2, Devices: []DeviceStatus{{Hostname: "R1", Status: "FAILING"}}}

	b := NewBuilder(opts)
	for i := len(entries) - 1; i >= 0; i-- { // reverse order
		b.AddEntry(entries[i])
	}
	for _, r := range incidents {
		b.AddIncident(r)
	}
	first := b.Build()
	if want := Compute(entries, incidents, opts); !reflect.DeepEqual(first, want) {
		t.Fatalf("builder and Compute disagree\n got: %+v\nwant: %+v", first, want)
	}
	if again := b.Build(); !reflect.DeepEqual(first, again) {
		t.Error("Build must be repeatable")
	}
	// Adding more afterwards is reflected.
	b.AddEntry(fault("R9", t0))
	if after := b.Build(); len(after.NoisyDevices) != 2 || after.NoisyDevices[0].Hostname != "R1" && after.NoisyDevices[1].Hostname != "R9" {
		t.Errorf("entries added after a Build must count: %+v", after.NoisyDevices)
	}
}
