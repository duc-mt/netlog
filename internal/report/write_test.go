// ==============================================================================
// Package report: tests for the table and JSON writers.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-24
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"netlog/internal/collector"
	"netlog/internal/query"
)

var ict = time.FixedZone("ICT", 7*3600)

// reANSI matches the colour codes the tool itself emits.
var reANSI = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func strip(s string) string { return reANSI.ReplaceAllString(s, "") }

// fixture is a report with something in every section.
func fixture() Report {
	day := 24 * time.Hour
	entries := cat(
		repeat(12, func(int) collector.LogEntry { return fault("SW-LAB-LONG", t0.Add(-2*time.Hour)) }),
		repeat(3, func(int) collector.LogEntry { return fault("SW-CORE", t0.Add(-day)) }),
		repeat(2, func(int) collector.LogEntry { return change("SW-CORE", "alice", t0.Add(-3*time.Hour)) }),
		[]collector.LogEntry{change("SW-LAB-LONG", "", t0.Add(-4*time.Hour))},
		[]collector.LogEntry{afterHours("SW-CORE", "bob", t0.Add(-time.Hour))},
		[]collector.LogEntry{
			loginFail("SW-LAB-LONG", "203.0.113.9", t0),
			loginFail("SW-CORE", "203.0.113.9", t0),
			loginFail("SW-CORE", "198.51.100.7", t0),
		},
		repeat(5, func(int) collector.LogEntry { return fault("SW-CORE", t0.Add(-9*day)) }), // previous week
	)
	incidents := []collector.IncidentReport{
		incident("SW-GONE", t0, diagNoConn),
		incident("SW-GONE", t0.Add(-time.Hour), diagNoConn),
		incident("SW-LAB-LONG", t0, diagOK),
	}
	return Compute(entries, incidents, Options{Since: t0.Add(-Week), Until: t0, Compare: true, Label: "7d"})
}

func table(t *testing.T, r Report, st query.Style) string {
	t.Helper()
	var b bytes.Buffer
	if err := WriteTable(&b, r, st); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// The whole text output, frozen. This is the check on alignment, ordering,
// headings and number formatting.
func TestWriteTableGolden(t *testing.T) {
	want := `=== Noisy Devices (top 10, last 7d) ===
DEVICE       FAULTS
SW-LAB-LONG      12
SW-CORE           3

=== Change Accountability (last 7d) ===
USER       CHANGES  AFTER-HOURS
alice            2            0
bob              1            1
(unknown)        1            0

After-hours changes: 1
TIME                 DEVICE   USER
2026-10-24 18:00:00  SW-CORE  bob

=== Security Watchlist (top 10, last 7d) ===
SOURCE IP     DEVICES  EVENTS  HOSTS
203.0.113.9         2       2  SW-CORE, SW-LAB-LONG
198.51.100.7        1       1  SW-CORE

=== Event Volume by Category/Day (UTC, last 7d) ===
DAY         CONFIG  AUTH  FAULT  SECURITY  SYSTEM
2026-10-17       0     0      0         0       0
2026-10-18       0     0      0         0       0
2026-10-19       0     0      0         0       0
2026-10-20       0     0      0         0       0
2026-10-21       0     0      0         0       0
2026-10-22       0     0      0         0       0
2026-10-23       0     0      3         0       0
2026-10-24       3     3     12         1       0

=== Week-over-Week (last 7d vs previous 7d) ===
CATEGORY  PREVIOUS  CURRENT  CHANGE  CHANGE %
CONFIG           0        3      +3       n/a
AUTH             0        3      +3       n/a
FAULT            5       15     +10   +200.0%
SECURITY         0        1      +1       n/a
SYSTEM           0        0       0       n/a
TOTAL            5       22     +17   +340.0%

=== Incident Closure (last 7d) ===
Incidents:                  3
All diagnostics succeeded:  1 (33.3%)
Unreachable during triage:  2 (66.7%)
Some commands failed:       0 (0.0%)

Devices unreachable during triage:
DEVICE   UNREACHABLE  INCIDENTS  ALWAYS
SW-GONE            2          2     yes
`
	got := table(t, fixture(), query.Style{Location: ict})
	if got != want {
		t.Errorf("table output changed.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	for i, line := range strings.Split(got, "\n") {
		if strings.HasSuffix(line, " ") {
			t.Errorf("line %d has trailing spaces: %q", i+1, line)
		}
	}
}

func TestWriteTableColourKeepsLayout(t *testing.T) {
	plain := table(t, fixture(), query.Style{Location: ict})
	coloured := table(t, fixture(), query.Style{Color: true, Location: ict})
	if coloured == plain {
		t.Error("colour was requested but nothing was coloured")
	}
	if strip(coloured) != plain {
		t.Errorf("colour changed the layout:\n%q\n%q", strip(coloured), plain)
	}
	if strings.Contains(plain, "\x1b") {
		t.Error("no ANSI codes when colour is off")
	}
	// Headings are bold; a source touching several devices is red.
	if !strings.Contains(coloured, "\x1b[1m=== Noisy Devices") || !strings.Contains(coloured, "\x1b[31m203.0.113.9") {
		t.Errorf("expected bold headings and a red multi-device source:\n%q", coloured)
	}
}

func TestWriteTableNoData(t *testing.T) {
	opts := Options{Since: t0.Add(-Week), Until: t0, Label: "7d"}
	got := table(t, Compute(nil, nil, opts), query.Style{})
	if n := strings.Count(got, "No matching events."); n != 4 {
		t.Errorf("want the no-data line in 4 sections, got %d:\n%s", n, got)
	}
	if !strings.Contains(got, "No incidents.") {
		t.Errorf("incident section should say so:\n%s", got)
	}
	if strings.Contains(got, "Week-over-Week") {
		t.Errorf("the delta section appears only when computed:\n%s", got)
	}

	// Compared, with nothing in either window: one line, not a table of n/a.
	opts.Compare = true
	got = table(t, Compute(nil, nil, opts), query.Style{})
	if n := strings.Count(got, "No matching events."); n != 5 || strings.Contains(got, "n/a") {
		t.Errorf("empty delta section:\n%s", got)
	}

	// A zero Report (never passed through Compute) must not panic either.
	if out := table(t, Report{}, query.Style{}); !strings.Contains(out, "Noisy Devices (top 10, all time)") {
		t.Errorf("zero report:\n%s", out)
	}
}

func TestWriteTableHeadings(t *testing.T) {
	cases := []struct {
		name string
		opts Options
		want string
	}{
		{"explicit label", Options{Since: t0.Add(-Week), Until: t0, Label: "7d"}, "Noisy Devices (top 10, last 7d)"},
		{"label is case-folded", Options{Since: t0.Add(-Week), Until: t0, Label: " 7D "}, "Noisy Devices (top 10, last 7d)"},
		{"today", Options{Since: t0.Add(-5 * time.Hour), Until: t0, Label: "today"}, "Noisy Devices (top 10, today)"},
		{"derived days", Options{Since: t0.Add(-48 * time.Hour), Until: t0}, "Noisy Devices (top 10, last 2d)"},
		{"derived hours", Options{Since: t0.Add(-36 * time.Hour), Until: t0}, "Noisy Devices (top 10, last 36h)"},
		{"derived minutes", Options{Since: t0.Add(-90 * time.Minute), Until: t0}, "Noisy Devices (top 10, last 90m)"},
		{"open window", Options{}, "Noisy Devices (top 10, all time)"},
		{"top is shown", Options{Top: 3, Label: "24h"}, "Noisy Devices (top 3, last 24h)"},
	}
	for _, c := range cases {
		if got := table(t, Compute(nil, nil, c.opts), query.Style{}); !strings.Contains(got, "=== "+c.want+" ===") {
			t.Errorf("%s: want heading %q in:\n%s", c.name, c.want, got)
		}
	}

	// The delta heading says "Week-over-Week" only for a 7-day window.
	d24 := Options{Since: t0.Add(-24 * time.Hour), Until: t0, Compare: true, Label: "24h"}
	if got := table(t, Compute(nil, nil, d24), query.Style{}); !strings.Contains(got, "=== Window-over-Window (last 24h vs the equal window before it) ===") {
		t.Errorf("non-week delta heading:\n%s", got)
	}
}

// Device, user and IP text is untrusted: a crafted value must not be able to
// drive the operator's terminal from any section of the report.
func TestWriteTableNeutralisesHostileText(t *testing.T) {
	evilHost := "R1\x1b[2J\x1b]0;pwned\x07"
	evilUser := "adm\x1b[1mbold\rovr\u009b2J"
	evilIP := "6.6.6.6\x1b[31m\x9b"
	entries := []collector.LogEntry{
		fault(evilHost, t0), fault(evilHost, t0),
		change(evilHost, evilUser, t0),
		afterHours(evilHost, evilUser, t0),
		loginFail(evilHost, evilIP, t0),
		loginFail("R2\x1b[H", evilIP, t0),
	}
	incidents := []collector.IncidentReport{
		incident(evilHost, t0, collector.DiagCmd{Command: "(connect)", Error: "dial\x1b[2J"}),
		incident("R2\x1b[H", t0, diagNoConn),
	}
	rep := Compute(entries, incidents, Options{Since: t0.Add(-Week), Until: t0, Compare: true, Label: "7d\x1b[2J"})

	plain := table(t, rep, query.Style{Location: ict})
	for _, bad := range []string{"\x1b", "\x07", "\r", "\x9b", "\u009b"} {
		if strings.Contains(plain, bad) {
			t.Errorf("output contains raw control %q:\n%q", bad, plain)
		}
	}
	if !strings.Contains(plain, "R1?[2J") {
		t.Errorf("sanitised text should still show the (neutralised) value:\n%s", plain)
	}

	// With colour on, the only escapes left are the tool's own.
	if got := strip(table(t, rep, query.Style{Color: true, Location: ict})); strings.Contains(got, "\x1b") {
		t.Errorf("device text smuggled an escape through the colour path:\n%q", got)
	}
}

// Over-long device text is cut, not allowed to wreck the table.
func TestWriteTableClipsLongValues(t *testing.T) {
	long := strings.Repeat("H", 80)
	rep := Compute([]collector.LogEntry{fault(long, t0)}, nil, Options{Since: t0.Add(-Week), Until: t0})
	got := table(t, rep, query.Style{})
	if strings.Contains(got, long) || !strings.Contains(got, strings.Repeat("H", query.MaxDeviceCol-1)+"…") {
		t.Errorf("hostname should be clipped to %d columns:\n%s", query.MaxDeviceCol, got)
	}
}

func TestWriteTableFormattingHelpers(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	for in, want := range map[*float64]string{nil: "n/a", f(0): "0.0%", f(50): "+50.0%", f(-33.3): "-33.3%", f(1234.5): "+1234.5%"} {
		if got := pctText(in); got != want {
			t.Errorf("pctText = %q, want %q", got, want)
		}
	}
	for in, want := range map[int]string{7: "+7", 0: "0", -4: "-4"} {
		if got := signed(in); got != want {
			t.Errorf("signed(%d) = %q, want %q", in, got, want)
		}
	}
	if got := padLeft("é", 3); got != "  é" {
		t.Errorf("padLeft must count runes, got %q", got)
	}
}

// failAfter errors once n bytes have been written.
type failAfter struct{ n int }

func (f *failAfter) Write(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errors.New("disk full")
	}
	f.n -= len(p)
	return len(p), nil
}

func TestWritersReportWriteErrors(t *testing.T) {
	rep := fixture()
	for _, n := range []int{0, 1, 100, 500} {
		if err := WriteTable(&failAfter{n}, rep, query.Style{}); err == nil {
			t.Errorf("WriteTable with a writer failing after %d bytes returned nil", n)
		}
	}
	if err := WriteJSON(&failAfter{0}, rep); err == nil {
		t.Error("WriteJSON must return the write error")
	}
}

// ==============================================================================
// JSON
// ==============================================================================

func jsonOf(t *testing.T, r Report) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := WriteJSON(&b, r); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestWriteJSONShape(t *testing.T) {
	raw := jsonOf(t, fixture())
	if !json.Valid(raw) {
		t.Fatalf("invalid JSON:\n%s", raw)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range top {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"change_accountability", "incident_closure", "noisy_devices", "security_watchlist", "volume_by_category", "week_over_week"}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("keys = %v, want exactly one per section %v", keys, want)
	}
	if !bytes.HasPrefix(raw, []byte("{\n  \"noisy_devices\": [")) {
		t.Errorf("want two-space indent like query's JSON, got:\n%.80s", raw)
	}
	if bytes.Contains(raw, []byte("\x1b")) || bytes.Contains(raw, []byte("\\u001b")) {
		t.Error("no ANSI in JSON")
	}
}

func TestWriteJSONRoundTrip(t *testing.T) {
	rep := fixture()
	first := jsonOf(t, rep)

	var back Report
	if err := json.Unmarshal(first, &back); err != nil {
		t.Fatal(err)
	}
	if second := jsonOf(t, back); !bytes.Equal(first, second) {
		t.Errorf("not stable across a decode/encode cycle:\n%s\n---\n%s", first, second)
	}
	if !reflect.DeepEqual(back.NoisyDevices, rep.NoisyDevices) ||
		!reflect.DeepEqual(back.SecurityWatchlist, rep.SecurityWatchlist) ||
		!reflect.DeepEqual(back.VolumeByCategory, rep.VolumeByCategory) ||
		!reflect.DeepEqual(back.IncidentClosure, rep.IncidentClosure) ||
		!reflect.DeepEqual(back.ChangeAccountability.ByUser, rep.ChangeAccountability.ByUser) {
		t.Errorf("sections changed in the round trip:\n%+v\n%+v", back, rep)
	}
	if back.WeekOverWeek == nil || back.WeekOverWeek.Total.ChangePct == nil || *back.WeekOverWeek.Total.ChangePct != 340 {
		t.Errorf("week_over_week lost in the round trip: %+v", back.WeekOverWeek)
	}
	if f := back.WeekOverWeek.Categories[0]; f.Category != "CONFIG" || f.ChangePct != nil {
		t.Errorf("an n/a percentage must survive as null: %+v", f)
	}
}

func TestWriteJSONNotComputedAndEmpty(t *testing.T) {
	// Not compared: week_over_week is null; nothing else is.
	rep := Compute(nil, nil, Options{Since: t0.Add(-Week), Until: t0})
	var top map[string]json.RawMessage
	if err := json.Unmarshal(jsonOf(t, rep), &top); err != nil {
		t.Fatal(err)
	}
	if string(top["week_over_week"]) != "null" {
		t.Errorf("week_over_week = %s, want null", top["week_over_week"])
	}
	for _, k := range []string{"noisy_devices", "security_watchlist"} {
		if string(top[k]) != "[]" {
			t.Errorf("%s = %s, want []", k, top[k])
		}
	}
	if string(top["volume_by_category"]) != "{}" {
		t.Errorf("volume_by_category = %s, want {}", top["volume_by_category"])
	}

	// A zero-value Report (not built by Compute) never prints a null section.
	var zero map[string]json.RawMessage
	if err := json.Unmarshal(jsonOf(t, Report{}), &zero); err != nil {
		t.Fatal(err)
	}
	for k, v := range zero {
		if string(v) == "null" && k != "week_over_week" {
			t.Errorf("zero report: %s is null", k)
		}
	}
	var ca struct {
		ByUser     json.RawMessage `json:"by_user"`
		AfterHours json.RawMessage `json:"after_hours"`
	}
	if err := json.Unmarshal(zero["change_accountability"], &ca); err != nil || string(ca.ByUser) != "[]" || string(ca.AfterHours) != "[]" {
		t.Errorf("change_accountability slices: %s %s (%v)", ca.ByUser, ca.AfterHours, err)
	}
	var ic struct {
		Hosts json.RawMessage `json:"unreachable_hosts"`
	}
	if err := json.Unmarshal(zero["incident_closure"], &ic); err != nil || string(ic.Hosts) != "[]" {
		t.Errorf("unreachable_hosts = %s (%v)", ic.Hosts, err)
	}
}

// JSON needs no sanitising (the encoder escapes control bytes) and must be
// lossless, and it must not HTML-escape like the default encoder.
func TestWriteJSONIsLosslessAndUnescaped(t *testing.T) {
	host := "R<1>&\x1b[2J"
	rep := Compute([]collector.LogEntry{fault(host, t0)}, nil, Options{})
	raw := jsonOf(t, rep)
	if bytes.Contains(raw, []byte("\x1b")) {
		t.Error("a raw ESC byte reached the JSON output")
	}
	if !bytes.Contains(raw, []byte("R<1>&")) {
		t.Errorf("HTML escaping must be off:\n%s", raw)
	}
	var back Report
	if err := json.Unmarshal(raw, &back); err != nil || len(back.NoisyDevices) != 1 || back.NoisyDevices[0].Hostname != host {
		t.Errorf("hostname not preserved: %v %+v", err, back.NoisyDevices)
	}
}
