// ==============================================================================
// Package query: tests for filtering, time parsing, tables and the timeline.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package query

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"netlog/internal/collector"
	"netlog/internal/store"
)

var ict = time.FixedZone("ICT", 7*3600)

func mk(host, cat, sev, event, user, summary string, ts time.Time) collector.LogEntry {
	return collector.LogEntry{
		ID: collector.EntryID(host, summary+ts.String()), Hostname: host, Category: cat, Severity: sev,
		Event: event, User: user, Summary: summary, Raw: summary, Timestamp: ts.UTC(), DeviceTS: ts,
	}
}

func seed(t *testing.T) (string, time.Time) {
	t.Helper()
	dir := t.TempDir()
	w, err := store.NewJSONLWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	entries := []collector.LogEntry{
		mk("NHG-BVU-GW-01", "FAULT", "ERROR", "OSPF_ADJ_DOWN", "", "Nbr 10.255.255.4 -> DOWN", now.Add(-10*time.Minute)),
		mk("NHG-BVU-GW-01", "CONFIG", "WARNING", "CONFIG_CHANGE", "tanvt", "Commit applied", now.Add(-40*time.Minute)),
		mk("NHG-HO-GW-01", "CONFIG", "WARNING", "CONFIG_CHANGE", "bachngo", "Configured from vty0", now.Add(-5*time.Hour)),
		mk("NHG-HO-GW-01", "SECURITY", "CRITICAL", "AFTER_HOURS_CHANGE", "bachngo", "Config at 02:10", now.Add(-26*time.Hour)), // previous UTC day
		mk("NHG-HO-GW-01", "SYSTEM", "INFO", "UNKNOWN", "", "chatter", now.Add(-time.Minute)),
	}
	if err := w.Append(entries); err != nil {
		t.Fatal(err)
	}
	// A crash-truncated trailing line and blank lines must be tolerated.
	f, err := os.OpenFile(filepath.Join(store.LogsDir(dir), "2026-10-20.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("\n{\"id\":\"trunc\",\"timestamp\":\"2026-10-20T11")
	f.Close()
	return dir, now
}

func hosts(es []collector.LogEntry) string {
	var s []string
	for _, e := range es {
		s = append(s, e.Hostname+":"+e.Event)
	}
	return strings.Join(s, ",")
}

func TestLoadAndFilters(t *testing.T) {
	dir, now := seed(t)

	all, err := Load(dir, Filter{})
	if err != nil || len(all) != 5 {
		t.Fatalf("all: %d %v", len(all), err)
	}
	for i := 1; i < len(all); i++ {
		if all[i].Timestamp.Before(all[i-1].Timestamp) {
			t.Fatal("Load must return oldest first")
		}
	}

	since, _ := ParseSince("24h", now)
	day, _ := Load(dir, Filter{Since: since, Until: now})
	if len(day) != 4 { // the 26h-old entry is excluded; it lives in the previous day's file
		t.Fatalf("24h window: %d (%s)", len(day), hosts(day))
	}
	week, _ := Load(dir, Filter{Since: now.Add(-7 * 24 * time.Hour), Until: now})
	if len(week) != 5 {
		t.Fatalf("7d window must span two day files: %d", len(week))
	}

	for name, tc := range map[string]struct {
		f    Filter
		want string
	}{
		"host substring":     {Filter{Host: "bvu"}, "NHG-BVU-GW-01:CONFIG_CHANGE,NHG-BVU-GW-01:OSPF_ADJ_DOWN"},
		"user exact":         {Filter{User: "TANVT"}, "NHG-BVU-GW-01:CONFIG_CHANGE"},
		"user not substring": {Filter{User: "tan"}, ""},
		"category":           {Filter{Category: "fault"}, "NHG-BVU-GW-01:OSPF_ADJ_DOWN"},
		"severity":           {Filter{Severity: "CRITICAL"}, "NHG-HO-GW-01:AFTER_HOURS_CHANGE"},
		"event substring":    {Filter{Event: "config"}, "NHG-HO-GW-01:CONFIG_CHANGE,NHG-BVU-GW-01:CONFIG_CHANGE"},
		"combined":           {Filter{Host: "HO", Category: "CONFIG"}, "NHG-HO-GW-01:CONFIG_CHANGE"},
	} {
		got, err := Load(dir, tc.f)
		if err != nil {
			t.Fatal(err)
		}
		if g := hosts(got); g != tc.want {
			t.Errorf("%s: got %q, want %q", name, g, tc.want)
		}
	}

	if got, err := Load(filepath.Join(dir, "nowhere"), Filter{Since: now.Add(-time.Hour)}); err != nil || len(got) != 0 {
		t.Errorf("missing data dir: %v %v", got, err)
	}
}

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 10, 20, 15, 30, 0, 0, ict)
	for in, want := range map[string]time.Time{
		"30m":   now.Add(-30 * time.Minute),
		"2h":    now.Add(-2 * time.Hour),
		"24h":   now.Add(-24 * time.Hour),
		"7d":    now.Add(-7 * 24 * time.Hour),
		"2w":    now.Add(-14 * 24 * time.Hour),
		"today": time.Date(2026, 10, 20, 0, 0, 0, 0, ict),
		"90s":   now.Add(-90 * time.Second),
		"1h30m": now.Add(-90 * time.Minute),
	} {
		got, err := ParseSince(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("ParseSince(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "0h", "-2h", "10x"} {
		if _, err := ParseSince(bad, now); err == nil {
			t.Errorf("ParseSince(%q) should fail", bad)
		}
	}
}

func TestParseTime(t *testing.T) {
	want := time.Date(2026, 10, 20, 10, 10, 0, 0, ict)
	for _, in := range []string{"2026-10-20 10:10:00", "2026-10-20T10:10:00", "2026-10-20T10:10:00+07:00", "2026-10-20T03:10:00Z", "2026-10-20 10:10"} {
		got, err := ParseTime(in, ict)
		if err != nil || !got.Equal(want) {
			t.Errorf("ParseTime(%q) = %v, %v", in, got, err)
		}
	}
	if d, err := ParseTime("2026-10-20", ict); err != nil || !d.Equal(time.Date(2026, 10, 20, 0, 0, 0, 0, ict)) {
		t.Errorf("date only: %v %v", d, err)
	}
	if _, err := ParseTime("yesterday", ict); err == nil {
		t.Error("garbage must fail")
	}
}

func TestWriteTable(t *testing.T) {
	es := []collector.LogEntry{
		mk("NHG-BVU-GW-01", "FAULT", "ERROR", "OSPF_ADJ_DOWN", "", "Nbr 10.255.255.4 -> DOWN", time.Date(2026, 10, 20, 10, 22, 15, 0, ict)),
		mk("R1", "CONFIG", "WARNING", "CONFIG_CHANGE", "tanvt", "Commit applied", time.Date(2026, 10, 20, 9, 44, 1, 0, ict)),
	}
	var plain bytes.Buffer
	if err := WriteTable(&plain, es, Style{Location: ict}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain.String(), "\x1b[") {
		t.Error("no ANSI codes when colour is off")
	}
	lines := strings.Split(strings.TrimRight(plain.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want header + 2 rows, got %d lines", len(lines))
	}
	if !strings.HasPrefix(lines[0], "TIME") || !strings.Contains(lines[0], "SUMMARY") {
		t.Errorf("header: %q", lines[0])
	}
	// Columns line up: every row's SUMMARY starts at the same offset as the header's.
	col := strings.Index(lines[0], "SUMMARY")
	if strings.Index(lines[1], "Nbr 10.255.255.4") != col || strings.Index(lines[2], "Commit applied") != col {
		t.Errorf("columns misaligned:\n%s", plain.String())
	}
	if !strings.Contains(lines[1], "2026-10-20 10:22:15") || !strings.Contains(lines[1], " -  ") {
		t.Errorf("time/user rendering: %q", lines[1])
	}

	var colour bytes.Buffer
	if err := WriteTable(&colour, es, Style{Color: true, Location: ict}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(colour.String(), "\x1b[31m") || !strings.Contains(colour.String(), "\x1b[33m") {
		t.Error("ERROR should be red and WARNING yellow")
	}
	// Colour must not disturb alignment once codes are stripped.
	stripped := regexpStrip(colour.String())
	if stripped != plain.String() {
		t.Errorf("colour changed the layout:\n%q\n%q", stripped, plain.String())
	}

	var empty bytes.Buffer
	WriteTable(&empty, nil, Style{})
	if !strings.Contains(empty.String(), "No matching events") {
		t.Errorf("empty result message: %q", empty.String())
	}
}

func regexpStrip(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, []collector.LogEntry{mk("R1", "FAULT", "ERROR", "X", "", "a <b>", time.Now())}); err != nil {
		t.Fatal(err)
	}
	var back []collector.LogEntry
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil || len(back) != 1 || back[0].Summary != "a <b>" {
		t.Fatalf("round trip: %v %+v", err, back)
	}
	buf.Reset()
	WriteJSON(&buf, nil)
	if strings.TrimSpace(buf.String()) != "[]" {
		t.Errorf("nil must render [], got %q", buf.String())
	}
}

func TestSortNewestFirst(t *testing.T) {
	a := mk("A", "", "", "", "", "a", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	b := mk("B", "", "", "", "", "b", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	es := []collector.LogEntry{a, b}
	SortNewestFirst(es)
	if es[0].Hostname != "B" {
		t.Error("newest must come first")
	}
}

func TestTimelineCorrelation(t *testing.T) {
	base := time.Date(2026, 10, 20, 10, 12, 0, 0, ict)
	es := []collector.LogEntry{
		mk("NHG-TRANSIT-GW-01", "FAULT", "ERROR", "BGP_PEER_DOWN", "", "BGP peer 10.255.255.5 down", base.Add(18*time.Second)),
		mk("NHG-TRANSIT-GW-01", "CONFIG", "WARNING", "CONFIG_CHANGE", "tanvt", "commit", base),
		mk("NHG-HO-GW-01", "FAULT", "ERROR", "OSPF_ADJ_DOWN", "", "OSPF recalculation", base.Add(20*time.Second)), // other device: no cause
		mk("NHG-TRANSIT-GW-01", "FAULT", "ERROR", "LINK_DOWN", "", "late fault", base.Add(11*time.Minute)),        // outside 10 min
		mk("NHG-TRANSIT-GW-01", "SYSTEM", "INFO", "UNKNOWN", "", "noise", base.Add(time.Second)),
		mk("NHG-BVU-GW-01", "FAULT", "WARNING", "VRRP_TRANSITION", "", "BACKUP -> MASTER", base.Add(22*time.Second)),
	}
	rows := BuildTimeline(es, TimelineOptions{})

	var order []string
	for _, r := range rows {
		order = append(order, r.Entry.Event)
	}
	if got := strings.Join(order, ","); got != "CONFIG_CHANGE,BGP_PEER_DOWN,OSPF_ADJ_DOWN,VRRP_TRANSITION,LINK_DOWN" {
		t.Fatalf("order (UNKNOWN hidden): %s", got)
	}
	if len(BuildTimeline(es, TimelineOptions{IncludeUnknown: true})) != 6 {
		t.Error("IncludeUnknown must keep the noise")
	}

	notes := map[string]string{}
	for _, r := range rows {
		notes[r.Entry.Event] = r.Note(ict)
	}
	if want := "Likely caused by config change by tanvt at 10:12:00 (18s prior)"; notes["BGP_PEER_DOWN"] != want {
		t.Errorf("note = %q, want %q", notes["BGP_PEER_DOWN"], want)
	}
	for _, ev := range []string{"OSPF_ADJ_DOWN", "VRRP_TRANSITION", "LINK_DOWN", "CONFIG_CHANGE"} {
		if notes[ev] != "" {
			t.Errorf("%s must not be annotated, got %q", ev, notes[ev])
		}
	}

	// From trims rows but the earlier config change still explains the fault.
	trimmed := BuildTimeline(es, TimelineOptions{From: base.Add(10 * time.Second)})
	if len(trimmed) == 0 || trimmed[0].Entry.Event != "BGP_PEER_DOWN" || trimmed[0].Note(ict) == "" {
		t.Fatalf("trim must keep correlation: %+v", trimmed)
	}

	var buf bytes.Buffer
	if err := WriteTimeline(&buf, rows, Style{Location: ict}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "10:12:00  NHG-TRANSIT-GW-01  [CONFIG]") || !strings.Contains(out, "└── Likely caused by config change by tanvt at 10:12:00 (18s prior)") {
		t.Errorf("timeline rendering:\n%s", out)
	}
	if !strings.Contains(out, "User 'tanvt': commit") {
		t.Errorf("config rows should name the user:\n%s", out)
	}
	if strings.Contains(out, "2026") {
		t.Errorf("single-day timeline should show time only:\n%s", out)
	}
	// The note sits on its own line directly below its fault.
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.Contains(l, "BGP peer 10.255.255.5") && !strings.Contains(lines[i+1], "└──") {
			t.Errorf("note not directly below its fault:\n%s", out)
		}
	}

	// Multi-day windows include the date.
	multi := BuildTimeline([]collector.LogEntry{
		mk("R1", "CONFIG", "WARNING", "CONFIG_CHANGE", "a", "x", base),
		mk("R1", "FAULT", "ERROR", "LINK_DOWN", "", "y", base.Add(30*time.Hour)),
	}, TimelineOptions{})
	buf.Reset()
	WriteTimeline(&buf, multi, Style{Location: ict})
	if !strings.Contains(buf.String(), "10-20 10:12:00") || !strings.Contains(buf.String(), "10-21 16:12:00") {
		t.Errorf("multi-day timeline should show dates:\n%s", buf.String())
	}
	buf.Reset()
	WriteTimeline(&buf, nil, Style{})
	if !strings.Contains(buf.String(), "No events") {
		t.Errorf("empty message: %q", buf.String())
	}
}

func TestWriteIncidentList(t *testing.T) {
	rs := []collector.IncidentReport{{
		ID: "a1b2c3d4", Timestamp: time.Date(2026, 10, 20, 10, 22, 15, 0, ict), Hostname: "NHG-BVU-GW-01", Playbook: "ospf_adj_down",
		TriggerLog: collector.LogEntry{Event: "OSPF_ADJ_DOWN", Summary: "Nbr 10.255.255.4 -> DOWN", Severity: "ERROR"},
	}}
	var buf bytes.Buffer
	if err := WriteIncidentList(&buf, rs, Style{Location: ict}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"TIME", "DEVICE", "PLAYBOOK", "TRIGGER", "2026-10-20 10:22:15", "NHG-BVU-GW-01", "ospf_adj_down", "OSPF_ADJ_DOWN: Nbr 10.255.255.4 -> DOWN", "a1b2c3d4"} {
		if !strings.Contains(out, want) {
			t.Errorf("incident list missing %q:\n%s", want, out)
		}
	}
	buf.Reset()
	if err := WriteIncidentJSON(&buf, rs[0]); err != nil || !strings.Contains(buf.String(), `"playbook": "ospf_adj_down"`) {
		t.Errorf("incident json: %v %s", err, buf.String())
	}
	buf.Reset()
	rs[0].Diagnostics = []collector.DiagCmd{
		{Command: "show ip bgp summary", Output: "BGP router identifier 10.0.0.1", DurationMs: 42},
		{Command: "show ip route", Error: "timeout", DurationMs: 5000},
	}
	rs[0].TriageHints = []string{"Check physical link", "Verify peer address"}
	rs[0].TriggerLog.User = "admin"
	if err := WriteIncidentDetail(&buf, rs[0], Style{Location: ict, Color: true}); err != nil {
		t.Fatal(err)
	}
	detailOut := buf.String()
	for _, want := range []string{
		"INCIDENT REPORT:", "a1b2c3d4", "NHG-BVU-GW-01", "ospf_adj_down",
		"User:", "admin",
		"TRIGGERING LOG:", "TRIAGE HINTS:", "Check physical link",
		"show ip bgp summary", "42ms", "OK",
		"show ip route", "ERROR: timeout",
	} {
		if !strings.Contains(detailOut, want) {
			t.Errorf("incident detail missing %q:\n%s", want, detailOut)
		}
	}
	buf.Reset()
	WriteIncidentList(&buf, nil, Style{})
	if !strings.Contains(buf.String(), "No incidents") {
		t.Errorf("empty message: %q", buf.String())
	}
}

func TestShortDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		42 * time.Second: "42s", time.Minute: "1m", 90 * time.Second: "1m30s", 5 * time.Minute: "5m", 10*time.Minute + 400*time.Millisecond: "10m",
	} {
		if got := shortDuration(d); got != want {
			t.Errorf("shortDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestTerminalEscapesFromDevicesAreNeutralised(t *testing.T) {
	evil := mk("R1\x1b[2J", "FAULT", "ERROR", "X", "adm\x1b]0;pwned\x07in", "boom\x1b[31m red \x9b2J \r overwritten", time.Date(2026, 10, 20, 10, 0, 0, 0, ict))
	cfg := mk("R1\x1b[2J", "CONFIG", "WARNING", "CONFIG_CHANGE", "x\x1b[1mbold", "commit", time.Date(2026, 10, 20, 9, 59, 0, 0, ict))

	var table, tl, inc bytes.Buffer
	if err := WriteTable(&table, []collector.LogEntry{evil}, Style{Location: ict}); err != nil {
		t.Fatal(err)
	}
	if err := WriteTimeline(&tl, BuildTimeline([]collector.LogEntry{cfg, evil}, TimelineOptions{}), Style{Location: ict}); err != nil {
		t.Fatal(err)
	}
	if err := WriteIncidentList(&inc, []collector.IncidentReport{{
		ID: "ab\x1bcd", Timestamp: evil.Timestamp, Hostname: "R1\x1b[2J", Playbook: "p\x1b",
		TriggerLog: collector.LogEntry{Event: "E\x1b", Summary: "s\x9b"},
	}}, Style{Location: ict}); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"table": table.String(), "timeline": tl.String(), "incidents": inc.String()} {
		for _, bad := range []string{"\x1b", "\x07", "\r", "\x9b"} {
			if strings.Contains(out, bad) {
				t.Errorf("%s output contains raw control byte %q:\n%q", name, bad, out)
			}
		}
	}
	// With colour on, the only escapes present are the tool's own.
	var coloured bytes.Buffer
	WriteTable(&coloured, []collector.LogEntry{evil}, Style{Color: true, Location: ict})
	if strings.Contains(regexpStrip(coloured.String()), "\x1b") {
		t.Error("device text smuggled an escape through the colour path")
	}
}

func TestLoadTailReadsOnlyTheEnd(t *testing.T) {
	dir := t.TempDir()
	w, _ := store.NewJSONLWriter(dir)
	base := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	var es []collector.LogEntry
	for i := 0; i < 2000; i++ {
		es = append(es, mk("R1", "SYSTEM", "INFO", "E"+strconv.Itoa(i), "", strings.Repeat("x", 100), base.Add(time.Duration(i)*time.Second)))
	}
	if err := w.Append(es); err != nil {
		t.Fatal(err)
	}
	got, err := LoadTail(dir, Filter{Since: base.Add(-time.Hour)}, 20_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || len(got) >= 2000 {
		t.Fatalf("tail should return a recent subset, got %d of 2000", len(got))
	}
	if last := got[len(got)-1]; last.Event != "E1999" {
		t.Errorf("the newest line must be included, got %s", last.Event)
	}
	for _, e := range got {
		if e.Event == "" {
			t.Fatal("a cut-in-half first line must be discarded, not returned as an empty entry")
		}
	}
	all, _ := LoadTail(dir, Filter{Since: base.Add(-time.Hour)}, 100_000_000)
	if len(all) != 2000 {
		t.Errorf("a tail larger than the file reads everything, got %d", len(all))
	}
}
