// ==============================================================================
// Package store: tests for the JSONL writer, retention and incident files.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package store

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netlog/internal/collector"
)

func le(host, raw string, ts time.Time) collector.LogEntry {
	return collector.LogEntry{ID: collector.EntryID(host, raw), Hostname: host, Raw: raw, Timestamp: ts, DeviceTS: ts, Summary: raw}
}

func readLines(t *testing.T, path string) []collector.LogEntry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []collector.LogEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e collector.LogEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("bad JSONL line %q: %v", sc.Text(), err)
		}
		out = append(out, e)
	}
	return out
}

func TestJSONLAppendPartitionsByUTCDay(t *testing.T) {
	dir := t.TempDir()
	w, err := NewJSONLWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	ict := time.FixedZone("ICT", 7*3600)
	// 06:00 ICT on the 21st is 23:00 UTC on the 20th.
	a := le("R1", "late-utc-20th", time.Date(2026, 10, 21, 6, 0, 0, 0, ict))
	b := le("R1", "early-utc-21st", time.Date(2026, 10, 21, 8, 0, 0, 0, ict))
	if err := w.Append([]collector.LogEntry{a, b}); err != nil {
		t.Fatal(err)
	}
	if err := w.Append([]collector.LogEntry{le("R2", "<a & b>", time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))}); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(nil); err != nil {
		t.Fatal(err)
	}

	d20 := readLines(t, filepath.Join(LogsDir(dir), "2026-10-20.jsonl"))
	d21 := readLines(t, filepath.Join(LogsDir(dir), "2026-10-21.jsonl"))
	if len(d20) != 2 || len(d21) != 1 || d21[0].Raw != "early-utc-21st" {
		t.Fatalf("partitioning wrong: %d / %d lines", len(d20), len(d21))
	}
	raw, _ := os.ReadFile(filepath.Join(LogsDir(dir), "2026-10-20.jsonl"))
	if !strings.Contains(string(raw), "<a & b>") {
		t.Errorf("HTML characters must not be escaped in stored raw text")
	}
	if n := strings.Count(string(raw), "\n"); n != 2 {
		t.Errorf("want one line per entry, got %d newlines", n)
	}
	// Appending again must not rewrite earlier lines.
	if err := w.Append([]collector.LogEntry{le("R1", "more", time.Date(2026, 10, 20, 11, 0, 0, 0, time.UTC))}); err != nil {
		t.Fatal(err)
	}
	if got := readLines(t, filepath.Join(LogsDir(dir), "2026-10-20.jsonl")); len(got) != 3 || got[0].Raw != "late-utc-20th" {
		t.Fatalf("append altered earlier data: %+v", got)
	}
}

func TestPrune(t *testing.T) {
	dir := t.TempDir()
	logs := LogsDir(dir)
	if err := os.MkdirAll(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"2026-09-01.jsonl", "2026-10-10.jsonl", "2026-10-19.jsonl", "2026-10-20.jsonl", "notes.txt", "garbage.jsonl"} {
		if err := os.WriteFile(filepath.Join(logs, n), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 10, 20, 15, 0, 0, 0, time.UTC)
	if n, err := Prune(dir, 0, now); err != nil || n != 0 {
		t.Fatalf("keepDays 0 must disable pruning: %d %v", n, err)
	}
	n, err := Prune(dir, 7, now)
	if err != nil || n != 2 { // 09-01 and 10-10 are older than 7 days
		t.Fatalf("pruned %d (%v), want 2", n, err)
	}
	for _, keep := range []string{"2026-10-19.jsonl", "2026-10-20.jsonl", "notes.txt", "garbage.jsonl"} {
		if _, err := os.Stat(filepath.Join(logs, keep)); err != nil {
			t.Errorf("%s must be kept: %v", keep, err)
		}
	}
	if n, err := Prune(filepath.Join(dir, "missing"), 7, now); err != nil || n != 0 {
		t.Errorf("missing dir: %d %v", n, err)
	}
}

func TestIncidentRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "incidents")
	ts := time.Date(2026, 10, 20, 10, 22, 15, 0, time.UTC)
	r := collector.IncidentReport{
		ID: "a1b2c3d4", Timestamp: ts, Hostname: "NHG/BVU GW", Playbook: "ospf_adj_down",
		TriggerLog:  collector.LogEntry{Event: "OSPF_ADJ_DOWN", Summary: "Nbr down"},
		Diagnostics: []collector.DiagCmd{{Command: "show ip ospf neighbor", Output: "x"}},
		TriageHints: []string{"hint"},
	}
	p1, err := WriteIncident(dir, r)
	if err != nil {
		t.Fatal(err)
	}
	if want := "2026-10-20_102215_NHG_BVU_GW_OSPF_ADJ_DOWN.json"; filepath.Base(p1) != want {
		t.Errorf("file name %q, want %q", filepath.Base(p1), want)
	}
	// Same host+event+second must not overwrite.
	r2 := r
	r2.ID = "ffff0000"
	p2, err := WriteIncident(dir, r2)
	if err != nil || p2 == p1 {
		t.Fatalf("collision handling: %q vs %q (%v)", p1, p2, err)
	}

	got, err := ListIncidents(dir, ts.Add(-time.Hour))
	if err != nil || len(got) != 2 {
		t.Fatalf("list: %d %v", len(got), err)
	}
	if none, _ := ListIncidents(dir, ts.Add(time.Hour)); len(none) != 0 {
		t.Errorf("since filter ignored")
	}
	one, err := FindIncident(dir, "a1b2")
	if err != nil || one.ID != "a1b2c3d4" || one.Diagnostics[0].Output != "x" {
		t.Fatalf("find: %+v %v", one, err)
	}
	if _, err := FindIncident(dir, "zzzz"); err == nil {
		t.Error("unknown id must fail")
	}
	if _, err := FindIncident(dir, ""); err == nil {
		t.Error("empty id must fail")
	}
	r3 := r
	r3.ID = "a1b2ffff"
	r3.Timestamp = ts.Add(time.Minute)
	if _, err := WriteIncident(dir, r3); err != nil {
		t.Fatal(err)
	}
	if _, err := FindIncident(dir, "a1b2"); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Errorf("ambiguous prefix must fail, got %v", err)
	}
	if list, err := ListIncidents(filepath.Join(dir, "nope"), time.Time{}); err != nil || len(list) != 0 {
		t.Errorf("missing dir: %v %v", list, err)
	}
	// Non-JSON clutter in the directory is ignored.
	if err := os.WriteFile(filepath.Join(dir, "junk.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if list, _ := ListIncidents(dir, time.Time{}); len(list) != 3 {
		t.Errorf("junk file broke listing: %d", len(list))
	}
}
