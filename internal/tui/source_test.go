package tui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netlog/internal/collector"
	"netlog/internal/store"
)

func entry(id, host string, at time.Time) collector.LogEntry {
	return collector.LogEntry{
		ID: id, Timestamp: at, DeviceTS: at, Hostname: host, Category: "FAULT", Severity: "ERROR",
		Event: "LINK_DOWN", Object: id, Summary: "summary " + id, Raw: "raw " + id,
	}
}

func appendEntries(t *testing.T, dir string, es ...collector.LogEntry) {
	t.Helper()
	w, err := store.NewJSONLWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(es); err != nil {
		t.Fatal(err)
	}
}

func dayFile(dir string, at time.Time) string {
	return filepath.Join(store.LogsDir(dir), store.LogFileName(at))
}

func ids(es []collector.LogEntry) string {
	var out []string
	for _, e := range es {
		out = append(out, e.ID)
	}
	return strings.Join(out, ",")
}

func TestFileSourceFirstPollThenIncremental(t *testing.T) {
	dir := t.TempDir()
	src := NewFileSource(dir, nil, SourceOptions{})

	// No logs at all yet is not an error.
	if got, _, err := src.Poll(now); err != nil || len(got) != 0 {
		t.Fatalf("empty data dir: %v %v", got, err)
	}

	appendEntries(t, dir,
		entry("e3", "r1", now.Add(-3*time.Minute)),
		entry("e1", "r1", now.Add(-10*time.Minute)),
		entry("old", "r1", now.Add(-30*time.Hour)), // outside the 24h window (and its file too)
		entry("e2", "r1", now.Add(-5*time.Minute)),
	)
	got, _, err := src.Poll(now)
	if err != nil {
		t.Fatal(err)
	}
	if ids(got) != "e1,e2,e3" { // sorted by time, the old one skipped
		t.Fatalf("first poll = %s", ids(got))
	}
	// Nothing new: nothing returned, however often it is polled.
	if got, _, _ := src.Poll(now); len(got) != 0 {
		t.Errorf("second poll returned %s", ids(got))
	}
	appendEntries(t, dir, entry("e4", "r2", now.Add(-time.Minute)))
	if got, _, _ := src.Poll(now); ids(got) != "e4" {
		t.Errorf("incremental poll = %s", ids(got))
	}
	// Read offsets never go backwards: nothing is delivered twice.
	appendEntries(t, dir, entry("e5", "r2", now))
	if got, _, _ := src.Poll(now); ids(got) != "e5" {
		t.Errorf("third poll = %s", ids(got))
	}
}

func TestFileSourceWaitsForCompleteLinesAndSkipsDamagedOnes(t *testing.T) {
	dir := t.TempDir()
	appendEntries(t, dir, entry("a", "r1", now.Add(-time.Hour)))
	src := NewFileSource(dir, nil, SourceOptions{})
	src.Poll(now)

	path := dayFile(dir, now)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	line, _ := json.Marshal(entry("b", "r1", now.Add(-time.Minute)))
	// A writer caught mid-line: only half of it is on disk.
	f.Write(line[:len(line)/2])
	if got, _, _ := src.Poll(now); len(got) != 0 {
		t.Fatalf("a partial line was consumed: %s", ids(got))
	}
	f.Write(line[len(line)/2:])
	f.WriteString("\n")
	f.WriteString("{this is not json}\n\n   \n{\"id\":\"no timestamp\"}\n")
	last, _ := json.Marshal(entry("c", "r1", now))
	f.Write(append(last, '\n'))
	got, _, err := src.Poll(now)
	if err != nil || ids(got) != "b,c" {
		t.Fatalf("after completion: %s, %v", ids(got), err)
	}
}

func TestFileSourceHandlesNewDayTruncationAndLargeFiles(t *testing.T) {
	dir := t.TempDir()
	yesterday := now.Add(-24 * time.Hour)
	appendEntries(t, dir, entry("y1", "r1", yesterday.Add(2*time.Hour)))
	src := NewFileSource(dir, nil, SourceOptions{})
	if got, _, _ := src.Poll(now); ids(got) != "y1" {
		t.Fatalf("yesterday's file inside the window: %s", ids(got))
	}
	// A new day's file appears after start-up: all of it is read.
	tomorrow := now.Add(24 * time.Hour)
	appendEntries(t, dir, entry("t1", "r1", tomorrow), entry("t2", "r1", tomorrow))
	if got, _, _ := src.Poll(tomorrow); ids(got) != "t1,t2" {
		t.Errorf("new day = %s", ids(got))
	}
	// A file that shrank (rotated or replaced) is read again from the top.
	if err := os.WriteFile(dayFile(dir, tomorrow), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	src.Poll(tomorrow)
	appendEntries(t, dir, entry("t3", "r1", tomorrow))
	if got, _, _ := src.Poll(tomorrow); ids(got) != "t3" {
		t.Errorf("after truncation = %s", ids(got))
	}

	// A huge file is read from its tail only, resuming at a line boundary.
	big := t.TempDir()
	var es []collector.LogEntry
	for i := 0; i < 300; i++ {
		es = append(es, entry(string(rune('A'+i%26))+strings.Repeat("x", i%7)+time.Duration(i).String(), "r1", now.Add(-time.Duration(300-i)*time.Second)))
	}
	appendEntries(t, big, es...)
	tail := NewFileSource(big, nil, SourceOptions{InitialBytes: 8 << 10})
	got, _, err := tail.Poll(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || len(got) >= 300 {
		t.Fatalf("tail read %d of 300 entries", len(got))
	}
	if got[len(got)-1].Timestamp != es[299].Timestamp {
		t.Error("the tail must end with the newest entry")
	}
	for _, e := range got {
		if e.ID == "" || e.Hostname != "r1" {
			t.Fatalf("a partial first line leaked into the results: %+v", e)
		}
	}
}

func TestFileSourceChunkLimitAndOversizedLine(t *testing.T) {
	dir := t.TempDir()
	appendEntries(t, dir, entry("seed", "r1", now.Add(-time.Hour)))
	src := NewFileSource(dir, nil, SourceOptions{ChunkBytes: 2048})
	src.Poll(now)

	// More than a chunk of new data arrives: it is drained over several polls.
	var es []collector.LogEntry
	for i := 0; i < 40; i++ {
		es = append(es, entry("n"+time.Duration(i).String(), "r1", now.Add(-time.Minute)))
	}
	appendEntries(t, dir, es...)
	total := 0
	for i := 0; i < 50 && total < 40; i++ {
		got, _, _ := src.Poll(now)
		total += len(got)
	}
	if total != 40 {
		t.Errorf("drained %d of 40 entries", total)
	}

	// A single line bigger than the chunk is skipped instead of stalling the tail.
	f, _ := os.OpenFile(dayFile(dir, now), os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(strings.Repeat("z", 5000) + "\n")
	f.Close()
	appendEntries(t, dir, entry("after-giant", "r1", now))
	var got []collector.LogEntry
	for i := 0; i < 10; i++ {
		g, _, _ := src.Poll(now)
		got = append(got, g...)
	}
	if ids(got) != "after-giant" {
		t.Errorf("after an oversized line: %s", ids(got))
	}
}

func TestFileSourceDevices(t *testing.T) {
	dir := t.TempDir()
	h, err := store.LoadHealth(store.HealthPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	h.Succeeded("ok-sw", now.Add(-time.Minute))
	h.NewLogs("ok-sw", now.Add(-time.Minute))
	h.Failed("bad-sw", now.Add(-30*time.Second), "ssh: connection refused", false)
	h.Succeeded("stale-sw", now.Add(-48*time.Hour))
	if err := h.Save(); err != nil {
		t.Fatal(err)
	}

	src := NewFileSource(dir, []string{"ok-sw", "bad-sw", "stale-sw", "never-sw"}, SourceOptions{})
	_, rows, err := src.Poll(now)
	if err != nil {
		t.Fatal(err)
	}
	byHost := map[string]DeviceRow{}
	for _, r := range rows {
		byHost[r.Hostname] = r
	}
	if len(rows) != 4 {
		t.Fatalf("%d rows: %+v", len(rows), rows)
	}
	if r := byHost["bad-sw"]; r.Status != "FAILING" || !strings.Contains(r.Detail, "connection refused") || r.LastPoll.IsZero() {
		t.Errorf("bad-sw: %+v", r)
	}
	if r := byHost["ok-sw"]; r.Status != "OK" {
		t.Errorf("ok-sw: %+v", r)
	}
	if r := byHost["stale-sw"]; r.Status != "STALE" {
		t.Errorf("stale-sw: %+v", r)
	}
	if r := byHost["never-sw"]; r.Status != "NEVER POLLED" || !r.LastPoll.IsZero() {
		t.Errorf("never-sw: %+v", r)
	}
	if rows[0].Status != "FAILING" {
		t.Errorf("most urgent first, got %s", rows[0].Status)
	}

	// The health file is re-read at most every HealthEvery, not every poll.
	h.Succeeded("late-sw", now)
	h.Save()
	if _, rows, _ := src.Poll(now.Add(time.Second)); len(rows) != 4 {
		t.Errorf("health re-read too early: %d rows", len(rows))
	}
	if _, rows, _ := src.Poll(now.Add(10 * time.Second)); len(rows) != 5 {
		t.Errorf("health not refreshed: %d rows", len(rows))
	}

	// An unreadable health file is reported but the last good list stays.
	if err := os.WriteFile(store.HealthPath(dir), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, rows, err = src.Poll(now.Add(30 * time.Second))
	if err == nil || len(rows) != 5 {
		t.Errorf("broken health file: err=%v rows=%d", err, len(rows))
	}
}

func TestModelEndToEndFromFiles(t *testing.T) {
	dir := t.TempDir()
	appendEntries(t, dir,
		entry("d1", "core1", now.Add(-5*time.Minute)),
	)
	src := NewFileSource(dir, []string{"core1"}, SourceOptions{})
	m := model()
	poll := func() {
		es, rows, _ := src.Poll(now)
		m.Ingest(es)
		m.SetDevices(rows)
	}
	poll()
	text := rowsOf(m.Render(100, 24, now))
	mustContain(t, "dashboard from files", text, "FAULT 1", "core1", "summary d1", "NEVER POLLED")
	appendEntries(t, dir, entry("d2", "core1", now.Add(-time.Minute)))
	poll()
	mustContain(t, "after an append", rowsOf(m.Render(100, 24, now)), "FAULT 2", "summary d2")
}
