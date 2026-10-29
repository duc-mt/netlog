package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"netlog/internal/collector"
	"netlog/internal/pipeline"
)

var now = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func ev(host, cat, sev, event, obj, summary string, ago time.Duration) collector.LogEntry {
	return collector.LogEntry{
		Timestamp: now.Add(-ago), Hostname: host, Category: cat, Severity: sev,
		Event: event, Object: obj, Summary: summary, Raw: summary,
	}
}

func model() *Model { return NewModel(Options{Loc: time.UTC}) }

func rowsOf(s *Screen) string { return strings.Join(s.Text(), "\n") }

func mustContain(t *testing.T, what, text string, subs ...string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(text, sub) {
			t.Errorf("%s lacks %q:\n%s", what, sub, text)
		}
	}
}

func TestScreenClipsAndSanitises(t *testing.T) {
	s := NewScreen(10, 2)
	s.Put(8, 0, "abcdef", styleRed) // clipped at the right edge
	s.Put(-2, 1, "xyz", styleNone)  // clipped at the left edge
	s.Put(0, 5, "off screen", styleNone)
	s.Put(0, -1, "off screen", styleNone)
	if got := s.Text(); got[0] != "        ab" || got[1] != "z" {
		t.Errorf("rows: %q", got)
	}
	s = NewScreen(40, 1)
	s.Put(0, 0, "a\x1b[2Jb\x00c\u4e2dd\u0301e\U0001F600f\x7f", styleNone)
	// control characters, a wide CJK rune, a combining mark and an astral rune each become one '?'
	if got := s.Text()[0]; got != "a?[2Jb?c?d?e?f?" {
		t.Errorf("sanitised row = %q", got)
	}
	for _, l := range s.Lines(true) {
		if strings.Count(l, "\x1b") != 0 {
			t.Errorf("styleless row contains an escape: %q", l)
		}
	}
	s = NewScreen(6, 1)
	s.PutClipped(0, 0, 6, "abcdefghij", styleNone)
	if s.Text()[0] != "abcde…" {
		t.Errorf("PutClipped = %q", s.Text()[0])
	}
}

func TestScreenLinesAreExactlyWideAndStyled(t *testing.T) {
	s := NewScreen(12, 2)
	s.Put(2, 0, "RED", styleRed)
	s.Put(5, 0, "BOLD", styleBold)
	plain, colour := s.Lines(false), s.Lines(true)
	for i, l := range plain {
		if len([]rune(l)) != 12 || strings.Contains(l, "\x1b") {
			t.Errorf("plain row %d = %q", i, l)
		}
	}
	if !strings.Contains(colour[0], "\x1b[0;31mRED") || !strings.Contains(colour[0], "BOLD\x1b[0m") {
		t.Errorf("styled row: %q", colour[0])
	}
	if strings.Contains(colour[1], "\x1b") {
		t.Errorf("an unstyled row needs no escapes: %q", colour[1])
	}
}

func fullModel() *Model {
	m := model()
	m.Ingest([]collector.LogEntry{
		ev("core1", "FAULT", "ERROR", pipeline.EventLinkDown, "Gi0/1", "Interface Gi0/1, changed state to down", 9*time.Minute),
		ev("core1", "FAULT", "CRITICAL", pipeline.EventBGPPeerDown, "10.0.0.2", "BGP neighbor 10.0.0.2 Down", 8*time.Minute),
		ev("edge2", "CONFIG", "WARNING", pipeline.EventConfigChange, "", "Configured from console by tanvt", 5*time.Minute),
		ev("edge2", "AUTH", "WARNING", pipeline.EventLoginFailure, "", "Failed password for admin", 4*time.Minute),
		ev("fw3", "SECURITY", "CRITICAL", pipeline.EventThreatDetected, "", "SSH brute force", 3*time.Minute),
		ev("fw3", "SYSTEM", "INFO", pipeline.EventUnknown, "", "periodic housekeeping", 2*time.Minute),
		ev("core1", "FAULT", "INFO", pipeline.EventLinkUp, "Gi0/9", "Interface Gi0/9, changed state to up", time.Minute),
	})
	m.SetDevices([]DeviceRow{
		{Hostname: "core1", Status: "FAILING", LastPoll: now.Add(-30 * time.Second), Detail: "ssh: connection refused"},
		{Hostname: "edge2", Status: "STALE", LastPoll: now.Add(-26 * time.Hour)},
		{Hostname: "fw3", Status: "OK", LastPoll: now.Add(-20 * time.Second)},
		{Hostname: "ap4", Status: "SILENT", LastPoll: now.Add(-1 * time.Minute)},
		{Hostname: "new5", Status: "NEVER POLLED"},
	})
	return m
}

func TestRenderLayout(t *testing.T) {
	m := fullModel()
	s := m.Render(120, 30, now)
	rows := s.Text()
	if len(rows) != 30 {
		t.Fatalf("%d rows", len(rows))
	}
	for i, r := range rows {
		if n := len([]rune(r)); n > 120 {
			t.Errorf("row %d is %d wide", i, n)
		}
	}
	mustContain(t, "title row", rows[0], "netlog top", "2026-10-20 12:00:00")
	mustContain(t, "counter row", rows[1], "FAULT 3", "CONFIG 1", "AUTH 1", "SECURITY 1", "SYSTEM 1", "(24h)")
	mustContain(t, "health row", rows[2], "devices 5", "collection health:", "1 FAILING", "1 STALE", "1 SILENT", "1 OK", "1 NEVER POLLED")
	if !strings.HasPrefix(rows[3], "──") {
		t.Errorf("rule row: %q", rows[3])
	}
	mustContain(t, "upper pane", rowsOf(s), "Live events (7)", "CRIT", "WARN", "INFO", "ERR", "core1", "edge2", "fw3",
		"LINK_DOWN", "BGP_PEER_DOWN", "SSH brute force", "12:00:00"[:0]+"11:51:00", "11:59:00")
	// Newest at the bottom of the feed.
	body := rowsOf(s)
	if strings.Index(body, "Interface Gi0/1, changed state to down") > strings.Index(body, "Gi0/9, changed state to up") {
		t.Error("the feed must list the oldest event first and the newest last")
	}
	mustContain(t, "lower panes", body, "Unresolved outages / flapping", "Devices", "core1 link Gi0/1", "down 9m",
		"core1 bgp 10.0.0.2", "FAILING", "ssh: connection refused", "STALE", "SILENT", "never polled", "q quit", "c category filter", "p pause/resume")
	// The two lower panes are split by a vertical rule at w/2.
	sep := 0
	for _, r := range rows[4:] {
		if rr := []rune(r); len(rr) > 60 && rr[60] == '│' {
			sep++
		}
	}
	if sep < 5 {
		t.Errorf("vertical divider found on %d rows", sep)
	}
	// The resolved link (Gi0/9 up with no down) is not an outage.
	if strings.Contains(body, "link Gi0/9") {
		t.Error("an interface that only came up is not an outage")
	}
}

func TestRenderTooSmallAndEveryReasonableSize(t *testing.T) {
	m := fullModel()
	small := m.Render(MinWidth-1, 30, now)
	mustContain(t, "small", rowsOf(small), "terminal too small", "q quit")
	small = m.Render(100, MinHeight-1, now)
	mustContain(t, "short", rowsOf(small), "terminal too small")

	for w := MinWidth; w <= 200; w += 7 {
		for h := MinHeight; h <= 60; h += 5 {
			s := m.Render(w, h, now)
			for y, r := range s.Text() {
				if len([]rune(r)) > w {
					t.Fatalf("%dx%d row %d is %d wide", w, h, y, len([]rune(r)))
				}
			}
			for y, l := range s.Lines(true) {
				if strings.Count(l, "\x1b[") > 4*w { // sanity: styles are grouped
					t.Fatalf("%dx%d row %d has too many escapes", w, h, y)
				}
			}
			mustContain(t, fmt.Sprintf("%dx%d", w, h), s.Text()[0], "netlog top")
		}
	}
	empty := model().Render(80, 24, now)
	mustContain(t, "empty", rowsOf(empty), "no events yet", "none: every down has recovered", "no devices known", "devices 0", "collection health: no devices")
}

func TestCountersAreWindowed(t *testing.T) {
	m := NewModel(Options{Loc: time.UTC, Window: time.Hour})
	m.Ingest([]collector.LogEntry{
		ev("a", "FAULT", "ERROR", pipeline.EventLinkDown, "x", "in", 10*time.Minute),
		ev("a", "FAULT", "ERROR", pipeline.EventLinkDown, "y", "in", 59*time.Minute),
		ev("a", "FAULT", "ERROR", pipeline.EventLinkDown, "z", "out", 61*time.Minute),
		ev("a", "OTHER", "INFO", "X", "", "unknown category", time.Minute),
	})
	c := m.Counts(now)
	if c[0] != 2 || c[1]+c[2]+c[3]+c[4] != 0 {
		t.Errorf("counts = %v", c)
	}
	// Later, the first two have aged out too and the table is pruned.
	later := now.Add(2 * time.Hour)
	if c := m.Counts(later); c != [5]int{} {
		t.Errorf("counts later = %v", c)
	}
	if len(m.buckets) != 0 {
		t.Errorf("%d buckets kept after expiry", len(m.buckets))
	}
}

func TestOutagesPairDownsWithUpsAndTrackFlaps(t *testing.T) {
	m := model()
	m.Ingest([]collector.LogEntry{
		ev("r1", "FAULT", "ERROR", pipeline.EventLinkDown, "Gi0/1", "down", 30*time.Minute),
		ev("r1", "FAULT", "INFO", pipeline.EventLinkUp, "Gi0/1", "up", 20*time.Minute), // resolved
		ev("r1", "FAULT", "ERROR", pipeline.EventLinkDown, "Gi0/2", "down", 15*time.Minute),
		ev("r1", "FAULT", "ERROR", pipeline.EventLinkDown, "Gi0/2", "down again", 5*time.Minute), // still open, 2x
		ev("r2", "FAULT", "ERROR", pipeline.EventOSPFAdjDown, "10.0.0.9", "ospf down", 12*time.Minute),
		ev("r2", "FAULT", "ERROR", pipeline.EventBGPPeerDown, "10.0.0.8", "bgp down", 11*time.Minute),
		ev("r2", "SYSTEM", "INFO", pipeline.EventBGPPeerUp, "10.0.0.8", "bgp up", 10*time.Minute),
		ev("r3", "FAULT", "ERROR", pipeline.EventLinkDown, "Gi0/3", "down", 4*time.Minute),
		ev("r3", "FAULT", "WARNING", pipeline.EventLinkFlap, "Gi0/3", "flapping", 3*time.Minute),
		ev("r4", "FAULT", "WARNING", pipeline.EventLinkFlap, "Gi0/4", "flapped, up now", 2*time.Minute),
		ev("r1", "FAULT", "ERROR", pipeline.EventLinkDown, "Gi0/7", "ancient", 30*time.Hour), // outside the window
	})
	got := m.Outages(now)
	var names []string
	for _, o := range got {
		names = append(names, fmt.Sprintf("%s/%s/%s flap=%v rec=%v downs=%d", o.Host, o.Kind, o.Object, o.Flapping, o.Recovered, o.Downs))
	}
	want := []string{
		"r3/link/Gi0/3 flap=true rec=false downs=1",
		"r4/link/Gi0/4 flap=true rec=true downs=0",
		"r1/link/Gi0/2 flap=false rec=false downs=2",
		"r2/ospf/10.0.0.9 flap=false rec=false downs=1",
	}
	if strings.Join(names, "\n") != strings.Join(want, "\n") {
		t.Errorf("outages:\n%s\nwant:\n%s", strings.Join(names, "\n"), strings.Join(want, "\n"))
	}
	s := rowsOf(m.Render(120, 30, now))
	mustContain(t, "outage pane", s, "FLAPPING, down 4m", "flapped 2m ago, up now", "down 15m (2x)", "r2 ospf 10.0.0.9")

	// A flap older than 10 minutes stops being shown.
	if o := m.Outages(now.Add(11 * time.Minute)); len(o) > 0 {
		for _, r := range o {
			if r.Recovered {
				t.Errorf("a recovered flap outlived the display period: %+v", r)
			}
		}
	}
}

func TestFilterKeyCyclesCategories(t *testing.T) {
	m := fullModel()
	if m.Filter() != "ALL" {
		t.Fatal("starts unfiltered")
	}
	for _, want := range []string{"FAULT", "CONFIG", "AUTH", "SECURITY", "SYSTEM", "ALL", "FAULT"} {
		if m.HandleKey('c') {
			t.Fatal("c must not quit")
		}
		if m.Filter() != want {
			t.Fatalf("filter = %s, want %s", m.Filter(), want)
		}
	}
	// FAULT: only fault events in the feed, and the title says so.
	text := rowsOf(m.Render(120, 30, now))
	mustContain(t, "faults only", text, "[filter: FAULT]", "Live events (FAULT, 3)", "BGP_PEER_DOWN")
	if strings.Contains(text, "Failed password") || strings.Contains(text, "SSH brute force") {
		t.Errorf("non-fault events leaked into the FAULT feed:\n%s", text)
	}
	// The counters stay global so the banner still shows the whole picture.
	mustContain(t, "counters", m.Render(120, 30, now).Text()[1], "CONFIG 1", "AUTH 1")
	m.HandleKey('C') // upper case works too
	if m.Filter() != "CONFIG" {
		t.Errorf("filter = %s", m.Filter())
	}
}

func TestPauseFreezesTheFeedButNotTheCounters(t *testing.T) {
	m := fullModel()
	m.HandleKey('p')
	if !m.Paused() {
		t.Fatal("p must pause")
	}
	m.Ingest([]collector.LogEntry{
		ev("new9", "FAULT", "ERROR", pipeline.EventLinkDown, "Gi9/9", "fresh event", time.Second),
		ev("new9", "AUTH", "WARNING", pipeline.EventLoginFailure, "", "fresh login failure", time.Second),
	})
	s := m.Render(120, 30, now)
	text := rowsOf(s)
	mustContain(t, "paused", text, "[PAUSED +2]", "Live events (7)")
	if strings.Contains(text, "fresh event") {
		t.Error("a paused feed must not scroll")
	}
	mustContain(t, "counters keep counting", s.Text()[1], "FAULT 4", "AUTH 2")
	mustContain(t, "outages keep tracking", text, "new9 link Gi9/9")

	m.HandleKey('p')
	if m.Paused() {
		t.Fatal("p must resume")
	}
	text = rowsOf(m.Render(120, 30, now))
	mustContain(t, "resumed", text, "fresh event", "Live events (9)")
	if strings.Contains(text, "PAUSED") {
		t.Error("PAUSED marker after resume")
	}
}

func TestQuitKeys(t *testing.T) {
	for _, k := range []byte{'q', 'Q', 0x03, 0x04} {
		if !model().HandleKey(k) {
			t.Errorf("key %#x should quit", k)
		}
	}
	m := model()
	for _, k := range []byte{'x', ' ', '\r', '1', 0x1b, 'h', 0} {
		if m.HandleKey(k) {
			t.Errorf("key %#x must not quit", k)
		}
	}
}

func TestFeedShowsNewestWhenThereAreMoreEventsThanRows(t *testing.T) {
	m := model()
	for i := 0; i < 50; i++ {
		m.Ingest([]collector.LogEntry{ev("h", "SYSTEM", "INFO", "E", "", fmt.Sprintf("event number %02d", i), time.Duration(50-i)*time.Second)})
	}
	text := rowsOf(m.Render(100, 20, now)) // upper pane has far fewer than 50 rows
	mustContain(t, "feed", text, "event number 49", "event number 45")
	if strings.Contains(text, "event number 00") {
		t.Error("the oldest events must scroll off")
	}
	// The ring itself is bounded.
	small := NewModel(Options{Loc: time.UTC, MaxEvents: 10})
	for i := 0; i < 100; i++ {
		small.Ingest([]collector.LogEntry{ev("h", "SYSTEM", "INFO", "E", "", fmt.Sprint(i), 0)})
	}
	if len(small.ring) != 10 || small.ring[9].Summary != "99" || small.ring[0].Summary != "90" {
		t.Errorf("ring: %d entries, first %q last %q", len(small.ring), small.ring[0].Summary, small.ring[len(small.ring)-1].Summary)
	}
}

func TestHostileTextCannotReachTheTerminal(t *testing.T) {
	m := model()
	m.Ingest([]collector.LogEntry{ev("ho\x1b[2Jst", "FAULT", "ERROR", "EV\x07", "", "evil \x1b]0;pwned\x07 \u4e2d\u6587 text\x00", 0)})
	m.SetDevices([]DeviceRow{{Hostname: "d\x1b[31m", Status: "OK\x1b"}})
	for _, l := range m.Render(100, 20, now).Lines(false) {
		if strings.ContainsAny(l, "\x1b\x07\x00") {
			t.Fatalf("control character in output row %q", l)
		}
	}
}

func TestColourFollowsTheOption(t *testing.T) {
	plain := NewModel(Options{Loc: time.UTC})
	colour := NewModel(Options{Loc: time.UTC, Color: true})
	for _, m := range []*Model{plain, colour} {
		m.Ingest([]collector.LogEntry{ev("h", "FAULT", "CRITICAL", pipeline.EventLinkDown, "x", "down", time.Minute)})
		m.SetDevices([]DeviceRow{{Hostname: "h", Status: "FAILING"}})
	}
	for _, l := range plain.Render(100, 20, now).Lines(plain.opts.Color) {
		if strings.Contains(l, "\x1b") {
			t.Fatal("colourless model produced escapes")
		}
	}
	joined := strings.Join(colour.Render(100, 20, now).Lines(colour.opts.Color), "")
	for _, want := range []string{"\x1b[0;7;31m", "\x1b[0;1;31m", "\x1b[0;7m"} { // critical badge, failing, pane titles
		if !strings.Contains(joined, want) {
			t.Errorf("coloured output lacks %q", want)
		}
	}
}

func TestShortDur(t *testing.T) {
	for d, want := range map[time.Duration]string{
		-5 * time.Second: "0s", 0: "0s", 45 * time.Second: "45s", 59 * time.Second: "59s",
		time.Minute: "1m", 12*time.Minute + 59*time.Second: "12m", 3*time.Hour + 5*time.Minute: "3h05m",
		47 * time.Hour: "47h00m", 52 * time.Hour: "2d4h",
	} {
		if got := shortDur(d); got != want {
			t.Errorf("shortDur(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestKeyFilterDropsEscapeSequences(t *testing.T) {
	feed := func(s string) string {
		var kf keyFilter
		var out []byte
		for i := 0; i < len(s); i++ {
			if b, ok := kf.feed(s[i]); ok {
				out = append(out, b)
			}
		}
		return string(out)
	}
	for in, want := range map[string]string{
		"cpq":                     "cpq",
		"\x1b[A":                  "",      // arrow up
		"\x1b[C":                  "",      // arrow right: its final byte is 'C', which must not act as a key
		"\x1b[1;5C":               "",      // ctrl+right
		"\x1bOP":                  "",      // F1
		"c\x1b[Dp":                "cp",    // keys around a sequence survive
		"\x1b[200~paste\x1b[201~": "paste", // bracketed paste markers dropped, text kept
		"\x1bx":                   "",      // alt+x
		"\x1b":                    "",
	} {
		if got := feed(in); got != want {
			t.Errorf("feed(%q) = %q, want %q", in, got, want)
		}
	}
}
