// ==============================================================================
// Package pipeline: tests for fleet-wide password-spray detection.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-24
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package pipeline

import (
	"strings"
	"testing"
	"time"

	"netlog/internal/collector"
)

func failFrom(host, ip string, at time.Time) collector.LogEntry {
	e := ev(host, EventLoginFailure, "AUTH", "Failed password for admin from "+ip, at)
	e.SourceIP = ip
	return e
}

func sprayOf(sigs []TriageSignal) []TriageSignal {
	var out []TriageSignal
	for _, s := range sigs {
		if s.Entry.Event == EventPasswordSpray {
			out = append(out, s)
		}
	}
	return out
}

func TestPasswordSpraySignalsOnTheThirdDevice(t *testing.T) {
	f := newFixture()
	base := f.now.Add(-5 * time.Minute)

	for i, h := range []string{"R1", "R2"} {
		if s := f.d.Observe(failFrom(h, "203.0.113.9", base.Add(time.Duration(i)*time.Minute))); len(s) != 0 {
			t.Fatalf("%s: signalled with only %d device(s)", h, i+1)
		}
	}
	got := f.d.Observe(failFrom("R3", "203.0.113.9", base.Add(2*time.Minute)))
	if len(got) != 1 {
		t.Fatalf("third device should signal once, got %+v", got)
	}
	s := got[0]
	if s.Playbook != PlaybookBruteForce || s.Priority != PriorityHigh || !s.Derived ||
		s.Entry.Event != EventPasswordSpray || s.Entry.Category != "SECURITY" || s.Entry.Severity != "CRITICAL" ||
		s.Entry.Hostname != "R3" || s.Entry.SourceIP != "203.0.113.9" {
		t.Errorf("signal = %+v", s)
	}
	if !strings.Contains(s.Entry.Summary, "203.0.113.9 on 3 devices (R1, R2, R3)") {
		t.Errorf("summary = %q", s.Entry.Summary)
	}
	if s.Entry.ID == "" || s.Entry.ID == failFrom("R3", "203.0.113.9", base).ID {
		t.Error("a derived entry needs its own ID or it would be dropped as a duplicate")
	}

	// The tally restarts: one more device is not enough, three more are.
	if s := f.d.Observe(failFrom("R4", "203.0.113.9", base.Add(3*time.Minute))); len(s) != 0 {
		t.Errorf("count must restart after a spray signal, got %+v", s)
	}
}

// The whole point: this is invisible to the per-device rule, which needs five
// failures inside 30 seconds on one device.
func TestSprayNeedsDistinctDevices(t *testing.T) {
	f := newFixture()
	base := f.now.Add(-9 * time.Minute)
	for i := 0; i < 9; i++ { // nine failures, one device, one a minute
		if s := f.d.Observe(failFrom("R1", "203.0.113.9", base.Add(time.Duration(i)*time.Minute))); len(s) != 0 {
			t.Fatalf("failure %d on a single device signalled: %+v", i+1, s)
		}
	}
	// ...and a different source on other devices is a different tally.
	f = newFixture()
	for i, h := range []string{"R1", "R2", "R3"} {
		ip := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3"}[i]
		if s := f.d.Observe(failFrom(h, ip, f.now.Add(-time.Minute))); len(s) != 0 {
			t.Fatalf("different sources must not combine: %+v", s)
		}
	}
}

func TestSprayWindow(t *testing.T) {
	f := newFixture()
	base := f.now.Add(-14 * time.Minute)
	f.d.Observe(failFrom("R1", "203.0.113.9", base))
	f.d.Observe(failFrom("R2", "203.0.113.9", base.Add(5*time.Minute)))
	// 11 minutes after R1: R1 has left the 10-minute window, so only R2 and R3 count.
	if s := f.d.Observe(failFrom("R3", "203.0.113.9", base.Add(11*time.Minute))); len(s) != 0 {
		t.Fatalf("a failure older than the window must not count: %+v", s)
	}
	// R2, R3, R4 are all inside it.
	if s := sprayOf(f.d.Observe(failFrom("R4", "203.0.113.9", base.Add(12*time.Minute)))); len(s) != 1 {
		t.Fatalf("three devices inside the window must signal, got %+v", s)
	}
}

// Devices are polled one after another: a newer device's batch can arrive
// before an older line of another device. Lines within the window of the
// newest still count; older ones are ignored rather than corrupting the tally.
func TestSprayAcceptsLateLinesFromAnotherDevice(t *testing.T) {
	f := newFixture()
	base := f.now.Add(-12 * time.Minute)
	f.d.Observe(failFrom("R1", "203.0.113.9", base.Add(9*time.Minute))) // newest first
	if s := f.d.Observe(failFrom("R2", "203.0.113.9", base.Add(time.Minute))); len(s) != 0 {
		t.Fatalf("2 devices: %+v", s)
	}
	if s := f.d.Observe(failFrom("R9", "203.0.113.9", base.Add(-2*time.Minute))); len(s) != 0 {
		t.Fatalf("a line older than newest-window must be ignored, got %+v", s)
	}
	if s := sprayOf(f.d.Observe(failFrom("R3", "203.0.113.9", base.Add(2*time.Minute)))); len(s) != 1 {
		t.Fatalf("R1(+9m) R2(+1m) R3(+2m) are inside one window and must signal, got %+v", s)
	}
}

func TestSprayIgnoresFailuresWithoutASource(t *testing.T) {
	f := newFixture()
	for _, h := range []string{"R1", "R2", "R3", "R4"} {
		if s := f.d.Observe(failFrom(h, "", f.now.Add(-time.Minute))); len(s) != 0 {
			t.Fatalf("no source address, no attribution: %+v", s)
		}
	}
	if len(f.d.spray) != 0 {
		t.Error("nothing should be tracked without a source")
	}
}

// History replayed at startup feeds the tally but never signals, and a spray
// already reported by an earlier run is not reported again.
func TestSprayAcrossRuns(t *testing.T) {
	now := time.Date(2026, 10, 20, 10, 30, 0, 0, time.UTC)
	mk := func() *Detector { return NewDetector(DetectorConfig{Now: func() time.Time { return now }}) }
	at := func(min int) time.Time { return now.Add(-time.Duration(min) * time.Minute) }

	// Two devices failed in the previous run; the third failure arrives now.
	d := mk()
	d.Prime([]collector.LogEntry{failFrom("R2", "203.0.113.9", at(4)), failFrom("R1", "203.0.113.9", at(5))}) // unsorted
	if s := sprayOf(d.Observe(failFrom("R3", "203.0.113.9", at(1)))); len(s) != 1 {
		t.Fatalf("primed history must count towards the spray, got %+v", s)
	}

	// Priming that itself completes a spray emits nothing...
	d = mk()
	d.Prime([]collector.LogEntry{failFrom("R1", "203.0.113.9", at(5)), failFrom("R2", "203.0.113.9", at(4)), failFrom("R3", "203.0.113.9", at(3))})
	// ...and leaves a clean tally, so one more device is not a second spray.
	if s := d.Observe(failFrom("R4", "203.0.113.9", at(1))); len(s) != 0 {
		t.Fatalf("a spray found while priming must not be reported again: %+v", s)
	}

	// A stored PASSWORD_SPRAY_ATTEMPT clears the tally even when the priming
	// window only saw part of the failures that caused it.
	sp := failFrom("R2", "203.0.113.9", at(4))
	sp.Event, sp.Category = EventPasswordSpray, "SECURITY"
	d = mk()
	d.Prime([]collector.LogEntry{failFrom("R1", "203.0.113.9", at(5)), failFrom("R2", "203.0.113.9", at(4)), sp})
	if s := d.Observe(failFrom("R3", "203.0.113.9", at(1))); len(s) != 0 {
		t.Fatalf("a spray reported by the previous run must stay suppressed: %+v", s)
	}
	// Control: without the stored spray entry the same stream does signal.
	d = mk()
	d.Prime([]collector.LogEntry{failFrom("R1", "203.0.113.9", at(5)), failFrom("R2", "203.0.113.9", at(4))})
	if s := sprayOf(d.Observe(failFrom("R3", "203.0.113.9", at(1)))); len(s) != 1 {
		t.Fatal("control: expected a spray signal")
	}
}

// A device's first poll delivers its whole old buffer: history may complete a
// spray, but connecting now cannot diagnose yesterday, so it must not signal.
func TestSprayFromStaleHistoryDoesNotSignal(t *testing.T) {
	f := newFixture()
	old := f.now.Add(-2 * time.Hour)
	for i, h := range []string{"R1", "R2", "R3"} {
		if s := f.d.Observe(failFrom(h, "203.0.113.9", old.Add(time.Duration(i)*time.Minute))); len(s) != 0 {
			t.Fatalf("stale history must not signal: %+v", s)
		}
	}
	if len(f.d.spray) != 0 {
		t.Error("the tripped tally should have been cleared")
	}
}

func TestSprayStateIsGarbageCollected(t *testing.T) {
	now := time.Date(2026, 10, 20, 10, 30, 0, 0, time.UTC)
	d := NewDetector(DetectorConfig{Now: func() time.Time { return now }})
	d.Observe(failFrom("R1", "203.0.113.9", now.Add(-time.Minute)))
	if len(d.spray) != 1 {
		t.Fatalf("tally missing: %d", len(d.spray))
	}
	now = now.Add(gcInterval + 11*time.Minute) // past both the sweep interval and the spray window
	d.Observe(failFrom("R2", "198.51.100.7", now))
	if _, ok := d.spray["203.0.113.9"]; ok {
		t.Error("an expired tally must be swept (internet scanners would otherwise grow it for ever)")
	}
}

func TestSprayThresholdAndSummaryAreBounded(t *testing.T) {
	f := newFixture()
	f.d = NewDetector(DetectorConfig{SprayDevices: 7, Now: func() time.Time { return f.now }})
	var last []TriageSignal
	for i := 1; i <= 7; i++ {
		last = f.d.Observe(failFrom("R"+string(rune('0'+i)), "203.0.113.9", f.now.Add(-time.Minute)))
	}
	if len(last) != 1 {
		t.Fatalf("seventh device should signal, got %+v", last)
	}
	if got := last[0].Entry.Summary; !strings.Contains(got, "on 7 devices (R1, R2, R3, R4, R5 and 2 more)") {
		t.Errorf("long device lists must be cut: %q", got)
	}
}
