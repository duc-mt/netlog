// ==============================================================================
// Package store: tests for collection health.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-24
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var hT0 = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func TestHealthLifecycle(t *testing.T) {
	h, err := LoadHealth(filepath.Join(t.TempDir(), "h.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.Get("R1"); ok {
		t.Fatal("no record before the first attempt")
	}

	h.Failed("R1", hT0, "dial tcp: i/o timeout", false)
	h.Failed("R1", hT0.Add(5*time.Minute), "dial tcp: i/o timeout", false)
	d, _ := h.Get("R1")
	if d.ConsecutiveFailures != 2 || d.FailingSince != hT0 || d.LastError == "" || d.FirstSeen != hT0 || !d.LastSuccess.IsZero() {
		t.Errorf("after two failures: %+v", d)
	}

	// A success clears the failure; FirstSeen and the failure history of other fields stay.
	h.Succeeded("R1", hT0.Add(10*time.Minute))
	d, _ = h.Get("R1")
	if d.ConsecutiveFailures != 0 || !d.FailingSince.IsZero() || d.LastError != "" || d.LastSuccess != hT0.Add(10*time.Minute) || d.FirstSeen != hT0 {
		t.Errorf("after recovery: %+v", d)
	}
	// ...and a later failure starts a new run with its own FailingSince.
	h.Failed("R1", hT0.Add(20*time.Minute), "again", false)
	if d, _ = h.Get("R1"); d.ConsecutiveFailures != 1 || d.FailingSince != hT0.Add(20*time.Minute) {
		t.Errorf("new failure run: %+v", d)
	}

	h.NewLogs("R1", hT0.Add(30*time.Minute))
	if d, _ = h.Get("R1"); d.LastNewLogs != hT0.Add(30*time.Minute) {
		t.Errorf("NewLogs: %+v", d)
	}
}

func TestHealthPersistsAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "h.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	h, _ := LoadHealth(path)
	if err := h.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("nothing changed: nothing should be written")
	}

	h.Failed("R1", hT0, "boom", false)
	h.Succeeded("R2", hT0)
	h.NewLogs("R2", hT0)
	h.Failed("PF", hT0, "no fetch command", true)
	if err := h.Save(); err != nil {
		t.Fatal(err)
	}

	again, err := LoadHealth(path)
	if err != nil {
		t.Fatal(err)
	}
	all := again.All()
	if len(all) != 3 || all["R1"].LastError != "boom" || !all["R2"].LastNewLogs.Equal(hT0) || !all["PF"].Unsupported {
		t.Errorf("round trip lost data: %+v", all)
	}
	// All returns a copy: editing it must not change the table.
	all["R1"] = DeviceHealth{}
	if d, _ := again.Get("R1"); d.LastError != "boom" {
		t.Error("All must return a copy")
	}
}

// Health is diagnostics: a bad file is reported but never blocks a run, and is
// replaced at the next save.
func TestHealthCorruptFileDoesNotStopCollection(t *testing.T) {
	for name, content := range map[string]string{"garbage": "{not json", "wrong shape": "[1,2,3]", "null": "null"} {
		path := filepath.Join(t.TempDir(), "h.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		h, err := LoadHealth(path)
		if h == nil || err == nil || !strings.Contains(err.Error(), "corrupt") {
			t.Fatalf("%s: want a usable empty table plus a corrupt-file error, got %v %v", name, h, err)
		}
		h.Succeeded("R1", hT0)
		if err := h.Save(); err != nil {
			t.Fatal(err)
		}
		if fixed, err := LoadHealth(path); err != nil || len(fixed.All()) != 1 {
			t.Errorf("%s: the bad file should have been replaced: %v %v", name, fixed.All(), err)
		}
	}
	if h, err := LoadHealth(filepath.Join(t.TempDir(), "absent.json")); err != nil || len(h.All()) != 0 {
		t.Errorf("a missing file is normal: %v %v", h.All(), err)
	}
}

func TestDeviceStates(t *testing.T) {
	day := 24 * time.Hour
	now := hT0.Add(10 * day)
	ok := DeviceHealth{FirstSeen: now.Add(-5 * day), LastAttempt: now.Add(-time.Minute), LastSuccess: now.Add(-time.Minute), LastNewLogs: now.Add(-time.Hour)}

	tests := []struct {
		name string
		mod  func(d *DeviceHealth)
		want Status
	}{
		{"healthy", func(*DeviceHealth) {}, StatusOK},
		{"never polled", func(d *DeviceHealth) { *d = DeviceHealth{} }, StatusNever},
		{"unsupported wins over everything", func(d *DeviceHealth) { d.Unsupported = true; d.ConsecutiveFailures = 9 }, StatusUnsupported},
		{"failing", func(d *DeviceHealth) { d.ConsecutiveFailures = 3 }, StatusFailing},
		{"stale beats failing: nobody is polling, so the failure count is old news", func(d *DeviceHealth) {
			d.LastAttempt = now.Add(-3 * day)
			d.ConsecutiveFailures = 3
		}, StatusStale},
		{"just inside the stale limit", func(d *DeviceHealth) { d.LastAttempt = now.Add(-day) }, StatusOK},
		{"unparseable", func(d *DeviceHealth) { d.Unparseable = true }, StatusUnparseable},
		{"silent: reachable but no new logs for two days", func(d *DeviceHealth) { d.LastNewLogs = now.Add(-2 * day) }, StatusSilent},
		{"just inside the silent limit", func(d *DeviceHealth) { d.LastNewLogs = now.Add(-day) }, StatusOK},
		{"never any logs, but tracked for under a day", func(d *DeviceHealth) {
			d.LastNewLogs = time.Time{}
			d.FirstSeen = now.Add(-time.Hour)
		}, StatusOK},
		{"never any logs in two days of tracking", func(d *DeviceHealth) {
			d.LastNewLogs = time.Time{}
			d.FirstSeen = now.Add(-2 * day)
		}, StatusSilent},
	}
	for _, c := range tests {
		d := ok
		c.mod(&d)
		if got := d.Status(now, DefaultStaleAfter, DefaultSilentAfter); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}
