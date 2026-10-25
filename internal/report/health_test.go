// ==============================================================================
// Package report: tests for deriving device status from collection health.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-24
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"netlog/internal/query"
	"netlog/internal/store"
)

func statusMap(rows []DeviceStatus) map[string]DeviceStatus {
	m := map[string]DeviceStatus{}
	for _, r := range rows {
		m[r.Hostname] = r
	}
	return m
}

func TestDeviceStatusesFromRecordsAndInventory(t *testing.T) {
	day := 24 * time.Hour
	now := t0
	healthy := store.DeviceHealth{FirstSeen: now.Add(-9 * day), LastAttempt: now.Add(-time.Minute), LastSuccess: now.Add(-time.Minute), LastNewLogs: now.Add(-time.Hour)}
	records := map[string]store.DeviceHealth{
		"ok":      healthy,
		"failing": {FirstSeen: now.Add(-9 * day), LastAttempt: now.Add(-time.Minute), LastSuccess: now.Add(-2 * day), ConsecutiveFailures: 14, FailingSince: now.Add(-2 * day), LastError: "dial tcp: i/o timeout"},
		"pf":      {FirstSeen: now.Add(-day), LastAttempt: now.Add(-time.Minute), ConsecutiveFailures: 3, Unsupported: true, LastError: "no log fetch command"},
		"gone":    healthy, // polled before, since removed from the inventory
	}
	rows := DeviceStatuses(records, []string{"ok", "failing", "pf", "brand-new"}, now, store.DefaultStaleAfter, store.DefaultSilentAfter)

	m := statusMap(rows)
	for host, want := range map[string]string{"ok": "OK", "failing": "FAILING", "pf": "UNSUPPORTED", "brand-new": "NEVER POLLED", "gone": "OK"} {
		if m[host].Status != want {
			t.Errorf("%s: %s, want %s", host, m[host].Status, want)
		}
	}
	if len(rows) != 5 {
		t.Fatalf("devices from either source must be listed once: %d", len(rows))
	}
	if !m["gone"].NotInInventory || m["ok"].NotInInventory || m["brand-new"].NotInInventory {
		t.Error("only a recorded device missing from the inventory is flagged")
	}
	if f := m["failing"]; f.ConsecutiveFailures != 14 || f.LastError == "" || f.FailingSince == nil || f.LastSuccess == nil || f.LastNewLogs != nil {
		t.Errorf("failing: %+v", f)
	}
	if b := m["brand-new"]; b.LastAttempt != nil || b.LastSuccess != nil || b.FirstSeen != nil {
		t.Errorf("a device never polled has no times: %+v", b)
	}
	if m["ok"].LastSuccess.Location() != time.UTC {
		t.Error("times are UTC in the data; the writers localise them")
	}

	// Most urgent first, healthy last.
	var order []string
	for _, r := range rows {
		order = append(order, r.Hostname)
	}
	if got := strings.Join(order, " "); got != "failing brand-new pf gone ok" {
		t.Errorf("order = %s", got)
	}
}

// With no inventory (it could not be read), recorded devices are not flagged.
func TestDeviceStatusesWithoutInventory(t *testing.T) {
	rows := DeviceStatuses(map[string]store.DeviceHealth{"a": {FirstSeen: t0, LastAttempt: t0, LastSuccess: t0, LastNewLogs: t0}}, nil, t0, store.DefaultStaleAfter, store.DefaultSilentAfter)
	if len(rows) != 1 || rows[0].NotInInventory {
		t.Errorf("%+v", rows)
	}
	if rows := DeviceStatuses(nil, nil, t0, store.DefaultStaleAfter, store.DefaultSilentAfter); rows == nil || len(rows) != 0 {
		t.Errorf("nothing known: want an empty slice, got %#v", rows)
	}
}

func TestWriteDeviceStatus(t *testing.T) {
	now := t0
	// pf has failed 1 poll, but as an unsupported platform shows no failure count.
	records := map[string]store.DeviceHealth{
		"core-1":  {FirstSeen: now.Add(-48 * time.Hour), LastAttempt: now.Add(-time.Minute), LastSuccess: now.Add(-time.Minute), LastNewLogs: now.Add(-time.Hour)},
		"dist-2":  {FirstSeen: now.Add(-48 * time.Hour), LastAttempt: now.Add(-time.Minute), LastSuccess: now.Add(-30 * time.Hour), ConsecutiveFailures: 47, LastError: "dial tcp 10.0.0.2:22: i/o timeout"},
		"quiet-3": {FirstSeen: now.Add(-48 * time.Hour), LastAttempt: now.Add(-time.Minute), LastSuccess: now.Add(-time.Minute), LastNewLogs: now.Add(-40 * time.Hour)},
		"pf":      {FirstSeen: now.Add(-time.Hour), LastAttempt: now.Add(-time.Minute), ConsecutiveFailures: 1, Unsupported: true, LastError: "pf: netlog has no log fetch command for this platform"},
	}
	rows := DeviceStatuses(records, []string{"core-1", "dist-2", "quiet-3", "pf", "new-4"}, now, store.DefaultStaleAfter, store.DefaultSilentAfter)

	var b bytes.Buffer
	if err := WriteDeviceStatus(&b, rows, query.Style{Location: ict}); err != nil {
		t.Fatal(err)
	}
	want := `DEVICE   STATUS        LAST POLL OK      FAILS  LAST NEW LOGS     DETAIL
dist-2   FAILING       2026-10-23 13:00     47  -                 dial tcp 10.0.0.2:22: i/o timeout
quiet-3  SILENT        2026-10-24 18:59      -  2026-10-23 03:00  reachable, but no new log lines since 2026-10-23 03:00
new-4    NEVER POLLED  -                     -  -                 in the inventory but never polled
pf       UNSUPPORTED   -                     -  -                 pf: netlog has no log fetch command for this platform
core-1   OK            2026-10-24 18:59      -  2026-10-24 18:00
`
	if got := b.String(); got != want {
		t.Errorf("status table changed.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	b.Reset()
	if err := WriteDeviceStatus(&b, nil, query.Style{}); err != nil || b.String() != "No devices.\n" {
		t.Errorf("empty: %q %v", b.String(), err)
	}
}

func TestWriteDeviceStatusJSON(t *testing.T) {
	var b bytes.Buffer
	if err := WriteDeviceStatusJSON(&b, nil); err != nil || strings.TrimSpace(b.String()) != "[]" {
		t.Errorf("nil rows must print []: %q %v", b.String(), err)
	}
	b.Reset()
	rows := DeviceStatuses(map[string]store.DeviceHealth{"x": {FirstSeen: t0, LastAttempt: t0, ConsecutiveFailures: 2, LastError: "a<b>&\x1b[2J"}}, nil, t0, store.DefaultStaleAfter, store.DefaultSilentAfter)
	if err := WriteDeviceStatusJSON(&b, rows); err != nil {
		t.Fatal(err)
	}
	var back []DeviceStatus
	if err := json.Unmarshal(b.Bytes(), &back); err != nil || len(back) != 1 || back[0].LastError != "a<b>&\x1b[2J" || back[0].Status != "FAILING" {
		t.Errorf("not lossless: %v %+v", err, back)
	}
	if bytes.Contains(b.Bytes(), []byte("\x1b")) || !bytes.Contains(b.Bytes(), []byte("a<b>&")) {
		t.Errorf("JSON must carry no raw escape and must not HTML-escape:\n%s", b.String())
	}
	if !bytes.Contains(b.Bytes(), []byte(`"last_success": null`)) {
		t.Errorf("a missing time is an explicit null:\n%s", b.String())
	}
}
