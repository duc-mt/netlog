// ==============================================================================
// Package report: collection health of the devices.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-24
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         rows := report.DeviceStatuses(health.All(), hostnames, time.Now(), store.DefaultStaleAfter, store.DefaultSilentAfter)
// Notes:         Go package implementation
// ==============================================================================
// The log sections of a report describe the network. This file describes
// netlog's own view of it: which devices it could poll, which it could not,
// and which poll fine but never produce a line. It turns the store's raw
// per-device records (and, when known, the inventory) into one ordered list
// that both "netlog status" and the report's Device Health section print.
package report

import (
	"encoding/json"
	"io"
	"sort"
	"time"

	"netlog/internal/query"
	"netlog/internal/store"
)

// DeviceStatus is one device's collection health, ready to print.
type DeviceStatus struct {
	Hostname string `json:"hostname"`
	Status   string `json:"status"` // a store.Status value

	LastAttempt *time.Time `json:"last_attempt"`
	LastSuccess *time.Time `json:"last_success"`
	LastNewLogs *time.Time `json:"last_new_logs"`
	FirstSeen   *time.Time `json:"first_seen"`

	ConsecutiveFailures int        `json:"consecutive_failures"`
	FailingSince        *time.Time `json:"failing_since"`
	LastError           string     `json:"last_error,omitempty"`

	// NotInInventory is set when an inventory was supplied and the device is
	// no longer in it (it is still in the health file from earlier runs).
	NotInInventory bool `json:"not_in_inventory,omitempty"`
}

// DeviceHealth is the report section: how many devices were checked and the
// ones that need attention.
type DeviceHealth struct {
	Checked   int            `json:"checked"`
	Unhealthy []DeviceStatus `json:"unhealthy"`
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}

// DeviceStatuses derives every device's status at time now. A device named in
// inventory but absent from records has never been polled. Devices in records
// but not in a non-empty inventory are kept and flagged, because they may
// still be failing. The result is ordered most urgent first.
func DeviceStatuses(records map[string]store.DeviceHealth, inventory []string, now time.Time, staleAfter, silentAfter time.Duration) []DeviceStatus {
	inInv := make(map[string]bool, len(inventory))
	hosts := make(map[string]struct{}, len(records)+len(inventory))
	for _, h := range inventory {
		inInv[h] = true
		hosts[h] = struct{}{}
	}
	for h := range records {
		hosts[h] = struct{}{}
	}

	out := make([]DeviceStatus, 0, len(hosts))
	for h := range hosts {
		rec, polled := records[h]
		s := DeviceStatus{
			Hostname:       h,
			Status:         string(rec.Status(now, staleAfter, silentAfter)),
			NotInInventory: len(inventory) > 0 && !inInv[h],
		}
		if !polled {
			s.Status = string(store.StatusNever)
		} else {
			s.LastAttempt, s.LastSuccess, s.LastNewLogs, s.FirstSeen = timePtr(rec.LastAttempt), timePtr(rec.LastSuccess), timePtr(rec.LastNewLogs), timePtr(rec.FirstSeen)
			s.ConsecutiveFailures, s.FailingSince, s.LastError = rec.ConsecutiveFailures, timePtr(rec.FailingSince), rec.LastError
		}
		out = append(out, s)
	}
	sortStatuses(out)
	return out
}

// statusRank orders statuses by urgency; OK is last.
func statusRank(s string) int {
	switch store.Status(s) {
	case store.StatusFailing:
		return 0
	case store.StatusStale:
		return 1
	case store.StatusUnparseable:
		return 2
	case store.StatusSilent:
		return 3
	case store.StatusNever:
		return 4
	case store.StatusUnsupported:
		return 5
	}
	return 6
}

// sortStatuses orders by urgency, then longest failure run, then hostname.
func sortStatuses(rows []DeviceStatus) {
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if ra, rb := statusRank(a.Status), statusRank(b.Status); ra != rb {
			return ra < rb
		}
		if a.ConsecutiveFailures != b.ConsecutiveFailures {
			return a.ConsecutiveFailures > b.ConsecutiveFailures
		}
		return lessFold(a.Hostname, b.Hostname)
	})
}

// buildDeviceHealth summarises rows: every device counted, the unhealthy ones
// listed. Rows are copied, so the caller's slice is untouched.
func buildDeviceHealth(rows []DeviceStatus) DeviceHealth {
	dh := DeviceHealth{Checked: len(rows), Unhealthy: []DeviceStatus{}}
	for _, r := range rows {
		if r.Status != string(store.StatusOK) {
			dh.Unhealthy = append(dh.Unhealthy, r)
		}
	}
	sortStatuses(dh.Unhealthy)
	return dh
}

// ==============================================================================
// Rendering
// ==============================================================================

// WriteDeviceStatus prints every row as the status table of "netlog status".
func WriteDeviceStatus(w io.Writer, rows []DeviceStatus, st query.Style) error {
	p := &printer{w: w}
	if len(rows) == 0 {
		p.println("No devices.")
		return p.err
	}
	writeStatusGrid(p, st, rows)
	return p.err
}

// WriteDeviceStatusJSON prints rows as a JSON array (never null).
func WriteDeviceStatusJSON(w io.Writer, rows []DeviceStatus) error {
	if rows == nil {
		rows = []DeviceStatus{}
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(rows)
}

const maxDetailCol = 60

func clock(t *time.Time, loc *time.Location) string {
	if t == nil {
		return "-"
	}
	return t.In(loc).Format("2006-01-02 15:04")
}

// detail explains a status in a few words. The device name and error text it
// may carry are untrusted and are clipped (and so sanitised) by the grid.
func detail(r DeviceStatus, loc *time.Location) string {
	var d string
	switch store.Status(r.Status) {
	case store.StatusFailing:
		d = r.LastError
	case store.StatusStale:
		d = "no poll since " + clock(r.LastAttempt, loc) + ": is collect running?"
	case store.StatusSilent:
		since := r.LastNewLogs
		if since == nil {
			since = r.FirstSeen
		}
		d = "reachable, but no new log lines since " + clock(since, loc)
	case store.StatusUnparseable:
		d = "log output could not be parsed (check the device's log timestamp format)"
	case store.StatusUnsupported:
		d = r.LastError
	case store.StatusNever:
		d = "in the inventory but never polled"
	}
	if r.NotInInventory {
		if d != "" {
			d += " "
		}
		d += "(not in inventory)"
	}
	return d
}

// writeStatusGrid prints the device table shared by the status command and the
// report section.
func writeStatusGrid(p *printer, st query.Style, rows []DeviceStatus) {
	loc := st.Loc()
	cells := make([][]string, len(rows))
	for i, r := range rows {
		// Failed polls of an unsupported platform are not an outage: the
		// count only grows with every cycle and means nothing there.
		fails := "-"
		if r.ConsecutiveFailures > 0 && store.Status(r.Status) != store.StatusUnsupported {
			fails = itoa(r.ConsecutiveFailures)
		}
		cells[i] = []string{r.Hostname, r.Status, clock(r.LastSuccess, loc), fails, clock(r.LastNewLogs, loc), detail(r, loc)}
	}
	cols := []column{
		{"DEVICE", query.MaxDeviceCol, false},
		{"STATUS", 12, false},
		{"LAST POLL OK", 16, false},
		{"FAILS", maxNumCol, true},
		{"LAST NEW LOGS", 16, false},
		{"DETAIL", maxDetailCol, false},
	}
	grid(p, st, cols, cells, func(i int, line string) string {
		switch store.Status(rows[i].Status) {
		case store.StatusFailing, store.StatusStale:
			return st.Red(line)
		case store.StatusSilent, store.StatusUnparseable:
			return st.Yellow(line)
		case store.StatusUnsupported, store.StatusNever:
			return st.Dim(line)
		}
		return line
	})
}

// writeDeviceHealth is the report section.
func writeDeviceHealth(p *printer, r Report, st query.Style) {
	dh := r.DeviceHealth
	heading(p, st, "Device Health (collection status now)")
	switch {
	case dh.Checked == 0:
		p.println("No collection health recorded yet (run netlog collect).")
	case len(dh.Unhealthy) == 0:
		p.println("All " + itoa(dh.Checked) + " devices healthy.")
	default:
		p.println(itoa(len(dh.Unhealthy)) + " of " + itoa(dh.Checked) + " devices need attention:")
		writeStatusGrid(p, st, dh.Unhealthy)
	}
}
