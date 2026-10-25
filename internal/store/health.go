// ==============================================================================
// Package store: per-device collection health.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-24
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
// netlog watches the network, and Health lets it watch itself. Poll failures
// used to be logged to stderr only, so a device that had been unreachable for
// a week left no trace in the data directory and no command could show it.
// Health records, per device, when it was last polled, when that last
// succeeded, when new log lines last arrived and how many polls in a row have
// failed. "netlog status" and "netlog report" read it; nothing here affects what
// is collected.
//
// The file is data/.netlog_health.json, written atomically like the
// watermark state. Unlike the watermarks it is only diagnostics, so a corrupt
// file is reported and replaced by an empty one rather than stopping a run.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"netlog/internal/fsutil"
)

const healthFileName = ".netlog_health.json"

// HealthPath returns the collection-health file path.
func HealthPath(dataDir string) string { return filepath.Join(dataDir, healthFileName) }

// Default thresholds for Status. A monitor polling every few minutes would use
// far smaller ones; a nightly cron job needs these or more.
const (
	DefaultStaleAfter  = 24 * time.Hour // no poll attempt at all for this long
	DefaultSilentAfter = 24 * time.Hour // polls succeed but no new log line for this long
)

// DeviceHealth is how polling one device is going.
type DeviceHealth struct {
	// FirstSeen is the first poll attempt on record: the start of the period
	// over which "no new logs" is judged for a device that has never had any.
	FirstSeen time.Time `json:"first_seen"`

	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success,omitempty"`

	// LastNewLogs is when a poll last stored at least one new log line (poll
	// time, not log time).
	LastNewLogs time.Time `json:"last_new_logs,omitempty"`

	// ConsecutiveFailures counts failed polls since the last success, and
	// FailingSince is when the first of them happened.
	ConsecutiveFailures int       `json:"consecutive_failures"`
	FailingSince        time.Time `json:"failing_since,omitempty"`
	LastError           string    `json:"last_error,omitempty"`

	// Unsupported marks a platform netlog has no log fetch command for. It is
	// permanent, not an outage.
	Unsupported bool `json:"unsupported,omitempty"`

	// Unparseable is set when the device answered with log output but not one
	// line could be parsed (typically a missing timestamp format setting).
	Unparseable bool `json:"unparseable,omitempty"`
}

// Status is the summary of a DeviceHealth.
type Status string

// Statuses.
const (
	StatusOK          Status = "OK"
	StatusFailing     Status = "FAILING"     // the last poll(s) failed
	StatusStale       Status = "STALE"       // nothing has polled it lately: is the collector running?
	StatusSilent      Status = "SILENT"      // reachable, but no new log lines for a long time
	StatusUnparseable Status = "UNPARSEABLE" // reachable, output not understood
	StatusUnsupported Status = "UNSUPPORTED" // no fetch command for this platform
	StatusNever       Status = "NEVER POLLED"
)

// Status classifies the device at time now. The order matters: a permanent
// condition wins, then "nobody is polling" (which would make every other
// field out of date), then failures, then the quieter problems.
func (d DeviceHealth) Status(now time.Time, staleAfter, silentAfter time.Duration) Status {
	switch {
	case d.Unsupported:
		return StatusUnsupported
	case d.LastAttempt.IsZero():
		return StatusNever
	case now.Sub(d.LastAttempt) > staleAfter:
		return StatusStale
	case d.ConsecutiveFailures > 0:
		return StatusFailing
	case d.Unparseable:
		return StatusUnparseable
	}
	since := d.LastNewLogs
	if since.IsZero() {
		since = d.FirstSeen // never any logs: judge from when tracking began
	}
	if !since.IsZero() && now.Sub(since) > silentAfter {
		return StatusSilent
	}
	return StatusOK
}

// Health is the file-backed table of DeviceHealth by hostname. It is safe for
// concurrent use.
type Health struct {
	path string

	mu      sync.Mutex
	devices map[string]DeviceHealth
	dirty   bool
}

// LoadHealth reads the health file at path. A missing file yields an empty
// table. A file that cannot be parsed yields an empty table together with an
// error: health is diagnostics, so the caller should log the error and carry
// on rather than refuse to collect.
func LoadHealth(path string) (*Health, error) {
	h := &Health{path: path, devices: make(map[string]DeviceHealth)}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return h, nil
		}
		return h, fmt.Errorf("reading health file %s: %w", path, err)
	}
	if len(data) == 0 {
		return h, nil
	}
	if err := json.Unmarshal(data, &h.devices); err != nil || h.devices == nil {
		h.devices = make(map[string]DeviceHealth) // the next poll dirties the table, replacing the bad file
		if err == nil {
			err = errors.New("not an object")
		}
		return h, fmt.Errorf("health file %s is corrupt, starting empty: %w", path, err)
	}
	return h, nil
}

// Get returns the record for hostname.
func (h *Health) Get(hostname string) (DeviceHealth, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	d, ok := h.devices[hostname]
	return d, ok
}

// All returns a copy of every record.
func (h *Health) All() map[string]DeviceHealth {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]DeviceHealth, len(h.devices))
	for k, v := range h.devices {
		out[k] = v
	}
	return out
}

// update applies fn to hostname's record, creating it on the first attempt.
func (h *Health) update(hostname string, at time.Time, fn func(*DeviceHealth)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	d := h.devices[hostname]
	if d.FirstSeen.IsZero() {
		d.FirstSeen = at
	}
	d.LastAttempt = at
	fn(&d)
	h.devices[hostname] = d
	h.dirty = true
}

// Failed records a failed poll. unsupported marks a platform with no fetch
// command, which is a permanent condition rather than an outage.
func (h *Health) Failed(hostname string, at time.Time, reason string, unsupported bool) {
	h.update(hostname, at, func(d *DeviceHealth) {
		if d.ConsecutiveFailures == 0 {
			d.FailingSince = at
		}
		d.ConsecutiveFailures++
		d.LastError = reason
		d.Unsupported = unsupported
	})
}

// Succeeded records a poll that reached the device and fetched its log.
func (h *Health) Succeeded(hostname string, at time.Time) {
	h.update(hostname, at, func(d *DeviceHealth) {
		d.LastSuccess = at
		d.ConsecutiveFailures = 0
		d.FailingSince = time.Time{}
		d.LastError = ""
		d.Unsupported = false
	})
}

// NewLogs records that a poll stored new log lines.
func (h *Health) NewLogs(hostname string, at time.Time) {
	h.update(hostname, at, func(d *DeviceHealth) { d.LastNewLogs = at })
}

// SetUnparseable records whether the last successful poll returned output
// that could not be parsed at all.
func (h *Health) SetUnparseable(hostname string, at time.Time, v bool) {
	h.update(hostname, at, func(d *DeviceHealth) { d.Unparseable = v })
}

// Save writes the table atomically if anything changed.
func (h *Health) Save() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.dirty {
		return nil
	}
	data, err := json.MarshalIndent(h.devices, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding health: %w", err)
	}
	if err := fsutil.WriteFileAtomic(h.path, append(data, '\n'), filePerm); err != nil {
		return err
	}
	h.dirty = false
	return nil
}
