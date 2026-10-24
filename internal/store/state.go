// ==============================================================================
// Package store: per-device watermark state.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
// State maps hostname -> WatermarkState and persists it to
// data/.netlog_state.json. Writes go through fsutil.WriteFileAtomic (temp
// file in the same directory, fsync, rename) so a crash can never leave a
// half-written state file. The temp file name is randomised rather than the
// fixed ".tmp" of the original sketch, which also makes two overlapping cron
// runs safe against each other's temp files.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"netlog/internal/fsutil"
)

// WatermarkState records how far into a device's log buffer netlog has read.
type WatermarkState struct {
	// LastSeenTime is the device timestamp (DeviceTS) of the newest line
	// already stored. Device time, not skew-corrected time: the device's own
	// clock is stable for a given line from poll to poll, while the measured
	// skew jitters.
	LastSeenTime time.Time `json:"last_seen_time"`

	// LastLineHash is the dedup ID of the newest stored line at
	// LastSeenTime. It disambiguates lines that share one timestamp second.
	LastLineHash string `json:"last_line_hash"`

	// LastSecondCount is how many stored lines carry exactly LastSeenTime.
	// With it, runs of byte-identical lines within one second (common at
	// the 1-second resolution of syslog) are deduplicated exactly instead of
	// by hash alone. It is an optional extension of the two-field state:
	// files written without it load with 0, which selects the hash-only
	// fallback.
	LastSecondCount int `json:"last_second_count,omitempty"`
}

// State is the in-memory, file-backed watermark table. It is safe for
// concurrent use.
type State struct {
	path string

	mu    sync.Mutex
	marks map[string]WatermarkState
	dirty bool
}

// LoadState reads the state file at path. A missing file yields an empty
// state. A file that exists but cannot be parsed is an error: silently
// starting empty would re-ingest every device's whole log buffer as duplicates.
func LoadState(path string) (*State, error) {
	s := &State{path: path, marks: make(map[string]WatermarkState)}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, fmt.Errorf("reading state file %s: %w", path, err)
	}
	if len(data) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(data, &s.marks); err != nil {
		return nil, fmt.Errorf("state file %s is corrupt (%v); fix or remove it to start fresh", path, err)
	}
	if s.marks == nil {
		s.marks = make(map[string]WatermarkState)
	}
	return s, nil
}

// Path returns the file the state is persisted to.
func (s *State) Path() string { return s.path }

// Get returns the watermark for hostname.
func (s *State) Get(hostname string) (WatermarkState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ws, ok := s.marks[hostname]
	return ws, ok
}

// Set records the watermark for hostname and marks the state dirty.
func (s *State) Set(hostname string, ws WatermarkState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.marks[hostname]; ok && old == ws {
		return
	}
	s.marks[hostname] = ws
	s.dirty = true
}

// Save writes the state atomically if anything changed since the last save.
func (s *State) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	data, err := json.MarshalIndent(s.marks, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding state: %w", err)
	}
	data = append(data, '\n')
	if err := fsutil.WriteFileAtomic(s.path, data, filePerm); err != nil {
		return err
	}
	s.dirty = false
	return nil
}
