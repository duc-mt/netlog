// ==============================================================================
// Package pipeline: watermark filter (Stage 1, deduplication).
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         fresh := w.Filter(host, entries); ...store...; w.Advance(host, fresh); w.Save()
// Notes:         Go package implementation
// ==============================================================================
// Every poll returns the device's whole log buffer, so almost every line has
// been seen before. The watermark remembers, per device, the newest line
// already stored and drops everything at or before it.
//
// The comparison key is the device's own timestamp (LogEntry.DeviceTS), not
// the skew-corrected Timestamp. A given line carries the same device time on
// every poll, whereas the measured skew changes slightly from poll to poll
// (device clocks tick in whole seconds); comparing corrected times would let
// the same line slip past the watermark as a "new" duplicate.
//
// Lines that share the watermark second are disambiguated by how many of
// them are already stored (LastSecondCount) and the dedup ID of the last one:
// buffer order is chronological, so that many leading lines are old and the
// rest are new. This stays exact for byte-identical lines in one second.
package pipeline

import (
	"sort"
	"time"

	"netlog/internal/collector"
	"netlog/internal/store"
)

// regressionWindow is how far behind the stored watermark a device's newest
// line may be before netlog concludes the device clock was stepped backwards
// (NTP correction, RTC reset after reboot) and re-bases the watermark.
// Without this guard a device whose clock jumped back a day would be ignored
// until its clock caught up with the old watermark.
const regressionWindow = time.Hour

// Watermarks filters out already-stored log entries.
type Watermarks struct {
	state *store.State
}

// NewWatermarks returns a Watermarks backed by state.
func NewWatermarks(state *store.State) *Watermarks {
	return &Watermarks{state: state}
}

// Filter returns the entries of hostname that are newer than the stored
// watermark, ordered by DeviceTS (stable, so buffer order is kept within one
// timestamp). The input slice is not modified. A device with no watermark
// yet gets every entry.
//
// Filter does not move the watermark; call Advance once the returned
// entries are safely stored.
func (w *Watermarks) Filter(hostname string, entries []collector.LogEntry) []collector.LogEntry {
	if len(entries) == 0 {
		return nil
	}
	sorted := make([]collector.LogEntry, len(entries))
	copy(sorted, entries)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].DeviceTS.Before(sorted[j].DeviceTS) })

	ws, ok := w.state.Get(hostname)
	if !ok || ws.LastSeenTime.IsZero() {
		return sorted
	}

	// Clock stepped backwards: nothing in the buffer is newer than the
	// watermark, yet the newest line is far older than it. Re-base.
	newest := sorted[len(sorted)-1].DeviceTS
	if ws.LastSeenTime.Sub(newest) > regressionWindow {
		return sorted
	}

	// The buffer is chronological, so the lines that share the watermark
	// second appear in the order they were stored. LastSecondCount says how
	// many of them are already stored; if the line at that position is the
	// remembered one, skip exactly that many (this is exact even when
	// several lines are byte-identical).
	var ties []int
	for i := range sorted {
		if sorted[i].DeviceTS.Equal(ws.LastSeenTime) {
			ties = append(ties, i)
		}
	}
	skip := 0 // number of leading tied lines already stored
	if n := ws.LastSecondCount; n > 0 && len(ties) >= n && sorted[ties[n-1]].ID == ws.LastLineHash {
		skip = n
	} else {
		// Count unknown (older state file) or the buffer has partly rolled
		// over: fall back to the last occurrence of the stored line. If it
		// is gone, it was overwritten, and since the buffer is FIFO every
		// remaining tied line is newer than it.
		for j, i := range ties {
			if sorted[i].ID == ws.LastLineHash {
				skip = j + 1
			}
		}
	}

	fresh := make([]collector.LogEntry, 0, len(sorted))
	seenTies := 0
	for i := range sorted {
		d := sorted[i].DeviceTS
		switch {
		case d.Before(ws.LastSeenTime):
			continue
		case d.Equal(ws.LastSeenTime):
			seenTies++
			if seenTies <= skip {
				continue
			}
		}
		fresh = append(fresh, sorted[i])
	}
	return fresh
}

// gapMinLines is the smallest batch for which "no overlap with the previous
// poll" is treated as evidence of lost lines rather than a quiet device.
const gapMinLines = 20

// PossibleGap reports whether the buffer fetched for hostname looks like it
// scrolled past lines netlog never saw: there is a stored watermark, the
// batch is substantial, and even its oldest line is newer than the watermark,
// so nothing in it overlaps the previous poll. That happens when a device
// logs faster than the polling interval relative to its buffer size (for
// example VyOS "show log tail 100" on a busy router). It is advisory only.
func (w *Watermarks) PossibleGap(hostname string, entries []collector.LogEntry) bool {
	if len(entries) < gapMinLines {
		return false
	}
	ws, ok := w.state.Get(hostname)
	if !ok || ws.LastSeenTime.IsZero() {
		return false
	}
	oldest := entries[0].DeviceTS
	for _, e := range entries[1:] {
		if e.DeviceTS.Before(oldest) {
			oldest = e.DeviceTS
		}
	}
	return oldest.After(ws.LastSeenTime)
}

// DropFuture removes entries whose device timestamp is later than now plus
// tolerance, and reports how many it removed. A line cannot have been logged
// in the future, so such a timestamp comes from a device clock that was
// stepped forward and back (or from a corrupt line). Keeping it would drag the
// watermark into the future and make every correct later line look "old".
// now should be the device's current time (fetch time plus measured skew).
func DropFuture(entries []collector.LogEntry, now time.Time, tolerance time.Duration) ([]collector.LogEntry, int) {
	limit := now.Add(tolerance)
	kept := entries[:0:0]
	dropped := 0
	for _, e := range entries {
		if e.DeviceTS.After(limit) {
			dropped++
			continue
		}
		kept = append(kept, e)
	}
	return kept, dropped
}

// Advance moves hostname's watermark to the newest entry of fresh (the slice
// returned by Filter, after it has been stored). It only updates the
// in-memory table; call Save to persist it.
func (w *Watermarks) Advance(hostname string, fresh []collector.LogEntry) {
	if len(fresh) == 0 {
		return
	}
	newest := fresh[0]
	for _, e := range fresh[1:] {
		if !e.DeviceTS.Before(newest.DeviceTS) { // ties: later buffer position wins
			newest = e
		}
	}
	atNewest := 0
	for _, e := range fresh {
		if e.DeviceTS.Equal(newest.DeviceTS) {
			atNewest++
		}
	}

	// If the watermark second did not move, the lines stored earlier at that
	// second still count; if their number was never recorded it stays
	// unknown (0), which selects the hash-only fallback in Filter.
	if prev, ok := w.state.Get(hostname); ok && prev.LastSeenTime.Equal(newest.DeviceTS) {
		if prev.LastSecondCount > 0 {
			atNewest += prev.LastSecondCount
		} else {
			atNewest = 0
		}
	}

	w.state.Set(hostname, store.WatermarkState{
		LastSeenTime:    newest.DeviceTS.UTC(),
		LastLineHash:    newest.ID,
		LastSecondCount: atNewest,
	})
}

// Save persists the watermark table atomically.
func (w *Watermarks) Save() error { return w.state.Save() }
