// ==============================================================================
// Package tui: incremental data source for the dashboard.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-27
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
package tui

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"netlog/internal/collector"
	"netlog/internal/report"
	"netlog/internal/store"
)

// Source supplies the dashboard with new events and the device list. Poll is
// called once per refresh from a single goroutine.
type Source interface {
	Poll(now time.Time) (entries []collector.LogEntry, devices []DeviceRow, err error)
}

// SourceOptions tunes a FileSource.
type SourceOptions struct {
	Window       time.Duration // how far back the first poll reads (default 24h)
	StaleAfter   time.Duration // device STALE threshold (default store.DefaultStaleAfter)
	SilentAfter  time.Duration // device SILENT threshold (default store.DefaultSilentAfter)
	HealthEvery  time.Duration // how often the health file is re-read (default 5s)
	InitialBytes int64         // at most this much of each daily file is read at start (default 16 MiB)
	ChunkBytes   int64         // at most this much per file per poll afterwards (default 4 MiB)
}

// FileSource follows the daily JSONL files under a data directory. The first
// Poll reads the tail of the files for the last Window; later polls read only
// what was appended, so a one-second refresh costs a stat and a small read per
// file however large the logs are. It is a reader only: it takes no lock and
// can run next to collect, monitor and listen.
type FileSource struct {
	dataDir string
	hosts   []string
	o       SourceOptions

	offsets    map[string]int64
	started    bool
	devices    []DeviceRow
	lastHealth time.Time
}

// NewFileSource creates a source for dataDir. hosts are the inventory
// hostnames (they make never-polled devices visible); it may be empty.
func NewFileSource(dataDir string, hosts []string, o SourceOptions) *FileSource {
	if o.Window <= 0 {
		o.Window = DefaultWindow
	}
	if o.StaleAfter <= 0 {
		o.StaleAfter = store.DefaultStaleAfter
	}
	if o.SilentAfter <= 0 {
		o.SilentAfter = store.DefaultSilentAfter
	}
	if o.HealthEvery <= 0 {
		o.HealthEvery = 5 * time.Second
	}
	if o.InitialBytes <= 0 {
		o.InitialBytes = 16 << 20
	}
	if o.ChunkBytes <= 0 {
		o.ChunkBytes = 4 << 20
	}
	return &FileSource{dataDir: dataDir, hosts: hosts, o: o, offsets: make(map[string]int64)}
}

// dayFiles returns the daily files that can hold events inside the window,
// oldest first.
func (s *FileSource) dayFiles(now time.Time) ([]string, error) {
	dir := store.LogsDir(s.dataDir)
	des, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	first := now.Add(-s.o.Window).UTC().Truncate(24 * time.Hour)
	var files []string
	for _, de := range des {
		name := de.Name()
		if de.IsDir() || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		day, err := time.Parse("2006-01-02", strings.TrimSuffix(name, ".jsonl"))
		if err != nil || day.Before(first) {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	sort.Strings(files)
	return files, nil
}

// Poll implements Source.
func (s *FileSource) Poll(now time.Time) ([]collector.LogEntry, []DeviceRow, error) {
	var errs []string
	files, err := s.dayFiles(now)
	if err != nil {
		errs = append(errs, err.Error())
	}
	cutoff := now.Add(-s.o.Window)
	var out []collector.LogEntry
	for _, path := range files {
		got, err := s.readNew(path, cutoff)
		if err != nil {
			errs = append(errs, err.Error())
		}
		out = append(out, got...)
	}
	s.started = true
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp.Before(out[j].Timestamp) })

	if s.lastHealth.IsZero() || now.Sub(s.lastHealth) >= s.o.HealthEvery {
		s.lastHealth = now
		if rows, err := s.loadDevices(now); err != nil {
			errs = append(errs, err.Error())
		} else {
			s.devices = rows
		}
	}
	var perr error
	if len(errs) > 0 {
		perr = errors.New(strings.Join(errs, "; "))
	}
	return out, s.devices, perr
}

// readNew returns the complete lines appended to path since the last poll.
func (s *FileSource) readNew(path string, cutoff time.Time) ([]collector.LogEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	off, seen := s.offsets[path]
	skipPartial := false
	switch {
	case !seen && !s.started: // first look at start-up: only the tail
		if size > s.o.InitialBytes {
			off, skipPartial = size-s.o.InitialBytes, true
		}
	case !seen: // a file that appeared later (new day): all of it
		off = 0
	case size < off: // truncated or replaced
		off = 0
	}
	if size == off {
		s.offsets[path] = off
		return nil, nil
	}
	limit := s.o.ChunkBytes
	if !s.started && limit < s.o.InitialBytes {
		limit = s.o.InitialBytes
	}
	n := size - off
	if n > limit {
		n = limit
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, off); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	start := 0
	if skipPartial { // began mid-line: resume after the first newline
		i := bytes.IndexByte(buf, '\n')
		if i < 0 {
			s.offsets[path] = off + n
			return nil, nil
		}
		start = i + 1
	}
	end := bytes.LastIndexByte(buf, '\n') + 1
	if end <= start {
		if n >= limit { // a single line larger than the chunk: skip it rather than stall
			s.offsets[path] = off + n
		} else {
			s.offsets[path] = off + int64(start)
		}
		return nil, nil
	}
	s.offsets[path] = off + int64(end)

	var out []collector.LogEntry
	for _, line := range bytes.Split(buf[start:end], []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e collector.LogEntry
		if json.Unmarshal(line, &e) != nil || e.Timestamp.IsZero() {
			continue // a damaged line is skipped, never fatal
		}
		if e.Timestamp.Before(cutoff) { // outside the window: of no use to the dashboard
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (s *FileSource) loadDevices(now time.Time) ([]DeviceRow, error) {
	h, err := store.LoadHealth(store.HealthPath(s.dataDir))
	if err != nil {
		return nil, fmt.Errorf("reading collection health: %w", err)
	}
	sts := report.DeviceStatuses(h.All(), s.hosts, now, s.o.StaleAfter, s.o.SilentAfter)
	rows := make([]DeviceRow, len(sts))
	for i, d := range sts {
		r := DeviceRow{Hostname: d.Hostname, Status: d.Status, Detail: d.LastError}
		if d.LastAttempt != nil {
			r.LastPoll = *d.LastAttempt
		}
		rows[i] = r
	}
	return rows, nil
}
