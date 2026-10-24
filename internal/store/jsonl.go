// ==============================================================================
// Package store: append-only daily JSONL log writer.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
// Entries are appended, one JSON object per line, to data/logs/YYYY-MM-DD.jsonl
// where the date is the UTC day of the entry's corrected Timestamp. Appending
// never rewrites existing bytes, so a crash can at worst leave one truncated
// final line, which readers skip.
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"netlog/internal/collector"
)

// JSONLWriter is the file-backed Writer. It is safe for concurrent use.
type JSONLWriter struct {
	dir string
	mu  sync.Mutex
}

var _ Writer = (*JSONLWriter)(nil)

// NewJSONLWriter creates <dataDir>/logs if needed and returns a writer for it.
func NewJSONLWriter(dataDir string) (*JSONLWriter, error) {
	dir := LogsDir(dataDir)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("creating logs directory: %w", err)
	}
	return &JSONLWriter{dir: dir}, nil
}

// LogFileName returns the daily file name for the UTC day of t.
func LogFileName(t time.Time) string { return t.UTC().Format("2006-01-02") + ".jsonl" }

// Append implements Writer. Each day's lines are written with a single write
// call followed by fsync, so the watermark that the caller advances afterwards
// never gets ahead of data that is only in the page cache.
func (w *JSONLWriter) Append(entries []collector.LogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	byDay := make(map[string]*bytes.Buffer)
	for i := range entries {
		day := LogFileName(entries[i].Timestamp)
		buf := byDay[day]
		if buf == nil {
			buf = &bytes.Buffer{}
			byDay[day] = buf
		}
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false) // keep "<", ">" and "&" readable in raw log text
		if err := enc.Encode(&entries[i]); err != nil {
			return fmt.Errorf("encoding log entry %s: %w", entries[i].ID, err)
		}
	}

	days := make([]string, 0, len(byDay))
	for d := range byDay {
		days = append(days, d)
	}
	sort.Strings(days)

	w.mu.Lock()
	defer w.mu.Unlock()
	for _, day := range days {
		if err := appendFile(filepath.Join(w.dir, day), byDay[day].Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func appendFile(path string, data []byte) (err error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, filePerm)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing %s: %w", path, cerr)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("appending to %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("syncing %s: %w", path, err)
	}
	return nil
}

// Close implements Writer. Files are opened per Append, so there is nothing
// to release.
func (w *JSONLWriter) Close() error { return nil }

// Prune deletes daily log files whose UTC day is more than keepDays before
// now and returns how many were removed. keepDays <= 0 disables pruning.
// Only files named YYYY-MM-DD.jsonl are considered.
func Prune(dataDir string, keepDays int, now time.Time) (int, error) {
	if keepDays <= 0 {
		return 0, nil
	}
	dir := LogsDir(dataDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("reading logs directory: %w", err)
	}
	cutoff := now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -keepDays)
	removed := 0
	for _, de := range entries {
		name := de.Name()
		if de.IsDir() || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		day, err := time.Parse("2006-01-02", strings.TrimSuffix(name, ".jsonl"))
		if err != nil || !day.Before(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return removed, fmt.Errorf("removing %s: %w", name, err)
		}
		removed++
	}
	return removed, nil
}
