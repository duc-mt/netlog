// ==============================================================================
// Package store defines netlog's on-disk layout and storage interfaces.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         store.NewJSONLWriter(dataDir), store.LoadState(path)
// Notes:         Go package implementation
// ==============================================================================
// Package store owns everything netlog writes to disk, rooted at one data
// directory:
//
//	<data>/logs/YYYY-MM-DD.jsonl      one normalized LogEntry per line (UTC day)
//	<data>/incidents/<ts>_<host>_<event>.json   one IncidentReport per file
//	<data>/.netlog_state.json         per-device watermarks (atomic writes)
//	<data>/.netlog_cooldown.json      triage cooldown timestamps (atomic writes)
//
// Plain JSON files keep the binary CGO-free and the data greppable with jq.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"netlog/internal/collector"
	"netlog/internal/fsutil"
)

// Names of the entries inside the data directory.
const (
	logsSubdir      = "logs"
	incidentsSubdir = "incidents"
	stateFileName   = ".netlog_state.json"
	cooldownName    = ".netlog_cooldown.json"
)

// Permissions: directories are owner-only; files are group-readable so a
// monitoring account can read logs.
const (
	dirPerm  os.FileMode = 0o700
	filePerm os.FileMode = 0o640
)

// LogsDir returns the directory holding the daily JSONL files.
func LogsDir(dataDir string) string { return filepath.Join(dataDir, logsSubdir) }

// IncidentsDir returns the directory holding incident reports.
func IncidentsDir(dataDir string) string { return filepath.Join(dataDir, incidentsSubdir) }

// StatePath returns the watermark state file path.
func StatePath(dataDir string) string { return filepath.Join(dataDir, stateFileName) }

// CooldownPath returns the triage cooldown file path.
func CooldownPath(dataDir string) string { return filepath.Join(dataDir, cooldownName) }

// Writer persists normalized log entries.
type Writer interface {
	// Append durably appends entries. Entries are partitioned by the UTC day
	// of their Timestamp. A nil or empty slice is a no-op.
	Append(entries []collector.LogEntry) error
	// Close releases resources. It is safe to call more than once.
	Close() error
}

// ==============================================================================
// Incidents
// ==============================================================================

var reUnsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// IncidentFileName returns "<YYYY-MM-DD_HHMMSS>_<host>_<event>.json" (UTC),
// with the host and event reduced to filename-safe characters.
func IncidentFileName(t time.Time, host, event string) string {
	return fmt.Sprintf("%s_%s_%s.json",
		t.UTC().Format("2006-01-02_150405"),
		reUnsafeName.ReplaceAllString(host, "_"),
		reUnsafeName.ReplaceAllString(event, "_"))
}

// WriteIncident writes r as pretty-printed JSON into dir and returns the
// path. If a file of that name already exists (two incidents for one host and
// event in the same second) a numeric suffix is added rather than
// overwriting.
func WriteIncident(dir string, r collector.IncidentReport) (string, error) {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return "", fmt.Errorf("creating incidents directory: %w", err)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encoding incident %s: %w", r.ID, err)
	}
	data = append(data, '\n')

	base := IncidentFileName(r.Timestamp, r.Hostname, r.TriggerLog.Event)
	path := filepath.Join(dir, base)
	for i := 2; i < 100; i++ {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			break
		}
		path = filepath.Join(dir, strings.TrimSuffix(base, ".json")+fmt.Sprintf("_%d.json", i))
	}
	if err := fsutil.WriteFileAtomic(path, data, filePerm); err != nil {
		return "", err
	}
	return path, nil
}

// ListIncidents loads the incident reports in dir with Timestamp >= since,
// newest first. A missing directory is not an error. Unreadable or malformed
// files are skipped.
func ListIncidents(dir string, since time.Time) ([]collector.IncidentReport, error) {
	reports, err := readIncidents(dir, since, "")
	if err != nil {
		return nil, err
	}
	sort.SliceStable(reports, func(i, j int) bool { return reports[i].Timestamp.After(reports[j].Timestamp) })
	return reports, nil
}

// FindIncident returns the single incident whose ID starts with idPrefix. It
// fails if the prefix matches none or more than one.
func FindIncident(dir, idPrefix string) (collector.IncidentReport, error) {
	if idPrefix == "" {
		return collector.IncidentReport{}, errors.New("incident id is empty")
	}
	reports, err := readIncidents(dir, time.Time{}, idPrefix)
	if err != nil {
		return collector.IncidentReport{}, err
	}
	switch len(reports) {
	case 0:
		return collector.IncidentReport{}, fmt.Errorf("no incident with id starting %q", idPrefix)
	case 1:
		return reports[0], nil
	default:
		return collector.IncidentReport{}, fmt.Errorf("id prefix %q is ambiguous (%d incidents match)", idPrefix, len(reports))
	}
}

func readIncidents(dir string, since time.Time, idPrefix string) ([]collector.IncidentReport, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading incidents directory: %w", err)
	}
	var out []collector.IncidentReport
	for _, de := range entries {
		name := de.Name()
		if de.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		// Cheap pre-filter on the timestamp embedded in the file name.
		if !since.IsZero() && len(name) >= 17 {
			if ft, err := time.Parse("2006-01-02_150405", name[:17]); err == nil && ft.Before(since.UTC().Add(-time.Minute)) {
				continue
			}
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var r collector.IncidentReport
		if json.Unmarshal(data, &r) != nil || r.ID == "" {
			continue
		}
		if idPrefix != "" && !strings.HasPrefix(r.ID, idPrefix) {
			continue
		}
		if !since.IsZero() && r.Timestamp.Before(since) {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}
