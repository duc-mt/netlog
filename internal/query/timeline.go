// ==============================================================================
// Package query: cross-device chronological timeline with causal annotation.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         rows := query.BuildTimeline(entries, query.TimelineOptions{...})
// Notes:         Go package implementation
// ==============================================================================
// A timeline merges every device's events into one chronological list. That
// only means something because entries are stored on skew-corrected
// timestamps: a config change on one switch and the fault it caused on its
// neighbour land in the right order even if their clocks disagree.
//
// FAULT events are annotated with the most recent config change on the SAME
// device within the correlation window, which is the "who broke it" line an
// operator wants at 2 AM:
//
//	10:12:00  NHG-TRANSIT-GW-01  [CONFIG]  User 'tanvt' applied commit
//	10:12:18  NHG-TRANSIT-GW-01  [FAULT]   BGP peer 10.255.255.5 down
//	              └── Likely caused by config change by tanvt at 10:12:00 (18s prior)
package query

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"netlog/internal/collector"
)

// CorrelationWindow is how far back a config change is considered a probable
// cause of a fault on the same device.
const CorrelationWindow = 10 * time.Minute

// TimelineOptions controls BuildTimeline.
type TimelineOptions struct {
	// From drops rows before this time after correlation, so callers can load
	// a little history before the window and still annotate its first faults.
	// Zero keeps everything.
	From time.Time

	// IncludeUnknown keeps UNKNOWN (unclassified, INFO) entries, which are
	// normally noise in a timeline.
	IncludeUnknown bool

	// Window overrides CorrelationWindow when non-zero.
	Window time.Duration
}

// Row is one timeline line plus, for a fault that follows a config change on
// the same device, the change that probably caused it.
type Row struct {
	Entry collector.LogEntry
	Cause *collector.LogEntry
}

// Note renders the causal annotation for display in loc, or "" if the row has
// no probable cause. The time is formatted at render time so it matches the
// zone of the row's own timestamp.
func (r Row) Note(loc *time.Location) string {
	if r.Cause == nil {
		return ""
	}
	who := "a config change"
	if r.Cause.User != "" {
		who = "config change by " + r.Cause.User
	}
	delta := r.Entry.Timestamp.Sub(r.Cause.Timestamp)
	return fmt.Sprintf("Likely caused by %s at %s (%s prior)",
		who, r.Cause.Timestamp.In(loc).Format("15:04:05"), shortDuration(delta))
}

// shortDuration renders d to whole seconds without Go's trailing "0s":
// 42s, 1m30s, 5m (not 5m0s).
func shortDuration(d time.Duration) string {
	s := d.Round(time.Second).String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	return s
}

func isConfigEvent(e collector.LogEntry) bool {
	return e.Event == "CONFIG_CHANGE" || e.Event == "AFTER_HOURS_CHANGE"
}

// BuildTimeline sorts entries chronologically, annotates faults with their
// probable cause, and applies the options.
func BuildTimeline(entries []collector.LogEntry, opts TimelineOptions) []Row {
	window := opts.Window
	if window <= 0 {
		window = CorrelationWindow
	}

	sorted := make([]collector.LogEntry, len(entries))
	copy(sorted, entries)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Timestamp.Before(sorted[j].Timestamp) })

	lastConfig := make(map[string]collector.LogEntry)
	rows := make([]Row, 0, len(sorted))
	for _, e := range sorted {
		row := Row{Entry: e}

		if isConfigEvent(e) {
			lastConfig[e.Hostname] = e
		} else if e.Category == collector.CategoryFault {
			if cc, ok := lastConfig[e.Hostname]; ok {
				if delta := e.Timestamp.Sub(cc.Timestamp); delta >= 0 && delta <= window {
					cause := cc
					row.Cause = &cause
				}
			}
		}

		if !opts.IncludeUnknown && e.Event == "UNKNOWN" {
			continue
		}
		if !opts.From.IsZero() && e.Timestamp.Before(opts.From) {
			continue
		}
		rows = append(rows, row)
	}
	return rows
}

func categoryColor(cat string) string {
	switch cat {
	case collector.CategoryFault:
		return ansiRed
	case collector.CategoryConfig:
		return ansiCyan
	case collector.CategorySecurity:
		return ansiBoldRd
	case collector.CategoryAuth:
		return ansiYellow
	}
	return ""
}

// rowText is the human-readable text of a row. For config and security
// events the acting user is named when the summary does not already say so.
func rowText(e collector.LogEntry) string {
	text := e.Summary
	if e.User != "" && !strings.Contains(text, e.User) &&
		(e.Category == collector.CategoryConfig || e.Category == collector.CategorySecurity) {
		text = fmt.Sprintf("User '%s': %s", e.User, text)
	}
	return text
}

// WriteTimeline prints rows in order. Times show HH:MM:SS when every row is
// on one local day and MM-DD HH:MM:SS otherwise.
func WriteTimeline(w io.Writer, rows []Row, st Style) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintln(w, "No events in this window.")
		return err
	}
	loc := st.loc()

	timeFmt := "15:04:05"
	firstDay := rows[0].Entry.Timestamp.In(loc).Format("2006-01-02")
	for _, r := range rows {
		if r.Entry.Timestamp.In(loc).Format("2006-01-02") != firstDay {
			timeFmt = "01-02 15:04:05"
			break
		}
	}

	wDev, wTag := 0, 0
	for _, r := range rows {
		if n := utf8.RuneCountInString(clip(r.Entry.Hostname, maxDeviceCol)); n > wDev {
			wDev = n
		}
		if n := len(r.Entry.Category) + 2; n > wTag {
			wTag = n
		}
	}

	for _, r := range rows {
		e := r.Entry
		stamp := e.Timestamp.In(loc).Format(timeFmt)
		tag := "[" + e.Category + "]"
		prefix := stamp + "  " + pad(clip(e.Hostname, maxDeviceCol), wDev) + "  "
		if _, err := fmt.Fprintf(w, "%s%s  %s\n",
			prefix,
			st.paint(categoryColor(e.Category), pad(tag, wTag)),
			st.paint(severityColor(e.Severity), clip(rowText(e), maxSummaryCol))); err != nil {
			return err
		}
		if note := r.Note(loc); note != "" {
			indent := strings.Repeat(" ", utf8.RuneCountInString(prefix)+2)
			if _, err := fmt.Fprintf(w, "%s%s\n", indent, st.paint(ansiYellow, "└── "+sanitize(note))); err != nil {
				return err
			}
		}
	}
	return nil
}
