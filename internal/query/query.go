// ==============================================================================
// Package query: filtered search over stored netlog data and table output.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         entries, _ := query.Load(dataDir, query.Filter{Since: since})
// Notes:         Go package implementation
// ==============================================================================
// Package query reads the daily JSONL files written by the store package,
// applies the filters behind "netlog query", and renders the results as an
// aligned, optionally colourised table or as JSON. It also renders the
// incident list for "netlog incidents".
//
// The files are partitioned by the UTC day of each entry's (skew-corrected)
// Timestamp, so a time window maps to an exact set of files and nothing
// outside the window's days is ever opened. Lines that fail to decode, such
// as a final line truncated by a crash, are skipped.
package query

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"netlog/internal/collector"
	"netlog/internal/store"
)

// Filter selects log entries. Empty fields match everything.
type Filter struct {
	Host     string // substring of the hostname, case-insensitive
	User     string // exact user, case-insensitive
	Category string // CONFIG | AUTH | FAULT | SECURITY | SYSTEM
	Severity string // INFO | WARNING | ERROR | CRITICAL
	Event    string // substring of the event type, case-insensitive

	Since time.Time // inclusive; zero means no lower bound
	Until time.Time // inclusive; zero means no upper bound
}

// Match reports whether e satisfies the filter.
func (f Filter) Match(e collector.LogEntry) bool {
	if f.Host != "" && !strings.Contains(strings.ToLower(e.Hostname), strings.ToLower(f.Host)) {
		return false
	}
	if f.User != "" && !strings.EqualFold(e.User, f.User) {
		return false
	}
	if f.Category != "" && !strings.EqualFold(e.Category, f.Category) {
		return false
	}
	if f.Severity != "" && !strings.EqualFold(e.Severity, f.Severity) {
		return false
	}
	if f.Event != "" && !strings.Contains(strings.ToLower(e.Event), strings.ToLower(f.Event)) {
		return false
	}
	if !f.Since.IsZero() && e.Timestamp.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && e.Timestamp.After(f.Until) {
		return false
	}
	return true
}

// maxScanDays bounds how many daily files one query will walk.
const maxScanDays = 3660

// Load returns the entries under dataDir that match f, oldest first. A data
// directory with no logs yields an empty result, not an error.
func Load(dataDir string, f Filter) ([]collector.LogEntry, error) {
	return load(dataDir, f, 0)
}

// LoadTail is Load restricted to the last tailBytes of each daily file. It
// is for callers that only need the most recent minutes (priming the anomaly
// detector at startup): newest lines are appended last, so reading the end of
// the file is enough and avoids scanning a whole day's logs on every
// cron-driven run.
func LoadTail(dataDir string, f Filter, tailBytes int64) ([]collector.LogEntry, error) {
	return load(dataDir, f, tailBytes)
}

// Scan streams the entries under dataDir that match f to fn, one at a time,
// without keeping them. Memory stays flat however much history is read, which
// is what an aggregating caller (netlog report) needs; Load, which collects
// and sorts every match, scales with the amount of data instead.
//
// Entries arrive in file (day) order and, within a day, in the order they were
// stored: not sorted by time, so a caller that needs order must sort what it
// keeps. A data directory with no logs yields no calls and no error.
func Scan(dataDir string, f Filter, fn func(collector.LogEntry)) error {
	files, err := logFiles(store.LogsDir(dataDir), f.Since, f.Until)
	if err != nil {
		return err
	}
	for _, path := range files {
		if err := scanFile(path, 0, func(e collector.LogEntry) {
			if f.Match(e) {
				fn(e)
			}
		}); err != nil {
			return err
		}
	}
	return nil
}

func load(dataDir string, f Filter, tailBytes int64) ([]collector.LogEntry, error) {
	dir := store.LogsDir(dataDir)

	files, err := logFiles(dir, f.Since, f.Until)
	if err != nil {
		return nil, err
	}

	var out []collector.LogEntry
	for _, path := range files {
		if err := scanFile(path, tailBytes, func(e collector.LogEntry) {
			if f.Match(e) {
				out = append(out, e)
			}
		}); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp.Before(out[j].Timestamp) })
	return out, nil
}

// logFiles lists the daily files that can contain entries in [since, until].
func logFiles(dir string, since, until time.Time) ([]string, error) {
	if _, err := os.Stat(dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading logs directory: %w", err)
	}

	// Bounded window: open exactly the files for the days it spans.
	if !since.IsZero() {
		end := until
		if end.IsZero() {
			end = time.Now()
		}
		var files []string
		day := since.UTC().Truncate(24 * time.Hour)
		last := end.UTC().Truncate(24 * time.Hour)
		for n := 0; !day.After(last) && n < maxScanDays; n++ {
			path := filepath.Join(dir, store.LogFileName(day))
			if _, err := os.Stat(path); err == nil {
				files = append(files, path)
			}
			day = day.AddDate(0, 0, 1)
		}
		return files, nil
	}

	// Unbounded: every daily file, in name (= date) order.
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading logs directory: %w", err)
	}
	var files []string
	for _, de := range des {
		if !de.IsDir() && strings.HasSuffix(de.Name(), ".jsonl") {
			files = append(files, filepath.Join(dir, de.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

// scanFile decodes every line of a JSONL file, skipping malformed ones.
func scanFile(path string, tailBytes int64, fn func(collector.LogEntry)) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var skipFirst bool
	if tailBytes > 0 {
		if fi, err := f.Stat(); err == nil && fi.Size() > tailBytes {
			if _, err := f.Seek(fi.Size()-tailBytes, io.SeekStart); err == nil {
				skipFirst = true
			}
		}
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	if skipFirst {
		sc.Scan() // the first line is almost certainly cut in half
	}
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e collector.LogEntry
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		fn(e)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	return nil
}

// ==============================================================================
// Time parsing
// ==============================================================================

var reSince = regexp.MustCompile(`^(\d+)\s*([smhdw])$`)

// ParseSince converts "30m", "2h", "24h", "7d", "2w", "today" (local
// midnight) or any Go duration into an absolute lower bound relative to now.
func ParseSince(s string, now time.Time) (time.Time, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "today" {
		y, m, d := now.Date()
		return time.Date(y, m, d, 0, 0, 0, 0, now.Location()), nil
	}
	if m := reSince.FindStringSubmatch(s); m != nil {
		n, err := strconv.Atoi(m[1])
		if err != nil || n <= 0 {
			return time.Time{}, fmt.Errorf("invalid --since value %q", s)
		}
		unit := map[string]time.Duration{
			"s": time.Second, "m": time.Minute, "h": time.Hour,
			"d": 24 * time.Hour, "w": 7 * 24 * time.Hour,
		}[m[2]]
		return now.Add(-time.Duration(n) * unit), nil
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	return time.Time{}, fmt.Errorf("invalid --since value %q (use e.g. 30m, 2h, 24h, 7d or today)", s)
}

// ParseTime parses "2006-01-02 15:04:05", "2006-01-02T15:04:05" (both read in
// loc), RFC 3339 (zone included), "2006-01-02 15:04" or "2006-01-02".
func ParseTime(s string, loc *time.Location) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, loc); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time %q (use \"2006-01-02 15:04:05\" or RFC 3339)", s)
}

// ==============================================================================
// Output
// ==============================================================================

// Style controls rendering.
type Style struct {
	Color    bool           // emit ANSI colours
	Location *time.Location // zone for displayed times; nil means time.Local
}

func (s Style) loc() *time.Location {
	if s.Location == nil {
		return time.Local
	}
	return s.Location
}

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
	ansiBoldRd = "\x1b[1;31m"
)

func (s Style) paint(code, text string) string {
	if !s.Color || code == "" {
		return text
	}
	return code + text + ansiReset
}

func severityColor(sev string) string {
	switch strings.ToUpper(sev) {
	case collector.SeverityCritical:
		return ansiBoldRd
	case collector.SeverityError:
		return ansiRed
	case collector.SeverityWarning:
		return ansiYellow
	}
	return ""
}

// Reasonable caps keep one long hostname or message from wrecking alignment.
const (
	maxDeviceCol  = 24
	maxUserCol    = 14
	maxEventCol   = 22
	maxSummaryCol = 160
)

// sanitize replaces control characters (ESC, CR, BEL, the C1 range...) with
// "?". Log text comes from network devices, which are not trusted; printed
// raw, a crafted log line could rewrite or clear the operator's terminal.
// JSON output needs no such care, since the encoder escapes control bytes.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return '?'
		}
		return r
	}, s)
}

// pad right-pads s with spaces to width w, counting runes.
func pad(s string, w int) string {
	if n := utf8.RuneCountInString(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}

func clip(s string, limit int) string {
	s = sanitize(s)
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	r := []rune(s)
	return string(r[:limit-1]) + "…"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func widest(header string, vals []string, limit int) int {
	w := utf8.RuneCountInString(header)
	for _, v := range vals {
		if n := utf8.RuneCountInString(clip(v, limit)); n > w {
			w = n
		}
	}
	return w
}

// WriteTable prints entries as TIME | DEVICE | CAT | SEV | USER | EVENT |
// SUMMARY, in the order given.
func WriteTable(w io.Writer, entries []collector.LogEntry, st Style) error {
	if len(entries) == 0 {
		_, err := fmt.Fprintln(w, "No matching events.")
		return err
	}
	loc := st.loc()

	var devs, cats, sevs, users, events []string
	for _, e := range entries {
		devs = append(devs, e.Hostname)
		cats = append(cats, e.Category)
		sevs = append(sevs, e.Severity)
		users = append(users, dash(e.User))
		events = append(events, e.Event)
	}
	const timeW = len("2006-01-02 15:04:05")
	wDev := widest("DEVICE", devs, maxDeviceCol)
	wCat := widest("CAT", cats, 10)
	wSev := widest("SEV", sevs, 8)
	wUser := widest("USER", users, maxUserCol)
	wEvt := widest("EVENT", events, maxEventCol)

	header := strings.Join([]string{
		pad("TIME", timeW), pad("DEVICE", wDev), pad("CAT", wCat), pad("SEV", wSev),
		pad("USER", wUser), pad("EVENT", wEvt), "SUMMARY",
	}, "  ")
	if _, err := fmt.Fprintln(w, st.paint(ansiBold, header)); err != nil {
		return err
	}

	for _, e := range entries {
		sevCode := severityColor(e.Severity)
		line := strings.Join([]string{
			pad(e.Timestamp.In(loc).Format("2006-01-02 15:04:05"), timeW),
			pad(clip(e.Hostname, maxDeviceCol), wDev),
			pad(clip(e.Category, 10), wCat),
			st.paint(sevCode, pad(clip(e.Severity, 8), wSev)),
			pad(clip(dash(e.User), maxUserCol), wUser),
			pad(clip(e.Event, maxEventCol), wEvt),
			st.paint(sevCode, clip(e.Summary, maxSummaryCol)),
		}, "  ")
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

// WriteJSON prints entries as an indented JSON array.
func WriteJSON(w io.Writer, entries []collector.LogEntry) error {
	if entries == nil {
		entries = []collector.LogEntry{}
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}

// SortNewestFirst orders entries by descending Timestamp (stable).
func SortNewestFirst(entries []collector.LogEntry) {
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Timestamp.After(entries[j].Timestamp) })
}

// WriteIncidentList prints incident reports as TIME | DEVICE | PLAYBOOK |
// TRIGGER | ID. The ID column is what "netlog incidents --id" takes.
func WriteIncidentList(w io.Writer, reports []collector.IncidentReport, st Style) error {
	if len(reports) == 0 {
		_, err := fmt.Fprintln(w, "No incidents.")
		return err
	}
	loc := st.loc()
	var devs, plays []string
	for _, r := range reports {
		devs = append(devs, r.Hostname)
		plays = append(plays, r.Playbook)
	}
	const timeW = len("2006-01-02 15:04:05")
	wDev := widest("DEVICE", devs, maxDeviceCol)
	wPlay := widest("PLAYBOOK", plays, 20)

	header := strings.Join([]string{pad("TIME", timeW), pad("DEVICE", wDev), pad("PLAYBOOK", wPlay), "TRIGGER", "ID"}, "  ")
	if _, err := fmt.Fprintln(w, st.paint(ansiBold, header)); err != nil {
		return err
	}
	for _, r := range reports {
		trigger := r.TriggerLog.Event
		if r.TriggerLog.Summary != "" {
			trigger += ": " + r.TriggerLog.Summary
		}
		line := strings.Join([]string{
			pad(r.Timestamp.In(loc).Format("2006-01-02 15:04:05"), timeW),
			pad(clip(r.Hostname, maxDeviceCol), wDev),
			pad(clip(r.Playbook, 20), wPlay),
			st.paint(severityColor(r.TriggerLog.Severity), clip(trigger, maxSummaryCol)),
			st.paint(ansiDim, sanitize(r.ID)),
		}, "  ")
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

// WriteIncidentJSON pretty-prints one incident report.
func WriteIncidentJSON(w io.Writer, r collector.IncidentReport) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteIncidentDetail renders a human-readable diagnostic report for a single incident.
func WriteIncidentDetail(w io.Writer, r collector.IncidentReport, st Style) error {
	loc := st.loc()
	fmt.Fprintf(w, "%s %s\n", st.paint(ansiBold, "INCIDENT REPORT:"), sanitize(r.ID))
	fmt.Fprintf(w, "  %-15s %s (%s)\n", "Timestamp:", r.Timestamp.In(loc).Format("2006-01-02 15:04:05 MST"), r.Timestamp.UTC().Format("15:04:05 UTC"))
	fmt.Fprintf(w, "  %-15s %s\n", "Device:", sanitize(r.Hostname))
	if r.TriggerLog.Vendor != "" {
		fmt.Fprintf(w, "  %-15s %s\n", "Vendor:", sanitize(r.TriggerLog.Vendor))
	}
	fmt.Fprintf(w, "  %-15s %s\n", "Playbook:", sanitize(r.Playbook))
	fmt.Fprintf(w, "  %-15s %s\n", "Severity:", st.paint(severityColor(r.TriggerLog.Severity), r.TriggerLog.Severity))
	fmt.Fprintf(w, "  %-15s %s\n", "Event:", sanitize(r.TriggerLog.Event))
	if r.TriggerLog.User != "" {
		fmt.Fprintf(w, "  %-15s %s\n", "User:", sanitize(r.TriggerLog.User))
	}
	if r.TriggerLog.SourceIP != "" {
		fmt.Fprintf(w, "  %-15s %s\n", "Source IP:", sanitize(r.TriggerLog.SourceIP))
	}

	fmt.Fprintf(w, "\n%s\n", st.paint(ansiBold, "TRIGGERING LOG:"))
	fmt.Fprintf(w, "  %s\n", sanitize(r.TriggerLog.Raw))

	if len(r.TriageHints) > 0 {
		fmt.Fprintf(w, "\n%s\n", st.paint(ansiBold, "TRIAGE HINTS:"))
		for _, hint := range r.TriageHints {
			fmt.Fprintf(w, "  * %s\n", sanitize(hint))
		}
	}

	fmt.Fprintf(w, "\n%s\n", st.paint(ansiBold, fmt.Sprintf("DIAGNOSTICS (%d command(s) executed):", len(r.Diagnostics))))
	for i, diag := range r.Diagnostics {
		status := "OK"
		statusColor := ansiGreen
		if diag.Error != "" {
			status = "ERROR: " + diag.Error
			statusColor = ansiRed
		}
		fmt.Fprintf(w, "\n[%d] Command: %s  (%dms, %s)\n", i+1, st.paint(ansiBold, sanitize(diag.Command)), diag.DurationMs, st.paint(statusColor, status))
		fmt.Fprintln(w, strings.Repeat("-", 70))
		out := strings.TrimRight(diag.Output, "\r\n")
		if out == "" {
			fmt.Fprintln(w, "  (no output returned)")
		} else {
			lines := strings.Split(out, "\n")
			for _, l := range lines {
				fmt.Fprintln(w, "  "+sanitize(strings.TrimRight(l, "\r")))
			}
		}
		fmt.Fprintln(w, strings.Repeat("-", 70))
	}
	return nil
}
