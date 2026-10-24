// ==============================================================================
// Package report: table and JSON rendering of a Report.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-24
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         report.WriteTable(os.Stdout, rep, query.Style{Color: true})
// Notes:         Go package implementation
// ==============================================================================
// The text output is a sequence of labelled sections, each an aligned table
// built with the same query.Pad / Clip / Widest / Sanitize helpers as
// "netlog query", so device-supplied text (hostnames, users, source IPs) is
// stripped of control characters before it reaches the operator's terminal.
// There is deliberately no unsanitised print path in this file: every string
// that can originate on a device goes through query.Clip.
//
// The JSON output is one object with a key per section, with no formatting
// and no ANSI. Slices are always arrays, never null.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"netlog/internal/query"
)

// noData is the line printed for a section with no rows, worded like the
// existing writers' "No matching events.".
const noData = "No matching events."

// Column caps for values that are not covered by the shared query constants.
const (
	maxNumCol   = 20
	maxIPCol    = 45 // longest textual IPv6 address
	maxHostsCol = 60
	maxDayCol   = len(dayLayout)
)

// ==============================================================================
// JSON
// ==============================================================================

// WriteJSON prints r as one indented JSON object with a key per section,
// following query.WriteJSON's conventions (no HTML escaping, indented). A
// nil slice or map in r is printed as an empty one so consumers never see
// null for a section that merely had no rows; week_over_week is null when
// the delta was not computed.
func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(r.normalized())
}

// normalized replaces nil slices and maps with empty ones. Compute already
// produces none; this protects a zero-value or hand-built Report.
func (r Report) normalized() Report {
	if r.NoisyDevices == nil {
		r.NoisyDevices = []DeviceFaultCount{}
	}
	if r.ChangeAccountability.ByUser == nil {
		r.ChangeAccountability.ByUser = []UserChangeCount{}
	}
	if r.ChangeAccountability.AfterHours == nil {
		r.ChangeAccountability.AfterHours = []AfterHoursChange{}
	}
	if r.SecurityWatchlist == nil {
		r.SecurityWatchlist = []WatchedSource{}
	}
	for i, s := range r.SecurityWatchlist {
		if s.Hostnames == nil {
			r.SecurityWatchlist[i].Hostnames = []string{}
		}
	}
	if r.VolumeByCategory == nil {
		r.VolumeByCategory = VolumeByCategory{}
	}
	if r.IncidentClosure.UnreachableHosts == nil {
		r.IncidentClosure.UnreachableHosts = []UnreachableHost{}
	}
	if w := r.WeekOverWeek; w != nil && w.Categories == nil {
		cp := *w
		cp.Categories = []CategoryDelta{}
		r.WeekOverWeek = &cp
	}
	return r
}

// ==============================================================================
// Table
// ==============================================================================

// WriteTable prints r as labelled sections separated by blank lines. The
// week-over-week section appears only when it was computed.
func WriteTable(w io.Writer, r Report, st query.Style) error {
	p := &printer{w: w}
	writers := []func(*printer, Report, query.Style){writeNoisy, writeChanges, writeWatchlist, writeVolume}
	if r.WeekOverWeek != nil {
		writers = append(writers, writeDelta)
	}
	writers = append(writers, writeClosure)

	for i, write := range writers {
		if i > 0 {
			p.println("")
		}
		write(p, r, st)
	}
	return p.err
}

// printer remembers the first write error so the section writers need not
// check every line; later writes become no-ops.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) println(s string) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintln(p.w, s)
}

// column describes one table column.
type column struct {
	title string
	limit int  // values are clipped to this many runes
	right bool // right-align, for numbers
}

// grid prints cols and rows as an aligned table: a bold header line, then
// one line per row. Every value is clipped (and so sanitised) here. paint, if
// set, colours a whole row; the last left-aligned column is not padded, so
// lines carry no trailing spaces.
func grid(p *printer, st query.Style, cols []column, rows [][]string, paint func(row int, line string) string) {
	widths := make([]int, len(cols))
	for c, col := range cols {
		vals := make([]string, len(rows))
		for r := range rows {
			vals[r] = rows[r][c]
		}
		widths[c] = query.Widest(col.title, vals, col.limit)
	}

	line := func(cells []string) string {
		parts := make([]string, len(cols))
		for c, col := range cols {
			text := query.Clip(cells[c], col.limit)
			switch {
			case col.right:
				parts[c] = padLeft(text, widths[c])
			case c == len(cols)-1:
				parts[c] = text
			default:
				parts[c] = query.Pad(text, widths[c])
			}
		}
		return strings.Join(parts, "  ")
	}

	titles := make([]string, len(cols))
	for c, col := range cols {
		titles[c] = col.title
	}
	p.println(st.Bold(line(titles)))
	for i, row := range rows {
		s := line(row)
		if paint != nil {
			s = paint(i, s)
		}
		p.println(s)
	}
}

// padLeft left-pads s with spaces to width w, counting runes.
func padLeft(s string, w int) string {
	if n := utf8.RuneCountInString(s); n < w {
		return strings.Repeat(" ", w-n) + s
	}
	return s
}

// heading prints a bold "=== title ===" line. The title may contain the
// caller's --since text, so it is sanitised like everything else.
func heading(p *printer, st query.Style, format string, args ...any) {
	p.println(st.Bold("=== " + query.Sanitize(fmt.Sprintf(format, args...)) + " ==="))
}

func itoa(n int) string { return strconv.Itoa(n) }

// windowPhrase describes the requested window for headings: "last 7d",
// "today", or "all time" when the window is open.
func windowPhrase(o Options) string {
	label := strings.ToLower(strings.TrimSpace(o.Label))
	if label == "" && !o.Since.IsZero() && !o.Until.IsZero() {
		label = durationLabel(o.Until.Sub(o.Since))
	}
	switch label {
	case "":
		return "all time"
	case "today":
		return "today"
	}
	return "last " + label
}

// durationLabel renders d as the largest whole unit: 7d, 36h, 90m.
func durationLabel(d time.Duration) string {
	switch {
	case d <= 0:
		return ""
	case d%(24*time.Hour) == 0:
		return itoa(int(d/(24*time.Hour))) + "d"
	case d%time.Hour == 0:
		return itoa(int(d/time.Hour)) + "h"
	case d%time.Minute == 0:
		return itoa(int(d/time.Minute)) + "m"
	}
	return d.Round(time.Second).String()
}

// ---- 1. noisy devices -------------------------------------------------------

func writeNoisy(p *printer, r Report, st query.Style) {
	heading(p, st, "Noisy Devices (top %d, %s)", r.Options.top(), windowPhrase(r.Options))
	if len(r.NoisyDevices) == 0 {
		p.println(noData)
		return
	}
	rows := make([][]string, len(r.NoisyDevices))
	for i, d := range r.NoisyDevices {
		rows[i] = []string{query.Dash(d.Hostname), itoa(d.Count)}
	}
	grid(p, st, []column{{"DEVICE", query.MaxDeviceCol, false}, {"FAULTS", maxNumCol, true}}, rows, nil)
}

// ---- 2. change accountability -----------------------------------------------

func writeChanges(p *printer, r Report, st query.Style) {
	ca := r.ChangeAccountability
	heading(p, st, "Change Accountability (%s)", windowPhrase(r.Options))
	if ca.Total == 0 {
		p.println(noData)
		return
	}
	rows := make([][]string, len(ca.ByUser))
	for i, u := range ca.ByUser {
		rows[i] = []string{u.User, itoa(u.Count), itoa(u.AfterHours)}
	}
	grid(p, st, []column{{"USER", query.MaxUserCol, false}, {"CHANGES", maxNumCol, true}, {"AFTER-HOURS", maxNumCol, true}}, rows, nil)

	p.println("")
	p.println(st.Bold("After-hours changes: " + itoa(ca.AfterHoursCount)))
	if ca.AfterHoursCount == 0 {
		return
	}
	loc := st.Loc()
	ah := make([][]string, len(ca.AfterHours))
	for i, e := range ca.AfterHours {
		ah[i] = []string{e.Timestamp.In(loc).Format("2006-01-02 15:04:05"), e.Hostname, e.User}
	}
	grid(p, st, []column{{"TIME", len("2006-01-02 15:04:05"), false}, {"DEVICE", query.MaxDeviceCol, false}, {"USER", query.MaxUserCol, false}}, ah,
		func(_ int, line string) string { return st.Yellow(line) })
}

// ---- 3. security watchlist --------------------------------------------------

func writeWatchlist(p *printer, r Report, st query.Style) {
	heading(p, st, "Security Watchlist (top %d, %s)", r.Options.top(), windowPhrase(r.Options))
	if len(r.SecurityWatchlist) == 0 {
		p.println(noData)
		return
	}
	rows := make([][]string, len(r.SecurityWatchlist))
	for i, s := range r.SecurityWatchlist {
		rows[i] = []string{s.SourceIP, itoa(s.DistinctHosts), itoa(s.Events), strings.Join(s.Hostnames, ", ")}
	}
	cols := []column{{"SOURCE IP", maxIPCol, false}, {"DEVICES", maxNumCol, true}, {"EVENTS", maxNumCol, true}, {"HOSTS", maxHostsCol, false}}
	grid(p, st, cols, rows, func(i int, line string) string {
		if r.SecurityWatchlist[i].DistinctHosts > 1 {
			return st.Red(line) // one source touching several devices
		}
		return line
	})
}

// ---- 4. event volume --------------------------------------------------------

func writeVolume(p *printer, r Report, st query.Style) {
	heading(p, st, "Event Volume by Category/Day (UTC, %s)", windowPhrase(r.Options))
	if len(r.VolumeByCategory) == 0 {
		p.println(noData)
		return
	}
	days := make([]string, 0, len(r.VolumeByCategory))
	for d := range r.VolumeByCategory {
		days = append(days, d)
	}
	sort.Strings(days)

	cols := []column{{"DAY", maxDayCol, false}}
	for _, c := range categories {
		cols = append(cols, column{c, maxNumCol, true})
	}
	rows := make([][]string, len(days))
	for i, d := range days {
		row := []string{d}
		for _, c := range categories {
			row = append(row, itoa(r.VolumeByCategory[d][c]))
		}
		rows[i] = row
	}
	grid(p, st, cols, rows, nil)
}

// ---- 5. week-over-week ------------------------------------------------------

func signed(n int) string {
	if n > 0 {
		return "+" + itoa(n)
	}
	return itoa(n)
}

func pctText(p *float64) string {
	if p == nil {
		return "n/a"
	}
	s := strconv.FormatFloat(*p, 'f', 1, 64)
	if *p > 0 {
		s = "+" + s
	}
	return s + "%"
}

func writeDelta(p *printer, r Report, st query.Style) {
	w := r.WeekOverWeek
	if r.Options.Until.Sub(r.Options.Since) == Week {
		heading(p, st, "Week-over-Week (last 7d vs previous 7d)")
	} else {
		heading(p, st, "Window-over-Window (%s vs the equal window before it)", windowPhrase(r.Options))
	}
	if w.Total.Previous == 0 && w.Total.Current == 0 {
		p.println(noData)
		return
	}
	all := append(append([]CategoryDelta{}, w.Categories...), w.Total)
	rows := make([][]string, len(all))
	for i, d := range all {
		rows[i] = []string{d.Category, itoa(d.Previous), itoa(d.Current), signed(d.Change), pctText(d.ChangePct)}
	}
	cols := []column{{"CATEGORY", 10, false}, {"PREVIOUS", maxNumCol, true}, {"CURRENT", maxNumCol, true}, {"CHANGE", maxNumCol, true}, {"CHANGE %", maxNumCol, true}}
	grid(p, st, cols, rows, func(i int, line string) string {
		if all[i].ChangePct == nil {
			return st.Dim(line) // no baseline to compare against
		}
		return line
	})
}

// ---- 6. incident closure ----------------------------------------------------

func writeClosure(p *printer, r Report, st query.Style) {
	ic := r.IncidentClosure
	heading(p, st, "Incident Closure (%s)", windowPhrase(r.Options))
	if ic.Total == 0 {
		p.println("No incidents.")
		return
	}
	p.println(fmt.Sprintf("%-27s %d", "Incidents:", ic.Total))
	p.println(fmt.Sprintf("%-27s %d (%.1f%%)", "All diagnostics succeeded:", ic.Succeeded, ic.SucceededPct))
	p.println(fmt.Sprintf("%-27s %d (%.1f%%)", "Unreachable during triage:", ic.Unreachable, ic.UnreachablePct))
	p.println(fmt.Sprintf("%-27s %d (%.1f%%)", "Some commands failed:", ic.PartialFailure, ic.PartialFailurePct))
	if len(ic.UnreachableHosts) == 0 {
		return
	}

	p.println("")
	p.println(st.Bold("Devices unreachable during triage:"))
	rows := make([][]string, len(ic.UnreachableHosts))
	for i, h := range ic.UnreachableHosts {
		always := "-"
		if h.Always {
			always = "yes"
		}
		rows[i] = []string{h.Hostname, itoa(h.Unreachable), itoa(h.Incidents), always}
	}
	cols := []column{{"DEVICE", query.MaxDeviceCol, false}, {"UNREACHABLE", maxNumCol, true}, {"INCIDENTS", maxNumCol, true}, {"ALWAYS", 6, true}}
	grid(p, st, cols, rows, func(i int, line string) string {
		if ic.UnreachableHosts[i].Always {
			return st.Red(line)
		}
		return line
	})
}
