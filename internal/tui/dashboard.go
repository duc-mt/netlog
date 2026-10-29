// ==============================================================================
// Package tui: live split-pane terminal dashboard ("netlog top").
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-27
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         m := tui.NewModel(opts); m.Ingest(entries); m.Render(w, h, now)
// Notes:         Go package implementation
// ==============================================================================
// The dashboard is a pure function of its Model: Ingest feeds it events,
// SetDevices feeds it collection health, HandleKey changes what is shown and
// Render draws the whole frame into a Screen. Nothing here touches a terminal
// (see terminal.go) or the file system (see source.go), which keeps the layout
// testable. Only the standard library and ANSI escape sequences are used.
//
// Layout (w x h):
//
//	row 0      title, clock, active filter, PAUSED marker
//	row 1      counters (FAULT CONFIG AUTH SECURITY SYSTEM, last 24h)
//	row 2      devices monitored, collection health
//	row 3      rule
//	upper      live event feed, newest at the bottom, severity badges
//	lower-left unresolved outages and flapping interfaces
//	lower-right device status (OK / FAILING / STALE / SILENT ...) and last poll
//	last row   key help
package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"netlog/internal/collector"
	"netlog/internal/pipeline"
)

// Limits and defaults.
const (
	MinWidth  = 60
	MinHeight = 12

	DefaultWindow    = 24 * time.Hour // counter window
	DefaultMaxEvents = 1000           // events kept for the feed
	flapShownFor     = 10 * time.Minute
)

// categories are the counters shown in the banner, in order.
var categories = []string{
	collector.CategoryFault, collector.CategoryConfig, collector.CategoryAuth,
	collector.CategorySecurity, collector.CategorySystem,
}

// filters are what the "c" key cycles through: all, then one category each.
var filters = append([]string{"ALL"}, categories...)

// Options configures a Model.
type Options struct {
	Color     bool
	Window    time.Duration  // counter window (default 24h)
	MaxEvents int            // feed size (default 1000)
	Loc       *time.Location // zone for clock times (default time.Local)
}

// DeviceRow is one device's collection health.
type DeviceRow struct {
	Hostname string
	Status   string // "OK", "FAILING", "STALE", "SILENT", ...
	LastPoll time.Time
	Detail   string // last error for a failing device
}

// outage is a down event not yet matched by its recovery.
type outage struct {
	host, kind, object string
	since              time.Time
	downs              int
}

// Model is the dashboard state.
type Model struct {
	opts Options

	ring    []collector.LogEntry
	buckets map[int64]*[5]int // minute -> per-category counts
	open    map[string]*outage
	flaps   map[string]time.Time

	devices []DeviceRow
	total   int

	filter   int
	paused   bool
	frozen   []collector.LogEntry
	newSince int // events that arrived while paused

	status string // last poll error, shown in the footer
}

// NewModel returns an empty model.
func NewModel(o Options) *Model {
	if o.Window <= 0 {
		o.Window = DefaultWindow
	}
	if o.MaxEvents <= 0 {
		o.MaxEvents = DefaultMaxEvents
	}
	if o.Loc == nil {
		o.Loc = time.Local
	}
	return &Model{
		opts:    o,
		buckets: make(map[int64]*[5]int),
		open:    make(map[string]*outage),
		flaps:   make(map[string]time.Time),
	}
}

func catIndex(c string) int {
	for i, n := range categories {
		if n == c {
			return i
		}
	}
	return -1
}

// kindOf classifies the state-change events that pair a down with an up.
func kindOf(event string) (kind string, down bool, ok bool) {
	switch event {
	case pipeline.EventLinkDown:
		return "link", true, true
	case pipeline.EventLinkUp:
		return "link", false, true
	case pipeline.EventOSPFAdjDown:
		return "ospf", true, true
	case pipeline.EventOSPFAdjUp:
		return "ospf", false, true
	case pipeline.EventBGPPeerDown:
		return "bgp", true, true
	case pipeline.EventBGPPeerUp:
		return "bgp", false, true
	}
	return "", false, false
}

// Ingest adds events, oldest first, to the feed, the counters and the outage
// tracking.
func (m *Model) Ingest(entries []collector.LogEntry) {
	for _, e := range entries {
		m.ring = append(m.ring, e)
		if m.paused {
			m.newSince++
		}
		if i := catIndex(e.Category); i >= 0 {
			minute := e.Timestamp.Unix() / 60
			b := m.buckets[minute]
			if b == nil {
				b = new([5]int)
				m.buckets[minute] = b
			}
			b[i]++
		}
		if kind, down, ok := kindOf(e.Event); ok {
			key := e.Hostname + "\x00" + kind + "\x00" + e.Object
			switch {
			case down:
				if o := m.open[key]; o != nil {
					o.downs++
				} else {
					m.open[key] = &outage{host: e.Hostname, kind: kind, object: e.Object, since: e.Timestamp, downs: 1}
				}
			default:
				delete(m.open, key)
			}
		}
		if e.Event == pipeline.EventLinkFlap {
			m.flaps[e.Hostname+"\x00link\x00"+e.Object] = e.Timestamp
		}
	}
	if over := len(m.ring) - m.opts.MaxEvents; over > 0 {
		m.ring = append(m.ring[:0], m.ring[over:]...)
	}
}

// SetDevices replaces the device list (most urgent first, as given).
func (m *Model) SetDevices(rows []DeviceRow) {
	m.devices = rows
	m.total = len(rows)
}

// SetStatus sets the message shown in the footer ("" clears it).
func (m *Model) SetStatus(s string) { m.status = s }

// Paused reports whether the event feed is frozen.
func (m *Model) Paused() bool { return m.paused }

// Filter returns the active category filter ("ALL" or a category).
func (m *Model) Filter() string { return filters[m.filter] }

// HandleKey applies a key press and reports whether the user asked to quit.
// q, Q, Ctrl+C (0x03) and Ctrl+D (0x04) quit; c cycles the category filter;
// p pauses and resumes the feed.
func (m *Model) HandleKey(b byte) (quit bool) {
	switch b {
	case 'q', 'Q', 0x03, 0x04:
		return true
	case 'c', 'C':
		m.filter = (m.filter + 1) % len(filters)
	case 'p', 'P':
		m.paused = !m.paused
		if m.paused {
			m.frozen = append([]collector.LogEntry(nil), m.ring...)
			m.newSince = 0
		} else {
			m.frozen, m.newSince = nil, 0
		}
	}
	return false
}

// Counts returns the per-category totals within the window ending at now.
func (m *Model) Counts(now time.Time) [5]int {
	var out [5]int
	cutoff := now.Add(-m.opts.Window).Unix() / 60
	for minute, b := range m.buckets {
		if minute < cutoff {
			delete(m.buckets, minute) // expired: keeps the table at one window
			continue
		}
		for i, n := range b {
			out[i] += n
		}
	}
	return out
}

// Outages returns the unresolved outages (within the window), flapping ones
// first, then oldest first.
func (m *Model) Outages(now time.Time) []OutageRow {
	var rows []OutageRow
	cutoff := now.Add(-m.opts.Window)
	for _, o := range m.open {
		if o.since.Before(cutoff) {
			continue
		}
		last, flapping := m.flaps[o.host+"\x00"+o.kind+"\x00"+o.object]
		rows = append(rows, OutageRow{
			Host: o.host, Kind: o.kind, Object: o.object, Since: o.since, Downs: o.downs,
			Flapping: flapping && now.Sub(last) <= flapShownFor,
		})
	}
	// A flapping interface that is currently up is still worth a line.
	for key, last := range m.flaps {
		if now.Sub(last) > flapShownFor {
			delete(m.flaps, key)
			continue
		}
		if _, isOpen := m.open[key]; isOpen {
			continue
		}
		parts := strings.SplitN(key, "\x00", 3)
		rows = append(rows, OutageRow{Host: parts[0], Kind: parts[1], Object: parts[2], Since: last, Flapping: true, Recovered: true})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Flapping != rows[j].Flapping {
			return rows[i].Flapping
		}
		if !rows[i].Since.Equal(rows[j].Since) {
			return rows[i].Since.Before(rows[j].Since)
		}
		return rows[i].Host+rows[i].Object < rows[j].Host+rows[j].Object
	})
	return rows
}

// OutageRow is one line of the lower-left pane.
type OutageRow struct {
	Host, Kind, Object string
	Since              time.Time
	Downs              int
	Flapping           bool
	Recovered          bool // flapped recently but is up now
}

func (m *Model) feed() []collector.LogEntry {
	src := m.ring
	if m.paused {
		src = m.frozen
	}
	f := filters[m.filter]
	if f == "ALL" {
		return src
	}
	out := make([]collector.LogEntry, 0, len(src))
	for _, e := range src {
		if e.Category == f {
			out = append(out, e)
		}
	}
	return out
}

// ---- rendering --------------------------------------------------------------------------

func (m *Model) styled(style string) string {
	if !m.opts.Color {
		return styleNone
	}
	return style
}

func sevBadge(sev string) (string, string) {
	switch strings.ToUpper(sev) {
	case collector.SeverityCritical:
		return "CRIT", styleRevRed
	case collector.SeverityError:
		return "ERR ", styleRed
	case collector.SeverityWarning:
		return "WARN", styleYellow
	}
	return "INFO", styleDim
}

func statusStyle(status string) string {
	switch status {
	case "OK":
		return styleGreen
	case "FAILING":
		return styleBoldRd
	case "STALE", "SILENT", "UNPARSEABLE":
		return styleYellow
	}
	return styleDim
}

// windowLabel renders the counter window: "24h" for whole hours.
func windowLabel(d time.Duration) string {
	if d >= time.Hour && d%time.Hour == 0 {
		return fmt.Sprintf("%dh", int(d/time.Hour))
	}
	return shortDur(d)
}

// shortDur renders a duration compactly: "45s", "12m", "3h05m", "2d4h".
func shortDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
}

// Render draws the whole dashboard for a w x h terminal at time now.
func (m *Model) Render(w, h int, now time.Time) *Screen {
	s := NewScreen(w, h)
	if w < MinWidth || h < MinHeight {
		s.Put(0, 0, fmt.Sprintf("netlog top: terminal too small (%dx%d), need %dx%d", w, h, MinWidth, MinHeight), m.styled(styleBoldRd))
		s.Put(0, h-1, "q quit", styleNone)
		return s
	}

	// Title line.
	title := " netlog top"
	s.Put(0, 0, title, m.styled(styleBold))
	right := now.In(m.opts.Loc).Format("2006-01-02 15:04:05") + " "
	s.Put(w-len(right), 0, right, styleNone)
	x := len(title) + 2
	if f := m.Filter(); f != "ALL" {
		tag := "[filter: " + f + "]"
		s.Put(x, 0, tag, m.styled(styleCyan))
		x += len(tag) + 1
	}
	if m.paused {
		tag := fmt.Sprintf("[PAUSED +%d]", m.newSince)
		s.Put(x, 0, tag, m.styled(styleRev))
	}

	// Counters, devices, collection health.
	counts := m.Counts(now)
	x = 1
	for i, name := range categories {
		st := styleNone
		if counts[i] > 0 {
			switch name {
			case collector.CategoryFault:
				st = styleRed
			case collector.CategorySecurity:
				st = styleYellow
			}
		}
		if m.Filter() == name {
			st = styleCyan
		}
		label := fmt.Sprintf("%s %d", name, counts[i])
		s.Put(x, 1, label, m.styled(st))
		x += len(label) + 2
	}
	s.Put(x, 1, "("+windowLabel(m.opts.Window)+")", m.styled(styleDim))

	// Devices monitored and collection health get their own row: with
	// several statuses present they would not fit beside the counters.
	devText := fmt.Sprintf("devices %d", m.total)
	s.Put(1, 2, devText, styleNone)
	healthText, healthStyle := m.healthSummary()
	s.Put(len(devText)+4, 2, "collection health: "+healthText, m.styled(healthStyle))
	s.Fill(3, 0, w, '─', m.styled(styleDim))

	// Pane geometry.
	body := h - 5 // rows 4 .. h-2
	upperH := body / 2
	lowerH := body - upperH
	y0, y1 := 4, 4+upperH

	// Upper: event feed.
	m.title(s, y0, 0, w, fmt.Sprintf("Live events%s", m.feedSuffix()))
	feed := m.feed()
	rows := upperH - 1
	if len(feed) > rows {
		feed = feed[len(feed)-rows:]
	}
	for i, e := range feed {
		m.eventRow(s, y0+1+i, w, e)
	}
	if len(feed) == 0 {
		s.Put(1, y0+1, "no events yet", m.styled(styleDim))
	}

	// Lower-left: outages and flaps. Lower-right: devices.
	lw := w / 2
	m.title(s, y1, 0, lw, "Unresolved outages / flapping")
	m.title(s, y1, lw+1, w-lw-1, "Devices")
	for y := y1; y < y1+lowerH; y++ {
		s.Put(lw, y, "│", m.styled(styleDim))
	}
	m.outagePane(s, y1+1, lowerH-1, 0, lw, now)
	m.devicePane(s, y1+1, lowerH-1, lw+1, w-lw-1, now)

	// Footer.
	foot := " q quit   c category filter   p pause/resume"
	if m.status != "" {
		foot += "   | " + m.status
	}
	s.PutClipped(0, h-1, w, foot, m.styled(styleDim))
	return s
}

func (m *Model) feedSuffix() string {
	n := len(m.feed())
	if f := m.Filter(); f != "ALL" {
		return fmt.Sprintf(" (%s, %d)", f, n)
	}
	return fmt.Sprintf(" (%d)", n)
}

func (m *Model) title(s *Screen, y, x, width int, text string) {
	s.Fill(y, x, x+width, ' ', m.styled(styleRev))
	s.PutClipped(x+1, y, width-2, text, m.styled(styleRev))
}

func (m *Model) healthSummary() (string, string) {
	if len(m.devices) == 0 {
		return "no devices", styleDim
	}
	counts := map[string]int{}
	var order []string
	for _, d := range m.devices {
		if counts[d.Status] == 0 {
			order = append(order, d.Status)
		}
		counts[d.Status]++
	}
	sort.SliceStable(order, func(i, j int) bool { return statusWeight(order[i]) < statusWeight(order[j]) })
	parts := make([]string, len(order))
	for i, st := range order {
		parts[i] = fmt.Sprintf("%d %s", counts[st], st)
	}
	style := styleGreen
	if counts["OK"] != len(m.devices) {
		style = styleYellow
		if counts["FAILING"] > 0 {
			style = styleBoldRd
		}
	}
	return strings.Join(parts, ", "), style
}

func statusWeight(s string) int {
	switch s {
	case "FAILING":
		return 0
	case "STALE":
		return 1
	case "SILENT":
		return 2
	case "OK":
		return 9
	}
	return 5
}

func (m *Model) eventRow(s *Screen, y, w int, e collector.LogEntry) {
	ts := e.Timestamp.In(m.opts.Loc).Format("15:04:05")
	badge, bst := sevBadge(e.Severity)
	s.Put(1, y, ts, m.styled(styleDim))
	s.Put(10, y, badge, m.styled(bst))
	hostW := 14
	s.PutClipped(15, y, hostW, e.Hostname, styleNone)
	ev := e.Event
	if ev == "" {
		ev = e.Category
	}
	evW := 18
	s.PutClipped(15+hostW+1, y, evW, ev, m.styled(styleBold))
	text := e.Summary
	if text == "" {
		text = e.Raw
	}
	start := 15 + hostW + 1 + evW + 1
	s.PutClipped(start, y, w-start-1, text, styleNone)
}

func (m *Model) outagePane(s *Screen, y, rows, x, width int, now time.Time) {
	list := m.Outages(now)
	if len(list) == 0 {
		s.Put(x+1, y, "none: every down has recovered", m.styled(styleGreen))
		return
	}
	for i, o := range list {
		if i >= rows {
			s.Put(x+1, y+rows-1, fmt.Sprintf("+%d more", len(list)-rows+1), m.styled(styleDim))
			return
		}
		tag, st := fmt.Sprintf("down %s", shortDur(now.Sub(o.Since))), styleRed
		if o.Recovered {
			tag, st = fmt.Sprintf("flapped %s ago, up now", shortDur(now.Sub(o.Since))), styleYellow
		} else if o.Flapping {
			tag, st = fmt.Sprintf("FLAPPING, down %s", shortDur(now.Sub(o.Since))), styleBoldRd
		}
		if o.Downs > 1 && !o.Recovered {
			tag += fmt.Sprintf(" (%dx)", o.Downs)
		}
		obj := o.Object
		if obj == "" {
			obj = "?"
		}
		s.PutClipped(x+1, y+i, width-2, fmt.Sprintf("%s %s %s  %s", o.Host, o.Kind, obj, tag), m.styled(st))
	}
}

func (m *Model) devicePane(s *Screen, y, rows, x, width int, now time.Time) {
	if len(m.devices) == 0 {
		s.Put(x+1, y, "no devices known (see --inventory)", m.styled(styleDim))
		return
	}
	for i, d := range m.devices {
		if i >= rows {
			s.Put(x+1, y+rows-1, fmt.Sprintf("+%d more", len(m.devices)-rows+1), m.styled(styleDim))
			return
		}
		st := d.Status
		s.PutClipped(x+1, y+i, 12, st, m.styled(statusStyle(st)))
		hostW := 16
		s.PutClipped(x+14, y+i, hostW, d.Hostname, styleNone)
		poll := "never polled"
		if !d.LastPoll.IsZero() {
			poll = fmt.Sprintf("%s (%s ago)", d.LastPoll.In(m.opts.Loc).Format("15:04:05"), shortDur(now.Sub(d.LastPoll)))
		}
		if d.Status == "FAILING" && d.Detail != "" {
			poll = d.Detail
		}
		start := x + 14 + hostW + 1
		s.PutClipped(start, y+i, x+width-start-1, poll, m.styled(styleDim))
	}
}
