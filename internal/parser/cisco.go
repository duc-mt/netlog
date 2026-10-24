// ==============================================================================
// Package parser: Cisco IOS / IOS-XE / ASA / Small Business log parser.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
// Handles the %FACILITY-SEVERITY-MNEMONIC message format and its common
// timestamp variants:
//
//	Oct 20 09:30:15.123: %SYS-5-CONFIG_I: Configured from console by bachngo on vty0 (10.10.10.50)
//	000123: *Oct 20 09:31:02.001 UTC: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down
//	Oct 20 2026 09:30:15: %ASA-6-302013: Built inbound TCP connection ...
//	Oct 20 2026 09:30:15 %LINK-W-Down:  gi5            (Small Business: letter severity)
//
// Lines timestamped with device uptime instead of a date ("1d02h: %...")
// carry no wall-clock time and are dropped; enable
// "service timestamps log datetime" on such devices to have them collected.
package parser

import (
	"regexp"
	"strconv"
	"time"

	"netlog/internal/collector"
	"netlog/internal/inventory"
)

type ciscoParser struct {
	key  string
	opts Options
}

var (
	// groups: 1 mon, 2 day, 3 year?, 4 hms, 5 facility, 6 severity, 7 mnemonic, 8 message
	reCiscoIOS = regexp.MustCompile(`^(?:\d+:\s*)?[*.!]?([A-Za-z]{3})\s+(\d{1,2})(?:\s+(\d{4}))?\s+(\d{2}:\d{2}:\d{2}(?:\.\d+)?)(?:\s+(?:[+-]\d{2}(?::?\d{2})?|[A-Za-z][A-Za-z0-9._-]*))?\s*:\s*%([A-Za-z0-9_]+)-(\d)-([A-Za-z0-9_]+):\s*(.*)$`)

	// groups: 1 yyyy, 2 mon, 3 dd | 4 mon, 5 dd, 6 yyyy, 7 hms, 8 facility, 9 severity letter, 10 mnemonic, 11 message
	reCiscoSB = regexp.MustCompile(`^(?:(\d{4})-([A-Za-z]{3})-(\d{2})|([A-Za-z]{3})\s+(\d{1,2})\s+(\d{4}))\s+(\d{2}:\d{2}:\d{2})\s+%([A-Za-z0-9_]+)-([A-Z])-([A-Za-z0-9_]+):\s*(.*)$`)
)

// Parse implements Parser.
func (p *ciscoParser) Parse(raw string, dev inventory.Device) []collector.LogEntry {
	lines := splitLines(raw)
	out := make([]collector.LogEntry, 0, len(lines))
	for _, line := range lines {
		if e, ok := p.parseLine(line, dev); ok {
			out = append(out, e)
		}
	}
	return out
}

// parseLine parses one line; it is also used by the generic parser.
func (p *ciscoParser) parseLine(line string, dev inventory.Device) (collector.LogEntry, bool) {
	if m := reCiscoIOS.FindStringSubmatch(line); m != nil {
		mon, ok := parseMonth(m[1])
		if !ok {
			return collector.LogEntry{}, false
		}
		day, _ := strconv.Atoi(m[2])
		var ts time.Time
		if m[3] != "" {
			y, _ := strconv.Atoi(m[3])
			ts, ok = buildTime(y, mon, day, m[4], p.opts.loc())
		} else {
			ts, ok = buildYearless(mon, day, m[4], p.opts)
		}
		if !ok {
			return collector.LogEntry{}, false
		}
		e := newEntry(dev, p.key, line, ts, normalizeFacility(m[5]), m[8])
		attribute(&e, m[8])
		return e, true
	}
	if m := reCiscoSB.FindStringSubmatch(line); m != nil {
		var (
			mon time.Month
			day int
			y   int
			ok  bool
		)
		if m[1] != "" {
			y, _ = strconv.Atoi(m[1])
			mon, ok = parseMonth(m[2])
			day, _ = strconv.Atoi(m[3])
		} else {
			mon, ok = parseMonth(m[4])
			day, _ = strconv.Atoi(m[5])
			y, _ = strconv.Atoi(m[6])
		}
		if !ok {
			return collector.LogEntry{}, false
		}
		ts, ok := buildTime(y, mon, day, m[7], p.opts.loc())
		if !ok {
			return collector.LogEntry{}, false
		}
		e := newEntry(dev, p.key, line, ts, normalizeFacility(m[8]), m[11])
		attribute(&e, m[11])
		return e, true
	}
	return collector.LogEntry{}, false
}
