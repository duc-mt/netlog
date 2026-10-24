// ==============================================================================
// Package parser: Huawei VRP log parser.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
// Parses "display logbuffer" output:
//
//	Oct 20 2026 09:31:02+07:00 NHG-HO-GW-01 %%01SHELL/5/CMDRECORD(l)[123]:bachngo: interface GigabitEthernet0/0/1 shutdown
//	Oct 20 2026 09:31:02+07:00 HOST %%01SHELL/6/CMDRECORD(s)[9]:Record command information. (Task=VTY0, Ip=10.1.1.1, VpnName=, User=admin, Command="system-view")
//
// CMDRECORD lines log every CLI command and are the best "who changed what"
// source on VRP without TACACS+, so the user and the command are extracted
// for both the short and the long message form. The banner that precedes the
// buffer ("Logging buffer configuration and contents...") is dropped.
package parser

import (
	"regexp"
	"strconv"

	"netlog/internal/collector"
	"netlog/internal/inventory"
)

type huaweiParser struct {
	key  string
	opts Options
}

// groups: 1 mon, 2 day, 3 year, 4 hms, 5 offset?, 6 host, 7 module, 8 severity, 9 mnemonic, 10 class?, 11 message
var reHuawei = regexp.MustCompile(`^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{4})\s+(\d{2}:\d{2}:\d{2}(?:\.\d+)?)(?:\s*([+-]\d{2}:?\d{2}))?\s+(\S+)\s+%{1,2}\d*([A-Za-z0-9_]+)/(\d)/([A-Za-z0-9_]+)(?:\((\w)\))?(?:\[\d+\])?:\s*(.*)$`)

var (
	reHuaweiShortCmd = regexp.MustCompile(`^([^\s:]+):\s*(.+)$`)
	reHuaweiLongCmd  = regexp.MustCompile(`Command="([^"]*)"`)
)

// Parse implements Parser.
func (p *huaweiParser) Parse(raw string, dev inventory.Device) []collector.LogEntry {
	lines := splitLines(raw)
	out := make([]collector.LogEntry, 0, len(lines))
	for _, line := range lines {
		m := reHuawei.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		mon, ok := parseMonth(m[1])
		if !ok {
			continue
		}
		day, _ := strconv.Atoi(m[2])
		year, _ := strconv.Atoi(m[3])
		loc := p.opts.loc()
		if m[5] != "" {
			if z, ok := zoneFromOffset(m[5]); ok {
				loc = z
			}
		}
		ts, ok := buildTime(year, mon, day, m[4], loc)
		if !ok {
			continue
		}

		msg := m[11]
		summary := msg
		e := newEntry(dev, p.key, line, ts, normalizeFacility(m[7]), "")

		if m[9] == "CMDRECORD" {
			if lc := reHuaweiLongCmd.FindStringSubmatch(msg); lc != nil {
				summary = lc[1]
			} else if sc := reHuaweiShortCmd.FindStringSubmatch(msg); sc != nil {
				e.User = sc[1]
				summary = sc[2]
			}
		}
		e.Summary = truncate(summary, maxSummary)
		attribute(&e, msg)
		out = append(out, e)
	}
	return out
}
