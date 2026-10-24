// ==============================================================================
// Package parser: MikroTik RouterOS log parser.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
// Parses "/log print" output. RouterOS prints a short date only for entries
// that are not from today, so a missing date means "today" (by the fetch
// time):
//
//	oct/19 23:59:59 system,info,account user admin logged in from 10.1.1.1 via ssh
//	09:31:00 interface,info ether1 link down
//	2026-10-20 09:31:05 system,error,critical login failure for user admin from 10.1.1.1 via ssh
//
// This is a best-effort parser: RouterOS 6 and 7 differ in column layout, and
// only the date/time/topics/message form above is recognised.
package parser

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"netlog/internal/collector"
	"netlog/internal/inventory"
)

type mikrotikParser struct {
	key  string
	opts Options
}

// groups: 1 mon, 2 day, 3 year? | 4 yyyy, 5 mm, 6 dd | 7 hms, 8 topics, 9 message
var reMikrotik = regexp.MustCompile(`^(?:\d+\s+)?(?:(?:([A-Za-z]{3})/(\d{1,2})(?:/(\d{4}))?|(\d{4})-(\d{2})-(\d{2}))\s+)?(\d{2}:\d{2}:\d{2})\s+([A-Za-z0-9_,.-]+)\s+(.+)$`)

// mikrotikFacility maps the topic list to the shared vocabulary.
func mikrotikFacility(topics string) string {
	t := strings.ToLower(topics)
	switch {
	case strings.Contains(t, "account"):
		return "SEC"
	case strings.Contains(t, "ospf"):
		return "OSPF"
	case strings.Contains(t, "bgp"):
		return "BGP"
	case strings.Contains(t, "vrrp"):
		return "VRRP"
	case strings.Contains(t, "interface"):
		return "LINK"
	case strings.Contains(t, "system"):
		return "SYS"
	}
	first, _, _ := strings.Cut(topics, ",")
	return strings.ToUpper(first)
}

// Parse implements Parser.
func (p *mikrotikParser) Parse(raw string, dev inventory.Device) []collector.LogEntry {
	lines := splitLines(raw)
	out := make([]collector.LogEntry, 0, len(lines))
	ref := p.opts.ref().In(p.opts.loc())
	for _, line := range lines {
		m := reMikrotik.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		var (
			ts time.Time
			ok bool
		)
		switch {
		case m[1] != "":
			mon, mok := parseMonth(m[1])
			if !mok {
				continue
			}
			day, _ := strconv.Atoi(m[2])
			if m[3] != "" {
				y, _ := strconv.Atoi(m[3])
				ts, ok = buildTime(y, mon, day, m[7], p.opts.loc())
			} else {
				ts, ok = buildYearless(mon, day, m[7], p.opts)
			}
		case m[4] != "":
			y, _ := strconv.Atoi(m[4])
			mo, _ := strconv.Atoi(m[5])
			day, _ := strconv.Atoi(m[6])
			ts, ok = buildTime(y, timeMonth(mo), day, m[7], p.opts.loc())
		default:
			ts, ok = buildTime(ref.Year(), ref.Month(), ref.Day(), m[7], p.opts.loc())
		}
		if !ok {
			continue
		}
		e := newEntry(dev, p.key, line, ts, mikrotikFacility(m[8]), m[9])
		attribute(&e, m[9])
		out = append(out, e)
	}
	return out
}
