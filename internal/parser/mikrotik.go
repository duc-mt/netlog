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
// RouterOS also forwards its log to a remote syslog server ("netlog listen").
// There the topics follow the device name, comma-joined and without a colon,
// and a firewall rule's log prefix leads the message:
//
//	Oct 27 10:15:02 edge-rtr2 interface,info ether1 link down
//	Oct 27 10:15:03 edge-rtr2 system,info,account user admin logged in from 10.1.1.1 via ssh
//	Oct 27 10:15:04 edge-rtr2 firewall,info DROP-IN: in:ether1 out:(unknown 0), proto TCP (SYN), 203.0.113.9:4444->198.51.100.1:22, len 60
//
// This is a best-effort parser: RouterOS 6 and 7 differ in column layout, and
// only the two forms above are recognised.
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

// reMikrotikSyslog matches the forwarded form. groups: 1 mon, 2 day, 3 hms,
// 4 topics (at least "topic,severity"), 5 message. The device name is not
// captured: the entry's Hostname comes from the inventory device.
var reMikrotikSyslog = regexp.MustCompile(`^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+\S+\s+([A-Za-z0-9_-]+(?:,[A-Za-z0-9_-]+)+):?\s+(.+)$`)

// reMikrotikBy picks the user out of RouterOS configuration messages such as
// "ip address added by admin" or "filter rule changed by admin".
var reMikrotikBy = regexp.MustCompile(`\b(?:added|changed|removed|moved|enabled|disabled) by ([A-Za-z0-9_.@-]+)`)

// mikrotikFacility maps the topic list to the shared vocabulary.
func mikrotikFacility(topics string) string {
	t := strings.ToLower(topics)
	switch {
	case strings.Contains(t, "account"):
		return "SEC"
	case strings.Contains(t, "firewall"):
		return "FW"
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
		if m := reMikrotikSyslog.FindStringSubmatch(line); m != nil {
			if e, ok := p.fromSyslog(line, m, dev); ok {
				out = append(out, e)
			}
			continue
		}
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
		mikrotikUser(&e, m[9])
		out = append(out, e)
	}
	return out
}

// fromSyslog builds an entry from a forwarded RouterOS syslog line.
func (p *mikrotikParser) fromSyslog(line string, m []string, dev inventory.Device) (collector.LogEntry, bool) {
	mon, ok := parseMonth(m[1])
	if !ok {
		return collector.LogEntry{}, false
	}
	day, _ := strconv.Atoi(m[2])
	ts, ok := buildYearless(mon, day, m[3], p.opts)
	if !ok {
		return collector.LogEntry{}, false
	}
	e := newEntry(dev, p.key, line, ts, mikrotikFacility(m[4]), m[5])
	attribute(&e, m[5])
	mikrotikUser(&e, m[5])
	return e, true
}

// mikrotikUser fills User from a "... changed by <user>" message.
func mikrotikUser(e *collector.LogEntry, msg string) {
	if e.User != "" {
		return
	}
	if m := reMikrotikBy.FindStringSubmatch(msg); m != nil {
		e.User = m[1]
	}
}
