// ==============================================================================
// Package parser: Cumulus Linux syslog parser.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-27
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
// Cumulus Linux is a Debian system: its log is plain rsyslog output, either
// RFC 3164 or the RFC 3339 form that recent releases write by default, and
// the same lines arrive over the network from "netlog listen":
//
//	Oct 27 10:15:02 leaf01 switchd[1234]: swp1: link down
//	2026-10-27T10:15:03.123456+07:00 leaf01 bgpd[987]: %ADJCHANGE: neighbor 10.0.0.2(swp1) in vrf default Down Peer closed the session
//	2026-10-27T10:15:04+07:00 leaf01 sshd[55]: Accepted publickey for cumulus from 10.1.1.5 port 5555 ssh2
//
// The line is split by the shared syslog splitter; this parser only adds the
// facility vocabulary of the Cumulus daemons (FRR, switchd, mstpd, clagd,
// ptmd, lldpd, nvued). The sample lines in the tests follow the documented
// formats and have not been checked against a live switch; a line worded
// differently is stored with facility SYS and is classified by its text like
// any other, never misparsed.
package parser

import (
	"strings"

	"netlog/internal/collector"
	"netlog/internal/inventory"
)

type cumulusParser struct {
	key  string
	opts Options
}

// cumulusFacility maps the daemon name (and, for the generic kernel/switchd
// channels, the message text) to the shared facility vocabulary.
func cumulusFacility(prog, msg string) string {
	p := strings.ToLower(prog)
	switch {
	case strings.HasPrefix(p, "bgpd"):
		return "BGP"
	case strings.HasPrefix(p, "ospfd") || strings.HasPrefix(p, "ospf6d"):
		return "OSPF"
	case strings.HasPrefix(p, "mstpd"):
		return "STP"
	case strings.HasPrefix(p, "clagd"):
		return "CLAG"
	case strings.HasPrefix(p, "ptmd"):
		return "PTM"
	case strings.HasPrefix(p, "lldpd"):
		return "LLDP"
	case strings.HasPrefix(p, "nvued") || strings.HasPrefix(p, "nvue"):
		return "NVUE"
	case p == "switchd" || p == "kernel" || p == "zebra":
		if reFacLink.MatchString(msg) || strings.Contains(strings.ToLower(msg), " is down") || strings.Contains(strings.ToLower(msg), " is up") {
			return "LINK"
		}
	}
	return guessFacility(prog, msg)
}

// Parse implements Parser.
func (p *cumulusParser) Parse(raw string, dev inventory.Device) []collector.LogEntry {
	lines := splitLines(raw)
	out := make([]collector.LogEntry, 0, len(lines))
	for _, line := range lines {
		sl, ok := parseSyslog(line, p.opts)
		if !ok {
			continue
		}
		e := newEntry(dev, p.key, line, sl.ts, cumulusFacility(sl.prog, sl.msg), sl.msg)
		attribute(&e, sl.msg)
		out = append(out, e)
	}
	return out
}
