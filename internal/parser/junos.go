// ==============================================================================
// Package parser: Juniper Junos log parser.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
// Parses "show log messages | last 100" (classic syslog in /var/log/messages):
//
//	Oct 20 09:30:15  sw1 mgd[1234]: UI_COMMIT: User 'tanvt' requested 'commit' operation
//	Oct 20 09:30:16  sw1 rpd[1500]: RPD_OSPF_NBRDOWN: OSPF neighbor 10.1.1.2 (...) state changed from Full to Down
//	Oct 20 09:31:00  sw1 sshd[3000]: Accepted password for tanvt from 10.1.1.1 port 5555 ssh2
//
// The Junos event name (UI_COMMIT, RPD_OSPF_NBRDOWN, ...) is kept in the
// summary so it stays greppable; the facility is derived from it.
package parser

import (
	"strings"

	"netlog/internal/collector"
	"netlog/internal/inventory"
)

type junosParser struct {
	key  string
	opts Options
}

// Parse implements Parser.
func (p *junosParser) Parse(raw string, dev inventory.Device) []collector.LogEntry {
	lines := splitLines(raw)
	out := make([]collector.LogEntry, 0, len(lines))
	for _, line := range lines {
		sl, ok := parseSyslog(line, p.opts)
		if !ok {
			continue
		}
		fac := guessFacility(sl.prog, sl.msg)
		if strings.HasPrefix(sl.msg, "UI_") || strings.HasPrefix(sl.msg, "SNMP_") {
			// Management-plane events: keep link traps under LINK, the rest SYS.
			if !strings.Contains(strings.ToUpper(sl.msg), "LINK") {
				fac = "SYS"
			}
		}
		e := newEntry(dev, p.key, line, sl.ts, fac, sl.msg)
		attribute(&e, sl.msg)
		out = append(out, e)
	}
	return out
}
