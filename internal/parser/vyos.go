// ==============================================================================
// Package parser: VyOS log parser.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
// VyOS "show log" output is syslog text. Depending on the release it is
// either ISO 8601 with a numeric offset (journald-style),
//
//	2026-10-20T09:44:01+07:00 NHG-BVU-GW-01 commit[1234]: [user: tanvt] Applying config changes
//
// or classic RFC 3164 (Mon DD HH:MM:SS). Both are handled by the shared
// syslog splitter. VyOS tags commits with a "[user: NAME]" marker, which the
// shared attribution step extracts.
package parser

import (
	"netlog/internal/collector"
	"netlog/internal/inventory"
)

type vyosParser struct {
	key  string
	opts Options
}

// Parse implements Parser.
func (p *vyosParser) Parse(raw string, dev inventory.Device) []collector.LogEntry {
	lines := splitLines(raw)
	out := make([]collector.LogEntry, 0, len(lines))
	for _, line := range lines {
		sl, ok := parseSyslog(line, p.opts)
		if !ok {
			continue // journald banner, wrapped line, etc.
		}
		e := newEntry(dev, p.key, line, sl.ts, guessFacility(sl.prog, sl.msg), sl.msg)
		attribute(&e, sl.msg)
		out = append(out, e)
	}
	return out
}
