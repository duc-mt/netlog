// ==============================================================================
// Package parser: generic best-effort log parser.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
// The fallback for Aruba, Ruijie, Arista, Palo Alto and any vendor without a
// dedicated parser. It tries, in order, the Cisco-style mnemonic format
// (Ruijie RGOS and many others emit it), ISO 8601 / RFC 3164 syslog (Arista
// EOS, Aruba, most Linux-based gear), and a plain "YYYY-MM-DD HH:MM:SS
// message" prefix (PAN-OS system log). Anything else is dropped.
package parser

import (
	"regexp"
	"strconv"

	"netlog/internal/collector"
	"netlog/internal/inventory"
)

type genericParser struct {
	key   string
	opts  Options
	cisco *ciscoParser
}

func newGenericParser(key string, opts Options) *genericParser {
	return &genericParser{key: key, opts: opts, cisco: &ciscoParser{key: key, opts: opts}}
}

// groups: 1 yyyy, 2 mm, 3 dd, 4 hms, 5 message
var reGenericDated = regexp.MustCompile(`^(\d{4})[-/](\d{2})[-/](\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(.+)$`)

// Parse implements Parser.
func (p *genericParser) Parse(raw string, dev inventory.Device) []collector.LogEntry {
	lines := splitLines(raw)
	out := make([]collector.LogEntry, 0, len(lines))
	for _, line := range lines {
		if e, ok := p.cisco.parseLine(line, dev); ok {
			out = append(out, e)
			continue
		}
		if sl, ok := parseSyslog(line, p.opts); ok {
			e := newEntry(dev, p.key, line, sl.ts, guessFacility(sl.prog, sl.msg), sl.msg)
			attribute(&e, sl.msg)
			out = append(out, e)
			continue
		}
		if m := reGenericDated.FindStringSubmatch(line); m != nil {
			y, _ := strconv.Atoi(m[1])
			mo, _ := strconv.Atoi(m[2])
			d, _ := strconv.Atoi(m[3])
			ts, ok := buildTime(y, timeMonth(mo), d, m[4], p.opts.loc())
			if !ok {
				continue
			}
			e := newEntry(dev, p.key, line, ts, guessFacility("", m[5]), m[5])
			attribute(&e, m[5])
			out = append(out, e)
		}
	}
	return out
}
