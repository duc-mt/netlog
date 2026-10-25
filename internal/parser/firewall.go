// ==============================================================================
// Package parser: pfSense and Check Point Gaia log parsers.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-24
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
// Both platforms are Unix firewalls whose logs are plain syslog files, read
// over SSH with tail (see the fetch plans in internal/collector).
//
// pfSense (2.5 and newer, where /var/log/*.log are plain text) writes classic
// RFC 3164 lines. system.log and auth.log are read together, so the buffer is
// not in time order; the watermark sorts by device time, so the parser does
// not need to.
//
//	Oct 24 17:02:11 gw1 sshd[1234]: Accepted password for admin from 10.0.0.5 port 5555 ssh2
//	Oct 24 17:02:40 gw1 php-fpm[4567]: /index.php: Successful login for user 'admin' from: 10.0.0.5 (Local Database)
//
// Check Point Gaia writes /var/log/messages with the year after the time of
// day, which RFC 3164 does not allow and the shared splitter does not read:
//
//	Oct 24 17:02:11 2026 gw1 clish[1234]: cmd by admin: Start executing : set hostname gw1 (cmd md5: ...)
//
// The Gaia parser reads that form first and falls back to the shared
// splitter, so a release that omits the year still parses.
//
// Neither format has been checked against a live device from this code base:
// the samples in the tests follow the documented formats. If a platform
// version words a line differently the line is simply not classified, never
// misparsed; "netlog collect --dry-run" and "netlog report" (classification
// coverage) show how much of a device's log is understood.
package parser

import (
	"regexp"
	"strconv"
	"time"

	"netlog/internal/collector"
	"netlog/internal/inventory"
)

// ---- pfSense ----------------------------------------------------------------

type pfsenseParser struct {
	key  string
	opts Options
}

// Parse implements Parser.
func (p *pfsenseParser) Parse(raw string, dev inventory.Device) []collector.LogEntry {
	lines := splitLines(raw)
	out := make([]collector.LogEntry, 0, len(lines))
	for _, line := range lines {
		sl, ok := parseSyslog(line, p.opts)
		if !ok {
			continue
		}
		e := newEntry(dev, p.key, line, sl.ts, guessFacility(sl.prog, sl.msg), sl.msg)
		attribute(&e, sl.msg)
		out = append(out, e)
	}
	return out
}

// ---- Check Point Gaia -------------------------------------------------------

type gaiaParser struct {
	key  string
	opts Options
}

// groups: 1 month, 2 day, 3 hms, 4 year, 5 host, 6 program, 7 pid, 8 message
var reGaiaStamp = regexp.MustCompile(`^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})\s+(\S+)\s+([^\s:\[\]]+)(?:\[(\d+)\])?:\s*(.*)$`)

// Parse implements Parser.
func (p *gaiaParser) Parse(raw string, dev inventory.Device) []collector.LogEntry {
	lines := splitLines(raw)
	out := make([]collector.LogEntry, 0, len(lines))
	for _, line := range lines {
		ts, prog, msg, ok := p.split(line)
		if !ok {
			continue
		}
		e := newEntry(dev, p.key, line, ts, guessFacility(prog, msg), msg)
		attribute(&e, msg)
		out = append(out, e)
	}
	return out
}

// split decomposes one line into time, program and message.
func (p *gaiaParser) split(line string) (ts time.Time, prog, msg string, ok bool) {
	if m := reGaiaStamp.FindStringSubmatch(line); m != nil {
		mon, good := parseMonth(m[1])
		if !good {
			return time.Time{}, "", "", false
		}
		day, _ := strconv.Atoi(m[2])
		year, _ := strconv.Atoi(m[4])
		ts, good = buildTime(year, mon, day, m[3], p.opts.loc())
		if !good {
			return time.Time{}, "", "", false
		}
		return ts, m[6], m[8], true
	}
	if sl, good := parseSyslog(line, p.opts); good {
		return sl.ts, sl.prog, sl.msg, true
	}
	return time.Time{}, "", "", false
}
