// ==============================================================================
// Package parser: Palo Alto PAN-OS log parser.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-27
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
// Two input forms are understood:
//
//  1. Forwarded PAN-OS syslog (CSV, the default syslog format), which is what
//     "netlog listen" receives. The message is a BSD or ISO header followed by
//     the comma-separated record; the field order is fixed per log type:
//
//     Oct 27 10:15:02 pa-fw1 1,2026/10/27 10:15:01,001234567890,SYSTEM,general,0,2026/10/27 10:15:01,vsys1,general,,0,0,general,high,Login failed for user admin,123456,0x0,0,0,0,0,,pa-fw1
//     Oct 27 10:16:00 pa-fw1 1,2026/10/27 10:15:59,001234567890,CONFIG,0,0,2026/10/27 10:15:59,10.1.1.5,vsys1,set,admin,Web,Succeeded, /config/shared,,,123457,0x0,0,0,0,0,,pa-fw1
//
//     TRAFFIC and THREAT records are recognised too (source -> destination,
//     application, rule, action, threat name and severity are put into the
//     summary). Receive/Generate times carry no zone and are read in the
//     parser's Location, like every other zone-less platform.
//
//  2. The "show log system" form the collector reads over SSH, which is
//     handled by the generic parser ("2026/10/20 09:30:15 high general
//     general 0 message").
//
// Field positions follow the documented PAN-OS 9/10 syslog field tables for
// each log type. They are bounds-checked and a record too short for its type
// still yields an entry (type and subtype in the summary), never a panic. The
// layouts have not been verified against a live firewall from this code base;
// a PAN-OS release that inserts fields shifts the optional details, never the
// header fields (receive time, type, generate time) that decide the entry's
// time and kind.
package parser

import (
	"encoding/csv"
	"regexp"
	"strings"
	"time"

	"netlog/internal/collector"
	"netlog/internal/inventory"
)

type paloaltoParser struct {
	key     string
	opts    Options
	generic *genericParser
}

func newPaloAltoParser(key string, opts Options) *paloaltoParser {
	return &paloaltoParser{key: key, opts: opts, generic: newGenericParser(key, opts)}
}

// reSyslogHeader strips an RFC 3164 or ISO 8601 header ("Oct 27 10:15:02 host "
// / "2026-10-27T10:15:02+07:00 host ") in front of the CSV record.
var reSyslogHeader = regexp.MustCompile(`^(?:[A-Za-z]{3}\s+\d{1,2}\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2}(?:\.\d+)?|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+\S+\s+`)

// panTypes are the record types the parser recognises.
var panTypes = map[string]bool{
	"TRAFFIC": true, "THREAT": true, "SYSTEM": true, "CONFIG": true,
	"URL": true, "DATA": true, "WILDFIRE": true, "TUNNEL": true, "AUTHENTICATION": true,
	"USERID": true, "GLOBALPROTECT": true, "HIP-MATCH": true, "DECRYPTION": true, "CORRELATION": true,
	"SCTP": true, "IPTAG": true,
}

const panTimeLayout = "2006/01/02 15:04:05"

// Parse implements Parser.
func (p *paloaltoParser) Parse(raw string, dev inventory.Device) []collector.LogEntry {
	lines := splitLines(raw)
	out := make([]collector.LogEntry, 0, len(lines))
	for _, line := range lines {
		if e, ok := p.parseCSV(line, dev); ok {
			out = append(out, e)
			continue
		}
		// Not a CSV record: the "show log system" form and plain syslog.
		out = append(out, p.generic.Parse(line, dev)...)
	}
	return out
}

// field returns rec[i] trimmed, or "" if the record is too short.
func field(rec []string, i int) string {
	if i < 0 || i >= len(rec) {
		return ""
	}
	return strings.TrimSpace(rec[i])
}

func (p *paloaltoParser) parseCSV(line string, dev inventory.Device) (collector.LogEntry, bool) {
	body := line
	if loc := reSyslogHeader.FindStringIndex(body); loc != nil {
		body = body[loc[1]:]
	}
	// A record has far more than seven commas; this keeps the CSV reader off
	// every ordinary syslog line.
	if strings.Count(body, ",") < 7 {
		return collector.LogEntry{}, false
	}
	r := csv.NewReader(strings.NewReader(body))
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	rec, err := r.Read()
	if err != nil || len(rec) < 7 {
		return collector.LogEntry{}, false
	}
	// rec[0] is the FUTURE_USE / domain field (normally "1" or empty).
	typ := strings.ToUpper(field(rec, 3))
	if !panTypes[typ] {
		return collector.LogEntry{}, false
	}
	ts, ok := p.recordTime(rec)
	if !ok {
		return collector.LogEntry{}, false
	}
	sub := field(rec, 4)

	var facility string
	summary, user, src := typ+" "+sub, "", ""
	switch typ {
	case "SYSTEM":
		// 8 event id, 9 object, 12 module, 13 severity, 14 description
		desc := field(rec, 14)
		if desc == "" {
			desc = typ + " " + field(rec, 8)
		}
		summary = desc
		facility = guessFacility("", desc)
		if m := strings.ToLower(field(rec, 12)); m != "" && facility == "SYS" && m != "general" {
			facility = strings.ToUpper(m)
		}
	case "CONFIG":
		// 7 host, 9 command, 10 admin, 11 client, 12 result, 13 path
		user = field(rec, 10)
		src = validIP(field(rec, 7))
		summary = strings.TrimSpace(strings.Join(nonEmpty(user, field(rec, 9), field(rec, 13), "("+field(rec, 12)+")"), " "))
		facility = "CFG"
	case "TRAFFIC":
		// 7 src, 8 dst, 11 rule, 14 application, 30 action
		summary = strings.TrimSpace(strings.Join(nonEmpty(field(rec, 7), "->", field(rec, 8), field(rec, 14), "rule", field(rec, 11), field(rec, 30)), " "))
		facility = "TRAFFIC"
	case "THREAT":
		// 7 src, 8 dst, 30 action, 32 threat name, 34 severity
		summary = strings.TrimSpace(strings.Join(nonEmpty(field(rec, 32), field(rec, 7), "->", field(rec, 8), field(rec, 30), field(rec, 34)), " "))
		facility = "THREAT"
	default:
		facility = typ
	}
	summary = strings.TrimSpace(summary)
	if summary == "" {
		summary = typ
	}

	e := newEntry(dev, p.key, line, ts, facility, summary)
	attribute(&e, summary)
	if user != "" {
		e.User = user
	}
	if src != "" && e.SourceIP == "" {
		e.SourceIP = src
	}
	return e, true
}

// nonEmpty drops the empty elements ("()" included) so summaries have no gaps.
func nonEmpty(parts ...string) []string {
	out := parts[:0:0]
	for _, s := range parts {
		if s != "" && s != "()" {
			out = append(out, s)
		}
	}
	return out
}

// recordTime reads the Generate Time (field 6), falling back to Receive Time
// (field 1).
func (p *paloaltoParser) recordTime(rec []string) (time.Time, bool) {
	for _, i := range []int{6, 1} {
		if t, err := time.ParseInLocation(panTimeLayout, field(rec, i), p.opts.loc()); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
