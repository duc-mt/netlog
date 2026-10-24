// ==============================================================================
// Package parser: Fortinet FortiGate (FortiOS) log parser.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
// FortiOS logs are key=value records. "execute log display" through a PTY
// returns them mixed with the echoed commands, the prompt and a page header,
// which are skipped because they contain no date=/time= pair:
//
//	1: date=2026-10-20 time=09:30:15 eventtime=... tz="+0700" logid="0100032001" type="event" subtype="system" level="alert" logdesc="Admin login failed" user="test" ui="ssh(10.1.1.9)" msg="Administrator test login failed from ssh(10.1.1.9) ..."
//
// The leading "N:" index is relative to the displayed page and changes from
// poll to poll, so it is stripped before the line becomes Raw (and hence
// before the dedup ID is computed).
package parser

import (
	"regexp"
	"strconv"
	"strings"

	"netlog/internal/collector"
	"netlog/internal/inventory"
)

type fortigateParser struct {
	key  string
	opts Options
}

var (
	reFortiIndex = regexp.MustCompile(`^\d+:\s+`)
	reFortiKV    = regexp.MustCompile(`(\w+)=("([^"]*)"|\S+)`)
	reFortiUI    = regexp.MustCompile(`^(\w+)\(([^)]*)\)`)
	reFortiDate  = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})$`)
)

// fortiFacility maps a log subtype to the shared facility vocabulary.
func fortiFacility(subtype string) string {
	switch strings.ToLower(subtype) {
	case "system", "":
		return "SYS"
	case "user":
		return "SEC"
	case "router":
		return "ROUTER"
	case "ha":
		return "HA"
	case "vpn":
		return "VPN"
	case "wireless":
		return "WIFI"
	}
	return strings.ToUpper(subtype)
}

// Parse implements Parser.
func (p *fortigateParser) Parse(raw string, dev inventory.Device) []collector.LogEntry {
	lines := splitLines(raw)
	out := make([]collector.LogEntry, 0, len(lines))
	for _, line := range lines {
		line = reFortiIndex.ReplaceAllString(line, "")
		if !strings.Contains(line, "date=") || !strings.Contains(line, "time=") {
			continue
		}

		kv := make(map[string]string, 16)
		for _, m := range reFortiKV.FindAllStringSubmatch(line, -1) {
			v := m[2]
			if m[3] != "" || strings.HasPrefix(v, `"`) {
				v = m[3]
			}
			if _, dup := kv[m[1]]; !dup {
				kv[m[1]] = v
			}
		}

		d := reFortiDate.FindStringSubmatch(kv["date"])
		if d == nil {
			continue
		}
		y, _ := strconv.Atoi(d[1])
		mo, _ := strconv.Atoi(d[2])
		day, _ := strconv.Atoi(d[3])
		loc := p.opts.loc()
		if tz := kv["tz"]; tz != "" {
			if z, ok := zoneFromOffset(tz); ok {
				loc = z
			}
		}
		ts, ok := buildTime(y, timeMonth(mo), day, kv["time"], loc)
		if !ok {
			continue
		}

		summary := kv["msg"]
		if summary == "" {
			summary = kv["logdesc"]
		}
		e := newEntry(dev, p.key, line, ts, fortiFacility(kv["subtype"]), summary)
		e.User = strings.TrimSpace(kv["user"])
		if ui := reFortiUI.FindStringSubmatch(kv["ui"]); ui != nil {
			e.SessionID = ui[1]
			e.SourceIP = validIP(ui[2])
		}
		if e.SourceIP == "" {
			e.SourceIP = validIP(kv["srcip"])
		}
		if e.User == "" {
			attribute(&e, summary)
		}
		out = append(out, e)
	}
	return out
}
