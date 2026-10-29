// ==============================================================================
// Package parser turns raw device log output into normalized netlog records.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         parser.For(vendorKey, parser.Options{...}).Parse(raw, device)
// Notes:         Go package implementation
// ==============================================================================
// Package parser holds one Parser per platform family plus the dispatch that
// picks one from a canonical vendor key. A parser only does lexical work: it
// splits the raw buffer into lines, extracts the device timestamp, facility,
// summary and (when present) attribution fields, and returns LogEntry values.
// Classification (Category/Severity/Event) and clock-skew correction happen
// later in the pipeline package, so a parser never needs to know about either.
//
// Parsers are tolerant by design: a line that does not match the platform's
// format (banners, counters, prompts, wrapped continuation lines) is dropped
// silently, exactly as the Parser contract requires.
package parser

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"netlog/internal/collector"
	"netlog/internal/inventory"
)

// maxSummary bounds LogEntry.Summary so one pathological line cannot bloat
// the JSONL files. Raw is never truncated.
const maxSummary = 240

// Parser converts a block of raw log output into individual entries.
type Parser interface {
	// Parse returns only successfully parsed entries; malformed lines are
	// dropped silently. Entries are returned in the order they appear in raw.
	// Category, Severity and Event are left empty for the classifier, and
	// Timestamp is initialised to DeviceTS (UTC) until the normalizer applies
	// the clock-skew correction.
	Parse(raw string, device inventory.Device) []collector.LogEntry
}

// Options tunes how timestamps are interpreted.
type Options struct {
	// Ref is the server-side time the log buffer was fetched. It supplies the
	// year for syslog stamps that carry none. Zero means time.Now().
	Ref time.Time

	// Location is the zone used for timestamps that carry no zone of their
	// own (classic syslog, IOS, Junos, MikroTik). Nil means time.Local, i.e.
	// the netlog host is assumed to sit in the same zone as the devices;
	// any difference is absorbed by the clock-skew correction.
	Location *time.Location
}

func (o Options) ref() time.Time {
	if o.Ref.IsZero() {
		return time.Now()
	}
	return o.Ref
}

func (o Options) loc() *time.Location {
	if o.Location == nil {
		return time.Local
	}
	return o.Location
}

// For returns the parser for a canonical vendor key (see vendor.CanonicalKey).
// Unknown and unlisted vendors get the tolerant generic parser.
func For(vendorKey string, opts Options) Parser {
	var p Parser
	switch vendorKey {
	case "vyos":
		p = &vyosParser{key: vendorKey, opts: opts}
	case "cisco_ios", "cisco_asa", "cisco_sb":
		p = &ciscoParser{key: vendorKey, opts: opts}
	case "huawei_vrp":
		p = &huaweiParser{key: vendorKey, opts: opts}
	case "juniper_junos":
		p = &junosParser{key: vendorKey, opts: opts}
	case "fortigate":
		p = &fortigateParser{key: vendorKey, opts: opts}
	case "mikrotik":
		p = &mikrotikParser{key: vendorKey, opts: opts}
	case "cumulus":
		p = &cumulusParser{key: vendorKey, opts: opts}
	case "paloalto":
		p = newPaloAltoParser(vendorKey, opts)
	case "pfsense":
		p = &pfsenseParser{key: vendorKey, opts: opts}
	case "checkpoint_gaia":
		p = &gaiaParser{key: vendorKey, opts: opts}
	default:
		p = newGenericParser(vendorKey, opts)
	}
	return &checkedParser{inner: p, opts: opts}
}

// Plausibility limits for parsed timestamps.
const (
	// maxFutureParse is how far past the fetch time a line may be dated. It
	// is generous (zone mix-ups alone reach 14 hours) and exists only to
	// reject garbage such as a corrupted year: a single line dated far in
	// the future would otherwise drag the watermark ahead of reality and
	// hide every genuine later line until it scrolled out of the buffer.
	maxFutureParse = 48 * time.Hour

	// minPlausibleYear rejects epoch-zero and similar nonsense. Devices with
	// an unset clock (2000, 2001...) are still accepted: their timestamps
	// are wrong but stable, and the skew correction can repair them.
	minPlausibleYear = 1990
)

// checkedParser applies the plausibility limits to whatever the vendor
// parser returns, so no vendor parser can forget them.
type checkedParser struct {
	inner Parser
	opts  Options
}

// Parse implements Parser.
func (c *checkedParser) Parse(raw string, dev inventory.Device) []collector.LogEntry {
	entries := c.inner.Parse(raw, dev)
	latest := c.opts.ref().Add(maxFutureParse)
	kept := entries[:0]
	for _, e := range entries {
		if e.DeviceTS.Year() < minPlausibleYear || e.DeviceTS.After(latest) {
			continue
		}
		kept = append(kept, e)
	}
	return kept
}

// Parse is a convenience wrapper around For(...).Parse(...).
func Parse(vendorKey, raw string, device inventory.Device, opts Options) []collector.LogEntry {
	return For(vendorKey, opts).Parse(raw, device)
}

// ==============================================================================
// Shared helpers
// ==============================================================================

// splitLines splits raw on LF/CRLF, trims trailing whitespace and drops
// empty lines. Leading whitespace is preserved only where a parser needs it,
// so lines are trimmed on the left as well, which is what every supported
// platform's format expects.
func splitLines(raw string) []string {
	// A bare CR (terminal-style "overwrite this line") separates lines just
	// like LF, so Raw is always a single physical line; CRLF simply yields an
	// empty piece that is dropped below.
	parts := strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == '\r' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Invalid UTF-8 (e.g. a GBK-encoded Huawei message) is replaced up
		// front, so Raw, the dedup ID and the JSON written later all describe
		// the same text; json.Marshal would otherwise rewrite it silently.
		out = append(out, clampLine(strings.ToValidUTF8(p, "\uFFFD")))
	}
	return out
}

// maxLineLen bounds one log line. Real syslog lines are far shorter; the cap
// stops a misbehaving or hostile device from pushing megabyte "lines" into
// the regexes and the JSONL files. It is applied identically on every poll,
// so the truncated text (and hence the dedup ID) stays stable.
const maxLineLen = 8 * 1024

// clampLine truncates s to maxLineLen bytes on a rune boundary.
func clampLine(s string) string {
	if len(s) <= maxLineLen {
		return s
	}
	cut := maxLineLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// newEntry builds a LogEntry with the fields every parser fills identically.
func newEntry(dev inventory.Device, key, line string, ts time.Time, facility, summary string) collector.LogEntry {
	return collector.LogEntry{
		ID:        collector.EntryID(dev.Hostname, line),
		Timestamp: ts.UTC(),
		DeviceTS:  ts,
		Hostname:  dev.Hostname,
		IP:        dev.Address,
		Vendor:    key,
		Facility:  facility,
		Summary:   truncate(strings.TrimSpace(summary), maxSummary),
		Raw:       line,
	}
}

// truncate shortens s to at most n runes, marking the cut with an ellipsis.
func truncate(s string, n int) string {
	if n <= 0 || len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

var monthByAbbrev = map[string]time.Month{
	"jan": time.January, "feb": time.February, "mar": time.March,
	"apr": time.April, "may": time.May, "jun": time.June,
	"jul": time.July, "aug": time.August, "sep": time.September,
	"oct": time.October, "nov": time.November, "dec": time.December,
}

// parseMonth maps "Oct", "oct", "October" to time.October.
func parseMonth(s string) (time.Month, bool) {
	if len(s) < 3 {
		return 0, false
	}
	m, ok := monthByAbbrev[strings.ToLower(s[:3])]
	return m, ok
}

// timeMonth converts a 1-12 month number; anything else yields 0, which
// buildTime rejects (time.Date would otherwise wrap month 0 or 13 silently).
func timeMonth(m int) time.Month {
	if m < 1 || m > 12 {
		return 0
	}
	return time.Month(m)
}

// parseHMS parses "09:30:15" or "09:30:15.123".
func parseHMS(s string) (h, m, sec, nsec int, ok bool) {
	main, frac, hasFrac := strings.Cut(s, ".")
	parts := strings.Split(main, ":")
	if len(parts) != 3 {
		return 0, 0, 0, 0, false
	}
	var err error
	if h, err = strconv.Atoi(parts[0]); err != nil || h < 0 || h > 23 {
		return 0, 0, 0, 0, false
	}
	if m, err = strconv.Atoi(parts[1]); err != nil || m < 0 || m > 59 {
		return 0, 0, 0, 0, false
	}
	if sec, err = strconv.Atoi(parts[2]); err != nil || sec < 0 || sec > 60 {
		return 0, 0, 0, 0, false
	}
	if hasFrac && frac != "" {
		if len(frac) > 9 {
			frac = frac[:9]
		}
		n, err := strconv.Atoi(frac)
		if err != nil {
			return 0, 0, 0, 0, false
		}
		for i := len(frac); i < 9; i++ {
			n *= 10
		}
		nsec = n
	}
	return h, m, sec, nsec, true
}

// buildTime assembles a time from parsed fields in loc.
func buildTime(year int, mon time.Month, day int, hms string, loc *time.Location) (time.Time, bool) {
	h, m, s, ns, ok := parseHMS(hms)
	if !ok || day < 1 || day > 31 || mon < time.January || mon > time.December {
		return time.Time{}, false
	}
	return time.Date(year, mon, day, h, m, s, ns, loc), true
}

// buildYearless assembles a time from a stamp with no year, inferring the
// year from the fetch time: a stamp more than a day in the future must
// belong to the previous year (a December line read in January).
func buildYearless(mon time.Month, day int, hms string, o Options) (time.Time, bool) {
	ref := o.ref().In(o.loc())
	t, ok := buildTime(ref.Year(), mon, day, hms, o.loc())
	if !ok {
		return time.Time{}, false
	}
	if t.After(ref.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t, true
}

var reOffset = regexp.MustCompile(`^(?:(Z|z)|([+-])(\d{2})(?::?(\d{2}))?)$`)

// zoneFromOffset converts "Z", "+07", "+0700" or "+07:00" to a fixed zone.
func zoneFromOffset(s string) (*time.Location, bool) {
	m := reOffset.FindStringSubmatch(s)
	if m == nil {
		return nil, false
	}
	if m[1] != "" {
		return time.UTC, true
	}
	h, _ := strconv.Atoi(m[3])
	mi := 0
	if m[4] != "" {
		mi, _ = strconv.Atoi(m[4])
	}
	secs := h*3600 + mi*60
	if m[2] == "-" {
		secs = -secs
	}
	return time.FixedZone(s, secs), true
}

// syslogLine is the decomposition of an RFC 3164 / ISO 8601 syslog line.
type syslogLine struct {
	ts              time.Time
	host, prog, pid string
	msg             string
}

var (
	reSyslogISO  = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)(Z|[+-]\d{2}:?\d{2})?\s+(\S+)\s+([^\s:\[\]]+)(?:\[(\d+)\])?:\s*(.*)$`)
	reSyslog3164 = regexp.MustCompile(`^([A-Za-z]{3})\s+(\d{1,2})\s+(?:(\d{4})\s+)?(\d{2}:\d{2}:\d{2}(?:\.\d+)?)(?:\s+(\d{4}))?\s+(\S+)\s+([^\s:\[\]]+)(?:\[(\d+)\])?:\s*(.*)$`)
)

// parseSyslog parses ISO 8601 and classic syslog lines.
func parseSyslog(line string, o Options) (syslogLine, bool) {
	if m := reSyslogISO.FindStringSubmatch(line); m != nil {
		loc := o.loc()
		if m[5] != "" {
			if z, ok := zoneFromOffset(m[5]); ok {
				loc = z
			}
		}
		y, _ := strconv.Atoi(m[1])
		mo, _ := strconv.Atoi(m[2])
		d, _ := strconv.Atoi(m[3])
		ts, ok := buildTime(y, time.Month(mo), d, strings.Replace(m[4], ",", ".", 1), loc)
		if !ok {
			return syslogLine{}, false
		}
		return syslogLine{ts: ts, host: m[6], prog: m[7], pid: m[8], msg: m[9]}, true
	}
	if m := reSyslog3164.FindStringSubmatch(line); m != nil {
		mon, ok := parseMonth(m[1])
		if !ok {
			return syslogLine{}, false
		}
		day, _ := strconv.Atoi(m[2])
		var ts time.Time
		yearStr := m[3]
		if yearStr == "" {
			yearStr = m[5]
		}
		if yearStr != "" {
			y, _ := strconv.Atoi(yearStr)
			ts, ok = buildTime(y, mon, day, m[4], o.loc())
		} else {
			ts, ok = buildYearless(mon, day, m[4], o)
		}
		if !ok {
			return syslogLine{}, false
		}
		return syslogLine{ts: ts, host: m[6], prog: m[7], pid: m[8], msg: m[9]}, true
	}
	return syslogLine{}, false
}

// normalizeFacility folds platform mnemonics into the small facility
// vocabulary used across vendors.
func normalizeFacility(f string) string {
	f = strings.ToUpper(strings.TrimSpace(f))
	switch {
	case f == "":
		return "SYS"
	case f == "SPANTREE" || strings.HasPrefix(f, "STP") || f == "MSTP":
		return "STP"
	case strings.HasPrefix(f, "SEC") || f == "SSH" || f == "AAA" || f == "LOGIN":
		return "SEC"
	case f == "LINEPROTO" || f == "IFNET" || f == "ETHPORT" || f == "PORT":
		return "LINK"
	default:
		return f
	}
}

var (
	reFacOSPF = regexp.MustCompile(`(?i)ospf`)
	reFacBGP  = regexp.MustCompile(`(?i)\bbgp|bgpd`)
	reFacVRRP = regexp.MustCompile(`(?i)vrrp|keepalived`)
	reFacSTP  = regexp.MustCompile(`(?i)\bstp\b|spantree|spanning`)
	reFacLink = regexp.MustCompile(`(?i)\blink\b|carrier|link_?(?:up|down)|lineproto|line protocol`)
	reFacSec  = regexp.MustCompile(`(?i)login|auth|password|accepted|invalid user`)
)

// guessFacility derives a facility for syslog-style lines from the program
// name and message text.
func guessFacility(prog, msg string) string {
	p := strings.ToLower(prog)
	switch {
	case p == "sshd" || p == "login" || p == "sudo" || p == "su" || strings.HasPrefix(p, "pam") || p == "dropbear":
		return "SEC"
	case strings.Contains(p, "ospf"):
		return "OSPF"
	case strings.Contains(p, "bgp"):
		return "BGP"
	case strings.Contains(p, "vrrp") || strings.Contains(p, "keepalived"):
		return "VRRP"
	}
	switch {
	case reFacOSPF.MatchString(msg):
		return "OSPF"
	case reFacBGP.MatchString(msg):
		return "BGP"
	case reFacVRRP.MatchString(msg):
		return "VRRP"
	case reFacSTP.MatchString(msg):
		return "STP"
	case reFacLink.MatchString(msg):
		return "LINK"
	case reFacSec.MatchString(msg):
		return "SEC"
	}
	return "SYS"
}

// ---- attribution ------------------------------------------------------------

var (
	reUserBracket = regexp.MustCompile(`(?i)\[user:\s*([^\]\s]+)\]`)
	reSrcBracket  = regexp.MustCompile(`(?i)\[(?:source|src):\s*([0-9a-f:.]+)\]`)
	reByOn        = regexp.MustCompile(`\bby\s+(?:user\s+)?(\S+)\s+on\s+(\S+?)(?:\s+\(([0-9a-fA-F:.]+)\))?(?:\s|$)`)
	reSSHAuth     = regexp.MustCompile(`(?i)\b(?:accepted|failed)\s+\S+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+([0-9a-f:.]+)`)
	reQuotedUser  = regexp.MustCompile(`(?i)\buser\s+'([^']+)'`)
	reKVUser      = regexp.MustCompile(`(?i)\b(?:user|username)="?([^\s,)"]+)`)
	reUserWord    = regexp.MustCompile(`(?i)\buser\s+([A-Za-z0-9_.@-]+)\s+(?:logged|from|login)`)
	reKVIP        = regexp.MustCompile(`(?i)\b(?:ip|ipaddress|srcip)="?([0-9a-f:.]+)`)
	reKVTask      = regexp.MustCompile(`(?i)\b(?:task|session)=([^\s,)"]+)`)
	reFromIP      = regexp.MustCompile(`(?i)\bfrom:?\s+(\d{1,3}(?:\.\d{1,3}){3})\b`)
	reCfgUserAt   = regexp.MustCompile(`(?i)configuration chang(?:e|ed)[^:]*:\s*([^\s@:]+)@([0-9a-f:.]+)`)
	reCmdBy       = regexp.MustCompile(`(?i)\bcmd by ([A-Za-z0-9_.@-]+):`)
	reSudoUser    = regexp.MustCompile(`(?i)\b(?:config session )?sudo_user is ([A-Za-z0-9_.@-]+)`)
)

// validIP returns s if it parses as an IP address (after trimming trailing
// punctuation), else "".
func validIP(s string) string {
	s = strings.TrimRight(s, ".,;:)")
	if net.ParseIP(s) == nil {
		return ""
	}
	return s
}

// attribute fills User, SourceIP and SessionID from the message text using
// the formats the supported platforms emit. Fields already set are kept, and
// nothing is guessed: if no pattern matches the fields stay empty.
func attribute(e *collector.LogEntry, msg string) {
	setUser := func(u string) {
		// A quoted name ("user ' admin '") may carry padding; entries promise
		// a trimmed user, and a blank one is no user at all.
		if u = strings.TrimSpace(u); e.User == "" && u != "" {
			e.User = u
		}
	}
	setSrc := func(ip string) {
		if e.SourceIP == "" {
			e.SourceIP = validIP(ip)
		}
	}
	setSess := func(s string) {
		if e.SessionID == "" && s != "" {
			e.SessionID = s
		}
	}

	// Each regexp is only run if its literal anchor text is present. Almost
	// every log line matches none of them, and attribute runs on every line
	// of the whole buffer at every poll, so the cheap substring tests matter.
	low := strings.ToLower(msg)
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(low, s) {
				return true
			}
		}
		return false
	}

	if has("[user:") {
		if m := reUserBracket.FindStringSubmatch(msg); m != nil {
			setUser(m[1])
		}
	}
	if has("[source:", "[src:") {
		if m := reSrcBracket.FindStringSubmatch(msg); m != nil {
			setSrc(m[1])
		}
	}
	if has("by ") {
		if m := reByOn.FindStringSubmatch(msg); m != nil {
			setUser(m[1])
			setSess(m[2])
			setSrc(m[3])
		}
	}
	if has("accepted", "failed") {
		if m := reSSHAuth.FindStringSubmatch(msg); m != nil {
			setUser(m[1])
			setSrc(m[2])
		}
	}
	if has("user") {
		if m := reQuotedUser.FindStringSubmatch(msg); m != nil {
			setUser(m[1])
		}
		if m := reKVUser.FindStringSubmatch(msg); m != nil {
			setUser(m[1])
		}
		if m := reUserWord.FindStringSubmatch(msg); m != nil {
			setUser(m[1])
		}
	}
	if has("ip=", "ipaddress=", "srcip=") {
		if m := reKVIP.FindStringSubmatch(msg); m != nil {
			setSrc(m[1])
		}
	}
	if has("task=", "session=") {
		if m := reKVTask.FindStringSubmatch(msg); m != nil {
			setSess(m[1])
		}
	}
	if has("from") {
		if m := reFromIP.FindStringSubmatch(msg); m != nil {
			setSrc(m[1])
		}
	}
	if has("configuration chang") { // pfSense: "Configuration Change: admin@10.0.0.5 (Local Database): ..."
		if m := reCfgUserAt.FindStringSubmatch(msg); m != nil {
			setUser(m[1])
			setSrc(m[2])
		}
	}
	if has("cmd by") { // Check Point Gaia clish: "cmd by admin: Start executing : set ..."
		if m := reCmdBy.FindStringSubmatch(msg); m != nil {
			setUser(m[1])
		}
	}
	if has("sudo_user") { // VyOS vyos-configd: "config session sudo_user is langpx"
		if m := reSudoUser.FindStringSubmatch(msg); m != nil {
			setUser(m[1])
		}
	}
}
