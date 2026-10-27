// ==============================================================================
// Package pipeline: timestamp normalizer (Stage 2, clock-skew correction).
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         pipeline.Normalize(entries, res.SkewMs, res.SkewOK)
// Notes:         Go package implementation
// ==============================================================================
// Two jobs: apply a measured clock skew to a batch of entries, and parse the
// output of each vendor's "what time is it" command so the collector can
// measure that skew (ParseDeviceClock satisfies collector.ClockParser).
//
// Time-zone handling. Devices report time in two styles, and the clock
// parser must treat the clock output the same way the vendor's log lines
// are treated, otherwise the skew would not cancel:
//
//   - Vendors whose log lines carry an explicit offset (VyOS journald, Huawei
//     VRP, FortiGate): the clock output's zone is honoured, so the reading is
//     an absolute instant and the skew is the true clock error.
//   - Vendors whose log lines are zone-less (IOS, Junos, MikroTik, ...): the
//     clock output's wall-clock fields are read in the netlog host's zone
//     and any zone label is ignored. The skew then also absorbs any zone
//     difference between device and host, and correcting the (equally
//     zone-less, equally host-zone-interpreted) log timestamps by it lands
//     them on the right absolute instant.
//
// Both styles assume the device prints its clock and its log timestamps in
// the same zone. If they differ (Cisco IOS with "clock timezone" set but
// "service timestamps log datetime" lacking the "localtime" keyword logs in
// UTC while "show clock" shows local time) the corrected timestamps are off
// by the zone difference; make the two agree on the device, or set the host's
// TZ to the zone the logs use. The measured skew (skew_ms) of a zone-less
// vendor also contains the whole-hour offset between device and host zones
// when they differ, which is intentional and not a clock error.
package pipeline

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"netlog/internal/collector"
)

// Normalize sets Timestamp (UTC, skew-corrected) and SkewMs on every entry.
// skewMs is device clock minus server clock. When skewOK is false the skew
// is unknown and entries keep their device time unchanged (SkewMs 0).
func Normalize(entries []collector.LogEntry, skewMs int64, skewOK bool) {
	if !skewOK {
		skewMs = 0
	}
	adj := time.Duration(skewMs) * time.Millisecond
	for i := range entries {
		entries[i].SkewMs = skewMs
		entries[i].Timestamp = entries[i].DeviceTS.Add(-adj).UTC()
	}
}

// FutureTolerance is how far past the device's current time a log line may be
// dated before it is treated as corrupt (see DropFuture). With a measured
// skew the device's "now" is known to within seconds. Without one, vendors
// whose lines carry an explicit offset are still absolute, so an hour of
// slack covers an unsynchronised clock; for zone-less vendors the reading is
// in the device's zone but interpreted in the host's, which can legitimately
// differ by up to 14 hours.
func FutureTolerance(vendorKey string, skewKnown bool) time.Duration {
	switch {
	case skewKnown:
		return 10 * time.Minute
	case zoneHonoringVendors[vendorKey]:
		return time.Hour
	default:
		return 15 * time.Hour
	}
}

// ---- device clock parsing ---------------------------------------------------

// zoneHonoringVendors log with an explicit UTC offset; see the package doc.
var zoneHonoringVendors = map[string]bool{
	"vyos":       true,
	"huawei_vrp": true,
	"fortigate":  true,
}

var (
	reClockHMS    = regexp.MustCompile(`(\d{1,2}):(\d{2}):(\d{2})(?:\.(\d+))?`)
	reClockISO    = regexp.MustCompile(`(\d{4})[-/](\d{1,2})[-/](\d{1,2})`)
	reClockDayMon = regexp.MustCompile(`(?i)\b(\d{1,2})[\s/.-]+([a-z]{3})[a-z]*[\s/.,-]+(\d{4})\b`)
	reClockMonDay = regexp.MustCompile(`(?i)\b([a-z]{3})[a-z]*[\s/.,-]+(\d{1,2})(?:[\s/.,-]+(\d{4}))?\b`)
	reClockYear   = regexp.MustCompile(`\b((?:19|20)\d{2})\b`)
	reClockAMPM   = regexp.MustCompile(`(?i)^\s*(AM|PM)\b`)
	reClockZone   = regexp.MustCompile(`^\s*(?:(Z|UTC|GMT)\b|([+-]\d{2}(?::?\d{2})?)\b|(ICT)\b)`)
	reClockUTCOff = regexp.MustCompile(`(?i)\butc\s*([+-]\d{1,2})(?::?(\d{2}))?`)
)

var clockMonths = map[string]time.Month{
	"jan": time.January, "feb": time.February, "mar": time.March, "apr": time.April,
	"may": time.May, "jun": time.June, "jul": time.July, "aug": time.August,
	"sep": time.September, "oct": time.October, "nov": time.November, "dec": time.December,
}

// ParseDeviceClock extracts the current device time from the output of a
// vendor clock command. It is tolerant of layout: it looks for a
// time-of-day, a date in any of the common spellings, and an optional zone,
// rather than matching one format per vendor. ref is the server time at
// which the command ran; it supplies a missing date or year. Zone handling
// follows the vendor policy described in the package comment.
//
// It matches collector.ClockParser.
func ParseDeviceClock(vendorKey, output string, ref time.Time) (time.Time, error) {
	loc := ref.Location()

	// On FortiGate, "get system status" includes older database signature dates
	// (e.g. "Virus-DB: 91.02634(2018-04-09 10:20)") which would mislead generic
	// date parsers into thinking the device clock is years in the past.
	// If "System time:" is present, restrict parsing to that line.
	if vendorKey == "fortigate" {
		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "System time:") {
				output = line
				break
			}
		}
	}

	tm := reClockHMS.FindStringSubmatchIndex(output)
	if tm == nil {
		return time.Time{}, fmt.Errorf("no time of day found in clock output %q", abbreviate(output))
	}
	hour, _ := strconv.Atoi(output[tm[2]:tm[3]])
	minute, _ := strconv.Atoi(output[tm[4]:tm[5]])
	second, _ := strconv.Atoi(output[tm[6]:tm[7]])
	nsec := 0
	if tm[8] >= 0 {
		frac := output[tm[8]:tm[9]]
		if len(frac) > 9 {
			frac = frac[:9]
		}
		n, _ := strconv.Atoi(frac)
		for i := len(frac); i < 9; i++ {
			n *= 10
		}
		nsec = n
	}
	if hour > 23 || minute > 59 || second > 60 {
		return time.Time{}, fmt.Errorf("implausible time of day in clock output %q", abbreviate(output))
	}

	rest := output[tm[1]:]
	if m := reClockAMPM.FindStringSubmatchIndex(rest); m != nil {
		if strings.EqualFold(rest[m[2]:m[3]], "PM") && hour < 12 {
			hour += 12
		} else if strings.EqualFold(rest[m[2]:m[3]], "AM") && hour == 12 {
			hour = 0
		}
		rest = rest[m[1]:]
	}

	if zoneHonoringVendors[vendorKey] {
		if z, ok := clockZone(rest, output); ok {
			loc = z
		}
	}

	year, month, day, haveDate := findClockDate(output, ref.In(loc))
	t := time.Date(year, month, day, hour, minute, second, nsec, loc)
	if !haveDate {
		// Only a time of day was printed: pick the day that puts the reading
		// closest to the server clock (handles a device just past midnight).
		switch d := t.Sub(ref); {
		case d > 12*time.Hour:
			t = t.AddDate(0, 0, -1)
		case d < -12*time.Hour:
			t = t.AddDate(0, 0, 1)
		}
	}
	return t, nil
}

// clockZone resolves the zone for a reading: first a token directly after the
// time ("+07", "UTC"), then a "UTC+07:00" label anywhere in the output
// (Huawei prints the zone on its own line).
func clockZone(afterTime, whole string) (*time.Location, bool) {
	if m := reClockZone.FindStringSubmatch(afterTime); m != nil {
		switch {
		case m[1] != "":
			return time.UTC, true
		case m[2] != "":
			return offsetZone(m[2])
		case m[3] != "":
			return time.FixedZone("ICT", 7*3600), true
		}
	}
	if m := reClockUTCOff.FindStringSubmatch(whole); m != nil {
		h, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, false
		}
		mins := 0
		if m[2] != "" {
			mins, _ = strconv.Atoi(m[2])
		}
		secs := absInt(h)*3600 + mins*60
		if h < 0 || strings.HasPrefix(m[1], "-") {
			secs = -secs
		}
		return time.FixedZone(fmt.Sprintf("UTC%+03d", h), secs), true
	}
	return nil, false
}

func offsetZone(s string) (*time.Location, bool) {
	if len(s) == 0 {
		return nil, false
	}
	sign := 1
	if s[0] == '-' {
		sign = -1
	}
	digits := strings.ReplaceAll(s[1:], ":", "")
	if len(digits) < 2 {
		return nil, false
	}
	h, err := strconv.Atoi(digits[:2])
	if err != nil {
		return nil, false
	}
	mi := 0
	if len(digits) >= 4 {
		mi, _ = strconv.Atoi(digits[2:4])
	}
	return time.FixedZone(s, sign*(h*3600+mi*60)), true
}

// findClockDate looks for a calendar date in the output. ok is false when
// none is present, in which case ref's date is returned.
func findClockDate(output string, ref time.Time) (year int, month time.Month, day int, ok bool) {
	if m := reClockISO.FindStringSubmatch(output); m != nil {
		y, _ := strconv.Atoi(m[1])
		mo, _ := strconv.Atoi(m[2])
		d, _ := strconv.Atoi(m[3])
		if mo >= 1 && mo <= 12 && d >= 1 && d <= 31 {
			return y, time.Month(mo), d, true
		}
	}
	for _, m := range reClockDayMon.FindAllStringSubmatch(output, -1) {
		if mo, found := clockMonths[strings.ToLower(m[2])]; found {
			d, _ := strconv.Atoi(m[1])
			y, _ := strconv.Atoi(m[3])
			return y, mo, d, true
		}
	}
	for _, m := range reClockMonDay.FindAllStringSubmatch(output, -1) {
		mo, found := clockMonths[strings.ToLower(m[1])]
		if !found {
			continue
		}
		d, _ := strconv.Atoi(m[2])
		y := 0
		if m[3] != "" {
			y, _ = strconv.Atoi(m[3])
		} else if ym := reClockYear.FindStringSubmatch(output); ym != nil {
			y, _ = strconv.Atoi(ym[1]) // e.g. "Tue Oct 20 09:44:01 +07 2026"
		} else {
			y = ref.Year()
		}
		return y, mo, d, true
	}
	return ref.Year(), ref.Month(), ref.Day(), false
}

func abbreviate(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
