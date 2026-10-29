// ==============================================================================
// Package diagnose: PoE budget and port power audit.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-27
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
// For campus switches the section reads the PoE summary the platform prints
// and flags the two things an operator needs to know first:
//
//   - a port that reports an overload or a fault, and
//   - a power budget used beyond PoEUsageWarnPercent (90%).
//
// Commands (read-only, registered in the GATE 1 exact list):
//
//	Cisco IOS / IOS-XE   show power inline
//	Aruba                show power-over-ethernet
//	Huawei VRP           display poe power-state
//
// No command is specified for Ruijie, so Ruijie gets no PoE section rather
// than a guessed command. The parsers follow the documented layouts of these
// commands; the budget lines in particular differ between releases, so when no
// budget can be read the section says that the 90% check was skipped instead
// of passing silently. They have not been checked against live switches.
package diagnose

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SecPoE is the PoE section name.
const SecPoE = "PoE power budget"

// PoEUsageWarnPercent is the budget usage above which the section warns.
const PoEUsageWarnPercent = 90.0

// poeCommands maps a canonical vendor key to its PoE command.
var poeCommands = map[string]string{
	"cisco_ios":  "show power inline",
	"aruba":      "show power-over-ethernet",
	"huawei_vrp": "display poe power-state",
}

// PoECommand returns the PoE command for a vendor key, or "" if there is none.
func PoECommand(vendorKey string) string { return poeCommands[vendorKey] }

// PoEBudget is one power budget read from the output.
type PoEBudget struct {
	Scope      string // "system", "module 2", ...
	AvailableW float64
	UsedW      float64
}

// Percent is the share of the budget in use (0 when the budget is unknown).
func (b PoEBudget) Percent() float64 {
	if b.AvailableW <= 0 {
		return 0
	}
	return 100 * b.UsedW / b.AvailableW
}

// PoEPort is a port flagged by the audit.
type PoEPort struct {
	Port   string
	Reason string // "overload" or "faulty"
}

// PoEFindings is the result of ParsePoE.
type PoEFindings struct {
	Budgets  []PoEBudget
	Flagged  []PoEPort
	Rejected bool // the device did not understand the command
}

var (
	rePoEReject = regexp.MustCompile(`(?i)invalid input|unrecognized command|unknown command|incorrect command|% ?incomplete|command not found|not supported`)

	// A port row starts with an interface-like token: "Gi1/0/2", "GE0/0/3",
	// "A12", "12" or "1/24". Header and summary lines do not.
	rePoEPortRow = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z-]*\d+(?:/\d+)*|[A-Za-z]{1,2}\d+|\d+(?:/\d+)+|\d+)\s`)
	rePoEBad     = regexp.MustCompile(`(?i)\b(overload(?:ed)?|ovld|over-?current|faulty|fault)\b`)

	// Cisco: "Available:740.0(w)  Used:123.4(w)  Remaining:616.6(w)" and the
	// per-module table "    1   370.0   129.0   241.0".
	rePoECiscoSys = regexp.MustCompile(`(?i)Available:\s*([\d.]+)\s*\(w\)\s+Used:\s*([\d.]+)\s*\(w\)`)
	rePoECiscoMod = regexp.MustCompile(`^\s*(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*$`)

	// Labelled totals (Aruba "Total Available Power : 382 W" and similar).
	rePoETotal = regexp.MustCompile(`(?i)\b(?:total\s+available|available|maximum|max|total)\s+(?:poe\s+)?power[^:=\n]*[:=]\s*([\d.]+)`)
	rePoEUsed  = regexp.MustCompile(`(?i)\b(?:total\s+used|used|consum\w*)\s+(?:poe\s+)?power[^:=\n]*[:=]\s*([\d.]+)|\bpower\s+(?:consum\w*|used)[^:=\n]*[:=]\s*([\d.]+)`)
)

// ParsePoE extracts the budgets and flagged ports from a PoE command's output.
func ParsePoE(out string) PoEFindings {
	var f PoEFindings
	if rePoEReject.MatchString(out) {
		f.Rejected = true
		return f
	}
	hasSys := false
	if m := rePoECiscoSys.FindStringSubmatch(out); m != nil {
		hasSys = true
		f.Budgets = append(f.Budgets, PoEBudget{Scope: "system", AvailableW: num(m[1]), UsedW: num(m[2])})
	}
	var total, used float64
	var haveTotal, haveUsed bool
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		// The per-module table is only read when there is no system summary line.
		if m := rePoECiscoMod.FindStringSubmatch(line); m != nil && !hasSys {
			f.Budgets = append(f.Budgets, PoEBudget{Scope: "module " + m[1], AvailableW: num(m[2]), UsedW: num(m[3])})
			continue
		}
		if m := rePoETotal.FindStringSubmatch(line); m != nil && !haveTotal {
			total, haveTotal = num(m[1]), true
		}
		if m := rePoEUsed.FindStringSubmatch(line); m != nil && !haveUsed {
			v := m[1]
			if v == "" {
				v = m[2]
			}
			used, haveUsed = num(v), true
		}
		if pm := rePoEPortRow.FindStringSubmatch(line); pm != nil {
			if bad := rePoEBad.FindStringSubmatch(line); bad != nil {
				reason := strings.ToLower(bad[1])
				if strings.HasPrefix(reason, "fault") {
					reason = "faulty"
				} else {
					reason = "overload"
				}
				f.Flagged = append(f.Flagged, PoEPort{Port: pm[1], Reason: reason})
			}
		}
	}
	if len(f.Budgets) == 0 && haveTotal && haveUsed {
		f.Budgets = append(f.Budgets, PoEBudget{Scope: "system", AvailableW: total, UsedW: used})
	}
	return f
}

func num(s string) float64 {
	v, _ := strconv.ParseFloat(strings.TrimRight(s, "."), 64)
	return v
}

// analysePoE turns the parsed output into the section's status, notes and metrics.
func analysePoE(s *Section) {
	if s.Status == "" {
		s.Status = StatusOK
	}
	if s.Metrics == nil {
		s.Metrics = map[string]float64{}
	}
	warn := func(msg string) {
		if s.Status != StatusError {
			s.Status = StatusWarn
		}
		s.Notes = append(s.Notes, msg)
	}
	f := ParsePoE(s.Output)
	if f.Rejected {
		s.Status = StatusUnknown
		s.Notes = append(s.Notes, "the device rejected the PoE command: PoE is not supported here, or the syntax differs on this release")
		return
	}

	if len(f.Flagged) > 0 {
		parts := make([]string, len(f.Flagged))
		for i, p := range f.Flagged {
			parts[i] = fmt.Sprintf("%s (%s)", p.Port, p.Reason)
		}
		warn(fmt.Sprintf("%d port(s) reporting overload or fault: %s", len(f.Flagged), strings.Join(parts, ", ")))
	}
	s.Metrics["poe_flagged_ports"] = float64(len(f.Flagged))

	if len(f.Budgets) == 0 {
		s.Notes = append(s.Notes, fmt.Sprintf("power budget not found in the output: the %.0f%% usage check was skipped", PoEUsageWarnPercent))
		return
	}
	for i, b := range f.Budgets {
		pct := b.Percent()
		if i == 0 || strings.HasPrefix(b.Scope, "module") {
			s.Metrics["poe_"+strings.ReplaceAll(b.Scope, " ", "_")+"_used_pct"] = pct
		}
		line := fmt.Sprintf("PoE budget (%s): %.1f of %.1f W in use (%.1f%%)", b.Scope, b.UsedW, b.AvailableW, pct)
		if pct > PoEUsageWarnPercent {
			warn(line + fmt.Sprintf(", above the %.0f%% threshold", PoEUsageWarnPercent))
		} else {
			s.Notes = append(s.Notes, line)
		}
	}
}
