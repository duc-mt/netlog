// ==============================================================================
// Package triage: read-only command allowlist (GATE 1).
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         if err := triage.Check(cmd); err != nil { ...abort... }
// Notes:         Go package implementation
// ==============================================================================
// GATE 1 of the auto-triage safety design. Every diagnostic command must pass
// Check before an SSH session is even opened. The rules are compiled into the
// binary: there is no configuration file, flag or environment variable that
// can widen them.
//
// A command passes only if it clears the size and metacharacter checks AND
// either matches one of the anchored exact patterns below (exactAllowed) or
// satisfies ALL of the following generic rules:
//
//  1. It starts with one of: "show ", "display ", "/log print",
//     "cat /proc/net/", "execute log display", "get " (FortiOS read-only
//     status commands) (case-sensitive).
//  2. It contains none of the destructive words: conf, set, delete, clear,
//     write, reload, restart, copy, format, "debug ip packet" (case-
//     insensitive substring, deliberately blunt: "show running-config" and
//     anything with "reset" are refused too).
//  3. It contains no shell metacharacters or control characters, so a
//     command cannot be chained or redirected.
//  4. Any "|" is followed only by a recognised output filter (head, last,
//     include, exclude, begin, section, match, count, no-more) with at most
//     one plain-text argument.
//
// Rules 3 and 4 go beyond the minimum in the specification. They matter
// because the interface and peer names substituted into playbook commands
// are extracted from device log text, which is not trusted input.
//
// The exact patterns exist for read-only commands that the generic rules
// cannot express: configuration comparisons whose names contain the blunt
// word "config" ("show archive config differences ..."), RouterOS "print"
// commands, and Linux commands such as "ip -s link show". Each pattern is
// anchored with ^...$ and spells the whole command out, so a pattern can only
// ever admit the command it names (plus, where a pattern has a variable part,
// a strictly bounded interface token). The size limit and the metacharacter
// check still apply to them first; they contain no pipe.
package triage

import (
	"fmt"
	"regexp"
	"strings"
)

// maxCommandLen bounds a single command; real diagnostics are far shorter.
const maxCommandLen = 200

var (
	allowedPrefix = regexp.MustCompile(`^(show |display |get |/log print|/tool sniffer quick|cat /proc/net/|execute log display|diagnose sniffer packet |tcpdump -c \d{1,2} |monitor traffic (?:interface \S+ )?count \d{1,2} no-resolve)`)

	// Anything that could chain, redirect, substitute or break out of the line.
	// Note: ' (single quote) is permitted only for sniffer filter string if no metachars are inside.
	metaChars = regexp.MustCompile("[;&`$<>\\\\!{}\\x00-\\x1f\\x7f]")

	// One pipe stage: a known filter plus at most one plain argument.
	pipeStage = regexp.MustCompile(`^(?:head|last|include|exclude|begin|section|match|count|no-more)(?: [A-Za-z0-9_./:%-]+)?$`)
)

// exactAllowed lists the read-only commands admitted by an anchored exact
// pattern instead of the generic prefix rules. Keep the groups together and
// add a command here only together with the playbook, topology, diff or PoE
// table entry that uses it; TestNewCommandsMatchExactAllowlist ties the two
// together.
var exactAllowed = []*regexp.Regexp{
	// Configuration diff capture (comparison output only, nothing is saved).
	regexp.MustCompile(`^show archive config differences nvram:startup-config system:running-config$`), // Cisco IOS / IOS-XE
	regexp.MustCompile(`^show system rollback compare 0 1$`),                                           // Junos
	regexp.MustCompile(`^show diff rollback-patch$`),                                                   // Arista EOS
	regexp.MustCompile(`^display configuration changes system-committed$`),                             // Huawei VRP

	// Topology discovery (CDP / LLDP neighbour tables).
	regexp.MustCompile(`^show cdp neighbors detail$`),                 // Cisco
	regexp.MustCompile(`^show lldp neighbors detail$`),                // Cisco, Arista
	regexp.MustCompile(`^show lldp info remote-device$`),              // Aruba AOS-S
	regexp.MustCompile(`^display lldp neighbor-information verbose$`), // Huawei VRP

	// PoE budget and per-port power state.
	regexp.MustCompile(`^show power inline$`),        // Cisco
	regexp.MustCompile(`^show power-over-ethernet$`), // Aruba
	regexp.MustCompile(`^display poe power-state$`),  // Huawei VRP

	// Palo Alto PAN-OS operational commands.
	regexp.MustCompile(`^show system info$`),
	regexp.MustCompile(`^show routing route$`),
	regexp.MustCompile(`^show interface all$`),

	// Cumulus Linux. The interface token is bounded to the characters
	// pipeline.ExtractInterface can produce ("/ . : _ -", letters, digits)
	// and must start with a letter.
	regexp.MustCompile(`^ip -s link show(?: dev [A-Za-z][A-Za-z0-9._:/-]{0,30})?$`),
	regexp.MustCompile(`^vtysh -c 'show ip bgp summary'$`),

	// MikroTik RouterOS ("print" never changes anything).
	regexp.MustCompile(`^/system resource print$`),
	regexp.MustCompile(`^/interface print stats$`),
}

// matchesExact reports whether cmd matches one of the anchored exact patterns.
func matchesExact(cmd string) bool {
	for _, re := range exactAllowed {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

// deniedWords are refused anywhere in a command, case-insensitively.
var deniedWords = []string{
	"conf", "set", "delete", "clear", "write", "reload", "restart", "copy", "format", "debug ip packet",
}

// allowedSafeDiffCommands are strictly read-only configuration diff inspection
// commands that are permitted despite containing the substring "conf".
var allowedSafeDiffCommands = map[string]struct{}{
	"show system commit diff 0":                   {},
	"show system rollback compare 0 1":            {},
	"show configuration commit changes last 1":    {},
	"display configuration commit changes last 1": {},
	"show archive log config all":                 {},
	"show configuration diffs":                    {},
	"show session-config diff":                    {},
}

// Check reports why cmd may not be executed, or nil if it passes GATE 1.
// The error text is for logging only; callers abort triage on any non-nil
// result and do not retry.
func Check(cmd string) error {
	switch {
	case cmd == "":
		return fmt.Errorf("empty command")
	case len(cmd) > maxCommandLen:
		return fmt.Errorf("command longer than %d characters", maxCommandLen)
	case metaChars.MatchString(cmd):
		return fmt.Errorf("command %q contains shell metacharacters or control characters", cmd)
	case matchesExact(cmd):
		return nil
	case !allowedPrefix.MatchString(cmd):
		return fmt.Errorf("command %q does not start with an allowlisted read-only prefix", cmd)
	}

	lower := strings.ToLower(cmd)
	_, isSafeDiff := allowedSafeDiffCommands[lower]
	for _, w := range deniedWords {
		if w == "conf" && isSafeDiff {
			continue
		}
		if strings.Contains(lower, w) {
			return fmt.Errorf("command %q contains blocked word %q", cmd, w)
		}
	}

	if strings.Contains(cmd, "|") {
		stages := strings.Split(cmd, "|")
		for _, stage := range stages[1:] {
			if !pipeStage.MatchString(strings.TrimSpace(stage)) {
				return fmt.Errorf("command %q uses a pipe stage that is not an allowlisted output filter", cmd)
			}
		}
	}
	return nil
}

// Allowed reports whether cmd passes GATE 1.
func Allowed(cmd string) bool { return Check(cmd) == nil }
