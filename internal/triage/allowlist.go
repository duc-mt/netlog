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
// A command passes only if ALL of the following hold:
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
package triage

import (
	"fmt"
	"regexp"
	"strings"
)

// maxCommandLen bounds a single command; real diagnostics are far shorter.
const maxCommandLen = 200

var (
	allowedPrefix = regexp.MustCompile(`^(show |display |get |/log print|cat /proc/net/|execute log display)`)

	// Anything that could chain, redirect, substitute or break out of the line.
	metaChars = regexp.MustCompile("[;&`$<>\\\\!{}\\x00-\\x1f\\x7f]")

	// One pipe stage: a known filter plus at most one plain argument.
	pipeStage = regexp.MustCompile(`^(?:head|last|include|exclude|begin|section|match|count|no-more)(?: [A-Za-z0-9_./:%-]+)?$`)
)

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
	case !allowedPrefix.MatchString(cmd):
		return fmt.Errorf("command %q does not start with an allowlisted read-only prefix", cmd)
	case metaChars.MatchString(cmd):
		return fmt.Errorf("command %q contains shell metacharacters or control characters", cmd)
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
