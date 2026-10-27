// ==============================================================================
// Package query: exported rendering helpers shared with sibling packages.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-24
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         query.Pad(query.Clip(host, query.MaxDeviceCol), width)
// Notes:         Go package implementation
// ==============================================================================
// The table writers in this package (query, timeline, incidents) share a few
// small helpers: sanitize strips control characters from untrusted device
// text, clip caps a column, pad aligns it. Other packages that print tables
// ("netlog report") must use exactly these, not copies, so that every netlog
// table clips and neutralises device text the same way. This file exports
// them as thin delegating wrappers, which leaves every existing call site in
// the package untouched.
package query

import "time"

// Column caps shared by every netlog table.
const (
	MaxDeviceCol = maxDeviceCol
	MaxUserCol   = maxUserCol
)

// Sanitize replaces control characters in untrusted device text with "?".
// Every string that originated on a device must pass through it (or Clip,
// which calls it) before it is written to a terminal.
func Sanitize(s string) string { return sanitize(s) }

// Pad right-pads s with spaces to width w, counting runes.
func Pad(s string, w int) string { return pad(s, w) }

// Clip sanitizes s and truncates it to limit runes, ending in "…" if cut.
func Clip(s string, limit int) string { return clip(s, limit) }

// Dash returns "-" for an empty string and s otherwise.
func Dash(s string) string { return dash(s) }

// Widest returns the width of a column: the larger of its header and the
// longest value after clipping to limit.
func Widest(header string, vals []string, limit int) int { return widest(header, vals, limit) }

// Bold renders text in bold when colour is enabled.
func (s Style) Bold(text string) string { return s.paint(ansiBold, text) }

// Dim renders text dimmed when colour is enabled.
func (s Style) Dim(text string) string { return s.paint(ansiDim, text) }

// Green renders text green when colour is enabled.
func (s Style) Green(text string) string { return s.paint(ansiGreen, text) }

// Red renders text red when colour is enabled.
func (s Style) Red(text string) string { return s.paint(ansiRed, text) }

// Yellow renders text yellow when colour is enabled.
func (s Style) Yellow(text string) string { return s.paint(ansiYellow, text) }

// Loc returns the zone for displayed times (time.Local when unset).
func (s Style) Loc() *time.Location { return s.loc() }
