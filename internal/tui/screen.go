// ==============================================================================
// Package tui: screen buffer for the pure-Go ANSI dashboard.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-27
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
package tui

import "strings"

// ANSI styles (SGR parameters). The empty style is the terminal default.
const (
	styleNone   = ""
	styleBold   = "1"
	styleDim    = "2"
	styleRev    = "7"
	styleRed    = "31"
	styleGreen  = "32"
	styleYellow = "33"
	styleCyan   = "36"
	styleBoldRd = "1;31"
	styleRevRed = "7;31"
)

type cell struct {
	r     rune
	style string
}

// Screen is a W x H grid of single-width cells. Panes draw into it and clip
// at its edges; Lines serialises it to ANSI text and Text to plain text, so a
// layout can be checked without a terminal.
type Screen struct {
	W, H  int
	cells [][]cell
}

// NewScreen returns a blank screen.
func NewScreen(w, h int) *Screen {
	if w < 0 {
		w = 0
	}
	if h < 0 {
		h = 0
	}
	s := &Screen{W: w, H: h, cells: make([][]cell, h)}
	for y := range s.cells {
		row := make([]cell, w)
		for x := range row {
			row[x] = cell{r: ' '}
		}
		s.cells[y] = row
	}
	return s
}

// safeRune maps what must not reach a terminal or break column arithmetic
// (control characters, combining marks, double-width and astral characters,
// which this single-width grid cannot place) to '?'.
func safeRune(r rune) rune {
	switch {
	case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
		return '?'
	case r >= 0x0300 && r <= 0x036f, r == 0x200b, r == 0x200d, r == 0xfeff, r == 0xfffd:
		return '?'
	case r >= 0x1100 && r <= 0x115f, r >= 0x2e80 && r <= 0xa4cf, r >= 0xac00 && r <= 0xd7a3,
		r >= 0xf900 && r <= 0xfaff, r >= 0xfe30 && r <= 0xfe6f, r >= 0xff00 && r <= 0xff60,
		r >= 0xffe0 && r <= 0xffe6, r > 0xffff:
		return '?'
	}
	return r
}

// Put writes text at (x, y) in the given style, clipped to the screen.
func (s *Screen) Put(x, y int, text, style string) {
	if y < 0 || y >= s.H {
		return
	}
	for _, r := range text {
		if x >= s.W {
			return
		}
		if x >= 0 {
			s.cells[y][x] = cell{r: safeRune(r), style: style}
		}
		x++
	}
}

// PutClipped writes text at (x, y) but at most width cells, ending with '…' when it was cut.
func (s *Screen) PutClipped(x, y, width int, text, style string) {
	if width <= 0 {
		return
	}
	rs := []rune(text)
	if len(rs) > width {
		rs = append(rs[:width-1], '…')
	}
	s.Put(x, y, string(rs), style)
}

// Fill sets every cell of row y between x0 (inclusive) and x1 (exclusive).
func (s *Screen) Fill(y, x0, x1 int, r rune, style string) {
	if y < 0 || y >= s.H {
		return
	}
	for x := x0; x < x1 && x < s.W; x++ {
		if x >= 0 {
			s.cells[y][x] = cell{r: r, style: style}
		}
	}
}

// Text returns the screen as plain rows, trailing spaces trimmed.
func (s *Screen) Text() []string {
	out := make([]string, s.H)
	for y, row := range s.cells {
		var b strings.Builder
		for _, c := range row {
			b.WriteRune(c.r)
		}
		out[y] = strings.TrimRight(b.String(), " ")
	}
	return out
}

// Lines returns the screen as ANSI rows (no newlines). With color false the
// styles are dropped. Each row is exactly W cells wide.
func (s *Screen) Lines(color bool) []string {
	out := make([]string, s.H)
	for y, row := range s.cells {
		var b strings.Builder
		cur := styleNone
		for _, c := range row {
			if color && c.style != cur {
				b.WriteString("\x1b[0")
				if c.style != styleNone {
					b.WriteString(";" + c.style)
				}
				b.WriteString("m")
				cur = c.style
			}
			b.WriteRune(c.r)
		}
		if color && cur != styleNone {
			b.WriteString("\x1b[0m")
		}
		out[y] = b.String()
	}
	return out
}
