// ==============================================================================
// Package report: NetOps-style Unicode box-drawing table renderer with cell wrapping.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-28
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package report

import (
	"io"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"

	"netlog/internal/query"
)

// Column describes one table column for box tables.
type Column struct {
	Title string
	Limit int  // max allowed width for values before wrapping (0 = natural)
	Right bool // right-align, for numbers
}

// terminalWidth inspects w and returns visible terminal columns, or 0 if
// w is not a terminal or size cannot be determined.
func terminalWidth(w io.Writer) int {
	type fder interface {
		Fd() uintptr
	}
	if f, ok := w.(fder); ok {
		fd := int(f.Fd())
		if term.IsTerminal(fd) {
			if width, _, err := term.GetSize(fd); err == nil && width > 0 {
				return width
			}
		}
	}
	return 0
}

// padCell pads s to width w, counting runes.
func padCell(s string, width int, alignRight bool) string {
	n := utf8.RuneCountInString(s)
	if n >= width {
		return s
	}
	pad := strings.Repeat(" ", width-n)
	if alignRight {
		return pad + s
	}
	return s + pad
}

// padLeft left-pads s with spaces to width w, counting runes.
func padLeft(s string, w int) string {
	return padCell(s, w, true)
}

// writeBorder writes a horizontal Unicode rounded border line.
func writeBorder(p *printer, widths []int, left, mid, right string) {
	var b strings.Builder
	b.WriteString(left)
	for i, w := range widths {
		b.WriteString(strings.Repeat("─", w+2))
		if i < len(widths)-1 {
			b.WriteString(mid)
		}
	}
	b.WriteString(right)
	p.println(b.String())
}

// wrapCell breaks text into one or more lines of at most width runes.
// If text is empty or width <= 0, returns [""] or [text].
func wrapCell(text string, width int) []string {
	if width <= 0 {
		return []string{text}
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return []string{""}
	}
	if utf8.RuneCountInString(text) <= width {
		return []string{text}
	}

	rawLines := strings.Split(text, "\n")
	var result []string

	for _, rawLine := range rawLines {
		rawLine = strings.TrimSpace(rawLine)
		if rawLine == "" {
			continue
		}
		if utf8.RuneCountInString(rawLine) <= width {
			result = append(result, rawLine)
			continue
		}

		words := strings.Fields(rawLine)
		if len(words) == 0 {
			continue
		}

		var curLine strings.Builder
		curLen := 0

		for _, w := range words {
			wLen := utf8.RuneCountInString(w)
			if curLen == 0 {
				if wLen <= width {
					curLine.WriteString(w)
					curLen = wLen
				} else {
					runes := []rune(w)
					for len(runes) > width {
						result = append(result, string(runes[:width]))
						runes = runes[width:]
					}
					curLine.WriteString(string(runes))
					curLen = len(runes)
				}
			} else if curLen+1+wLen <= width {
				curLine.WriteByte(' ')
				curLine.WriteString(w)
				curLen += 1 + wLen
			} else {
				result = append(result, curLine.String())
				curLine.Reset()
				if wLen <= width {
					curLine.WriteString(w)
					curLen = wLen
				} else {
					runes := []rune(w)
					for len(runes) > width {
						result = append(result, string(runes[:width]))
						runes = runes[width:]
					}
					curLine.WriteString(string(runes))
					curLen = len(runes)
				}
			}
		}
		if curLine.Len() > 0 {
			result = append(result, curLine.String())
		}
	}

	if len(result) == 0 {
		return []string{""}
	}
	return result
}

// renderBoxTable renders columns and rows using NetOps-style Unicode rounded box borders.
// Any cell exceeding column width cleanly wraps across multiple lines inside its cell.
func renderBoxTable(p *printer, st query.Style, cols []Column, rows [][]string, paint func(row int, text string) string) {
	if len(cols) == 0 {
		return
	}

	// 1. Calculate natural widths based on header and cell contents.
	widths := make([]int, len(cols))
	for c, col := range cols {
		widths[c] = utf8.RuneCountInString(col.Title)
	}

	for _, row := range rows {
		for c, cell := range row {
			if c >= len(cols) {
				break
			}
			san := query.Sanitize(cell)
			n := utf8.RuneCountInString(san)
			if n > widths[c] {
				widths[c] = n
			}
		}
	}

	// Cap to col.Limit if specified and non-zero
	for c, col := range cols {
		if col.Limit > 0 && widths[c] > col.Limit {
			widths[c] = col.Limit
		}
	}

	// 2. Adjust for terminal width if stdout is an interactive terminal.
	if tw := terminalWidth(p.w); tw > 0 {
		// Total table width = 1 + sum(widths[c] + 3)
		totalWidth := 1
		for _, w := range widths {
			totalWidth += w + 3
		}

		if totalWidth > tw {
			// Find trailing or flexible column to shrink
			lastIdx := len(cols) - 1
			fixedWidth := 1
			for i := 0; i < lastIdx; i++ {
				fixedWidth += widths[i] + 3
			}
			fixedWidth += 3 // overhead for last column: " " + cell + " │"

			budget := tw - fixedWidth
			const minTrailingColWidth = 15
			if budget < minTrailingColWidth {
				budget = minTrailingColWidth
			}
			if budget < widths[lastIdx] {
				widths[lastIdx] = budget
			}
		}
	}

	// 3. Write top border
	writeBorder(p, widths, "╭", "┬", "╮")

	// 4. Write header
	var head strings.Builder
	head.WriteString("│")
	for i, col := range cols {
		text := padCell(col.Title, widths[i], col.Right)
		head.WriteString(" ")
		head.WriteString(st.Bold(text))
		head.WriteString(" │")
	}
	p.println(head.String())

	// 5. Write header separator
	writeBorder(p, widths, "├", "┼", "┤")

	// 6. Write rows with multi-line cell wrapping
	for rowIdx, row := range rows {
		cellLines := make([][]string, len(cols))
		maxLines := 1

		for c := range cols {
			var cellText string
			if c < len(row) {
				cellText = query.Sanitize(row[c])
			}
			lines := wrapCell(cellText, widths[c])
			cellLines[c] = lines
			if len(lines) > maxLines {
				maxLines = len(lines)
			}
		}

		for l := 0; l < maxLines; l++ {
			var rowBuf strings.Builder
			rowBuf.WriteString("│")

			for c, col := range cols {
				var subText string
				if l < len(cellLines[c]) {
					subText = cellLines[c][l]
				}
				padded := padCell(subText, widths[c], col.Right)
				if paint != nil {
					padded = paint(rowIdx, padded)
				}
				rowBuf.WriteString(" ")
				rowBuf.WriteString(padded)
				rowBuf.WriteString(" │")
			}
			p.println(rowBuf.String())
		}
	}

	// 7. Write bottom border
	writeBorder(p, widths, "╰", "┴", "╯")
}

// WriteBoxTable writes a standalone box-drawing table to w.
func WriteBoxTable(w io.Writer, st query.Style, cols []Column, rows [][]string, paint func(row int, text string) string) error {
	p := &printer{w: w}
	renderBoxTable(p, st, cols, rows, paint)
	return p.err
}
