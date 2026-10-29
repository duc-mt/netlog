// ==============================================================================
// Package diagnose: terminal report renderer.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-26
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         diagnose.Render(os.Stdout, rep, diagnose.RenderOptions{Color: true})
// Notes:         Go package implementation
// ==============================================================================
package diagnose

import (
	"fmt"
	"io"
	"strings"
)

// RenderOptions controls Render.
type RenderOptions struct {
	Color bool // ANSI status badges
	Raw   bool // include verbatim device output under each section
}

func badge(status string, color bool) string {
	text := "[" + status + "]"
	if !color {
		return text
	}
	code := "32" // green
	switch status {
	case StatusWarn:
		code = "33"
	case StatusError:
		code = "31"
	case StatusUnknown:
		code = "90"
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func renderSection(w io.Writer, s Section, o RenderOptions) {
	fmt.Fprintf(w, "%s %s  (%s)\n", badge(s.Status, o.Color), s.Name, s.Command)
	for _, n := range s.Notes {
		fmt.Fprintf(w, "      - %s\n", n)
	}
	if s.Error != "" {
		fmt.Fprintf(w, "      - error: %s\n", s.Error)
	}
	if o.Raw && strings.TrimSpace(s.Output) != "" {
		for _, line := range strings.Split(strings.TrimRight(s.Output, "\r\n"), "\n") {
			fmt.Fprintf(w, "      | %s\n", strings.TrimRight(line, "\r"))
		}
	}
}

// Render writes a human-readable report.
func Render(w io.Writer, r Report, o RenderOptions) {
	fmt.Fprintf(w, "netlog diagnose: %s (%s:%d, %s)\n", r.Device.Hostname, r.Device.Address, r.Device.Port, r.VendorKey)
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 60))

	// The probe needs no SSH session, so it is shown first and also when
	// the connection fails.
	if r.ProbeSection != nil {
		renderSection(w, *r.ProbeSection, o)
	}

	if r.Connected {
		fmt.Fprintf(w, "%s SSH connect + auth in %d ms\n", badge(StatusOK, o.Color), r.ConnectTime.Milliseconds())
	} else {
		fmt.Fprintf(w, "%s SSH: %s\n", badge(StatusError, o.Color), r.ConnectErr)
		return
	}

	for _, s := range r.Sections {
		renderSection(w, s, o)
	}
	if r.PoESection != nil {
		renderSection(w, *r.PoESection, o)
	}

	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 60))
	if r.Healthy() {
		fmt.Fprintln(w, "Result: HEALTHY")
	} else {
		fmt.Fprintln(w, "Result: ATTENTION NEEDED (re-run with --raw for device output)")
	}
}
