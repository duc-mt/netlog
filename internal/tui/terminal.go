// ==============================================================================
// Package tui: terminal control for the dashboard.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-27
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

// ErrNotTerminal is returned by Run when input or output is not a terminal.
var ErrNotTerminal = errors.New("netlog top needs an interactive terminal (stdin and stdout must both be a TTY)")

// Terminal escape sequences.
const (
	escEnterScreen = "\x1b[?1049h\x1b[?25l\x1b[2J" // alternate screen, hide cursor, clear
	escLeaveScreen = "\x1b[0m\x1b[?25h\x1b[?1049l" // reset style, show cursor, main screen
)

// RunOptions configures Run.
type RunOptions struct {
	Refresh time.Duration  // redraw and poll interval (default 1s, minimum 100ms)
	Color   bool           // use ANSI colours
	Window  time.Duration  // counter window (default 24h)
	Loc     *time.Location // zone for clock times
	Now     func() time.Time
}

// keyFilter drops escape sequences (arrow keys, function keys, mouse and
// paste reports) so that their trailing letters are never taken for commands.
type keyFilter struct{ state int }

const (
	kfNormal = iota
	kfEsc
	kfCSI
	kfSS3
)

// feed returns the byte to act on, or ok=false when it belongs to an escape
// sequence.
func (k *keyFilter) feed(b byte) (byte, bool) {
	switch k.state {
	case kfEsc:
		switch b {
		case '[':
			k.state = kfCSI
		case 'O':
			k.state = kfSS3
		default:
			k.state = kfNormal // ESC followed by a key: ignore both
		}
		return 0, false
	case kfCSI:
		if b >= 0x40 && b <= 0x7e { // final byte
			k.state = kfNormal
		}
		return 0, false
	case kfSS3:
		k.state = kfNormal
		return 0, false
	}
	if b == 0x1b {
		k.state = kfEsc
		return 0, false
	}
	return b, true
}

// Run shows the dashboard until the user quits (q, Ctrl+C), ctx is cancelled
// or the terminal goes away. The terminal is always put back: raw mode off,
// cursor shown, main screen restored, including on a panic.
func Run(ctx context.Context, in, out *os.File, src Source, o RunOptions) (err error) {
	inFd, outFd := int(in.Fd()), int(out.Fd())
	if !term.IsTerminal(inFd) || !term.IsTerminal(outFd) {
		return ErrNotTerminal
	}
	if o.Refresh <= 0 {
		o.Refresh = time.Second
	}
	if o.Refresh < 100*time.Millisecond {
		o.Refresh = 100 * time.Millisecond
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}

	old, err := term.MakeRaw(inFd)
	if err != nil {
		return fmt.Errorf("switching the terminal to raw mode: %w", err)
	}
	defer func() {
		_, _ = out.WriteString(escLeaveScreen)
		_ = term.Restore(inFd, old)
	}()
	if _, err := out.WriteString(escEnterScreen); err != nil {
		return err
	}

	m := NewModel(Options{Color: o.Color, Window: o.Window, Loc: o.Loc})

	keys := make(chan byte, 32)
	go func() { // ends with the process: a blocked terminal read cannot be cancelled
		defer close(keys)
		var kf keyFilter
		buf := make([]byte, 64)
		for {
			n, err := in.Read(buf)
			for _, b := range buf[:n] {
				if k, ok := kf.feed(b); ok {
					select {
					case keys <- k:
					case <-ctx.Done():
						return
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()

	var lastFrame string
	var lastW, lastH int
	draw := func() error {
		w, h, err := term.GetSize(outFd)
		if err != nil || w <= 0 || h <= 0 {
			w, h = 80, 24
		}
		scr := m.Render(w, h, now())
		var b strings.Builder
		if w != lastW || h != lastH {
			b.WriteString("\x1b[2J")
			lastFrame = ""
		}
		lastW, lastH = w, h
		for y, line := range scr.Lines(o.Color) {
			fmt.Fprintf(&b, "\x1b[%d;1H%s", y+1, line)
		}
		frame := b.String()
		if frame == lastFrame {
			return nil
		}
		lastFrame = frame
		_, err = out.WriteString(frame)
		return err
	}
	poll := func() {
		entries, devices, perr := src.Poll(now())
		m.Ingest(entries)
		if devices != nil {
			m.SetDevices(devices)
		}
		if perr != nil {
			m.SetStatus("data: " + perr.Error())
		} else {
			m.SetStatus("")
		}
	}

	poll()
	if err := draw(); err != nil {
		return err
	}
	tick := time.NewTicker(o.Refresh)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case k, ok := <-keys:
			if !ok { // input closed: the terminal is gone
				return nil
			}
			if m.HandleKey(k) {
				return nil
			}
			if err := draw(); err != nil {
				return err
			}
		case <-tick.C:
			poll()
			if err := draw(); err != nil {
				return err
			}
		}
	}
}
