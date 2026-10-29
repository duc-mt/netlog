// ==============================================================================
// Package main: "netlog top" and "netlog monitor --tui" (live dashboard).
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-27
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         netlog top [--data-dir data] [--refresh 1s]
// Notes:         Go package implementation
// ==============================================================================
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/term"

	"netlog/internal/inventory"
	"netlog/internal/store"
	"netlog/internal/tui"
)

// minRefresh is the fastest redraw rate the dashboard accepts.
const minRefresh = 100 * time.Millisecond

// isTTY reports whether f is an interactive terminal.
func isTTY(f *os.File) bool { return f != nil && term.IsTerminal(int(f.Fd())) }

func cmdTop(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("netlog top", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `Usage: netlog top [flags]

A live terminal dashboard over the stored data: a banner with the event counters
(FAULT, CONFIG, AUTH, SECURITY, SYSTEM; last 24h), devices monitored and
collection health; a scrolling event feed; unresolved outages and flapping
links; and the status of every device with its last poll time.

Keys:  q or Ctrl+C  quit     c  cycle the category filter     p  pause/resume the feed

It only reads data/, so it can run next to "netlog monitor", "collect" and
"netlog listen". Use "netlog monitor --tui" to poll and watch in one terminal.
`)
		fs.PrintDefaults()
	}
	var (
		dataDir     = fs.String("data-dir", "data", "base directory of logs/ and state files")
		refresh     = fs.Duration("refresh", time.Second, "redraw interval (minimum 100ms)")
		invPath     = fs.String("inventory", "inventory.csv", "inventory CSV, so devices that were never polled are listed too (optional)")
		staleAfter  = fs.Duration("stale-after", store.DefaultStaleAfter, "show a device as STALE when nothing has tried to poll it for this long")
		silentAfter = fs.Duration("silent-after", store.DefaultSilentAfter, "show a device as SILENT when it has produced no new log line for this long")
		noColor     = fs.Bool("no-color", false, "disable colours")
	)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "netlog top: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	if *refresh < minRefresh {
		fmt.Fprintf(stderr, "netlog top: --refresh must be at least %s\n", minRefresh)
		return exitUsage
	}
	if *staleAfter <= 0 || *silentAfter <= 0 {
		fmt.Fprintln(stderr, "netlog top: --stale-after and --silent-after must be positive")
		return exitUsage
	}
	out, ok := stdout.(*os.File)
	if !ok || !isTTY(os.Stdin) || !isTTY(out) {
		fmt.Fprintln(stderr, "netlog top: needs an interactive terminal (stdin and stdout must both be a TTY); use 'netlog status' or 'netlog query' in scripts")
		return exitError
	}

	var hosts []string
	if devices, _ := inventory.Load(*invPath); len(devices) > 0 {
		for _, d := range devices {
			hosts = append(hosts, d.Hostname)
		}
	}
	src := tui.NewFileSource(*dataDir, hosts, tui.SourceOptions{StaleAfter: *staleAfter, SilentAfter: *silentAfter})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := tui.Run(ctx, os.Stdin, out, src, tui.RunOptions{Refresh: *refresh, Color: colorEnabled(out, *noColor)}); err != nil {
		fmt.Fprintf(stderr, "netlog top: %v\n", err)
		return exitError
	}
	return exitOK
}

// runMonitorTUI is "netlog monitor --tui": the monitor loop runs in the
// background while the dashboard owns the terminal. Log lines go to a file
// because anything written to the terminal would corrupt the screen.
func runMonitorTUI(o collectOpts, stdout, stderr io.Writer) int {
	out, ok := stdout.(*os.File)
	if !ok || !isTTY(os.Stdin) || !isTTY(out) {
		fmt.Fprintln(stderr, "netlog monitor: --tui needs an interactive terminal (stdin and stdout must both be a TTY)")
		return exitError
	}
	if err := os.MkdirAll(o.dataDir, 0o700); err != nil {
		fmt.Fprintf(stderr, "netlog monitor: creating data directory: %v\n", err)
		return exitError
	}
	logPath := filepath.Join(o.dataDir, "monitor.log")
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "netlog monitor: opening %s: %v\n", logPath, err)
		return exitError
	}
	defer logFile.Close()
	log := &stderrLogger{w: logFile}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a, err := newApp(o, log)
	if err != nil {
		log.Error("%v", err)
		fmt.Fprintf(stderr, "netlog monitor: %v\n", err)
		return exitError
	}
	defer a.close()

	ctx, cancel := context.WithCancel(sigCtx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		a.monitorLoop(ctx, o, log)
	}()

	hosts := make([]string, len(a.devices))
	for i, d := range a.devices {
		hosts[i] = d.Hostname
	}
	src := tui.NewFileSource(o.dataDir, hosts, tui.SourceOptions{})
	runErr := tui.Run(ctx, os.Stdin, out, src, tui.RunOptions{Refresh: time.Second, Color: colorEnabled(out, o.noColor)})

	cancel()
	fmt.Fprintln(stderr, "netlog monitor: stopping (waiting for in-flight polls and triage)...")
	<-done
	if runErr != nil {
		fmt.Fprintf(stderr, "netlog monitor: %v\n", runErr)
		return exitError
	}
	fmt.Fprintf(stderr, "netlog monitor: stopped; log: %s\n", logPath)
	return exitOK
}
