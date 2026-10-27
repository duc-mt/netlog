// ==============================================================================
// Package main: dry-run connectivity and clock-skew audit.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-23
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"netlog/internal/collector"
	"netlog/internal/credentials"
	"netlog/internal/inventory"
	"netlog/internal/pipeline"
	"netlog/internal/sshclient"
)

type dryResult struct {
	dev      inventory.Device
	vendor   string
	success  bool
	duration time.Duration
	skewMs   int64
	skewOK   bool
	bytes    int
	err      error
}

func runDryRun(ctx context.Context, o collectOpts, log *stderrLogger, stdout, stderr io.Writer) int {
	devices, warns := inventory.Load(o.inventory)
	for _, w := range warns {
		log.Warn("inventory: %v", w)
	}
	if len(devices) == 0 {
		log.Error("inventory %q contains no devices", o.inventory)
		if _, statErr := os.Stat(o.inventory); os.IsNotExist(statErr) || strings.Contains(o.inventory, "no such file") {
			fmt.Fprintf(stderr, "\nTip: Run 'netlog init' (or './run init') to create sample inventory.csv and .env templates.\n\n")
		}
		return exitError
	}

	if o.jumpHost != "" {
		os.Setenv(credentials.EnvJumpHost, o.jumpHost)
	}
	creds, err := credentials.NewStore(o.envFile)
	if err != nil {
		log.Error("loading credentials: %v", err)
		return exitError
	}

	hostKeys, err := hostKeyCallback(o, log)
	if err != nil {
		log.Error("%v", err)
		return exitError
	}
	sshOpts := sshclient.Options{
		ConnectTimeout:   o.connectTimeout,
		CommandTimeout:   o.commandTimeout,
		HostKeyCallback:  hostKeys,
		LegacyAlgorithms: o.legacyAlgorithms,
	}

	coll := collector.New(collector.Config{
		SSH:               sshOpts,
		CredStore:         creds,
		JumpEnabled:       o.jumpEnabled,
		JumpDefaultHost:   o.jumpHost,
		Concurrency:       o.concurrency,
		ClockParser:       pipeline.ParseDeviceClock,
		WarnOnSkewFailure: true,
		Logger:            log,
	})

	log.Info("dry-run: probing %d device(s) with concurrency %d...", len(devices), o.concurrency)
	began := time.Now()

	results := make([]dryResult, 0, len(devices))
	for res := range coll.Run(ctx, devices) {
		dr := dryResult{
			dev:      res.Device,
			vendor:   res.VendorKey,
			success:  res.Err == nil,
			duration: res.Duration,
			skewMs:   res.SkewMs,
			skewOK:   res.SkewOK,
			bytes:    len(res.Raw),
			err:      res.Err,
		}
		results = append(results, dr)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].dev.Hostname < results[j].dev.Hostname
	})

	useColor := colorEnabled(stdout, o.noColor)
	printDryRunTable(stdout, results, useColor)

	succeeded := 0
	for _, r := range results {
		if r.success {
			succeeded++
		}
	}

	log.Info("dry-run complete: %d/%d device(s) connected successfully in %s (0 logs written, 0 watermarks saved)",
		succeeded, len(devices), time.Since(began).Round(10*time.Millisecond))

	if succeeded == 0 {
		return exitError
	}
	return exitOK
}

func printDryRunTable(w io.Writer, results []dryResult, useColor bool) {
	if len(results) == 0 {
		return
	}

	wDev := len("DEVICE")
	wAddr := len("ADDRESS")
	wVend := len("VENDOR")

	for _, r := range results {
		if len(r.dev.Hostname) > wDev {
			wDev = len(r.dev.Hostname)
		}
		addr := r.dev.Address
		if r.dev.Port != 0 && r.dev.Port != 22 {
			addr = fmt.Sprintf("%s:%d", r.dev.Address, r.dev.Port)
		}
		if len(addr) > wAddr {
			wAddr = len(addr)
		}
		if len(r.vendor) > wVend {
			wVend = len(r.vendor)
		}
	}

	paint := func(code, s string) string {
		if !useColor || code == "" {
			return s
		}
		return code + s + "\x1b[0m"
	}

	header := fmt.Sprintf("%-*s  %-*s  %-*s  %-6s  %-8s  %-8s  %s",
		wDev, "DEVICE", wAddr, "ADDRESS", wVend, "VENDOR", "STATUS", "DURATION", "SKEW", "NOTES")
	fmt.Fprintln(w, paint("\x1b[1m", header))

	for _, r := range results {
		addr := r.dev.Address
		if r.dev.Port != 0 && r.dev.Port != 22 {
			addr = fmt.Sprintf("%s:%d", r.dev.Address, r.dev.Port)
		}

		status := "OK"
		statusCode := "\x1b[32m" // green
		notes := "Connected"
		if r.bytes > 0 {
			notes = fmt.Sprintf("Connected (buffer: %d bytes)", r.bytes)
		}
		if r.dev.JumpHost != "" {
			notes += " via " + r.dev.JumpHost
		}
		if !r.success {
			status = "FAIL"
			statusCode = "\x1b[31m" // red
			notes = r.err.Error()
		}

		skewStr := "-"
		if r.skewOK {
			skewStr = fmt.Sprintf("%+dms", r.skewMs)
		}

		durStr := r.duration.Round(time.Millisecond).String()

		row := fmt.Sprintf("%-*s  %-*s  %-*s  %-6s  %-8s  %-8s  %s",
			wDev, r.dev.Hostname,
			wAddr, addr,
			wVend, r.vendor,
			paint(statusCode, status),
			durStr,
			skewStr,
			notes,
		)
		fmt.Fprintln(w, row)
	}
	fmt.Fprintln(w)
}
