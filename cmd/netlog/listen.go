// ==============================================================================
// Package main: "netlog listen" (passive syslog receiver).
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-27
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         netlog listen [--port 514] [--proto udp,tcp] [--data-dir data]
// Notes:         Go package implementation
// ==============================================================================
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"netlog/internal/collector"
	"netlog/internal/inventory"
	"netlog/internal/listener"
	"netlog/internal/pipeline"
	"netlog/internal/query"
	"netlog/internal/store"
)

// listenSettings is the validated form of the listen flags.
type listenSettings struct {
	udpAddr, tcpAddr string // "" = that protocol is off
}

// resolveListenAddrs combines --bind, --port, --proto, --udp-port and
// --tcp-port: --proto picks the protocols, --port is their port, and
// --udp-port / --tcp-port override it for one protocol.
func resolveListenAddrs(bind string, port int, proto string, udpPort, tcpPort int) (listenSettings, error) {
	var ls listenSettings
	for _, p := range strings.Split(strings.ToLower(proto), ",") {
		switch strings.TrimSpace(p) {
		case "udp":
			ls.udpAddr = "x"
		case "tcp":
			ls.tcpAddr = "x"
		case "":
		default:
			return ls, fmt.Errorf("--proto: unknown protocol %q (use udp, tcp or udp,tcp)", p)
		}
	}
	if ls.udpAddr == "" && ls.tcpAddr == "" {
		return ls, errors.New("--proto: nothing to listen on (use udp, tcp or udp,tcp)")
	}
	addr := func(name string, override int) (string, error) {
		p := port
		if override != 0 {
			p = override
		}
		if p < 1 || p > 65535 {
			return "", fmt.Errorf("%s: %d is not a valid port (1-65535)", name, p)
		}
		return net.JoinHostPort(bind, strconv.Itoa(p)), nil
	}
	var err error
	if ls.udpAddr != "" {
		if ls.udpAddr, err = addr("--udp-port", udpPort); err != nil {
			return ls, err
		}
	}
	if ls.tcpAddr != "" {
		if ls.tcpAddr, err = addr("--tcp-port", tcpPort); err != nil {
			return ls, err
		}
	}
	return ls, nil
}

func cmdListen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("netlog listen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `Usage: netlog listen [flags]

Receives syslog from the devices in the inventory (UDP and/or TCP, RFC 3164 and
RFC 5424, newline-delimited or octet-counted TCP), stores each message as a
normal netlog event in the daily JSONL files and runs the anomaly detector on
it, so "netlog query", "timeline", "report" and "top" see events the moment
they arrive. It is passive: it never connects to a device and never triages.
It can run next to "netlog monitor" on the same data directory.

Messages from addresses that are not in the inventory are dropped unless
--accept-unknown is given. Restart to pick up inventory changes.
`)
		fs.PrintDefaults()
	}
	var (
		inv       = fs.String("inventory", "inventory.csv", "path to the device inventory CSV (sender addresses are matched against it)")
		dataDir   = fs.String("data-dir", "data", "base directory for logs/ and state files")
		bind      = fs.String("bind", "", "address to listen on (default: all interfaces)")
		port      = fs.Int("port", 514, "port for every protocol selected by --proto")
		proto     = fs.String("proto", "udp,tcp", "protocols to listen on: udp, tcp or udp,tcp")
		udpPort   = fs.Int("udp-port", 0, "UDP port (overrides --port for UDP)")
		tcpPort   = fs.Int("tcp-port", 0, "TCP port (overrides --port for TCP)")
		acceptAny = fs.Bool("accept-unknown", false, "also store messages from addresses that are not in the inventory (vendor \"generic\")")
		dropUnk   = fs.Bool("drop-unclassified", false, "do not store messages the classifier could not recognise (keeps high-volume noise such as firewall traffic logs out of storage)")
		ahStart   = fs.Int("after-hours-start", envInt("NETLOG_AFTER_HOURS_START", pipeline.DefaultAfterHoursStart), "first hour (0-23) of the after-hours change window")
		ahEnd     = fs.Int("after-hours-end", envInt("NETLOG_AFTER_HOURS_END", pipeline.DefaultAfterHoursEnd), "first hour (0-23) after which changes are no longer after-hours")
		statEvery = fs.Duration("stats-interval", time.Minute, "how often to log receive statistics (0 = never)")
	)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "netlog listen: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	addrs, err := resolveListenAddrs(*bind, *port, *proto, *udpPort, *tcpPort)
	if err != nil {
		fmt.Fprintf(stderr, "netlog listen: %v\n", err)
		return exitUsage
	}

	log := &stderrLogger{w: stderr}
	devices, warns := inventory.Load(*inv)
	for _, w := range warns {
		log.Warn("inventory: %v", w)
	}
	if len(devices) == 0 && !*acceptAny {
		fmt.Fprintf(stderr, "netlog listen: inventory %q contains no devices, so every sender would be dropped (fix the inventory, run 'netlog init', or pass --accept-unknown)\n", *inv)
		return exitError
	}

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		fmt.Fprintf(stderr, "netlog listen: creating data directory: %v\n", err)
		return exitError
	}
	release, err := lockListener(*dataDir)
	if err != nil {
		if errors.Is(err, errAlreadyRunning) {
			err = fmt.Errorf("another 'netlog listen' is already using data directory %q", *dataDir)
		}
		fmt.Fprintf(stderr, "netlog listen: %v\n", err)
		return exitError
	}
	defer release()
	writer, err := store.NewJSONLWriter(*dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "netlog listen: %v\n", err)
		return exitError
	}
	defer writer.Close()

	// The detector is seeded from recent stored events, as in collect/monitor,
	// so flaps and login bursts that straddle a restart are still seen.
	det := pipeline.NewDetector(pipeline.DetectorConfig{})
	if recent, err := query.LoadTail(*dataDir, query.Filter{Since: time.Now().Add(-primeWindow)}, primeTailBytes); err != nil {
		log.Warn("priming anomaly detector from stored logs: %v", err)
	} else {
		det.Prime(recent)
	}

	// The sink runs on the listener's single worker goroutine, so the
	// detector needs no locking.
	sink := func(entries []collector.LogEntry) {
		if *dropUnk {
			kept := entries[:0:0]
			for _, e := range entries {
				if e.Event != pipeline.EventUnknown {
					kept = append(kept, e)
				}
			}
			entries = kept
		}
		if len(entries) == 0 {
			return
		}
		if err := writer.Append(entries); err != nil {
			log.Error("storing %d syslog entries: %v", len(entries), err)
			return
		}
		var derived []collector.LogEntry
		for _, e := range entries {
			for _, s := range det.Observe(e) {
				log.Info("%s: %s detected (%s): %s", e.Hostname, s.Entry.Event, s.Playbook, s.Entry.Summary)
				if s.Derived {
					derived = append(derived, s.Entry)
				}
			}
		}
		if err := writer.Append(derived); err != nil {
			log.Warn("storing derived events: %v", err)
		}
	}

	srv, err := listener.New(listener.Config{
		UDPAddr:       addrs.udpAddr,
		TCPAddr:       addrs.tcpAddr,
		Devices:       devices,
		AcceptUnknown: *acceptAny,
		Classifier: pipeline.NewClassifierWithOptions(pipeline.ClassifierOptions{
			Location: time.Local, AfterHoursStart: *ahStart, AfterHoursEnd: *ahEnd,
		}),
		Location: time.Local,
		Sink:     sink,
		Logger:   log,
	})
	if err != nil {
		fmt.Fprintf(stderr, "netlog listen: %v\n", err)
		return exitError
	}
	if err := srv.Start(); err != nil {
		fmt.Fprintf(stderr, "netlog listen: %v\n", err)
		return exitError
	}
	udpA, tcpA := srv.Addrs()
	var where []string
	if udpA != nil {
		where = append(where, "udp "+udpA.String())
	}
	if tcpA != nil {
		where = append(where, "tcp "+tcpA.String())
	}
	log.Info("listening on %s; %d device(s) in the inventory; storing to %s", strings.Join(where, ", "), len(devices), store.LogsDir(*dataDir))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var tick <-chan time.Time
	if *statEvery > 0 {
		t := time.NewTicker(*statEvery)
		defer t.Stop()
		tick = t.C
	}
	var last listener.Stats
	for running := true; running; {
		select {
		case <-ctx.Done():
			running = false
		case <-tick:
			s := srv.Stats()
			log.Info("syslog: %d received, %d stored, %d unknown-source, %d dropped (queue full) in the last %s",
				s.Received-last.Received, s.Stored-last.Stored, s.Unknown-last.Unknown, s.Dropped-last.Dropped, *statEvery)
			last = s
		}
	}
	log.Info("shutting down: closing listeners and flushing pending events")
	srv.Stop()
	s := srv.Stats()
	log.Info("stopped: %d received, %d stored, %d unknown-source, %d unparsed, %d dropped, %d truncated",
		s.Received, s.Stored, s.Unknown, s.Unparsed, s.Dropped, s.Truncated)
	return exitOK
}
