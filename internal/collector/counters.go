// ==============================================================================
// Package collector: interface counters and rate delta models.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-28
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package collector

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// InterfaceCounter represents raw counter metrics for a single network interface at a point in time.
type InterfaceCounter struct {
	Timestamp   time.Time `json:"timestamp"`
	InOctets    uint64    `json:"in_octets"`
	OutOctets   uint64    `json:"out_octets"`
	InPackets   uint64    `json:"in_packets"`
	OutPackets  uint64    `json:"out_packets"`
	InErrors    uint64    `json:"in_errors"`
	OutErrors   uint64    `json:"out_errors"`
	InDiscards  uint64    `json:"in_discards"`
	OutDiscards uint64    `json:"out_discards"`
}

// InterfaceDelta represents calculated rate differences between two counter snapshots.
type InterfaceDelta struct {
	Device       string        `json:"device"`
	Interface    string        `json:"interface"`
	Duration     time.Duration `json:"duration"`
	DurationSec  float64       `json:"duration_sec"`
	InBps        float64       `json:"in_bps"`
	OutBps       float64       `json:"out_bps"`
	InPps        float64       `json:"in_pps"`
	OutPps       float64       `json:"out_pps"`
	InErrorDiff  uint64        `json:"in_errors_delta"`
	OutErrorDiff uint64        `json:"out_errors_delta"`
	InDropDiff   uint64        `json:"in_drops_delta"`
	OutDropDiff  uint64        `json:"out_drops_delta"`
}

// ComputeDelta calculates rates and delta changes from prev to curr.
// If counters wrapped or reset, deltas default to zero for that metric.
func ComputeDelta(device, iface string, prev, curr InterfaceCounter) InterfaceDelta {
	d := InterfaceDelta{
		Device:    device,
		Interface: iface,
	}
	dur := curr.Timestamp.Sub(prev.Timestamp)
	if dur <= 0 {
		return d
	}
	d.Duration = dur
	d.DurationSec = dur.Seconds()

	if curr.InOctets >= prev.InOctets {
		d.InBps = float64(curr.InOctets-prev.InOctets) * 8.0 / d.DurationSec
	}
	if curr.OutOctets >= prev.OutOctets {
		d.OutBps = float64(curr.OutOctets-prev.OutOctets) * 8.0 / d.DurationSec
	}
	if curr.InPackets >= prev.InPackets {
		d.InPps = float64(curr.InPackets-prev.InPackets) / d.DurationSec
	}
	if curr.OutPackets >= prev.OutPackets {
		d.OutPps = float64(curr.OutPackets-prev.OutPackets) / d.DurationSec
	}
	if curr.InErrors >= prev.InErrors {
		d.InErrorDiff = curr.InErrors - prev.InErrors
	}
	if curr.OutErrors >= prev.OutErrors {
		d.OutErrorDiff = curr.OutErrors - prev.OutErrors
	}
	if curr.InDiscards >= prev.InDiscards {
		d.InDropDiff = curr.InDiscards - prev.InDiscards
	}
	if curr.OutDiscards >= prev.OutDiscards {
		d.OutDropDiff = curr.OutDiscards - prev.OutDiscards
	}
	return d
}

// Regex patterns for interface counter parsing across common platforms.
var (
	// Cisco: "GigabitEthernet0/1 is up ... 1000 packets input, 80000 bytes, 2 input errors, 1 CRC, 0 dropped"
	reCiscoIface = regexp.MustCompile(`^(\S+) is (?:up|down|administratively down)`)
	reCiscoIn    = regexp.MustCompile(`(\d+) packets input,\s+(\d+) bytes`)
	reCiscoOut   = regexp.MustCompile(`(\d+) packets output,\s+(\d+) bytes`)
	reCiscoInErr = regexp.MustCompile(`(\d+) input errors`)
	reCiscoInDrp = regexp.MustCompile(`(\d+) (?:input|total) (?:drops|dropped)`)
	reCiscoOutErr = regexp.MustCompile(`(\d+) output errors`)
	reCiscoOutDrp = regexp.MustCompile(`(\d+) (?:output) (?:drops|dropped)`)

	// VyOS / Linux: "eth0: rx 1000 pkts 80000 bytes, tx 500 pkts 40000 bytes" or /proc/net/dev lines
	reProcNetDev = regexp.MustCompile(`^\s*([a-zA-Z0-9_.-]+):\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)`)

	// Juniper: "Physical interface: ge-0/0/0, Enabled, ..."
	reJunosIface   = regexp.MustCompile(`^Physical interface:\s*(\S+)`)
	reJunosInBytes = regexp.MustCompile(`Input bytes\s*:\s*(\d+)`)
	reJunosOutBytes = regexp.MustCompile(`Output bytes\s*:\s*(\d+)`)
	reJunosInPkts  = regexp.MustCompile(`Input packets\s*:\s*(\d+)`)
	reJunosOutPkts = regexp.MustCompile(`Output packets\s*:\s*(\d+)`)
	reJunosInErr   = regexp.MustCompile(`Input errors\s*:\s*(\d+)`)
	reJunosInDrop  = regexp.MustCompile(`Input drops\s*:\s*(\d+)`)
	reJunosOutErr  = regexp.MustCompile(`Output errors\s*:\s*(\d+)`)
	reJunosOutDrop = regexp.MustCompile(`Output drops\s*:\s*(\d+)`)
)

// ParseCiscoInterfaces parses "show interfaces" text output.
func ParseCiscoInterfaces(output string, now time.Time) map[string]InterfaceCounter {
	res := make(map[string]InterfaceCounter)
	lines := strings.Split(output, "\n")
	var curName string
	var curCnt InterfaceCounter

	flush := func() {
		if curName != "" {
			curCnt.Timestamp = now
			res[curName] = curCnt
			curName = ""
			curCnt = InterfaceCounter{}
		}
	}

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if m := reCiscoIface.FindStringSubmatch(line); len(m) > 1 {
			flush()
			curName = m[1]
			continue
		}
		if curName == "" {
			continue
		}
		if m := reCiscoIn.FindStringSubmatch(line); len(m) == 3 {
			pkts, _ := strconv.ParseUint(m[1], 10, 64)
			bytes, _ := strconv.ParseUint(m[2], 10, 64)
			curCnt.InPackets = pkts
			curCnt.InOctets = bytes
		}
		if m := reCiscoOut.FindStringSubmatch(line); len(m) == 3 {
			pkts, _ := strconv.ParseUint(m[1], 10, 64)
			bytes, _ := strconv.ParseUint(m[2], 10, 64)
			curCnt.OutPackets = pkts
			curCnt.OutOctets = bytes
		}
		if m := reCiscoInErr.FindStringSubmatch(line); len(m) == 2 {
			errs, _ := strconv.ParseUint(m[1], 10, 64)
			curCnt.InErrors = errs
		}
		if m := reCiscoInDrp.FindStringSubmatch(line); len(m) == 2 {
			drp, _ := strconv.ParseUint(m[1], 10, 64)
			curCnt.InDiscards = drp
		}
		if m := reCiscoOutErr.FindStringSubmatch(line); len(m) == 2 {
			errs, _ := strconv.ParseUint(m[1], 10, 64)
			curCnt.OutErrors = errs
		}
		if m := reCiscoOutDrp.FindStringSubmatch(line); len(m) == 2 {
			drp, _ := strconv.ParseUint(m[1], 10, 64)
			curCnt.OutDiscards = drp
		}
	}
	flush()
	return res
}

// ParseProcNetDev parses standard Linux/VyOS /proc/net/dev format.
func ParseProcNetDev(output string, now time.Time) map[string]InterfaceCounter {
	res := make(map[string]InterfaceCounter)
	for _, line := range strings.Split(output, "\n") {
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}
		name := strings.TrimSpace(line[:colonIdx])
		if name == "" {
			continue
		}
		fields := strings.Fields(line[colonIdx+1:])
		if len(fields) < 16 {
			continue
		}
		rxBytes, _ := strconv.ParseUint(fields[0], 10, 64)
		rxPackets, _ := strconv.ParseUint(fields[1], 10, 64)
		rxErrors, _ := strconv.ParseUint(fields[2], 10, 64)
		rxDrop, _ := strconv.ParseUint(fields[3], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[8], 10, 64)
		txPackets, _ := strconv.ParseUint(fields[9], 10, 64)
		txErrors, _ := strconv.ParseUint(fields[10], 10, 64)
		txDrop, _ := strconv.ParseUint(fields[11], 10, 64)

		res[name] = InterfaceCounter{
			Timestamp:   now,
			InOctets:    rxBytes,
			OutOctets:   txBytes,
			InPackets:   rxPackets,
			OutPackets:  txPackets,
			InErrors:    rxErrors,
			OutErrors:   txErrors,
			InDiscards:  rxDrop,
			OutDiscards: txDrop,
		}
	}
	return res
}

// ParseJunosInterfaces parses "show interfaces extensive" or "show interfaces" text output from Junos.
func ParseJunosInterfaces(output string, now time.Time) map[string]InterfaceCounter {
	res := make(map[string]InterfaceCounter)
	lines := strings.Split(output, "\n")
	var curName string
	var curCnt InterfaceCounter

	flush := func() {
		if curName != "" {
			curCnt.Timestamp = now
			res[curName] = curCnt
			curName = ""
			curCnt = InterfaceCounter{}
		}
	}

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if m := reJunosIface.FindStringSubmatch(line); len(m) > 1 {
			flush()
			curName = strings.TrimSuffix(m[1], ",")
			continue
		}
		if curName == "" {
			continue
		}
		if m := reJunosInBytes.FindStringSubmatch(line); len(m) == 2 {
			bytes, _ := strconv.ParseUint(m[1], 10, 64)
			curCnt.InOctets = bytes
		}
		if m := reJunosOutBytes.FindStringSubmatch(line); len(m) == 2 {
			bytes, _ := strconv.ParseUint(m[1], 10, 64)
			curCnt.OutOctets = bytes
		}
		if m := reJunosInPkts.FindStringSubmatch(line); len(m) == 2 {
			pkts, _ := strconv.ParseUint(m[1], 10, 64)
			curCnt.InPackets = pkts
		}
		if m := reJunosOutPkts.FindStringSubmatch(line); len(m) == 2 {
			pkts, _ := strconv.ParseUint(m[1], 10, 64)
			curCnt.OutPackets = pkts
		}
		if m := reJunosInErr.FindStringSubmatch(line); len(m) == 2 {
			errs, _ := strconv.ParseUint(m[1], 10, 64)
			curCnt.InErrors = errs
		}
		if m := reJunosInDrop.FindStringSubmatch(line); len(m) == 2 {
			drp, _ := strconv.ParseUint(m[1], 10, 64)
			curCnt.InDiscards = drp
		}
		if m := reJunosOutErr.FindStringSubmatch(line); len(m) == 2 {
			errs, _ := strconv.ParseUint(m[1], 10, 64)
			curCnt.OutErrors = errs
		}
		if m := reJunosOutDrop.FindStringSubmatch(line); len(m) == 2 {
			drp, _ := strconv.ParseUint(m[1], 10, 64)
			curCnt.OutDiscards = drp
		}
	}
	flush()
	return res
}
