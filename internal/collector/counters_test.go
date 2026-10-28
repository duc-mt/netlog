// ==============================================================================
// Package collector: counter parser tests.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-28
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package collector

import (
	"testing"
	"time"
)

func TestParseCiscoInterfaces(t *testing.T) {
	ciscoOutput := `
GigabitEthernet0/1 is up, line protocol is up
  Hardware is Gigabit Ethernet, address is 0050.56b0.1234
  5 minute input rate 1000 bits/sec, 2 packets/sec
  5 minute output rate 2000 bits/sec, 4 packets/sec
     1500 packets input, 120000 bytes, 0 no buffer
     Received 200 broadcasts (0 IP multicasts)
     5 input errors, 2 CRC, 0 frame, 0 overrun, 10 total drops
     2500 packets output, 240000 bytes, 0 underruns
     1 output errors, 0 collisions, 1 interface resets
     2 output drops
GigabitEthernet0/2 is administratively down, line protocol is down
  Hardware is Gigabit Ethernet
     0 packets input, 0 bytes
     0 input errors, 0 drops
     0 packets output, 0 bytes
     0 output errors, 0 drops
`
	now := time.Now()
	res := ParseCiscoInterfaces(ciscoOutput, now)
	if len(res) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(res))
	}

	g1, ok := res["GigabitEthernet0/1"]
	if !ok {
		t.Fatalf("missing GigabitEthernet0/1")
	}
	if g1.InPackets != 1500 || g1.InOctets != 120000 {
		t.Errorf("wrong in pkts/bytes: got %d pkts, %d bytes", g1.InPackets, g1.InOctets)
	}
	if g1.InErrors != 5 || g1.InDiscards != 10 {
		t.Errorf("wrong in errors/drops: got %d errors, %d discards", g1.InErrors, g1.InDiscards)
	}
	if g1.OutPackets != 2500 || g1.OutOctets != 240000 {
		t.Errorf("wrong out pkts/bytes: got %d pkts, %d bytes", g1.OutPackets, g1.OutOctets)
	}
	if g1.OutErrors != 1 || g1.OutDiscards != 2 {
		t.Errorf("wrong out errors/drops: got %d errors, %d discards", g1.OutErrors, g1.OutDiscards)
	}
}

func TestParseProcNetDev(t *testing.T) {
	procNet := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567      100    0    0    0     0          0         0  1234567      100    0    0    0     0       0          0
  eth0: 5000000     4000    3    1    0     0          0         0  8000000     6000    1    0    0     0       0          0
`
	now := time.Now()
	res := ParseProcNetDev(procNet, now)
	if len(res) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(res))
	}
	e0, ok := res["eth0"]
	if !ok {
		t.Fatalf("missing eth0")
	}
	if e0.InOctets != 5000000 || e0.InPackets != 4000 || e0.InErrors != 3 || e0.InDiscards != 1 {
		t.Errorf("unexpected rx counters: %+v", e0)
	}
	if e0.OutOctets != 8000000 || e0.OutPackets != 6000 || e0.OutErrors != 1 {
		t.Errorf("unexpected tx counters: %+v", e0)
	}
}

func TestParseJunosInterfaces(t *testing.T) {
	junosOutput := `
Physical interface: ge-0/0/0, Enabled, Physical link is Up
  Interface index: 134, SNMP ifIndex: 507
  Input packets : 12345
  Output packets: 67890
  Input bytes   : 1000000
  Output bytes  : 2000000
  Input errors: 4, Output errors: 1
  Input drops: 2, Output drops: 0
Physical interface: ge-0/0/1, Enabled, Physical link is Down
  Input packets : 0
  Output packets: 0
  Input bytes   : 0
  Output bytes  : 0
  Input errors: 0, Output errors: 0
  Input drops: 0, Output drops: 0
`
	now := time.Now()
	res := ParseJunosInterfaces(junosOutput, now)
	if len(res) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(res))
	}
	ge0, ok := res["ge-0/0/0"]
	if !ok {
		t.Fatalf("missing ge-0/0/0")
	}
	if ge0.InPackets != 12345 || ge0.OutPackets != 67890 {
		t.Errorf("wrong pkts: in=%d out=%d", ge0.InPackets, ge0.OutPackets)
	}
	if ge0.InOctets != 1000000 || ge0.OutOctets != 2000000 {
		t.Errorf("wrong bytes: in=%d out=%d", ge0.InOctets, ge0.OutOctets)
	}
	if ge0.InErrors != 4 || ge0.InDiscards != 2 || ge0.OutErrors != 1 {
		t.Errorf("wrong errors/drops: %+v", ge0)
	}
}

func TestComputeDelta(t *testing.T) {
	t0 := time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(10 * time.Second)

	prev := InterfaceCounter{
		Timestamp:  t0,
		InOctets:   100000,
		OutOctets:  50000,
		InPackets:  1000,
		OutPackets: 500,
		InErrors:   2,
		InDiscards: 1,
	}
	curr := InterfaceCounter{
		Timestamp:  t1,
		InOctets:   110000, // +10000 bytes in 10s = 8000 bps
		OutOctets:  60000,  // +10000 bytes in 10s = 8000 bps
		InPackets:  1100,   // +100 pkts in 10s = 10 pps
		OutPackets: 550,    // +50 pkts in 10s = 5 pps
		InErrors:   5,      // +3 errors
		InDiscards: 3,      // +2 drops
	}

	delta := ComputeDelta("R1", "eth0", prev, curr)
	if delta.DurationSec != 10.0 {
		t.Fatalf("expected 10s duration, got %v", delta.DurationSec)
	}
	if delta.InBps != 8000.0 || delta.OutBps != 8000.0 {
		t.Errorf("expected 8000 bps, got in=%v out=%v", delta.InBps, delta.OutBps)
	}
	if delta.InPps != 10.0 || delta.OutPps != 5.0 {
		t.Errorf("expected 10/5 pps, got in=%v out=%v", delta.InPps, delta.OutPps)
	}
	if delta.InErrorDiff != 3 || delta.InDropDiff != 2 {
		t.Errorf("expected 3 errs, 2 drops, got err=%v drop=%v", delta.InErrorDiff, delta.InDropDiff)
	}
}
