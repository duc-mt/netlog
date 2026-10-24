// ==============================================================================
// Package pipeline: fuzz tests for the stages that consume untrusted device text.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-21
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package pipeline

import (
	"strings"
	"testing"
	"time"

	"netlog/internal/collector"
)

var clockSeeds = []string{
	"*09:30:15.123 UTC Tue Oct 20 2026\n",
	"Tue Oct 20 09:44:01 +07 2026\n",
	"2026-10-20 09:31:02\nTuesday\nTime Zone(Vietnam) : UTC+07:00\n",
	"Current time: 2026-10-20 09:44:01 ICT\nSystem booted: 2026-09-01 08:00:00 ICT (7w0d 01:44 ago)\n",
	"date: oct/20/2026\n time: 09:31:02\n",
	"current time is: 00:00:05\n",
	"Tue Oct 20 09:44:01 PM +0530 2026",
}

var clockVendors = []string{"cisco_ios", "vyos", "huawei_vrp", "fortigate", "mikrotik", "juniper_junos", "generic"}

func FuzzParseDeviceClock(f *testing.F) {
	for i := range clockVendors {
		for _, s := range clockSeeds {
			f.Add(uint8(i), s)
		}
	}
	ref := time.Date(2026, 10, 20, 9, 30, 10, 0, ict)
	f.Fuzz(func(t *testing.T, v uint8, out string) {
		got, err := ParseDeviceClock(clockVendors[int(v)%len(clockVendors)], out, ref)
		if err == nil && got.IsZero() {
			t.Fatalf("nil error with zero time for %q", out)
		}
	})
}

func FuzzClassifyAndExtract(f *testing.F) {
	for _, s := range []string{
		"%SYS-5-CONFIG_I: Configured from console by bachngo on vty0 (10.10.10.50)",
		"%OSPF-5-ADJCHG: Process 1, Nbr 10.255.255.4 on Gi0/1 from FULL to DOWN, Neighbor Down: Interface down or detached",
		`Oct 20 2026 09:31:02+07:00 H %%01SHELL/6/CMDRECORD(s)[9]:Record command information. (Task=VTY0, Command="dis cu")`,
		"bgpd: %ADJCHANGE: neighbor 192.0.2.2 in vrf default Down",
		"ifName ge-0/0/1 eth1:10.0.0.1 Interface 1/1/24",
	} {
		f.Add(s)
	}
	cl := NewClassifier(ict)
	f.Fuzz(func(t *testing.T, raw string) {
		e := collector.LogEntry{Raw: raw, Timestamp: time.Date(2026, 10, 20, 3, 0, 0, 0, time.UTC)}
		cl.Classify(&e)
		if e.Category == "" || e.Event == "" || e.Severity == "" {
			t.Fatalf("unclassified result for %q: %+v", raw, e)
		}
		// Extracted names end up inside device commands: they must stay inert.
		for _, v := range []string{ExtractInterface(raw), ExtractPeer(raw)} {
			if strings.ContainsAny(v, " ;&|`$<>\\\"'\n\r\t(){}!*?") {
				t.Fatalf("extractor returned unsafe value %q for %q", v, raw)
			}
		}
	})
}
