// ==============================================================================
// Package pipeline: tests for watermark, normalizer, classifier and anomaly stages.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package pipeline

import (
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"netlog/internal/collector"
	"netlog/internal/inventory"
	"netlog/internal/parser"
	"netlog/internal/store"
)

var (
	ict     = time.FixedZone("ICT", 7*3600)
	popts   = parser.Options{Ref: time.Date(2026, 10, 20, 10, 0, 0, 0, ict), Location: ict}
	testDev = inventory.Device{Hostname: "SW1", Address: "10.0.0.1"}
)

// ---- classifier ---------------------------------------------------------------

func classified(t *testing.T, key, line string) collector.LogEntry {
	t.Helper()
	got := parser.Parse(key, line, testDev, popts)
	if len(got) != 1 {
		t.Fatalf("parse %q: got %d entries", line, len(got))
	}
	e := got[0]
	Normalize([]collector.LogEntry{e}, 0, false)
	e.Timestamp = e.DeviceTS.UTC()
	NewClassifier(ict).Classify(&e)
	return e
}

func TestClassifierRules(t *testing.T) {
	tests := []struct {
		name, key, line, cat, event, sev string
	}{
		{"ios config", "cisco_ios", "Oct 20 09:30:15: %SYS-5-CONFIG_I: Configured from console by bachngo on vty0 (10.10.10.50)", "CONFIG", EventConfigChange, "WARNING"},
		{"vyos commit", "vyos", "2026-10-20T09:44:01+07:00 R1 commit[1234]: [user: tanvt] Applying config changes", "CONFIG", EventConfigChange, "WARNING"},
		{"huawei shutdown", "huawei_vrp", "Oct 20 2026 09:31:02+07:00 H %%01SHELL/5/CMDRECORD(l)[1]:bachngo: interface GigabitEthernet0/0/1 shutdown", "CONFIG", EventConfigChange, "WARNING"},
		{"huawei display is not a change", "huawei_vrp", "Oct 20 2026 09:31:02+07:00 H %%01SHELL/5/CMDRECORD(l)[1]:bachngo: display ip interface brief", "SYSTEM", EventCLICommand, "INFO"},
		{"huawei long display", "huawei_vrp", `Oct 20 2026 09:31:02+07:00 H %%01SHELL/6/CMDRECORD(s)[1]:Record command information. (Task=VTY0, Ip=1.1.1.1, VpnName=, User=a, Command="dis cu")`, "SYSTEM", EventCLICommand, "INFO"},
		{"junos commit", "juniper_junos", "Oct 20 09:30:15  sw1 mgd[1]: UI_COMMIT: User 'tanvt' requested 'commit' operation", "CONFIG", EventConfigChange, "WARNING"},
		{"ssh accepted", "vyos", "Oct 20 09:44:05 vyos sshd[77]: Accepted password for tanvt from 10.1.1.1 port 4444 ssh2", "AUTH", EventLoginSuccess, "INFO"},
		{"cisco login success", "cisco_ios", "Oct 20 09:30:15: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 10.1.1.1] [localport: 22]", "AUTH", EventLoginSuccess, "INFO"},
		{"ssh failed", "vyos", "Oct 20 09:44:05 vyos sshd[77]: Failed password for invalid user admin from 203.0.113.9 port 4444 ssh2", "AUTH", EventLoginFailure, "WARNING"},
		{"cisco login failed", "cisco_ios", "Oct 20 09:30:15: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: x] [Source: 1.2.3.4] [localport: 22]", "AUTH", EventLoginFailure, "WARNING"},
		{"ios link", "cisco_ios", "Oct 20 09:31:02.001: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down", "FAULT", EventLinkDown, "ERROR"},
		{"huawei link", "huawei_vrp", "Oct 20 2026 09:31:02+07:00 H %%01IFNET/4/LINK_STATE(l)[1]:The line protocol on the interface GigabitEthernet0/0/1 has entered the DOWN state.", "FAULT", EventLinkDown, "ERROR"},
		{"vyos kernel link", "vyos", "2026-10-20T09:44:03+07:00 R1 kernel: e1000e: eth1 NIC Link is Down", "FAULT", EventLinkDown, "ERROR"},
		{"junos link trap", "juniper_junos", "Oct 20 09:30:17  sw1 mib2d[1]: SNMP_TRAP_LINK_DOWN: ifIndex 501, ifAdminStatus up(1), ifOperStatus down(2), ifName ge-0/0/1", "FAULT", EventLinkDown, "ERROR"},
		{"ospf with 'interface down' text stays OSPF", "cisco_ios", "Oct 20 09:31:02: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.255.4 on Gi0/1 from FULL to DOWN, Neighbor Down: Interface down or detached", "FAULT", EventOSPFAdjDown, "ERROR"},
		{"frr ospf", "vyos", "Oct 20 09:44:05 R1 ospfd[1]: %ADJCHG: Nbr 10.0.0.2 on eth1:10.0.0.1: Full -> Down (InactivityTimer)", "FAULT", EventOSPFAdjDown, "ERROR"},
		{"junos ospf", "juniper_junos", "Oct 20 09:30:16  sw1 rpd[1]: RPD_OSPF_NBRDOWN: OSPF neighbor 10.1.1.2 (realm ospf-v2 ge-0/0/1.0 area 0.0.0.0) state changed from Full to Down", "FAULT", EventOSPFAdjDown, "ERROR"},
		{"cisco bgp", "cisco_ios", "Oct 20 09:31:02: %BGP-5-ADJCHANGE: neighbor 10.1.1.1 Down Peer closed the session", "FAULT", EventBGPPeerDown, "ERROR"},
		{"junos bgp", "juniper_junos", "Oct 20 09:30:16  sw1 rpd[1]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.2.2.2 (External AS 65001) changed state from Established to Idle", "FAULT", EventBGPPeerDown, "ERROR"},
		{"vrrp", "vyos", "Oct 20 09:44:05 R1 Keepalived_vrrp[9]: (VRRP1) Entering BACKUP STATE", "FAULT", EventVRRPTransition, "WARNING"},
		{"vrrp fault", "vyos", "Oct 20 09:44:05 R1 Keepalived_vrrp[9]: Entering FAULT STATE", "FAULT", EventVRRPTransition, "WARNING"},
		{"vrrp master", "vyos", "Oct 20 09:44:05 R1 Keepalived_vrrp[9]: Entering MASTER STATE", "SYSTEM", EventVRRPTransition, "INFO"},
		{"vrrp lower pri advert", "vyos", "Oct 20 09:44:05 R1 Keepalived_vrrp[9]: (LAN) Received advert from 10.134.4.3 with lower priority 100, ours 150, forcing new election", "SYSTEM", EventHAChange, "INFO"},
		{"stp", "cisco_ios", "Oct 20 09:31:02: %SPANTREE-5-TOPOTRAP: Topology Change Trap for vlan 100", "FAULT", EventSTPTCN, "WARNING"},
		{"cpu", "cisco_ios", "Oct 20 09:31:02: %SYS-3-CPUHOG: CPU utilization for five seconds: 97%/3%", "SYSTEM", EventHighCPU, "WARNING"},
		{"unknown", "cisco_ios", "Oct 20 09:31:02: %SYS-6-LOGGINGHOST_STARTSTOP: Logging to host 10.0.0.9 port 514 started", "SYSTEM", EventUnknown, "INFO"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := classified(t, tc.key, tc.line)
			if e.Category != tc.cat || e.Event != tc.event || e.Severity != tc.sev {
				t.Errorf("got %s/%s/%s, want %s/%s/%s", e.Category, e.Event, e.Severity, tc.cat, tc.event, tc.sev)
			}
		})
	}
}

func TestAfterHoursOverride(t *testing.T) {
	cl := NewClassifier(ict)
	cfg := func(h, m int) collector.LogEntry {
		return collector.LogEntry{Raw: "%SYS-5-CONFIG_I: Configured", Timestamp: time.Date(2026, 10, 20, h, m, 0, 0, ict).UTC()}
	}
	for _, tc := range []struct {
		h, m  int
		after bool
	}{{0, 0, true}, {2, 30, true}, {5, 59, true}, {6, 0, false}, {9, 0, false}, {23, 59, false}} {
		e := cfg(tc.h, tc.m)
		cl.Classify(&e)
		got := e.Event == EventAfterHoursChange
		if got != tc.after {
			t.Errorf("%02d:%02d after-hours=%v, want %v (event %s)", tc.h, tc.m, got, tc.after, e.Event)
		}
		if tc.after && (e.Category != "SECURITY" || e.Severity != "CRITICAL") {
			t.Errorf("%02d:%02d override wrong: %s/%s", tc.h, tc.m, e.Category, e.Severity)
		}
	}
	// Local time, not UTC: 02:00 UTC is 09:00 ICT -> not after hours in ICT.
	e := collector.LogEntry{Raw: "CONFIG_I", Timestamp: time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC)}
	cl.Classify(&e)
	if e.Event != EventConfigChange {
		t.Errorf("after-hours must use the classifier's zone, got %s", e.Event)
	}
}

func TestIsAfterHours(t *testing.T) {
	dateAt := func(h int) time.Time {
		return time.Date(2026, 10, 20, h, 30, 0, 0, time.UTC)
	}

	// Intra-day: 0 to 6
	for h := 0; h < 24; h++ {
		got := IsAfterHours(dateAt(h), 0, 6)
		want := h < 6
		if got != want {
			t.Errorf("IsAfterHours(%d, 0, 6) = %v, want %v", h, got, want)
		}
	}

	// Overnight wrap-around: 20 to 6
	for h := 0; h < 24; h++ {
		got := IsAfterHours(dateAt(h), 20, 6)
		want := h >= 20 || h < 6
		if got != want {
			t.Errorf("IsAfterHours(%d, 20, 6) = %v, want %v", h, got, want)
		}
	}

	// Disabled when equal
	if IsAfterHours(dateAt(5), 5, 5) {
		t.Error("IsAfterHours with start == end must be false")
	}
}

func TestCustomAfterHoursWindow(t *testing.T) {
	cl := NewClassifierWithOptions(ClassifierOptions{
		Location:        ict,
		AfterHoursStart: 20,
		AfterHoursEnd:   6,
	})
	cfg := func(h, m int) collector.LogEntry {
		return collector.LogEntry{Raw: "%SYS-5-CONFIG_I: Configured", Timestamp: time.Date(2026, 10, 20, h, m, 0, 0, ict).UTC()}
	}

	// 21:00 ICT should be AFTER_HOURS_CHANGE
	e1 := cfg(21, 0)
	cl.Classify(&e1)
	if e1.Event != EventAfterHoursChange || e1.Severity != collector.SeverityCritical {
		t.Errorf("21:00 want AFTER_HOURS_CHANGE/CRITICAL, got %s/%s", e1.Event, e1.Severity)
	}

	// 14:00 ICT should be normal CONFIG_CHANGE
	e2 := cfg(14, 0)
	cl.Classify(&e2)
	if e2.Event != EventConfigChange || e2.Severity != collector.SeverityWarning {
		t.Errorf("14:00 want CONFIG_CHANGE/WARNING, got %s/%s", e2.Event, e2.Severity)
	}
}

// ---- normalizer -----------------------------------------------------------------

func TestNormalize(t *testing.T) {
	dev := time.Date(2026, 10, 20, 10, 0, 5, 0, ict)
	es := []collector.LogEntry{{DeviceTS: dev}}
	Normalize(es, 5000, true) // device is 5s fast
	if want := time.Date(2026, 10, 20, 3, 0, 0, 0, time.UTC); !es[0].Timestamp.Equal(want) || es[0].SkewMs != 5000 || es[0].Timestamp.Location() != time.UTC {
		t.Errorf("got %v skew %d, want %v", es[0].Timestamp, es[0].SkewMs, want)
	}
	Normalize(es, 5000, false) // skew unknown: leave device time
	if !es[0].Timestamp.Equal(dev) || es[0].SkewMs != 0 {
		t.Errorf("unknown skew must not shift time: %v %d", es[0].Timestamp, es[0].SkewMs)
	}
}

func TestParseDeviceClock(t *testing.T) {
	utc := time.UTC
	tests := []struct {
		name, vendor, out string
		ref               time.Time
		want              time.Time
	}{
		{"cisco wallclock ignores zone label", "cisco_ios", "*09:30:15.123 UTC Tue Oct 20 2026\n",
			time.Date(2026, 10, 20, 9, 30, 10, 0, ict), time.Date(2026, 10, 20, 9, 30, 15, 123e6, ict)},
		{"vyos honours +07 on a UTC server", "vyos", "Tue Oct 20 09:44:01 +07 2026\n",
			time.Date(2026, 10, 20, 2, 44, 0, 0, utc), time.Date(2026, 10, 20, 2, 44, 1, 0, utc)},
		{"vyos AM/PM", "vyos", "Tue Oct 20 09:44:01 PM +07 2026",
			time.Date(2026, 10, 20, 14, 44, 0, 0, utc), time.Date(2026, 10, 20, 14, 44, 1, 0, utc)},
		{"huawei zone on its own line", "huawei_vrp", "2026-10-20 09:31:02\nTuesday\nTime Zone(Vietnam) : UTC+07:00\n",
			time.Date(2026, 10, 20, 2, 31, 0, 0, utc), time.Date(2026, 10, 20, 2, 31, 2, 0, utc)},
		{"huawei inline offset", "huawei_vrp", "2026-10-20 09:31:02+07:00\n",
			time.Date(2026, 10, 20, 2, 31, 0, 0, utc), time.Date(2026, 10, 20, 2, 31, 2, 0, utc)},
		{"junos current time line first", "juniper_junos", "Current time: 2026-10-20 09:44:01 ICT\nSystem booted: 2026-09-01 08:00:00 ICT (7w0d 01:44 ago)\n",
			time.Date(2026, 10, 20, 9, 44, 0, 0, ict), time.Date(2026, 10, 20, 9, 44, 1, 0, ict)},
		{"mikrotik split lines", "mikrotik", "                   date: oct/20/2026\n                   time: 09:31:02\n          time-zone-name: Asia/Ho_Chi_Minh\n",
			time.Date(2026, 10, 20, 9, 31, 0, 0, ict), time.Date(2026, 10, 20, 9, 31, 2, 0, ict)},
		{"time only, device just past midnight", "fortigate", "current time is: 00:00:05\n",
			time.Date(2026, 10, 20, 23, 59, 50, 0, utc), time.Date(2026, 10, 21, 0, 0, 5, 0, utc)},
		{"fortigate get system status with ancient virus db", "fortigate",
			"Version: FortiGate-100E v7.0.12\nVirus-DB: 91.02634(2018-04-09 10:20)\nHostname: FG1\nSystem time: Tue Oct 20 09:31:02 2026\n",
			time.Date(2026, 10, 20, 9, 31, 0, 0, utc), time.Date(2026, 10, 20, 9, 31, 2, 0, utc)},
		{"time only, device just before midnight", "generic", "23:59:55",
			time.Date(2026, 10, 21, 0, 0, 3, 0, utc), time.Date(2026, 10, 20, 23, 59, 55, 0, utc)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDeviceClock(tc.vendor, tc.out, tc.ref)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
	if _, err := ParseDeviceClock("cisco_ios", "% Invalid input detected", time.Now()); err == nil {
		t.Error("garbage output must be an error")
	}
	// The whole point: skew = device reading - server time.
	ref := time.Date(2026, 10, 20, 9, 30, 10, 0, ict)
	dt, _ := ParseDeviceClock("cisco_ios", "09:30:15.123 +07 Tue Oct 20 2026", ref)
	if skew := dt.Sub(ref).Milliseconds(); skew != 5123 {
		t.Errorf("skew = %dms, want 5123", skew)
	}
}

func TestOffsetZoneEdgeCases(t *testing.T) {
	tests := []struct {
		input   string
		valid   bool
		wantSec int
	}{
		{"", false, 0},
		{"+", false, 0},
		{"-", false, 0},
		{"+1", false, 0},
		{"-1", false, 0},
		{"+07", true, 7 * 3600},
		{"-05", true, -5 * 3600},
		{"+07:00", true, 7 * 3600},
		{"-05:30", true, -(5*3600 + 30*60)},
		{"+invalid", false, 0},
	}
	for _, tc := range tests {
		loc, ok := offsetZone(tc.input)
		if ok != tc.valid {
			t.Errorf("offsetZone(%q) ok = %v, want %v", tc.input, ok, tc.valid)
			continue
		}
		if ok {
			now := time.Now().In(loc)
			_, offset := now.Zone()
			if offset != tc.wantSec {
				t.Errorf("offsetZone(%q) offset = %d, want %d", tc.input, offset, tc.wantSec)
			}
		}
	}
}

// ---- watermark ------------------------------------------------------------------

func entry(host, raw string, at time.Time) collector.LogEntry {
	return collector.LogEntry{ID: collector.EntryID(host, raw), Hostname: host, Raw: raw, DeviceTS: at, Timestamp: at.UTC()}
}

func newMarks(t *testing.T) (*Watermarks, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".netlog_state.json")
	st, err := store.LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	return NewWatermarks(st), path
}

func rawsOf(es []collector.LogEntry) string {
	var b []string
	for _, e := range es {
		b = append(b, e.Raw)
	}
	return strings.Join(b, ",")
}

func TestWatermarkDedup(t *testing.T) {
	w, path := newMarks(t)
	t0 := time.Date(2026, 10, 20, 9, 0, 0, 0, ict)
	a, b := entry("R1", "a", t0), entry("R1", "b", t0.Add(time.Second))

	// First poll: everything is new; input order is irrelevant (sorted by device time).
	fresh := w.Filter("R1", []collector.LogEntry{b, a})
	if rawsOf(fresh) != "a,b" {
		t.Fatalf("first poll: %s", rawsOf(fresh))
	}
	w.Advance("R1", fresh)

	// Same buffer again: nothing new.
	if got := w.Filter("R1", []collector.LogEntry{a, b}); len(got) != 0 {
		t.Fatalf("repeat poll should be empty, got %s", rawsOf(got))
	}
	// One new line.
	c := entry("R1", "c", t0.Add(2*time.Second))
	if got := w.Filter("R1", []collector.LogEntry{a, b, c}); rawsOf(got) != "c" {
		t.Fatalf("want only c, got %s", rawsOf(got))
	}
	// Other devices are independent.
	if got := w.Filter("R2", []collector.LogEntry{entry("R2", "a", t0)}); len(got) != 1 {
		t.Fatalf("R2 must be unaffected")
	}

	// Persistence round trip.
	if err := w.Save(); err != nil {
		t.Fatal(err)
	}
	st2, err := store.LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := NewWatermarks(st2).Filter("R1", []collector.LogEntry{a, b}); len(got) != 0 {
		t.Fatalf("watermark lost across restart: %s", rawsOf(got))
	}
}

func TestWatermarkSameSecondBatch(t *testing.T) {
	w, _ := newMarks(t)
	ts := time.Date(2026, 10, 20, 9, 0, 0, 0, ict)
	a, b, c := entry("R1", "a", ts), entry("R1", "b", ts), entry("R1", "c", ts)

	w.Advance("R1", w.Filter("R1", []collector.LogEntry{a, b})) // stored a,b; mark = b
	if got := w.Filter("R1", []collector.LogEntry{a, b, c}); rawsOf(got) != "c" {
		t.Fatalf("same-second late arrival: want c, got %s", rawsOf(got))
	}
	// The stored tail line fell out of the buffer: remaining tied lines are newer.
	if got := w.Filter("R1", []collector.LogEntry{c}); rawsOf(got) != "c" {
		t.Fatalf("rolled-out hash: want c, got %s", rawsOf(got))
	}
}

func TestWatermarkClockStepBack(t *testing.T) {
	w, _ := newMarks(t)
	future := time.Date(2026, 10, 21, 9, 0, 0, 0, ict)
	w.Advance("R1", []collector.LogEntry{entry("R1", "old", future)})

	now := future.Add(-26 * time.Hour) // device clock stepped back a day
	got := w.Filter("R1", []collector.LogEntry{entry("R1", "x", now), entry("R1", "y", now.Add(time.Second))})
	if len(got) != 2 {
		t.Fatalf("after a backwards clock step the buffer must be re-ingested, got %d", len(got))
	}
	// A small backwards wobble (< 1h) is just old data.
	if got := w.Filter("R1", []collector.LogEntry{entry("R1", "z", future.Add(-time.Minute))}); len(got) != 0 {
		t.Fatalf("minor regression must not re-ingest, got %d", len(got))
	}
}

func TestStateCorruptFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadState(path); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("want corrupt-state error, got %v", err)
	}
}

// ---- anomaly --------------------------------------------------------------------

type fixture struct {
	d   *Detector
	now time.Time
}

func newFixture() *fixture {
	f := &fixture{now: time.Date(2026, 10, 20, 10, 30, 0, 0, time.UTC)}
	f.d = NewDetector(DetectorConfig{Now: func() time.Time { return f.now }})
	return f
}

func ev(host, event, cat, raw string, at time.Time) collector.LogEntry {
	return collector.LogEntry{Hostname: host, Event: event, Category: cat, Raw: raw, Timestamp: at, Summary: raw}
}

func TestLinkFlapCollapsesSignals(t *testing.T) {
	f := newFixture()
	base := f.now.Add(-4 * time.Minute)
	raw := "%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down"
	down := func(sec int) collector.LogEntry {
		return ev("SW1", EventLinkDown, "FAULT", raw, base.Add(time.Duration(sec)*time.Second))
	}

	if s := f.d.Observe(down(0)); len(s) != 1 || s[0].Playbook != PlaybookLinkDown || s[0].Derived {
		t.Fatalf("1st: %+v", s)
	}
	if s := f.d.Observe(down(30)); len(s) != 1 || s[0].Playbook != PlaybookLinkDown {
		t.Fatalf("2nd: %+v", s)
	}
	s := f.d.Observe(down(60))
	if len(s) != 1 || s[0].Playbook != PlaybookLinkFlap || !s[0].Derived || s[0].Entry.Event != EventLinkFlap {
		t.Fatalf("3rd should be one LINK_FLAP, got %+v", s)
	}
	if !strings.Contains(s[0].Entry.Summary, "GigabitEthernet0/1") {
		t.Errorf("flap summary should name the interface: %q", s[0].Entry.Summary)
	}
	if s := f.d.Observe(down(90)); len(s) != 0 {
		t.Fatalf("individual signals must be suppressed after a flap, got %+v", s)
	}
	// A different interface is independent.
	other := ev("SW1", EventLinkDown, "FAULT", "%LINK-3-UPDOWN: Interface GigabitEthernet0/2, changed state to down", base.Add(100*time.Second))
	if s := f.d.Observe(other); len(s) != 1 || s[0].Playbook != PlaybookLinkDown {
		t.Fatalf("other iface: %+v", s)
	}
}

func TestSimpleSignalsAndStaleSuppression(t *testing.T) {
	f := newFixture()
	recent := f.now.Add(-time.Minute)
	for _, tc := range []struct{ event, pb string }{
		{EventOSPFAdjDown, PlaybookOSPFAdjDown}, {EventBGPPeerDown, PlaybookBGPPeerDown},
		{EventVRRPTransition, PlaybookVRRPTransition}, {EventSTPTCN, PlaybookSTPTCN}, {EventHighCPU, PlaybookHighCPU},
	} {
		s := f.d.Observe(ev("R1", tc.event, "FAULT", "x", recent))
		if len(s) != 1 || s[0].Playbook != tc.pb {
			t.Errorf("%s: %+v", tc.event, s)
		}
	}
	// A line from yesterday (first-poll backfill) must not trigger triage.
	if s := f.d.Observe(ev("R1", EventOSPFAdjDown, "FAULT", "x", f.now.Add(-24*time.Hour))); len(s) != 0 {
		t.Fatalf("stale entry produced a signal: %+v", s)
	}
	// Unclassified / auth success / config produce nothing.
	for _, e := range []string{EventUnknown, EventLoginSuccess, EventConfigChange, EventCLICommand} {
		if s := f.d.Observe(ev("R1", e, "X", "x", recent)); len(s) != 0 {
			t.Errorf("%s must not signal", e)
		}
	}
}

func TestStaleHistoryStillCountsTowardFlap(t *testing.T) {
	f := newFixture()
	base := f.now.Add(-3 * time.Hour) // all stale
	raw := "Interface Gi0/1, changed state to down"
	for i := 0; i < 3; i++ {
		if s := f.d.Observe(ev("SW1", EventLinkDown, "FAULT", raw, base.Add(time.Duration(i)*time.Minute))); len(s) != 0 {
			t.Fatalf("stale entries must not signal: %+v", s)
		}
	}
	// The flap was recorded; a fresh single down right after is suppressed? No: suppression
	// ended long ago (10m), so it signals normally.
	if s := f.d.Observe(ev("SW1", EventLinkDown, "FAULT", raw, f.now.Add(-time.Minute))); len(s) != 1 {
		t.Fatalf("fresh link-down after stale flap should signal once, got %+v", s)
	}
}

func TestBruteForce(t *testing.T) {
	f := newFixture()
	base := f.now.Add(-time.Minute)
	fail := func(src string, sec int) collector.LogEntry {
		e := ev("R1", EventLoginFailure, "AUTH", "Failed password", base.Add(time.Duration(sec)*time.Second))
		e.SourceIP = src
		return e
	}
	for i := 0; i < 4; i++ {
		if s := f.d.Observe(fail("203.0.113.9", i*5)); len(s) != 0 {
			t.Fatalf("failure %d signalled early", i+1)
		}
	}
	s := f.d.Observe(fail("203.0.113.9", 20))
	if len(s) != 1 || s[0].Playbook != PlaybookBruteForce || s[0].Priority != PriorityCritical || !s[0].Derived ||
		s[0].Entry.Event != EventBruteForce || s[0].Entry.Category != "SECURITY" || s[0].Entry.Severity != "CRITICAL" {
		t.Fatalf("5th failure should signal brute force, got %+v", s)
	}
	// Window cleared: the next failure starts a new count.
	if s := f.d.Observe(fail("203.0.113.9", 21)); len(s) != 0 {
		t.Fatalf("count must restart after a signal")
	}
	// Slow failures (one per 10s) never reach 5 inside 30s.
	for i := 0; i < 8; i++ {
		if s := f.d.Observe(fail("198.51.100.7", 100+i*10)); len(s) != 0 {
			t.Fatalf("slow failures must not signal")
		}
	}
	// No source address: cannot be attributed.
	for i := 0; i < 6; i++ {
		if s := f.d.Observe(fail("", 200+i)); len(s) != 0 {
			t.Fatalf("failures without a source must not signal")
		}
	}
}

func TestConfigFaultCorrelation(t *testing.T) {
	f := newFixture()
	cfgAt := f.now.Add(-5 * time.Minute)
	cfg := ev("R1", EventConfigChange, "CONFIG", "commit[1]", cfgAt)
	cfg.User = "tanvt"
	f.d.Observe(cfg)

	s := f.d.Observe(ev("R1", EventOSPFAdjDown, "FAULT", "x", cfgAt.Add(42*time.Second)))
	if len(s) != 1 || len(s[0].Annotations) != 1 ||
		!strings.Contains(s[0].Annotations[0], "tanvt") || !strings.Contains(s[0].Annotations[0], "42s") {
		t.Fatalf("expected correlation note naming tanvt and 42s, got %+v", s)
	}
	// Outside the 10 minute window: no note.
	s = f.d.Observe(ev("R1", EventBGPPeerDown, "FAULT", "x", cfgAt.Add(11*time.Minute)))
	// (that entry is 6 minutes old relative to f.now, still fresh)
	if len(s) != 1 || len(s[0].Annotations) != 0 {
		t.Fatalf("no note expected beyond the window, got %+v", s)
	}
	// Another device is unaffected.
	s = f.d.Observe(ev("R2", EventOSPFAdjDown, "FAULT", "x", cfgAt.Add(time.Minute)))
	if len(s) != 1 || len(s[0].Annotations) != 0 {
		t.Fatalf("other host must not inherit the config change, got %+v", s)
	}
}

func TestExtractInterfaceAndPeer(t *testing.T) {
	ifaces := map[string]string{
		"%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down":                                           "GigabitEthernet0/1",
		"The line protocol on the interface GigabitEthernet0/0/1 has entered the DOWN state.":                           "GigabitEthernet0/0/1",
		"kernel: e1000e: eth1 NIC Link is Down":                                                                         "eth1",
		"SNMP_TRAP_LINK_DOWN: ifIndex 501, ifOperStatus down(2), ifName ge-0/0/1":                                       "ge-0/0/1",
		"interface,info ether1 link down":                                                                               "ether1",
		"%ADJCHG: Nbr 10.0.0.2 on eth1:10.0.0.1: Full -> Down (InactivityTimer)":                                        "eth1",
		"%OSPF-5-ADJCHG: Process 1, Nbr 10.1.1.2 on Gi0/1 from FULL to DOWN, Neighbor Down: Interface down or detached": "Gi0/1",
		"Neighbor Down: Interface down or detached":                                                                     "",
		"kernel: igb0: link state changed to DOWN":                                                                      "igb0",
		"kernel: vtnet1: link state changed to UP":                                                                      "vtnet1",
		"nothing relevant here":                                                                                         "",
	}
	for raw, want := range ifaces {
		if got := ExtractInterface(raw); got != want {
			t.Errorf("ExtractInterface(%q) = %q, want %q", raw, got, want)
		}
	}
	peers := map[string]string{
		"%BGP-5-ADJCHANGE: neighbor 10.1.1.1 Down Peer closed the session":    "10.1.1.1",
		"BGP peer 10.2.2.2 (External AS 65001) changed state":                 "10.2.2.2",
		"bgpd: %ADJCHANGE: neighbor 192.0.2.2 in vrf default Down":            "192.0.2.2",
		"%BGP-5-ADJCHANGE: neighbor 2001:db8:1::1 Down BGP Notification sent": "2001:db8:1::1",
		"BGP: %NOTIFICATION: sent to neighbor 2001:db8::2, 3/11":              "2001:db8::2",
		"bgp: NOTIFICATION sent to peer 2001:db8:beef::1 (External AS 65001)": "2001:db8:beef::1",
		"neighbor 999.1.1.1 Down":                                             "",
		"neighbor 2001:zzz::1 Down":                                           "",
		"neighbor 12345 Down":                                                 "",
		"no peer here":                                                        "",
	}
	for raw, want := range peers {
		if got := ExtractPeer(raw); got != want {
			t.Errorf("ExtractPeer(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestExtractInterfaceDigitLed(t *testing.T) {
	if got := ExtractInterface("Interface 1/1/24 is down"); got != "1/1/24" {
		t.Errorf("got %q", got)
	}
}

func TestDerivedEntriesGetOwnIDs(t *testing.T) {
	f := newFixture()
	base := f.now.Add(-time.Minute)
	raw := "Interface Gi0/1, changed state to down"
	var flap TriageSignal
	for i := 0; i < 3; i++ {
		e := ev("SW1", EventLinkDown, "FAULT", raw, base.Add(time.Duration(i)*time.Second))
		e.ID = collector.EntryID("SW1", raw)
		for _, s := range f.d.Observe(e) {
			if s.Derived {
				flap = s
			}
		}
	}
	if !flap.Derived || flap.Entry.ID == "" || flap.Entry.ID == collector.EntryID("SW1", raw) {
		t.Fatalf("derived entry must not reuse the parsed line's ID: %+v", flap.Entry)
	}
}

// TestWatermarkRingBufferSimulation models a device whose log buffer is a
// ring, polled at irregular intervals, with lots of identical same-second
// lines (1-second syslog resolution makes those real). Every produced line
// must be stored exactly once and in order.
//
// The model assumes the buffer holds at least two seconds of the device's
// peak burst (no more than capacity/2 lines share a second). A buffer
// smaller than one second of logging loses lines regardless of dedup, and
// once the lines of the watermark second start rolling out of the buffer,
// byte-identical lines can no longer be told apart by any scheme.
func TestWatermarkRingBufferSimulation(t *testing.T) {
	const capacity = 40
	texts := []string{"link flap", "auth fail", "ok"}

	for seed := int64(1); seed <= 500; seed++ {
		rng := rand.New(rand.NewSource(seed))
		path := filepath.Join(t.TempDir(), "state.json")
		st, err := store.LoadState(path)
		if err != nil {
			t.Fatal(err)
		}
		w := NewWatermarks(st)

		clock := time.Date(2026, 10, 20, 9, 0, 0, 0, ict)
		var produced, buffer, stored []string
		var bufEntries []collector.LogEntry
		sincePoll, sameSecond := 0, 0

		poll := func() {
			fresh := w.Filter("R1", bufEntries)
			for _, e := range fresh {
				stored = append(stored, e.Raw)
			}
			w.Advance("R1", fresh)
			sincePoll = 0
			if seed%7 == 0 { // simulate a restart: state round-trips through disk
				if err := w.Save(); err != nil {
					t.Fatal(err)
				}
				st2, err := store.LoadState(path)
				if err != nil {
					t.Fatal(err)
				}
				w = NewWatermarks(st2)
			}
		}

		for step := 0; step < 150; step++ {
			if rng.Intn(3) == 0 || sameSecond >= capacity/2 {
				clock = clock.Add(time.Second)
				sameSecond = 0
			}
			for k := rng.Intn(4); k > 0; k-- {
				sameSecond++
				raw := texts[rng.Intn(len(texts))] + " @" + clock.Format("15:04:05")
				produced = append(produced, raw)
				buffer = append(buffer, raw)
				bufEntries = append(bufEntries, entry("R1", raw, clock))
				if len(buffer) > capacity {
					buffer, bufEntries = buffer[1:], bufEntries[1:]
				}
				sincePoll++
			}
			if rng.Intn(2) == 0 || sincePoll > capacity/2 {
				poll()
			}
		}
		poll()

		if strings.Join(stored, "|") != strings.Join(produced, "|") {
			t.Fatalf("seed %d: stored %d lines, produced %d (first divergence below)\n%s",
				seed, len(stored), len(produced), firstDivergence(stored, produced))
		}
	}
}

func firstDivergence(got, want []string) string {
	for i := 0; i < len(got) && i < len(want); i++ {
		if got[i] != want[i] {
			return "at index " + strconv.Itoa(i) + ": got " + got[i] + ", want " + want[i]
		}
	}
	return "lengths differ: got " + strconv.Itoa(len(got)) + ", want " + strconv.Itoa(len(want))
}

func TestWatermarkIdenticalLinesInOneSecond(t *testing.T) {
	w, _ := newMarks(t)
	ts := time.Date(2026, 10, 20, 9, 0, 0, 0, ict)
	x := func() collector.LogEntry { return entry("R1", "Failed password for root from 1.2.3.4 port 22", ts) }

	// Poll 1 sees the first of three identical lines; poll 2 sees all three.
	w.Advance("R1", w.Filter("R1", []collector.LogEntry{x()}))
	if got := w.Filter("R1", []collector.LogEntry{x(), x(), x()}); len(got) != 2 {
		t.Fatalf("want the 2 new identical lines, got %d", len(got))
	}
	w.Advance("R1", w.Filter("R1", []collector.LogEntry{x(), x(), x()}))
	if got := w.Filter("R1", []collector.LogEntry{x(), x(), x()}); len(got) != 0 {
		t.Fatalf("nothing is new now, got %d", len(got))
	}
	// A fourth identical line later in the same second is still seen.
	if got := w.Filter("R1", []collector.LogEntry{x(), x(), x(), x()}); len(got) != 1 {
		t.Fatalf("want exactly the 4th identical line, got %d", len(got))
	}
}

func TestWatermarkLegacyStateWithoutCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	ts := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	b := entry("R1", "b", ts)
	// A state file from before last_second_count existed.
	old := `{"R1":{"last_seen_time":"2026-10-20T09:00:00Z","last_line_hash":"` + b.ID + `"}}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	w := NewWatermarks(st)
	got := w.Filter("R1", []collector.LogEntry{entry("R1", "a", ts), b, entry("R1", "c", ts)})
	if rawsOf(got) != "c" {
		t.Fatalf("hash fallback broke for legacy state: %s", rawsOf(got))
	}
}

func TestPossibleGapAndDropFuture(t *testing.T) {
	w, _ := newMarks(t)
	t0 := time.Date(2026, 10, 20, 9, 0, 0, 0, ict)
	mk := func(from, n int) []collector.LogEntry {
		var es []collector.LogEntry
		for i := 0; i < n; i++ {
			es = append(es, entry("R1", "line"+strconv.Itoa(from+i), t0.Add(time.Duration(from+i)*time.Second)))
		}
		return es
	}
	if w.PossibleGap("R1", mk(0, 100)) {
		t.Error("no watermark yet: cannot be a gap")
	}
	w.Advance("R1", mk(0, 100)) // watermark = t0+99s
	if w.PossibleGap("R1", mk(50, 100)) {
		t.Error("overlapping buffer is not a gap")
	}
	if !w.PossibleGap("R1", mk(150, 100)) {
		t.Error("a full buffer with no overlap should be reported as a possible gap")
	}
	if w.PossibleGap("R1", mk(150, 5)) {
		t.Error("a few new lines on a quiet device are not a gap")
	}

	now := t0.Add(time.Hour)
	kept, dropped := DropFuture([]collector.LogEntry{
		entry("R1", "ok", now.Add(-time.Minute)),
		entry("R1", "edge", now.Add(5*time.Minute)),
		entry("R1", "future", now.Add(6*time.Hour)),
	}, now, 10*time.Minute)
	if dropped != 1 || len(kept) != 2 || kept[1].Raw != "edge" {
		t.Fatalf("DropFuture kept %d dropped %d", len(kept), dropped)
	}
}

func TestDetectorGarbageCollectsIdleState(t *testing.T) {
	f := newFixture()
	for i := 0; i < 200; i++ {
		e := ev("R1", EventLoginFailure, "AUTH", "Failed password", f.now.Add(-time.Minute))
		e.SourceIP = "198.51.100." + strconv.Itoa(i)
		f.d.Observe(e)
	}
	f.d.Observe(ev("R1", EventLinkDown, "FAULT", "Interface Gi0/1, changed state to down", f.now.Add(-time.Minute)))
	f.d.Observe(ev("R1", EventConfigChange, "CONFIG", "commit[1]", f.now.Add(-time.Minute)))
	if st := f.d.devices["R1"]; st == nil || len(st.loginFails) != 200 {
		t.Fatalf("expected 200 tracked source IPs before the sweep")
	}

	f.now = f.now.Add(gcInterval + time.Minute) // everything above is now far outside its window
	f.d.Observe(ev("R2", EventUnknown, "SYSTEM", "tick", f.now))
	if _, still := f.d.devices["R1"]; still {
		t.Fatalf("idle device state must be swept: %+v", f.d.devices["R1"])
	}
}

func TestDetectorPrimeRestoresWindowsWithoutSignals(t *testing.T) {
	raw := "Interface GigabitEthernet0/1, changed state to down"
	now := time.Date(2026, 10, 20, 10, 30, 0, 0, time.UTC)
	mkDet := func() *Detector { return NewDetector(DetectorConfig{Now: func() time.Time { return now }}) }

	// Two link-downs from the previous cron run plus one now make a flap.
	d := mkDet()
	d.Prime([]collector.LogEntry{
		ev("SW1", EventLinkDown, "FAULT", raw, now.Add(-3*time.Minute)),
		ev("SW1", EventLinkDown, "FAULT", raw, now.Add(-4*time.Minute)), // unsorted on purpose
	})
	s := d.Observe(ev("SW1", EventLinkDown, "FAULT", raw, now.Add(-time.Minute)))
	if len(s) != 1 || s[0].Playbook != PlaybookLinkFlap {
		t.Fatalf("primed history must complete a flap, got %+v", s)
	}

	// Priming itself never emits signals, even for events that would.
	d = mkDet()
	if got := d.Observe(ev("R1", EventOSPFAdjDown, "FAULT", "x", now.Add(-time.Minute))); len(got) != 1 {
		t.Fatal("control: normal observe must signal")
	}
	d = mkDet()
	d.Prime([]collector.LogEntry{ev("R1", EventOSPFAdjDown, "FAULT", "x", now.Add(-time.Minute))})
	if len(d.devices) != 0 && d.priming {
		t.Fatal("priming flag must be cleared afterwards")
	}

	// A config change from the previous run still explains a fault now.
	d = mkDet()
	cfg := ev("R1", EventConfigChange, "CONFIG", "commit[1]", now.Add(-5*time.Minute))
	cfg.User = "tanvt"
	d.Prime([]collector.LogEntry{cfg})
	s = d.Observe(ev("R1", EventBGPPeerDown, "FAULT", "x", now.Add(-time.Minute)))
	if len(s) != 1 || len(s[0].Annotations) != 1 || !strings.Contains(s[0].Annotations[0], "tanvt") {
		t.Fatalf("primed config change must annotate the fault, got %+v", s)
	}

	// A stored LINK_FLAP restores its suppression: no duplicate individual signals.
	d = mkDet()
	flap := ev("SW1", EventLinkFlap, "FAULT", raw, now.Add(-2*time.Minute))
	d.Prime([]collector.LogEntry{flap})
	if s := d.Observe(ev("SW1", EventLinkDown, "FAULT", raw, now.Add(-time.Minute))); len(s) != 0 {
		t.Fatalf("a flap reported by the previous run must stay suppressed, got %+v", s)
	}
}

// ---- own-session suppressor -----------------------------------------------------

func TestSuppressOwn(t *testing.T) {
	ts := time.Date(2026, 10, 23, 15, 24, 58, 0, ict)
	e := func(raw string) collector.LogEntry {
		return collector.LogEntry{Raw: raw, Timestamp: ts}
	}

	// --- entries that MUST be suppressed (all from the first live run) ---
	suppressed := []string{
		// PAM env deprecation
		"Oct 23 15:24:58 NHG-TRANSIT-GW-01 sshd[283444]: pam_env(sshd:session): deprecated reading of user environment enabled",
		// PAM session opened
		"Oct 23 15:24:58 NHG-TRANSIT-GW-01 sshd[283444]: pam_unix(sshd:session): session opened for user nms-net(uid=1004) by (uid=0)",
		// PAM session closed
		"Oct 23 15:25:03 NHG-TRANSIT-GW-01 sshd[283444]: pam_unix(sshd:session): session closed for user nms-net",
		// systemd session started
		"Oct 23 15:24:58 NHG-TRANSIT-GW-01 systemd[1]: Started Session 899 of User nms-net.",
		// systemd session removed
		"Oct 23 15:25:03 NHG-TRANSIT-GW-01 systemd[1]: Removed Session 899 of User nms-net.",
		// systemd-logind new session
		"Oct 23 15:24:58 NHG-TRANSIT-GW-01 systemd-logind[986]: New session 899 of user nms-net.",
		// systemd-logind removed session
		"Oct 23 15:25:03 NHG-TRANSIT-GW-01 systemd-logind[986]: Removed session 899 of user nms-net.",
		// systemd session scope deactivated
		"Oct 23 15:25:03 NHG-TRANSIT-GW-01 systemd[1]: session-899.scope: Deactivated successfully.",
		// VyOS config-mount unit
		"Oct 23 15:24:58 NHG-TRANSIT-GW-01 systemd[1]: opt-vyatta-config-tmp-new_config_283448.mount: Deactivated successfully.",
		// uppercase variant (case-insensitive)
		"Oct 23 15:24:58 NHG-TRANSIT-GW-01 systemd[1]: Session-1234.SCOPE: Activated successfully.",
		// systemd-logind without "of user"
		"Oct 27 15:57:00 NHG-VYOS systemd-logind[980]: Removed session 966.",
		"Oct 27 15:57:00 NHG-VYOS systemd-logind[980]: Session 966 logged out. Waiting for processes to exit.",
		// sshd signal error
		"Oct 27 15:57:00 NHG-VYOS sshd[249974]: error: session_signal_req: no pid for session 0",
		// user runtime manager
		"Oct 27 15:41:14 NHG-VYOS systemd[1]: Starting User Manager for UID 1004...",
		"Oct 27 15:41:14 NHG-VYOS systemd[1]: Started User Manager for UID 1004.",
		"Oct 27 15:41:14 NHG-VYOS systemd[1]: Created slice User Slice of UID 1004.",
		"Oct 27 15:41:14 NHG-VYOS systemd[1]: Finished User Runtime Directory /run/user/1004.",
		"Oct 27 15:41:15 NHG-VYOS systemd[247600]: Reached target default.target - Main User Target.",
		"Oct 27 15:41:15 NHG-VYOS systemd[247600]: Queued start job for default target default.target.",
		"Oct 27 15:41:14 NHG-VYOS (systemd)[247600]: pam_unix(systemd-user:session): session opened for user sysadmin(uid=1004) by (uid=0)",
		// rsyslog mark
		"Oct 27 15:37:55 NHG-VYOS rsyslogd[8010]: -- MARK --",
		// logrotate
		"Oct 27 16:00:09 NHG-VYOS systemd[1]: Starting Rotate log files...",
		"Oct 27 16:00:09 NHG-VYOS systemd[1]: Finished Rotate log files.",
		"Oct 27 16:00:09 NHG-VYOS systemd[1]: logrotate.service: Deactivated successfully.",
		// cron maintenance
		"Oct 27 15:17:01 NHG-VYOS CRON[247503]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
		"Oct 27 15:17:01 NHG-VYOS CRON[247503]: pam_unix(cron:session): session closed for user root",
		"Oct 27 15:17:01 NHG-VYOS CRON[247504]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)",
		"Oct 25 06:25:01 NHG-VyOS CRON[244992]: (CRON) info (No MTA installed, discarding output)",
		"Oct 25 06:25:01 NHG-VyOS CRON[244993]: (root) CMD (test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; })",
		// kernel noise
		"Oct 27 07:00:01 NHG-MIT-GW-02 kernel: ll header: 00000000: ff ff ff ff ff ff fa 16 3e 24 fe 8a 08 06",
		"Oct 27 07:00:01 NHG-MIT-GW-02 kernel: net_ratelimit: 45 callbacks suppressed",
		// IPC debug messages
		`Oct 27 06:59:55 NHG-MIT-GW-01 keepalived-fifo.py[424042]: Received message: INSTANCE "LAN" MASTER_RX_LOWER_PRI 150`,
		`Oct 27 06:59:55 NHG-MIT-GW-01 keepalived-fifo.py[424042]: INSTANCE LAN changed state to MASTER_RX_LOWER_PRI`,
		`Oct 27 15:56:08 NHG-VYOS vyos-configd[798]: Received message: {"type": "init"}`,
		`Oct 27 15:56:09 NHG-VYOS vyos-configd[798]: commit_scripts: ['policy']`,
		`Oct 27 15:56:09 NHG-VYOS vyos-configd[798]: scripts_called: ['policy']`,
		`Oct 27 15:56:09 NHG-VYOS vyos-configd[798]: config session pid is 249598`,
		`Oct 27 15:53:17 NHG-VYOS vyos-configd[798]: Sending reply: ERROR_COMMIT with output`,
		`Oct 27 15:56:10 NHG-VYOS vyos-configd[798]: Sending reply: SUCCESS with output`,
		`Oct 27 15:56:10 NHG-VYOS watchfrr[1402]: [VTVCM-Y2NW3] Configuration Read in Took: 00:00:00`,
		`Oct 27 15:56:10 NHG-VYOS watchfrr[1402]: [WFP93-1D146] configuration write completed with exit code 0`,
	}
	for _, raw := range suppressed {
		got := SuppressOwn([]collector.LogEntry{e(raw)})
		if len(got) != 0 {
			t.Errorf("SuppressOwn must drop:\n  %s\ngot %d entries", raw, len(got))
		}
	}

	// --- entries that MUST NOT be suppressed (real security / fault events) ---
	kept := []string{
		// Real SSH login failure (brute-force candidate)
		"Oct 23 15:24:58 NHG-TRANSIT-GW-01 sshd[1234]: Failed password for nms-net from 203.0.113.9 port 4444 ssh2",
		// Real SSH login success from a non-polling IP
		"Oct 23 15:24:58 NHG-TRANSIT-GW-01 sshd[1234]: Accepted publickey for nms-net from 10.1.1.50 port 22 ssh2",
		// Link down — contains "session" nowhere but present as a sanity check
		"Oct 23 15:24:58 NHG-TRANSIT-GW-01 kernel: e1000e: eth1 NIC Link is Down",
		// BGP neighbour down
		"Oct 23 15:24:58 NHG-TRANSIT-GW-01 bgpd: %ADJCHG: Neighbor 10.255.255.1 Down",
		// Generic INFO
		"Oct 23 15:24:58 NHG-TRANSIT-GW-01 sshd[9]: Server listening on 0.0.0.0 port 22.",
	}
	for _, raw := range kept {
		got := SuppressOwn([]collector.LogEntry{e(raw)})
		if len(got) != 1 {
			t.Errorf("SuppressOwn must keep:\n  %s\ngot %d entries", raw, len(got))
		}
	}

	// Empty input returns empty output without panic.
	if got := SuppressOwn(nil); got != nil {
		t.Errorf("nil input: want nil, got %v", got)
	}
	if got := SuppressOwn([]collector.LogEntry{}); len(got) != 0 {
		t.Errorf("empty input: want empty, got %d", len(got))
	}

	// Mixed batch: only noisy lines are stripped; order of clean lines is preserved.
	mixed := []collector.LogEntry{
		e("Oct 23 15:24:58 GW sshd[1]: Accepted password for admin from 10.0.0.1 port 22 ssh2"),
		e("Oct 23 15:24:58 GW systemd[1]: Started Session 1 of User nms-net."),
		e("Oct 23 15:24:58 GW kernel: eth0 NIC Link is Down"),
		e("Oct 23 15:24:58 GW systemd-logind[2]: New session 1 of user nms-net."),
		e("Oct 23 15:24:58 GW sshd[3]: Failed password for root from 198.51.100.7 port 22 ssh2"),
	}
	got := SuppressOwn(mixed)
	if len(got) != 3 {
		t.Fatalf("mixed batch: want 3 clean entries, got %d", len(got))
	}
	if got[0].Raw != mixed[0].Raw || got[1].Raw != mixed[2].Raw || got[2].Raw != mixed[4].Raw {
		t.Errorf("mixed batch order wrong: %v", got)
	}

	// No-match fast path: original slice is returned (pointer equality).
	clean := []collector.LogEntry{e("kernel: eth0 NIC Link is Down")}
	if &SuppressOwn(clean)[0] != &clean[0] {
		t.Error("fast path must return the original slice when nothing is suppressed")
	}
}

func TestClassifierOpticsAndVendorRouting(t *testing.T) {
	c := NewClassifier(time.UTC)
	tests := []struct{ raw, event string }{
		{"%SFF8472-5-THRESHOLD_VIOLATION: Gi1/0/1: Rx power low alarm; Operating value: -25.3 dBm", EventOpticsAlarm},
		{"OPTMOD/4/MODULE_INFO: Optical module on interface 10GE1/0/1 Rx power is too low", EventOpticsAlarm},
		{"transceiver loss of signal on Ethernet1", EventOpticsAlarm},
		{"rpd[1234]: RPD_OSPF_NBRDOWN: OSPF neighbor 10.0.0.2 (ge-0/0/1.0) state changed from Full to Down", EventOSPFAdjDown},
		{"rpd[1234]: RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 10.0.0.9 (External AS 65001) changed state from Established to Idle", EventBGPPeerDown},
		{"%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down", EventLinkDown},
		{"Power supply 2 failed", EventHardwareFault},
	}
	for _, tc := range tests {
		e := collector.LogEntry{Raw: tc.raw, Timestamp: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
		c.Classify(&e)
		if e.Event != tc.event {
			t.Errorf("%q: event %s, want %s", tc.raw, e.Event, tc.event)
		}
	}
}

// ---- PAN-OS and MikroTik classification -----------------------------------------------

func TestClassifyPaloAltoAndMikroTik(t *testing.T) {
	c := NewClassifier(time.UTC)
	ts := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC) // outside the after-hours window
	tests := []struct {
		name, raw, category, event string
	}{
		{"pan config", `1,2026/10/20 09:30:59,001234567890,CONFIG,0,0,2026/10/20 09:30:59,10.1.1.5,vsys1,set,tanvt,Web,Succeeded, /config/shared,,,1,0x0`, "CONFIG", EventConfigChange},
		{"pan threat", `1,2026/10/20 09:32:59,001234567890,THREAT,vulnerability,2305,2026/10/20 09:32:59,203.0.113.9,10.0.0.5,SSH User Authentication Brute-force login Attempt(40015),high`, "SECURITY", EventThreatDetected},
		{"pan system login failure", `1,2026/10/20 09:30:14,001234567890,SYSTEM,general,0,2026/10/20 09:30:14,vsys1,general,,0,0,general,high,Login failed for user admin`, "AUTH", EventLoginFailure},
		{"pan traffic stays unclassified", `1,2026/10/20 09:31:58,001234567890,TRAFFIC,end,2305,2026/10/20 09:31:58,10.0.0.5,8.8.8.8,allow-dns,dns,allow`, "SYSTEM", EventUnknown},
		{"mikrotik change", "Oct 20 09:31:02 edge-rtr2 system,info ip address added by tanvt", "CONFIG", EventConfigChange},
		{"mikrotik log print change", "09:31:02 system,info filter rule changed by tanvt", "CONFIG", EventConfigChange},
		{"mikrotik login is not a change", "Oct 20 09:31:01 edge-rtr2 system,info,account user admin logged in from 10.1.1.1 via ssh", "AUTH", EventLoginSuccess},
		{"mikrotik link", "Oct 20 09:31:00 edge-rtr2 interface,info ether1 link down", "FAULT", EventLinkDown},
		{"cumulus bgp", "2026-10-20T09:31:03+07:00 leaf01 bgpd[987]: %ADJCHANGE: neighbor 10.0.0.2(swp1) in vrf default Down Peer closed the session", "FAULT", EventBGPPeerDown},
		{"cumulus link", "Oct 20 09:31:02 leaf01 switchd[1234]: swp1: link down", "FAULT", EventLinkDown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := collector.LogEntry{Raw: tc.raw, Timestamp: ts}
			c.Classify(&e)
			if e.Category != tc.category || e.Event != tc.event {
				t.Errorf("got %s/%s, want %s/%s", e.Category, e.Event, tc.category, tc.event)
			}
		})
	}
}

// ---- config-change signals (opt-in) ------------------------------------------------------

func TestConfigSignalsAreOptIn(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-time.Minute)
	mk := func(on bool) *Detector {
		return NewDetector(DetectorConfig{ConfigSignals: on, Now: func() time.Time { return now }})
	}

	// Default: configuration changes only feed fault correlation.
	if s := mk(false).Observe(ev("R1", EventConfigChange, "CONFIG", "x", recent)); len(s) != 0 {
		t.Fatalf("default detector signalled a config change: %+v", s)
	}

	for _, event := range []string{EventConfigChange, EventAfterHoursChange} {
		d := mk(true)
		s := d.Observe(ev("R1", event, "CONFIG", "x", recent))
		if len(s) != 1 || s[0].Playbook != PlaybookConfigChange || s[0].Priority != PriorityLow || s[0].Derived {
			t.Fatalf("%s: %+v", event, s)
		}
	}

	// Stale history (first-poll backfill) and detector priming never signal.
	if s := mk(true).Observe(ev("R1", EventConfigChange, "CONFIG", "x", now.Add(-24*time.Hour))); len(s) != 0 {
		t.Errorf("stale config change signalled: %+v", s)
	}
	d := mk(true)
	d.Prime([]collector.LogEntry{ev("R1", EventConfigChange, "CONFIG", "x", recent)})

	// The fault correlation still works with signalling on.
	d = mk(true)
	d.Observe(ev("R1", EventConfigChange, "CONFIG", "x", recent))
	s := d.Observe(ev("R1", EventLinkDown, "FAULT", "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down", recent.Add(30*time.Second)))
	if len(s) != 1 || len(s[0].Annotations) != 1 || !strings.Contains(s[0].Annotations[0], "preceded this fault") {
		t.Errorf("correlation lost: %+v", s)
	}
}

func TestExtractInterfaceCumulus(t *testing.T) {
	for raw, want := range map[string]string{
		"switchd[1234]: swp1: link down":                             "swp1",
		"zebra[88]: Interface swp3 is down":                          "swp3",
		"bgpd[987]: %ADJCHANGE: neighbor 10.0.0.2(swp12) in vrf red": "swp12",
		"ospfd[55]: %ADJCHG: Nbr 10.0.0.3 on swp2s1:10.0.0.4":        "swp2s1",
	} {
		if got := ExtractInterface(raw); got != want {
			t.Errorf("ExtractInterface(%q) = %q, want %q", raw, got, want)
		}
	}
}
