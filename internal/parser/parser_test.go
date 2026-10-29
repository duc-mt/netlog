// ==============================================================================
// Package parser: tests for the vendor log parsers.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package parser

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"netlog/internal/collector"
	"netlog/internal/inventory"
)

var (
	testLoc = time.FixedZone("ICT", 7*3600)
	testRef = time.Date(2026, 10, 20, 10, 0, 0, 0, testLoc)
	testOpt = Options{Ref: testRef, Location: testLoc}
	testDev = inventory.Device{Hostname: "SW1", Address: "10.0.0.1", Vendor: "x"}
)

func parseOne(t *testing.T, key, line string) collector.LogEntry {
	t.Helper()
	got := Parse(key, line, testDev, testOpt)
	if len(got) != 1 {
		t.Fatalf("%s: want 1 entry for %q, got %d", key, line, len(got))
	}
	return got[0]
}

func TestSpecSamples(t *testing.T) {
	tests := []struct {
		name, key, line string
		ts              time.Time
		facility        string
		user, src, sess string
	}{
		{"cisco config", "cisco_ios",
			"Oct 20 09:30:15.123: %SYS-5-CONFIG_I: Configured from console by bachngo on vty0 (10.10.10.50)",
			time.Date(2026, 10, 20, 9, 30, 15, 123e6, testLoc), "SYS", "bachngo", "10.10.10.50", "vty0"},
		{"cisco link", "cisco_ios",
			"Oct 20 09:31:02.001: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
			time.Date(2026, 10, 20, 9, 31, 2, 1e6, testLoc), "LINK", "", "", ""},
		{"cisco seq+star+zone", "cisco_ios",
			"000123: *Oct 20 09:31:02.001 UTC: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.255.4 on Gi0/1 from FULL to DOWN, Neighbor Down: Dead timer expired",
			time.Date(2026, 10, 20, 9, 31, 2, 1e6, testLoc), "OSPF", "", "", ""},
		{"cisco asa", "cisco_asa",
			"Oct 20 2026 09:30:15: %ASA-6-302013: Built inbound TCP connection 1 for outside:1.1.1.1/1234",
			time.Date(2026, 10, 20, 9, 30, 15, 0, testLoc), "ASA", "", "", ""},
		{"cisco login", "cisco_ios",
			"Oct 20 09:30:15: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 10.1.1.1] [localport: 22] at 09:30:15 UTC Tue Oct 20 2026",
			time.Date(2026, 10, 20, 9, 30, 15, 0, testLoc), "SEC", "admin", "10.1.1.1", ""},
		{"cisco sb", "cisco_sb",
			"Oct 20 2026 09:30:15 %LINK-W-Down:  gi5",
			time.Date(2026, 10, 20, 9, 30, 15, 0, testLoc), "LINK", "", "", ""},
		{"vyos iso", "vyos",
			"2026-10-20T09:44:01+07:00 NHG-BVU-GW-01 commit[1234]: [user: tanvt] Applying config changes",
			time.Date(2026, 10, 20, 9, 44, 1, 0, testLoc), "SYS", "tanvt", "", ""},
		{"vyos commit 1.4", "vyos",
			"Oct 20 09:44:02 vyos commit[249867]: Successful change to active configuration by user langpx on /dev/pts/7",
			time.Date(2026, 10, 20, 9, 44, 2, 0, testLoc), "SYS", "langpx", "", "/dev/pts/7"},
		{"vyos sudo_user", "vyos",
			"Oct 20 09:44:02 vyos vyos-configd[798]: config session sudo_user is langpx",
			time.Date(2026, 10, 20, 9, 44, 2, 0, testLoc), "SYS", "langpx", "", ""},
		{"vyos kernel", "vyos",
			"2026-10-20T09:44:03+07:00 NHG-BVU-GW-01 kernel: eth1: renamed from vethXXX",
			time.Date(2026, 10, 20, 9, 44, 3, 0, testLoc), "SYS", "", "", ""},
		{"vyos 3164 ssh", "vyos",
			"Oct 20 09:44:05 vyos sshd[77]: Failed password for invalid user admin from 203.0.113.9 port 4444 ssh2",
			time.Date(2026, 10, 20, 9, 44, 5, 0, testLoc), "SEC", "admin", "203.0.113.9", ""},
		{"huawei cmdrecord", "huawei_vrp",
			"Oct 20 2026 09:31:02+07:00 NHG-HO-GW-01 %%01SHELL/5/CMDRECORD(l)[123]:bachngo: interface GigabitEthernet0/0/1 shutdown",
			time.Date(2026, 10, 20, 9, 31, 2, 0, testLoc), "SHELL", "bachngo", "", ""},
		{"huawei long cmdrecord", "huawei_vrp",
			`Oct 20 2026 02:31:02+00:00 HOST %%01SHELL/6/CMDRECORD(s)[9]:Record command information. (Task=VTY0, Ip=10.1.1.1, VpnName=, User=admin, Command="system-view")`,
			time.Date(2026, 10, 20, 2, 31, 2, 0, time.UTC), "SHELL", "admin", "10.1.1.1", "VTY0"},
		{"junos commit", "juniper_junos",
			"Oct 20 09:30:15  sw1 mgd[1234]: UI_COMMIT: User 'tanvt' requested 'commit' operation (comment: none)",
			time.Date(2026, 10, 20, 9, 30, 15, 0, testLoc), "SYS", "tanvt", "", ""},
		{"junos year suffix", "juniper_junos",
			"Oct 20 09:30:15.203 2026  VPTTN-TTN-NET-Pro-8F-CORE-01-9-251-U31 dot1xd[1850]: devrt_rtsock Don't know how to handle message type 2",
			time.Date(2026, 10, 20, 9, 30, 15, 203000000, testLoc), "SYS", "", "", ""},
		{"junos ospf", "juniper_junos",
			"Oct 20 09:30:16  sw1 rpd[1500]: RPD_OSPF_NBRDOWN: OSPF neighbor 10.1.1.2 (realm ospf-v2 ge-0/0/1.0 area 0.0.0.0) state changed from Full to Down",
			time.Date(2026, 10, 20, 9, 30, 16, 0, testLoc), "OSPF", "", "", ""},
		{"fortigate", "fortigate",
			`3: date=2026-10-20 time=09:30:15 eventtime=1760927415123456789 tz="+0700" logid="0100032001" type="event" subtype="system" level="alert" logdesc="Admin login failed" user="test" ui="ssh(10.1.1.9)" msg="Administrator test login failed from ssh(10.1.1.9)"`,
			time.Date(2026, 10, 20, 9, 30, 15, 0, testLoc), "SYS", "test", "10.1.1.9", "ssh"},
		{"mikrotik today", "mikrotik",
			"09:31:00 interface,info ether1 link down",
			time.Date(2026, 10, 20, 9, 31, 0, 0, testLoc), "LINK", "", "", ""},
		{"mikrotik dated", "mikrotik",
			"oct/19 23:59:59 system,info,account user admin logged in from 10.1.1.1 via ssh",
			time.Date(2026, 10, 19, 23, 59, 59, 0, testLoc), "SEC", "admin", "10.1.1.1", ""},
		{"arista generic", "arista",
			"Oct 20 09:30:15 sw9 Ebra: %LINEPROTO-5-UPDOWN: Line protocol on Interface Ethernet1, changed state to down",
			time.Date(2026, 10, 20, 9, 30, 15, 0, testLoc), "LINK", "", "", ""},
		{"panos generic", "paloalto",
			"2026/10/20 09:30:15 high general general 0 Login failed for user admin",
			time.Date(2026, 10, 20, 9, 30, 15, 0, testLoc), "SEC", "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := parseOne(t, tc.key, tc.line)
			if !e.DeviceTS.Equal(tc.ts) {
				t.Errorf("DeviceTS = %v, want %v", e.DeviceTS, tc.ts)
			}
			if !e.Timestamp.Equal(tc.ts) || e.Timestamp.Location() != time.UTC {
				t.Errorf("Timestamp = %v, want UTC %v", e.Timestamp, tc.ts.UTC())
			}
			if e.Facility != tc.facility {
				t.Errorf("Facility = %q, want %q", e.Facility, tc.facility)
			}
			if e.User != tc.user || e.SourceIP != tc.src || e.SessionID != tc.sess {
				t.Errorf("attribution = (%q,%q,%q), want (%q,%q,%q)", e.User, e.SourceIP, e.SessionID, tc.user, tc.src, tc.sess)
			}
			wantRaw := tc.line
			if tc.key == "fortigate" {
				wantRaw = strings.TrimPrefix(tc.line, "3: ")
			}
			if e.Raw != wantRaw {
				t.Errorf("Raw not preserved:\n got %q\nwant %q", e.Raw, wantRaw)
			}
			if e.Hostname != "SW1" || e.IP != "10.0.0.1" || e.Vendor != tc.key || e.Summary == "" {
				t.Errorf("identity fields wrong: %+v", e)
			}
			if e.ID != collector.EntryID("SW1", wantRaw) {
				t.Errorf("ID mismatch")
			}
		})
	}
}

func TestSummaries(t *testing.T) {
	e := parseOne(t, "huawei_vrp", "Oct 20 2026 09:31:02+07:00 H %%01SHELL/5/CMDRECORD(l)[1]:bachngo: interface GigabitEthernet0/0/1 shutdown")
	if e.Summary != "interface GigabitEthernet0/0/1 shutdown" {
		t.Errorf("huawei summary = %q", e.Summary)
	}
	e = parseOne(t, "huawei_vrp", `Oct 20 2026 09:31:02+07:00 H %%01SHELL/6/CMDRECORD(s)[1]:Record command information. (Task=VTY0, Ip=1.1.1.1, VpnName=, User=a, Command="display ip routing-table")`)
	if e.Summary != "display ip routing-table" {
		t.Errorf("huawei long summary = %q", e.Summary)
	}
}

func TestYearInference(t *testing.T) {
	// A December line fetched in early January belongs to the previous year.
	o := Options{Ref: time.Date(2027, 1, 1, 0, 5, 0, 0, testLoc), Location: testLoc}
	got := Parse("cisco_ios", "Dec 31 23:59:00: %SYS-5-CONFIG_I: Configured from console by a on vty0 (1.1.1.1)", testDev, o)
	if len(got) != 1 || got[0].DeviceTS.Year() != 2026 {
		t.Fatalf("year not rolled back: %+v", got)
	}
	// A stamp a few hours ahead of the fetch time (device clock fast) stays in the current year.
	o = Options{Ref: time.Date(2026, 10, 20, 9, 0, 0, 0, testLoc), Location: testLoc}
	got = Parse("cisco_ios", "Oct 20 12:00:00: %LINK-3-UPDOWN: Interface Gi1, changed state to down", testDev, o)
	if len(got) != 1 || got[0].DeviceTS.Year() != 2026 {
		t.Fatalf("future-by-hours stamp misdated: %+v", got)
	}
}

func TestMalformedLinesDropped(t *testing.T) {
	raw := strings.Join([]string{
		"Syslog logging: enabled (0 messages dropped, 0 flushes, 0 overruns)",
		"Log Buffer (65536 bytes):",
		"",
		"1d02h: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down", // uptime stamp: no wall clock
		"garbage ### line",
		"Oct 20 09:30:15: %LINK-3-UPDOWN: Interface Gi0/2, changed state to down",
		"Foo 99 25:61:61: %X-1-Y: bad",
	}, "\r\n")
	got := Parse("cisco_ios", raw, testDev, testOpt)
	if len(got) != 1 || !strings.Contains(got[0].Raw, "Gi0/2") {
		t.Fatalf("expected exactly the one valid line, got %d: %+v", len(got), got)
	}
}

func TestFortigateInteractiveNoise(t *testing.T) {
	raw := "FGT-01 # execute log filter category 1\r\nFGT-01 # execute log display\r\n" +
		"10 logs found.\r\n10 logs returned.\r\n\r\n" +
		`1: date=2026-10-20 time=09:30:15 tz="+0700" subtype="system" logdesc="Admin login successful" user="admin" ui="https(10.1.1.1)" msg="Administrator admin logged in successfully from https(10.1.1.1)"` + "\r\n" +
		`2: date=2026-10-20 time=09:30:16 subtype="system" logdesc="Attribute configured" cfgpath="system.interface" user="admin"` + "\r\nFGT-01 # "
	got := Parse("fortigate", raw, testDev, testOpt)
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got))
	}
	if strings.HasPrefix(got[0].Raw, "1:") {
		t.Errorf("index prefix not stripped: %q", got[0].Raw)
	}
	// Same line at a different page index must keep the same dedup ID.
	again := Parse("fortigate", "7: "+got[0].Raw, testDev, testOpt)
	if len(again) != 1 || again[0].ID != got[0].ID {
		t.Errorf("ID not stable across page indexes")
	}
}

func TestForDispatch(t *testing.T) {
	for key, want := range map[string]string{
		"vyos": "*parser.vyosParser", "cisco_ios": "*parser.ciscoParser", "cisco_asa": "*parser.ciscoParser",
		"huawei_vrp": "*parser.huaweiParser", "juniper_junos": "*parser.junosParser", "fortigate": "*parser.fortigateParser",
		"mikrotik": "*parser.mikrotikParser", "arista": "*parser.genericParser", "ruijie": "*parser.genericParser", "generic": "*parser.genericParser",
		"pfsense": "*parser.pfsenseParser", "checkpoint_gaia": "*parser.gaiaParser",
	} {
		if got := typeName(For(key, testOpt)); got != want {
			t.Errorf("For(%q) = %s, want %s", key, got, want)
		}
	}
}

func typeName(p Parser) string {
	if c, ok := p.(*checkedParser); ok {
		p = c.inner
	}
	switch p.(type) {
	case *vyosParser:
		return "*parser.vyosParser"
	case *ciscoParser:
		return "*parser.ciscoParser"
	case *huaweiParser:
		return "*parser.huaweiParser"
	case *junosParser:
		return "*parser.junosParser"
	case *fortigateParser:
		return "*parser.fortigateParser"
	case *mikrotikParser:
		return "*parser.mikrotikParser"
	case *pfsenseParser:
		return "*parser.pfsenseParser"
	case *gaiaParser:
		return "*parser.gaiaParser"
	case *genericParser:
		return "*parser.genericParser"
	}
	return "?"
}

func TestInvalidDateRejected(t *testing.T) {
	if got := Parse("generic", "2026-13-40 09:30:15 something happened", testDev, testOpt); len(got) != 0 {
		t.Fatalf("month 13 must be rejected, got %+v", got)
	}
}

func TestImplausibleTimestampsDropped(t *testing.T) {
	// A corrupted year, a far-future date, and a pre-1990 date are rejected;
	// a clock that is merely wrong by years in the past (unset RTC) is kept.
	lines := map[string]bool{
		"9026-10-20T09:44:01+07:00 R1 commit[1]: x":           false,
		"2031-10-20T09:44:01+07:00 R1 commit[1]: x":           false, // years ahead
		"1970-01-01T00:00:05+00:00 R1 kernel: boot":           false,
		"2001-01-01T00:00:05+00:00 R1 kernel: rtc not set":    true,
		"2026-10-21T08:00:00+07:00 R1 kernel: a day ahead ok": true,
	}
	for line, keep := range lines {
		got := Parse("vyos", line, testDev, testOpt)
		if (len(got) == 1) != keep {
			t.Errorf("%q: kept=%v, want %v", line, len(got) == 1, keep)
		}
	}
}

func TestOverlongLinesAreClamped(t *testing.T) {
	long := "Oct 20 09:30:15: %SYS-5-CONFIG_I: Configured from console by a on vty0 (1.1.1.1) " + strings.Repeat("é", 20000)
	got := Parse("cisco_ios", long, testDev, testOpt)
	if len(got) != 1 || len(got[0].Raw) > maxLineLen || !utf8.ValidString(got[0].Raw) {
		t.Fatalf("overlong line not clamped safely: %d entries, raw %d bytes", len(got), len(got[0].Raw))
	}
	again := Parse("cisco_ios", long, testDev, testOpt)
	if again[0].ID != got[0].ID {
		t.Error("clamped line must keep a stable ID across polls")
	}
}

func TestInvalidUTF8IsReplacedConsistently(t *testing.T) {
	line := "Oct 20 09:30:15: %SYS-5-CONFIG_I: Configured from console by b\xe9\xff on vty0 (10.10.10.50)"
	got := Parse("cisco_ios", line, testDev, testOpt)
	if len(got) != 1 || !utf8.ValidString(got[0].Raw) || !utf8.ValidString(got[0].Summary) {
		t.Fatalf("invalid UTF-8 must be sanitized: %+v", got)
	}
	var back collector.LogEntry
	b, _ := json.Marshal(got[0])
	if err := json.Unmarshal(b, &back); err != nil || back.Raw != got[0].Raw || back.ID != collector.EntryID(testDev.Hostname, back.Raw) {
		t.Fatalf("Raw must survive JSON unchanged so the ID still matches: %v", err)
	}
}

// ---- PAN-OS, Cumulus and forwarded MikroTik syslog ---------------------------------

func TestPaloAltoForwardedSyslog(t *testing.T) {
	const (
		system  = `Oct 20 09:30:15 pa-fw1 1,2026/10/20 09:30:14,001234567890,SYSTEM,general,0,2026/10/20 09:30:14,vsys1,general,,0,0,general,high,"Login failed for user admin from 10.1.1.9",123456,0x0,0,0,0,0,,pa-fw1`
		config  = `Oct 20 09:31:00 pa-fw1 1,2026/10/20 09:30:59,001234567890,CONFIG,0,0,2026/10/20 09:30:59,10.1.1.5,vsys1,set,tanvt,Web,Succeeded, /config/shared/log-settings,,,123457,0x0,0,0,0,0,,pa-fw1`
		traffic = `2026-10-20T09:32:00+07:00 pa-fw1 1,2026/10/20 09:31:58,001234567890,TRAFFIC,end,2305,2026/10/20 09:31:58,10.0.0.5,8.8.8.8,0.0.0.0,0.0.0.0,allow-dns,,,dns,vsys1,trust,untrust,ethernet1/1,ethernet1/2,fwd,2026/10/20 09:31:58,1001,1,5555,53,0,0,0x19,udp,allow,200,100,100,2,2026/10/20 09:31:50,8,any,0,1,0x0`
		threat  = `Oct 20 09:33:00 pa-fw1 1,2026/10/20 09:32:59,001234567890,THREAT,vulnerability,2305,2026/10/20 09:32:59,203.0.113.9,10.0.0.5,0.0.0.0,0.0.0.0,inbound,,,ssh,vsys1,untrust,trust,ethernet1/2,ethernet1/1,fwd,2026/10/20 09:32:59,1002,1,4444,22,0,0,0x2000,tcp,reset-both,,SSH User Authentication Brute-force Attempt(40015),any,high,client-to-server,1`
	)
	tests := []struct {
		name, line, facility string
		ts                   time.Time
		user, src, summary   string
	}{
		{"system", system, "SEC", time.Date(2026, 10, 20, 9, 30, 14, 0, testLoc), "admin", "10.1.1.9", "Login failed for user admin from 10.1.1.9"},
		{"config", config, "CFG", time.Date(2026, 10, 20, 9, 30, 59, 0, testLoc), "tanvt", "10.1.1.5", "tanvt set /config/shared/log-settings (Succeeded)"},
		{"traffic", traffic, "TRAFFIC", time.Date(2026, 10, 20, 9, 31, 58, 0, testLoc), "", "", "10.0.0.5 -> 8.8.8.8 dns rule allow-dns allow"},
		{"threat", threat, "THREAT", time.Date(2026, 10, 20, 9, 32, 59, 0, testLoc), "", "", "SSH User Authentication Brute-force Attempt(40015) 203.0.113.9 -> 10.0.0.5 reset-both high"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := parseOne(t, "paloalto", tc.line)
			if !e.DeviceTS.Equal(tc.ts) {
				t.Errorf("DeviceTS = %v, want %v", e.DeviceTS, tc.ts)
			}
			if e.Facility != tc.facility {
				t.Errorf("Facility = %q, want %q", e.Facility, tc.facility)
			}
			if e.User != tc.user || e.SourceIP != tc.src {
				t.Errorf("attribution = (%q,%q), want (%q,%q)", e.User, e.SourceIP, tc.user, tc.src)
			}
			if e.Summary != tc.summary {
				t.Errorf("Summary = %q, want %q", e.Summary, tc.summary)
			}
			if e.Raw != tc.line || e.ID != collector.EntryID("SW1", tc.line) {
				t.Errorf("Raw / ID not preserved")
			}
		})
	}
}

func TestPaloAltoKeepsShowLogSystemFormat(t *testing.T) {
	e := parseOne(t, "paloalto", "2026/10/20 09:30:15 high general general 0 Login failed for user admin")
	if !e.DeviceTS.Equal(time.Date(2026, 10, 20, 9, 30, 15, 0, testLoc)) || e.Facility != "SEC" {
		t.Errorf("show log system line misparsed: %+v", e)
	}
}

func TestPaloAltoShortAndHostileRecords(t *testing.T) {
	// Too short for its type: still an entry (header fields are present), no panic.
	short := "Oct 20 09:30:15 pa-fw1 1,2026/10/20 09:30:14,001234567890,SYSTEM,general,0,2026/10/20 09:30:14,vsys1"
	e := parseOne(t, "paloalto", short)
	if e.Facility == "" || e.Summary == "" {
		t.Errorf("short record: %+v", e)
	}
	// Not a PAN-OS record at all, a bad time, an unknown type: dropped, never panicking.
	for _, line := range []string{
		"Oct 20 09:30:15 pa-fw1 a,b,c,d,e,f,g,h,i",
		"1,not-a-time,001,SYSTEM,general,0,not-a-time,x",
		"1,2026/10/20 09:30:14,001,BOGUS,general,0,2026/10/20 09:30:14,x",
		`1,2026/10/20 09:30:14,001,"SYSTEM,general,0,2026/10/20 09:30:14,x`,
		strings.Repeat(",", 5000),
	} {
		if got := Parse("paloalto", line, testDev, testOpt); len(got) > 1 {
			t.Errorf("%q: %d entries", line, len(got))
		}
	}
}

func TestCumulusSyslog(t *testing.T) {
	tests := []struct {
		name, line, facility string
		ts                   time.Time
		user, src            string
	}{
		{"switchd link", "Oct 20 09:31:02 leaf01 switchd[1234]: swp1: link down", "LINK", time.Date(2026, 10, 20, 9, 31, 2, 0, testLoc), "", ""},
		{"bgpd iso", "2026-10-20T09:31:03.123456+07:00 leaf01 bgpd[987]: %ADJCHANGE: neighbor 10.0.0.2(swp1) in vrf default Down Peer closed the session", "BGP", time.Date(2026, 10, 20, 9, 31, 3, 123456000, time.FixedZone("+07:00", 7*3600)), "", ""},
		{"ospfd", "Oct 20 09:31:04 leaf01 ospfd[55]: %ADJCHG: Nbr 10.0.0.3 on swp2:10.0.0.4 from Full to Down", "OSPF", time.Date(2026, 10, 20, 9, 31, 4, 0, testLoc), "", ""},
		{"mstpd", "Oct 20 09:31:05 leaf01 mstpd: topology change detected on bridge br_default", "STP", time.Date(2026, 10, 20, 9, 31, 5, 0, testLoc), "", ""},
		{"zebra", "Oct 20 09:31:06 leaf01 zebra[88]: Interface swp3 is down", "LINK", time.Date(2026, 10, 20, 9, 31, 6, 0, testLoc), "", ""},
		{"sshd", "Oct 20 09:31:07 leaf01 sshd[5]: Accepted publickey for cumulus from 10.1.1.5 port 5555 ssh2", "SEC", time.Date(2026, 10, 20, 9, 31, 7, 0, testLoc), "cumulus", "10.1.1.5"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := parseOne(t, "cumulus", tc.line)
			if !e.DeviceTS.Equal(tc.ts) || e.Facility != tc.facility || e.User != tc.user || e.SourceIP != tc.src {
				t.Errorf("got ts=%v fac=%q user=%q src=%q, want ts=%v fac=%q user=%q src=%q",
					e.DeviceTS, e.Facility, e.User, e.SourceIP, tc.ts, tc.facility, tc.user, tc.src)
			}
			if e.Raw != tc.line || e.Vendor != "cumulus" {
				t.Errorf("Raw/Vendor wrong: %+v", e)
			}
		})
	}
	if got := Parse("cumulus", "not a syslog line\n\n   \nOct 20 09:31:07", testDev, testOpt); len(got) != 0 {
		t.Errorf("garbage produced %d entries", len(got))
	}
}

func TestMikroTikForwardedSyslog(t *testing.T) {
	tests := []struct {
		name, line, facility, user, src string
		sec                             int
	}{
		{"interface", "Oct 20 09:31:00 edge-rtr2 interface,info ether1 link down", "LINK", "", "", 0},
		{"account", "Oct 20 09:31:01 edge-rtr2 system,info,account user admin logged in from 10.1.1.1 via ssh", "SEC", "admin", "10.1.1.1", 1},
		{"system change", "Oct 20 09:31:02 edge-rtr2 system,info ip address added by tanvt", "SYS", "tanvt", "", 2},
		{"firewall", "Oct 20 09:31:03 edge-rtr2 firewall,info DROP-IN: in:ether1 out:(unknown 0), proto TCP (SYN), 203.0.113.9:4444->198.51.100.1:22, len 60", "FW", "", "", 3},
		{"colon form", "Oct 20 09:31:04 edge-rtr2 system,error,critical: login failure for user admin from 10.1.1.1 via ssh", "SYS", "admin", "10.1.1.1", 4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := parseOne(t, "mikrotik", tc.line)
			if e.Facility != tc.facility || e.User != tc.user || e.SourceIP != tc.src {
				t.Errorf("got fac=%q user=%q src=%q, want %q %q %q", e.Facility, e.User, e.SourceIP, tc.facility, tc.user, tc.src)
			}
			if !e.DeviceTS.Equal(time.Date(2026, 10, 20, 9, 31, tc.sec, 0, testLoc)) {
				t.Errorf("DeviceTS = %v", e.DeviceTS)
			}
		})
	}
	// The /log print forms keep working next to the forwarded one.
	if e := parseOne(t, "mikrotik", "09:31:00 interface,info ether1 link down"); e.Facility != "LINK" {
		t.Errorf("log print form regressed: %+v", e)
	}
	// A plain syslog line without "topic,severity" is not a RouterOS line.
	if got := Parse("mikrotik", "Oct 20 09:31:00 edge-rtr2 sshd[1]: hello", testDev, testOpt); len(got) != 0 {
		t.Errorf("non-RouterOS syslog line accepted: %+v", got)
	}
}
