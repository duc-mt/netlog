// ==============================================================================
// Package parser: fuzz and robustness tests (parsers must never panic).
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-21
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package parser

import (
	"strings"
	"testing"
	"unicode/utf8"

	"netlog/internal/collector"
)

var fuzzKeys = []string{"vyos", "cisco_ios", "cisco_asa", "cisco_sb", "huawei_vrp", "juniper_junos", "fortigate", "mikrotik", "pfsense", "checkpoint_gaia", "arista", "generic"}

var fuzzSeeds = []string{
	"Oct 20 09:30:15.123: %SYS-5-CONFIG_I: Configured from console by bachngo on vty0 (10.10.10.50)",
	"000123: *Oct 20 09:31:02.001 UTC: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
	"Oct 20 2026 09:30:15 %LINK-W-Down:  gi5",
	"2026-10-20T09:44:01+07:00 NHG-BVU-GW-01 commit[1234]: [user: tanvt] Applying config changes",
	"Oct 20 2026 09:31:02+07:00 H %%01SHELL/6/CMDRECORD(s)[9]:Record command information. (Task=VTY0, Ip=10.1.1.1, User=admin, Command=\"system-view\")",
	"Oct 20 09:30:16  sw1 rpd[1500]: RPD_OSPF_NBRDOWN: OSPF neighbor 10.1.1.2 state changed from Full to Down",
	`3: date=2026-10-20 time=09:30:15 tz="+0700" subtype="system" user="test" ui="ssh(10.1.1.9)" msg="x"`,
	"oct/19 23:59:59 system,info,account user admin logged in from 10.1.1.1 via ssh",
	"2026/10/20 09:30:15 high general general 0 Login failed for user admin",
	"Oct 20 09:30:40 gw1 php-fpm[4567]: /index.php: Successful login for user 'admin' from: 10.0.0.5 (Local Database)",
	"Oct 20 09:32:00 gw1 php-fpm[4567]: /interfaces.php: Configuration Change: admin@10.0.0.5 (Local Database): Interfaces: WAN configured",
	"Oct 20 09:30:15 2026 gw1 clish[2345]: cmd by admin: Start executing : set hostname gw1 (cmd md5: abc123)",
}

// checkEntries asserts the invariants every parser promises.
func checkEntries(t *testing.T, key, raw string, es []collector.LogEntry) {
	t.Helper()
	for _, e := range es {
		if e.Raw == "" || e.ID != collector.EntryID(testDev.Hostname, e.Raw) {
			t.Fatalf("%s: bad Raw/ID for input %q: %+v", key, raw, e)
		}
		if e.DeviceTS.IsZero() || e.DeviceTS.Year() < 1900 || e.DeviceTS.Year() > 2200 {
			t.Fatalf("%s: implausible DeviceTS %v for %q", key, e.DeviceTS, e.Raw)
		}
		if !e.Timestamp.Equal(e.DeviceTS) {
			t.Fatalf("%s: Timestamp must start equal to DeviceTS", key)
		}
		if strings.ContainsAny(e.Raw, "\r\n") {
			t.Fatalf("%s: Raw must be a single line: %q", key, e.Raw)
		}
		if !utf8.ValidString(e.Summary) {
			t.Fatalf("%s: Summary is not valid UTF-8: %q", key, e.Summary)
		}
		if e.User != strings.TrimSpace(e.User) {
			t.Fatalf("%s: user not trimmed %q", key, e.User)
		}
	}
}

func FuzzParse(f *testing.F) {
	for i := range fuzzKeys {
		for _, s := range fuzzSeeds {
			f.Add(uint8(i), s)
		}
	}
	f.Fuzz(func(t *testing.T, k uint8, raw string) {
		key := fuzzKeys[int(k)%len(fuzzKeys)]
		checkEntries(t, key, raw, Parse(key, raw, testDev, testOpt))
	})
}

// TestParsersSurviveMutations is the deterministic cousin of FuzzParse that
// runs in every "go test": every prefix and suffix of every seed line, plus
// single-byte corruptions, through every parser.
func TestParsersSurviveMutations(t *testing.T) {
	for _, key := range fuzzKeys {
		for _, seed := range fuzzSeeds {
			for i := 0; i <= len(seed); i++ {
				for _, in := range []string{seed[:i], seed[i:]} {
					checkEntries(t, key, in, Parse(key, in, testDev, testOpt))
				}
			}
			for i := 0; i < len(seed); i++ {
				for _, b := range []byte{0, '\n', '%', ':', ' ', '9', 0xff} {
					m := []byte(seed)
					m[i] = b
					checkEntries(t, key, string(m), Parse(key, string(m), testDev, testOpt))
				}
			}
		}
	}
}
