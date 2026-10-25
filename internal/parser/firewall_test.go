// ==============================================================================
// Package parser: tests for the pfSense and Check Point Gaia parsers.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-24
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// The sample lines follow the documented formats of each platform; they are
// not captured from a live device (see the package comment in firewall.go).
package parser

import (
	"testing"
	"time"
)

func TestPfsenseSamples(t *testing.T) {
	tests := []struct {
		name, line      string
		ts              time.Time
		facility        string
		user, src, sess string
	}{
		{"sshd accepted",
			"Oct 20 09:30:15 gw1 sshd[1234]: Accepted password for admin from 10.0.0.5 port 5555 ssh2",
			time.Date(2026, 10, 20, 9, 30, 15, 0, testLoc), "SEC", "admin", "10.0.0.5", ""},
		{"web gui login (colon after from)",
			"Oct 20 09:30:40 gw1 php-fpm[4567]: /index.php: Successful login for user 'admin' from: 10.0.0.5 (Local Database)",
			time.Date(2026, 10, 20, 9, 30, 40, 0, testLoc), "SEC", "admin", "10.0.0.5", ""},
		{"web gui failure",
			"Oct 20 09:31:00 gw1 php-fpm[4567]: /index.php: webConfigurator authentication error for user 'root' from: 203.0.113.9",
			time.Date(2026, 10, 20, 9, 31, 0, 0, testLoc), "SEC", "root", "203.0.113.9", ""},
		{"configuration change",
			"Oct 20 09:32:00 gw1 php-fpm[4567]: /interfaces.php: Configuration Change: admin@10.0.0.5 (Local Database): Interfaces: WAN configured",
			time.Date(2026, 10, 20, 9, 32, 0, 0, testLoc), "SYS", "admin", "10.0.0.5", ""},
		{"kernel link",
			"Oct 20 09:33:00 gw1 kernel: igb0: link state changed to DOWN",
			time.Date(2026, 10, 20, 9, 33, 0, 0, testLoc), "LINK", "", "", ""},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			e := parseOne(t, "pfsense", c.line)
			if !e.DeviceTS.Equal(c.ts) || e.Facility != c.facility || e.User != c.user || e.SourceIP != c.src || e.SessionID != c.sess {
				t.Errorf("got ts=%v fac=%q user=%q src=%q sess=%q\nwant ts=%v fac=%q user=%q src=%q sess=%q",
					e.DeviceTS, e.Facility, e.User, e.SourceIP, e.SessionID, c.ts, c.facility, c.user, c.src, c.sess)
			}
			if e.Vendor != "pfsense" || e.Raw != c.line {
				t.Errorf("vendor/raw not carried: %q %q", e.Vendor, e.Raw)
			}
		})
	}
}

// tail over two files interleaves them: the parser keeps buffer order (its
// contract) and drops what is not a log line.
func TestPfsenseTwoFilesAndNoise(t *testing.T) {
	raw := "Oct 20 09:31:00 gw1 sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2\n" +
		"==> /var/log/auth.log <==\n" +
		"\n" +
		"Oct 20 09:30:00 gw1 kernel: igb0: link state changed to UP\n" +
		"last message repeated 3 times\n"
	got := Parse("pfsense", raw, testDev, testOpt)
	if len(got) != 2 || got[0].Facility != "SEC" || got[1].Facility != "LINK" {
		t.Fatalf("got %d entries: %+v", len(got), got)
	}
	if !got[0].DeviceTS.After(got[1].DeviceTS) {
		t.Error("buffer order must be preserved (the watermark sorts, not the parser)")
	}
}

func TestGaiaSamples(t *testing.T) {
	tests := []struct {
		name, line string
		ts         time.Time
		user, src  string
	}{
		{"year after the time of day",
			"Oct 20 09:30:15 2026 gw1 sshd[1234]: Accepted password for admin from 10.0.0.5 port 5555 ssh2",
			time.Date(2026, 10, 20, 9, 30, 15, 0, testLoc), "admin", "10.0.0.5"},
		{"clish command",
			"Oct 20 09:31:00 2026 gw1 clish[2345]: cmd by admin: Start executing : set hostname gw1 (cmd md5: abc123)",
			time.Date(2026, 10, 20, 9, 31, 0, 0, testLoc), "admin", ""},
		{"explicit year wins over the reference year",
			"Dec 31 23:59:59 2025 gw1 sshd[1]: Failed password for admin from 203.0.113.9 port 22 ssh2",
			time.Date(2025, 12, 31, 23, 59, 59, 0, testLoc), "admin", "203.0.113.9"},
		{"no year: falls back to the shared syslog splitter",
			"Oct 20 09:32:00 gw1 sshd[1]: Failed password for admin from 203.0.113.9 port 22 ssh2",
			time.Date(2026, 10, 20, 9, 32, 0, 0, testLoc), "admin", "203.0.113.9"},
		{"year before the time of day (RFC 3164 variant)",
			"Oct 20 2026 09:33:00 gw1 sshd[1]: Failed password for admin from 203.0.113.9 port 22 ssh2",
			time.Date(2026, 10, 20, 9, 33, 0, 0, testLoc), "admin", "203.0.113.9"},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			e := parseOne(t, "checkpoint_gaia", c.line)
			if !e.DeviceTS.Equal(c.ts) || e.User != c.user || e.SourceIP != c.src {
				t.Errorf("got ts=%v user=%q src=%q, want ts=%v user=%q src=%q", e.DeviceTS, e.User, e.SourceIP, c.ts, c.user, c.src)
			}
		})
	}
}

func TestGaiaDropsMalformedLines(t *testing.T) {
	for name, line := range map[string]string{
		"day 32":         "Oct 32 09:30:15 2026 gw1 sshd[1]: x",
		"bad month":      "Foo 20 09:30:15 2026 gw1 sshd[1]: x",
		"no program":     "Oct 20 09:30:15 2026 gw1 something without a colon",
		"banner":         "[Expert@gw1:0]# tail -n 300 /var/log/messages",
		"repeat marker":  "last message repeated 3 times",
		"implausible yr": "Oct 20 09:30:15 1970 gw1 sshd[1]: x",
	} {
		if got := Parse("checkpoint_gaia", line, testDev, testOpt); len(got) != 0 {
			t.Errorf("%s: want the line dropped, got %+v", name, got)
		}
	}
}

// A quoted user name is trimmed, and a blank one is no user. (Found by the
// byte-corruption pass over the pfSense seeds: "user ' dmin'".)
func TestQuotedUserIsTrimmed(t *testing.T) {
	e := parseOne(t, "pfsense", "Oct 20 09:30:40 gw1 php-fpm[1]: /index.php: Successful login for user '  admin  ' from: 10.0.0.5")
	if e.User != "admin" || e.SourceIP != "10.0.0.5" {
		t.Errorf("user=%q src=%q, want admin / 10.0.0.5", e.User, e.SourceIP)
	}
	e = parseOne(t, "pfsense", "Oct 20 09:30:40 gw1 php-fpm[1]: /index.php: Successful login for user '   ' from: 10.0.0.5")
	if e.User != "" {
		t.Errorf("a blank quoted name must give no user, got %q", e.User)
	}
}
