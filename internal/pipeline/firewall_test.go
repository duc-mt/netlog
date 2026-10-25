// ==============================================================================
// Package pipeline: pfSense and Check Point lines through parse + classify.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-24
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// The sample lines follow the documented formats of each platform; they are
// not captured from a live device (see internal/parser/firewall.go).
package pipeline

import "testing"

// What matters for these two platforms is that logins, changes and link
// events become the right events with the right user and source address:
// those feed the change-accountability and security-watchlist sections.
func TestFirewallPlatformsClassify(t *testing.T) {
	tests := []struct {
		name, key, line       string
		cat, event, user, src string
		object                string
	}{
		// pfSense
		{"pf ssh login", "pfsense", "Oct 20 09:30:15 gw1 sshd[1234]: Accepted password for admin from 10.0.0.5 port 5555 ssh2", "AUTH", EventLoginSuccess, "admin", "10.0.0.5", ""},
		{"pf web login", "pfsense", "Oct 20 09:30:40 gw1 php-fpm[4567]: /index.php: Successful login for user 'admin' from: 10.0.0.5 (Local Database)", "AUTH", EventLoginSuccess, "admin", "10.0.0.5", ""},
		{"pf web failure", "pfsense", "Oct 20 09:31:00 gw1 php-fpm[4567]: /index.php: webConfigurator authentication error for user 'root' from: 203.0.113.9", "AUTH", EventLoginFailure, "root", "203.0.113.9", ""},
		{"pf ssh failure", "pfsense", "Oct 20 09:31:05 gw1 sshd[99]: Failed password for invalid user test from 203.0.113.9 port 4444 ssh2", "AUTH", EventLoginFailure, "test", "203.0.113.9", ""},
		{"pf config change", "pfsense", "Oct 20 09:32:00 gw1 php-fpm[4567]: /interfaces.php: Configuration Change: admin@10.0.0.5 (Local Database): Interfaces: WAN configured", "CONFIG", EventConfigChange, "admin", "10.0.0.5", ""},
		{"pf link down", "pfsense", "Oct 20 09:33:00 gw1 kernel: igb0: link state changed to DOWN", "FAULT", EventLinkDown, "", "", "igb0"},
		{"pf link up", "pfsense", "Oct 20 09:33:20 gw1 kernel: igb0: link state changed to UP", "SYSTEM", EventLinkUp, "", "", "igb0"},

		// Check Point Gaia
		{"gaia ssh login", "checkpoint_gaia", "Oct 20 09:30:15 2026 gw1 sshd[1234]: Accepted password for admin from 10.0.0.5 port 5555 ssh2", "AUTH", EventLoginSuccess, "admin", "10.0.0.5", ""},
		{"gaia ssh failure", "checkpoint_gaia", "Oct 20 09:31:00 2026 gw1 sshd[1]: Failed password for admin from 203.0.113.9 port 22 ssh2", "AUTH", EventLoginFailure, "admin", "203.0.113.9", ""},
		{"gaia clish set", "checkpoint_gaia", "Oct 20 09:31:00 2026 gw1 clish[2345]: cmd by admin: Start executing : set hostname gw1 (cmd md5: abc123)", "CONFIG", EventConfigChange, "admin", "", ""},
		{"gaia clish add", "checkpoint_gaia", "Oct 20 09:31:30 2026 gw1 clish[2345]: cmd by admin: Start executing : add user bob uid 0 homedir /home/bob (cmd md5: abc123)", "CONFIG", EventConfigChange, "admin", "", ""},
		{"gaia clusterxl", "checkpoint_gaia", "Oct 20 09:32:00 2026 gw1 kernel: [fw4_0];CLUS-114904-1: State change: Active -> Standby | Reason: Interface eth1 is down", "FAULT", EventHAChange, "", "", ""},
		{"gaia link down", "checkpoint_gaia", "Oct 20 09:33:00 2026 gw1 kernel: e1000e: eth1 NIC Link is Down", "FAULT", EventLinkDown, "", "", "eth1"},
		{"gaia link up", "checkpoint_gaia", "Oct 20 09:33:20 2026 gw1 kernel: e1000e: eth1 NIC Link is Up 1000 Mbps Full Duplex", "SYSTEM", EventLinkUp, "", "", "eth1"},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			e := classified(t, c.key, c.line)
			if e.Category != c.cat || e.Event != c.event || e.User != c.user || e.SourceIP != c.src || e.Object != c.object {
				t.Errorf("got %s/%s user=%q src=%q object=%q\nwant %s/%s user=%q src=%q object=%q",
					e.Category, e.Event, e.User, e.SourceIP, e.Object, c.cat, c.event, c.user, c.src, c.object)
			}
		})
	}
}

// Read-only Gaia commands are not configuration changes: clish logs every
// command, and "show" must not light up the change report.
func TestGaiaReadOnlyCommandsAreNotChanges(t *testing.T) {
	for cmd, isChange := range map[string]bool{
		"show version all":   false,
		"show configuration": false,
		"save config":        true,
		"delete user bob":    true,
	} {
		line := "Oct 20 09:31:00 2026 gw1 clish[2345]: cmd by admin: Start executing : " + cmd + " (cmd md5: abc123)"
		if e := classified(t, "checkpoint_gaia", line); (e.Event == EventConfigChange) != isChange {
			t.Errorf("%q classified %s, want change=%v", cmd, e.Event, isChange)
		}
	}
}
