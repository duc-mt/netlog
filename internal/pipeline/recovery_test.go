// ==============================================================================
// Package pipeline: tests for recovery events and the additional fault classes.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-24
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package pipeline

import "testing"

// Each pair is a "down" line and its "up" counterpart. What matters is that a
// down is never mistaken for an up (first match wins and several down lines
// contain words like FULL or UP) and that both halves name the same Object,
// because the report pairs them on (device, kind, object).
func TestRecoveryPairs(t *testing.T) {
	tests := []struct {
		name, key, line, cat, event, object string
	}{
		// Cisco IOS link
		{"ios link down", "cisco_ios", "Oct 20 09:31:02.001: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down", "FAULT", EventLinkDown, "GigabitEthernet0/1"},
		{"ios link up", "cisco_ios", "Oct 20 09:31:09.001: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up", "SYSTEM", EventLinkUp, "GigabitEthernet0/1"},
		{"ios line protocol down", "cisco_ios", "Oct 20 09:31:02.002: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to down", "FAULT", EventLinkDown, "GigabitEthernet0/1"},
		{"ios line protocol up", "cisco_ios", "Oct 20 09:31:09.002: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to up", "SYSTEM", EventLinkUp, "GigabitEthernet0/1"},

		// Cisco OSPF: both lines contain FULL, only the direction differs
		{"ospf down", "cisco_ios", "000123: *Oct 20 09:31:02.001 UTC: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.255.4 on GigabitEthernet0/1 from FULL to DOWN, Neighbor Down: Dead timer expired", "FAULT", EventOSPFAdjDown, "10.255.255.4"},
		{"ospf up", "cisco_ios", "000124: *Oct 20 09:31:40.001 UTC: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.255.4 on GigabitEthernet0/1 from LOADING to FULL, Loading Done", "SYSTEM", EventOSPFAdjUp, "10.255.255.4"},

		// Junos OSPF and link trap
		{"junos ospf down", "juniper_junos", "Oct 20 09:30:16  sw1 rpd[1500]: RPD_OSPF_NBRDOWN: OSPF neighbor 10.1.1.2 (realm ospf-v2 ge-0/0/0.0 area 0.0.0.0) state changed from Full to Down due to KillNbr", "FAULT", EventOSPFAdjDown, "10.1.1.2"},
		{"junos ospf up", "juniper_junos", "Oct 20 09:30:46  sw1 rpd[1500]: RPD_OSPF_NBRUP: OSPF neighbor 10.1.1.2 (realm ospf-v2 ge-0/0/0.0 area 0.0.0.0) state changed from Loading to Full due to LoadDone", "SYSTEM", EventOSPFAdjUp, "10.1.1.2"},
		{"junos link down", "juniper_junos", "Oct 20 09:30:16  sw1 mib2d[1]: SNMP_TRAP_LINK_DOWN: ifIndex 507, ifAdminStatus up(1), ifOperStatus down(2), ifName ge-0/0/1", "FAULT", EventLinkDown, "ge-0/0/1"},
		{"junos link up", "juniper_junos", "Oct 20 09:30:26  sw1 mib2d[1]: SNMP_TRAP_LINK_UP: ifIndex 507, ifAdminStatus up(1), ifOperStatus up(1), ifName ge-0/0/1", "SYSTEM", EventLinkUp, "ge-0/0/1"},

		// BGP
		{"bgp down", "cisco_ios", "Oct 20 09:31:02.001: %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down BGP Notification sent", "FAULT", EventBGPPeerDown, "10.0.0.1"},
		{"bgp up", "cisco_ios", "Oct 20 09:32:02.001: %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Up", "SYSTEM", EventBGPPeerUp, "10.0.0.1"},
		{"frr bgp up", "vyos", "2026-10-20T09:44:01+07:00 R1 bgpd[123]: %ADJCHANGE: neighbor 10.0.0.1 Up", "SYSTEM", EventBGPPeerUp, "10.0.0.1"},

		// Huawei
		{"huawei link down", "huawei_vrp", "Oct 20 2026 09:31:02+07:00 H %%01IFNET/4/LINK_STATE(l)[1]:The line protocol IP on the interface GigabitEthernet0/0/1 has entered the DOWN state.", "FAULT", EventLinkDown, "GigabitEthernet0/0/1"},
		{"huawei link up", "huawei_vrp", "Oct 20 2026 09:31:09+07:00 H %%01IFNET/4/LINK_STATE(l)[2]:The line protocol IP on the interface GigabitEthernet0/0/1 has entered the UP state.", "SYSTEM", EventLinkUp, "GigabitEthernet0/0/1"},

		// Linux kernel
		{"linux link down", "vyos", "Oct 20 09:44:05 vyos kernel: [123.45] eth1: Link is Down", "FAULT", EventLinkDown, "eth1"},
		{"linux link up", "vyos", "Oct 20 09:44:15 vyos kernel: [133.45] eth1: Link is Up - 1Gbps/Full", "SYSTEM", EventLinkUp, "eth1"},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			e := classified(t, c.key, c.line)
			if e.Event != c.event || e.Category != c.cat || e.Object != c.object {
				t.Errorf("got %s/%s object %q, want %s/%s object %q\n%s", e.Category, e.Event, e.Object, c.cat, c.event, c.object, c.line)
			}
		})
	}
}

// Recovery events are SYSTEM/INFO on purpose: counted as FAULT they would
// inflate the noisy-device ranking with the end of every outage.
func TestRecoveryEventsAreNotFaults(t *testing.T) {
	for _, line := range []string{
		"Oct 20 09:31:09.001: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up",
		"Oct 20 09:32:02.001: %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Up",
	} {
		if e := classified(t, "cisco_ios", line); e.Category == "FAULT" || e.Severity != "INFO" {
			t.Errorf("%s classified %s/%s", line, e.Category, e.Severity)
		}
	}
}

// Intermediate and teardown states are neither a recovery nor an outage, and
// must not be read as one just because the line mentions FULL or UP.
func TestNotARecovery(t *testing.T) {
	for name, line := range map[string]string{
		"ospf full to loading":   "Oct 20 09:31:02.001: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.255.4 on GigabitEthernet0/1 from FULL to LOADING, Bad LS Req",
		"ospf 2way to exstart":   "Oct 20 09:31:02.001: %OSPF-5-ADJCHG: Process 1, Nbr 10.255.255.4 on GigabitEthernet0/1 from 2WAY to EXSTART, Negotiation Done",
		"bgp bounce reason":      "Oct 20 09:31:02.001: %BGP-3-NOTIFICATION: received from neighbor 10.0.0.1 4/0 (hold time expired) 0 bytes",
		"bgp word containing up": "Oct 20 09:31:02.001: %BGP-4-MSGDUMP: unsupported or mal-formatted message received from 10.0.0.1",
		"temperature normal":     "Oct 20 09:30:15: %ENVM-6-INFO: Temperature is normal",
		"fan speed":              "Oct 20 09:30:15: %ENVM-6-INFO: Fan speed set to auto",
	} {
		if e := classified(t, "cisco_ios", line); e.Event != EventUnknown || e.Object != "" {
			t.Errorf("%s: got %s object %q, want UNKNOWN", name, e.Event, e.Object)
		}
	}
}

func TestAdditionalFaultClasses(t *testing.T) {
	tests := []struct {
		name, key, line, event string
	}{
		{"fortigate ha", "fortigate", `3: date=2026-10-20 time=09:30:15 tz="+0700" subtype="ha" level="critical" msg="Virtual cluster 1 detected a new primary"`, EventHAChange},
		{"asa failover", "cisco_asa", "Oct 20 2026 09:30:15: %ASA-1-104001: (Primary) Switching to ACTIVE - Other unit wants me Active.", EventHAChange},
		{"asa lost failover", "cisco_asa", "Oct 20 2026 09:30:15: %ASA-1-105005: (Primary) Lost Failover communications with mate on interface inside", EventHAChange},
		// The reason text says "is down": HA must win over the link rule.
		{"clusterxl", "generic", "Oct 20 09:30:15 gw1 kernel: [fw4_0];CLUS-114904-1: State change: Active -> Standby | Reason: Interface eth1 is down", EventHAChange},
		{"fan failed", "cisco_ios", "Oct 20 09:30:15: %ENVMON-2-FAN_FAILED: Fan 1 has failed", EventHardwareFault},
		{"temp high", "cisco_ios", "Oct 20 09:30:15: %ENVM-1-TEMP: Temperature is too high on slot 1", EventHardwareFault},
		{"psu removed", "cisco_ios", "Oct 20 09:30:15: %PLATFORM-2-PS: Power supply 2 removed", EventHardwareFault},
		{"bpduguard", "cisco_ios", "Oct 20 09:30:15: %PM-4-ERR_DISABLE: bpduguard error detected on Gi0/1, putting Gi0/1 in err-disable state", EventPortErrDisable},
		{"port security", "cisco_ios", "Oct 20 09:30:15: %PORT_SECURITY-2-PSECURE_VIOLATION: Security violation occurred, caused by MAC address 0000.1111.2222 on port GigabitEthernet0/2.", EventPortErrDisable},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			e := classified(t, c.key, c.line)
			if e.Event != c.event || e.Category != "FAULT" {
				t.Errorf("got %s/%s, want FAULT/%s\n%s", e.Category, e.Event, c.event, c.line)
			}
		})
	}
}

// The new classes have no playbook: stored and reported, but they must not
// start a triage (the detector only reacts to the events it has playbooks for).
func TestNewEventsRaiseNoSignals(t *testing.T) {
	f := newFixture()
	for _, c := range []struct{ key, line string }{
		{"cisco_ios", "Oct 20 09:31:09.001: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up"},
		{"cisco_ios", "Oct 20 09:30:15: %ENVMON-2-FAN_FAILED: Fan 1 has failed"},
		{"cisco_ios", "Oct 20 09:30:15: %PM-4-ERR_DISABLE: bpduguard error detected on Gi0/1, putting Gi0/1 in err-disable state"},
		{"cisco_asa", "Oct 20 2026 09:30:15: %ASA-1-104001: (Primary) Switching to ACTIVE - Other unit wants me Active."},
	} {
		e := classified(t, c.key, c.line)
		e.Timestamp = f.now
		if sigs := f.d.Observe(e); len(sigs) != 0 {
			t.Errorf("%s raised %d signal(s)", e.Event, len(sigs))
		}
	}
}
