package triage

import (
	"context"
	"strings"
	"testing"

	"netlog/internal/collector"
	"netlog/internal/inventory"
	"netlog/internal/pipeline"
)

// The samples follow the documented layouts of each platform; they are
// synthetic, not captures from live devices.

const cdpSample = `-------------------------
Device ID: SW2.example.com
Entry address(es):
  IP address: 10.0.0.2
Platform: cisco WS-C3850-24P,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet1/0/24
Holdtime : 150 sec

-------------------------
Device ID: nexus9k(FOX2145)
Entry address(es):
  IPv4 Address: 10.0.0.3
Platform: N9K-C93180YC-EX,  Capabilities: Router Switch
Interface: GigabitEthernet1/0/2,  Port ID (outgoing port): Ethernet1/7
Holdtime : 140 sec
`

const aristaSample = `Interface Ethernet1 detected 1 LLDP neighbors:

  Neighbor 001c.7300.0001/Ethernet49, age 12 seconds
  Discovered 2026-10-27 10:00:00; Last changed 2026-10-27 10:00:00
  - Chassis ID type: MAC address (4)
    Chassis ID     : 001c.7300.0001
  - Port ID type: Interface name (5)
    Port ID     : "Ethernet49"
  - Time To Live: 120 seconds
  - System Name: "spine1.lab"
  - Management Address Subtype: IPv4 (1)
    Management Address     : 10.0.0.9

Interface Ethernet2 detected 1 LLDP neighbors:

  Neighbor 001c.7300.0002/Ethernet50, age 3 seconds
  - Port ID type: Interface name (5)
    Port ID     : "Ethernet50"
  - System Name: "spine2"
`

const huaweiSample = `GigabitEthernet0/0/1 has 1 neighbor(s):

Neighbor index : 1
Chassis type   : MAC address
Chassis ID     : 00e0-fc12-3456
Port ID type   : Interface name
Port ID        : GigabitEthernet0/0/24
Port description : GigabitEthernet0/0/24 Interface
System name    : SW2
Management address value : 10.0.0.2

GigabitEthernet0/0/2 has 1 neighbor(s):

Neighbor index : 1
Chassis type   : MAC address
Chassis ID     : 00e0-fc12-9999
Port ID type   : MAC address
Port ID        : 00e0-fc12-9998
Port description : GigabitEthernet0/0/7 Interface
System name    : SW3
`

const arubaSample = ` LLDP Remote Devices Information

  LocalPort | ChassisId                 PortId PortDescr SysName
  --------- + ------------------------- ------ --------- ----------------------
  1         | 00 11 22 33 44 55         24     24        Switch-B
  2         | 0011-2233-4466            25     25        Switch-C
  3         | 00 11 22 33 44 77         26
`

func TestParseNeighbors(t *testing.T) {
	tests := []struct {
		name, fam, out string
		want           []Neighbor
	}{
		{"cisco cdp", famCisco, cdpSample, []Neighbor{
			{"GigabitEthernet1/0/1", "SW2.example.com", "GigabitEthernet1/0/24", "10.0.0.2"},
			{"GigabitEthernet1/0/2", "nexus9k", "Ethernet1/7", "10.0.0.3"},
		}},
		{"arista lldp", famArista, aristaSample, []Neighbor{
			{"Ethernet1", "spine1.lab", "Ethernet49", "10.0.0.9"},
			{"Ethernet2", "spine2", "Ethernet50", ""},
		}},
		{"huawei lldp", famHuawei, huaweiSample, []Neighbor{
			{"GigabitEthernet0/0/1", "SW2", "GigabitEthernet0/0/24", "10.0.0.2"},
			{"GigabitEthernet0/0/2", "SW3", "GigabitEthernet0/0/7", ""}, // MAC port ID: description used
		}},
		{"aruba lldp", famAruba, arubaSample, []Neighbor{
			{"1", "Switch-B", "24", ""},
			{"2", "Switch-C", "25", ""},
			// row 3 has no system name column: skipped
		}},
		{"empty", famCisco, "", nil},
		{"unrelated text", famCisco, "% Invalid input detected at '^' marker.\n", nil},
		{"family without parser", famJunos, cdpSample, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseNeighbors(tc.fam, tc.out)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d neighbours %+v, want %d", len(got), got, len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("neighbour %d = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestParseNeighborsDropsHostileAdvertisements(t *testing.T) {
	for _, tc := range []struct{ name, out string }{
		{"port with command", "-----\nDevice ID: sw2\nInterface: Gi1/0/1,  Port ID (outgoing port): Gi1/0/24;reload\n"},
		{"port with substitution", "-----\nDevice ID: sw2\nInterface: Gi1/0/1,  Port ID (outgoing port): $(reload)\n"},
		{"name with quote", "-----\nDevice ID: sw2'; reload\nInterface: Gi1/0/1,  Port ID (outgoing port): Gi1/0/24\n"},
		{"name with space tail", "-----\nDevice ID: -sw2\nInterface: Gi1/0/1,  Port ID (outgoing port): Gi1/0/24\n"},
		{"port too long", "-----\nDevice ID: sw2\nInterface: Gi1/0/1,  Port ID (outgoing port): " + strings.Repeat("a", 80) + "\n"},
	} {
		if got := ParseNeighbors(famCisco, tc.out); len(got) != 0 {
			t.Errorf("%s: hostile entry survived: %+v", tc.name, got)
		}
	}
	// Garbage of every shape must not panic any parser.
	junk := []string{"", "\x00\x01\x02", strings.Repeat("-", 10000), strings.Repeat("Device ID: x\n", 1000), "|||||\n | | |\n1 | a b c d e f g h"}
	for _, fam := range []string{famCisco, famArista, famAruba, famHuawei} {
		for _, j := range junk {
			ParseNeighbors(fam, j)
		}
	}
}

func TestSameInterface(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"GigabitEthernet1/0/1", "Gi1/0/1", true},
		{"gi1/0/1", "GigabitEthernet1/0/1", true},
		{"GE0/0/1", "GigabitEthernet0/0/1", true},
		{"TenGigabitEthernet1/1/1", "Te1/1/1", true},
		{"Ethernet1", "Eth1", true},
		{"Port-channel1", "Po1", true},
		{"24", "24", true},
		{"1/24", "A1/24", true}, // number-only on one side
		{"swp1", "swp1", true},
		{"Gi1/0/1", "Gi1/0/2", false},
		{"Gi1/0/1", "Te1/0/1", false},
		{"Gi1/0/1", "Gi1/0/11", false},
		{"Ethernet1", "Ethernet12", false},
		{"", "Gi1/0/1", false},
		{"Gi", "Gi", false},
	} {
		if got := SameInterface(tc.a, tc.b); got != tc.want {
			t.Errorf("SameInterface(%q,%q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestFindPeer(t *testing.T) {
	inv := []inventory.Device{
		{Hostname: "R1", Address: "10.0.0.1"},
		{Hostname: "SW2", Address: "10.0.0.2"},
		{Hostname: "core3.example.com", Address: "10.0.0.3"},
		{Hostname: "edge4", Address: "10.0.0.4"},
	}
	for _, tc := range []struct {
		name string
		n    Neighbor
		want string
	}{
		{"fqdn advertised, short in inventory", Neighbor{RemoteName: "sw2.example.com"}, "SW2"},
		{"short advertised, fqdn in inventory", Neighbor{RemoteName: "core3"}, "core3.example.com"},
		{"case-insensitive", Neighbor{RemoteName: "EDGE4"}, "edge4"},
		{"by management address", Neighbor{RemoteName: "unknown-name", RemoteAddr: "10.0.0.4"}, "edge4"},
		{"self is never a peer", Neighbor{RemoteName: "r1", RemoteAddr: "10.0.0.1"}, ""},
		{"not in inventory", Neighbor{RemoteName: "other", RemoteAddr: "192.0.2.9"}, ""},
	} {
		d, ok := FindPeer(inv, tc.n, "R1")
		if (tc.want == "") == ok || d.Hostname != tc.want {
			t.Errorf("%s: got %q ok=%v, want %q", tc.name, d.Hostname, ok, tc.want)
		}
	}
}

// ---- engine: peer triage and config diff -----------------------------------------------

const linkDownRaw = "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/1, changed state to down"

func linkSignal(host string) pipeline.TriageSignal {
	sig := signal("LINK_DOWN", pipeline.PlaybookLinkDown, linkDownRaw)
	sig.Entry.Hostname = host
	return sig
}

// peerRig starts R1 (whose CDP table names R2) and R2, and an engine that
// knows both in its inventory.
type peerRig struct {
	eng     *Engine
	dir     string
	hook    *recordingHook
	r1, r2  *fakeDevice
	d1, d2  inventory.Device
	cdpOfR1 string
	cdpOfR2 string
}

func newPeerRig(t *testing.T, cdpOfR1 string) *peerRig {
	t.Helper()
	rig := &peerRig{cdpOfR1: cdpOfR1, cdpOfR2: "-----\nDevice ID: R1\n  IP address: 10.0.0.1\nInterface: GigabitEthernet1/0/24,  Port ID (outgoing port): GigabitEthernet1/0/1\n"}
	var host1, host2 string
	var port1, port2 int
	rig.r1, host1, port1 = startFakeDevice(t, func(cmd string) string {
		if cmd == "show cdp neighbors detail" {
			return rig.cdpOfR1
		}
		return "R1 output of " + cmd + "\n"
	})
	rig.r2, host2, port2 = startFakeDevice(t, func(cmd string) string {
		if cmd == "show cdp neighbors detail" {
			return rig.cdpOfR2
		}
		return "R2 output of " + cmd + "\n"
	})
	rig.d1 = inventory.Device{Hostname: "R1", Address: host1, Port: port1, Vendor: "cisco_ios", CredentialGroup: "default"}
	rig.d2 = inventory.Device{Hostname: "R2", Address: host2, Port: port2, Vendor: "cisco_ios", CredentialGroup: "default"}
	rig.eng, rig.dir, rig.hook = newEngine(t)
	rig.eng.cfg.Inventory = []inventory.Device{rig.d1, rig.d2}
	return rig
}

func (r *peerRig) incident(t *testing.T, host string) collector.IncidentReport {
	t.Helper()
	for _, rep := range readIncidents(t, r.dir) {
		if rep.Hostname == host {
			return rep
		}
	}
	t.Fatalf("no incident for %s", host)
	return collector.IncidentReport{}
}

const cdpNamingR2 = "-----\nDevice ID: R2.lab.local\n  IP address: 10.0.0.2\nInterface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet1/0/24\n"

func TestPeerTriageRunsOnTheRemoteEndAndLinksIncidents(t *testing.T) {
	rig := newPeerRig(t, cdpNamingR2)
	rig.eng.Handle(context.Background(), linkSignal("R1"), rig.d1)
	rig.eng.Wait()

	if n := len(readIncidents(t, rig.dir)); n != 2 {
		t.Fatalf("want 2 incidents (R1 and its peer R2), got %d", n)
	}
	parent, peer := rig.incident(t, "R1"), rig.incident(t, "R2")

	// The parent saw the neighbour table, within the GATE 3 command cap, and links the peer.
	cmds := rig.r1.commands()
	if len(cmds) > MaxCommands || cmds[len(cmds)-1] != "show cdp neighbors detail" {
		t.Errorf("R1 commands = %q", cmds)
	}
	if parent.PeerIncidentID != peer.ID || parent.PeerDevice != "R2" {
		t.Errorf("parent links peer %q/%q, want %q/R2", parent.PeerIncidentID, parent.PeerDevice, peer.ID)
	}
	if !strings.Contains(strings.Join(parent.TriageHints, "\n"), "Peer triage started on R2") {
		t.Errorf("parent hints: %q", parent.TriageHints)
	}

	// The peer ran the link playbook for ITS interface from the CDP entry, never for R1's.
	var sawPeerIface bool
	for _, c := range rig.r2.commands() {
		if strings.Contains(c, "GigabitEthernet1/0/24") {
			sawPeerIface = true
		}
		if strings.Contains(c, "GigabitEthernet1/0/1 ") || strings.HasSuffix(c, "GigabitEthernet1/0/1") {
			t.Errorf("peer was sent the parent's interface: %q", c)
		}
		if c == "show cdp neighbors detail" {
			t.Error("a peer triage must not read topology (no chained peers)")
		}
	}
	if !sawPeerIface {
		t.Errorf("peer commands %q never mention its own port", rig.r2.commands())
	}
	hints := strings.Join(peer.TriageHints, "\n")
	if !strings.Contains(hints, "remote end of the faulted link") || !strings.Contains(hints, parent.ID) {
		t.Errorf("peer hints should name the parent incident: %q", peer.TriageHints)
	}
	if strings.Contains(hints, "No CONFIG_CHANGE was seen") {
		t.Errorf("peer hints carry the local-fault CONFIG_CHANGE note: %q", peer.TriageHints)
	}
	if rig.r1.sessions != 1 || rig.r2.sessions != 1 {
		t.Errorf("sessions R1=%d R2=%d, want 1 and 1 (no loop between the two)", rig.r1.sessions, rig.r2.sessions)
	}
	if len(rig.hook.reports) != 2 {
		t.Errorf("hook saw %d incidents, want 2", len(rig.hook.reports))
	}
}

func TestPeerTriageSkippedWhenNotApplicable(t *testing.T) {
	t.Run("neighbour not in inventory", func(t *testing.T) {
		rig := newPeerRig(t, strings.ReplaceAll(cdpNamingR2, "R2.lab.local", "stranger.lab.local"))
		rig.eng.Handle(context.Background(), linkSignal("R1"), rig.d1)
		rig.eng.Wait()
		if n := len(readIncidents(t, rig.dir)); n != 1 || rig.r2.sessions != 0 {
			t.Fatalf("incidents=%d R2 sessions=%d, want 1 and 0", n, rig.r2.sessions)
		}
		p := rig.incident(t, "R1")
		if p.PeerIncidentID != "" || !strings.Contains(strings.Join(p.TriageHints, "\n"), "not in the inventory") {
			t.Errorf("parent: %+v", p)
		}
	})
	t.Run("no neighbour on the faulted port", func(t *testing.T) {
		rig := newPeerRig(t, strings.ReplaceAll(cdpNamingR2, "GigabitEthernet1/0/1,", "GigabitEthernet1/0/9,"))
		rig.eng.Handle(context.Background(), linkSignal("R1"), rig.d1)
		rig.eng.Wait()
		if len(readIncidents(t, rig.dir)) != 1 || rig.r2.sessions != 0 {
			t.Fatal("a neighbour on another port must not be triaged")
		}
	})
	t.Run("hostile advertisement", func(t *testing.T) {
		rig := newPeerRig(t, strings.ReplaceAll(cdpNamingR2, "GigabitEthernet1/0/24", "Gi1/0/24;reload"))
		rig.eng.Handle(context.Background(), linkSignal("R1"), rig.d1)
		rig.eng.Wait()
		if len(readIncidents(t, rig.dir)) != 1 || rig.r2.sessions != 0 {
			t.Fatal("hostile neighbour data must not start a peer triage")
		}
		for _, c := range rig.r2.commands() {
			if strings.Contains(c, "reload") {
				t.Fatalf("hostile text reached a device: %q", c)
			}
		}
	})
	t.Run("no inventory configured", func(t *testing.T) {
		rig := newPeerRig(t, cdpNamingR2)
		rig.eng.cfg.Inventory = nil
		rig.eng.Handle(context.Background(), linkSignal("R1"), rig.d1)
		rig.eng.Wait()
		for _, c := range rig.r1.commands() {
			if c == "show cdp neighbors detail" {
				t.Fatal("topology lookup ran without an inventory to resolve peers in")
			}
		}
		if len(readIncidents(t, rig.dir)) != 1 {
			t.Fatal("want exactly the parent incident")
		}
	})
	t.Run("not a link fault", func(t *testing.T) {
		rig := newPeerRig(t, cdpNamingR2)
		sig := signal("OSPF_ADJ_DOWN", pipeline.PlaybookOSPFAdjDown, "%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Gi1/0/1 from FULL to DOWN, Neighbor Down: Dead timer expired")
		rig.eng.Handle(context.Background(), sig, rig.d1)
		rig.eng.Wait()
		for _, c := range rig.r1.commands() {
			if c == "show cdp neighbors detail" {
				t.Fatal("only link faults read the neighbour table")
			}
		}
	})
}

func TestPeerTriageHonoursCooldownAndPeerBound(t *testing.T) {
	t.Run("peer cooldown", func(t *testing.T) {
		rig := newPeerRig(t, cdpNamingR2)
		if ok, _ := rig.eng.cooldown.Allow("R2", "LINK_DOWN"); !ok { // R2 was just triaged
			t.Fatal("setup")
		}
		rig.eng.Handle(context.Background(), linkSignal("R1"), rig.d1)
		rig.eng.Wait()
		p := rig.incident(t, "R1")
		if rig.r2.sessions != 0 || p.PeerIncidentID != "" || !strings.Contains(strings.Join(p.TriageHints, "\n"), "cooldown") {
			t.Errorf("R2 sessions=%d parent=%+v", rig.r2.sessions, p)
		}
	})
	t.Run("peer bound", func(t *testing.T) {
		if MaxPeerTriage != 5 || cap(newPeerRig(t, "").eng.peerSem) != 5 {
			t.Fatalf("peer bound must be 5, got const %d", MaxPeerTriage)
		}
		rig := newPeerRig(t, cdpNamingR2)
		for i := 0; i < MaxPeerTriage; i++ {
			rig.eng.peerSem <- struct{}{} // five peer triages already queued or running
		}
		rig.eng.Handle(context.Background(), linkSignal("R1"), rig.d1)
		rig.eng.Wait()
		p := rig.incident(t, "R1")
		if rig.r2.sessions != 0 || p.PeerIncidentID != "" || !strings.Contains(strings.Join(p.TriageHints, "\n"), "already queued or running") {
			t.Errorf("R2 sessions=%d parent=%+v", rig.r2.sessions, p)
		}
		// A refusal for lack of a slot must not have used up R2's cooldown.
		if ok, _ := rig.eng.cooldown.Allow("R2", "LINK_DOWN"); !ok {
			t.Error("peer cooldown was consumed although no peer triage ran")
		}
	})
}

func TestConfigChangeCapturesDiffInTheIncident(t *testing.T) {
	const diff = "!Contents of Running Config - startup config\n+interface Loopback99\n+ ip address 192.0.2.1 255.255.255.255\n"
	fd, host, port := startFakeDevice(t, func(cmd string) string { return diff })
	eng, dir, hook := newEngine(t)
	dev := inventory.Device{Hostname: "R1", Address: host, Port: port, Vendor: "cisco_ios", CredentialGroup: "default"}

	sig := signal("CONFIG_CHANGE", pipeline.PlaybookConfigChange, "%SYS-5-CONFIG_I: Configured from console by tanvt on vty0 (10.1.1.5)")
	sig.Entry.Category = collector.CategoryConfig
	eng.Handle(context.Background(), sig, dev)
	eng.Wait()

	if got := fd.commands(); len(got) != 1 || got[0] != "show archive config differences nvram:startup-config system:running-config" {
		t.Fatalf("device received %q", got)
	}
	rs := readIncidents(t, dir)
	if len(rs) != 1 {
		t.Fatalf("want 1 incident, got %d", len(rs))
	}
	if rs[0].Playbook != "config_change" || rs[0].ConfigDiff != diff || rs[0].PeerIncidentID != "" {
		t.Errorf("incident: %+v", rs[0])
	}
	if !strings.Contains(strings.Join(rs[0].TriageHints, "\n"), "Configuration comparison captured") {
		t.Errorf("hints: %q", rs[0].TriageHints)
	}
	if len(hook.reports) != 0 {
		t.Error("config-diff captures are evidence only and must not fire the alert hook")
	}
}

func TestConfigChangeWithoutComparisonCommandOpensNoSession(t *testing.T) {
	fd, host, port := startFakeDevice(t, func(cmd string) string { return "x" })
	eng, dir, _ := newEngine(t)
	dev := inventory.Device{Hostname: "R1", Address: host, Port: port, Vendor: "vyos", CredentialGroup: "default"}
	eng.Handle(context.Background(), signal("CONFIG_CHANGE", pipeline.PlaybookConfigChange, "commit[123]: user=vyos"), dev)
	eng.Wait()
	if fd.sessions != 0 || len(readIncidents(t, dir)) != 0 {
		t.Fatalf("sessions=%d incidents=%d, want none", fd.sessions, len(readIncidents(t, dir)))
	}
}

func TestConfigDiffOfJoinsOnlySuccessfulOutputs(t *testing.T) {
	if got := configDiffOf(nil); got != "" {
		t.Errorf("nil: %q", got)
	}
	if got := configDiffOf([]collector.DiagCmd{{Command: "(connect)", Error: "refused"}}); got != "" {
		t.Errorf("connect failure: %q", got)
	}
	two := []collector.DiagCmd{{Command: "a", Output: "one"}, {Command: "b", Error: "timeout"}, {Command: "c", Output: "three"}}
	if got := configDiffOf(two); got != "# a\none\n# c\nthree" {
		t.Errorf("joined: %q", got)
	}
}
