// ==============================================================================
// Package triage: tests for the safety gates, playbooks and the engine.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package triage

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"netlog/internal/collector"
	"netlog/internal/credentials"
	"netlog/internal/inventory"
	"netlog/internal/pipeline"
	"netlog/internal/sshclient"
	"netlog/internal/store"
)

// ---- GATE 1 ---------------------------------------------------------------------

func TestAllowlistAccepts(t *testing.T) {
	for _, cmd := range []string{
		"show ip ospf neighbor", "show ip ospf interface Gi0/1", "show interfaces ethernet eth1 physical",
		"show ip bgp neighbors 10.1.1.1", "display bgp peer", "display users online", "display cpu-usage",
		"/log print", "cat /proc/net/dev", "execute log display", "show vrrp", "show users",
		"show processes cpu sorted | head 15", "show interfaces | include up", "show x | head 5 | include y",
		"show system commit diff 0", "show system rollback compare 0 1",
		"show configuration commit changes last 1", "display configuration commit changes last 1",
		"show archive log config all", "show configuration diffs", "show session-config diff",
	} {
		if err := Check(cmd); err != nil {
			t.Errorf("Check(%q) = %v, want nil", cmd, err)
		}
	}
}

func TestAllowlistRejects(t *testing.T) {
	long := "show " + strings.Repeat("a", 300)
	for cmd, why := range map[string]string{
		"":                                   "empty",
		"conf t":                             "not allowlisted prefix",
		"configure terminal":                 "not allowlisted prefix",
		"show running-config":                "blocked word conf",
		"show startup-config":                "blocked word conf",
		"set interfaces ethernet eth0":       "not allowlisted prefix",
		"show interfaces Reset0":             "blocked word set",
		"delete file flash:x":                "not allowlisted prefix",
		"clear ip bgp *":                     "not allowlisted prefix",
		"show clear":                         "blocked word clear",
		"write memory":                       "not allowlisted prefix",
		"show write":                         "blocked word write",
		"reload":                             "not allowlisted prefix",
		"show reload":                        "blocked word reload",
		"restart ospf":                       "not allowlisted prefix",
		"show restart":                       "blocked word restart",
		"copy running-config startup-config": "not allowlisted prefix",
		"show copy":                          "blocked word copy",
		"format flash:":                      "not allowlisted prefix",
		"show format":                        "blocked word format",
		"debug ip packet":                    "not allowlisted prefix",
		"show debug ip packet":               "blocked phrase",
		"show ip route; reload":              "chaining",
		"show ip route && reboot":            "chaining",
		"show ip route `id`":                 "substitution",
		"show $(id)":                         "substitution",
		"show x > flash:out":                 "redirect",
		"show x < /etc/passwd":               "redirect",
		"show x\nreload":                     "newline injection",
		"show x\rreload":                     "CR injection",
		"show x\x00":                         "NUL",
		" show x":                            "leading space",
		"SHOW IP ROUTE":                      "prefix is case-sensitive",
		"show x | redirect flash:y":          "pipe to non-filter",
		"show x | tftp 1.1.1.1":              "pipe to non-filter",
		"show x | head 5; reboot":            "chaining after pipe",
		"show x | include a b":               "pipe arg with space",
		"show x |":                           "empty pipe stage",
		long:                                 "too long",
	} {
		if err := Check(cmd); err == nil {
			t.Errorf("Check(%q) = nil, want rejection (%s)", cmd, why)
		}
	}
}

// Every template in the playbook table, with every placeholder filled by a
// typical value and with the fallback, must pass GATE 1: a shipped playbook
// that its own gate refuses would be a silent bug.
func TestAllPlaybookTemplatesPassGate1(t *testing.T) {
	fill := strings.NewReplacer("{iface}", "GigabitEthernet0/0/1", "{peer}", "10.255.255.5", "{vyif}", "ethernet eth1 vif 100")
	n := 0
	for name, byFamily := range playbooks {
		for fam, steps := range byFamily {
			for _, s := range steps {
				for _, cmd := range []string{fill.Replace(s.tmpl), s.fallback} {
					if cmd == "" {
						continue
					}
					n++
					if err := Check(cmd); err != nil {
						t.Errorf("playbook %s/%s: %v", name, fam, err)
					}
				}
			}
		}
	}
	if n < 20 {
		t.Fatalf("only %d templates checked; table looks truncated", n)
	}
}

// Interface and peer names come from device logs and are therefore hostile
// input. Whatever a log line says, every command that results must pass GATE 1.
func TestHostileLogTextCannotSmuggleCommands(t *testing.T) {
	hostile := []string{
		"Interface eth1;reload, changed state to down",
		"Interface Gi0/1`reboot`, changed state to down",
		"Interface Gi0/1$(reboot) changed state to down",
		"Interface eth1\nreload",
		"%OSPF-5-ADJCHG: Process 1, Nbr 1.1.1.1 on Gi0/1&&reload from FULL to DOWN",
		"neighbor 10.1.1.1;reload Down",
		"Interface eth1|tftp 1.2.3.4 changed state to down",
	}
	for _, raw := range hostile {
		for _, key := range []string{"vyos", "cisco_ios", "huawei_vrp", "juniper_junos", "arista"} {
			for _, pb := range []string{pipeline.PlaybookLinkDown, pipeline.PlaybookOSPFAdjDown, pipeline.PlaybookBGPPeerDown} {
				for _, cmd := range Commands(key, pb, collector.LogEntry{Raw: raw}) {
					if err := Check(cmd); err != nil {
						t.Errorf("hostile %q on %s/%s produced unsafe command: %v", raw, key, pb, err)
					}
				}
			}
		}
	}
}

// ---- playbooks ------------------------------------------------------------------

func cmdsFor(key, pb, raw string) string {
	return strings.Join(Commands(key, pb, collector.LogEntry{Raw: raw}), " ; ")
}

func TestPlaybookCommands(t *testing.T) {
	tests := []struct {
		name, key, pb, raw, want string
	}{
		{"vyos link", "vyos", "link_down", "kernel: e1000e: eth1 NIC Link is Down",
			"show interfaces ethernet eth1 ; show interfaces ethernet eth1 physical"},
		{"vyos vlan link", "vyos", "link_flap", "kernel: eth1.100: Link is Down",
			"show interfaces ethernet eth1 vif 100 ; show interfaces ethernet eth1 vif 100 physical"},
		{"vyos link, unknown iface", "vyos", "link_down", "link went down", "show interfaces"},
		{"cisco link", "cisco_ios", "link_down", "%LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
			"show interfaces GigabitEthernet0/1 ; show interfaces GigabitEthernet0/1 transceiver detail ; show interfaces GigabitEthernet0/1 counters errors"},
		{"cisco link, no iface -> broader command only", "cisco_ios", "link_down", "something went down", "show ip interface brief"},
		{"huawei link", "huawei_vrp", "link_down", "The line protocol on the interface GigabitEthernet0/0/1 has entered the DOWN state.",
			"display interface GigabitEthernet0/0/1 ; display transceiver diagnosis interface GigabitEthernet0/0/1"},
		{"generic link", "aruba", "link_down", "Interface 1/1/24 is down", "show interface 1/1/24 ; show interface 1/1/24 transceiver"},
		{"cisco ospf", "cisco_ios", "ospf_adj_down", "%OSPF-5-ADJCHG: Process 1, Nbr 10.255.255.4 on Gi0/1 from FULL to DOWN",
			"show ip ospf neighbor ; show ip ospf interface Gi0/1"},
		{"cisco ospf, no iface", "cisco_ios", "ospf_adj_down", "OSPF neighbor down", "show ip ospf neighbor ; show ip ospf interface"},
		{"huawei ospf", "huawei_vrp", "ospf_adj_down", "OSPF neighbor Down", "display ospf peer ; display ospf interface"},
		{"junos ospf", "juniper_junos", "ospf_adj_down", "x", "show ospf neighbor ; show ospf interface"},
		{"fortigate ospf", "fortigate", "ospf_adj_down", "x", "get router info ospf neighbor ; get router info ospf interface"},
		{"arista bgp", "arista", "bgp_peer_down", "bgp neighbor 192.0.2.9 down", "show ip bgp summary ; show ip bgp neighbors 192.0.2.9"},
		{"cisco optics", "cisco_ios", "optics_alarm", "Transceiver Rx power low on interface TenGigabitEthernet1/0/1", "show interfaces TenGigabitEthernet1/0/1 transceiver detail ; show interfaces TenGigabitEthernet1/0/1 counters errors"},
		{"huawei optics", "huawei_vrp", "optics_alarm", "optical module Rx power low on interface XGigabitEthernet0/0/1", "display transceiver diagnosis interface XGigabitEthernet0/0/1 ; display interface XGigabitEthernet0/0/1"},
		{"cisco link ddm", "cisco_ios", "link_down", "Interface Gi0/1 changed state to down", "show interfaces Gi0/1 ; show interfaces Gi0/1 transceiver detail ; show interfaces Gi0/1 counters errors"},
		{"vyos bgp", "vyos", "bgp_peer_down", "bgpd: %ADJCHANGE: neighbor 192.0.2.2 Down", "show ip bgp summary ; show ip bgp neighbors 192.0.2.2"},
		{"bgp without peer -> summary only", "cisco_ios", "bgp_peer_down", "BGP down", "show ip bgp summary"},
		{"junos bgp", "juniper_junos", "bgp_peer_down", "x", "show bgp summary"},
		{"vrrp", "vyos", "vrrp_transition", "x", "show vrrp"},
		{"stp", "cisco_ios", "stp_tcn", "x", "show spanning-tree detail"},
		{"cpu cisco", "cisco_ios", "high_cpu", "x", "show processes cpu sorted | head 15"},
		{"cpu huawei", "huawei_vrp", "high_cpu", "x", "display cpu-usage"},
		{"cpu vyos", "vyos", "high_cpu", "x", "show system processes"},
		{"brute vyos", "vyos", "brute_force", "x", "show users"},
		{"brute huawei", "huawei_vrp", "brute_force", "x", "display users online"},
		{"junos link: fallback", "juniper_junos", "link_down", "x", "show interfaces terse"},
		{"config_diff vyos", "vyos", "config_diff", "x", "show system commit diff 0"},
		{"config_diff junos", "juniper_junos", "config_diff", "x", "show system rollback compare 0 1"},
		{"config_diff cisco", "cisco_ios", "config_diff", "x", "show configuration commit changes last 1"},
		{"config_diff huawei", "huawei_vrp", "config_diff", "x", "display configuration commit changes last 1"},
		{"config_diff arista", "arista", "config_diff", "x", "show configuration diffs"},
		{"mikrotik: no playbook", "mikrotik", "ospf_adj_down", "x", ""},
		{"fortigate link: fallback", "fortigate", "link_down", "x", "get system interface physical"},
		{"unknown playbook", "cisco_ios", "nope", "x", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cmdsFor(tc.key, tc.pb, tc.raw); got != tc.want {
				t.Errorf("\n got %q\nwant %q", got, tc.want)
			}
		})
	}
}

// ---- GATE 2 ---------------------------------------------------------------------

func TestCooldownPeriods(t *testing.T) {
	for event, want := range map[string]time.Duration{
		"LINK_DOWN": 10 * time.Minute, "LINK_FLAP": 10 * time.Minute, "OSPF_ADJ_DOWN": 5 * time.Minute,
		"BGP_PEER_DOWN": 5 * time.Minute, "BRUTE_FORCE_ATTEMPT": 15 * time.Minute, "STP_TCN": DefaultCooldown,
		"CONFIG_CHANGE": 2 * time.Minute, "AFTER_HOURS_CHANGE": 2 * time.Minute,
	} {
		if got := CooldownFor(event); got != want {
			t.Errorf("CooldownFor(%s) = %v, want %v", event, got, want)
		}
	}
}

func TestCooldownGate(t *testing.T) {
	now := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	cd, _ := NewCooldown("")
	cd.now = func() time.Time { return now }

	if ok, _ := cd.Allow("R1", "OSPF_ADJ_DOWN"); !ok {
		t.Fatal("first triage must be allowed")
	}
	now = now.Add(4 * time.Minute)
	ok, rem := cd.Allow("R1", "OSPF_ADJ_DOWN")
	if ok || rem != time.Minute {
		t.Fatalf("within cooldown: ok=%v remaining=%v, want false/1m", ok, rem)
	}
	if ok, _ := cd.Allow("R1", "BGP_PEER_DOWN"); !ok {
		t.Error("a different event type has its own cooldown")
	}
	if ok, _ := cd.Allow("R2", "OSPF_ADJ_DOWN"); !ok {
		t.Error("a different device has its own cooldown")
	}
	now = now.Add(time.Minute)
	if ok, _ := cd.Allow("R1", "OSPF_ADJ_DOWN"); !ok {
		t.Error("allowed again once the 5 minutes have passed")
	}
	// Denied attempts must not extend the cooldown.
	now = now.Add(4 * time.Minute)
	cd.Allow("R1", "OSPF_ADJ_DOWN")
	now = now.Add(time.Minute)
	if ok, _ := cd.Allow("R1", "OSPF_ADJ_DOWN"); !ok {
		t.Error("a denied attempt must not restart the clock")
	}
}

func TestCooldownPersistsAcrossRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".netlog_cooldown.json")
	a, err := NewCooldown(path)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := a.Allow("R1", "LINK_DOWN"); !ok {
		t.Fatal("first must pass")
	}
	b, err := NewCooldown(path) // a new process, as with cron-driven collect
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := b.Allow("R1", "LINK_DOWN"); ok {
		t.Fatal("cooldown must survive a restart")
	}
	// A corrupt file gives a usable tracker plus an error to log.
	if err := os.WriteFile(path, []byte("{oops"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := NewCooldown(path)
	if err == nil || c == nil {
		t.Fatalf("want usable tracker and an error, got %v %v", c, err)
	}
	if ok, _ := c.Allow("R1", "LINK_DOWN"); !ok {
		t.Fatal("empty tracker must allow")
	}
}

// ---- GATE 3 helpers -------------------------------------------------------------

func TestSplitHeadAndTruncate(t *testing.T) {
	if b, n := splitHead("show processes cpu sorted | head 15"); b != "show processes cpu sorted" || n != 15 {
		t.Errorf("splitHead = %q,%d", b, n)
	}
	for _, c := range []string{"show x", "show x | include y", "show x | head", "show x | head 0", "show x | head abc"} {
		if b, n := splitHead(c); b != c || n != 0 {
			t.Errorf("splitHead(%q) = %q,%d, want unchanged", c, b, n)
		}
	}
	if got := firstLines("a\nb\nc\nd\n", 2); got != "a\nb\n" {
		t.Errorf("firstLines = %q", got)
	}

	s := strings.Repeat("é", 40000) // 80000 bytes of 2-byte runes
	out := truncateOutput(s, MaxOutputBytes)
	body, marker, _ := strings.Cut(out, "\n[output truncated")
	if len(body) > MaxOutputBytes || !strings.Contains(marker, "bytes omitted") {
		t.Errorf("truncation wrong: body %d bytes, marker %q", len(body), marker)
	}
	if strings.ContainsRune(body, '\uFFFD') {
		t.Error("truncation split a multi-byte rune")
	}
	if small := "short"; truncateOutput(small, MaxOutputBytes) != small {
		t.Error("small output must pass through")
	}
}

// ---- engine, end to end against a fake SSH device --------------------------------

type fakeDevice struct {
	mu       sync.Mutex
	cmds     []string
	sessions int
	handler  func(cmd string) string
}

func (f *fakeDevice) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}

func startFakeDevice(t *testing.T, handler func(cmd string) string) (*fakeDevice, string, int) {
	t.Helper()
	dev := &fakeDevice{handler: handler}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if c.User() == "u" && string(pw) == "p" {
			return nil, nil
		}
		return nil, ssh.ErrNoAuth
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				dev.mu.Lock()
				dev.sessions++
				dev.mu.Unlock()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, _ := nc.Accept()
					go func() {
						for r := range creqs {
							if r.Type != "exec" {
								r.Reply(false, nil)
								continue
							}
							n := binary.BigEndian.Uint32(r.Payload[:4])
							cmd := string(r.Payload[4 : 4+n])
							r.Reply(true, nil)
							dev.mu.Lock()
							dev.cmds = append(dev.cmds, cmd)
							dev.mu.Unlock()
							ch.Write([]byte(dev.handler(cmd)))
							ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
							ch.Close()
							return
						}
					}()
				}
			}()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return dev, host, port
}

type recordingHook struct {
	mu      sync.Mutex
	reports []collector.IncidentReport
}

func (h *recordingHook) OnIncident(r collector.IncidentReport, _ string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reports = append(h.reports, r)
}

func newEngine(t *testing.T) (*Engine, string, *recordingHook) {
	t.Helper()
	t.Setenv("NETLOG_USERNAME", "u")
	t.Setenv("NETLOG_PASSWORD", "p")
	creds, err := credentials.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	hook := &recordingHook{}
	eng, err := New(Config{
		DataDir:   dir,
		CredStore: creds,
		SSH:       sshclient.Options{ConnectTimeout: 30 * time.Second, CommandTimeout: 30 * time.Second, HostKeyCallback: ssh.InsecureIgnoreHostKey()},
		Hook:      hook,
	})
	if err != nil {
		t.Fatal(err)
	}
	// GATE 3: a caller cannot raise the timeouts above the caps.
	if eng.sshOpts.ConnectTimeout != MaxConnectTimeout || eng.sshOpts.CommandTimeout != MaxCommandTimeout {
		t.Fatalf("timeouts not clamped: %v %v", eng.sshOpts.ConnectTimeout, eng.sshOpts.CommandTimeout)
	}
	t.Cleanup(eng.Close)
	return eng, dir, hook
}

func signal(event, playbook, raw string, annotations ...string) pipeline.TriageSignal {
	return pipeline.TriageSignal{
		Entry:       collector.LogEntry{Hostname: "R1", Event: event, Category: collector.CategoryFault, Raw: raw, Timestamp: time.Now().UTC()},
		Playbook:    playbook,
		Priority:    pipeline.PriorityHigh,
		Annotations: annotations,
	}
}

func readIncidents(t *testing.T, dir string) []collector.IncidentReport {
	t.Helper()
	rs, err := store.ListIncidents(store.IncidentsDir(dir), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestEngineRunsPlaybookAndWritesIncident(t *testing.T) {
	fd, host, port := startFakeDevice(t, func(cmd string) string { return "output of " + cmd + "\n" })
	eng, dir, hook := newEngine(t)
	dev := inventory.Device{Hostname: "R1", Address: host, Port: port, Vendor: "cisco_ios", CredentialGroup: "default"}

	sig := signal("OSPF_ADJ_DOWN", pipeline.PlaybookOSPFAdjDown,
		"%OSPF-5-ADJCHG: Process 1, Nbr 10.255.255.4 on Gi0/1 from FULL to DOWN, Neighbor Down: Dead timer expired",
		"CONFIG_CHANGE by tanvt at 10:12:00 UTC (42s before) preceded this fault")
	eng.Handle(context.Background(), sig, dev)
	eng.Wait()

	if got := strings.Join(fd.commands(), " ; "); got != "show ip ospf neighbor ; show ip ospf interface Gi0/1" {
		t.Fatalf("device received %q", got)
	}
	rs := readIncidents(t, dir)
	if len(rs) != 1 {
		t.Fatalf("want 1 incident, got %d", len(rs))
	}
	r := rs[0]
	if r.Hostname != "R1" || r.Playbook != "ospf_adj_down" || r.TriggerLog.Event != "OSPF_ADJ_DOWN" || len(r.ID) != 8 {
		t.Errorf("report header wrong: %+v", r)
	}
	if len(r.Diagnostics) != 2 || r.Diagnostics[0].Output != "output of show ip ospf neighbor\n" || r.Diagnostics[0].Error != "" {
		t.Errorf("diagnostics wrong: %+v", r.Diagnostics)
	}
	joined := strings.Join(r.TriageHints, "\n")
	if !strings.Contains(joined, "tanvt") || !strings.Contains(strings.ToLower(joined), "dead timer") {
		t.Errorf("hints missing annotation / dead-timer note: %q", joined)
	}
	if len(hook.reports) != 1 {
		t.Errorf("hook not called")
	}

	// The file is named per the layout: <ts>_<host>_<event>.json
	files, _ := filepath.Glob(filepath.Join(store.IncidentsDir(dir), "*_R1_OSPF_ADJ_DOWN.json"))
	if len(files) != 1 {
		t.Errorf("incident file name pattern not matched: %v", files)
	}
	// No credentials in the report.
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "\"p\"") || strings.Contains(strings.ToLower(string(b)), "password") {
		t.Errorf("incident must not contain credentials")
	}
}

func TestEngineCooldownOpensNoSession(t *testing.T) {
	fd, host, port := startFakeDevice(t, func(string) string { return "ok\n" })
	eng, dir, _ := newEngine(t)
	dev := inventory.Device{Hostname: "R1", Address: host, Port: port, Vendor: "cisco_ios", CredentialGroup: "default"}
	sig := signal("OSPF_ADJ_DOWN", pipeline.PlaybookOSPFAdjDown, "Nbr 1.1.1.1 on Gi0/1 from FULL to DOWN")

	eng.Handle(context.Background(), sig, dev)
	eng.Wait()
	fd.mu.Lock()
	before := fd.sessions
	fd.mu.Unlock()

	eng.Handle(context.Background(), sig, dev) // inside the 5 minute cooldown
	eng.Wait()
	fd.mu.Lock()
	after := fd.sessions
	fd.mu.Unlock()

	if after != before {
		t.Fatalf("SSH session opened during cooldown (%d -> %d)", before, after)
	}
	if n := len(readIncidents(t, dir)); n != 1 {
		t.Fatalf("want exactly 1 incident, got %d", n)
	}
	// Cooldown state was persisted for the next (cron) run.
	if _, err := os.Stat(store.CooldownPath(dir)); err != nil {
		t.Errorf("cooldown file not written: %v", err)
	}
}

func TestEngineNoPlaybookOrBlockedCommandOpensNoSession(t *testing.T) {
	fd, host, port := startFakeDevice(t, func(string) string { return "ok\n" })
	eng, dir, _ := newEngine(t)

	// MikroTik has no playbook: nothing happens.
	mt := inventory.Device{Hostname: "R1", Address: host, Port: port, Vendor: "mikrotik", CredentialGroup: "default"}
	eng.Handle(context.Background(), signal("LINK_DOWN", pipeline.PlaybookLinkDown, "ether1 link down"), mt)

	// An unknown playbook name: nothing happens.
	cs := inventory.Device{Hostname: "R1", Address: host, Port: port, Vendor: "cisco_ios", CredentialGroup: "default"}
	eng.Handle(context.Background(), signal("LINK_DOWN", "does_not_exist", "x"), cs)

	eng.Wait()
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if fd.sessions != 0 || len(readIncidents(t, dir)) != 0 {
		t.Fatalf("expected no session and no incident, got %d sessions", fd.sessions)
	}
}

func TestEngineVyOSWrapperHeadAndTruncation(t *testing.T) {
	big := strings.Repeat("x", 80*1024)
	fd, host, port := startFakeDevice(t, func(cmd string) string {
		switch {
		case strings.HasSuffix(cmd, "physical"):
			return big
		case strings.Contains(cmd, "show system processes"):
			var b strings.Builder
			for i := 1; i <= 40; i++ {
				b.WriteString("line " + strconv.Itoa(i) + "\n")
			}
			return b.String()
		}
		return "ok\n"
	})
	eng, dir, _ := newEngine(t)
	vy := inventory.Device{Hostname: "R1", Address: host, Port: port, Vendor: "vyos", CredentialGroup: "default"}

	eng.Handle(context.Background(), signal("LINK_DOWN", pipeline.PlaybookLinkDown, "kernel: e1000e: eth1 NIC Link is Down"), vy)
	eng.Wait()
	want := []string{
		"/opt/vyatta/bin/vyatta-op-cmd-wrapper show interfaces ethernet eth1",
		"/opt/vyatta/bin/vyatta-op-cmd-wrapper show interfaces ethernet eth1 physical",
	}
	if got := fd.commands(); strings.Join(got, ";") != strings.Join(want, ";") {
		t.Fatalf("wire commands = %q, want %q", got, want)
	}
	r := readIncidents(t, dir)[0]
	if r.Diagnostics[0].Command != "show interfaces ethernet eth1" {
		t.Errorf("report must record the gated logical command, got %q", r.Diagnostics[0].Command)
	}
	phys := r.Diagnostics[1].Output
	if !strings.Contains(phys, "bytes omitted") || len(phys) > MaxOutputBytes+100 {
		t.Errorf("80KB output not truncated to ~50KB: %d bytes", len(phys))
	}
	if r.Diagnostics[1].Error != "" {
		t.Errorf("truncation must not be an error: %q", r.Diagnostics[1].Error)
	}

	// "| head 15" is applied client-side: the device never sees "head".
	cs := inventory.Device{Hostname: "R2", Address: host, Port: port, Vendor: "cisco_ios", CredentialGroup: "default"}
	hs := signal("HIGH_CPU", pipeline.PlaybookHighCPU, "CPU utilization 97%")
	hs.Entry.Hostname = "R2"
	eng.Handle(context.Background(), hs, cs)
	eng.Wait()
	last := fd.commands()[len(fd.commands())-1]
	if last != "show processes cpu sorted" {
		t.Errorf("device saw %q, want the command without the head filter", last)
	}
}

func TestEngineRecordsUnreachableDevice(t *testing.T) {
	eng, dir, _ := newEngine(t)
	dev := inventory.Device{Hostname: "R1", Address: "127.0.0.1", Port: 1, Vendor: "cisco_ios", CredentialGroup: "default"}
	eng.Handle(context.Background(), signal("OSPF_ADJ_DOWN", pipeline.PlaybookOSPFAdjDown, "Nbr 1.1.1.1 on Gi0/1 from FULL to DOWN"), dev)
	eng.Wait()

	rs := readIncidents(t, dir)
	if len(rs) != 1 || len(rs[0].Diagnostics) != 1 || rs[0].Diagnostics[0].Command != "(connect)" || rs[0].Diagnostics[0].Error == "" {
		t.Fatalf("an unreachable device must still produce an incident recording the failure: %+v", rs)
	}
	if !strings.Contains(strings.Join(rs[0].TriageHints, " "), "could not reconnect") {
		t.Errorf("hint missing: %v", rs[0].TriageHints)
	}
}

func TestHintsNeverNil(t *testing.T) {
	h := buildHints(pipeline.TriageSignal{Entry: collector.LogEntry{Category: "SECURITY"}}, nil)
	if h == nil {
		t.Fatal("hints must marshal as [] not null")
	}
	b, _ := json.Marshal(h)
	if string(b) != "[]" {
		t.Errorf("got %s", b)
	}
}

// FuzzCheck states the gate's guarantees independently of its implementation:
// whatever Check accepts must be a short, single-line, allowlisted read-only
// command with no blocked word, no shell metacharacter, and only recognised
// output filters after a pipe.
func FuzzCheck(f *testing.F) {
	for _, s := range []string{
		"show ip ospf neighbor", "show processes cpu sorted | head 15", "show x; reload", "show $(id)",
		"display bgp peer", "/log print", "show running-config", "show x | redirect flash:y", "execute log display",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cmd string) {
		if Check(cmd) != nil {
			return
		}
		lower := strings.ToLower(cmd)
		okPrefix := false
		for _, p := range []string{"show ", "display ", "/log print", "cat /proc/net/", "execute log display"} {
			if strings.HasPrefix(cmd, p) {
				okPrefix = true
			}
		}
		if !okPrefix || len(cmd) > 200 {
			t.Fatalf("accepted %q: bad prefix or too long", cmd)
		}
		for _, w := range []string{"conf", "set", "delete", "clear", "write", "reload", "restart", "copy", "format", "debug ip packet"} {
			if strings.Contains(lower, w) {
				t.Fatalf("accepted %q containing %q", cmd, w)
			}
		}
		for _, r := range cmd {
			if r < 0x20 || r == 0x7f || strings.ContainsRune(";&`$<>\\!{}", r) {
				t.Fatalf("accepted %q containing %q", cmd, r)
			}
		}
		stages := strings.Split(cmd, "|")
		for _, st := range stages[1:] {
			word := strings.Fields(st)
			if len(word) == 0 || len(word) > 2 {
				t.Fatalf("accepted %q with malformed pipe stage %q", cmd, st)
			}
			switch word[0] {
			case "head", "last", "include", "exclude", "begin", "section", "match", "count", "no-more":
			default:
				t.Fatalf("accepted %q with pipe stage %q", cmd, st)
			}
		}
	})
}
