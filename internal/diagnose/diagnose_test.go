// ==============================================================================
// Package diagnose: tests.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-26
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package diagnose

import (
	"bytes"
	"strings"
	"testing"

	"netlog/internal/triage"
	"netlog/internal/vendor"
)

// Every shipped command, with and without an interface, must pass GATE 1.
func TestAllCommandsPassGate1(t *testing.T) {
	for _, key := range vendor.Keys() {
		for _, iface := range []string{"", "Gi0/1"} {
			for _, s := range Commands(key, iface) {
				if err := triage.Check(s.Command); err != nil {
					t.Errorf("%s/%q: %v", key, iface, err)
				}
			}
		}
	}
}

func TestCommandsInterface(t *testing.T) {
	got := map[string]string{}
	for _, s := range Commands("cisco_ios", "Gi0/1") {
		got[s.Name] = s.Command
	}
	if got[SecOptics] != "show interfaces Gi0/1 transceiver detail" {
		t.Errorf("optics = %q", got[SecOptics])
	}
	if got[SecInterfaces] != "show interfaces Gi0/1 counters errors" {
		t.Errorf("errors = %q", got[SecInterfaces])
	}
}

func TestValidInterface(t *testing.T) {
	for _, ok := range []string{"Gi0/1", "ge-0/0/1", "eth1.100", "TenGigabitEthernet1/0/1", "1/1/24"} {
		if !ValidInterface(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "Gi0/1; reload", "$(id)", "Gi0/1 x", "Gi0/1|x"} {
		if ValidInterface(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestAnalyse(t *testing.T) {
	tests := []struct {
		name, out, status string
	}{
		{SecInterfaces, "5 input errors, 3 CRC, 0 frame", StatusWarn},
		{SecInterfaces, "0 input errors, 0 CRC, 0 frame", StatusOK},
		{SecOptics, "Rx Power: -25.31 dBm\nTx Power: -2.10 dBm", StatusWarn},
		{SecOptics, "Rx Power: -5.31 dBm\nTx Power: -2.10 dBm", StatusOK},
		{SecOptics, "Rx Power: -40.00 dBm", StatusWarn},
		{SecBGP, "10.0.0.2 4 65001 100 100 1 0 0 00:10:00 5", StatusOK},
		{SecBGP, "10.0.0.2 4 65001 0 0 1 0 0 never Active", StatusWarn},
		{SecOSPF, "10.0.0.2 1 FULL/DR 00:00:33 10.0.0.2 Gi0/1", StatusOK},
		{SecOSPF, "10.0.0.2 1 INIT/DROTHER 00:00:33 10.0.0.2 Gi0/1", StatusWarn},
		{SecAlarms, "No alarms currently active", StatusOK},
		{SecAlarms, "Major alarm: PSU 2 failed", StatusWarn},
	}
	for _, tc := range tests {
		s := Section{Name: tc.name, Output: tc.out}
		analyse(&s)
		if s.Status != tc.status {
			t.Errorf("%s %q: status %s, want %s (notes %v)", tc.name, tc.out, s.Status, tc.status, s.Notes)
		}
	}
}

func TestRender(t *testing.T) {
	r := Report{Connected: true, VendorKey: "cisco_ios", Sections: []Section{
		{Name: SecBGP, Command: "show ip bgp summary", Status: StatusWarn, Notes: []string{"BGP session(s) not Established"}, Output: "x\ny"},
	}}
	r.Device.Hostname = "r1"
	var b bytes.Buffer
	Render(&b, r, RenderOptions{Raw: true})
	out := b.String()
	for _, want := range []string{"r1", "[WARN]", "not Established", "| x", "ATTENTION NEEDED"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("color escape emitted with Color=false")
	}
}

func TestUnreachableReport(t *testing.T) {
	r := Report{ConnectErr: "dial tcp: timeout"}
	var b bytes.Buffer
	Render(&b, r, RenderOptions{})
	if !strings.Contains(b.String(), "[ERROR] SSH: dial tcp: timeout") || r.Healthy() {
		t.Errorf("unexpected: %s", b.String())
	}
}
