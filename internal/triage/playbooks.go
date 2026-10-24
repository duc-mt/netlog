// ==============================================================================
// Package triage: event-to-diagnostics playbooks.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         cmds := triage.Commands("cisco_ios", "ospf_adj_down", entry)
// Notes:         Go package implementation
// ==============================================================================
// A playbook maps a triggering event to the read-only commands worth running
// while the evidence still exists (neighbour tables, interface counters).
// Each platform family has its own command list; a family with no list for a
// playbook simply gets no triage (omitting a command is always safer than
// guessing one).
//
// Commands may contain {iface}, {peer} and {vyif} placeholders. They are
// filled from the triggering log line (pipeline.ExtractInterface /
// ExtractPeer). When extraction fails, the step's fallback (a broader
// command) is used instead, or the step is dropped if it has none.
//
// Commands returned here are candidates only: the engine passes every one
// through GATE 1 (Check) before anything is sent to a device, and the test
// suite verifies that every template in this table passes it.
package triage

import (
	"strings"

	"netlog/internal/collector"
	"netlog/internal/pipeline"
)

// step is one diagnostic command template.
type step struct {
	tmpl     string // may contain {iface}, {peer}, {vyif}
	fallback string // used when a placeholder cannot be filled; "" drops the step
}

// Platform families used as playbook table keys.
const (
	famVyOS    = "vyos"
	famCisco   = "cisco"
	famHuawei  = "huawei_vrp"
	famJunos   = "juniper_junos"
	famGeneric = "generic"
)

// family maps a canonical vendor key to its playbook family ("" = none).
func family(vendorKey string) string {
	switch vendorKey {
	case "vyos":
		return famVyOS
	case "cisco_ios", "cisco_asa", "cisco_sb":
		return famCisco
	case "huawei_vrp":
		return famHuawei
	case "juniper_junos":
		return famJunos
	case "generic", "aruba", "ruijie", "arista":
		return famGeneric
	}
	return ""
}

var linkSteps = map[string][]step{
	famVyOS: {
		{"show interfaces {vyif}", "show interfaces"},
		{"show interfaces {vyif} physical", ""},
	},
	famCisco: {
		{"show interfaces {iface}", "show ip interface brief"},
		{"show interfaces {iface} transceiver", ""},
	},
	famHuawei: {
		{"display interface {iface}", "display interface brief"},
	},
	famGeneric: {
		{"show interfaces {iface}", "show interfaces"},
	},
}

var ospfSteps = map[string][]step{
	famVyOS:   {{"show ip ospf neighbor", ""}, {"show ip ospf interface {iface}", "show ip ospf interface"}},
	famCisco:  {{"show ip ospf neighbor", ""}, {"show ip ospf interface {iface}", "show ip ospf interface"}},
	famHuawei: {{"display ospf peer", ""}, {"display ospf interface", ""}},
	famJunos:  {{"show ospf neighbor", ""}},
}

var bgpSteps = map[string][]step{
	famVyOS:   {{"show ip bgp summary", ""}, {"show ip bgp neighbors {peer}", ""}},
	famCisco:  {{"show ip bgp summary", ""}, {"show ip bgp neighbors {peer}", ""}},
	famHuawei: {{"display bgp peer", ""}},
	famJunos:  {{"show bgp summary", ""}},
}

var usersSteps = map[string][]step{
	famVyOS:   {{"show users", ""}},
	famCisco:  {{"show users", ""}},
	famHuawei: {{"display users online", ""}},
}

// playbooks maps playbook name -> platform family -> steps.
var playbooks = map[string]map[string][]step{
	pipeline.PlaybookLinkDown:    linkSteps,
	pipeline.PlaybookLinkFlap:    linkSteps,
	pipeline.PlaybookOSPFAdjDown: ospfSteps,
	pipeline.PlaybookBGPPeerDown: bgpSteps,
	pipeline.PlaybookVRRPTransition: {
		famVyOS: {{"show vrrp", ""}},
	},
	pipeline.PlaybookSTPTCN: {
		famCisco: {{"show spanning-tree detail", ""}},
	},
	pipeline.PlaybookHighCPU: {
		famCisco:  {{"show processes cpu sorted | head 15", ""}},
		famHuawei: {{"display cpu-usage", ""}},
		famVyOS:   {{"show system processes", ""}},
	},
	pipeline.PlaybookBruteForce: usersSteps,
}

// vyosTypes maps interface name prefixes to the VyOS interface type keyword
// that "show interfaces" requires ("show interfaces ethernet eth1").
var vyosTypes = []struct{ prefix, typ string }{
	{"eth", "ethernet"}, {"ens", "ethernet"}, {"enp", "ethernet"}, {"eno", "ethernet"},
	{"bond", "bonding"}, {"br", "bridge"}, {"vti", "vti"}, {"tun", "tunnel"},
	{"wg", "wireguard"}, {"lo", "loopback"}, {"veth", "virtual-ethernet"},
	{"vxlan", "vxlan"}, {"dum", "dummy"}, {"pppoe", "pppoe"},
}

// vyosInterface renders "ethernet eth1" (or "ethernet eth1 vif 100" for a
// VLAN sub-interface "eth1.100"), or "" if the type is not recognised.
func vyosInterface(iface string) string {
	base, vif, hasVif := strings.Cut(iface, ".")
	for _, t := range vyosTypes {
		if strings.HasPrefix(base, t.prefix) {
			s := t.typ + " " + base
			if hasVif && vif != "" {
				s += " vif " + vif
			}
			return s
		}
	}
	return ""
}

// Commands returns the candidate diagnostic commands for playbook on the
// given canonical vendor key, with placeholders filled from the triggering
// log entry. The result is de-duplicated, in playbook order, and may be
// empty. It is NOT filtered through the allowlist; the engine does that.
func Commands(vendorKey, playbook string, trigger collector.LogEntry) []string {
	byFamily, ok := playbooks[playbook]
	if !ok {
		return nil
	}
	steps := byFamily[family(vendorKey)]
	if len(steps) == 0 {
		return nil
	}

	iface := pipeline.ExtractInterface(trigger.Raw)
	peer := pipeline.ExtractPeer(trigger.Raw)
	vals := map[string]string{"{iface}": iface, "{peer}": peer}
	if family(vendorKey) == famVyOS && iface != "" {
		vals["{vyif}"] = vyosInterface(iface)
	} else {
		vals["{vyif}"] = ""
	}

	var out []string
	seen := make(map[string]bool)
	add := func(cmd string) {
		if cmd != "" && !seen[cmd] {
			seen[cmd] = true
			out = append(out, cmd)
		}
	}
	for _, s := range steps {
		cmd, complete := s.tmpl, true
		for ph, val := range vals {
			if strings.Contains(cmd, ph) {
				if val == "" {
					complete = false
					break
				}
				cmd = strings.ReplaceAll(cmd, ph, val)
			}
		}
		if complete {
			add(cmd)
		} else {
			add(s.fallback)
		}
	}
	return out
}
