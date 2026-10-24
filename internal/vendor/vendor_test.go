// ==============================================================================
// Package vendor: tests for platform-name canonicalization.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-21
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package vendor

import "testing"

func TestCanonicalKey(t *testing.T) {
	tests := map[string]string{
		"cisco": "cisco_ios", "IOS-XE": "cisco_ios", " ios xe ": "cisco_ios", "iosxe": "cisco_ios",
		"cisco_sb": "cisco_sb", "SG350": "cisco_sb", "cbs350": "cisco_sb",
		"asa": "cisco_asa", "FTD": "cisco_asa",
		"junos": "juniper_junos", "Juniper": "juniper_junos",
		"huawei": "huawei_vrp", "VRP": "huawei_vrp", "h3c": "huawei_vrp", "comware": "huawei_vrp",
		"fortios": "fortigate", "Fortinet": "fortigate", "fortigate": "fortigate",
		"EOS": "arista", "routeros": "mikrotik", "aos-cx": "aruba", "rgos": "ruijie",
		"checkpoint": "checkpoint_gaia", "gaia": "checkpoint_gaia", "pfsense": "pfsense",
		"pan-os": "paloalto", "sophos xg": "sophos", "vyos": "vyos", "generic": "generic",
	}
	for in, want := range tests {
		got, ok := CanonicalKey(in)
		if !ok || got != want {
			t.Errorf("CanonicalKey(%q) = (%q, %v), want (%q, true)", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "  ", "nokia", "cisco ios nx os", "unknown-vendor"} {
		if got, ok := CanonicalKey(bad); ok {
			t.Errorf("CanonicalKey(%q) = (%q, true), want unknown", bad, got)
		}
	}
}

// Every alias must resolve to a canonical key that exists, and every
// canonical key must resolve to itself: a typo in either table would
// otherwise silently disable a platform.
func TestTablesAreConsistent(t *testing.T) {
	for alias, target := range aliases {
		if !IsKnown(target) {
			t.Errorf("alias %q points at unknown key %q", alias, target)
		}
	}
	for _, k := range Keys() {
		if got, ok := CanonicalKey(k); !ok || got != k {
			t.Errorf("canonical key %q does not resolve to itself: (%q, %v)", k, got, ok)
		}
	}
	if len(Keys()) < 10 {
		t.Errorf("suspiciously few platform keys: %v", Keys())
	}
}

func TestKeysReturnsACopy(t *testing.T) {
	k := Keys()
	k[0] = "mutated"
	if Keys()[0] == "mutated" {
		t.Error("Keys must return a copy")
	}
}
