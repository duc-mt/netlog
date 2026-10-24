// ==============================================================================
// Package vendor normalizes the platform names used in inventory.csv.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-21
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         key, ok := vendor.CanonicalKey(device.Vendor)
// Notes:         Go package implementation
// ==============================================================================
// Package vendor maps the platform names and aliases operators write in the
// "vendor" column of inventory.csv ("cisco", "IOS-XE", "junos", "fortios", ...)
// to the canonical keys the rest of netlog dispatches on (per-vendor log
// commands, parsers and triage playbooks).
//
// It only answers "which platform is this?". What netlog does for each
// platform lives next to the code that does it (internal/collector for log
// and clock commands, internal/parser, internal/triage for playbooks).
package vendor

import (
	"sort"
	"strings"
)

// keys lists every canonical platform key.
var keys = []string{
	"cisco_ios",
	"cisco_sb",
	"cisco_asa",
	"huawei_vrp",
	"juniper_junos",
	"aruba",
	"ruijie",
	"fortigate",
	"checkpoint_gaia",
	"pfsense",
	"vyos",
	"arista",
	"mikrotik",
	"paloalto",
	"sophos",
	"generic",
}

// Keys returns the canonical platform keys, sorted.
func Keys() []string {
	out := make([]string, len(keys))
	copy(out, keys)
	sort.Strings(out)
	return out
}

// IsKnown reports whether key is a canonical platform key.
func IsKnown(key string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}

// aliases maps every accepted spelling (lower case, '-' and ' ' folded to '_')
// to its canonical key.
var aliases = map[string]string{
	// Cisco
	"cisco":        "cisco_ios",
	"cisco_ios":    "cisco_ios",
	"cisco_ios_xe": "cisco_ios",
	"ios":          "cisco_ios",
	"ios_xe":       "cisco_ios",
	"iosxe":        "cisco_ios",

	// Cisco Small Business (SF/SG/CBS)
	"cisco_sb": "cisco_sb",
	"cisco_sf": "cisco_sb",
	"cisco_sg": "cisco_sb",
	"ciscosb":  "cisco_sb",
	"ciscosf":  "cisco_sb",
	"ciscosg":  "cisco_sb",
	"cbs":      "cisco_sb",
	"cbs350":   "cisco_sb",
	"sg300":    "cisco_sb",
	"sg350":    "cisco_sb",
	"sg500":    "cisco_sb",
	"sf300":    "cisco_sb",
	"sf500":    "cisco_sb",

	// Cisco ASA / Firepower FTD in ASA mode
	"cisco_asa": "cisco_asa",
	"asa":       "cisco_asa",
	"cisco_ftd": "cisco_asa",
	"ftd":       "cisco_asa",

	// Juniper
	"junos":         "juniper_junos",
	"juniper":       "juniper_junos",
	"juniper_junos": "juniper_junos",

	// Huawei
	"huawei":     "huawei_vrp",
	"vrp":        "huawei_vrp",
	"huawei_vrp": "huawei_vrp",
	"h3c":        "huawei_vrp", // H3C / HP Comware use the same CLI
	"comware":    "huawei_vrp",
	"hp_comware": "huawei_vrp",

	// Fortinet
	"fortinet":  "fortigate",
	"fortios":   "fortigate",
	"fortigate": "fortigate",

	// Arista
	"arista":     "arista",
	"eos":        "arista",
	"arista_eos": "arista",

	// MikroTik RouterOS
	"mikrotik": "mikrotik",
	"routeros": "mikrotik",
	"ros":      "mikrotik",

	// Aruba
	"aruba":    "aruba",
	"aruba_cx": "aruba",
	"aos_cx":   "aruba",
	"aos_s":    "aruba",

	// Ruijie
	"ruijie": "ruijie",
	"rgos":   "ruijie",

	// Check Point
	"checkpoint":      "checkpoint_gaia",
	"checkpoint_gaia": "checkpoint_gaia",
	"gaia":            "checkpoint_gaia",

	// pfSense
	"pfsense": "pfsense",

	// Palo Alto
	"paloalto": "paloalto",
	"panos":    "paloalto",
	"pan_os":   "paloalto",

	// Sophos
	"sophos":    "sophos",
	"sophos_xg": "sophos",
	"sfos":      "sophos",

	// VyOS
	"vyos": "vyos",

	// Generic
	"generic": "generic",
}

// CanonicalKey normalizes a vendor name or alias (handling case, '-', ' ')
// and returns its canonical key if known.
func CanonicalKey(name string) (string, bool) {
	norm := strings.ToLower(strings.TrimSpace(name))
	norm = strings.NewReplacer("-", "_", " ", "_").Replace(norm)
	if canonical, ok := aliases[norm]; ok {
		return canonical, true
	}
	if IsKnown(norm) {
		return norm, true
	}
	return "", false
}
