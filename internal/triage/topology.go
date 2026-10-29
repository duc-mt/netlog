// ==============================================================================
// Package triage: topology-aware peer triage (CDP / LLDP neighbour discovery).
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-27
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
// When a link fault is triaged on a device that speaks CDP or LLDP, one more
// read-only command (the neighbour table) is run on the same SSH session. The
// entry for the faulted port names the device and port at the other end; if
// that device is in the inventory, the engine starts a secondary triage there
// (see Engine.spawnPeer) and links the two incidents.
//
// The parsers below read the documented layouts of:
//
//	Cisco    show cdp neighbors detail
//	Arista   show lldp neighbors detail
//	Aruba    show lldp info remote-device       (AOS-S table)
//	Huawei   display lldp neighbor-information verbose
//
// They have not been checked against live devices of every release: an
// output that does not look like the documented layout yields no neighbour
// (and therefore no peer triage), never a wrong one. Names and ports taken
// from a neighbour's advertisement are untrusted text; they are validated
// here and the commands built from them still pass GATE 1.
package triage

import (
	"regexp"
	"strings"

	"netlog/internal/inventory"
)

// topologyCommands maps a platform family to the neighbour-table commands run
// on a link fault. A family with no entry gets no peer triage. Every command
// is registered in exactAllowed.
var topologyCommands = map[string][]string{
	famCisco:  {"show cdp neighbors detail"},
	famArista: {"show lldp neighbors detail"},
	famAruba:  {"show lldp info remote-device"},
	famHuawei: {"display lldp neighbor-information verbose"},
}

// TopologyCommands returns the neighbour-table commands for a canonical
// vendor key (nil when the platform has none).
func TopologyCommands(vendorKey string) []string {
	return topologyCommands[family(vendorKey)]
}

// Neighbor is one CDP/LLDP neighbour entry as advertised.
type Neighbor struct {
	LocalPort  string // local interface the neighbour was learned on
	RemoteName string // advertised device ID / system name
	RemotePort string // advertised port on the remote device
	RemoteAddr string // advertised IPv4 management address, if any
}

var (
	reCDPDevice = regexp.MustCompile(`^Device ID:\s*(\S+)`)
	reCDPAddr   = regexp.MustCompile(`^\s*IP(?:v4)? [Aa]ddress:\s*(\d{1,3}(?:\.\d{1,3}){3})`)
	reCDPIntf   = regexp.MustCompile(`^Interface:\s*([^,\s]+),\s*Port ID \(outgoing port\):\s*(\S+)`)
	reDashes    = regexp.MustCompile(`^-{5,}\s*$`)

	reAristaIntf = regexp.MustCompile(`^Interface (\S+) detected \d+ LLDP neighbors?:`)
	reAristaNbr  = regexp.MustCompile(`^\s*Neighbor \S+, age `)
	reAristaPort = regexp.MustCompile(`^\s*Port ID\s*:\s*"?([^"]*?)"?\s*$`)
	reAristaName = regexp.MustCompile(`^\s*-?\s*System Name:\s*"?([^"]*?)"?\s*$`)
	reAristaAddr = regexp.MustCompile(`^\s*Management Address\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})`)

	reHuaweiHdr   = regexp.MustCompile(`^(\S+) has \d+ neighbor\(s\):`)
	reHuaweiIdx   = regexp.MustCompile(`^Neighbor index\s*:`)
	reHuaweiPType = regexp.MustCompile(`^Port ID type\s*:\s*(.+?)\s*$`)
	reHuaweiPort  = regexp.MustCompile(`^Port ID\s*:\s*(.+?)\s*$`)
	reHuaweiDesc  = regexp.MustCompile(`^Port description\s*:\s*(.+?)\s*$`)
	reHuaweiName  = regexp.MustCompile(`^System name\s*:\s*(.+?)\s*$`)
	reHuaweiAddr  = regexp.MustCompile(`^Management address value\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})`)

	reHex2 = regexp.MustCompile(`^[0-9A-Fa-f]{2}$`)

	// Advertised names and ports are untrusted: only plain identifiers survive.
	reSafeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
	reSafePort = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9/._:-]{0,40}$`)
)

// ParseNeighbors parses the neighbour-table output of a platform family.
// Entries whose name or port is not a plain identifier are dropped.
func ParseNeighbors(fam, out string) []Neighbor {
	var raw []Neighbor
	switch fam {
	case famCisco:
		raw = parseCDP(out)
	case famArista:
		raw = parseAristaLLDP(out)
	case famAruba:
		raw = parseArubaLLDP(out)
	case famHuawei:
		raw = parseHuaweiLLDP(out)
	}
	clean := raw[:0:0]
	for _, n := range raw {
		n.RemoteName = cleanName(n.RemoteName)
		n.RemotePort = strings.TrimSpace(n.RemotePort)
		n.LocalPort = strings.TrimSpace(n.LocalPort)
		if reSafeName.MatchString(n.RemoteName) && reSafePort.MatchString(n.RemotePort) && n.LocalPort != "" {
			clean = append(clean, n)
		}
	}
	return clean
}

// cleanName strips a serial-number suffix ("sw2(FOX123)") from an advertised
// device ID.
func cleanName(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '('); i > 0 {
		s = s[:i]
	}
	return s
}

func parseCDP(out string) []Neighbor {
	var res []Neighbor
	var cur Neighbor
	var have bool
	flush := func() {
		if have && cur.LocalPort != "" {
			res = append(res, cur)
		}
		cur, have = Neighbor{}, false
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case reDashes.MatchString(line):
			flush()
		case reCDPDevice.MatchString(line):
			flush()
			cur.RemoteName = reCDPDevice.FindStringSubmatch(line)[1]
			have = true
		case reCDPAddr.MatchString(line):
			if cur.RemoteAddr == "" {
				cur.RemoteAddr = reCDPAddr.FindStringSubmatch(line)[1]
			}
		case reCDPIntf.MatchString(line):
			m := reCDPIntf.FindStringSubmatch(line)
			cur.LocalPort, cur.RemotePort = m[1], m[2]
		}
	}
	flush()
	return res
}

func parseAristaLLDP(out string) []Neighbor {
	var res []Neighbor
	var local string
	var cur Neighbor
	var have bool
	flush := func() {
		if have && cur.LocalPort != "" {
			res = append(res, cur)
		}
		cur, have = Neighbor{}, false
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case reAristaIntf.MatchString(line):
			flush()
			local = reAristaIntf.FindStringSubmatch(line)[1]
		case reAristaNbr.MatchString(line):
			flush()
			cur.LocalPort, have = local, true
		case !have:
		case reAristaPort.MatchString(line):
			cur.RemotePort = reAristaPort.FindStringSubmatch(line)[1]
		case reAristaName.MatchString(line):
			cur.RemoteName = reAristaName.FindStringSubmatch(line)[1]
		case reAristaAddr.MatchString(line):
			if cur.RemoteAddr == "" {
				cur.RemoteAddr = reAristaAddr.FindStringSubmatch(line)[1]
			}
		}
	}
	flush()
	return res
}

func parseHuaweiLLDP(out string) []Neighbor {
	var res []Neighbor
	var local, ptype, pid, pdesc string
	var cur Neighbor
	var have bool
	flush := func() {
		if have {
			port := pid
			if strings.Contains(strings.ToLower(ptype), "mac") || port == "" {
				// A MAC-address port ID names nothing usable; the port
				// description normally starts with the interface name.
				if f := strings.Fields(pdesc); len(f) > 0 {
					port = f[0]
				}
			}
			cur.RemotePort = port
			if cur.LocalPort != "" {
				res = append(res, cur)
			}
		}
		cur, have, ptype, pid, pdesc = Neighbor{}, false, "", "", ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		switch {
		case reHuaweiHdr.MatchString(line):
			flush()
			local = reHuaweiHdr.FindStringSubmatch(line)[1]
		case reHuaweiIdx.MatchString(line):
			flush()
			cur.LocalPort, have = local, true
		case !have:
		case reHuaweiPType.MatchString(line):
			ptype = reHuaweiPType.FindStringSubmatch(line)[1]
		case reHuaweiPort.MatchString(line):
			pid = reHuaweiPort.FindStringSubmatch(line)[1]
		case reHuaweiDesc.MatchString(line):
			pdesc = reHuaweiDesc.FindStringSubmatch(line)[1]
		case reHuaweiName.MatchString(line):
			cur.RemoteName = reHuaweiName.FindStringSubmatch(line)[1]
		case reHuaweiAddr.MatchString(line):
			if cur.RemoteAddr == "" {
				cur.RemoteAddr = reHuaweiAddr.FindStringSubmatch(line)[1]
			}
		}
	}
	flush()
	return res
}

// parseArubaLLDP reads the AOS-S summary table:
//
//	LocalPort | ChassisId                 PortId PortDescr SysName
//	--------- + ------------------------- ------ --------- ----------
//	1         | 00 11 22 33 44 55         24     24        Switch-B
//
// The chassis ID is either six two-digit hex groups or one token. The system
// name is the last column; a row with fewer than three columns after the
// chassis ID has no usable name and is skipped.
func parseArubaLLDP(out string) []Neighbor {
	var res []Neighbor
	for _, line := range strings.Split(out, "\n") {
		i := strings.IndexByte(line, '|')
		if i <= 0 {
			continue
		}
		left := strings.Fields(line[:i])
		if len(left) != 1 || strings.EqualFold(left[0], "LocalPort") {
			continue
		}
		right := strings.Fields(line[i+1:])
		skip := 1
		if len(right) >= 6 {
			six := true
			for _, f := range right[:6] {
				if !reHex2.MatchString(f) {
					six = false
					break
				}
			}
			if six {
				skip = 6
			}
		}
		if len(right) < skip+3 {
			continue
		}
		rest := right[skip:]
		res = append(res, Neighbor{LocalPort: left[0], RemotePort: rest[0], RemoteName: rest[len(rest)-1]})
	}
	return res
}

// ---- interface and inventory matching ---------------------------------------------

// ifPrefixes folds the long and short spellings of an interface type into one
// canonical prefix ("GigabitEthernet", "Gi", "GE" -> "gi").
var ifPrefixes = map[string]string{
	"gigabitethernet": "gi", "gigeth": "gi", "gige": "gi", "gi": "gi", "ge": "gi",
	"tengigabitethernet": "te", "tengige": "te", "te": "te", "xgigabitethernet": "te", "xge": "te",
	"fastethernet": "fa", "fa": "fa",
	"ethernet": "eth", "eth": "eth", "et": "eth", "e": "eth",
	"port-channel": "po", "po": "po", "eth-trunk": "po",
	"hundredgige": "hu", "hu": "hu",
	"fortygigabitethernet": "fo", "fo": "fo",
	"twentyfivegige": "twe", "twe": "twe",
	"vlan": "vlan", "vl": "vlan",
}

// splitIf splits an interface name into its canonical type prefix and the
// numeric part ("Gi1/0/24" -> "gi", "1/0/24").
func splitIf(name string) (prefix, rest string) {
	s := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), " ", ""))
	i := strings.IndexAny(s, "0123456789")
	if i < 0 {
		return s, ""
	}
	prefix, rest = s[:i], s[i:]
	if c, ok := ifPrefixes[prefix]; ok {
		prefix = c
	}
	return prefix, rest
}

// SameInterface reports whether a and b name the same interface, tolerating
// long/short type spellings ("GigabitEthernet1/0/1" == "Gi1/0/1") and a
// number-only name (AOS-S "24") on either side.
func SameInterface(a, b string) bool {
	pa, ra := splitIf(a)
	pb, rb := splitIf(b)
	if ra == "" || rb == "" || ra != rb {
		return false
	}
	return pa == "" || pb == "" || pa == pb
}

// FindNeighbor returns the neighbour learned on the given local interface.
func FindNeighbor(ns []Neighbor, iface string) (Neighbor, bool) {
	for _, n := range ns {
		if SameInterface(n.LocalPort, iface) {
			return n, true
		}
	}
	return Neighbor{}, false
}

// FindPeer resolves an advertised neighbour to an inventory device: by
// hostname (the full advertised name, then its first label, either way round)
// and, failing that, by management address. The device being triaged is never
// its own peer.
func FindPeer(inv []inventory.Device, n Neighbor, self string) (inventory.Device, bool) {
	first := func(s string) string {
		if i := strings.IndexByte(s, '.'); i > 0 {
			return s[:i]
		}
		return s
	}
	for _, d := range inv {
		if strings.EqualFold(d.Hostname, self) {
			continue
		}
		if strings.EqualFold(d.Hostname, n.RemoteName) || strings.EqualFold(first(d.Hostname), first(n.RemoteName)) {
			return d, true
		}
	}
	if n.RemoteAddr != "" {
		for _, d := range inv {
			if !strings.EqualFold(d.Hostname, self) && d.Address == n.RemoteAddr {
				return d, true
			}
		}
	}
	return inventory.Device{}, false
}
