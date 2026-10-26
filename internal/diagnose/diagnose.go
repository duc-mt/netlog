// ==============================================================================
// Package diagnose: on-demand single-device triage helper.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-26
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         rep := diagnose.Run(ctx, dialer, dev, diagnose.Options{})
//
//	diagnose.Render(w, rep, diagnose.RenderOptions{})
//
// Notes:         Go package implementation
// ==============================================================================
// Package diagnose runs a fixed set of strictly read-only checks against one
// device (SSH reachability, active alarms, routing adjacencies, interface
// errors and optical DDM power) and renders a short report.
//
// Every command passes the triage allowlist (GATE 1, triage.Check) before it
// is sent, exactly like auto-triage. A failing command never aborts the run:
// each section reports its own error.
package diagnose

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"netlog/internal/collector"
	"netlog/internal/inventory"
	"netlog/internal/sshclient"
	"netlog/internal/triage"
	"netlog/internal/vendor"
)

// vyosWrapper makes VyOS operational commands work over an SSH exec channel
// (same fixed prefix the triage engine uses).
const vyosWrapper = "/opt/vyatta/bin/vyatta-op-cmd-wrapper "

// Section names, in report order.
const (
	SecAlarms     = "Active alarms"
	SecBGP        = "BGP peers"
	SecOSPF       = "OSPF neighbors"
	SecInterfaces = "Interface errors (CRC)"
	SecOptics     = "Optical DDM"
)

// Status of a section.
const (
	StatusOK      = "OK"
	StatusWarn    = "WARN"
	StatusError   = "ERROR"
	StatusUnknown = "N/A"
)

// plan lists the commands per section for one platform family.
type plan struct {
	alarms, bgp, ospf, errs, optics string
}

// plans is keyed by canonical vendor key. {iface} is replaced when an
// interface is requested; a command that still contains it is skipped, and
// the section's allIfaces variant is used instead where one exists.
var plans = map[string]plan{
	"cisco_ios": {"show environment all", "show ip bgp summary", "show ip ospf neighbor", "show interfaces counters errors", "show interfaces transceiver detail"},
	"cisco_sb":  {"", "", "", "show interfaces counters", ""},
	"cisco_asa": {"show environment", "show bgp summary", "show ospf neighbor", "show interface", ""},
	"huawei_vrp": {"display alarm active", "display bgp peer", "display ospf peer",
		"display interface brief", "display transceiver diagnosis interface"},
	"juniper_junos": {"show chassis alarms", "show bgp summary", "show ospf neighbor",
		"show interfaces extensive", "show interfaces diagnostics optics"},
	"arista": {"show system environment all", "show ip bgp summary", "show ip ospf neighbor", "show interfaces counters errors", "show interfaces transceiver"},
	"ruijie": {"show environment", "show ip bgp summary", "show ip ospf neighbor", "show interfaces counters", "show interfaces transceiver"},
	"aruba":  {"show environment", "show bgp summary", "show ip ospf neighbor", "show interface brief", "show interface transceiver"},
	"fortigate": {"get system status", "get router info bgp summary", "get router info ospf neighbor",
		"get system interface physical", ""},
	"vyos":    {"show system uptime", "show ip bgp summary", "show ip ospf neighbor", "show interfaces", ""},
	"generic": {"", "", "", "show interfaces", ""},
}

// Options configures Run.
type Options struct {
	// Interface, if set, narrows the interface and optics checks to one port.
	Interface string
	// CommandTimeout bounds each command (default and cap: triage.MaxCommandTimeout).
	CommandTimeout time.Duration
	// SSH carries host-key and algorithm settings for command execution.
	SSH sshclient.Options
}

// Section is the outcome of one check.
type Section struct {
	Name    string
	Command string
	Status  string
	Notes   []string // human findings (CRC totals, low Rx power, ...)
	Output  string   // raw device output
	Error   string
}

// Report is the result of Run.
type Report struct {
	Device      inventory.Device
	VendorKey   string
	StartedAt   time.Time
	ConnectTime time.Duration
	Connected   bool
	ConnectErr  string
	Sections    []Section
}

// ifaceRe restricts a user-supplied interface name to characters that are
// safe to place in a command line.
var ifaceRe = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9/._:-]*\d|\d+(?:/\d+)+)$`)

// ValidInterface reports whether name is acceptable for Options.Interface.
func ValidInterface(name string) bool { return ifaceRe.MatchString(name) }

// Commands returns the section -> command list that Run would execute for a
// vendor key, in report order. Empty commands (unsupported checks) are
// omitted. Exported for tests and for dry inspection.
func Commands(vendorKey, iface string) []Section {
	p, ok := plans[vendorKey]
	if !ok {
		p = plans["generic"]
	}
	withIface := func(base string) string {
		if base == "" || iface == "" {
			return base
		}
		return base + " " + iface
	}
	// Per-interface syntax differs: "show interfaces X counters errors" and
	// "show interfaces X transceiver detail" put the name in the middle.
	errs, optics := withIface(p.errs), withIface(p.optics)
	if iface != "" {
		switch vendorKey {
		case "cisco_ios":
			errs = "show interfaces " + iface + " counters errors"
			optics = "show interfaces " + iface + " transceiver detail"
		case "arista", "ruijie":
			errs = "show interfaces " + iface + " counters errors"
			optics = "show interfaces " + iface + " transceiver"
		case "aruba":
			errs = "show interface " + iface
			optics = "show interface " + iface + " transceiver"
		case "juniper_junos":
			errs = "show interfaces " + iface + " extensive"
			optics = "show interfaces diagnostics optics " + iface
		case "huawei_vrp":
			errs = "display interface " + iface
		case "fortigate":
			errs = "get hardware nic " + iface
		}
	}
	all := []Section{
		{Name: SecAlarms, Command: p.alarms},
		{Name: SecBGP, Command: p.bgp},
		{Name: SecOSPF, Command: p.ospf},
		{Name: SecInterfaces, Command: errs},
		{Name: SecOptics, Command: optics},
	}
	out := all[:0]
	for _, s := range all {
		if s.Command != "" {
			out = append(out, s)
		}
	}
	return out
}

// Run connects to dev and executes the vendor's checks. It never returns an
// error: failures are recorded in the Report.
func Run(ctx context.Context, d *collector.Dialer, dev inventory.Device, o Options) Report {
	key, ok := vendor.CanonicalKey(dev.Vendor)
	if !ok {
		key = "generic"
	}
	rep := Report{Device: dev, VendorKey: key, StartedAt: time.Now()}

	if o.Interface != "" && !ValidInterface(o.Interface) {
		rep.ConnectErr = fmt.Sprintf("invalid interface name %q", o.Interface)
		return rep
	}
	secs := Commands(key, o.Interface)

	// GATE 1 before any session is opened.
	for _, s := range secs {
		if err := triage.Check(s.Command); err != nil {
			rep.ConnectErr = "allowlist gate: " + err.Error()
			return rep
		}
	}

	t0 := time.Now()
	client, err := d.Dial(ctx, dev)
	rep.ConnectTime = time.Since(t0)
	if err != nil {
		rep.ConnectErr = err.Error()
		return rep
	}
	defer client.Close()
	rep.Connected = true

	opts := o.SSH
	opts.CommandTimeout = o.CommandTimeout
	if opts.CommandTimeout <= 0 || opts.CommandTimeout > triage.MaxCommandTimeout {
		opts.CommandTimeout = triage.MaxCommandTimeout
	}
	for _, s := range secs {
		if ctx.Err() != nil {
			s.Status, s.Error = StatusUnknown, ctx.Err().Error()
			rep.Sections = append(rep.Sections, s)
			continue
		}
		rep.Sections = append(rep.Sections, execSection(ctx, client, key, s, opts))
	}
	return rep
}

func execSection(ctx context.Context, client *ssh.Client, key string, s Section, opts sshclient.Options) Section {
	wire := s.Command
	if key == "vyos" {
		wire = vyosWrapper + wire
	}
	out, err := sshclient.RunCommand(ctx, client, wire, opts)
	if len(out) > triage.MaxOutputBytes {
		out = out[:triage.MaxOutputBytes]
	}
	s.Output = out
	if err != nil {
		s.Status, s.Error = StatusError, err.Error()
		if strings.TrimSpace(out) == "" {
			return s
		}
	}
	analyse(&s)
	return s
}

// ---- output analysis (best effort, vendor-neutral) ------------------------------

var (
	reCRC     = regexp.MustCompile(`(?i)(?:\bcrc\b[^0-9\n]{0,24}(\d+))|(?:(\d+)\s+crc\b)`)
	reInErr   = regexp.MustCompile(`(?i)(\d+)\s+input errors`)
	reDBm     = regexp.MustCompile(`(?i)(-?\d+(?:\.\d+)?)\s*dbm`)
	reLOS     = regexp.MustCompile(`(?i)\b(?:los|loss of signal)\b|rx power[^\n]*(?:-40|-inf|n/a)`)
	reBGPBad  = regexp.MustCompile(`(?im)\b(?:idle|active|connect|opensent|openconfirm)\b`)
	reOSPFBad = regexp.MustCompile(`(?im)\b(?:down|init|attempt|exstart|exchange|loading)\b`)
	reAlarm   = regexp.MustCompile(`(?i)\b(?:critical|major|minor|fail(?:ed|ure)?|fault|alarm(?:ed)?|over ?temp|shutdown)\b`)
	reNoAlarm = regexp.MustCompile(`(?i)no (?:active |current )?alarms?|alarm(?:s)?:? *(?:none|0)\b|^$`)
)

// Rx power thresholds in dBm: typical SFP+ sensitivity is about -14 (SR) to
// -23 (LR/ER); anything below -20 or a Tx/Rx pair this low deserves a look.
const (
	lowPowerDBm  = -20.0
	highPowerDBm = 3.0
)

func analyse(s *Section) {
	if s.Status == "" {
		s.Status = StatusOK
	}
	out := s.Output
	warn := func(msg string) {
		if s.Status != StatusError {
			s.Status = StatusWarn
		}
		s.Notes = append(s.Notes, msg)
	}
	switch s.Name {
	case SecAlarms:
		trimmed := strings.TrimSpace(out)
		if trimmed != "" && !reNoAlarm.MatchString(trimmed) && reAlarm.MatchString(out) {
			warn("alarm keywords present: review output")
		}
	case SecBGP:
		if reBGPBad.MatchString(out) {
			warn("BGP session(s) not Established")
		}
	case SecOSPF:
		if reOSPFBad.MatchString(out) {
			warn("OSPF neighbor(s) not FULL")
		} else if strings.TrimSpace(out) == "" {
			warn("no OSPF neighbors reported")
		}
	case SecInterfaces:
		if n := sumMatches(reCRC, out) + sumMatches(reInErr, out); n > 0 {
			warn(fmt.Sprintf("%d CRC/input error(s) counted", n))
		}
	case SecOptics:
		if reLOS.MatchString(out) {
			warn("loss of signal / no Rx light reported")
		}
		low, high := 0, 0
		for _, m := range reDBm.FindAllStringSubmatch(out, -1) {
			v, err := strconv.ParseFloat(m[1], 64)
			if err != nil {
				continue
			}
			switch {
			case v <= -30: // "-40.00 dBm" style no-light sentinel counts as LOS above
				low++
			case v < lowPowerDBm:
				low++
			case v > highPowerDBm:
				high++
			}
		}
		if low > 0 {
			warn(fmt.Sprintf("%d optical reading(s) below %.0f dBm", low, lowPowerDBm))
		}
		if high > 0 {
			warn(fmt.Sprintf("%d optical reading(s) above %.0f dBm", high, highPowerDBm))
		}
	}
}

// sumMatches adds the first numeric capture group found per match.
func sumMatches(re *regexp.Regexp, s string) int {
	total := 0
	for _, m := range re.FindAllStringSubmatch(s, -1) {
		for _, g := range m[1:] {
			if g == "" {
				continue
			}
			if n, err := strconv.Atoi(g); err == nil {
				total += n
			}
			break
		}
	}
	return total
}

// Healthy reports whether the device connected and no section warns or errors.
func (r Report) Healthy() bool {
	if !r.Connected {
		return false
	}
	for _, s := range r.Sections {
		if s.Status == StatusWarn || s.Status == StatusError {
			return false
		}
	}
	return true
}
