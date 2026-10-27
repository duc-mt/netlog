// ==============================================================================
// Package pipeline: event classifier (Stage 3).
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         pipeline.NewClassifier(time.Local).Classify(&entry)
// Notes:         Go package implementation
// ==============================================================================
// The classifier tags each parsed entry with a Category, Event and Severity by
// matching its Raw text, case-insensitively, against an ordered rule table;
// the first matching rule wins. Entries that match nothing become
// SYSTEM/UNKNOWN/INFO.
//
// The table is the one specified for netlog, with three deliberate,
// conservative differences, each there because the literal table misreads
// real device output:
//
//  1. Ordering. The protocol rules (OSPF, BGP, VRRP, STP) are evaluated
//     before the broad link rule. OSPF's own message "Neighbor Down: Interface
//     down or detached" contains "interface ... down" and would otherwise be
//     filed as LINK_DOWN instead of OSPF_ADJ_DOWN.
//  2. Extra phrasings for the same events, so the rules work on more than
//     Cisco/VyOS: "Login Success" (Cisco prints that, not "successful"),
//     "login failed"/"LOGIN_FAILED", Huawei "succeeded in logging in", Junos
//     UI_COMMIT, FortiOS "cfgpath=", MikroTik "logged in from", "link is
//     down"/SNMP link-down traps, BGP "from Established to ...", Cisco
//     SPANTREE topology traps.
//  3. Huawei CMDRECORD logs every CLI command, including read-only ones
//     (display, ping, quit...). Those are filed as SYSTEM/CLI_COMMAND/INFO
//     rather than CONFIG_CHANGE, so a "display" at 3 AM does not raise a
//     CRITICAL AFTER_HOURS_CHANGE.
package pipeline

import (
	"regexp"
	"time"

	"netlog/internal/collector"
)

// Event names produced by the classifier and the anomaly detector.
const (
	EventConfigChange     = "CONFIG_CHANGE"
	EventAfterHoursChange = "AFTER_HOURS_CHANGE"
	EventLoginSuccess     = "LOGIN_SUCCESS"
	EventLoginFailure     = "LOGIN_FAILURE"
	EventBruteForce       = "BRUTE_FORCE_ATTEMPT"
	EventLinkDown         = "LINK_DOWN"
	EventLinkFlap         = "LINK_FLAP"
	EventOSPFAdjDown      = "OSPF_ADJ_DOWN"
	EventBGPPeerDown      = "BGP_PEER_DOWN"
	EventVRRPTransition   = "VRRP_TRANSITION"
	EventSTPTCN           = "STP_TCN"
	EventHighCPU          = "HIGH_CPU"
	EventOpticsAlarm      = "OPTICS_ALARM"
	EventCLICommand       = "CLI_COMMAND"
	EventUnknown          = "UNKNOWN"

	// Recovery events: the "up" half of LINK_DOWN, OSPF_ADJ_DOWN and
	// BGP_PEER_DOWN. They are SYSTEM/INFO, not FAULT, so they never count as
	// faults; their job is to close an outage (see internal/report).
	EventLinkUp    = "LINK_UP"
	EventOSPFAdjUp = "OSPF_ADJ_UP"
	EventBGPPeerUp = "BGP_PEER_UP"

	// Further fault classes. None has a triage playbook yet, so they are
	// stored and reported but start no diagnostics.
	EventHAChange       = "HA_CHANGE"        // HA / cluster / failover state change
	EventHardwareFault  = "HARDWARE_FAULT"   // power supply, fan, temperature
	EventPortErrDisable = "PORT_ERR_DISABLE" // err-disable, port security, BPDU guard

	// EventPasswordSpray is derived by the detector: one source address
	// failing logins on several devices (see DetectorConfig.SprayDevices).
	EventPasswordSpray = "PASSWORD_SPRAY_ATTEMPT"
)

// DefaultAfterHoursStart and DefaultAfterHoursEnd define the default 00:00-06:00 window.
const (
	DefaultAfterHoursStart = 0
	DefaultAfterHoursEnd   = 6
)

type rule struct {
	re       *regexp.Regexp
	category string
	event    string
	severity string
}

func mk(pattern, category, event, severity string) rule {
	return rule{re: regexp.MustCompile(`(?i)` + pattern), category: category, event: event, severity: severity}
}

// rules is the ordered classification table; the first match wins.
var rules = []rule{
	mk(`config_i|commit\[|cmdrecord|ui_commit|cfgpath=|configuration chang(?:e|ed)|clish\[\d+\]:\s*cmd by \S+:\s*start executing\s*:\s*(?:set|add|delete|remove|save|load)\b`,
		collector.CategoryConfig, EventConfigChange, collector.SeverityWarning),

	mk(`login[ _]success(?:ful)?|successful login|accepted (?:password|publickey|keyboard-interactive)|logged in (?:successfully|from)|succeeded in logging in`,
		collector.CategoryAuth, EventLoginSuccess, collector.SeverityInfo),

	mk(`authentication (?:failure|failed|error)|failed password|bad auth|login[ _]fail(?:ed|ure)|failed login|failed to log ?in|invalid user`,
		collector.CategoryAuth, EventLoginFailure, collector.SeverityWarning),

	mk(`ospf.*adjchg.*down|ospf.*neighbor.*down|ospf.*nbr_chg.*down|ospf.*nbr.*(?:to|->)\\s*down\\b|rpd_ospf_nbrdown`,
		collector.CategoryFault, EventOSPFAdjDown, collector.SeverityError),

	mk(`bgp.*adjchange.*down|bgp.*peer.*down|bgp.*from established|rpd_bgp_neighbor_state_changed.*(?:idle|active|connect)|bgp.*backward.?transition|bgp.*notification.*sent`,
		collector.CategoryFault, EventBGPPeerDown, collector.SeverityError),

	mk(`vrrp.*backup|vrrp.*master.*lost|keepalived.*(?:entering (?:backup|fault)|changed state to (?:backup|fault))`,
		collector.CategoryFault, EventVRRPTransition, collector.SeverityWarning),

	mk(`stp.*topology.change|spanning-tree.*tcn|spantree.*topo`,
		collector.CategoryFault, EventSTPTCN, collector.SeverityWarning),

	// HA / cluster / failover. "subtype=ha" is a FortiGate HA event, "CLUS-"
	// a Check Point ClusterXL state change, "Switching to Active/Standby" and
	// "Failover" a Cisco ASA or generic failover pair. Best effort: the rule
	// flags a state change, not which node is now active.
	mk(`subtype="?ha\b"?|clus-\d+.*state change|\bfailover\b|switching to (?:active|standby)|\bha[ _](?:state|role)`,
		collector.CategoryFault, EventHAChange, collector.SeverityWarning),

	// Optical transceiver / DDM alarms. Placed before the hardware rule so
	// "temperature high" on a transceiver is filed as optics, not chassis.
	mk(`(?:transceiver|optical|\\bsfp\\b|\\bqsfp|\\bddm\\b|\\brx power|\\btx power|\\blos\\b|loss of signal).*(?:alarm|warning|threshold|low|high|loss|fail|fault|absent|los\\b)|(?:rx|tx)[ _-]?power.*(?:low|high|alarm|warn)`,
		collector.CategoryFault, EventOpticsAlarm, collector.SeverityWarning),

	mk(`(?:power[ -]?supply|\bpsu\b|\bfans?\b|temperature|thermal|over-?heat).*(?:fail|fault|down|alarm|critical|exceed|too high|high|removed|stopp|shut ?down)`,
		collector.CategoryFault, EventHardwareFault, collector.SeverityError),

	mk(`err[-_ ]?disable|psecure[_-]violation|port[- ]security.*violation|bpdu ?guard|loop ?guard|root[ _]?inconsistent|storm[- ]control.*(?:shut|disabl|block)`,
		collector.CategoryFault, EventPortErrDisable, collector.SeverityError),

	mk(`link-3-updown.*down|carrier.*down|interface.*down|link is down|link[ _]down|ifoperstatus down|link state changed to down`,
		collector.CategoryFault, EventLinkDown, collector.SeverityError),

	// Recoveries. They come after every "down" rule, so a line that matches
	// both (OSPF "from FULL to DOWN") is a down. OSPF needs "to FULL" so that
	// "from FULL to LOADING" (an adjacency being torn down) is not an up.
	mk(`ospf.*(?:nbrup|(?:to|->)\s*full\b)|ospf.*neighborcurrentstate=full`,
		collector.CategorySystem, EventOSPFAdjUp, collector.SeverityInfo),

	mk(`bgp.*adjchange.*\bup\b|bgp.*to established\b|bgp.*peer.*\bestablished\b`,
		collector.CategorySystem, EventBGPPeerUp, collector.SeverityInfo),

	mk(`changed state to up|link is up|link[ _]up|carrier (?:acquired|up)|ifoperstatus up|entered the up state|link state changed to up`,
		collector.CategorySystem, EventLinkUp, collector.SeverityInfo),

	mk(`vrrp.*(?:entering master|changed state to master)|keepalived.*(?:entering master|changed state to master)`,
		collector.CategorySystem, EventVRRPTransition, collector.SeverityInfo),

	mk(`keepalived.*(?:received advert.*lower priority|master_rx_lower_pri)`,
		collector.CategorySystem, EventHAChange, collector.SeverityInfo),

	mk(`cpu.*utilization.*[89][0-9]%|cpu.*100%`,
		collector.CategorySystem, EventHighCPU, collector.SeverityWarning),
}

var (
	reCmdRecord     = regexp.MustCompile(`(?i)cmdrecord`)
	reCmdRecordLong = regexp.MustCompile(`(?i)command="([^"]*)"`)
	reCmdRecordShrt = regexp.MustCompile(`(?i)cmdrecord[^:]*:\s*[^\s:]+:\s*(.+)$`)
	reReadOnlyCmd   = regexp.MustCompile(`(?i)^(?:display|dis|show|ping|tracert|quit|return|exit|screen-length|system-view|sys)\b`)
)

// Classifier assigns Category, Event and Severity.
type Classifier struct {
	loc             *time.Location
	afterHoursStart int
	afterHoursEnd   int
}

// ClassifierOptions configures custom after-hours evaluation.
type ClassifierOptions struct {
	Location        *time.Location
	AfterHoursStart int // inclusive hour [0..23]
	AfterHoursEnd   int // exclusive hour [0..23]
}

// IsAfterHours reports whether t falls within [startHour, endHour).
// If startHour == endHour, after-hours detection is disabled (returns false).
// If startHour < endHour (e.g. 0 to 6), returns true for hours in [startHour, endHour).
// If startHour > endHour (e.g. 20 to 6, overnight), returns true for hours >= startHour || hours < endHour.
func IsAfterHours(t time.Time, startHour, endHour int) bool {
	if startHour == endHour {
		return false
	}
	h := t.Hour()
	if startHour < endHour {
		return h >= startHour && h < endHour
	}
	return h >= startHour || h < endHour
}

// NewClassifier returns a Classifier with default 00:00-06:00 after-hours window.
// loc is the zone in which the window is evaluated; nil means time.Local.
func NewClassifier(loc *time.Location) *Classifier {
	return NewClassifierWithOptions(ClassifierOptions{
		Location:        loc,
		AfterHoursStart: DefaultAfterHoursStart,
		AfterHoursEnd:   DefaultAfterHoursEnd,
	})
}

// NewClassifierWithOptions returns a Classifier with custom location and after-hours hours.
func NewClassifierWithOptions(opts ClassifierOptions) *Classifier {
	loc := opts.Location
	if loc == nil {
		loc = time.Local
	}
	start := opts.AfterHoursStart
	end := opts.AfterHoursEnd
	if start == 0 && end == 0 {
		end = DefaultAfterHoursEnd
	}
	return &Classifier{
		loc:             loc,
		afterHoursStart: start,
		afterHoursEnd:   end,
	}
}

// Classify tags e in place from its Raw text and Timestamp. Timestamp must
// already be skew-corrected so the after-hours test uses true time.
func (c *Classifier) Classify(e *collector.LogEntry) {
	e.Category, e.Event, e.Severity = collector.CategorySystem, EventUnknown, collector.SeverityInfo

	for _, r := range rules {
		if r.re.MatchString(e.Raw) {
			e.Category, e.Event, e.Severity = r.category, r.event, r.severity
			break
		}
	}

	e.Object = objectOf(e.Event, e.Raw)

	// Read-only Huawei CLI commands are not changes.
	if e.Event == EventConfigChange && reCmdRecord.MatchString(e.Raw) {
		if cmd := cmdRecordCommand(e.Raw); cmd != "" && reReadOnlyCmd.MatchString(cmd) {
			e.Category, e.Event, e.Severity = collector.CategorySystem, EventCLICommand, collector.SeverityInfo
		}
	}

	// Post-classification rule: out-of-hours change.
	if e.Category == collector.CategoryConfig && IsAfterHours(e.Timestamp.In(c.loc), c.afterHoursStart, c.afterHoursEnd) {
		e.Category, e.Event, e.Severity = collector.CategorySecurity, EventAfterHoursChange, collector.SeverityCritical
	}
}

// objectOf returns the interface or neighbor a state-change event is about,
// or "" if the event has no object or the line does not name one. Only the
// events that can be paired into an outage carry one.
func objectOf(event, raw string) string {
	switch event {
	case EventLinkDown, EventLinkUp:
		return ExtractInterface(raw)
	case EventOSPFAdjDown, EventOSPFAdjUp, EventBGPPeerDown, EventBGPPeerUp:
		return ExtractPeer(raw)
	}
	return ""
}

// ClassifyAll classifies every entry in place.
func (c *Classifier) ClassifyAll(entries []collector.LogEntry) {
	for i := range entries {
		c.Classify(&entries[i])
	}
}

// cmdRecordCommand returns the CLI command recorded by a CMDRECORD line, in
// either the long ("Command=\"...\"") or short ("user: command") form.
func cmdRecordCommand(raw string) string {
	if m := reCmdRecordLong.FindStringSubmatch(raw); m != nil {
		return m[1]
	}
	if m := reCmdRecordShrt.FindStringSubmatch(raw); m != nil {
		return m[1]
	}
	return ""
}
