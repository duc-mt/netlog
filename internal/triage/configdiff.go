// ==============================================================================
// Package triage: configuration diff capture after a configuration change.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-27
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
// A CONFIG_CHANGE (or AFTER_HOURS_CHANGE) signal runs the config_change
// playbook: one read-only comparison command per platform (configDiffSteps in
// playbooks.go), nothing that saves, commits or rolls back. The output is
// stored in IncidentReport.ConfigDiff so the change is on record before any
// fault it causes. A platform without a comparison command is skipped.
package triage

import (
	"fmt"
	"strings"

	"netlog/internal/collector"
	"netlog/internal/pipeline"
)

// isConfigDiff reports whether the playbook is the config-diff capture.
func isConfigDiff(playbook string) bool { return playbook == pipeline.PlaybookConfigChange }

// configDiffOf joins the successful comparison outputs of a config_change
// triage. With one command (the normal case) it is that command's output as is.
func configDiffOf(diags []collector.DiagCmd) string {
	var ok []collector.DiagCmd
	for _, d := range diags {
		if d.Command == "(connect)" || (d.Error != "" && strings.TrimSpace(d.Output) == "") {
			continue
		}
		ok = append(ok, d)
	}
	switch len(ok) {
	case 0:
		return ""
	case 1:
		return ok[0].Output
	}
	var b strings.Builder
	for i, d := range ok {
		if i > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "# %s\n%s", d.Command, d.Output)
	}
	return b.String()
}

// configDiffHint describes the capture in one line for the incident's hints.
func configDiffHint(diff string) string {
	if strings.TrimSpace(diff) == "" {
		return "The configuration comparison returned no output: the running configuration matched the reference, or the device rejected the command (see diagnostics)."
	}
	return fmt.Sprintf("Configuration comparison captured (%d bytes) right after the change; see config_diff.", len(diff))
}
