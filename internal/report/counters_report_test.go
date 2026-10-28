// ==============================================================================
// Package report: interface deltas table tests.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-28
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package report

import (
	"bytes"
	"strings"
	"testing"

	"netlog/internal/collector"
	"netlog/internal/query"
)

func TestWriteInterfaceDeltasTable(t *testing.T) {
	rep := Report{
		InterfaceDeltas: []collector.InterfaceDelta{
			{
				Device:      "SW-01",
				Interface:   "Gi0/1",
				InBps:       1500000,
				OutBps:      2500000,
				InDropDiff:  15,
				OutDropDiff: 0,
				InErrorDiff: 2,
			},
		},
	}
	var buf bytes.Buffer
	st := query.Style{}
	if err := WriteTable(&buf, rep, st); err != nil {
		t.Fatalf("WriteTable failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Interface Drops & Errors (Diff Stats)") {
		t.Errorf("missing header in output:\n%s", out)
	}
	if !strings.Contains(out, "SW-01") || !strings.Contains(out, "Gi0/1") {
		t.Errorf("missing row data in output:\n%s", out)
	}
}
