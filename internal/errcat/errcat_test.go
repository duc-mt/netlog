// ==============================================================================
// Package errcat: tests.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go test ./internal/errcat
// Notes:         Go package implementation
// ==============================================================================
package errcat

import (
	"errors"
	"testing"
)

type dummyTimeoutError struct{}

func (d dummyTimeoutError) Error() string   { return "i/o timeout" }
func (d dummyTimeoutError) Timeout() bool   { return true }
func (d dummyTimeoutError) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	tests := []struct {
		device   string
		stage    string
		err      error
		expected Category
	}{
		{"sw01", "connect", dummyTimeoutError{}, CategoryUnreachable},
		{"sw01", "command", dummyTimeoutError{}, CategoryTimeout},
		{"sw01", "command", errors.New("command timed out after 30s"), CategoryTimeout},
		{"sw01", "connect", errors.New("connection refused"), CategoryUnreachable},
		{"sw01", "connect", errors.New("ssh: handshake failed: permission denied"), CategoryAuthFailed},
		{"sw01", "connect", errors.New("ssh: unable to authenticate, attempted methods [password], no supported methods remain"), CategoryAuthFailed},
		{"sw01", "connect", errors.New("ssh: handshake failed: read tcp 10.0.0.1:22: connection reset by peer"), CategorySessionError},
		{"sw01", "connect", errors.New("ssh: handshake failed: no common algorithm for host key"), CategorySessionError},
		{"sw01", "command", errors.New("process exited with status 1"), CategoryCommandFailed},
		{"sw01", "connect", errors.New("ssh: unexpected packet type"), CategorySessionError},
		{"sw01", "validate", errors.New("backup appears truncated or incomplete: expected end marker not found"), CategoryTruncatedOutput},
		{"sw01", "write", errors.New("something totally random"), CategoryUnknown},
	}

	for _, tt := range tests {
		cerr := Classify(tt.device, tt.stage, tt.err)
		if cerr.Category != tt.expected {
			t.Errorf("Classify(%s, %s, %v): expected category %s, got %s", tt.device, tt.stage, tt.err, tt.expected, cerr.Category)
		}
	}

	// Verify AuditReason mappings
	auditTests := map[Category]string{
		CategoryAuthFailed:      "AUTH_FAILED",
		CategoryUnreachable:     "CONNECT_FAILED",
		CategoryConnectFailed:   "CONNECT_FAILED",
		CategoryTimeout:         "TIMEOUT",
		CategoryTruncatedOutput: "TRUNCATED_OUTPUT",
		CategoryUnknown:         "FAILED",
	}
	for cat, expected := range auditTests {
		if got := cat.AuditReason(); got != expected {
			t.Errorf("cat.AuditReason() for %s: expected %s, got %s", cat, expected, got)
		}
	}
}
