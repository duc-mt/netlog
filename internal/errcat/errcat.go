// ==============================================================================
// Package errcat classifies errors into operator-friendly categories.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         imported by cmd/netlog and the other internal packages
// Notes:         Go package implementation
// ==============================================================================
// Package errcat classifies failures into a small set of operator-facing
// categories so the final run summary says *why* a device failed, not just
// that it failed.
package errcat

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

type Category string

const (
	CategoryUnreachable     Category = "CONNECTION_TIMEOUT_OR_UNREACHABLE"
	CategoryConnectFailed   Category = "CONNECT_FAILED"
	CategoryAuthFailed      Category = "AUTHENTICATION_FAILED"
	CategoryCommandFailed   Category = "COMMAND_REJECTED_OR_FAILED"
	CategoryTimeout         Category = "COMMAND_TIMEOUT"
	CategoryTruncatedOutput Category = "TRUNCATED_OUTPUT"
	CategorySessionError    Category = "SSH_SESSION_ERROR"
	CategoryIOError         Category = "LOCAL_IO_ERROR"
	CategoryUnknown         Category = "UNKNOWN_ERROR"
)

// AuditReason maps Category to standard machine-readable audit report status
// (AUTH_FAILED, CONNECT_FAILED, TIMEOUT, TRUNCATED_OUTPUT, or generic FAILED).
func (c Category) AuditReason() string {
	switch c {
	case CategoryAuthFailed:
		return "AUTH_FAILED"
	case CategoryUnreachable, CategoryConnectFailed:
		return "CONNECT_FAILED"
	case CategoryTimeout:
		return "TIMEOUT"
	case CategoryTruncatedOutput:
		return "TRUNCATED_OUTPUT"
	default:
		return "FAILED"
	}
}

// Error wraps an underlying error with a Category so the caller can log,
// count, and report on it without needing to know the plumbing details.
type Error struct {
	Category Category
	Device   string
	Stage    string // e.g. "dial", "auth", "command", "write"
	Err      error
}

func (e *Error) Error() string {
	return fmt.Sprintf("[%s] %s (stage=%s): %v", e.Category, e.Device, e.Stage, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// New builds a categorized error directly when the caller already knows
// the category (e.g. a local timeout it enforced itself).
func New(category Category, device, stage string, err error) *Error {
	return &Error{Category: category, Device: device, Stage: stage, Err: err}
}

// Classify inspects a raw error from the SSH stack and assigns the best
// matching category. It is intentionally heuristic: the golang.org/x/crypto/ssh
// and net packages don't expose rich typed errors for every failure mode
// network gear can produce, so after checking the typed cases we fall back
// to substring matching against known vendor/library error text.
func Classify(device, stage string, err error) *Error {
	if err == nil {
		return nil
	}

	msg := strings.ToLower(err.Error())
	var netErr net.Error
	isTimeout := (errors.As(err, &netErr) && netErr.Timeout()) ||
		strings.Contains(msg, "timed out") ||
		strings.Contains(msg, "i/o timeout")

	if stage == "command" && isTimeout {
		return New(CategoryTimeout, device, stage, err)
	}

	if stage == "validate" || strings.Contains(msg, "truncated") || strings.Contains(msg, "incomplete") {
		return New(CategoryTruncatedOutput, device, stage, err)
	}

	switch {
	case isTimeout,
		strings.Contains(msg, "no route to host"),
		strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "no such host"):
		return New(CategoryUnreachable, device, stage, err)

	case strings.Contains(msg, "unable to authenticate"),
		strings.Contains(msg, "permission denied"),
		strings.Contains(msg, "auth fail"),
		strings.Contains(msg, "authentication failed"):
		return New(CategoryAuthFailed, device, stage, err)

	case strings.Contains(msg, "process exited"),
		strings.Contains(msg, "command not found"),
		strings.Contains(msg, "exit status"):
		return New(CategoryCommandFailed, device, stage, err)

	case strings.Contains(msg, "handshake failed"),
		strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "broken pipe"),
		strings.Contains(msg, "no common algorithm"),
		strings.Contains(msg, "ssh: "),
		strings.Contains(msg, "session"):
		return New(CategorySessionError, device, stage, err)
	}

	return New(CategoryUnknown, device, stage, err)
}
