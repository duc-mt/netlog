//go:build windows

// ==============================================================================
// Package main: advisory data-directory lock (Windows).
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-21
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// lockDataDir takes an exclusive, non-blocking lock on <dir>/.netlog.lock via
// LockFileEx and returns the function that releases it. The Windows kernel
// automatically releases file locks if the process dies or exits.
func lockDataDir(dir string) (func(), error) {
	p := filepath.Join(dir, ".netlog.lock")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening lock file: %w", err)
	}

	h := windows.Handle(f.Fd())
	var ol windows.Overlapped
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK | windows.LOCKFILE_FAIL_IMMEDIATELY)
	err = windows.LockFileEx(h, flags, 0, 1, 0, &ol)
	if err != nil {
		_ = f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errAlreadyRunning
		}
		return nil, fmt.Errorf("locking data directory: %w", err)
	}

	return func() {
		var uol windows.Overlapped
		_ = windows.UnlockFileEx(h, 0, 1, 0, &uol)
		_ = f.Close()
	}, nil
}
