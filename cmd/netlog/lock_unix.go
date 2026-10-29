//go:build !windows

// ==============================================================================
// Package main: advisory data-directory lock (Unix).
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
	"syscall"
)

// lockDataDir takes an exclusive, non-blocking flock on <dir>/.netlog.lock and
// returns the function that releases it. The kernel drops the lock if the
// process dies, so a crashed run never leaves the directory locked.
func lockDataDir(dir string) (func(), error) {
	return lockFile(filepath.Join(dir, ".netlog.lock"))
}

// lockListener is the same for "netlog listen", on its own lock file: one
// listener per data directory, but a listener and a collect/monitor run may
// share it (they append whole batches to the daily JSONL files).
func lockListener(dir string) (func(), error) {
	return lockFile(filepath.Join(dir, ".netlog-listen.lock"))
}

func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errAlreadyRunning
		}
		return nil, fmt.Errorf("locking data directory: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
