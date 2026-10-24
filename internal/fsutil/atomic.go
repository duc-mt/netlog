// ==============================================================================
// Package fsutil implements small, dependency-free file helpers.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-18
// License:       MIT
// ==============================================================================
// Usage:         imported by internal/store and internal/triage
// Notes:         Go package implementation
// ==============================================================================
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFileAtomic writes data to a temporary file in the same directory as filename,
// flushes and syncs it to disk (fsync), closes the file, and renames it atomically to filename.
// This guarantees that if power is lost or the disk saturates mid-write, the target file
// is not corrupted or truncated to zero bytes.
func WriteFileAtomic(filename string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating directory for %s: %w", filename, err)
	}

	tmpFile, err := os.CreateTemp(dir, "."+filepath.Base(filename)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file for %s: %w", filename, err)
	}
	tmpName := tmpFile.Name()
	cleaned := false
	defer func() {
		if !cleaned {
			_ = tmpFile.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmpFile.Chmod(perm); err != nil {
		return fmt.Errorf("setting permissions on temp file for %s: %w", filename, err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("writing data to temp file for %s: %w", filename, err)
	}

	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("syncing temp file for %s: %w", filename, err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing temp file for %s: %w", filename, err)
	}

	if err := os.Rename(tmpName, filename); err != nil {
		return fmt.Errorf("renaming temp file to %s: %w", filename, err)
	}
	cleaned = true
	return nil
}
