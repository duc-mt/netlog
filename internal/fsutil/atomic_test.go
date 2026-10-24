package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	tempDir := t.TempDir()
	target := filepath.Join(tempDir, "sub", "testfile.cfg")

	data := []byte("hostname core-router-01\nend\n")
	if err := WriteFileAtomic(target, data, 0o600); err != nil {
		t.Fatalf("WriteFileAtomic failed: %v", err)
	}

	readData, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("reading target file: %v", err)
	}
	if string(readData) != string(data) {
		t.Errorf("content mismatch, expected %q, got %q", string(data), string(readData))
	}

	fi, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected 0600 file permissions, got %#o", perm)
	}

	dirFi, err := os.Stat(filepath.Dir(target))
	if err != nil {
		t.Fatalf("stat target dir: %v", err)
	}
	if perm := dirFi.Mode().Perm(); perm != 0o700 {
		t.Errorf("expected 0700 dir permissions, got %#o", perm)
	}
}
