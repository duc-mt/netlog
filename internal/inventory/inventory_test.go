// ==============================================================================
// Package inventory: tests.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go test ./internal/inventory
// Notes:         Go package implementation
// ==============================================================================
package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadInventory(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "inventory.csv")
	content := `hostname,address,port,vendor,credential_group
# Comment line
core-sw-01,10.10.1.1,22,cisco_ios,site_a
dc-fw-01,10.20.1.1,,fortigate,site_b
edge-rtr-01,10.30.1.1,2222,juniper_junos
"quoted-sw",10.40.1.1,22,aruba,datacenter
bad-line
invalid-port,10.50.1.1,99999,cisco_ios
`
	if err := os.WriteFile(csvPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp csv: %v", err)
	}

	devices, warnings := Load(csvPath)

	if len(devices) != 4 {
		t.Errorf("expected 4 valid devices, got %d", len(devices))
	}
	if len(warnings) != 2 {
		t.Errorf("expected 2 warnings, got %d", len(warnings))
	}

	// Verify device 1
	if devices[0].Hostname != "core-sw-01" || devices[0].CredentialGroup != "site_a" {
		t.Errorf("unexpected device 0: %+v", devices[0])
	}

	// Verify device 2 (default port 22, site_b)
	if devices[1].Hostname != "dc-fw-01" || devices[1].Port != 22 || devices[1].CredentialGroup != "site_b" {
		t.Errorf("unexpected device 1: %+v", devices[1])
	}

	// Verify device 3 (omitted credential_group defaults to "default")
	if devices[2].Port != 2222 || devices[2].CredentialGroup != "default" {
		t.Errorf("unexpected device 2: %+v", devices[2])
	}

	// Verify device 4 (quoted hostname, datacenter group)
	if devices[3].Hostname != "quoted-sw" || devices[3].CredentialGroup != "datacenter" {
		t.Errorf("unexpected device 3: %+v", devices[3])
	}
}
