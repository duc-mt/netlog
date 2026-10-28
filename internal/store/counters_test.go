// ==============================================================================
// Package store: counter store tests.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-28
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package store

import (
	"testing"
	"time"

	"netlog/internal/collector"
)

func TestCountersPersistence(t *testing.T) {
	dir := t.TempDir()
	path := CountersPath(dir)

	// Test load from non-existent file
	fc, err := LoadCounters(path)
	if err != nil {
		t.Fatalf("unexpected error loading non-existent counters: %v", err)
	}
	if len(fc.Devices) != 0 {
		t.Fatalf("expected 0 devices, got %d", len(fc.Devices))
	}

	// Add sample data and save
	now := time.Now().Truncate(time.Second)
	fc.UpdatedAt = now
	fc.Devices["SW-01"] = DeviceCounters{
		"eth0": collector.InterfaceCounter{
			Timestamp:  now,
			InOctets:   123456,
			OutOctets:  654321,
			InPackets:  1000,
			OutPackets: 500,
		},
	}

	if err := SaveCounters(path, fc); err != nil {
		t.Fatalf("failed to save counters: %v", err)
	}

	// Re-load and verify
	loaded, err := LoadCounters(path)
	if err != nil {
		t.Fatalf("failed to reload counters: %v", err)
	}
	if len(loaded.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(loaded.Devices))
	}
	dev, ok := loaded.Devices["SW-01"]
	if !ok {
		t.Fatalf("missing SW-01")
	}
	cnt, ok := dev["eth0"]
	if !ok {
		t.Fatalf("missing eth0")
	}
	if cnt.InOctets != 123456 || cnt.OutOctets != 654321 {
		t.Errorf("mismatched counter data: %+v", cnt)
	}
}
