// ==============================================================================
// Package store: interface counter snapshots persistence.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-28
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"netlog/internal/collector"
	"netlog/internal/fsutil"
)

const countersFileName = ".netlog_counters.json"

// CountersPath returns the path to the persisted interface counters JSON file.
func CountersPath(dataDir string) string {
	return filepath.Join(dataDir, countersFileName)
}

// DeviceCounters holds a map of interface name to InterfaceCounter.
type DeviceCounters map[string]collector.InterfaceCounter

// FleetCounters is the root schema persisted in .netlog_counters.json.
type FleetCounters struct {
	UpdatedAt time.Time                 `json:"updated_at"`
	Devices   map[string]DeviceCounters `json:"devices"`
}

// LoadCounters reads the stored counter snapshots.
// Returns an empty struct if the file does not exist.
func LoadCounters(path string) (*FleetCounters, error) {
	fc := &FleetCounters{
		Devices: make(map[string]DeviceCounters),
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fc, nil
		}
		return nil, fmt.Errorf("reading counters file: %w", err)
	}
	if len(data) == 0 {
		return fc, nil
	}
	if err := json.Unmarshal(data, fc); err != nil {
		return nil, fmt.Errorf("decoding counters file: %w", err)
	}
	if fc.Devices == nil {
		fc.Devices = make(map[string]DeviceCounters)
	}
	return fc, nil
}

// SaveCounters writes the fleet counters snapshot atomically to disk.
func SaveCounters(path string, fc *FleetCounters) error {
	if fc == nil {
		return nil
	}
	data, err := json.MarshalIndent(fc, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding counters: %w", err)
	}
	data = append(data, '\n')
	return fsutil.WriteFileAtomic(path, data, filePerm)
}
