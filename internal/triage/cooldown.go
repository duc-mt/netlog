// ==============================================================================
// Package triage: per-(device, event) cooldown tracker (GATE 2).
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         ok, wait := cd.Allow("NHG-BVU-GW-01", "OSPF_ADJ_DOWN")
// Notes:         Go package implementation
// ==============================================================================
// GATE 2: at most one triage per device and event type per cooldown period,
// so a flapping neighbour or a login storm cannot turn netlog into a source
// of SSH sessions against the very device that is in trouble.
//
//	LINK_DOWN, LINK_FLAP  10 min      OSPF_ADJ_DOWN  5 min
//	BGP_PEER_DOWN          5 min      BRUTE_FORCE_ATTEMPT 15 min
//
// Event types not in that list (VRRP, STP, high CPU) get the conservative
// default of 5 minutes rather than no limit.
//
// Cooldown timestamps are persisted to data/.netlog_cooldown.json when a path
// is given. That matters for cron-style "netlog collect" runs, where every
// invocation is a fresh process: without it the in-memory tracker would reset
// on each run and the cooldown would never hold.
package triage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"netlog/internal/fsutil"
)

// DefaultCooldown applies to event types without an explicit entry.
const DefaultCooldown = 5 * time.Minute

var cooldowns = map[string]time.Duration{
	"LINK_DOWN":              10 * time.Minute,
	"LINK_FLAP":              10 * time.Minute,
	"OSPF_ADJ_DOWN":          5 * time.Minute,
	"BGP_PEER_DOWN":          5 * time.Minute,
	"BRUTE_FORCE_ATTEMPT":    15 * time.Minute,
	"PASSWORD_SPRAY_ATTEMPT": 15 * time.Minute,
	"CONFIG_CHANGE":          2 * time.Minute,
	"AFTER_HOURS_CHANGE":     2 * time.Minute,
}

// CooldownFor returns the cooldown period for an event type.
func CooldownFor(event string) time.Duration {
	if d, ok := cooldowns[event]; ok {
		return d
	}
	return DefaultCooldown
}

// Cooldown tracks when each (device, event) last passed GATE 2. It is safe
// for concurrent use.
type Cooldown struct {
	path string
	now  func() time.Time

	mu   sync.Mutex
	last map[string]time.Time
}

// NewCooldown returns a tracker persisted at path ("" keeps it in memory
// only). A missing file is normal. If the file exists but cannot be read, a
// usable empty tracker is still returned together with the error, so the
// caller can log it; the cost of a lost file is at most one extra triage.
func NewCooldown(path string) (*Cooldown, error) {
	c := &Cooldown{path: path, now: time.Now, last: make(map[string]time.Time)}
	if path == "" {
		return c, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return c, nil
		}
		return c, fmt.Errorf("reading cooldown file %s: %w", path, err)
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &c.last); err != nil {
			c.last = make(map[string]time.Time)
			return c, fmt.Errorf("cooldown file %s is corrupt, starting empty: %w", path, err)
		}
	}
	return c, nil
}

func cooldownKey(host, event string) string { return host + "|" + event }

// Allow reports whether a triage for (host, event) may proceed. If it may,
// the attempt is recorded immediately, so the cooldown also covers triages
// that later fail or are aborted (no retry storms). If it may not, remaining
// is how long until the next triage is permitted.
func (c *Cooldown) Allow(host, event string) (ok bool, remaining time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	key := cooldownKey(host, event)
	period := CooldownFor(event)
	if last, seen := c.last[key]; seen {
		if elapsed := now.Sub(last); elapsed >= 0 && elapsed < period {
			return false, period - elapsed
		}
	}
	c.last[key] = now
	c.saveLocked(now)
	return true, 0
}

// saveLocked persists the table, dropping entries whose cooldown has long
// expired. Persistence is best-effort: a failure never blocks triage.
func (c *Cooldown) saveLocked(now time.Time) {
	if c.path == "" {
		return
	}
	maxPeriod := DefaultCooldown
	for _, d := range cooldowns {
		if d > maxPeriod {
			maxPeriod = d
		}
	}
	for k, t := range c.last {
		if now.Sub(t) > maxPeriod {
			delete(c.last, k)
		}
	}
	data, err := json.MarshalIndent(c.last, "", "  ")
	if err != nil {
		return
	}
	_ = fsutil.WriteFileAtomic(c.path, append(data, '\n'), 0o640)
}
