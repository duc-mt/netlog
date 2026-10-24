// ==============================================================================
// Package credentials resolves SSH credentials from a .env file and the environment.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         imported by cmd/netlog and the other internal packages
// Notes:         Go package implementation
// ==============================================================================
// Package credentials resolves the SSH username/password the tool uses,
// in this strict priority order, and never from source code:
//
//  1. An .env file (KEY=VALUE, simple and dependency-free to parse)
//  2. Process environment variables
//  3. An interactive, non-echoing terminal prompt
//
// Whichever source is used, the values never get logged or written to the
// output/log files.
package credentials

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"
)

const (
	EnvUsername = "NETLOG_USERNAME"
	EnvPassword = "NETLOG_PASSWORD"
	EnvKeyFile  = "NETLOG_KEY_FILE"

	// Global jump / bastion host defaults.  Per-named-jump credentials use
	// NETLOG_JUMP_<NAME>_USERNAME / _PASSWORD / _KEY_FILE (same group-key pattern as
	// device credentials).
	EnvJumpHost     = "NETLOG_JUMP_HOST" // host[:port], e.g. bastion.example.com:22
	EnvJumpUsername = "NETLOG_JUMP_USERNAME"
	EnvJumpPassword = "NETLOG_JUMP_PASSWORD" //nolint:gosec // G101: environment variable name, not a hardcoded credential
	EnvJumpKeyFile  = "NETLOG_JUMP_KEY_FILE"
)

// CheckFilePermissions inspects the given file's permissions. On Unix-like systems,
// it returns a warning string if group or other bits are set (permissions looser than 0600).
// Returns "" if the file has 0600 or stricter permissions, or if stat fails.
func CheckFilePermissions(path string) string {
	if path == "" {
		return ""
	}
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	perm := fi.Mode().Perm()
	if perm&0o077 != 0 {
		return fmt.Sprintf("file %q has overly permissive permissions %#o (recommend 0600 or stricter)", path, perm)
	}
	return ""
}

// JumpCredentials holds connection details for a bastion / jump host.
type JumpCredentials struct {
	Host     string // host[:port]; empty disables jump
	Username string
	Password string
	KeyFile  string
}

type Credentials struct {
	Username string
	Password string
	KeyFile  string
}

// Store caches configuration and credentials for the default profile and
// any per-site credential groups defined in .env or the process environment.
type Store struct {
	fileVals     map[string]string
	defaultCreds Credentials
	jumpDefaults JumpCredentials // global jump host defaults (from env / .env)
}

// NewStore initializes a credential Store from the specified env file and
// environment variables, interactively prompting for default credentials
// if not provided.
func NewStore(envFile string) (*Store, error) {
	s := &Store{
		fileVals: make(map[string]string),
	}
	if envFile != "" {
		if warn := CheckFilePermissions(envFile); warn != "" {
			fmt.Fprintf(os.Stderr, "WARNING: %s\n", warn)
		}
		vals, err := parseEnvFile(envFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("reading env file %q: %w", envFile, err)
		}
		if err == nil {
			s.fileVals = vals
		}
	}

	// Seed global jump host defaults (no interactive prompt -- bastions are
	// always configured via env/file rather than prompted interactively).
	s.jumpDefaults = JumpCredentials{
		Host:     s.lookup(EnvJumpHost),
		Username: s.lookup(EnvJumpUsername),
		Password: s.lookup(EnvJumpPassword),
		KeyFile:  s.lookup(EnvJumpKeyFile),
	}

	defaultCreds := Credentials{
		Username: s.lookup(EnvUsername),
		Password: s.lookup(EnvPassword),
		KeyFile:  s.lookup(EnvKeyFile),
	}

	if defaultCreds.Username == "" {
		u, err := promptLine("SSH username: ")
		if err != nil {
			return nil, fmt.Errorf("reading username: %w", err)
		}
		defaultCreds.Username = u
	}

	if defaultCreds.Password == "" && defaultCreds.KeyFile == "" {
		p, err := promptPassword("SSH password (or set NETLOG_KEY_FILE): ")
		if err != nil {
			return nil, fmt.Errorf("reading password: %w", err)
		}
		defaultCreds.Password = p
	}

	if defaultCreds.Username == "" || (defaultCreds.Password == "" && defaultCreds.KeyFile == "") {
		return nil, fmt.Errorf("username and either password or key file are required")
	}

	s.defaultCreds = defaultCreds
	return s, nil
}

// ForGroup returns credentials for the named group (case-insensitive).
// It searches for NETLOG_<GROUP>_USERNAME, NETLOG_<GROUP>_PASSWORD, and NETLOG_<GROUP>_KEY_FILE.
// Any missing field falls back to the default credentials.
func (s *Store) ForGroup(group string) Credentials {
	group = strings.ToUpper(strings.TrimSpace(group))
	if group == "" || group == "DEFAULT" {
		return s.defaultCreds
	}

	cleanGroup := strings.Map(func(r rune) rune {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, group)

	userKey := fmt.Sprintf("NETLOG_%s_USERNAME", cleanGroup)
	passKey := fmt.Sprintf("NETLOG_%s_PASSWORD", cleanGroup)
	fileKey := fmt.Sprintf("NETLOG_%s_KEY_FILE", cleanGroup)

	u := s.lookup(userKey)
	p := s.lookup(passKey)
	k := s.lookup(fileKey)

	if u == "" {
		u = s.defaultCreds.Username
	}
	if p == "" && k == "" {
		p = s.defaultCreds.Password
		k = s.defaultCreds.KeyFile
	}

	return Credentials{Username: u, Password: p, KeyFile: k}
}

// JumpDefaults returns the global bastion / jump host connection details
// loaded from NETLOG_JUMP_HOST / NETLOG_JUMP_USERNAME / NETLOG_JUMP_PASSWORD
// (or their .env equivalents). Host will be empty if none were configured.
func (s *Store) JumpDefaults() JumpCredentials {
	return s.jumpDefaults
}

// ForJumpHost resolves credentials for a named jump host (the value from the
// inventory's jump_host column). It uses the following priority:
//
//  1. NETLOG_JUMP_<NAME>_USERNAME / NETLOG_JUMP_<NAME>_PASSWORD / NETLOG_JUMP_<NAME>_KEY_FILE
//  2. Global NETLOG_JUMP_USERNAME / NETLOG_JUMP_PASSWORD / NETLOG_JUMP_KEY_FILE
//  3. The device default credentials (username and key file, as a last resort)
//
// name is case-insensitive and sanitised before key lookup.
func (s *Store) ForJumpHost(name string) JumpCredentials {
	name = strings.ToUpper(strings.TrimSpace(name))

	cleanName := strings.Map(func(r rune) rune {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, name)

	userKey := fmt.Sprintf("NETLOG_JUMP_%s_USERNAME", cleanName)
	passKey := fmt.Sprintf("NETLOG_JUMP_%s_PASSWORD", cleanName)
	hostKey := fmt.Sprintf("NETLOG_JUMP_%s_HOST", cleanName)
	keyFileKey := fmt.Sprintf("NETLOG_JUMP_%s_KEY_FILE", cleanName)

	host := firstNonEmpty(s.lookup(hostKey), s.jumpDefaults.Host)
	u := firstNonEmpty(s.lookup(userKey), s.jumpDefaults.Username, s.defaultCreds.Username)
	p := firstNonEmpty(s.lookup(passKey), s.jumpDefaults.Password)
	k := firstNonEmpty(s.lookup(keyFileKey), s.jumpDefaults.KeyFile, s.defaultCreds.KeyFile)

	return JumpCredentials{Host: host, Username: u, Password: p, KeyFile: k}
}

// Resolve loads default credentials using the priority described above.
func Resolve(envFile string) (Credentials, error) {
	s, err := NewStore(envFile)
	if err != nil {
		return Credentials{}, fmt.Errorf("resolving credentials: %w", err)
	}
	return s.defaultCreds, nil
}

// parseEnvFile reads simple KEY=VALUE lines. No external dependency is used
// so the build has nothing extra to vendor for this.
func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening env file %q: %w", path, err)
	}
	defer f.Close()

	vals := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue // tolerate stray lines rather than aborting the whole run
		}
		key := strings.TrimSpace(parts[0])
		val := unquote(parts[1])
		vals[key] = val
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning env file %q: %w", path, err)
	}
	return vals, nil
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`)) ||
			(strings.HasPrefix(s, `'`) && strings.HasSuffix(s, `'`)) {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func promptLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading input from terminal: %w", err)
	}
	return strings.TrimSpace(line), nil
}

func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	bytePw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading password from terminal: %w", err)
	}
	return string(bytePw), nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Settings live in the NETLOG_* namespace. The names this tool used before it
// had a namespace of its own (NETBACKUP_*) are still honoured as a deprecated
// fallback, so an existing .env keeps working; a one-time warning tells the
// operator what to rename. Dropping the fallback means deleting legacyName,
// warnLegacy and the second half of lookup.
const (
	envPrefix       = "NETLOG_"
	legacyEnvPrefix = "NETBACKUP_"
)

// legacyName returns the deprecated spelling of a NETLOG_* setting.
func legacyName(key string) (string, bool) {
	if !strings.HasPrefix(key, envPrefix) {
		return "", false
	}
	return legacyEnvPrefix + strings.TrimPrefix(key, envPrefix), true
}

var legacyWarned sync.Map // legacy names already reported

func warnLegacy(legacy, current string) {
	if _, dup := legacyWarned.LoadOrStore(legacy, struct{}{}); !dup {
		fmt.Fprintf(os.Stderr, "WARNING: %s is deprecated; rename it to %s\n", legacy, current)
	}
}

// lookup resolves one setting: the .env file wins over the process
// environment, and the NETLOG_* name wins over its deprecated spelling.
func (s *Store) lookup(key string) string {
	if v := firstNonEmpty(s.fileVals[key], os.Getenv(key)); v != "" {
		return v
	}
	legacy, ok := legacyName(key)
	if !ok {
		return ""
	}
	v := firstNonEmpty(s.fileVals[legacy], os.Getenv(legacy))
	if v != "" {
		warnLegacy(legacy, key)
	}
	return v
}

// Get returns the value for key from .env file or environment variable.
func (s *Store) Get(key string) string {
	if s == nil {
		return os.Getenv(key)
	}
	return s.lookup(key)
}
