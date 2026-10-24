// ==============================================================================
// Package credentials: tests.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go test ./internal/credentials
// Notes:         Go package implementation
// ==============================================================================
package credentials

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseEnvFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	content := `
# Comment line
NETLOG_USERNAME=admin
NETLOG_PASSWORD="secret_password"
QUOTED_SINGLE='single_quoted'
WITH_EQUALS=foo=bar
PASSTHROUGH_QUOTE=p@ss"word!
`
	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp env file: %v", err)
	}

	vals, err := parseEnvFile(envPath)
	if err != nil {
		t.Fatalf("parseEnvFile returned unexpected error: %v", err)
	}

	tests := map[string]string{
		"NETLOG_USERNAME":   "admin",
		"NETLOG_PASSWORD":   "secret_password",
		"QUOTED_SINGLE":     "single_quoted",
		"WITH_EQUALS":       "foo=bar",
		"PASSTHROUGH_QUOTE": `p@ss"word!`,
	}

	for k, expected := range tests {
		if got := vals[k]; got != expected {
			t.Errorf("key %q: expected %q, got %q", k, expected, got)
		}
	}
}

func TestStoreForGroup(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	content := `
NETLOG_USERNAME=default_admin
NETLOG_PASSWORD=default_secret
NETLOG_SITE_A_USERNAME=site_a_user
NETLOG_SITE_A_PASSWORD=site_a_pass
NETLOG_PARTIAL_USERNAME=partial_user
`
	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp env file: %v", err)
	}

	store, err := NewStore(envPath)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	// 1. Default group
	cDef := store.ForGroup("")
	if cDef.Username != "default_admin" || cDef.Password != "default_secret" {
		t.Errorf("unexpected default creds: %+v", cDef)
	}

	// 2. Specific group site_a
	cSiteA := store.ForGroup("site_a")
	if cSiteA.Username != "site_a_user" || cSiteA.Password != "site_a_pass" {
		t.Errorf("unexpected site_a creds: %+v", cSiteA)
	}

	// 3. Partial group (password falls back to default)
	cPartial := store.ForGroup("partial")
	if cPartial.Username != "partial_user" || cPartial.Password != "default_secret" {
		t.Errorf("unexpected partial creds: %+v", cPartial)
	}

	// 4. Unknown group (fully falls back to default)
	cUnknown := store.ForGroup("nonexistent")
	if cUnknown.Username != "default_admin" || cUnknown.Password != "default_secret" {
		t.Errorf("unexpected unknown creds: %+v", cUnknown)
	}
}

func TestStoreKeyFile(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	content := `
NETLOG_USERNAME=key_admin
NETLOG_KEY_FILE=/path/to/id_ed25519
NETLOG_JUMP_KEY_FILE=/path/to/jump_key
`
	if err := os.WriteFile(envPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write temp env file: %v", err)
	}

	store, err := NewStore(envPath)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	cDef := store.ForGroup("")
	if cDef.Username != "key_admin" || cDef.KeyFile != "/path/to/id_ed25519" {
		t.Errorf("unexpected default key creds: %+v", cDef)
	}

	jump := store.JumpDefaults()
	if jump.KeyFile != "/path/to/jump_key" {
		t.Errorf("unexpected jump key creds: %+v", jump)
	}
}

func TestUnquote(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{`"hello"`, "hello"},
		{`'hello'`, "hello"},
		{`"hello`, `"hello`},
		{`hello"`, `hello"`},
		{`p@ss"word!`, `p@ss"word!`},
		{`  "spaces"  `, "spaces"},
	}

	for _, tt := range tests {
		if got := unquote(tt.input); got != tt.expected {
			t.Errorf("unquote(%q): expected %q, got %q", tt.input, tt.expected, got)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "", "first", "second"); got != "first" {
		t.Errorf("expected 'first', got %q", got)
	}
	if got := firstNonEmpty("", ""); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestCheckFilePermissions(t *testing.T) {
	dir := t.TempDir()

	// Safe file: 0600
	safeFile := filepath.Join(dir, "safe.env")
	if err := os.WriteFile(safeFile, []byte("NETLOG_USERNAME=test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if warn := CheckFilePermissions(safeFile); warn != "" {
		t.Errorf("expected no warning for 0600 file, got: %s", warn)
	}

	// Permissive file: 0644
	looseFile := filepath.Join(dir, "loose.env")
	if err := os.WriteFile(looseFile, []byte("NETLOG_USERNAME=test"), 0o644); err != nil {
		t.Fatal(err)
	}
	if warn := CheckFilePermissions(looseFile); warn == "" {
		t.Errorf("expected warning for 0644 file, got none")
	}

	// Non-existent file
	if warn := CheckFilePermissions(filepath.Join(dir, "nonexistent")); warn != "" {
		t.Errorf("expected no warning for nonexistent file, got: %s", warn)
	}
}

// ---- NETLOG_* namespace and the deprecated NETBACKUP_* fallback ---------------

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()
	fn()
	w.Close()
	var buf [8192]byte
	n, _ := r.Read(buf[:])
	return string(buf[:n])
}

func resetLegacyWarnings() {
	legacyWarned.Range(func(k, _ any) bool { legacyWarned.Delete(k); return true })
}

func writeEnv(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLegacyNamesStillWork(t *testing.T) {
	resetLegacyWarnings()
	envPath := writeEnv(t, `
NETBACKUP_USERNAME=old_admin
NETBACKUP_PASSWORD=old_secret
NETBACKUP_SITE_A_USERNAME=old_site_a
NETBACKUP_SITE_A_PASSWORD=old_site_pass
NETBACKUP_JUMP_HOST=bastion.example.com:2222
NETBACKUP_JUMP_USERNAME=old_jump
NETBACKUP_JUMP_PASSWORD=old_jump_pass
NETBACKUP_JUMP_DC1_HOST=dc1-bastion:22
`)
	var store *Store
	warnings := captureStderr(t, func() {
		var err error
		if store, err = NewStore(envPath); err != nil {
			t.Fatalf("NewStore: %v", err)
		}
	})

	if c := store.ForGroup(""); c.Username != "old_admin" || c.Password != "old_secret" {
		t.Errorf("default creds from legacy names: %+v", c)
	}
	if c := store.ForGroup("site_a"); c.Username != "old_site_a" || c.Password != "old_site_pass" {
		t.Errorf("group creds from legacy names: %+v", c)
	}
	jd := store.JumpDefaults()
	if jd.Host != "bastion.example.com:2222" || jd.Username != "old_jump" || jd.Password != "old_jump_pass" {
		t.Errorf("jump defaults from legacy names: %+v", jd)
	}
	if j := store.ForJumpHost("dc1"); j.Host != "dc1-bastion:22" {
		t.Errorf("named jump from legacy names: %+v", j)
	}
	if !strings.Contains(warnings, "NETBACKUP_USERNAME is deprecated; rename it to NETLOG_USERNAME") {
		t.Errorf("expected a deprecation warning naming both spellings, got %q", warnings)
	}
}

func TestNewNamesWinOverLegacy(t *testing.T) {
	resetLegacyWarnings()
	envPath := writeEnv(t, `
NETLOG_USERNAME=new_admin
NETBACKUP_USERNAME=old_admin
NETLOG_PASSWORD=new_secret
NETBACKUP_PASSWORD=old_secret
`)
	var store *Store
	warnings := captureStderr(t, func() {
		var err error
		if store, err = NewStore(envPath); err != nil {
			t.Fatal(err)
		}
	})
	if c := store.ForGroup(""); c.Username != "new_admin" || c.Password != "new_secret" {
		t.Errorf("NETLOG_* must win over NETBACKUP_*: %+v", c)
	}
	if warnings != "" {
		t.Errorf("no deprecation warning when the new names are used, got %q", warnings)
	}

	// The same precedence holds for the process environment.
	t.Setenv("NETLOG_KEY_FILE", "/new/key")
	t.Setenv("NETBACKUP_KEY_FILE", "/old/key")
	if got := store.Get("NETLOG_KEY_FILE"); got != "/new/key" {
		t.Errorf("Get(NETLOG_KEY_FILE) = %q", got)
	}
}

func TestLegacyEnvironmentVariablesAndOneTimeWarning(t *testing.T) {
	resetLegacyWarnings()
	t.Setenv("NETBACKUP_USERNAME", "env_old_user")
	t.Setenv("NETBACKUP_PASSWORD", "env_old_pass")
	t.Setenv("NETLOG_USERNAME", "")
	t.Setenv("NETLOG_PASSWORD", "")

	var store *Store
	var first, second string
	first = captureStderr(t, func() {
		var err error
		if store, err = NewStore(filepath.Join(t.TempDir(), "absent.env")); err != nil {
			t.Fatal(err)
		}
	})
	second = captureStderr(t, func() { _ = store.ForGroup(""); _ = store.ForGroup("other") })

	if c := store.ForGroup(""); c.Username != "env_old_user" || c.Password != "env_old_pass" {
		t.Errorf("legacy process environment not honoured: %+v", c)
	}
	if n := strings.Count(first, "NETBACKUP_USERNAME is deprecated"); n != 1 {
		t.Errorf("warning must appear once on first use, got %d: %q", n, first)
	}
	if second != "" {
		t.Errorf("warning must not repeat, got %q", second)
	}
}

func TestLegacyNameMapping(t *testing.T) {
	for in, want := range map[string]string{
		"NETLOG_USERNAME": "NETBACKUP_USERNAME", "NETLOG_JUMP_DC1_HOST": "NETBACKUP_JUMP_DC1_HOST",
	} {
		if got, ok := legacyName(in); !ok || got != want {
			t.Errorf("legacyName(%q) = %q, %v", in, got, ok)
		}
	}
	for _, in := range []string{"USERNAME", "NETBACKUP_USERNAME", "HOME"} {
		if got, ok := legacyName(in); ok {
			t.Errorf("legacyName(%q) = %q; only NETLOG_* keys have a legacy spelling", in, got)
		}
	}
}

// "make init" copies examples/.env.example to .env: the template must parse and
// use only the NETLOG_* names.
func TestExampleEnvFile(t *testing.T) {
	vals, err := parseEnvFile("../../examples/.env.example")
	if err != nil {
		t.Fatal(err)
	}
	if vals[EnvUsername] == "" || vals[EnvPassword] == "" {
		t.Errorf("template must define %s and %s, got %v", EnvUsername, EnvPassword, vals)
	}
	for k := range vals {
		if !strings.HasPrefix(k, envPrefix) {
			t.Errorf("template defines %q outside the %s namespace", k, envPrefix)
		}
	}
	raw, _ := os.ReadFile("../../examples/.env.example")
	if strings.Contains(string(raw), "NETBACKUP_") && !strings.Contains(string(raw), "deprecated") {
		t.Error("the template may only mention NETBACKUP_* to flag it as deprecated")
	}
}
