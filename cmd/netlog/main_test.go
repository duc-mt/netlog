// ==============================================================================
// Package main: end-to-end tests of the netlog command against a fake device.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-21
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"netlog/internal/collector"
	"netlog/internal/inventory"
	"netlog/internal/parser"
	"netlog/internal/pipeline"
	"netlog/internal/report"
	"netlog/internal/store"
)

// fakeIOS is a Cisco-IOS-like device with a fixed log buffer (so repeated
// polls see the same lines, as on a real device) that tests can append to.
type fakeIOS struct {
	mu    sync.Mutex
	base  time.Time
	extra []string
	execs []string
}

func (f *fakeIOS) stamp(ago time.Duration) string {
	return f.base.Add(-ago).Format("Jan _2 15:04:05.000")
}

func (f *fakeIOS) addLine(line string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.extra = append(f.extra, line)
}

func (f *fakeIOS) count(cmd string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.execs {
		if c == cmd {
			n++
		}
	}
	return n
}

func (f *fakeIOS) respond(cmd string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execs = append(f.execs, cmd)
	switch cmd {
	case "show logging":
		out := "Syslog logging: enabled\n    Log Buffer (65536 bytes):\n\n" +
			f.stamp(5*time.Minute) + ": %SYS-5-CONFIG_I: Configured from console by tanvt on vty0 (10.10.10.50)\n" +
			f.stamp(4*time.Minute) + ": %OSPF-5-ADJCHG: Process 1, Nbr 10.255.255.4 on GigabitEthernet0/1 from FULL to DOWN, Neighbor Down: Dead timer expired\n" +
			f.stamp(3*time.Minute) + ": %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down\n" +
			f.stamp(2*time.Minute) + ": %SYS-5-CONFIG_I: Configured from console by \x1b[2Jevil on vty1 (6.6.6.6)\n"
		return out + strings.Join(f.extra, "")
	case "show clock":
		return "*" + time.Now().Add(3*time.Second).Format("15:04:05.000 MST Mon Jan 2 2006") + "\n"
	}
	return "output of [" + cmd + "]\n"
}

// pinDaytime makes the local zone a fixed offset at which "now" reads 14:00.
// netlog reclassifies config changes between 00:00 and 06:00 local as
// AFTER_HOURS_CHANGE, so without this the tests would pass in the daytime and
// fail if they happened to run at night. It must run before anything captures
// time.Local (the fake device formats its log lines in local time, and the app
// reads time.Local when it starts).
func pinDaytime(t *testing.T) {
	t.Helper()
	old := time.Local
	now := time.Now().UTC()
	// Whole minutes only: RFC 3339 (hence the JSON state files) cannot represent
	// an offset with a seconds component, and real zones never have one.
	offset := (14*3600 - (now.Hour()*3600 + now.Minute()*60 + now.Second())) / 60 * 60
	time.Local = time.FixedZone("netlog-test", offset)
	t.Cleanup(func() { time.Local = old })
}

func startFakeIOS(t *testing.T) (*fakeIOS, string, int) {
	t.Helper()
	pinDaytime(t)
	dev := &fakeIOS{base: time.Now()}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if c.User() == "u" && string(pw) == "p" {
			return nil, nil
		}
		return nil, fmt.Errorf("denied")
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, _ := nc.Accept()
					go func() {
						for r := range creqs {
							if r.Type != "exec" {
								r.Reply(false, nil)
								continue
							}
							n := binary.BigEndian.Uint32(r.Payload[:4])
							cmd := string(r.Payload[4 : 4+n])
							r.Reply(true, nil)
							ch.Write([]byte(dev.respond(cmd)))
							ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
							ch.Close()
							return
						}
					}()
				}
			}()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return dev, host, port
}

type env struct {
	dir  string
	args []string // common collect flags
}

func newEnv(t *testing.T, inventory string) env {
	t.Helper()
	t.Setenv("NETLOG_USERNAME", "u")
	t.Setenv("NETLOG_PASSWORD", "p")
	t.Setenv("NETLOG_JUMP_HOST", "")
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.csv")
	if err := os.WriteFile(inv, []byte("hostname,address,port,vendor,credential_group,jump_host\n"+inventory), 0o600); err != nil {
		t.Fatal(err)
	}
	return env{dir: dir, args: []string{
		"--inventory", inv, "--env-file", filepath.Join(dir, "none.env"), "--data-dir", filepath.Join(dir, "data"),
		"--known-hosts", filepath.Join(dir, "known_hosts"), "--jump=false",
	}}
}

func (e env) run(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var o, er bytes.Buffer
	code = run(args, &o, &er)
	return o.String(), er.String(), code
}

func (e env) collect(t *testing.T) (string, int) {
	_, stderr, code := e.run(t, append([]string{"collect"}, e.args...)...)
	return stderr, code
}

func (e env) logEntries(t *testing.T) []collector.LogEntry {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(e.dir, "data", "logs", "*.jsonl"))
	var out []collector.LogEntry
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if line == "" {
				continue
			}
			var le collector.LogEntry
			if err := json.Unmarshal([]byte(line), &le); err != nil {
				t.Fatalf("bad JSONL: %v", err)
			}
			out = append(out, le)
		}
	}
	return out
}

func (e env) incidents(t *testing.T) []collector.IncidentReport {
	t.Helper()
	rs, err := store.ListIncidents(store.IncidentsDir(filepath.Join(e.dir, "data")), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestCollectEndToEnd(t *testing.T) {
	dev, host, port := startFakeIOS(t)
	e := newEnv(t, fmt.Sprintf("SW-LAB,%s,%d,cisco_ios,default,\n", host, port))

	// ---- first poll: ingest, classify, correct skew, triage ----
	stderr, code := e.collect(t)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr)
	}
	entries := e.logEntries(t)
	if len(entries) != 4 {
		t.Fatalf("want 4 entries (banner lines are not events), got %d\n%s", len(entries), stderr)
	}
	byEvent := map[string]collector.LogEntry{}
	for _, le := range entries {
		byEvent[le.Event] = le
	}
	for _, ev := range []string{"CONFIG_CHANGE", "OSPF_ADJ_DOWN", "LINK_DOWN"} {
		if _, ok := byEvent[ev]; !ok {
			t.Errorf("missing event %s", ev)
		}
	}
	var tanvt collector.LogEntry
	for _, le := range entries {
		if le.User == "tanvt" {
			tanvt = le
		}
	}
	if tanvt.ID == "" || tanvt.SessionID != "vty0" || tanvt.SourceIP != "10.10.10.50" {
		t.Errorf("config change lost its attribution: %+v", tanvt)
	}
	if skew := entries[0].SkewMs; skew < 1500 || skew > 6000 {
		t.Errorf("skew_ms = %d, want about +3000 (the fake clock runs 3s fast)", skew)
	}
	// Corrected time should land close to the true event time (5 minutes ago).
	if d := time.Since(tanvt.Timestamp); d < 4*time.Minute || d > 6*time.Minute {
		t.Errorf("corrected timestamp is %v old, want about 5m (event was 5m before the fake's 'now')", d)
	}
	if n := len(e.incidents(t)); n != 2 { // OSPF down + link down; the evil config line is not a fault
		t.Fatalf("want 2 incidents (ospf_adj_down, link_down), got %d\n%s", n, stderr)
	}
	if dev.count("show ip ospf neighbor") != 1 {
		t.Errorf("ospf playbook should have run once, ran %d times", dev.count("show ip ospf neighbor"))
	}
	if _, err := os.Stat(store.StatePath(filepath.Join(e.dir, "data"))); err != nil {
		t.Errorf("state file missing: %v", err)
	}

	// ---- second poll of the same buffer: nothing new, nothing triaged ----
	stderr, code = e.collect(t)
	if code != 0 || len(e.logEntries(t)) != 4 || len(e.incidents(t)) != 2 {
		t.Fatalf("repeat poll must be idempotent: code=%d entries=%d incidents=%d\n%s", code, len(e.logEntries(t)), len(e.incidents(t)), stderr)
	}
	if !strings.Contains(stderr, "0 new log entries") {
		t.Errorf("summary should report 0 new entries:\n%s", stderr)
	}

	// ---- a new OSPF-down line: stored, but the persisted cooldown stops triage ----
	dev.addLine(dev.stamp(30*time.Second) + ": %OSPF-5-ADJCHG: Process 1, Nbr 10.255.255.9 on GigabitEthernet0/2 from FULL to DOWN, Neighbor Down: Dead timer expired\n")
	stderr, code = e.collect(t)
	if code != 0 || len(e.logEntries(t)) != 5 {
		t.Fatalf("new line must be stored: code=%d entries=%d\n%s", code, len(e.logEntries(t)), stderr)
	}
	if dev.count("show ip ospf neighbor") != 1 || len(e.incidents(t)) != 2 {
		t.Errorf("cooldown must hold across runs: ospf execs=%d incidents=%d", dev.count("show ip ospf neighbor"), len(e.incidents(t)))
	}
	if !strings.Contains(stderr, "in cooldown") {
		t.Errorf("suppression should be logged:\n%s", stderr)
	}

	// ---- query / timeline / incidents ----
	out, _, code := e.run(t, "query", "--data-dir", filepath.Join(e.dir, "data"), "--category", "FAULT", "--since", "1h", "--no-color")
	if code != 0 || !strings.Contains(out, "OSPF_ADJ_DOWN") || !strings.Contains(out, "LINK_DOWN") || strings.Contains(out, "CONFIG_CHANGE") {
		t.Errorf("query --category FAULT:\n%s", out)
	}
	out, _, code = e.run(t, "query", "--data-dir", filepath.Join(e.dir, "data"), "--user", "tanvt", "--format", "json", "--since", "1h")
	var js []collector.LogEntry
	if code != 0 || json.Unmarshal([]byte(out), &js) != nil || len(js) != 1 || js[0].User != "tanvt" {
		t.Errorf("query --user tanvt --format json: code=%d out=%s", code, out)
	}
	out, _, code = e.run(t, "timeline", "--data-dir", filepath.Join(e.dir, "data"), "--from", time.Now().Add(-30*time.Minute).Format("2006-01-02 15:04:05"), "--no-color")
	if code != 0 || !strings.Contains(out, "[CONFIG]") || !strings.Contains(out, "└── Likely caused by config change by tanvt") {
		t.Errorf("timeline should attribute the OSPF fault to tanvt's change:\n%s", out)
	}
	out, _, code = e.run(t, "incidents", "--data-dir", filepath.Join(e.dir, "data"), "--since", "1h", "--no-color")
	if code != 0 || !strings.Contains(out, "ospf_adj_down") || !strings.Contains(out, "link_down") {
		t.Errorf("incidents list:\n%s", out)
	}
	id := e.incidents(t)[0].ID
	// Default text format
	out, _, code = e.run(t, "incidents", "--data-dir", filepath.Join(e.dir, "data"), "--id", id[:4])
	if code != 0 || !strings.Contains(out, "INCIDENT REPORT:") || !strings.Contains(out, "DIAGNOSTICS") {
		t.Errorf("incidents --id (text): code=%d\n%s", code, out)
	}
	// Explicit json format
	out, _, code = e.run(t, "incidents", "--data-dir", filepath.Join(e.dir, "data"), "--id", id[:4], "--format", "json")
	var rep collector.IncidentReport
	if code != 0 || json.Unmarshal([]byte(out), &rep) != nil || rep.ID != id || len(rep.Diagnostics) == 0 {
		t.Errorf("incidents --id (json): code=%d\n%s", code, out)
	}

	// ---- a hostile device cannot drive the operator's terminal or forge log lines ----
	if strings.Contains(stderr, "\x1b") {
		t.Errorf("escape from device text reached netlog's own log output:\n%q", stderr)
	}
	out, _, _ = e.run(t, "query", "--data-dir", filepath.Join(e.dir, "data"), "--since", "1h")
	if strings.Contains(out, "\x1b") {
		t.Errorf("escape from device text reached the table output:\n%q", out)
	}
}

func TestCollectExitCodes(t *testing.T) {
	// A device that cannot be reached: the run completes but nothing was polled.
	e := newEnv(t, "DEAD,127.0.0.1,1,cisco_ios,default,\n")
	stderr, code := e.collect(t)
	if code != exitError || !strings.Contains(stderr, "no device could be polled") {
		t.Errorf("all devices failing must exit 1, got %d\n%s", code, stderr)
	}

	// An unsupported vendor alongside a healthy device: partial failure is still success.
	_, host, port := startFakeIOS(t)
	e = newEnv(t, fmt.Sprintf("SW-LAB,%s,%d,cisco_ios,default,\nPF,%s,%d,sophos,default,\n", host, port, host, port))
	stderr, code = e.collect(t)
	if code != 0 {
		t.Errorf("partial failure must exit 0, got %d\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "PF: netlog has no log fetch command") {
		t.Errorf("unsupported vendor should be reported:\n%s", stderr)
	}

	for name, tc := range map[string]struct {
		args []string
		want int
	}{
		"no args":             {nil, exitUsage},
		"unknown command":     {[]string{"bogus"}, exitUsage},
		"help":                {[]string{"help"}, exitOK},
		"version":             {[]string{"version"}, exitOK},
		"bad flag":            {[]string{"query", "--nope"}, exitUsage},
		"bad category":        {[]string{"query", "--category", "NOPE"}, exitUsage},
		"bad severity":        {[]string{"query", "--severity", "LOUD"}, exitUsage},
		"bad format":          {[]string{"query", "--format", "xml"}, exitUsage},
		"bad since":           {[]string{"query", "--since", "soon"}, exitUsage},
		"timeline bad range":  {[]string{"timeline", "--from", "2026-10-20 10:00:00", "--to", "2026-10-20 09:00:00"}, exitUsage},
		"timeline bad time":   {[]string{"timeline", "--from", "yesterday"}, exitUsage},
		"collect zero conc":   {[]string{"collect", "--concurrency", "0"}, exitUsage},
		"monitor tiny interv": {[]string{"monitor", "--interval", "1s"}, exitUsage},
		"collect stray arg":   {[]string{"collect", "extra"}, exitUsage},
		"collect no inv":      {[]string{"collect", "--inventory", "/nonexistent/inv.csv", "--data-dir", t.TempDir()}, exitError},
		"incidents unknown":   {[]string{"incidents", "--data-dir", t.TempDir(), "--id", "zzzz"}, exitError},
	} {
		var o, er bytes.Buffer
		if got := run(tc.args, &o, &er); got != tc.want {
			t.Errorf("%s: exit %d, want %d\nstdout: %s\nstderr: %s", name, got, tc.want, o.String(), er.String())
		}
		if name == "collect no inv" && !strings.Contains(er.String(), "Tip: Run 'netlog init'") {
			t.Errorf("collect no inv should include tip on stderr: %s", er.String())
		}
	}
}

// A persistent failure must be logged once, and its recovery once, rather than
// every cycle (monitor mode runs a cycle every couple of minutes).
func TestFailureLoggingIsDeduplicated(t *testing.T) {
	_, host, port := startFakeIOS(t)
	e := newEnv(t, fmt.Sprintf("SW-LAB,%s,%d,cisco_ios,default,\nDEAD,127.0.0.1,1,cisco_ios,default,\n", host, port))

	var stderr bytes.Buffer
	log := &stderrLogger{w: &stderr}
	o := collectOpts{
		inventory: e.args[1], envFile: e.args[3], dataDir: e.args[5], concurrency: 4,
		connectTimeout: 2 * time.Second, commandTimeout: 2 * time.Second, knownHosts: e.args[7], knownHostsPolicy: "accept-new",
		legacyAlgorithms: true, jumpEnabled: false,
		interval: 4 * time.Second, // narrows the start stagger so three cycles stay quick
	}
	a, err := newApp(o, log)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()

	for i := 0; i < 3; i++ {
		a.cycle(t.Context())
	}
	if n := strings.Count(stderr.String(), "DEAD: poll failed"); n != 1 {
		t.Errorf("a persistent failure must be logged once, logged %d times:\n%s", n, stderr.String())
	}
	if n := strings.Count(stderr.String(), "cycle complete"); n != 3 {
		t.Errorf("each cycle still gets its summary line, got %d", n)
	}
}

func TestStderrLoggerSanitises(t *testing.T) {
	var b bytes.Buffer
	l := &stderrLogger{w: &b}
	l.Info("%s", "forged\nERROR fake line \x1b[2J")
	if strings.Count(b.String(), "\n") != 1 || strings.Contains(b.String(), "\x1b") {
		t.Errorf("log injection not neutralised: %q", b.String())
	}
}

func TestSecondCollectorOnSameDataDirIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no data-directory lock on Windows")
	}
	_, host, port := startFakeIOS(t)
	e := newEnv(t, fmt.Sprintf("SW-LAB,%s,%d,cisco_ios,default,\n", host, port))
	o := collectOpts{
		inventory: e.args[1], envFile: e.args[3], dataDir: e.args[5], concurrency: 1,
		connectTimeout: time.Second, commandTimeout: time.Second, knownHosts: e.args[7], knownHostsPolicy: "accept-new",
	}
	var sink bytes.Buffer
	first, err := newApp(o, &stderrLogger{w: &sink})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newApp(o, &stderrLogger{w: &sink}); !errors.Is(err, errAlreadyRunning) {
		t.Fatalf("a second collector on the same data dir must be refused, got %v", err)
	}
	first.close()
	again, err := newApp(o, &stderrLogger{w: &sink})
	if err != nil {
		t.Fatalf("the lock must be released on close: %v", err)
	}
	again.close()
}

func TestWarnEveryRateLimits(t *testing.T) {
	var b bytes.Buffer
	a := &app{log: &stderrLogger{w: &b}, warnedAt: make(map[string]time.Time)}
	for i := 0; i < 5; i++ {
		a.warnEvery("k", time.Hour, "repeat")
		a.warnEvery("once", 0, "only-once")
	}
	a.warnEvery("other", time.Hour, "different key")
	if got := strings.Count(b.String(), "repeat"); got != 1 {
		t.Errorf("rate-limited warning logged %d times", got)
	}
	if got := strings.Count(b.String(), "only-once"); got != 1 {
		t.Errorf("once-only warning logged %d times", got)
	}
	if !strings.Contains(b.String(), "different key") {
		t.Error("distinct keys are independent")
	}
	// After the interval elapses the warning is allowed again.
	a.warnedAt["k"] = time.Now().Add(-2 * time.Hour)
	a.warnEvery("k", time.Hour, "repeat")
	if got := strings.Count(b.String(), "repeat"); got != 2 {
		t.Errorf("warning must re-arm after the interval, logged %d times", got)
	}
}

func TestCollectDryRun(t *testing.T) {
	_, host, port := startFakeIOS(t)
	e := newEnv(t, fmt.Sprintf("SW-DRY,%s,%d,cisco_ios,default,\n", host, port))
	dataDir := filepath.Join(e.dir, "data")

	// Run with --dry-run: should exit 0 and print the audit table to stdout.
	stdout, stderr, code := e.run(t, append([]string{"collect", "--dry-run"}, e.args...)...)
	if code != 0 {
		t.Fatalf("dry-run exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}

	// The connectivity table must appear on stdout with the right columns.
	for _, want := range []string{"DEVICE", "ADDRESS", "VENDOR", "STATUS", "DURATION", "SKEW", "SW-DRY", "OK"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q\nstdout: %s", want, stdout)
		}
	}

	// The summary line must appear in the log output (stderr).
	if !strings.Contains(stderr, "dry-run complete") {
		t.Errorf("stderr missing 'dry-run complete':\n%s", stderr)
	}

	// No log files, state file, or lock must be created under data/.
	if _, err := os.Stat(dataDir); err == nil {
		// data/ may not exist at all; if it does, it must be empty.
		entries, _ := os.ReadDir(dataDir)
		if len(entries) != 0 {
			names := make([]string, len(entries))
			for i, en := range entries {
				names[i] = en.Name()
			}
			t.Errorf("dry-run must not create files in data/; found: %v", names)
		}
	}
}

func TestCollectDryRunAllFail(t *testing.T) {
	// An unreachable device: dry-run must exit 1 when every device fails.
	e := newEnv(t, "DEAD,127.0.0.1,1,cisco_ios,default,\n")
	_, stderr, code := e.run(t, append([]string{"collect", "--dry-run"}, e.args...)...)
	if code != exitError {
		t.Errorf("all-fail dry-run must exit 1, got %d\nstderr: %s", code, stderr)
	}
}

func TestCmdInit(t *testing.T) {
	tmp := t.TempDir()
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origWd) }()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"init"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("run(init) = %d, want %d (stderr: %s)", code, exitOK, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Created .env") || !strings.Contains(stdout.String(), "Created inventory.csv") {
		t.Errorf("stdout missing creation notices: %s", stdout.String())
	}

	info, err := os.Stat(".env")
	if err != nil {
		t.Fatalf(".env not created: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf(".env perm = %o, want 0600", info.Mode().Perm())
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-init"}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("run(-init) = %d, want %d", code, exitOK)
	}
	if !strings.Contains(stdout.String(), ".env already exists, skipping") {
		t.Errorf("second run should skip .env, got: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "inventory.csv already exists, skipping") {
		t.Errorf("second run should skip inventory.csv, got: %s", stdout.String())
	}
}

// reportSection returns the text of one "=== <title> ... ===" section of the
// table output, up to the next heading.
func reportSection(t *testing.T, out, title string) string {
	t.Helper()
	i := strings.Index(out, "=== "+title)
	if i < 0 {
		t.Fatalf("section %q missing:\n%s", title, out)
	}
	rest := out[i+4:]
	if j := strings.Index(rest, "\n=== "); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// seedReportHistory adds days of history the fake device cannot produce (its
// buffer only holds the last few minutes): an earlier part of the current
// 7-day window, a previous-week window, and one entry too old for either.
// Timestamps are at noon UTC so no test run can straddle a day boundary.
func seedReportHistory(t *testing.T, dataDir string) {
	t.Helper()
	midnight := time.Now().UTC().Truncate(24 * time.Hour)
	noon := func(daysAgo int, minute int) time.Time {
		return midnight.AddDate(0, 0, -daysAgo).Add(12*time.Hour + time.Duration(minute)*time.Minute)
	}
	var entries []collector.LogEntry
	add := func(host, category, event, user, srcIP string, ts time.Time) {
		entries = append(entries, collector.LogEntry{
			ID: collector.EntryID(host, fmt.Sprint(event, user, srcIP, ts.UnixNano())), Timestamp: ts, DeviceTS: ts,
			Hostname: host, Category: category, Severity: "WARNING", Event: event, User: user, SourceIP: srcIP,
			Summary: event, Raw: event,
		})
	}
	// current window
	for m := 0; m < 3; m++ {
		add("SW-CORE", "FAULT", "LINK_DOWN", "", "", noon(3, m))
	}
	add("SW-CORE", "CONFIG", "CONFIG_CHANGE", "bachngo", "", noon(3, 10))
	add("SW-CORE", "CONFIG", "CONFIG_CHANGE", "bachngo", "", noon(3, 11))
	add("SW-CORE", "SECURITY", "AFTER_HOURS_CHANGE", "night", "", noon(2, 0))
	add("SW-A", "AUTH", "LOGIN_FAILURE", "", "203.0.113.9", noon(3, 20))
	add("SW-B", "AUTH", "LOGIN_FAILURE", "", "203.0.113.9", noon(3, 21))
	add("SW-B", "AUTH", "LOGIN_FAILURE", "", "203.0.113.9", noon(3, 22))
	add("SW-A", "AUTH", "LOGIN_FAILURE", "", "198.51.100.7", noon(3, 23))
	// previous week
	add("SW-CORE", "FAULT", "LINK_DOWN", "", "", noon(9, 0))
	add("SW-CORE", "CONFIG", "CONFIG_CHANGE", "bachngo", "", noon(9, 1))
	add("SW-CORE", "CONFIG", "CONFIG_CHANGE", "bachngo", "", noon(9, 2))
	add("SW-A", "AUTH", "LOGIN_FAILURE", "", "203.0.113.9", noon(9, 3))
	// older than both windows: must appear nowhere
	add("SW-OLD", "FAULT", "LINK_DOWN", "", "", noon(20, 0))

	w, err := store.NewJSONLWriter(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(entries); err != nil {
		t.Fatal(err)
	}

	// Incidents: two where triage could not connect (SW-GONE every time), one
	// where a command failed on a reachable device.
	now := time.Now()
	for _, r := range []collector.IncidentReport{
		{ID: "seed-gone-1", Timestamp: now.Add(-24 * time.Hour), Hostname: "SW-GONE", Playbook: "link_down",
			Diagnostics: []collector.DiagCmd{{Command: "(connect)", Error: "dial tcp: i/o timeout"}}},
		{ID: "seed-gone-2", Timestamp: now.Add(-48 * time.Hour), Hostname: "SW-GONE", Playbook: "link_down",
			Diagnostics: []collector.DiagCmd{{Command: "(connect)", Error: "dial tcp: i/o timeout"}}},
		{ID: "seed-partial", Timestamp: now.Add(-3 * time.Hour), Hostname: "SW-LAB", Playbook: "link_down",
			Diagnostics: []collector.DiagCmd{{Command: "show version", Output: "ok"}, {Command: "show ip route", Error: "timeout"}}},
	} {
		if _, err := store.WriteIncident(store.IncidentsDir(dataDir), r); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReportEndToEnd(t *testing.T) {
	_, host, port := startFakeIOS(t)
	e := newEnv(t, fmt.Sprintf("SW-LAB,%s,%d,cisco_ios,default,\n", host, port))
	dataDir := filepath.Join(e.dir, "data")

	// ---- nothing collected yet: exit 0 and "no data" lines, never an error ----
	out, stderr, code := e.run(t, "report", "--data-dir", dataDir, "--no-color")
	if code != 0 || stderr != "" || strings.Count(out, "No matching events.") != 6 || !strings.Contains(out, "No incidents.") || !strings.Contains(out, "No outages.") {
		t.Fatalf("empty data dir: code=%d stderr=%q\n%s", code, stderr, out)
	}
	out, _, code = e.run(t, "report", "--data-dir", dataDir, "--format", "json")
	var empty map[string]json.RawMessage
	if code != 0 || json.Unmarshal([]byte(out), &empty) != nil || len(empty) != 9 || string(empty["noisy_devices"]) != "[]" {
		t.Fatalf("empty data dir, json: code=%d\n%s", code, out)
	}

	// ---- real collection (SW-LAB: 2 faults, 2 config changes, 2 incidents), plus older days ----
	if stderr, code := e.collect(t); code != 0 {
		t.Fatalf("collect: exit %d\n%s", code, stderr)
	}
	seedReportHistory(t, dataDir)

	// ---- table ----
	out, stderr, code = e.run(t, "report", "--data-dir", dataDir, "--no-color")
	if code != 0 || stderr != "" {
		t.Fatalf("report: code=%d stderr=%q\n%s", code, stderr, out)
	}
	for _, bad := range []string{"\x1b", "\x07", "\r", "SW-OLD"} {
		if strings.Contains(out, bad) {
			t.Errorf("output contains %q:\n%q", bad, out)
		}
	}
	last := -1
	for _, h := range []string{"Noisy Devices (top 10, last 7d)", "Change Accountability", "Security Watchlist (top 10, last 7d)",
		"Event Volume by Category/Day", "Week-over-Week (last 7d vs previous 7d)", "Triage Reach", "Outages", "Device Health", "Classification Coverage"} {
		i := strings.Index(out, "=== "+h)
		if i < 0 || i < last {
			t.Fatalf("heading %q missing or out of order:\n%s", h, out)
		}
		last = i
	}

	match := func(section, pattern string) {
		t.Helper()
		if !regexp.MustCompile(pattern).MatchString(section) {
			t.Errorf("want /%s/ in:\n%s", pattern, section)
		}
	}
	noisy := reportSection(t, out, "Noisy Devices")
	match(noisy, `(?m)^SW-CORE\s+3$`)
	match(noisy, `(?m)^SW-LAB\s+2$`)
	if strings.Index(noisy, "SW-CORE") > strings.Index(noisy, "SW-LAB") {
		t.Errorf("most faults first:\n%s", noisy)
	}

	changes := reportSection(t, out, "Change Accountability")
	match(changes, `(?m)^bachngo\s+2\s+0$`)
	match(changes, `(?m)^night\s+1\s+1$`)
	match(changes, `(?m)^tanvt\s+1\s+0$`)
	match(changes, `After-hours changes: 1`)
	match(changes, `(?m)^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\s+SW-CORE\s+night$`)
	if !strings.Contains(changes, "?[2Jevil") {
		t.Errorf("the hostile user name should appear neutralised:\n%s", changes)
	}

	watch := reportSection(t, out, "Security Watchlist")
	match(watch, `(?m)^203\.0\.113\.9\s+2\s+3\s+0\s+SW-A, SW-B$`)
	match(watch, `(?m)^198\.51\.100\.7\s+1\s+1\s+0\s+SW-A$`)
	if strings.Contains(watch, "6.6.6.6") || strings.Index(watch, "203.0.113.9") > strings.Index(watch, "198.51.100.7") {
		t.Errorf("a source on more devices ranks first, and config-change IPs are not logins:\n%s", watch)
	}

	day3 := time.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, -3).Format("2006-01-02")
	match(reportSection(t, out, "Event Volume"), `(?m)^`+day3+`\s+2\s+4\s+3\s+0\s+0$`)

	delta := reportSection(t, out, "Week-over-Week")
	match(delta, `(?m)^CONFIG\s+2\s+4\s+\+2\s+\+100\.0%$`)
	match(delta, `(?m)^AUTH\s+1\s+4\s+\+3\s+\+300\.0%$`)
	match(delta, `(?m)^FAULT\s+1\s+5\s+\+4\s+\+400\.0%$`)
	match(delta, `(?m)^SECURITY\s+0\s+1\s+\+1\s+n/a$`)
	match(delta, `(?m)^SYSTEM\s+0\s+0\s+0\s+n/a$`)
	match(delta, `(?m)^TOTAL\s+4\s+14\s+\+10\s+\+250\.0%$`)

	closure := reportSection(t, out, "Triage Reach")
	match(closure, `Incidents:\s+5`)
	match(closure, `All diagnostics succeeded:\s+2 \(40\.0%\)`)
	match(closure, `Unreachable during triage:\s+2 \(40\.0%\)`)
	match(closure, `Some commands failed:\s+1 \(20\.0%\)`)
	match(closure, `(?m)^SW-GONE\s+2\s+2\s+yes$`)

	// The collection that just ran left a health record: SW-LAB is fine, so
	// the section only says so.
	match(reportSection(t, out, "Device Health"), `All 1 devices healthy\.`)
	// Every collected line was classified except the banner-free few the fake
	// device prints; coverage is reported per vendor.
	match(reportSection(t, out, "Classification Coverage"), `(?m)^cisco_ios\s+\d+\s+\d+\s+\d+\.\d%$`)
	match(reportSection(t, out, "Outages"), `No outages\.|Outages: \d+`)

	// ---- json ----
	out, stderr, code = e.run(t, "report", "--data-dir", dataDir, "--format", "json")
	if code != 0 || stderr != "" || !json.Valid([]byte(out)) {
		t.Fatalf("report --format json: code=%d stderr=%q\n%s", code, stderr, out)
	}
	if strings.Contains(out, "\x1b") {
		t.Error("raw ESC in JSON output")
	}
	var rep report.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if got := rep.NoisyDevices; len(got) != 2 || got[0] != (report.DeviceFaultCount{Hostname: "SW-CORE", Count: 3}) || got[1] != (report.DeviceFaultCount{Hostname: "SW-LAB", Count: 2}) {
		t.Errorf("noisy_devices = %+v", got)
	}
	if ca := rep.ChangeAccountability; ca.Total != 5 || ca.AfterHoursCount != 1 || ca.AfterHours[0].User != "night" || ca.AfterHours[0].Hostname != "SW-CORE" || ca.ByUser[0].User != "bachngo" {
		t.Errorf("change_accountability = %+v", ca)
	}
	if w := rep.SecurityWatchlist; len(w) != 2 || w[0].SourceIP != "203.0.113.9" || w[0].DistinctHosts != 2 || w[0].Events != 3 {
		t.Errorf("security_watchlist = %+v", w)
	}
	var faults int
	for _, row := range rep.VolumeByCategory {
		faults += row["FAULT"]
	}
	if faults != 5 {
		t.Errorf("volume_by_category FAULT total = %d, want 5 (2 collected + 3 seeded; none from SW-OLD)", faults)
	}
	if w := rep.WeekOverWeek; w == nil || w.Categories[2].Category != "FAULT" || w.Categories[2].ChangePct == nil || *w.Categories[2].ChangePct != 400 ||
		w.Categories[3].ChangePct != nil || w.Total.Current != 14 || w.Total.Previous != 4 {
		t.Errorf("week_over_week = %+v", w)
	}
	if ic := rep.IncidentClosure; ic.Total != 5 || ic.Succeeded != 2 || ic.Unreachable != 2 || ic.PartialFailure != 1 ||
		len(ic.UnreachableHosts) != 1 || ic.UnreachableHosts[0] != (report.UnreachableHost{Hostname: "SW-GONE", Unreachable: 2, Incidents: 2, Always: true}) {
		t.Errorf("incident_closure = %+v", ic)
	}

	// ---- flags: --top, --since, --compare ----
	out, _, code = e.run(t, "report", "--data-dir", dataDir, "--format", "json", "--top", "1")
	var top1 report.Report
	if code != 0 || json.Unmarshal([]byte(out), &top1) != nil || len(top1.NoisyDevices) != 1 || len(top1.SecurityWatchlist) != 1 ||
		len(top1.ChangeAccountability.ByUser) != 4 {
		t.Errorf("--top 1 caps the two rankings only: code=%d\n%s", code, out)
	}

	// 24h: only the collected events; no delta unless asked for.
	out, _, code = e.run(t, "report", "--data-dir", dataDir, "--format", "json", "--since", "24h")
	var day report.Report
	if code != 0 || json.Unmarshal([]byte(out), &day) != nil || day.WeekOverWeek != nil ||
		len(day.NoisyDevices) != 1 || day.NoisyDevices[0].Hostname != "SW-LAB" || len(day.SecurityWatchlist) != 0 {
		t.Errorf("--since 24h: code=%d\n%s", code, out)
	}
	if !strings.Contains(out, `"week_over_week": null`) {
		t.Errorf("week_over_week must be an explicit null when not computed:\n%s", out)
	}
	out, _, code = e.run(t, "report", "--data-dir", dataDir, "--since", "24h", "--compare", "--no-color")
	if code != 0 || !strings.Contains(out, "=== Window-over-Window (last 24h vs the equal window before it) ===") {
		t.Errorf("--since 24h --compare:\n%s", out)
	}
	out, _, code = e.run(t, "report", "--data-dir", dataDir, "--compare=false", "--no-color")
	if code != 0 || strings.Contains(out, "Week-over-Week") || !strings.Contains(out, "=== Triage Reach") {
		t.Errorf("--compare=false must drop the delta section:\n%s", out)
	}

	// ---- usage errors exit 2 without touching stdout ----
	for _, args := range [][]string{{"--format", "xml"}, {"--top", "0"}, {"--since", "bogus"}, {"--nope"}} {
		out, stderr, code := e.run(t, append([]string{"report", "--data-dir", dataDir}, args...)...)
		if code != exitUsage || out != "" || stderr == "" {
			t.Errorf("report %v: code=%d stdout=%q stderr=%q, want exit %d, an error on stderr and nothing on stdout", args, code, out, stderr, exitUsage)
		}
	}

	// report only reads: running it changed nothing under the data directory.
	before := len(e.logEntries(t))
	e.run(t, "report", "--data-dir", dataDir)
	if after := len(e.logEntries(t)); after != before {
		t.Errorf("report modified the logs: %d -> %d entries", before, after)
	}
}

// TestStatusEndToEnd drives collection health end to end: a healthy device, a
// dead one, an unsupported platform and (before the first poll) devices that
// are only in the inventory, through collection cycles, "netlog status" and
// "netlog report".
func TestStatusEndToEnd(t *testing.T) {
	_, host, port := startFakeIOS(t)
	e := newEnv(t, fmt.Sprintf("SW-LAB,%s,%d,cisco_ios,default,\n"+
		"DEAD,127.0.0.1,1,cisco_ios,default,\n"+ // connection refused, instantly
		"PF,%s,%d,sophos,default,\n", host, port, host, port))
	dataDir := filepath.Join(e.dir, "data")
	inv := filepath.Join(e.dir, "inventory.csv")
	status := func(extra ...string) (string, string, int) {
		return e.run(t, append([]string{"status", "--inventory", inv, "--data-dir", dataDir, "--no-color"}, extra...)...)
	}
	// startApp is a collector over the test inventory. A narrow interval
	// shrinks the start stagger so a cycle takes milliseconds.
	startApp := func() (*app, *bytes.Buffer) {
		var stderr bytes.Buffer
		a, err := newApp(collectOpts{
			inventory: e.args[1], envFile: e.args[3], dataDir: e.args[5], concurrency: 4,
			connectTimeout: 2 * time.Second, commandTimeout: 2 * time.Second, knownHosts: e.args[7], knownHostsPolicy: "accept-new",
			legacyAlgorithms: true, jumpEnabled: false, interval: time.Second,
		}, &stderrLogger{w: &stderr})
		if err != nil {
			t.Fatal(err)
		}
		return a, &stderr
	}
	row := func(out, dev string) string {
		t.Helper()
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, dev+" ") {
				return l
			}
		}
		t.Fatalf("no row for %s in:\n%s", dev, out)
		return ""
	}

	// Nothing polled yet: every inventory device is NEVER POLLED, and --fail says so.
	out, stderr, code := status()
	if code != 0 || stderr != "" || strings.Count(out, "NEVER POLLED") != 3 {
		t.Fatalf("before any poll: code=%d stderr=%q\n%s", code, stderr, out)
	}
	if _, _, code := status("--fail"); code != exitError {
		t.Errorf("--fail with unhealthy devices: exit %d, want %d", code, exitError)
	}

	// One cycle: SW-LAB is polled, DEAD refuses, PF has no fetch command.
	a, _ := startApp()
	a.cycle(t.Context())
	out, _, code = status()
	if code != 0 {
		t.Fatalf("status: exit %d", code)
	}
	if r := row(out, "SW-LAB"); !strings.Contains(r, "OK") {
		t.Errorf("SW-LAB should be OK: %q", r)
	}
	if r := row(out, "DEAD"); !regexp.MustCompile(`FAILING\s+-\s+1\s`).MatchString(r) {
		t.Errorf("DEAD should be FAILING with 1 failed poll and no successful one: %q", r)
	}
	if r := row(out, "PF"); !strings.Contains(r, "UNSUPPORTED") || !strings.Contains(r, "no log fetch command") {
		t.Errorf("PF should be UNSUPPORTED, not an outage: %q", r)
	}
	if strings.Index(out, "DEAD") > strings.Index(out, "SW-LAB") {
		t.Errorf("the failing device must be listed first:\n%s", out)
	}
	if _, _, code := status("--fail"); code != exitError {
		t.Errorf("--fail: exit %d, want %d", code, exitError)
	}

	// A second cycle extends the failure run; the healthy device stays healthy.
	a.cycle(t.Context())
	a.close()
	out, _, _ = status()
	if r := row(out, "DEAD"); !regexp.MustCompile(`FAILING\s+-\s+2\s`).MatchString(r) {
		t.Errorf("two failed polls in a row: %q", r)
	}
	if r := row(out, "PF"); regexp.MustCompile(`UNSUPPORTED\s+-\s+\d`).MatchString(r) {
		t.Errorf("an unsupported platform shows no failure count: %q", r)
	}
	if r := row(out, "SW-LAB"); !strings.Contains(r, "OK") {
		t.Errorf("SW-LAB should still be OK: %q", r)
	}

	// JSON is a plain array with explicit nulls for what never happened.
	out, _, code = status("--format", "json")
	var rows []report.DeviceStatus
	if code != 0 || json.Unmarshal([]byte(out), &rows) != nil || len(rows) != 3 {
		t.Fatalf("status --format json: code=%d\n%s", code, out)
	}
	byHost := map[string]report.DeviceStatus{}
	for _, r := range rows {
		byHost[r.Hostname] = r
	}
	if d := byHost["DEAD"]; d.Status != "FAILING" || d.ConsecutiveFailures != 2 || d.LastSuccess != nil || d.FailingSince == nil || d.LastError == "" {
		t.Errorf("DEAD = %+v", d)
	}
	if s := byHost["SW-LAB"]; s.Status != "OK" || s.LastSuccess == nil || s.LastNewLogs == nil {
		t.Errorf("SW-LAB = %+v", s)
	}

	// The thresholds are knobs: with 1ns nothing has been polled "recently"
	// and no log line is "new" any more.
	out, _, _ = status("--stale-after", "1ns")
	if r := row(out, "SW-LAB"); !strings.Contains(r, "STALE") || !strings.Contains(r, "is collect running?") {
		t.Errorf("--stale-after 1ns: %q", r)
	}
	out, _, _ = status("--silent-after", "1ns")
	if r := row(out, "SW-LAB"); !strings.Contains(r, "SILENT") || !strings.Contains(r, "no new log lines since") {
		t.Errorf("--silent-after 1ns: %q", r)
	}

	// The report carries the same picture, and names only what needs attention.
	out, _, code = e.run(t, "report", "--data-dir", dataDir, "--no-color")
	if code != 0 {
		t.Fatalf("report: exit %d", code)
	}
	health := reportSection(t, out, "Device Health")
	if !strings.Contains(health, "2 of 3 devices need attention") || !strings.Contains(health, "DEAD") || !strings.Contains(health, "PF") {
		t.Errorf("report device health:\n%s", health)
	}
	if regexp.MustCompile(`(?m)^SW-LAB\s`).MatchString(health) {
		t.Errorf("a healthy device is not listed:\n%s", health)
	}

	// The health file is diagnostics: a corrupt one is reported but changes
	// neither the exit code nor what the next collection does, and is replaced.
	if err := os.WriteFile(store.HealthPath(dataDir), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, stderr, code = status()
	if code != 0 || !strings.Contains(stderr, "corrupt") || strings.Count(out, "NEVER POLLED") != 3 {
		t.Errorf("corrupt health file: code=%d stderr=%q\n%s", code, stderr, out)
	}
	a, log := startApp()
	a.cycle(t.Context())
	a.close()
	if !strings.Contains(log.String(), "corrupt") || !strings.Contains(log.String(), "cycle complete") {
		t.Errorf("a corrupt health file must be reported and must not stop the cycle:\n%s", log.String())
	}
	if out, stderr, _ = status(); stderr != "" || !strings.Contains(row(out, "SW-LAB"), "OK") {
		t.Errorf("the next collection should have replaced the bad file: %q\n%s", stderr, out)
	}

	// Usage errors.
	for _, args := range [][]string{{"--format", "xml"}, {"--stale-after", "0s"}, {"--nope"}, {"extra"}} {
		if out, stderr, code := status(args...); code != exitUsage || out != "" || stderr == "" {
			t.Errorf("status %v: code=%d stdout=%q stderr=%q", args, code, out, stderr)
		}
	}
}

// TestOutagesEndToEnd follows raw device log lines all the way to the report:
// parsed, classified (recovery events and the interface/neighbor they are
// about), stored as JSONL, streamed back and paired into outages.
func TestOutagesEndToEnd(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	stamp := func(ago time.Duration) string { return now.Add(-ago).Format("Jan _2 15:04:05.000") + ":" }

	// Cisco logs the link and the line protocol for one physical event, a
	// moment apart: each pair must count as one outage, not two.
	iosLines := strings.Join([]string{
		stamp(3*time.Hour) + " %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down",
		stamp(3*time.Hour-time.Second) + " %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to down",
		stamp(3*time.Hour-20*time.Minute) + " %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to up",
		stamp(3*time.Hour-20*time.Minute-time.Second) + " %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/1, changed state to up",
		stamp(50*time.Minute) + " %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down BGP Notification sent",
		stamp(20*time.Minute) + " %BGP-5-ADJCHANGE: neighbor 10.0.0.1 Up",
	}, "\n")
	// A neighbor that dropped and never came back. FULL appears in both the
	// down and the (absent) up line: only the direction tells them apart.
	ospfLines := stamp(90*time.Minute) + " %OSPF-5-ADJCHG: Process 1, Nbr 10.255.255.4 on GigabitEthernet0/2 from FULL to DOWN, Neighbor Down: Dead timer expired\n" +
		stamp(80*time.Minute) + " %OSPF-5-ADJCHG: Process 1, Nbr 10.255.255.9 on GigabitEthernet0/3 from FULL to LOADING, Bad LS Req"

	cls := pipeline.NewClassifier(time.UTC)
	var entries []collector.LogEntry
	for host, raw := range map[string]string{"R1": iosLines, "R2": ospfLines} {
		dev := inventory.Device{Hostname: host, Address: "10.0.0.1", Vendor: "cisco_ios"}
		got := parser.Parse("cisco_ios", raw, dev, parser.Options{Ref: now, Location: time.UTC})
		for i := range got {
			got[i].Timestamp = got[i].DeviceTS
		}
		cls.ClassifyAll(got)
		entries = append(entries, got...)
	}
	if len(entries) != 8 {
		t.Fatalf("parsed %d entries, want 8", len(entries))
	}

	dataDir := filepath.Join(t.TempDir(), "data")
	w, err := store.NewJSONLWriter(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(entries); err != nil {
		t.Fatal(err)
	}

	// The interface / neighbor is part of what is stored.
	var stored strings.Builder
	files, _ := filepath.Glob(filepath.Join(store.LogsDir(dataDir), "*.jsonl"))
	for _, f := range files {
		b, _ := os.ReadFile(f)
		stored.Write(b)
	}
	for _, want := range []string{`"object":"GigabitEthernet0/1"`, `"object":"10.0.0.1"`, `"object":"10.255.255.4"`, `"event":"LINK_UP"`, `"event":"BGP_PEER_UP"`} {
		if !strings.Contains(stored.String(), want) {
			t.Errorf("stored logs lack %s", want)
		}
	}

	out, stderr, code := (env{}).run(t, "report", "--data-dir", dataDir, "--since", "24h", "--format", "json")
	if code != 0 || stderr != "" {
		t.Fatalf("report: code=%d stderr=%q\n%s", code, stderr, out)
	}
	var rep report.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	o := rep.Outages
	if o.Total != 3 || o.Resolved != 2 || o.Open != 1 || o.Untracked != 0 || o.MeanSecondsToRecover != 1500 {
		t.Fatalf("outages = %+v\n(the FULL→LOADING line is neither an outage nor a recovery; the doubled Cisco events are one each)", o)
	}
	// Longest first: the open OSPF neighbor (a lower bound), the BGP peer, the link.
	ospf, bgp, link := o.Longest[0], o.Longest[1], o.Longest[2]
	if !ospf.Open || ospf.Kind != "ospf" || ospf.Object != "10.255.255.4" || ospf.Hostname != "R2" || ospf.Up != nil || ospf.DurationSeconds < 5400 || ospf.DurationSeconds > 5400+120 {
		t.Errorf("ospf = %+v", ospf)
	}
	if bgp.Open || bgp.Kind != "bgp" || bgp.Object != "10.0.0.1" || bgp.DurationSeconds != 1800 {
		t.Errorf("bgp = %+v", bgp)
	}
	if link.Open || link.Kind != "link" || link.Object != "GigabitEthernet0/1" || link.DurationSeconds != 1200 {
		t.Errorf("link = %+v", link)
	}
	// Recoveries are not faults: R1 has two link-down lines and one BGP down, R2 one OSPF down.
	if got := rep.NoisyDevices; len(got) != 2 || got[0] != (report.DeviceFaultCount{Hostname: "R1", Count: 3}) || got[1] != (report.DeviceFaultCount{Hostname: "R2", Count: 1}) {
		t.Errorf("noisy_devices = %+v (the up events must not count as faults)", got)
	}

	// And the table says it in words.
	tbl, _, _ := (env{}).run(t, "report", "--data-dir", dataDir, "--since", "24h", "--no-color")
	section := reportSection(t, tbl, "Outages")
	for _, want := range []string{"Outages: 3 (2 resolved, 1 still open)", "Mean time to recover: 25m", "(open)"} {
		if !strings.Contains(section, want) {
			t.Errorf("outages section lacks %q:\n%s", want, section)
		}
	}
}
