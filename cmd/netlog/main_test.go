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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"netlog/internal/collector"
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
	e = newEnv(t, fmt.Sprintf("SW-LAB,%s,%d,cisco_ios,default,\nPF,%s,%d,pfsense,default,\n", host, port, host, port))
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
