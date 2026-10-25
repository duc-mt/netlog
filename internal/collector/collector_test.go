// ==============================================================================
// Package collector: tests for staggering, vendor plans, clock skew and the worker pool.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-20
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package collector

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"netlog/internal/credentials"
	"netlog/internal/inventory"
	"netlog/internal/sshclient"
	"netlog/internal/vendor"
)

func TestStagger(t *testing.T) {
	// 10 devices, 2m interval: stagger = min(60s, 30s) = 30s, step 3s
	o := StaggerOffsets(10, 2*time.Minute)
	if len(o) != 10 || o[0] != 0 || o[1] != 3*time.Second || o[9] != 27*time.Second {
		t.Fatalf("bad offsets: %v", o)
	}
	// 100 devices: stagger capped at interval/2 = 60s, step 600ms
	o = StaggerOffsets(100, 2*time.Minute)
	if o[1] != 600*time.Millisecond || o[99] != 99*600*time.Millisecond {
		t.Fatalf("bad offsets: %v", o[:3])
	}
	// tiny interval
	o = StaggerOffsets(4, 4*time.Second) // min(2s, 12s)=2s, step 500ms
	if o[3] != 1500*time.Millisecond {
		t.Fatalf("bad offsets: %v", o)
	}
	if StaggerOffsets(0, time.Minute) != nil {
		t.Fatal("want nil")
	}
}

func TestPlansAndID(t *testing.T) {
	for in, want := range map[string]string{"cisco": "cisco_ios", "huawei": "huawei_vrp", "junos": "juniper_junos", "weird": "generic", "fortinet": "fortigate", "ASA": "cisco_asa"} {
		k, _, err := resolvePlan(inventory.Device{Vendor: in})
		if err != nil || k != want {
			t.Fatalf("%s -> %s %v", in, k, err)
		}
	}
	// Sophos is recognised by the vendor registry but has no fetch plan.
	if _, _, err := resolvePlan(inventory.Device{Vendor: "sophos"}); !errors.Is(err, ErrUnsupportedVendor) {
		t.Fatalf("sophos should be unsupported, got %v", err)
	}
	// pfSense and Check Point read plain-text syslog files with tail.
	for in, want := range map[string]string{"pfsense": "pfsense", "checkpoint": "checkpoint_gaia", "gaia": "checkpoint_gaia"} {
		k, plan, err := resolvePlan(inventory.Device{Vendor: in})
		if err != nil || k != want || len(plan.Commands) != 1 || !strings.HasPrefix(plan.Commands[0], "tail ") || plan.Interactive {
			t.Fatalf("%s -> %s %+v %v", in, k, plan, err)
		}
		if clockCommandFor(k) != "date" {
			t.Fatalf("%s clock command %q, want date", k, clockCommandFor(k))
		}
	}
	if clockCommandFor("cisco_asa") != "show clock" || clockCommandFor("vyos") != "date" {
		t.Fatal("clock cmds")
	}
	a, b := EntryID("ab", "c"), EntryID("a", "bc")
	if a == b || len(a) != 12 || EntryID("ab", "c") != a {
		t.Fatalf("ids %s %s", a, b)
	}
	h, p := splitHostPort("bastion.example.com")
	if h != "bastion.example.com" || p != 22 {
		t.Fatal("split")
	}
	h, p = splitHostPort("10.0.0.1:2222")
	if h != "10.0.0.1" || p != 2222 {
		t.Fatal("split2")
	}
}

// fake SSH server: replies to exec requests with canned output.
func startServer(t *testing.T, served *atomic.Int32) (string, int) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if c.User() == "u" && string(pw) == "p" {
			return nil, nil
		}
		return nil, ssh.ErrNoAuth
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
							served.Add(1)
							switch {
							case cmd == "show clock":
								// device is 5s ahead of the server
								ch.Write([]byte(time.Now().Add(5*time.Second).UTC().Format(time.RFC3339Nano) + "\n"))
							case strings.HasPrefix(cmd, "show logging"):
								ch.Write([]byte("Oct 20 09:30:15: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down\n"))
							default:
								ch.Stderr().Write([]byte("bad command"))
								ch.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
								ch.Close()
								return
							}
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
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port
}

func TestRunEndToEnd(t *testing.T) {
	t.Setenv("NETLOG_USERNAME", "u")
	t.Setenv("NETLOG_PASSWORD", "p")
	store, err := credentials.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	var served atomic.Int32
	host, port := startServer(t, &served)

	devs := []inventory.Device{
		{Hostname: "sw1", Address: host, Port: port, Vendor: "cisco_ios", CredentialGroup: "default"},
		{Hostname: "sw2", Address: host, Port: port, Vendor: "cisco", CredentialGroup: "default"},
		{Hostname: "pf", Address: host, Port: port, Vendor: "sophos", CredentialGroup: "default"},
		{Hostname: "dead", Address: "127.0.0.1", Port: 1, Vendor: "cisco_ios", CredentialGroup: "default"},
	}
	parser := func(vendorKey, out string, ref time.Time) (time.Time, error) {
		return time.Parse(time.RFC3339Nano, strings.TrimSpace(out))
	}
	c := New(Config{
		Concurrency: 2, Interval: 4 * time.Second, // stagger = min(2s, 12s) = 2s
		SSH:         sshclient.Options{ConnectTimeout: 2 * time.Second, CommandTimeout: 2 * time.Second, HostKeyCallback: ssh.InsecureIgnoreHostKey()},
		CredStore:   store,
		ClockParser: parser,
	})
	start := time.Now()
	got := map[string]Result{}
	for r := range c.Run(context.Background(), devs) {
		got[r.Device.Hostname] = r
	}
	t.Logf("cycle took %v", time.Since(start))
	if len(got) != 4 {
		t.Fatalf("want 4 results, got %d", len(got))
	}
	for _, h := range []string{"sw1", "sw2"} {
		r := got[h]
		if r.Err != nil || !strings.Contains(r.Raw, "LINK-3-UPDOWN") || !r.SkewOK {
			t.Fatalf("%s: %+v", h, r)
		}
		if r.SkewMs < 4000 || r.SkewMs > 6000 {
			t.Fatalf("%s skew %d, want ~5000", h, r.SkewMs)
		}
		if r.FetchedAt.IsZero() || r.VendorKey != "cisco_ios" {
			t.Fatalf("%s: %+v", h, r)
		}
	}
	if got["pf"].Err == nil || !strings.Contains(got["pf"].Err.Error(), "no log fetch command") {
		t.Fatalf("pf: %+v", got["pf"].Err)
	}
	if got["dead"].Err == nil {
		t.Fatal("dead should fail")
	}
	t.Logf("dead err: %v", got["dead"].Err)
	// an unsupported vendor must not have opened any session: 2 devices * (log + clock) = 4 execs
	if served.Load() != 4 {
		t.Fatalf("served %d execs, want 4 (an unsupported vendor must not dial)", served.Load())
	}
}

func TestSkewFailureIsNonFatal(t *testing.T) {
	t.Setenv("NETLOG_USERNAME", "u")
	t.Setenv("NETLOG_PASSWORD", "p")
	store, _ := credentials.NewStore("")
	var served atomic.Int32
	host, port := startServer(t, &served)
	// vyos uses "date", which the fake server rejects -> skew fails, but the vyos log cmd is also rejected;
	// use cisco_ios with a parser that errors instead.
	c := New(Config{
		Concurrency: 1,
		SSH:         sshclient.Options{ConnectTimeout: 2 * time.Second, CommandTimeout: 2 * time.Second, HostKeyCallback: ssh.InsecureIgnoreHostKey()},
		CredStore:   store,
		ClockParser: func(string, string, time.Time) (time.Time, error) { return time.Time{}, context.DeadlineExceeded },
	})
	for r := range c.Run(context.Background(), []inventory.Device{{Hostname: "a", Address: host, Port: port, Vendor: "cisco_ios", CredentialGroup: "default"}}) {
		if r.Err != nil || r.SkewOK || r.SkewErr == nil || r.Raw == "" {
			t.Fatalf("%+v", r)
		}
	}
}

func TestCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := New(Config{Concurrency: 1})
	n := 0
	for range c.Run(ctx, []inventory.Device{{Hostname: "a"}, {Hostname: "b"}}) {
		n++
	}
	if n != 0 {
		t.Fatalf("cancelled run should emit nothing, got %d", n)
	}
}

// startPTYDevice is a FortiGate-like device: it grants a PTY and a shell,
// echoes commands, and takes displayDelay to produce the log page.
type ptyOpts struct {
	displayDelay time.Duration
	paged        bool // print "--More-- " mid-page and wait for a space
	noPrompt     bool // never print a prompt after the log page
}

func startPTYDevice(t *testing.T, o ptyOpts) (string, int) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if c.User() == "u" && string(pw) == "p" {
			return nil, nil
		}
		return nil, ssh.ErrNoAuth
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	logPage := "1: date=" + time.Now().Format("2006-01-02") + " time=" + time.Now().Format("15:04:05") +
		` tz="+0000" subtype="system" logdesc="Admin login failed" user="test" ui="ssh(10.1.1.9)" msg="login failed"` + "\r\n"

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
							switch r.Type {
							case "pty-req":
								r.Reply(true, nil)
							case "shell":
								r.Reply(true, nil)
								go func() {
									ch.Write([]byte("FGT-01 # "))
									var line []byte
									buf := make([]byte, 1)
									for {
										if _, err := ch.Read(buf); err != nil {
											return
										}
										if buf[0] == ' ' && len(line) == 0 {
											continue // pager keystroke handled inline below
										}
										if buf[0] != '\n' {
											line = append(line, buf[0])
											continue
										}
										cmd := strings.TrimSpace(string(line))
										line = line[:0]
										ch.Write([]byte(cmd + "\r\n"))
										if strings.HasPrefix(cmd, "execute log display") {
											time.Sleep(o.displayDelay)
											ch.Write([]byte("10 logs found.\r\n1 logs returned.\r\n\r\n"))
											if o.paged {
												ch.Write([]byte("--More-- "))
												b := make([]byte, 1)
												for {
													if _, err := ch.Read(b); err != nil || b[0] == ' ' {
														break
													}
												}
												ch.Write([]byte("\r        \r"))
											}
											ch.Write([]byte(logPage))
											if o.noPrompt {
												continue
											}
										}
										ch.Write([]byte("FGT-01 # "))
									}
								}()
							default:
								r.Reply(false, nil)
							}
						}
					}()
				}
			}()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// A FortiGate echoes the command at once and may take seconds to render the
// log page. The collector must wait for the prompt rather than conclude from
// a moment of silence that the page is empty (which would lose logs without
// any error).
func TestInteractivePlanWaitsForSlowDevice(t *testing.T) {
	if testing.Short() {
		t.Skip("takes ~6s")
	}
	t.Setenv("NETLOG_USERNAME", "u")
	t.Setenv("NETLOG_PASSWORD", "p")
	store, _ := credentials.NewStore("")
	host, port := startPTYDevice(t, ptyOpts{displayDelay: 2 * time.Second})

	c := New(Config{
		Concurrency: 1,
		SSH:         sshclient.Options{ConnectTimeout: 3 * time.Second, CommandTimeout: 5 * time.Second, HostKeyCallback: ssh.InsecureIgnoreHostKey()},
		CredStore:   store,
	})
	started := time.Now()
	var res Result
	for r := range c.Run(context.Background(), []inventory.Device{{Hostname: "FGT-01", Address: host, Port: port, Vendor: "fortigate", CredentialGroup: "default"}}) {
		res = r
	}
	if res.Err != nil {
		t.Fatalf("interactive poll failed after %v: %v", time.Since(started), res.Err)
	}
	if !strings.Contains(res.Raw, "Admin login failed") || res.VendorKey != "fortigate" {
		t.Fatalf("log page missing from output: %q", res.Raw)
	}
	t.Logf("interactive poll took %v", time.Since(started).Round(100*time.Millisecond))
}

// A bastion session that has died must be forgotten, not cached forever.
func TestDeadBastionIsEvicted(t *testing.T) {
	var served atomic.Int32
	host, port := startServer(t, &served)
	d := NewDialer(DialerConfig{})

	dial := func() *ssh.Client {
		c, err := ssh.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)), &ssh.ClientConfig{
			User: "u", Auth: []ssh.AuthMethod{ssh.Password("p")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	live := dial()
	d.jumps["bastion:22"] = live
	d.dropIfDead("bastion:22", live)
	if d.jumps["bastion:22"] != live {
		t.Fatal("a healthy bastion session must stay cached")
	}

	dead := dial()
	d.jumps["bastion:23"] = dead
	dead.Close()
	d.dropIfDead("bastion:23", dead)
	if _, still := d.jumps["bastion:23"]; still {
		t.Fatal("a dead bastion session must be evicted so the next dial reconnects")
	}
	live.Close()
}

func pollFortigate(t *testing.T, host string, port int) Result {
	t.Helper()
	t.Setenv("NETLOG_USERNAME", "u")
	t.Setenv("NETLOG_PASSWORD", "p")
	store, _ := credentials.NewStore("")
	c := New(Config{
		Concurrency: 1,
		SSH:         sshclient.Options{ConnectTimeout: 3 * time.Second, CommandTimeout: time.Second, HostKeyCallback: ssh.InsecureIgnoreHostKey()},
		CredStore:   store,
	})
	var res Result
	for r := range c.Run(context.Background(), []inventory.Device{{Hostname: "FGT-01", Address: host, Port: port, Vendor: "fortigate", CredentialGroup: "default"}}) {
		res = r
	}
	return res
}

func TestInteractivePlanAnswersPager(t *testing.T) {
	host, port := startPTYDevice(t, ptyOpts{paged: true})
	res := pollFortigate(t, host, port)
	if res.Err != nil || !strings.Contains(res.Raw, "Admin login failed") {
		t.Fatalf("pager not answered: err=%v raw=%q", res.Err, res.Raw)
	}
}

func TestInteractivePlanTimesOutWithoutPrompt(t *testing.T) {
	old := minInteractiveTimeout
	minInteractiveTimeout = 1500 * time.Millisecond
	t.Cleanup(func() { minInteractiveTimeout = old })

	host, port := startPTYDevice(t, ptyOpts{noPrompt: true})
	started := time.Now()
	res := pollFortigate(t, host, port)
	if res.Err == nil || !strings.Contains(res.Err.Error(), "waiting for the prompt") {
		t.Fatalf("a device that never returns to its prompt must be an error, got %v", res.Err)
	}
	if res.Raw != "" {
		t.Errorf("a failed poll must not return partial output as data: %q", res.Raw)
	}
	if d := time.Since(started); d > 6*time.Second {
		t.Errorf("hard deadline not honoured: %v", d)
	}
}

func TestAtPrompt(t *testing.T) {
	for out, want := range map[string]bool{
		"FGT-01 # ":                               true,
		"x\r\nFGT-01 (root) # ":                   true,
		"x\nFGT-01 $ ":                            true,
		"\x1b[32mFGT-01 # \x1b[0m":                true,
		"FGT-01 # execute log display":            false,
		"some log text # not a prompt here, long": false,
		"": false,
	} {
		if got := atPrompt(out, fortiPrompt); got != want {
			t.Errorf("atPrompt(%q) = %v, want %v", out, got, want)
		}
	}
}

// A key in the log or clock tables that the platform registry does not know
// could never be selected, so the entry would be dead without any error.
func TestPlansUseKnownVendorKeys(t *testing.T) {
	for key := range logPlans {
		if !vendor.IsKnown(key) {
			t.Errorf("logPlans has unknown platform key %q", key)
		}
	}
	for key := range clockCommands {
		if !vendor.IsKnown(key) {
			t.Errorf("clockCommands has unknown platform key %q", key)
		}
	}
}

// The shipped example inventory is what "make init" copies for new users: it
// must load without warnings and every device in it must be pollable.
func TestExampleInventoryIsUsable(t *testing.T) {
	devices, warns := inventory.Load("../../examples/inventory.csv")
	for _, w := range warns {
		t.Errorf("example inventory warning: %v", w)
	}
	if len(devices) < 8 {
		t.Fatalf("example inventory should show a range of platforms, got %d devices", len(devices))
	}
	for _, d := range devices {
		if _, _, err := resolvePlan(d); err != nil {
			t.Errorf("example device %s (%s) cannot be polled: %v", d.Hostname, d.Vendor, err)
		}
	}
}
