package diagnose

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"netlog/internal/collector"
	"netlog/internal/credentials"
	"netlog/internal/inventory"
	"netlog/internal/sshclient"
	"netlog/internal/triage"
)

// fakeSSH serves exec requests on loopback with password u/p.
type fakeSSH struct {
	mu   sync.Mutex
	cmds []string
}

func (f *fakeSSH) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}

func startFakeSSH(t *testing.T, handler func(cmd string) string) (*fakeSSH, string, int) {
	t.Helper()
	fs := &fakeSSH{}
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
		t.Skipf("cannot listen: %v", err)
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
							fs.mu.Lock()
							fs.cmds = append(fs.cmds, cmd)
							fs.mu.Unlock()
							ch.Write([]byte(handler(cmd)))
							ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
							ch.Close()
							return
						}
					}()
				}
			}()
		}
	}()
	host, ps, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(ps)
	return fs, host, port
}

func testDialer(t *testing.T, jump bool) *collector.Dialer {
	t.Helper()
	t.Setenv("NETLOG_USERNAME", "u")
	t.Setenv("NETLOG_PASSWORD", "p")
	creds, err := credentials.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	return collector.NewDialer(collector.DialerConfig{
		SSH:         sshclient.Options{ConnectTimeout: 5 * time.Second, CommandTimeout: 5 * time.Second, HostKeyCallback: ssh.InsecureIgnoreHostKey()},
		CredStore:   creds,
		JumpEnabled: jump,
	})
}

func TestRunIncludesProbeAndPoE(t *testing.T) {
	fd, host, port := startFakeSSH(t, func(cmd string) string {
		if cmd == "show power inline" {
			return ciscoPoE
		}
		return ""
	})
	dev := inventory.Device{Hostname: "SW1", Address: host, Port: port, Vendor: "cisco_ios", CredentialGroup: "default"}
	d := testDialer(t, false)
	defer d.CloseJumps()

	rep := Run(context.Background(), d, dev, Options{Probe: ProbeOptions{openICMP: denyICMP}})
	if !rep.Connected || rep.ProbeSection == nil || rep.PoESection == nil {
		t.Fatalf("connected=%v probe=%v poe=%v err=%q", rep.Connected, rep.ProbeSection, rep.PoESection, rep.ConnectErr)
	}
	if rep.ProbeSection.Status != StatusOK || !statRe.MatchString(strings.Join(rep.ProbeSection.Notes, "\n")) {
		t.Errorf("probe: %+v", rep.ProbeSection)
	}
	if rep.PoESection.Status != StatusWarn || !strings.Contains(strings.Join(rep.PoESection.Notes, "\n"), "Gi1/0/2 (faulty)") {
		t.Errorf("poe: %+v", rep.PoESection)
	}
	if rep.Healthy() {
		t.Error("a flagged PoE port must make the report unhealthy")
	}
	sent := fd.commands()
	if sent[len(sent)-1] != "show power inline" {
		t.Errorf("commands sent: %q", sent)
	}

	// Render: probe first (before the SSH line), PoE after the other checks.
	var b bytes.Buffer
	Render(&b, rep, RenderOptions{})
	out := b.String()
	iProbe, iSSH, iPoE := strings.Index(out, SecProbe), strings.Index(out, "SSH connect"), strings.Index(out, SecPoE)
	if iProbe <= 0 || iProbe >= iSSH || iSSH >= iPoE || !strings.Contains(out, "ATTENTION NEEDED") {
		t.Errorf("render order wrong:\n%s", out)
	}

	// JSON: probe and poe keys at the top level, no credentials, valid JSON.
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, raw)
	}
	for _, k := range []string{"probe", "poe", "sections", "hostname", "healthy", "connected"} {
		if _, ok := m[k]; !ok {
			t.Errorf("JSON lacks %q: %s", k, raw)
		}
	}
	if strings.Contains(string(raw), "CredentialGroup") || strings.Contains(string(raw), "password") {
		t.Errorf("JSON leaks inventory internals: %s", raw)
	}
}

func TestRunWithoutProbeOrPoE(t *testing.T) {
	_, host, port := startFakeSSH(t, func(cmd string) string { return "" })
	d := testDialer(t, false)
	defer d.CloseJumps()

	// No PoE command for this platform and the probe switched off.
	dev := inventory.Device{Hostname: "R1", Address: host, Port: port, Vendor: "juniper_junos", CredentialGroup: "default"}
	rep := Run(context.Background(), d, dev, Options{NoProbe: true})
	if !rep.Connected || rep.ProbeSection != nil || rep.PoESection != nil {
		t.Fatalf("probe=%v poe=%v", rep.ProbeSection, rep.PoESection)
	}
	raw, _ := json.Marshal(rep)
	if strings.Contains(string(raw), `"probe"`) || strings.Contains(string(raw), `"poe"`) {
		t.Errorf("omitempty not honoured: %s", raw)
	}
}

func TestProbeShownWhenSSHFailsAndSkippedBehindJump(t *testing.T) {
	// A closed port: SSH cannot connect, but the probe still reports why.
	host, port, stop := listener(t)
	stop()
	time.Sleep(20 * time.Millisecond)
	d := testDialer(t, false)
	defer d.CloseJumps()
	dev := inventory.Device{Hostname: "SW1", Address: host, Port: port, Vendor: "cisco_ios", CredentialGroup: "default"}
	rep := Run(context.Background(), d, dev, Options{Probe: ProbeOptions{openICMP: denyICMP}})
	if rep.Connected || rep.ProbeSection == nil || rep.ProbeSection.Status != StatusError {
		t.Fatalf("connected=%v probe=%+v", rep.Connected, rep.ProbeSection)
	}
	var b bytes.Buffer
	Render(&b, rep, RenderOptions{})
	if !strings.Contains(b.String(), "connection refused") || !strings.Contains(b.String(), "SSH:") {
		t.Errorf("render:\n%s", b.String())
	}

	// Through a jump host a direct probe measures the wrong path.
	dj := testDialer(t, true)
	defer dj.CloseJumps()
	devJ := inventory.Device{Hostname: "SW2", Address: "10.255.255.1", Port: 22, Vendor: "cisco_ios", CredentialGroup: "default", JumpHost: "bastion-a"}
	rep = Run(context.Background(), dj, devJ, Options{Probe: ProbeOptions{openICMP: denyICMP}})
	if rep.ProbeSection == nil || rep.ProbeSection.Status != StatusUnknown || !strings.Contains(strings.Join(rep.ProbeSection.Notes, ""), "jump host") {
		t.Errorf("probe behind a jump host: %+v", rep.ProbeSection)
	}
}

func TestPoECommandsPassGate1ForEveryVendor(t *testing.T) {
	// Every PoE command in the table passes GATE 1 (TestPoECommands checks
	// the individual commands; this walks the registry the way Run does).
	for key := range poeCommands {
		if err := triage.Check(PoECommand(key)); err != nil {
			t.Errorf("%s: %v", key, err)
		}
	}
}
