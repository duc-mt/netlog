// ==============================================================================
// Package sshclient: tests.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         go test ./internal/sshclient
// Notes:         Go package implementation
// ==============================================================================
package sshclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func startMockSSHServer(t *testing.T) (int, func()) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating host key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "testuser" && string(pass) == "testpass" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected")
		},
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if c.User() == "kbuser" {
				answers, err := client(c.User(), "", []string{"Password: "}, []bool{false})
				if err == nil && len(answers) == 1 && answers[0] == "kbpass" {
					return nil, nil
				}
			}
			return nil, fmt.Errorf("keyboard interactive rejected")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == "keyuser" {
				return nil, nil
			}
			return nil, fmt.Errorf("public key rejected")
		},
	}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	done := make(chan struct{})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}

			go handleSSHConn(conn, serverConfig)
		}
	}()

	return port, func() {
		close(done)
		_ = listener.Close()
	}
}

func handleSSHConn(conn net.Conn, config *ssh.ServerConfig) {
	sConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		conn.Close()
		return
	}
	defer sConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChan.Accept()
		if err != nil {
			continue
		}

		go handleSession(channel, requests)
	}
}

func handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	for req := range requests {
		switch req.Type {
		case "pty-req":
			req.Reply(true, nil)
		case "shell":
			req.Reply(true, nil)
			// Read commands from stdin and respond
			go func() {
				buf := make([]byte, 1024)
				paged := false
				for {
					n, err := channel.Read(buf)
					if err != nil || n == 0 {
						return
					}
					input := string(buf[:n])
					switch {
					case strings.Contains(input, "page-test"):
						paged = true
						_, _ = channel.Write([]byte("hostname paged-router\n--More--"))
					case paged && strings.Contains(input, " "):
						paged = false
						_, _ = channel.Write([]byte("\ninterface gig0/2\nend\n"))
					case strings.Contains(input, "show"):
						_, _ = channel.Write([]byte("hostname router-sw-01\ninterface GigabitEthernet0/1\n"))
					default:
						_, _ = channel.Write([]byte("ok\n"))
					}
				}
			}()
		case "exec":
			cmd := ""
			if len(req.Payload) >= 4 {
				cmd = string(req.Payload[4:])
			}
			req.Reply(true, nil)
			if strings.Contains(cmd, "sleep") {
				time.Sleep(500 * time.Millisecond)
			}
			if strings.Contains(cmd, "error") {
				_, _ = channel.Stderr().Write([]byte("syntax error in command"))
				_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 1})
			} else {
				_, _ = channel.Write([]byte("! Configuration\nhostname core-switch-01\nend\n"))
				_, _ = channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
			}
			return
		default:
			req.Reply(false, nil)
		}
	}
}

func TestConnectAndPasswordAuth(t *testing.T) {
	port, cleanup := startMockSSHServer(t)
	defer cleanup()

	opts := Options{
		ConnectTimeout:  2 * time.Second,
		CommandTimeout:  2 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// 1. Successful password authentication
	client, err := Connect(context.Background(), "127.0.0.1", port, "testuser", "testpass", opts)
	if err != nil {
		t.Fatalf("expected successful connect: %v", err)
	}
	defer client.Close()

	// 2. RunCommand test
	out, err := RunCommand(context.Background(), client, "show run", opts)
	if err != nil {
		t.Fatalf("expected successful command run: %v", err)
	}
	if !strings.Contains(out, "core-switch-01") {
		t.Errorf("unexpected command output: %q", out)
	}

	// 3. RunCommand error test
	_, err = RunCommand(context.Background(), client, "error cmd", opts)
	if err == nil {
		t.Fatalf("expected command error")
	}
	if !strings.Contains(err.Error(), "syntax error in command") {
		t.Errorf("expected stderr message in error, got: %v", err)
	}

	// 4. Failed authentication
	_, err = Connect(context.Background(), "127.0.0.1", port, "testuser", "wrongpass", opts)
	if err == nil {
		t.Fatalf("expected connection to fail with wrong password")
	}
}

func TestKeyboardInteractiveAuth(t *testing.T) {
	port, cleanup := startMockSSHServer(t)
	defer cleanup()

	opts := Options{
		ConnectTimeout:  2 * time.Second,
		CommandTimeout:  2 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Connect using keyboard-interactive credentials
	client, err := Connect(context.Background(), "127.0.0.1", port, "kbuser", "kbpass", opts)
	if err != nil {
		t.Fatalf("expected successful connect with keyboard-interactive: %v", err)
	}
	defer client.Close()
}

func TestPublicKeyAuth(t *testing.T) {
	port, cleanup := startMockSSHServer(t)
	defer cleanup()

	// Generate client private key
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	pemBytes, err := ssh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		t.Fatalf("marshaling private key: %v", err)
	}
	keyFile := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBytes), 0o600); err != nil {
		t.Fatalf("writing temp key file: %v", err)
	}

	opts := Options{
		ConnectTimeout:  2 * time.Second,
		CommandTimeout:  2 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// 1. Connect with private key file
	client, err := ConnectWithAuth(context.Background(), "127.0.0.1", port, AuthOptions{
		Username: "keyuser",
		KeyFile:  keyFile,
	}, opts)
	if err != nil {
		t.Fatalf("expected successful connect with public key: %v", err)
	}
	defer client.Close()

	// 2. Reject unknown keyuser
	_, err = ConnectWithAuth(context.Background(), "127.0.0.1", port, AuthOptions{
		Username: "wrongkeyuser",
		KeyFile:  keyFile,
	}, opts)
	if err == nil {
		t.Fatalf("expected connection to fail for wrong key user")
	}
}

func TestRunCommandTimeout(t *testing.T) {
	port, cleanup := startMockSSHServer(t)
	defer cleanup()

	opts := Options{
		ConnectTimeout:  2 * time.Second,
		CommandTimeout:  100 * time.Millisecond,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := Connect(context.Background(), "127.0.0.1", port, "testuser", "testpass", opts)
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer client.Close()

	_, err = RunCommand(context.Background(), client, "sleep 5", opts)
	if err == nil {
		t.Fatalf("expected command timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunCommandContextCancellation(t *testing.T) {
	port, cleanup := startMockSSHServer(t)
	defer cleanup()

	opts := Options{
		ConnectTimeout:  2 * time.Second,
		CommandTimeout:  5 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := Connect(context.Background(), "127.0.0.1", port, "testuser", "testpass", opts)
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = RunCommand(ctx, client, "sleep 5", opts)
	if err == nil {
		t.Fatalf("expected command cancellation error")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("expected context cancellation error, got: %v", err)
	}
}

func TestRunInteractive(t *testing.T) {
	port, cleanup := startMockSSHServer(t)
	defer cleanup()

	opts := Options{
		ConnectTimeout:  5 * time.Second,
		CommandTimeout:  10 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := Connect(context.Background(), "127.0.0.1", port, "testuser", "testpass", opts)
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer client.Close()

	output, err := RunInteractive(context.Background(), client, []string{"terminal length 0", "show run"}, opts)
	if err != nil {
		t.Fatalf("RunInteractive failed: %v", err)
	}
	if !strings.Contains(output, "router-sw-01") {
		t.Errorf("unexpected output from RunInteractive: %q", output)
	}
}

func TestRunInteractivePager(t *testing.T) {
	port, cleanup := startMockSSHServer(t)
	defer cleanup()

	opts := Options{
		ConnectTimeout:  5 * time.Second,
		CommandTimeout:  10 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := Connect(context.Background(), "127.0.0.1", port, "testuser", "testpass", opts)
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	defer client.Close()

	output, err := RunInteractive(context.Background(), client, []string{"page-test"}, opts)
	if err != nil {
		t.Fatalf("RunInteractive failed with pager: %v", err)
	}
	if !strings.Contains(output, "paged-router") || !strings.Contains(output, "gig0/2") {
		t.Errorf("expected complete output across pager, got: %q", output)
	}
	if strings.Contains(output, "--More--") {
		t.Errorf("expected --More-- markers to be cleaned up, got: %q", output)
	}
}

func TestLegacyAlgorithmsOption(t *testing.T) {
	optsModern := Options{
		ConnectTimeout:   2 * time.Second,
		LegacyAlgorithms: false,
	}
	cfgModern, err := buildClientConfig(AuthOptions{Username: "u", Password: "p"}, ssh.InsecureIgnoreHostKey(), optsModern)
	if err != nil {
		t.Fatalf("buildClientConfig modern failed: %v", err)
	}
	for _, c := range cfgModern.Config.Ciphers {
		if c == "3des-cbc" || c == "aes128-cbc" || c == "arcfour" {
			t.Errorf("did not expect legacy cipher %s in modern config", c)
		}
	}
	hasDH16 := false
	hasDHGEX256 := false
	for _, k := range cfgModern.Config.KeyExchanges {
		if k == "diffie-hellman-group16-sha512" {
			hasDH16 = true
		}
		if k == "diffie-hellman-group-exchange-sha256" {
			hasDHGEX256 = true
		}
		if k == "diffie-hellman-group-exchange-sha1" || k == "diffie-hellman-group1-sha1" {
			t.Errorf("did not expect legacy kex %s in modern config", k)
		}
	}
	if !hasDH16 {
		t.Errorf("expected diffie-hellman-group16-sha512 in modern config, kex: %v", cfgModern.Config.KeyExchanges)
	}
	if !hasDHGEX256 {
		t.Errorf("expected diffie-hellman-group-exchange-sha256 in modern config, kex: %v", cfgModern.Config.KeyExchanges)
	}

	optsLegacy := Options{
		ConnectTimeout:   2 * time.Second,
		LegacyAlgorithms: true,
	}
	cfgLegacy, err := buildClientConfig(AuthOptions{Username: "u", Password: "p"}, ssh.InsecureIgnoreHostKey(), optsLegacy)
	if err != nil {
		t.Fatalf("buildClientConfig legacy failed: %v", err)
	}
	has3DES := false
	hasArcfour := false
	for _, c := range cfgLegacy.Config.Ciphers {
		if c == "3des-cbc" {
			has3DES = true
		}
		if c == "arcfour" {
			hasArcfour = true
		}
	}
	if !has3DES {
		t.Errorf("expected 3des-cbc in legacy config, ciphers: %v", cfgLegacy.Config.Ciphers)
	}
	if !hasArcfour {
		t.Errorf("expected arcfour in legacy config, ciphers: %v", cfgLegacy.Config.Ciphers)
	}
	hasDHGEX1 := false
	hasDSA := false
	for _, k := range cfgLegacy.Config.KeyExchanges {
		if k == "diffie-hellman-group-exchange-sha1" {
			hasDHGEX1 = true
		}
	}
	for _, hk := range cfgLegacy.HostKeyAlgorithms {
		if hk == "ssh-dss" {
			hasDSA = true
		}
	}
	if !hasDHGEX1 {
		t.Errorf("expected diffie-hellman-group-exchange-sha1 in legacy config, kex: %v", cfgLegacy.Config.KeyExchanges)
	}
	if !hasDSA {
		t.Errorf("expected ssh-dss in legacy host keys, got: %v", cfgLegacy.HostKeyAlgorithms)
	}
}

func TestKnownHostsCallbackStrict(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	pub := signer.PublicKey()

	f, _ := os.CreateTemp("", "known_hosts_strict")
	defer os.Remove(f.Name())
	f.Close()

	cb, err := KnownHostsCallback(f.Name(), PolicyStrict)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	err = cb("127.0.0.1", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}, pub)
	if err == nil {
		t.Fatal("expected strict policy to reject unknown key, got nil")
	}
}

func TestKnownHostsCallbackAcceptNew(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	pub := signer.PublicKey()

	f, _ := os.CreateTemp("", "known_hosts_acceptnew")
	defer os.Remove(f.Name())
	f.Close()

	cb, err := KnownHostsCallback(f.Name(), PolicyAcceptNew)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	err = cb("127.0.0.1:22", addr, pub)
	if err != nil {
		t.Fatalf("expected accept-new policy to accept unknown key, got: %v", err)
	}

	content, _ := os.ReadFile(f.Name())
	if !strings.Contains(string(content), "127.0.0.1") {
		t.Fatalf("expected key to be written to known_hosts, file is: %s", string(content))
	}

	// second call should succeed via known key logic without re-appending
	err = cb("127.0.0.1:22", addr, pub)
	if err != nil {
		t.Fatalf("expected known key to be accepted: %v", err)
	}
}

func TestKnownHostsCallbackUpdate(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	signer1, _ := ssh.NewSignerFromKey(priv1)
	pub1 := signer1.PublicKey()

	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	signer2, _ := ssh.NewSignerFromKey(priv2)
	pub2 := signer2.PublicKey()

	f, _ := os.CreateTemp("", "known_hosts_update")
	defer os.Remove(f.Name())
	f.Close()

	addr := &net.TCPAddr{IP: net.ParseIP("192.168.1.50"), Port: 22}

	// 1. Initial write with AcceptNew
	cbAcceptNew, err := KnownHostsCallback(f.Name(), PolicyAcceptNew)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := cbAcceptNew("192.168.1.50:22", addr, pub1); err != nil {
		t.Fatalf("accept-new failed on initial key: %v", err)
	}

	// 2. AcceptNew must REJECT changed key pub2
	cbAcceptNew2, _ := KnownHostsCallback(f.Name(), PolicyAcceptNew)
	if err := cbAcceptNew2("192.168.1.50:22", addr, pub2); err == nil {
		t.Fatalf("expected accept-new to reject mismatched key, got nil")
	}

	// 3. Strict must REJECT changed key pub2
	cbStrict, _ := KnownHostsCallback(f.Name(), PolicyStrict)
	if err := cbStrict("192.168.1.50:22", addr, pub2); err == nil {
		t.Fatalf("expected strict to reject mismatched key, got nil")
	}

	// 4. Update policy must ACCEPT changed key pub2 and replace pub1 in file
	cbUpdate, err := KnownHostsCallback(f.Name(), PolicyUpdate)
	if err != nil {
		t.Fatalf("unexpected err for update policy: %v", err)
	}
	if err := cbUpdate("192.168.1.50:22", addr, pub2); err != nil {
		t.Fatalf("expected update policy to succeed and replace mismatched key, got: %v", err)
	}

	// 5. Verify with Strict policy that pub2 is now the recognized key and pub1 is rejected
	cbStrictAfter, err := KnownHostsCallback(f.Name(), PolicyStrict)
	if err != nil {
		t.Fatalf("failed to create strict callback after update: %v", err)
	}
	if err := cbStrictAfter("192.168.1.50:22", addr, pub2); err != nil {
		t.Fatalf("expected new key pub2 to be valid under strict policy after update: %v", err)
	}
	if err := cbStrictAfter("192.168.1.50:22", addr, pub1); err == nil {
		t.Fatalf("expected old key pub1 to be rejected under strict policy after update")
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("user home dir not available")
	}

	if got := ExpandHome("~"); got != home {
		t.Errorf("ExpandHome(~) = %q, want %q", got, home)
	}
	wantPath := filepath.Join(home, ".ssh", "known_hosts")
	if got := ExpandHome("~/.ssh/known_hosts"); got != wantPath {
		t.Errorf("ExpandHome(~/.ssh/known_hosts) = %q, want %q", got, wantPath)
	}
	if got := ExpandHome(`~\.ssh\known_hosts`); got != wantPath {
		t.Errorf(`ExpandHome(~\\.ssh\\known_hosts) = %q, want %q`, got, wantPath)
	}
	if got := ExpandHome("/tmp/known_hosts"); got != "/tmp/known_hosts" {
		t.Errorf("ExpandHome(/tmp/known_hosts) = %q, want %q", got, "/tmp/known_hosts")
	}
}

func TestDefaultKnownHostsFile(t *testing.T) {
	path := DefaultKnownHostsFile()
	if path == "" {
		t.Fatal("DefaultKnownHostsFile returned empty string")
	}
	if !strings.HasSuffix(filepath.ToSlash(path), ".ssh/known_hosts") && path != "known_hosts" {
		t.Errorf("unexpected default path %q", path)
	}
}

func TestKnownHostsCallbackCrossPlatform(t *testing.T) {
	dir := t.TempDir()
	fakeHome := filepath.Join(dir, "userhome")
	t.Setenv("HOME", fakeHome)
	t.Setenv("USERPROFILE", fakeHome)

	userKhPath := filepath.Join(fakeHome, ".ssh", "known_hosts")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	pub := signer.PublicKey()
	addr := &net.TCPAddr{IP: net.ParseIP("192.0.2.100"), Port: 22}

	cb, err := KnownHostsCallback(userKhPath, PolicyAcceptNew)
	if err != nil {
		t.Fatalf("KnownHostsCallback failed: %v", err)
	}
	if err := cb("192.0.2.100:22", addr, pub); err != nil {
		t.Fatalf("cb enrollment failed: %v", err)
	}

	data, err := os.ReadFile(userKhPath)
	if err != nil {
		t.Fatalf("failed reading enrolled file: %v", err)
	}
	if !strings.Contains(string(data), "192.0.2.100") {
		t.Fatalf("enrolled key not found in %s: %s", userKhPath, string(data))
	}
}

// startMockSSHServerWithForward starts a mock SSH server that also handles
// "direct-tcpip" channel requests, forwarding them to the given target addr.
// This mimics a real bastion host that can proxy connections.
func startMockSSHServerWithForward(t *testing.T, targetAddr string) (int, func()) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}

	serverConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "jumpuser" && string(pass) == "jumppass" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected")
		},
	}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	done := make(chan struct{})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-done:
				default:
				}
				return
			}
			go handleBastionConn(conn, serverConfig, targetAddr)
		}
	}()

	return port, func() {
		close(done)
		_ = listener.Close()
	}
}

// handleBastionConn handles SSH connections on the mock bastion, proxying
// direct-tcpip channel requests to targetAddr.
func handleBastionConn(conn net.Conn, config *ssh.ServerConfig, targetAddr string) {
	sConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		conn.Close()
		return
	}
	defer sConn.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		switch newChan.ChannelType() {
		case "direct-tcpip":
			// Accept the channel and pipe it to the real target.
			ch, _, err := newChan.Accept()
			if err != nil {
				continue
			}
			go func() {
				defer ch.Close()
				target, err := net.Dial("tcp", targetAddr)
				if err != nil {
					return
				}
				defer target.Close()
				done := make(chan struct{}, 2)
				copy := func(dst, src interface {
					Read([]byte) (int, error)
					Write([]byte) (int, error)
				}) {
					buf := make([]byte, 32*1024)
					for {
						n, err := src.Read(buf)
						if n > 0 {
							if _, werr := dst.Write(buf[:n]); werr != nil {
								break
							}
						}
						if err != nil {
							break
						}
					}
					done <- struct{}{}
				}
				go copy(target, ch)
				go copy(ch, target)
				<-done
			}()
		default:
			newChan.Reject(ssh.UnknownChannelType, "only direct-tcpip is supported on this bastion")
		}
	}
}

func TestConnectViaJump(t *testing.T) {
	// Start the "real" target SSH server.
	targetPort, targetCleanup := startMockSSHServer(t)
	defer targetCleanup()

	targetAddr := fmt.Sprintf("127.0.0.1:%d", targetPort)

	// Start the bastion that can forward to the target.
	bastionPort, bastionCleanup := startMockSSHServerWithForward(t, targetAddr)
	defer bastionCleanup()

	opts := Options{
		ConnectTimeout:  5 * time.Second,
		CommandTimeout:  5 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// 1. Connect to bastion.
	bastionClient, err := ConnectJumpHost(context.Background(), "127.0.0.1", bastionPort, "jumpuser", "jumppass", opts)
	if err != nil {
		t.Fatalf("ConnectJumpHost failed: %v", err)
	}
	defer bastionClient.Close()

	// 2. Connect to target via the bastion tunnel.
	client, err := ConnectViaJump(context.Background(), bastionClient, "127.0.0.1", targetPort, "testuser", "testpass", opts)
	if err != nil {
		t.Fatalf("ConnectViaJump failed: %v", err)
	}
	defer client.Close()

	// 3. Run a command through the tunnelled connection.
	out, err := RunCommand(context.Background(), client, "show run", opts)
	if err != nil {
		t.Fatalf("RunCommand via jump failed: %v", err)
	}
	if !strings.Contains(out, "core-switch-01") {
		t.Errorf("unexpected output through jump: %q", out)
	}
}

func TestConnectJumpHostBadPassword(t *testing.T) {
	bastionPort, cleanup := startMockSSHServerWithForward(t, "127.0.0.1:22")
	defer cleanup()

	opts := Options{
		ConnectTimeout:  2 * time.Second,
		CommandTimeout:  2 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	_, err := ConnectJumpHost(context.Background(), "127.0.0.1", bastionPort, "jumpuser", "wrongpass", opts)
	if err == nil {
		t.Fatal("expected auth failure for bad jump host password")
	}
}

func TestCheckKeyPermissions(t *testing.T) {
	dir := t.TempDir()

	safeKey := filepath.Join(dir, "id_ed25519_safe")
	if err := os.WriteFile(safeKey, []byte("fake-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if warn := CheckKeyPermissions(safeKey); warn != "" {
		t.Errorf("expected no warning for 0600 key file, got: %s", warn)
	}

	looseKey := filepath.Join(dir, "id_ed25519_loose")
	if err := os.WriteFile(looseKey, []byte("fake-key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if warn := CheckKeyPermissions(looseKey); warn == "" {
		t.Errorf("expected warning for 0644 key file, got none")
	}

	if warn := CheckKeyPermissions(filepath.Join(dir, "nonexistent")); warn != "" {
		t.Errorf("expected no warning for nonexistent file, got: %s", warn)
	}
}
