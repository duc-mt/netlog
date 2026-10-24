// ==============================================================================
// Package sshclient dials devices and runs commands over SSH (legacy algorithms, bastions).
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         imported by cmd/netlog and the other internal packages
// Notes:         Go package implementation
// ==============================================================================
// Package sshclient wraps golang.org/x/crypto/ssh with the two things a
// network tool actually needs on top of it: hard timeouts at every stage
// (dial, handshake, command execution) and two execution strategies
// (plain one-shot exec, and interactive shell for platforms that need it).
package sshclient

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var (
	pagerPromptRe = regexp.MustCompile(`(?i)(?:--\s*More(?:\s*\(\d+%\))?\s*--|---\(more(?:\s+\d+%)?\)---|\[More\]|Press any key to continue|<--- More --->)\s*$`)
	pagerMarkerRe = regexp.MustCompile(`(?i)(?:--\s*More(?:\s*\(\d+%\))?\s*--|---\(more(?:\s+\d+%)?\)---|\[More\]|Press any key to continue|<--- More --->)`)
)

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Len()
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// Options controls the timeouts applied to every connection. All fields are
// required; see main.go for the CLI flags that populate this.
type Options struct {
	ConnectTimeout time.Duration // TCP dial + SSH handshake
	CommandTimeout time.Duration // time budget for running the command(s)

	// HostKeyCallback verifies the server's host key during the SSH
	// handshake. It is required: Connect returns an error if it is nil
	// rather than silently accepting any host key. Use LoadKnownHosts to
	// build one from a known_hosts file, ssh.FixedHostKey for a single
	// pinned key, or ssh.InsecureIgnoreHostKey() as an explicit, callsite-
	// visible opt-out (never as a hidden default).
	HostKeyCallback ssh.HostKeyCallback

	// JumpHostKeyCallback, when non-nil, is used to verify the bastion /
	// jump host's own key. Falls back to HostKeyCallback when nil.
	JumpHostKeyCallback ssh.HostKeyCallback

	// TCPMSS clamps the TCP Maximum Segment Size on outgoing sockets.
	// 0 = default (1360), <0 = disabled (OS default).
	TCPMSS int

	// LegacyAlgorithms, when true, enables older ciphers (e.g. 3des-cbc, aes128-cbc),
	// key exchanges (e.g. diffie-hellman-group1-sha1, diffie-hellman-group14-sha1),
	// and legacy host keys (ssh-dss) for compatibility with older network hardware.
	LegacyAlgorithms bool
}

// ErrNoHostKeyCallback is returned by Connect when opts.HostKeyCallback is
// nil, so callers can't accidentally run with host key checking disabled.
var ErrNoHostKeyCallback = errors.New("sshclient: Options.HostKeyCallback is required")

// KnownHostsPolicy defines how unknown host keys are handled.
type KnownHostsPolicy string

const (
	PolicyStrict    KnownHostsPolicy = "strict"     // reject unknown or changed keys
	PolicyAcceptNew KnownHostsPolicy = "accept-new" // add unknown keys, reject changed keys
	PolicyUpdate    KnownHostsPolicy = "update"     // add unknown keys, automatically remove mismatched keys and learn new keys
	PolicyReplace   KnownHostsPolicy = "replace"    // alias for update
)

// DefaultKnownHostsFile returns the default user OpenSSH known_hosts path
// for the current OS (Linux/macOS: ~/.ssh/known_hosts, Windows: %USERPROFILE%\.ssh\known_hosts).
func DefaultKnownHostsFile() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "known_hosts"
	}
	return filepath.Join(home, ".ssh", "known_hosts")
}

// SystemKnownHostsFiles returns the standard system-wide known_hosts file paths
// for the current OS if they exist.
// Linux/macOS: /etc/ssh/ssh_known_hosts, /etc/ssh/ssh_known_hosts2
// Windows: %ProgramData%\ssh\ssh_known_hosts
func SystemKnownHostsFiles() []string {
	var candidates []string
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			candidates = append(candidates, filepath.Join(pd, "ssh", "ssh_known_hosts"))
		}
	} else {
		candidates = append(candidates, "/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2")
	}

	var existing []string
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			existing = append(existing, c)
		}
	}
	return existing
}

// ExpandHome resolves a leading "~/" or "~\" against the current user's home directory.
func ExpandHome(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return home
		}
		return path
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			rest := filepath.FromSlash(strings.ReplaceAll(path[2:], `\`, "/"))
			return filepath.Join(home, rest)
		}
	}
	return path
}

// KnownHostsCallback builds a HostKeyCallback from an OpenSSH-format known_hosts
// file and enforces the given policy (strict or accept-new). If path points to
// the default user known_hosts file, system-wide known_hosts files are also checked as read-only fallbacks.
func KnownHostsCallback(path string, policy KnownHostsPolicy) (ssh.HostKeyCallback, error) {
	if policy != PolicyStrict && policy != PolicyAcceptNew && policy != PolicyUpdate && policy != PolicyReplace {
		return nil, fmt.Errorf("invalid known_hosts policy: %q", policy)
	}

	path = ExpandHome(path)

	// In accept-new or update mode, ensure user file and its directory exist
	if policy == PolicyAcceptNew || policy == PolicyUpdate || policy == PolicyReplace {
		if err := ensureFile(path); err != nil {
			return nil, err
		}
	}

	readFiles := []string{}
	if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
		readFiles = append(readFiles, path)
	}

	defUser := DefaultKnownHostsFile()
	if filepath.Clean(path) == filepath.Clean(defUser) {
		for _, sysFile := range SystemKnownHostsFiles() {
			if filepath.Clean(sysFile) != filepath.Clean(path) {
				readFiles = append(readFiles, sysFile)
			}
		}
	}

	var checker ssh.HostKeyCallback
	if len(readFiles) == 0 {
		if policy == PolicyStrict {
			return nil, fmt.Errorf("reading known_hosts %q: open %s: no such file or directory", path, path)
		}
		var err error
		checker, err = knownhosts.New()
		if err != nil {
			return nil, fmt.Errorf("reading known_hosts %q: %w", path, err)
		}
	} else {
		var err error
		checker, err = knownhosts.New(readFiles...)
		if err != nil {
			return nil, fmt.Errorf("reading known_hosts %q: %w", path, err)
		}
	}

	var mu sync.Mutex // protects concurrent writes to the known_hosts file

	reloadChecker := func() {
		updatedFiles := []string{path}
		if filepath.Clean(path) == filepath.Clean(defUser) {
			for _, sysFile := range SystemKnownHostsFiles() {
				if filepath.Clean(sysFile) != filepath.Clean(path) {
					updatedFiles = append(updatedFiles, sysFile)
				}
			}
		}
		if c, err := knownhosts.New(updatedFiles...); err == nil {
			checker = c
		}
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := checker(hostname, remote, key)
		if err == nil {
			return nil // Key is known and matches
		}

		var keyErr *knownhosts.KeyError
		if errors.As(err, &keyErr) {
			if len(keyErr.Want) == 0 {
				// The key is completely unknown
				if policy == PolicyAcceptNew || policy == PolicyUpdate || policy == PolicyReplace {
					mu.Lock()
					defer mu.Unlock()

					// Re-check inside the lock in case another goroutine or process just recorded it
					if isHostKeyRecorded(path, hostname, remote, key) {
						return nil
					}

					f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
					if err != nil {
						return fmt.Errorf("failed to open known_hosts to accept new key: %w", err)
					}
					defer f.Close()

					line := knownhosts.Line([]string{hostname}, key)
					if _, err := f.WriteString(line + "\n"); err != nil {
						return fmt.Errorf("failed to write new key to known_hosts: %w", err)
					}

					reloadChecker()
					return nil
				}
				return fmt.Errorf("host key verification failed: %s not found in known_hosts (policy=%s)", hostname, policy)
			}

			// Key mismatch (remote host identification changed)
			if policy == PolicyUpdate || policy == PolicyReplace {
				mu.Lock()
				defer mu.Unlock()

				// Re-check inside the lock in case another goroutine already updated it
				if isHostKeyRecorded(path, hostname, remote, key) {
					return nil
				}

				linesToRemove := make(map[int]bool)
				for _, w := range keyErr.Want {
					if filepath.Clean(w.Filename) == filepath.Clean(path) && w.Line > 0 {
						linesToRemove[w.Line] = true
					}
				}

				if err := removeAndReplaceHostKey(path, linesToRemove, hostname, key); err != nil {
					return fmt.Errorf("updating known_hosts for %s: %w", hostname, err)
				}
				fmt.Fprintf(os.Stderr, "NOTICE: updated known_hosts entry for %s (replaced mismatched key)\n", hostname)

				reloadChecker()
				return nil
			}

			return fmt.Errorf("host key verification failed for %s: %w", hostname, err)
		}

		return err
	}, nil
}

// removeAndReplaceHostKey removes lines matching lineNums or hostname/address from path,
// and appends a new entry for hostname with newKey.
func removeAndReplaceHostKey(path string, lineNums map[int]bool, hostname string, newKey ssh.PublicKey) error {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	var remainingLines []string
	curLine := 0

	hostOnly, port, splitErr := net.SplitHostPort(hostname)
	if splitErr != nil {
		hostOnly = hostname
		port = "22"
	}

	for scanner.Scan() {
		curLine++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// 1. If line number matched the exact Want line from knownhosts.New, drop it
		if lineNums[curLine] {
			continue
		}

		// 2. Also check if unhashed line starts with this hostname or IP
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "@") && !strings.HasPrefix(trimmed, "|") {
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				hosts := strings.Split(fields[0], ",")
				matched := false
				for _, h := range hosts {
					if h == hostname || (port == "22" && h == hostOnly) || h == "["+hostOnly+"]:"+port {
						matched = true
						break
					}
				}
				if matched {
					continue
				}
			}
		}

		remainingLines = append(remainingLines, line)
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// Append the new host key line
	newLine := knownhosts.Line([]string{hostname}, newKey)
	remainingLines = append(remainingLines, newLine)

	out := strings.Join(remainingLines, "\n") + "\n"
	tmp := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, []byte(out), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(path)
		return os.Rename(tmp, path)
	}
	return nil
}

func isHostKeyRecorded(path string, hostname string, remote net.Addr, key ssh.PublicKey) bool {
	cb, err := knownhosts.New(path)
	if err != nil {
		return false
	}
	if remote == nil {
		if host, port, err := net.SplitHostPort(hostname); err == nil {
			var p int
			_, _ = fmt.Sscanf(port, "%d", &p)
			remote = &net.TCPAddr{IP: net.ParseIP(host), Port: p}
		}
	}
	return cb(hostname, remote, key) == nil
}

func ensureFile(path string) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("creating known_hosts directory %q: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("creating known_hosts %q: %w", path, err)
	}
	return f.Close()
}

// AuthOptions contains authentication parameters for SSH connections.
type AuthOptions struct {
	Username string
	Password string
	KeyFile  string
}

// Connect opens a TCP connection and completes the SSH handshake, both
// bounded by opts.ConnectTimeout so an unreachable or black-holed device
// can never hang the run. It also respects ctx: cancelling ctx (e.g. on
// SIGINT/SIGTERM) aborts an in-progress dial immediately.
func Connect(ctx context.Context, address string, port int, username, password string, opts Options) (*ssh.Client, error) {
	return ConnectWithAuth(ctx, address, port, AuthOptions{Username: username, Password: password}, opts)
}

// ConnectWithAuth opens an SSH connection supporting passwords and private key files.
func ConnectWithAuth(ctx context.Context, address string, port int, auth AuthOptions, opts Options) (*ssh.Client, error) {
	if opts.HostKeyCallback == nil {
		return nil, ErrNoHostKeyCallback
	}

	addr := net.JoinHostPort(address, fmt.Sprintf("%d", port))

	dialer := newDialer(opts.ConnectTimeout, opts.TCPMSS)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	config, err := buildClientConfig(auth, opts.HostKeyCallback, opts)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("auth config: %w", err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	return ssh.NewClient(sshConn, chans, reqs), nil
}

// ConnectJumpHost opens an SSH connection to a bastion / jump host. The
// returned *ssh.Client can be shared across many concurrent ConnectViaJump
// calls because (*ssh.Client).Dial is safe for concurrent use.
// The caller is responsible for calling Close() on the returned client when
// the run is done.
func ConnectJumpHost(ctx context.Context, address string, port int, username, password string, opts Options) (*ssh.Client, error) {
	return ConnectJumpHostWithAuth(ctx, address, port, AuthOptions{Username: username, Password: password}, opts)
}

// ConnectJumpHostWithAuth opens an SSH connection to a bastion using AuthOptions.
func ConnectJumpHostWithAuth(ctx context.Context, address string, port int, auth AuthOptions, opts Options) (*ssh.Client, error) {
	hkCb := opts.JumpHostKeyCallback
	if hkCb == nil {
		hkCb = opts.HostKeyCallback
	}
	if hkCb == nil {
		return nil, ErrNoHostKeyCallback
	}

	addr := net.JoinHostPort(address, fmt.Sprintf("%d", port))
	dialer := newDialer(opts.ConnectTimeout, opts.TCPMSS)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial jump host: %w", err)
	}

	config, err := buildClientConfig(auth, hkCb, opts)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("jump host auth config: %w", err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("jump host handshake: %w", err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// ConnectViaJump opens a ProxyJump-style connection to targetAddress:targetPort
// by tunnelling through an already-established jump host client (bastion).
// The tunnel is a standard SSH "direct-tcpip" channel -- exactly what OpenSSH
// does with `ssh -J bastion target` and Paramiko does via a proxy channel.
//
// jumpClient is safe to share across goroutines; pass the same value for all
// devices that route through the same bastion.
func ConnectViaJump(ctx context.Context, jumpClient *ssh.Client, address string, port int, username, password string, opts Options) (*ssh.Client, error) {
	return ConnectViaJumpWithAuth(ctx, jumpClient, address, port, AuthOptions{Username: username, Password: password}, opts)
}

// ConnectViaJumpWithAuth opens a ProxyJump-style connection using AuthOptions.
func ConnectViaJumpWithAuth(ctx context.Context, jumpClient *ssh.Client, address string, port int, auth AuthOptions, opts Options) (*ssh.Client, error) {
	if opts.HostKeyCallback == nil {
		return nil, ErrNoHostKeyCallback
	}

	targetAddr := net.JoinHostPort(address, fmt.Sprintf("%d", port))

	// Open a direct-tcpip channel through the bastion. This is identical to
	// what `ssh -W` / ProxyJump does under the hood.
	tunnelConn, err := jumpClient.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("jump tunnel to %s: %w", targetAddr, err)
	}

	config, err := buildClientConfig(auth, opts.HostKeyCallback, opts)
	if err != nil {
		tunnelConn.Close()
		return nil, fmt.Errorf("auth config via jump: %w", err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(tunnelConn, targetAddr, config)
	if err != nil {
		tunnelConn.Close()
		return nil, fmt.Errorf("handshake via jump: %w", err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// CheckKeyPermissions inspects the given private key file's permissions. On Unix-like systems,
// it returns a warning string if group or other bits are set (permissions looser than 0600).
// Returns "" if the file has 0600 or stricter permissions, or if stat fails.
func CheckKeyPermissions(path string) string {
	if path == "" {
		return ""
	}
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	perm := fi.Mode().Perm()
	if perm&0o077 != 0 {
		return fmt.Sprintf("private key file %q has overly permissive permissions %#o (recommend 0600 or stricter)", path, perm)
	}
	return ""
}

// buildClientConfig is a shared helper so Connect, ConnectJumpHost, and
// ConnectViaJump all use the exact same auth methods and cipher suite.
func buildClientConfig(auth AuthOptions, hkCb ssh.HostKeyCallback, opts Options) (*ssh.ClientConfig, error) {
	var authMethods []ssh.AuthMethod

	if auth.KeyFile != "" {
		if warn := CheckKeyPermissions(auth.KeyFile); warn != "" {
			fmt.Fprintf(os.Stderr, "WARNING: %s\n", warn)
		}
		keyBytes, err := os.ReadFile(auth.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("reading SSH private key %q: %w", auth.KeyFile, err)
		}
		var signer ssh.Signer
		if auth.Password != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(auth.Password))
			if err != nil {
				// Fall back to unencrypted parse in case password was only device password
				signer, err = ssh.ParsePrivateKey(keyBytes)
			}
		} else {
			signer, err = ssh.ParsePrivateKey(keyBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("parsing SSH private key %q: %w", auth.KeyFile, err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if auth.Password != "" {
		authMethods = append(authMethods,
			ssh.Password(auth.Password),
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = auth.Password
				}
				return answers, nil
			}),
		)
	}

	if len(authMethods) == 0 {
		return nil, errors.New("no SSH authentication methods provided (specify password or key file)")
	}

	modernHostKeys := []string{
		ssh.KeyAlgoED25519,
		ssh.KeyAlgoECDSA256,
		ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoRSASHA256,
		ssh.KeyAlgoRSASHA512,
		ssh.KeyAlgoRSA,
	}
	legacyHostKeys := []string{
		ssh.KeyAlgoDSA, //nolint:staticcheck // SA1019: required for legacy network appliances
	}

	modernCiphers := []string{
		"aes128-gcm@openssh.com",
		"aes256-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
		"aes128-ctr",
		"aes192-ctr",
		"aes256-ctr",
	}
	legacyCiphers := []string{
		"aes128-cbc",
		"3des-cbc",
		"arcfour",
		"arcfour128",
		"arcfour256",
	}

	modernKex := []string{
		"curve25519-sha256",
		"curve25519-sha256@libssh.org",
		"ecdh-sha2-nistp256",
		"ecdh-sha2-nistp384",
		"ecdh-sha2-nistp521",
		"diffie-hellman-group14-sha256",
		"diffie-hellman-group16-sha512",
		"diffie-hellman-group-exchange-sha256",
	}
	legacyKex := []string{
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group-exchange-sha1",
		"diffie-hellman-group1-sha1",
	}

	hostKeys := modernHostKeys
	ciphers := modernCiphers
	kex := modernKex

	if opts.LegacyAlgorithms {
		hostKeys = append(slices.Clone(modernHostKeys), legacyHostKeys...)
		ciphers = append(slices.Clone(modernCiphers), legacyCiphers...)
		kex = append(slices.Clone(modernKex), legacyKex...)
	}

	return &ssh.ClientConfig{
		User:              auth.Username,
		Auth:              authMethods,
		HostKeyCallback:   hkCb,
		HostKeyAlgorithms: hostKeys,
		Timeout:           opts.ConnectTimeout,
		Config: ssh.Config{
			Ciphers:      ciphers,
			KeyExchanges: kex,
		},
	}, nil
}

// RunCommand executes a single command on a plain (non-interactive, no PTY)
// exec channel -- the default, simplest, and most broadly compatible mode.
// It is bounded by opts.CommandTimeout: if the device never responds, the
// session is closed and a timeout error is returned instead of hanging.
// If ctx is cancelled, the session is terminated immediately and ctx.Err() is returned.
func RunCommand(ctx context.Context, client *ssh.Client, command string, opts Options) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("opening session: %w", err)
	}
	defer session.Close()

	var stdout, stderr safeBuffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()

	select {
	case err := <-done:
		if err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg != "" {
				return stdout.String(), fmt.Errorf("command failed: %w (stderr: %s)", err, msg)
			}
			return stdout.String(), fmt.Errorf("command failed: %w", err)
		}
		return stdout.String(), nil

	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		session.Close()
		return "", ctx.Err()

	case <-time.After(opts.CommandTimeout):
		_ = session.Signal(ssh.SIGKILL)
		session.Close()
		return "", fmt.Errorf("command timed out after %s", opts.CommandTimeout)
	}
}

var reANSI = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

// AtPrompt reports whether the output currently ends at the device prompt.
func AtPrompt(out string, prompt *regexp.Regexp) bool {
	if prompt == nil {
		return false
	}
	out = reANSI.ReplaceAllString(out, "")
	last := out
	if i := strings.LastIndexAny(out, "\r\n"); i >= 0 {
		last = out[i+1:]
	}
	return prompt.MatchString(last)
}

// RunInteractive is for platforms whose SSH login does not accept a
// one-shot exec command (e.g. a restricted console menu). It allocates a
// PTY, starts a shell, feeds each command in sequence, and collects
// output until either the shell goes quiet for a short settle period or
// the hard opts.CommandTimeout is reached.
func RunInteractive(ctx context.Context, client *ssh.Client, commands []string, opts Options) (string, error) {
	return RunInteractivePrompt(ctx, client, commands, nil, opts)
}

// RunInteractivePrompt feeds commands to a PTY shell session. If prompt is non-nil,
// it waits for the prompt after login and after each command (answering paging markers
// on the way). If prompt is nil, it falls back to a quiet/settle period. The entire
// session is bounded by ctx and opts.CommandTimeout.
func RunInteractivePrompt(ctx context.Context, client *ssh.Client, commands []string, prompt *regexp.Regexp, opts Options) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("opening session: %w", err)
	}
	defer session.Close()

	if err := session.RequestPty("xterm", 200, 800, ssh.TerminalModes{
		ssh.ECHO: 0,
	}); err != nil {
		return "", fmt.Errorf("requesting pty: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("stdin pipe: %w", err)
	}

	var output safeBuffer
	session.Stdout = &output
	session.Stderr = &output

	if err := session.Shell(); err != nil {
		return "", fmt.Errorf("starting shell: %w", err)
	}

	deadline := time.Now().Add(opts.CommandTimeout)

	if prompt != nil {
		const poll = 40 * time.Millisecond
		waitPrompt := func(from int, what string) error {
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}
				cur := output.String()
				if len(cur) > from {
					tail := cur[from:]
					if AtPrompt(tail, prompt) {
						return nil
					}
					if pagerPromptRe.MatchString(tail) {
						if _, err := stdin.Write([]byte(" ")); err != nil {
							return fmt.Errorf("answering pager: %w", err)
						}
						from = len(cur)
						time.Sleep(poll)
						continue
					}
				}
				if time.Now().After(deadline) {
					return fmt.Errorf("timed out after %s waiting for the prompt %s", opts.CommandTimeout, what)
				}
				time.Sleep(poll)
			}
		}

		if err := waitPrompt(0, "after login"); err != nil {
			return reANSI.ReplaceAllString(output.String(), ""), err
		}
		for _, cmd := range commands {
			from := len(output.String())
			if _, err := fmt.Fprintf(stdin, "%s\n", cmd); err != nil {
				return reANSI.ReplaceAllString(output.String(), ""), fmt.Errorf("writing command: %w", err)
			}
			if err := waitPrompt(from, fmt.Sprintf("after %q", cmd)); err != nil {
				return reANSI.ReplaceAllString(output.String(), ""), err
			}
		}
		return reANSI.ReplaceAllString(output.String(), ""), nil
	}

	const settle = 1500 * time.Millisecond
	for _, cmd := range commands {
		if _, err := fmt.Fprintf(stdin, "%s\n", cmd); err != nil {
			return output.String(), fmt.Errorf("writing command to stdin: %w", err)
		}

		startLen := output.Len()
		lastSize := startLen
		lastChange := time.Now()

	waitLoop:
		for {
			select {
			case <-ctx.Done():
				return output.String(), ctx.Err()
			default:
			}
			if time.Now().After(deadline) {
				session.Close()
				return output.String(), fmt.Errorf("command timed out after %s", opts.CommandTimeout)
			}
			time.Sleep(150 * time.Millisecond)
			size := output.Len()
			switch {
			case size != lastSize:
				lastSize = size
				lastChange = time.Now()
			default:
				// Detect and answer interactive paging markers (--More--, ---(more)---, etc.)
				str := output.String()
				tail := str
				if len(tail) > 256 {
					tail = tail[len(tail)-256:]
				}
				if pagerPromptRe.MatchString(tail) {
					if _, err := stdin.Write([]byte(" ")); err == nil {
						lastChange = time.Now()
						time.Sleep(100 * time.Millisecond)
						continue
					}
				}

				if size > startLen && time.Since(lastChange) >= settle {
					break waitLoop // command output arrived and settled
				} else if size == startLen && time.Since(lastChange) >= settle*2 {
					// command produced no new output within quiet window (e.g. empty command or prompt wake)
					break waitLoop
				}
			}
		}
	}

	cleaned := pagerMarkerRe.ReplaceAllString(reANSI.ReplaceAllString(output.String(), ""), "")
	return cleaned, nil
}
