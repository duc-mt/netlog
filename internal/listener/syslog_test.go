package listener

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"netlog/internal/collector"
	"netlog/internal/inventory"
	"netlog/internal/pipeline"
)

var testNow = time.Date(2026, 10, 20, 9, 31, 5, 0, time.UTC)

// sinkRec collects what the listener delivers.
type sinkRec struct {
	mu      sync.Mutex
	entries []collector.LogEntry
	calls   int
}

func (r *sinkRec) sink(b []collector.LogEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.entries = append(r.entries, b...)
}

func (r *sinkRec) all() []collector.LogEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]collector.LogEntry(nil), r.entries...)
}

// wait polls until at least n entries arrived.
func (r *sinkRec) wait(t *testing.T, n int) []collector.LogEntry {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := r.all(); len(got) >= n {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d entries, have %d", n, len(r.all()))
	return nil
}

func newServer(t *testing.T, mod func(*Config)) (*Server, *sinkRec) {
	t.Helper()
	rec := &sinkRec{}
	cfg := Config{
		UDPAddr:       "127.0.0.1:0",
		TCPAddr:       "127.0.0.1:0",
		Devices:       []inventory.Device{{Hostname: "LEAF1", Address: "127.0.0.1", Vendor: "cumulus"}},
		Classifier:    pipeline.NewClassifier(time.UTC),
		Location:      time.UTC,
		Sink:          rec.sink,
		Now:           func() time.Time { return testNow },
		FlushInterval: 10 * time.Millisecond,
	}
	if mod != nil {
		mod(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Skipf("cannot bind loopback sockets here: %v", err)
	}
	t.Cleanup(srv.Stop)
	return srv, rec
}

func sendUDP(t *testing.T, srv *Server, msgs ...string) {
	t.Helper()
	ua, _ := srv.Addrs()
	c, err := net.Dial("udp", ua.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, m := range msgs {
		if _, err := c.Write([]byte(m)); err != nil {
			t.Fatal(err)
		}
	}
}

func dialTCP(t *testing.T, srv *Server) net.Conn {
	t.Helper()
	_, ta := srv.Addrs()
	c, err := net.Dial("tcp", ta.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// ---- pure helpers -------------------------------------------------------------------------

func TestSplitPRIAndNormalizeHeader(t *testing.T) {
	for _, tc := range []struct {
		in   string
		pri  int
		rest string
	}{
		{"<189>Oct 20 09:31:02 sw1 x", 189, "Oct 20 09:31:02 sw1 x"},
		{"<0>a", 0, "a"},
		{"<191>a", 191, "a"},
		{"<192>a", -1, "<192>a"},
		{"<>a", -1, "<>a"},
		{"<12a>a", -1, "<12a>a"},
		{"no pri", -1, "no pri"},
		{"", -1, ""},
	} {
		if pri, rest := splitPRI(tc.in); pri != tc.pri || rest != tc.rest {
			t.Errorf("splitPRI(%q) = %d,%q", tc.in, pri, rest)
		}
	}

	rcv := time.Date(2026, 10, 20, 9, 31, 5, 0, time.UTC)
	for _, tc := range []struct{ in, line, host string }{
		{"1 2026-10-20T09:31:02+07:00 leaf01 bgpd 987 ID47 - %ADJCHANGE: neighbor 10.0.0.2 Down", "2026-10-20T09:31:02+07:00 leaf01 bgpd[987]: %ADJCHANGE: neighbor 10.0.0.2 Down", "leaf01"},
		{"1 2026-10-20T09:31:02Z leaf01 sshd - - [exampleSDID@32473 iut=\"3\" eventSource=\"x\\]y\"] \ufeffAccepted publickey", "2026-10-20T09:31:02Z leaf01 sshd: Accepted publickey", "leaf01"},
		{"1 - - app - - - hello", "2026-10-20T09:31:05Z - app: hello", ""},
		{"1 2026-10-20T09:31:02Z h app 1 - -", "2026-10-20T09:31:02Z h app[1]: ", "h"},
		{"Oct 20 09:31:02 leaf01 switchd[1]: swp1: link down", "Oct 20 09:31:02 leaf01 switchd[1]: swp1: link down", "leaf01"},
		{"2026-10-20T09:31:02Z leaf01 x: y", "2026-10-20T09:31:02Z leaf01 x: y", "leaf01"},
		{"*Oct 20 09:31:02.123: %LINK-3-UPDOWN: x", "*Oct 20 09:31:02.123: %LINK-3-UPDOWN: x", ""},
		{"1 not-5424", "1 not-5424", ""},
	} {
		line, host := normalizeHeader(tc.in, rcv)
		if line != tc.line || host != tc.host {
			t.Errorf("normalizeHeader(%q)\n got %q,%q\nwant %q,%q", tc.in, line, host, tc.line, tc.host)
		}
	}
}

func TestSanitize(t *testing.T) {
	if got := sanitize("a\x00b\x1b[31mc\x7fd\te\xff\u0085f"); got != "a?b?[31mc?d\te??f" {
		t.Errorf("sanitize = %q", got)
	}
}

func TestReadFrame(t *testing.T) {
	br := func(s string) *bufio.Reader { return bufio.NewReaderSize(strings.NewReader(s), 16) }
	read := readFrame

	// Mixed framing on one stream, blank lines skipped, CRLF trimmed.
	r := br("<13>one\n\n\r\n<13>two\r\n11 <13>counted<13>after-count\n")
	for _, want := range []string{"<13>one", "<13>two", "<13>counted", "<13>after-count"} {
		got, trunc, err := read(r, 1000)
		if got != want || trunc || err != nil {
			t.Fatalf("frame = %q trunc=%v err=%v, want %q", got, trunc, err, want)
		}
	}
	if _, _, err := read(r, 1000); !errors.Is(err, io.EOF) {
		t.Errorf("end of stream: %v", err)
	}

	// An octet-counted frame may contain newlines.
	if got, _, _ := read(br("11 line1\nline2"), 1000); got != "line1\nline2" {
		t.Errorf("counted frame with newline = %q", got)
	}
	// Truncation keeps the head and consumes the whole frame.
	r = br("20 abcdefghijklmnopqrst5 next\n")
	if got, trunc, err := read(r, 6); got != "abcdef" || !trunc || err != nil {
		t.Errorf("truncated counted = %q %v %v", got, trunc, err)
	}
	if got, _, _ := read(r, 100); got != "next" {
		t.Errorf("frame after truncated one = %q", got)
	}
	// A long line is cut at max, fully consumed, and the next line is intact.
	r = br(strings.Repeat("x", 500) + "\nshort\n")
	if got, trunc, _ := read(r, 10); got != strings.Repeat("x", 10) || !trunc {
		t.Errorf("truncated line = %q %v", got, trunc)
	}
	if got, _, _ := read(r, 10); got != "short" {
		t.Errorf("line after truncated one = %q", got)
	}
	// An unterminated last line is returned together with EOF.
	if got, _, err := read(br("<13>tail"), 100); got != "<13>tail" || !errors.Is(err, io.EOF) {
		t.Errorf("tail = %q %v", got, err)
	}
	// A truncated counted frame, and an absurd count.
	if got, _, err := read(br("50 short"), 100); got != "short" || err == nil {
		t.Errorf("short counted frame = %q %v", got, err)
	}
	if _, _, err := read(br("9999999 x"), 100); err == nil || errors.Is(err, io.EOF) {
		t.Errorf("huge count must be an error, got %v", err)
	}
	// Things that only look like counts.
	if got, _, _ := read(br("0 zero count\n"), 100); got != "0 zero count" {
		t.Errorf("zero count = %q", got)
	}
	if got, _, _ := read(br("12345678 not a count\n"), 100); got != "" && !strings.HasPrefix(got, "12345678") {
		t.Errorf("long digits = %q", got)
	}
}

// ---- end to end ---------------------------------------------------------------------------

func TestUDPRFC3164AndRFC5424(t *testing.T) {
	srv, rec := newServer(t, nil)
	sendUDP(t, srv,
		"<30>Oct 20 09:31:02 leaf01 switchd[1234]: swp1: link down",
		"<14>1 2026-10-20T09:31:03+07:00 leaf01 bgpd 987 - - %ADJCHANGE: neighbor 10.0.0.2(swp1) in vrf default Down Peer closed the session",
	)
	got := rec.wait(t, 2)
	byEvent := map[string]collector.LogEntry{}
	for _, e := range got {
		byEvent[e.Event] = e
	}
	link, ok := byEvent[pipeline.EventLinkDown]
	if !ok {
		t.Fatalf("no LINK_DOWN in %+v", got)
	}
	if link.Hostname != "LEAF1" || link.IP != "127.0.0.1" || link.Vendor != "cumulus" || link.Category != "FAULT" ||
		link.Facility != "LINK" || link.Object == "" || !link.Timestamp.Equal(time.Date(2026, 10, 20, 9, 31, 2, 0, time.UTC)) {
		t.Errorf("link entry: %+v", link)
	}
	if !strings.HasPrefix(link.Raw, "Oct 20 09:31:02 leaf01 switchd") || strings.HasPrefix(link.Raw, "<") {
		t.Errorf("Raw should be the message without its PRI header: %q", link.Raw)
	}
	bgp, ok := byEvent[pipeline.EventBGPPeerDown]
	if !ok || bgp.Hostname != "LEAF1" || bgp.Facility != "BGP" || !bgp.Timestamp.Equal(time.Date(2026, 10, 20, 2, 31, 3, 0, time.UTC)) {
		t.Errorf("bgp entry: %+v", bgp)
	}
	if s := srv.Stats(); s.Received != 2 || s.Unknown != 0 || s.Dropped != 0 {
		t.Errorf("stats %+v", s)
	}
}

func TestTCPBothFramingsAndManyClients(t *testing.T) {
	srv, rec := newServer(t, nil)
	msg := "<30>Oct 20 09:31:02 leaf01 switchd[1]: swp%d: link down"

	// One connection, both framings.
	c := dialTCP(t, srv)
	counted := fmt.Sprintf(msg, 1)
	fmt.Fprintf(c, "%d %s", len(counted), counted)
	fmt.Fprintf(c, "%s\n", fmt.Sprintf(msg, 2))
	rec.wait(t, 2)

	// 20 clients x 25 messages, each connection from the same device address.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cc := dialTCP(t, srv)
			w := bufio.NewWriter(cc)
			for j := 0; j < 25; j++ {
				fmt.Fprintf(w, "%s\n", fmt.Sprintf(msg, 10+i*100+j))
			}
			w.Flush()
		}(i)
	}
	wg.Wait()
	got := rec.wait(t, 2+20*25)
	seen := map[string]bool{}
	for _, e := range got {
		seen[e.Object] = true
	}
	if len(seen) != 2+20*25 {
		t.Errorf("%d distinct interfaces delivered, want %d", len(seen), 2+20*25)
	}
	if srv.Stats().Conns != 21 {
		t.Errorf("conns = %d", srv.Stats().Conns)
	}
}

func TestUnknownSourcesAreDroppedUnlessAccepted(t *testing.T) {
	other := []inventory.Device{{Hostname: "ELSEWHERE", Address: "192.0.2.7", Vendor: "cumulus"}}
	msg := "<30>Oct 20 09:31:02 leaf01 switchd[1]: swp1: link down"

	srv, rec := newServer(t, func(c *Config) { c.Devices = other })
	sendUDP(t, srv, msg)
	c := dialTCP(t, srv) // refused at accept
	fmt.Fprintf(c, "%s\n", msg)
	time.Sleep(150 * time.Millisecond)
	if n := len(rec.all()); n != 0 {
		t.Fatalf("unknown source stored %d entries", n)
	}
	if s := srv.Stats(); s.Unknown < 2 {
		t.Errorf("Unknown = %d", s.Unknown)
	}

	srv2, rec2 := newServer(t, func(c *Config) { c.Devices = other; c.AcceptUnknown = true })
	sendUDP(t, srv2, msg, "<30>Oct 20 09:31:03 bad host!;rm: x")
	got := rec2.wait(t, 1)
	if got[0].Hostname != "leaf01" || got[0].Vendor != "generic" || got[0].IP != "127.0.0.1" {
		t.Errorf("accepted unknown source: %+v", got[0])
	}
	for _, e := range rec2.wait(t, 2) { // a hostile hostname never becomes the device name
		if strings.ContainsAny(e.Hostname, " !;") {
			t.Errorf("unsafe hostname %q", e.Hostname)
		}
	}
}

func TestUnparseableMessagesAreKeptAtReceiveTime(t *testing.T) {
	srv, rec := newServer(t, nil)
	sendUDP(t, srv, "<189>%LINK-3-UPDOWN: Interface GigabitEthernet1/0/1, changed state to down")
	e := rec.wait(t, 1)[0]
	if e.Hostname != "LEAF1" || !e.Timestamp.Equal(testNow) || e.Event != pipeline.EventLinkDown || e.Object == "" {
		t.Errorf("entry: %+v", e)
	}
	if srv.Stats().Unparsed != 1 {
		t.Errorf("stats %+v", srv.Stats())
	}
}

func TestOversizeAndHostileMessages(t *testing.T) {
	srv, rec := newServer(t, func(c *Config) { c.MaxMessage = 200 })
	huge := "<30>Oct 20 09:31:02 leaf01 switchd[1]: swp1: link down " + strings.Repeat("A", 5000)
	sendUDP(t, srv, huge, "<30>Oct 20 09:31:03 leaf01 switchd[1]: swp2: link down \x1b[2J\x00evil")
	c := dialTCP(t, srv)
	fmt.Fprintf(c, "%s\n", huge)
	fmt.Fprintf(c, "9999999 never read\n") // absurd count: the connection is closed
	got := rec.wait(t, 3)
	for _, e := range got {
		if len(e.Raw) > 200 {
			t.Errorf("Raw is %d bytes, want <= 200", len(e.Raw))
		}
		if strings.ContainsAny(e.Raw, "\x1b\x00") {
			t.Errorf("control characters stored: %q", e.Raw)
		}
	}
	if srv.Stats().Truncated < 2 {
		t.Errorf("Truncated = %d", srv.Stats().Truncated)
	}
	// The abusive connection was dropped.
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("connection with a 9999999-byte frame should be closed")
	}
}

func TestUDPDropsAreCountedWhenQueueIsFull(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	srv, rec := newServer(t, func(c *Config) {
		c.QueueSize, c.BatchSize = 1, 1
		c.Sink = func(b []collector.LogEntry) { <-release }
	})
	_ = rec
	msgs := make([]string, 300)
	for i := range msgs {
		msgs[i] = fmt.Sprintf("<30>Oct 20 09:31:02 leaf01 switchd[1]: swp%d: link down", i)
	}
	sendUDP(t, srv, msgs...)
	deadline := time.Now().Add(5 * time.Second)
	for srv.Stats().Dropped == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.Stats().Dropped == 0 {
		t.Error("a full queue must drop and count UDP messages")
	}
	once.Do(func() { close(release) })
}

func TestStopFlushesPendingEntriesAndClosesConnections(t *testing.T) {
	srv, rec := newServer(t, func(c *Config) { c.FlushInterval = time.Hour; c.BatchSize = 1000 })
	c := dialTCP(t, srv) // idle connection that Stop must close
	fmt.Fprintf(c, "<30>Oct 20 09:31:02 leaf01 switchd[1]: swp1: link down\n")
	sendUDP(t, srv, "<30>Oct 20 09:31:03 leaf01 switchd[1]: swp2: link down")
	deadline := time.Now().Add(3 * time.Second)
	for srv.Stats().Received < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := len(rec.all()); n != 0 {
		t.Fatalf("flush interval is an hour but %d entries were delivered early", n)
	}

	done := make(chan struct{})
	go func() { srv.Stop(); srv.Stop(); close(done) }() // idempotent
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not return")
	}
	if n := len(rec.all()); n != 2 {
		t.Errorf("Stop delivered %d entries, want the 2 pending ones", n)
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("idle connection survived Stop")
	}
	if s := srv.Stats(); s.Stored != 2 {
		t.Errorf("stats %+v", s)
	}
}

func TestSinkPanicLosesOnlyThatBatch(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	var got []collector.LogEntry
	srv, _ := newServer(t, func(c *Config) {
		c.BatchSize = 1
		c.Sink = func(b []collector.LogEntry) {
			mu.Lock()
			defer mu.Unlock()
			calls++
			if calls == 1 {
				panic("boom")
			}
			got = append(got, b...)
		}
	})
	sendUDP(t, srv, "<30>Oct 20 09:31:02 leaf01 switchd[1]: swp1: link down")
	time.Sleep(100 * time.Millisecond)
	sendUDP(t, srv, "<30>Oct 20 09:31:03 leaf01 switchd[1]: swp2: link down")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("listener stopped delivering after a sink panic")
}

func TestConnectionLimit(t *testing.T) {
	srv, rec := newServer(t, func(c *Config) { c.MaxConns = 1 })
	first := dialTCP(t, srv)
	fmt.Fprintf(first, "<30>Oct 20 09:31:02 leaf01 switchd[1]: swp1: link down\n")
	rec.wait(t, 1)
	second := dialTCP(t, srv)
	second.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Error("second connection should be closed at the limit")
	}
	if srv.Stats().Refused != 1 {
		t.Errorf("stats %+v", srv.Stats())
	}
	// The first connection still works.
	fmt.Fprintf(first, "<30>Oct 20 09:31:03 leaf01 switchd[1]: swp2: link down\n")
	rec.wait(t, 2)
}

func TestIdleConnectionsTimeOut(t *testing.T) {
	srv, _ := newServer(t, func(c *Config) { c.IdleTimeout = 100 * time.Millisecond })
	c := dialTCP(t, srv)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Errorf("idle connection should be closed by the server, got %v", err)
	}
}

// ---- lifecycle and configuration ------------------------------------------------------------

func TestConfigValidationAndBindErrors(t *testing.T) {
	cls := pipeline.NewClassifier(time.UTC)
	sink := func([]collector.LogEntry) {}
	for name, cfg := range map[string]Config{
		"no protocol":   {Classifier: cls, Sink: sink},
		"no classifier": {UDPAddr: "127.0.0.1:0", Sink: sink},
		"no sink":       {UDPAddr: "127.0.0.1:0", Classifier: cls},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}

	srv, _ := newServer(t, nil)
	_, ta := srv.Addrs()
	// TCP port taken: Start fails, releases the UDP socket it already bound,
	// and Stop must not hang.
	again, err := New(Config{UDPAddr: "127.0.0.1:0", TCPAddr: ta.String(), Classifier: cls, Sink: sink})
	if err != nil {
		t.Fatal(err)
	}
	err = again.Start()
	if err == nil || !strings.Contains(err.Error(), "TCP "+ta.String()) || !strings.Contains(err.Error(), "already in use") {
		t.Errorf("bind error: %v", err)
	}
	done := make(chan struct{})
	go func() { again.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop hung after a failed Start")
	}
	if err := srv.Start(); err == nil {
		t.Error("starting twice must fail")
	}
	idle, _ := New(Config{UDPAddr: "127.0.0.1:0", Classifier: cls, Sink: sink})
	idle.Stop() // never started: no-op
}

func TestDevicesResolvedByAddress(t *testing.T) {
	srv, err := New(Config{
		UDPAddr:    "127.0.0.1:0",
		Classifier: pipeline.NewClassifier(time.UTC),
		Sink:       func([]collector.LogEntry) {},
		Devices: []inventory.Device{
			{Hostname: "A", Address: "10.0.0.1"},
			{Hostname: "B", Address: "10.0.0.1"}, // duplicate address: first wins
			{Hostname: "V6", Address: "2001:db8::1"},
			{Hostname: "LO", Address: "localhost"},
			{Hostname: "BAD", Address: "no-such-host.invalid"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d := srv.byIP[mustAddr("10.0.0.1")]; d.Hostname != "A" {
		t.Errorf("10.0.0.1 -> %q", d.Hostname)
	}
	if d := srv.byIP[mustAddr("2001:db8::1")]; d.Hostname != "V6" {
		t.Errorf("v6 -> %q", d.Hostname)
	}
	if _, ok := srv.byIP[mustAddr("127.0.0.1")]; !ok {
		t.Log("localhost did not resolve to 127.0.0.1 here (resolver-dependent)")
	}
	for a, d := range srv.byIP {
		if d.Hostname == "BAD" {
			t.Errorf("unresolvable device mapped from %v", a)
		}
	}
}

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}
