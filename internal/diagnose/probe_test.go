package diagnose

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

// fakeICMP scripts the echo results: one entry per call, in order.
type fakeICMP struct {
	results []fakeEcho
	calls   []fakeCall
}
type fakeEcho struct {
	rtt time.Duration
	err error
}
type fakeCall struct {
	seq, payload int
	df           bool
}

func (f *fakeICMP) Echo(_ context.Context, seq, payload int, df bool, _ time.Duration) (time.Duration, error) {
	f.calls = append(f.calls, fakeCall{seq, payload, df})
	r := f.results[len(f.calls)-1]
	return r.rtt, r.err
}
func (f *fakeICMP) Close() {}

// denyICMP is what a host without ping-socket permission returns.
func denyICMP(net.IP) (icmpSession, error) { return nil, errors.New("permission denied") }

func listener(t *testing.T) (host string, port int, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, func() { ln.Close() }
}

var statRe = regexp.MustCompile(`\d+\.\dms / \d+\.\dms / \d+\.\dms`)

func notes(s Section) string { return strings.Join(s.Notes, "\n") }

func TestRunProbeTCPLoopback(t *testing.T) {
	host, port, stop := listener(t)
	defer stop()

	s := RunProbe(context.Background(), host, port, ProbeOptions{openICMP: denyICMP})
	if s.Name != SecProbe || s.Status != StatusOK {
		t.Fatalf("status %s, notes %q, error %q", s.Status, s.Notes, s.Error)
	}
	n := notes(s)
	if !strings.Contains(n, "(3/3 connected)") || !statRe.MatchString(n) {
		t.Errorf("TCP stats missing: %q", n)
	}
	if !strings.Contains(n, "ICMP echo not used: unprivileged ICMP is not permitted") || !strings.Contains(n, "TCP probe only") {
		t.Errorf("ICMP fallback not explained: %q", n)
	}
	if !strings.Contains(n, "Route: via lo") {
		t.Errorf("route/MTU line missing: %q", n)
	}
	if s.Metrics["tcp_loss_pct"] != 0 || s.Metrics["tcp_avg_ms"] <= 0 || s.Metrics["local_mtu"] <= 0 {
		t.Errorf("metrics: %v", s.Metrics)
	}
	if s.Metrics["tcp_min_ms"] > s.Metrics["tcp_avg_ms"] || s.Metrics["tcp_avg_ms"] > s.Metrics["tcp_max_ms"] {
		t.Errorf("min/avg/max out of order: %v", s.Metrics)
	}
}

func TestRunProbeRefusedAndUnreachablePorts(t *testing.T) {
	host, port, stop := listener(t)
	stop() // nothing listens any more: connection refused
	time.Sleep(20 * time.Millisecond)
	s := RunProbe(context.Background(), host, port, ProbeOptions{openICMP: denyICMP})
	if s.Status != StatusError || !strings.Contains(notes(s), "connection refused") {
		t.Errorf("refused: status %s notes %q", s.Status, s.Notes)
	}
	if s.Metrics["tcp_loss_pct"] != 100 {
		t.Errorf("loss = %v", s.Metrics["tcp_loss_pct"])
	}
}

func TestProbeIsStrictlyBounded(t *testing.T) {
	// A dial that never completes must be cut at the probe timeout, and a
	// caller asking for more than 2s must still get 2s.
	var deadlines []time.Duration
	hang := func(ctx context.Context, _, _ string) (net.Conn, error) {
		dl, ok := ctx.Deadline()
		if !ok {
			t.Error("probe dial has no deadline")
		}
		deadlines = append(deadlines, time.Until(dl))
		<-ctx.Done()
		return nil, ctx.Err()
	}
	t0 := time.Now()
	s := RunProbe(context.Background(), "127.0.0.1", 22, ProbeOptions{Count: 2, Timeout: 80 * time.Millisecond, dial: hang, openICMP: denyICMP})
	if el := time.Since(t0); el > 2*time.Second {
		t.Fatalf("hung dials took %v", el)
	}
	if s.Status != StatusError || len(deadlines) != 2 {
		t.Fatalf("status %s, %d dials", s.Status, len(deadlines))
	}

	deadlines = nil
	ctx, cancel := context.WithCancel(context.Background())
	hangOnce := func(c context.Context, n, a string) (net.Conn, error) {
		cancel() // cancel after the first dial starts: the rest must not run
		return hang(c, n, a)
	}
	RunProbe(ctx, "127.0.0.1", 22, ProbeOptions{Count: 3, Timeout: 10 * time.Second, dial: hangOnce, openICMP: denyICMP})
	if len(deadlines) != 1 || deadlines[0] > ProbeTimeout {
		t.Errorf("a 10s timeout must be capped at %v and a cancelled run must stop: %v", ProbeTimeout, deadlines)
	}
}

func TestProbePartialLossWarns(t *testing.T) {
	calls := 0
	flaky := func(ctx context.Context, n, a string) (net.Conn, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("i/o timeout")
		}
		c, _ := net.Pipe()
		return c, nil
	}
	s := RunProbe(context.Background(), "127.0.0.1", 22, ProbeOptions{dial: flaky, openICMP: denyICMP})
	if s.Status != StatusWarn || !strings.Contains(notes(s), "1 of 3 connection attempts failed") {
		t.Errorf("status %s notes %q", s.Status, s.Notes)
	}
	if got := s.Metrics["tcp_loss_pct"]; got < 33 || got > 34 {
		t.Errorf("loss = %v", got)
	}
}

func TestProbeDefaultsAndBadHost(t *testing.T) {
	var ports []string
	rec := func(ctx context.Context, n, a string) (net.Conn, error) {
		ports = append(ports, a)
		c, _ := net.Pipe()
		return c, nil
	}
	RunProbe(context.Background(), "127.0.0.1", 0, ProbeOptions{dial: rec, openICMP: denyICMP})
	if len(ports) != 3 || ports[0] != "127.0.0.1:22" {
		t.Errorf("want 3 probes of port 22, got %v", ports)
	}
	s := RunProbe(context.Background(), "no-such-host.invalid", 22, ProbeOptions{dial: rec, openICMP: denyICMP})
	if s.Status != StatusError || !strings.Contains(s.Error, "cannot resolve") {
		t.Errorf("unresolvable host: %+v", s)
	}
}

func TestProbeICMPAndMTU(t *testing.T) {
	ip := net.ParseIP("192.0.2.10")
	ok := func(ms int) fakeEcho { return fakeEcho{rtt: time.Duration(ms) * time.Millisecond} }

	t.Run("all replies and full-size packet crosses", func(t *testing.T) {
		f := &fakeICMP{results: []fakeEcho{ok(1), ok(2), ok(3), ok(4)}}
		r := probeICMP(context.Background(), func(net.IP) (icmpSession, error) { return f, nil }, ip, 3, time.Second, 1500)
		if len(r.rtts) != 3 || !r.mtuOK || r.mtuPayload != 1472 {
			t.Fatalf("%+v", r)
		}
		// Three plain echoes, then one don't-fragment echo with a payload that makes a 1500-byte packet.
		if len(f.calls) != 4 || f.calls[0].df || !f.calls[3].df || f.calls[3].payload != 1472 {
			t.Errorf("calls: %+v", f.calls)
		}
	})
	t.Run("full-size packet lost: warn", func(t *testing.T) {
		f := &fakeICMP{results: []fakeEcho{ok(1), ok(2), ok(3), {err: errEchoTooBig}}}
		r := probeICMP(context.Background(), func(net.IP) (icmpSession, error) { return f, nil }, ip, 3, time.Second, 1500)
		var s Section
		s.Metrics = map[string]float64{}
		report(&s, ip, 22, 3, tcpResult{rtts: []time.Duration{time.Millisecond}, sent: 1}, r, routeInfo{Interface: "eth0", Source: net.ParseIP("192.0.2.1"), MTU: 1500}, nil)
		if s.Status != StatusWarn || !strings.Contains(notes(s), "path MTU may be below the local MTU of 1500") {
			t.Errorf("status %s notes %q", s.Status, s.Notes)
		}
	})
	t.Run("no replies: MTU not attempted", func(t *testing.T) {
		f := &fakeICMP{results: []fakeEcho{{err: errEchoTimeout}, {err: errEchoTimeout}, {err: errEchoTimeout}}}
		r := probeICMP(context.Background(), func(net.IP) (icmpSession, error) { return f, nil }, ip, 3, time.Second, 1500)
		if r.mtuPayload != 0 || len(f.calls) != 3 {
			t.Errorf("%+v calls %v", r, f.calls)
		}
		var s Section
		s.Metrics = map[string]float64{}
		report(&s, ip, 22, 3, tcpResult{rtts: []time.Duration{time.Millisecond}, sent: 1}, r, routeInfo{Interface: "eth0", MTU: 1500}, nil)
		if s.Status != StatusOK || !strings.Contains(notes(s), "no replies") || !strings.Contains(notes(s), "not verified") {
			t.Errorf("ICMP being filtered must not fail the probe: %s %q", s.Status, s.Notes)
		}
	})
	t.Run("loopback and tiny MTU skip the MTU echo", func(t *testing.T) {
		f := &fakeICMP{results: []fakeEcho{ok(1), ok(1), ok(1), ok(1)}}
		open := func(net.IP) (icmpSession, error) { return f, nil }
		if r := probeICMP(context.Background(), open, net.ParseIP("127.0.0.1"), 3, time.Second, 65536); r.mtuPayload != 0 {
			t.Errorf("loopback: %+v", r)
		}
		f.calls = nil
		if r := probeICMP(context.Background(), open, ip, 3, time.Second, 20); r.mtuPayload != 0 {
			t.Errorf("tiny MTU: %+v", r)
		}
	})
	t.Run("jumbo MTU is capped at the largest ICMP payload", func(t *testing.T) {
		f := &fakeICMP{results: []fakeEcho{ok(1), ok(1), ok(1), ok(1)}}
		r := probeICMP(context.Background(), func(net.IP) (icmpSession, error) { return f, nil }, ip, 3, time.Second, 70000)
		if r.mtuPayload != maxICMPPayload {
			t.Errorf("payload = %d", r.mtuPayload)
		}
	})
	t.Run("session cannot be opened", func(t *testing.T) {
		r := probeICMP(context.Background(), func(net.IP) (icmpSession, error) { return nil, errICMPv4Only }, ip, 3, time.Second, 1500)
		if !strings.Contains(r.unavailable, "IPv4 only") || r.sent != 0 {
			t.Errorf("%+v", r)
		}
	})
}

func TestNoRouteIsAnError(t *testing.T) {
	var s Section
	s.Metrics = map[string]float64{}
	report(&s, net.ParseIP("192.0.2.1"), 22, 3, tcpResult{sent: 3, failed: 3, lastErr: errors.New("x")}, icmpResult{unavailable: "n/a"}, routeInfo{}, errors.New("network is unreachable"))
	if s.Status != StatusError || !strings.Contains(notes(s), "no route to 192.0.2.1") {
		t.Errorf("%s %q", s.Status, s.Notes)
	}
}

func TestLocalRouteLoopback(t *testing.T) {
	r, err := localRoute(net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Skipf("no loopback route: %v", err)
	}
	if r.Interface == "" || r.MTU <= 0 || !r.Source.IsLoopback() {
		t.Errorf("%+v", r)
	}
}

func TestStatLine(t *testing.T) {
	got, m := statLine([]time.Duration{3400 * time.Microsecond, 2100 * time.Microsecond, 2800 * time.Microsecond})
	if got != "2.1ms / 2.8ms / 3.4ms" {
		t.Errorf("statLine = %q", got)
	}
	if m["min"] != 2.1 || m["max"] != 3.4 {
		t.Errorf("%v", m)
	}
	if got, m := statLine(nil); got != "" || m != nil {
		t.Errorf("empty: %q %v", got, m)
	}
}

// ---- ICMP packet helpers ----------------------------------------------------------------

func TestEchoRequestIsAValidICMPPacket(t *testing.T) {
	for _, payload := range []int{0, 1, 32, 1472, 65507} {
		p := buildEchoRequest(0x1234, payload)
		if len(p) != 8+payload || p[0] != 8 || p[1] != 0 || p[6] != 0x12 || p[7] != 0x34 {
			t.Fatalf("payload %d: bad header %v", payload, p[:8])
		}
		if checksum(p) != 0 { // a correct packet checksums to zero
			t.Errorf("payload %d: checksum does not verify", payload)
		}
	}
	// RFC 1071 example data.
	if got := checksum([]byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}); got != 0x220d {
		t.Errorf("checksum = %#x, want 0x220d", got)
	}
}

func TestIsEchoReply(t *testing.T) {
	reply := buildEchoRequest(7, 16)
	reply[0] = icmpEchoReply
	if !isEchoReply(reply, 7) || isEchoReply(reply, 8) {
		t.Error("sequence matching wrong")
	}
	withIP := append([]byte{0x45, 0, 0, 0, 0, 0, 0, 0, 64, 1, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1}, reply...)
	if !isEchoReply(withIP, 7) {
		t.Error("reply with IPv4 header not accepted")
	}
	req := buildEchoRequest(7, 16)
	for name, b := range map[string][]byte{"request": req, "empty": nil, "short": {0, 0, 0}, "ttl exceeded": {11, 0, 0, 0, 0, 0, 0, 7}, "bad code": {0, 3, 0, 0, 0, 0, 0, 7}} {
		if isEchoReply(b, 7) {
			t.Errorf("%s accepted as a reply", name)
		}
	}
	badIHL := append([]byte{0x4f, 0, 0, 0, 0, 0, 0, 0, 64, 1}, make([]byte, 10)...)
	if isEchoReply(badIHL, 7) {
		t.Error("truncated IP header accepted")
	}
}

// The real unprivileged ICMP socket, where the host allows one (Linux with
// net.ipv4.ping_group_range covering this group); skipped elsewhere.
func TestRealICMPSessionLoopback(t *testing.T) {
	sess, err := openICMPSession(net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Skipf("unprivileged ICMP not available here: %v", err)
	}
	defer sess.Close()
	rtt, err := sess.Echo(context.Background(), 1, 32, false, ProbeTimeout)
	if err != nil || rtt <= 0 {
		t.Fatalf("echo to loopback: rtt=%v err=%v", rtt, err)
	}
	// A cancelled context stops the wait at once.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := sess.Echo(ctx, 2, 32, false, ProbeTimeout); err == nil {
		t.Error("cancelled echo succeeded")
	}
	// A don't-fragment packet larger than the loopback MTU is refused locally.
	if _, err := sess.Echo(context.Background(), 3, 70000, true, ProbeTimeout); err == nil {
		t.Error("oversized DF echo should fail")
	}
	if _, err := openICMPSession(net.ParseIP("::1")); !errors.Is(err, errICMPv4Only) {
		t.Errorf("IPv6 destination: %v", err)
	}
}
