// ==============================================================================
// Package diagnose: active path and reachability probe.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-27
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Notes:         Go package implementation
// ==============================================================================
// The probe complements the SSH checks with what the device cannot tell about
// itself: whether this machine can reach it at all, how fast, and whether a
// full-size packet fits the path. It sends nothing to the device beyond TCP
// connection attempts to its management port and ICMP echo requests, and runs
// before the SSH connection so it still reports when SSH cannot connect.
//
//   - TCP connect probe: ProbeCount connection attempts to the SSH port,
//     timed (min / avg / max). A refused connection is a reply (the host is up,
//     the port is closed) and is reported as such.
//   - ICMP echo (Linux): unprivileged ping socket (SOCK_DGRAM, IPPROTO_ICMP);
//     no raw sockets and no root, but the kernel only allows it for groups in
//     net.ipv4.ping_group_range. When that is not permitted, or on another
//     platform, the TCP numbers stand alone and the section says why.
//   - Local route and MTU: the interface and source address the kernel picks
//     for the destination (a UDP "connect", nothing is sent) and its MTU. With
//     ICMP available, a don't-fragment echo of exactly that MTU then checks
//     the path end to end.
//
// Every probe is bounded by ProbeTimeout (2 seconds), name resolution
// included, so a dead host cannot make the command hang.
//
// Not implemented: hop-by-hop path tracing. It needs raw sockets or ICMP
// error queues that the unprivileged approach above deliberately avoids.
package diagnose

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Probe limits.
const (
	SecProbe     = "Path & Reachability Probe"
	ProbeCount   = 3
	ProbeTimeout = 2 * time.Second // per probe, a cap not a default

	defaultSSHPort = 22
	maxProbeCount  = 10
	icmpHeaderLen  = 28 // 20 byte IPv4 header + 8 byte ICMP header
	maxICMPPayload = 65507
)

// ProbeOptions configures RunProbe.
type ProbeOptions struct {
	// Count is the number of TCP connects and ICMP echoes (default ProbeCount).
	Count int
	// Timeout bounds each probe (default and cap: ProbeTimeout).
	Timeout time.Duration

	// Test hooks. Nil means the real network.
	dial     func(ctx context.Context, network, address string) (net.Conn, error)
	openICMP func(ip net.IP) (icmpSession, error)
}

// icmpSession sends echo requests to one destination.
type icmpSession interface {
	// Echo sends one request with a payload of the given size and waits for
	// the matching reply. With df set the packet must not be fragmented.
	Echo(ctx context.Context, seq, payload int, df bool, timeout time.Duration) (time.Duration, error)
	Close()
}

// Echo errors.
var (
	errEchoTimeout = errors.New("timeout")
	errEchoTooBig  = errors.New("message too long for the path (don't-fragment)")
	errICMPv4Only  = errors.New("ICMP probing supports IPv4 only")
)

// RunProbe probes host:port and returns the "Path & Reachability Probe"
// section. It never returns an error: problems are part of the section.
func RunProbe(ctx context.Context, host string, port int, o ProbeOptions) Section {
	if port <= 0 {
		port = defaultSSHPort
	}
	timeout := o.Timeout
	if timeout <= 0 || timeout > ProbeTimeout {
		timeout = ProbeTimeout
	}
	count := o.Count
	if count <= 0 || count > maxProbeCount {
		count = ProbeCount
	}
	s := Section{
		Name:    SecProbe,
		Command: fmt.Sprintf("local probe: tcp connect x%d, icmp echo, route/MTU (no device command)", count),
		Metrics: map[string]float64{},
	}

	ip, err := resolveHost(ctx, host, timeout)
	if err != nil {
		s.Status, s.Error = StatusError, fmt.Sprintf("cannot resolve %q: %v", host, err)
		return s
	}

	var (
		wg       sync.WaitGroup
		tcp      tcpResult
		icmp     icmpResult
		route    routeInfo
		routeErr error
	)
	route, routeErr = localRoute(ip)
	wg.Add(2)
	go func() { defer wg.Done(); tcp = probeTCP(ctx, o.dial, ip, port, count, timeout) }()
	go func() { defer wg.Done(); icmp = probeICMP(ctx, o.openICMP, ip, count, timeout, route.MTU) }()
	wg.Wait()

	report(&s, ip, port, count, tcp, icmp, route, routeErr)
	return s
}

// resolveHost returns the address to probe, preferring IPv4.
func resolveHost(ctx context.Context, host string, timeout time.Duration) (net.IP, error) {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip, nil
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(rctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, errors.New("no addresses")
	}
	for _, a := range addrs {
		if a.IP.To4() != nil {
			return a.IP, nil
		}
	}
	return addrs[0].IP, nil
}

// ---- TCP ---------------------------------------------------------------------------------

type tcpResult struct {
	rtts    []time.Duration // successful connects
	refused int             // connection refused: the host answered
	failed  int             // timeouts and other errors
	lastErr error
	sent    int
}

func probeTCP(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), ip net.IP, port, count int, timeout time.Duration) tcpResult {
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	var r tcpResult
	for i := 0; i < count && ctx.Err() == nil; i++ {
		pctx, cancel := context.WithTimeout(ctx, timeout)
		t0 := time.Now()
		c, err := dial(pctx, "tcp", addr)
		d := time.Since(t0)
		cancel()
		r.sent++
		switch {
		case err == nil:
			_ = c.Close()
			r.rtts = append(r.rtts, d)
		case isRefused(err):
			r.refused++
			r.lastErr = err
		default:
			r.failed++
			r.lastErr = err
		}
	}
	return r
}

func isRefused(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "connection refused")
}

// ---- ICMP --------------------------------------------------------------------------------

type icmpResult struct {
	unavailable string          // why ICMP could not be used ("" = it was)
	rtts        []time.Duration // successful echoes
	sent        int
	mtuPayload  int    // payload of the don't-fragment echo (0 = not attempted)
	mtuOK       bool   // that echo was answered
	mtuErr      string // why it was not
}

func probeICMP(ctx context.Context, open func(net.IP) (icmpSession, error), ip net.IP, count int, timeout time.Duration, localMTU int) icmpResult {
	var r icmpResult
	if open == nil {
		open = openICMPSession
	}
	sess, err := open(ip)
	if err != nil {
		r.unavailable = explainICMPError(err)
		return r
	}
	defer sess.Close()

	for i := 0; i < count && ctx.Err() == nil; i++ {
		r.sent++
		if d, err := sess.Echo(ctx, i+1, 32, false, timeout); err == nil {
			r.rtts = append(r.rtts, d)
		}
	}
	// The MTU check only means something when small packets get through, and
	// is skipped for loopback (its MTU of 65536 says nothing about a path).
	if len(r.rtts) == 0 || ctx.Err() != nil || ip.IsLoopback() || localMTU <= icmpHeaderLen {
		return r
	}
	payload := localMTU - icmpHeaderLen
	if payload > maxICMPPayload {
		payload = maxICMPPayload
	}
	r.mtuPayload = payload
	if _, err := sess.Echo(ctx, count+1, payload, true, timeout); err == nil {
		r.mtuOK = true
	} else {
		r.mtuErr = err.Error()
	}
	return r
}

func explainICMPError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "permission denied") || strings.Contains(msg, "operation not permitted"):
		return "unprivileged ICMP is not permitted for this user (net.ipv4.ping_group_range)"
	case errors.Is(err, errICMPv4Only):
		return err.Error()
	}
	return msg
}

// ---- local route and MTU -----------------------------------------------------------------

type routeInfo struct {
	Interface string
	Source    net.IP
	MTU       int
}

// localRoute asks the kernel which source address (and so which interface)
// it would use to reach ip. A UDP "connect" sends nothing.
func localRoute(ip net.IP) (routeInfo, error) {
	network := "udp4"
	if ip.To4() == nil {
		network = "udp6"
	}
	c, err := net.Dial(network, net.JoinHostPort(ip.String(), "9"))
	if err != nil {
		return routeInfo{}, err
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return routeInfo{}, errors.New("no local address")
	}
	r := routeInfo{Source: ua.IP}
	ifaces, err := net.Interfaces()
	if err != nil {
		return r, nil // the route exists; its interface just cannot be named
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(ua.IP) {
				r.Interface, r.MTU = ifc.Name, ifc.MTU
				return r, nil
			}
		}
	}
	return r, nil
}

// ---- reporting ---------------------------------------------------------------------------

// statLine renders "min / avg / max" in milliseconds.
func statLine(rtts []time.Duration) (string, map[string]float64) {
	if len(rtts) == 0 {
		return "", nil
	}
	sorted := append([]time.Duration(nil), rtts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var sum time.Duration
	for _, d := range sorted {
		sum += d
	}
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	lo, avg, hi := ms(sorted[0]), ms(sum/time.Duration(len(sorted))), ms(sorted[len(sorted)-1])
	return fmt.Sprintf("%.1fms / %.1fms / %.1fms", lo, avg, hi), map[string]float64{"min": lo, "avg": avg, "max": hi}
}

func report(s *Section, ip net.IP, port, count int, tcp tcpResult, icmp icmpResult, route routeInfo, routeErr error) {
	s.Status = StatusOK
	warn := func(msg string) {
		if s.Status != StatusError {
			s.Status = StatusWarn
		}
		s.Notes = append(s.Notes, msg)
	}
	fail := func(msg string) {
		s.Status = StatusError
		s.Notes = append(s.Notes, msg)
	}
	var out strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&out, format+"\n", a...) }
	target := net.JoinHostPort(ip.String(), strconv.Itoa(port))

	// Route.
	switch {
	case routeErr != nil:
		fail(fmt.Sprintf("no route to %s: %v", ip, routeErr))
		line("route: none (%v)", routeErr)
	case route.Interface != "":
		s.Notes = append(s.Notes, fmt.Sprintf("Route: via %s (source %s), local MTU %d", route.Interface, route.Source, route.MTU))
		line("route: interface=%s source=%s mtu=%d", route.Interface, route.Source, route.MTU)
		s.Metrics["local_mtu"] = float64(route.MTU)
	default:
		s.Notes = append(s.Notes, fmt.Sprintf("Route: source %s (interface not identified)", route.Source))
		line("route: source=%s", route.Source)
	}

	// TCP.
	okN := len(tcp.rtts)
	switch {
	case okN > 0:
		stats, m := statLine(tcp.rtts)
		s.Notes = append(s.Notes, fmt.Sprintf("TCP %s: %s (%d/%d connected)", target, stats, okN, tcp.sent))
		line("tcp %s: min/avg/max %s, %d/%d connected", target, stats, okN, tcp.sent)
		s.Metrics["tcp_min_ms"], s.Metrics["tcp_avg_ms"], s.Metrics["tcp_max_ms"] = m["min"], m["avg"], m["max"]
		if okN < tcp.sent {
			warn(fmt.Sprintf("TCP %s: %d of %d connection attempts failed", target, tcp.sent-okN, tcp.sent))
		}
	case tcp.sent == 0:
		warn("TCP probe did not run (cancelled)")
	case tcp.refused == tcp.sent:
		fail(fmt.Sprintf("TCP %s: connection refused (the host answers, but nothing listens on the port)", target))
		line("tcp %s: refused x%d", target, tcp.sent)
	default:
		fail(fmt.Sprintf("TCP %s: no connection in %d attempt(s): %v", target, tcp.sent, tcp.lastErr))
		line("tcp %s: failed x%d (%v)", target, tcp.sent, tcp.lastErr)
	}
	if tcp.sent > 0 {
		s.Metrics["tcp_loss_pct"] = 100 * float64(tcp.sent-okN) / float64(tcp.sent)
	}

	// ICMP.
	switch {
	case icmp.unavailable != "":
		s.Notes = append(s.Notes, "ICMP echo not used: "+icmp.unavailable+"; TCP probe only")
		line("icmp: unavailable (%s)", icmp.unavailable)
	case len(icmp.rtts) > 0:
		stats, m := statLine(icmp.rtts)
		s.Notes = append(s.Notes, fmt.Sprintf("ICMP echo: %s (%d/%d replies)", stats, len(icmp.rtts), icmp.sent))
		line("icmp %s: min/avg/max %s, %d/%d replies", ip, stats, len(icmp.rtts), icmp.sent)
		s.Metrics["icmp_min_ms"], s.Metrics["icmp_avg_ms"], s.Metrics["icmp_max_ms"] = m["min"], m["avg"], m["max"]
		if len(icmp.rtts) < icmp.sent {
			warn(fmt.Sprintf("ICMP echo: %d of %d requests unanswered", icmp.sent-len(icmp.rtts), icmp.sent))
		}
	default:
		// Many networks drop ICMP while forwarding TCP: informational only.
		s.Notes = append(s.Notes, fmt.Sprintf("ICMP echo: no replies in %d attempt(s) (filtered or the host is down)", icmp.sent))
		line("icmp %s: no replies x%d", ip, icmp.sent)
	}

	// MTU.
	switch {
	case icmp.mtuPayload > 0 && icmp.mtuOK:
		s.Notes = append(s.Notes, fmt.Sprintf("MTU: a %d-byte packet (don't fragment) crosses the path", icmp.mtuPayload+icmpHeaderLen))
		line("mtu: %d-byte DF echo answered", icmp.mtuPayload+icmpHeaderLen)
		s.Metrics["path_mtu_verified"] = float64(icmp.mtuPayload + icmpHeaderLen)
	case icmp.mtuPayload > 0:
		warn(fmt.Sprintf("MTU: a %d-byte don't-fragment echo got no reply (%s) while small echoes did: the path MTU may be below the local MTU of %d", icmp.mtuPayload+icmpHeaderLen, icmp.mtuErr, route.MTU))
		line("mtu: %d-byte DF echo failed (%s)", icmp.mtuPayload+icmpHeaderLen, icmp.mtuErr)
	default:
		s.Notes = append(s.Notes, "MTU: end-to-end size not verified (needs ICMP replies from a non-loopback host)")
	}
	s.Output = out.String()
}
