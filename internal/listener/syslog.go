// ==============================================================================
// Package listener: passive syslog receiver (UDP and TCP).
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-27
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         srv, _ := listener.New(cfg); srv.Start(); ...; srv.Stop()
// Notes:         Go package implementation
// ==============================================================================
// Package listener receives syslog from the network devices themselves, so
// events reach netlog the moment they happen instead of at the next polling
// sweep. It speaks:
//
//   - UDP: one message per datagram (RFC 3164 and RFC 5424, any PRI header).
//   - TCP: RFC 6587 octet-counted frames ("123 <PRI>...") and newline-delimited
//     messages, detected per frame, so both kinds of sender work unchanged.
//
// Each message is attributed to an inventory device by its source address
// (messages from addresses that are not in the inventory are dropped, unless
// Config.AcceptUnknown is set), run through the same pipeline as polled logs
// (vendor parser, future-date filter, normalizer, classifier, own-session
// suppression) and handed in batches to Config.Sink.
//
// Resource behaviour, all bounded:
//
//	message size    MaxMessage bytes; longer messages are truncated
//	queue           QueueSize messages; UDP drops (and counts) when it is full,
//	                TCP readers wait, which throttles the sender through TCP
//	TCP connections MaxConns at once, each with an idle timeout
//	TCP frames      an octet count above maxFrame closes the connection
//
// A message's source address is only as trustworthy as UDP is: it can be
// spoofed. Bind the listener to a management interface and filter the port
// at the network edge if that matters.
package listener

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netlog/internal/collector"
	"netlog/internal/inventory"
	"netlog/internal/parser"
	"netlog/internal/pipeline"
	"netlog/internal/vendor"
)

// Defaults.
const (
	DefaultMaxMessage    = 8192
	DefaultQueueSize     = 8192
	DefaultBatchSize     = 500
	DefaultFlushInterval = time.Second
	DefaultMaxConns      = 256
	DefaultIdleTimeout   = 10 * time.Minute

	// maxFrame is the largest octet count a TCP sender may announce. A frame
	// above MaxMessage is read and truncated; above maxFrame the sender is
	// misbehaving and the connection is closed.
	maxFrame = 1 << 20
)

// Config configures a Server.
type Config struct {
	// UDPAddr and TCPAddr are listen addresses ("0.0.0.0:514", "127.0.0.1:0").
	// An empty address disables that protocol; at least one is required.
	UDPAddr string
	TCPAddr string

	// Devices is the inventory used to attribute messages by source address.
	Devices []inventory.Device
	// AcceptUnknown stores messages from addresses outside the inventory, as
	// vendor "generic", named after the message's hostname (or the address).
	AcceptUnknown bool

	// Classifier classifies each entry (required).
	Classifier *pipeline.Classifier
	// Location is the zone of timestamps that carry none (nil = time.Local).
	Location *time.Location
	// Sink receives each batch of finished entries. It is called from a
	// single goroutine, never concurrently, and may block (which fills the
	// queue; see the package comment). Required.
	Sink func([]collector.LogEntry)

	// Logger receives notices. Nil disables.
	Logger collector.Logger
	// Now overrides the clock (tests). Nil means time.Now.
	Now func() time.Time

	// Zero values select the defaults above.
	MaxMessage    int
	QueueSize     int
	BatchSize     int
	FlushInterval time.Duration
	MaxConns      int
	IdleTimeout   time.Duration
}

// Stats are cumulative counters.
type Stats struct {
	Received  uint64 // datagrams and TCP frames read
	Stored    uint64 // entries handed to the sink
	Unknown   uint64 // messages from addresses not in the inventory (dropped unless AcceptUnknown)
	Unparsed  uint64 // messages no parser understood; stored with the receive time
	Dropped   uint64 // UDP messages dropped because the queue was full
	Truncated uint64 // messages cut at MaxMessage
	Future    uint64 // entries dropped for a timestamp in the future
	Refused   uint64 // TCP connections refused at the MaxConns limit
	Conns     uint64 // TCP connections accepted
}

type counters struct {
	received, stored, unknown, unparsed, dropped, truncated, future, refused, conns atomic.Uint64
}

type rawMsg struct {
	remote   netip.Addr
	received time.Time
	text     string
}

type nopLogger struct{}

func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}

// Server is a running (or startable) syslog receiver.
type Server struct {
	cfg  Config
	log  collector.Logger
	now  func() time.Time
	byIP map[netip.Addr]inventory.Device

	udp net.PacketConn
	tcp net.Listener

	queue      chan rawMsg
	done       chan struct{}
	readers    sync.WaitGroup
	workerDone chan struct{}

	connMu sync.Mutex
	conns  map[net.Conn]struct{}

	warnMu   sync.Mutex
	warnedAt map[netip.Addr]time.Time

	started  atomic.Bool // Start was called
	running  atomic.Bool // the sockets are bound and the goroutines run
	stopOnce sync.Once
	c        counters
}

// New validates cfg and resolves the inventory addresses. It binds nothing;
// call Start.
func New(cfg Config) (*Server, error) {
	if cfg.UDPAddr == "" && cfg.TCPAddr == "" {
		return nil, errors.New("listener: at least one of UDP or TCP must be enabled")
	}
	if cfg.Classifier == nil || cfg.Sink == nil {
		return nil, errors.New("listener: a classifier and a sink are required")
	}
	if cfg.MaxMessage <= 0 {
		cfg.MaxMessage = DefaultMaxMessage
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = DefaultQueueSize
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultFlushInterval
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	s := &Server{
		cfg:        cfg,
		log:        nopLogger{},
		now:        time.Now,
		queue:      make(chan rawMsg, cfg.QueueSize),
		done:       make(chan struct{}),
		workerDone: make(chan struct{}),
		conns:      make(map[net.Conn]struct{}),
		warnedAt:   make(map[netip.Addr]time.Time),
	}
	if cfg.Logger != nil {
		s.log = cfg.Logger
	}
	if cfg.Now != nil {
		s.now = cfg.Now
	}
	s.byIP = s.resolveDevices(cfg.Devices)
	return s, nil
}

// resolveDevices maps source addresses to devices. A device whose address is a
// DNS name is resolved once, now; one that does not resolve is left out with a
// warning.
func (s *Server) resolveDevices(devs []inventory.Device) map[netip.Addr]inventory.Device {
	m := make(map[netip.Addr]inventory.Device, len(devs))
	add := func(d inventory.Device, a netip.Addr) {
		a = a.Unmap()
		if prev, dup := m[a]; dup {
			s.log.Warn("listen: %s and %s share the address %s; messages are attributed to %s", prev.Hostname, d.Hostname, a, prev.Hostname)
			return
		}
		m[a] = d
	}
	for _, d := range devs {
		if a, err := netip.ParseAddr(d.Address); err == nil {
			add(d, a)
			continue
		}
		addrs, err := net.LookupHost(d.Address)
		if err != nil || len(addrs) == 0 {
			s.log.Warn("listen: cannot resolve %s (%s); its syslog will not be attributed", d.Hostname, d.Address)
			continue
		}
		for _, text := range addrs {
			if a, err := netip.ParseAddr(text); err == nil {
				add(d, a)
			}
		}
	}
	return m
}

// Start binds the sockets and starts receiving. It returns once the sockets
// are bound, so a port already in use or a missing privilege is reported
// here, not discovered later.
func (s *Server) Start() error {
	if !s.started.CompareAndSwap(false, true) {
		return errors.New("listener: already started")
	}
	if s.cfg.UDPAddr != "" {
		pc, err := net.ListenPacket("udp", s.cfg.UDPAddr)
		if err != nil {
			return bindError("UDP", s.cfg.UDPAddr, err)
		}
		if uc, ok := pc.(*net.UDPConn); ok {
			_ = uc.SetReadBuffer(4 << 20) // best effort: bursts must not be lost in the kernel
		}
		s.udp = pc
	}
	if s.cfg.TCPAddr != "" {
		ln, err := net.Listen("tcp", s.cfg.TCPAddr)
		if err != nil {
			if s.udp != nil {
				_ = s.udp.Close()
			}
			return bindError("TCP", s.cfg.TCPAddr, err)
		}
		s.tcp = ln
	}

	go s.work()
	if s.udp != nil {
		s.readers.Add(1)
		go s.readUDP()
	}
	if s.tcp != nil {
		s.readers.Add(1)
		go s.acceptTCP()
	}
	s.running.Store(true)
	return nil
}

func bindError(proto, addr string, err error) error {
	hint := ""
	msg := err.Error()
	switch {
	case errors.Is(err, os.ErrPermission) || strings.Contains(msg, "permission denied") || strings.Contains(msg, "access permissions"):
		hint = " (ports below 1024 need root or CAP_NET_BIND_SERVICE; use --port with a higher port, e.g. 5514)"
	case strings.Contains(msg, "address already in use") || strings.Contains(msg, "only one usage of each socket address"):
		hint = " (another syslog receiver is using that port)"
	}
	return fmt.Errorf("listening on %s %s: %w%s", proto, addr, err, hint)
}

// Addrs returns the bound UDP and TCP addresses (nil when disabled or not yet
// started). Useful with port 0.
func (s *Server) Addrs() (udp, tcp net.Addr) {
	if s.udp != nil {
		udp = s.udp.LocalAddr()
	}
	if s.tcp != nil {
		tcp = s.tcp.Addr()
	}
	return udp, tcp
}

// Stats returns a snapshot of the counters.
func (s *Server) Stats() Stats {
	return Stats{
		Received: s.c.received.Load(), Stored: s.c.stored.Load(), Unknown: s.c.unknown.Load(),
		Unparsed: s.c.unparsed.Load(), Dropped: s.c.dropped.Load(), Truncated: s.c.truncated.Load(),
		Future: s.c.future.Load(), Refused: s.c.refused.Load(), Conns: s.c.conns.Load(),
	}
}

// Stop shuts the server down gracefully: it stops accepting, closes every
// connection, waits for the readers, lets the worker drain the queue and flush
// the last batch to the sink, and returns. It is safe to call more than once.
func (s *Server) Stop() {
	if !s.running.Load() { // never started, or Start failed before anything ran
		return
	}
	s.stopOnce.Do(func() {
		close(s.done)
		if s.udp != nil {
			_ = s.udp.Close()
		}
		if s.tcp != nil {
			_ = s.tcp.Close()
		}
		s.connMu.Lock()
		for c := range s.conns {
			_ = c.Close()
		}
		s.connMu.Unlock()
		s.readers.Wait()
		close(s.queue) // no sender is left
		<-s.workerDone
	})
}

// ---- receivers ---------------------------------------------------------------------------

func (s *Server) stopping() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *Server) readUDP() {
	defer s.readers.Done()
	buf := make([]byte, 65535)
	for {
		n, ra, err := s.udp.ReadFrom(buf)
		if err != nil {
			if s.stopping() || errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warn("listen: UDP read: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		addr := addrOf(ra)
		s.c.received.Add(1)
		if !s.admit(addr) {
			continue
		}
		if n > s.cfg.MaxMessage {
			n = s.cfg.MaxMessage
			s.c.truncated.Add(1)
		}
		select {
		case s.queue <- rawMsg{remote: addr, received: s.now(), text: string(buf[:n])}:
		default:
			s.c.dropped.Add(1) // queue full: UDP cannot be slowed down
		}
	}
}

func addrOf(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	}
	return netip.Addr{}
}

// admit reports whether messages from addr are accepted, counting (and, at
// most once per source and 5 minutes, logging) the refused ones.
func (s *Server) admit(addr netip.Addr) bool {
	if _, ok := s.byIP[addr]; ok || s.cfg.AcceptUnknown {
		return true
	}
	s.c.unknown.Add(1)
	s.warnMu.Lock()
	defer s.warnMu.Unlock()
	now := s.now()
	if last, seen := s.warnedAt[addr]; !seen || now.Sub(last) > 5*time.Minute {
		if len(s.warnedAt) >= 256 { // bound the table against a spoofed-source flood
			s.warnedAt = make(map[netip.Addr]time.Time)
		}
		s.warnedAt[addr] = now
		s.log.Warn("listen: dropping syslog from %s: not in the inventory (use --accept-unknown to store it)", addr)
	}
	return false
}

func (s *Server) acceptTCP() {
	defer s.readers.Done()
	for {
		c, err := s.tcp.Accept()
		if err != nil {
			if s.stopping() || errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warn("listen: TCP accept: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		addr := addrOf(c.RemoteAddr())
		if !s.admit(addr) {
			_ = c.Close()
			continue
		}
		s.connMu.Lock()
		if len(s.conns) >= s.cfg.MaxConns || s.stopping() {
			s.connMu.Unlock()
			s.c.refused.Add(1)
			_ = c.Close()
			continue
		}
		s.conns[c] = struct{}{}
		s.connMu.Unlock()
		s.c.conns.Add(1)
		s.readers.Add(1)
		go s.serveConn(c, addr)
	}
}

func (s *Server) serveConn(c net.Conn, addr netip.Addr) {
	defer s.readers.Done()
	defer func() {
		_ = c.Close()
		s.connMu.Lock()
		delete(s.conns, c)
		s.connMu.Unlock()
	}()
	br := bufio.NewReaderSize(c, 16<<10)
	for {
		_ = c.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))
		text, truncated, err := readFrame(br, s.cfg.MaxMessage)
		if text != "" {
			s.c.received.Add(1)
			if truncated {
				s.c.truncated.Add(1)
			}
			select {
			case s.queue <- rawMsg{remote: addr, received: s.now(), text: text}:
			case <-s.done:
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !s.stopping() && !errors.Is(err, net.ErrClosed) && !isTimeout(err) {
				s.log.Warn("listen: closing TCP connection from %s: %v", addr, err)
			}
			return
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// ---- TCP framing (RFC 6587) --------------------------------------------------------------

var reOctetCount = regexp.MustCompile(`^[1-9][0-9]{0,6} `)

var errFrameTooLarge = errors.New("octet-counted frame is larger than the 1 MiB limit")

// readFrame reads one message: an octet-counted frame when the next bytes are
// "<digits><space>", otherwise one newline-terminated line. (RFC 6587 admits
// the ambiguity: a message with no PRI header that begins with digits and a
// space reads as an octet count. Senders emit a "<PRI>" header, which cannot
// be mistaken for one.) It keeps at most
// max bytes and reports whether it cut the message. An error is returned
// together with whatever text was read before it (a final unterminated line).
func readFrame(br *bufio.Reader, max int) (text string, truncated bool, err error) {
	// Skip the blank lines that separate messages on some senders.
	for {
		b, perr := br.Peek(1)
		if perr != nil {
			return "", false, perr
		}
		if b[0] != '\n' && b[0] != '\r' {
			break
		}
		_, _ = br.ReadByte()
	}
	head, _ := br.Peek(8)
	if reOctetCount.Match(head) {
		sp := strings.IndexByte(string(head), ' ')
		n, _ := strconv.Atoi(string(head[:sp]))
		if n > maxFrame {
			return "", false, errFrameTooLarge
		}
		_, _ = br.Discard(sp + 1)
		keep := n
		if keep > max {
			keep, truncated = max, true
		}
		buf := make([]byte, keep)
		if got, err := io.ReadFull(br, buf); err != nil {
			return string(buf[:got]), truncated, err
		}
		if n > keep {
			if _, err := br.Discard(n - keep); err != nil {
				return string(buf), truncated, err
			}
		}
		return strings.TrimRight(string(buf), "\r\n"), truncated, nil
	}

	var line []byte
	for {
		chunk, rerr := br.ReadSlice('\n')
		if room := max - len(line); room > 0 {
			if len(chunk) > room {
				line = append(line, chunk[:room]...)
				truncated = true
			} else {
				line = append(line, chunk...)
			}
		} else if len(chunk) > 0 {
			truncated = true
		}
		switch {
		case rerr == nil:
			return strings.TrimRight(string(line), "\r\n"), truncated, nil
		case errors.Is(rerr, bufio.ErrBufferFull):
			continue
		default:
			return strings.TrimRight(string(line), "\r\n"), truncated, rerr
		}
	}
}

// ---- worker ------------------------------------------------------------------------------

func (s *Server) work() {
	defer close(s.workerDone)
	tick := time.NewTicker(s.cfg.FlushInterval)
	defer tick.Stop()
	var batch []collector.LogEntry
	flush := func() {
		if len(batch) == 0 {
			return
		}
		out := batch
		batch = nil
		s.deliver(out)
	}
	for {
		select {
		case m, ok := <-s.queue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, s.safeProcess(m)...)
			if len(batch) >= s.cfg.BatchSize {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

// deliver hands a batch to the sink; a panicking sink loses that batch but not
// the listener.
func (s *Server) deliver(batch []collector.LogEntry) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("listen: sink panicked, %d entries lost: %v", len(batch), r)
		}
	}()
	s.cfg.Sink(batch)
	s.c.stored.Add(uint64(len(batch)))
}

func (s *Server) safeProcess(m rawMsg) (out []collector.LogEntry) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("listen: internal error processing a message from %s: %v", m.remote, r)
			out = nil
		}
	}()
	return s.process(m)
}

// ---- message processing ------------------------------------------------------------------

var (
	rePRI      = regexp.MustCompile(`^<(\d{1,3})>`)
	reRFC5424  = regexp.MustCompile(`^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (.*))?$`)
	reHost3164 = regexp.MustCompile(`^(?:[A-Za-z]{3}\s+\d{1,2}\s+(?:\d{4}\s+)?\d{2}:\d{2}:\d{2}(?:\.\d+)?|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+([A-Za-z0-9._-]{1,63})\s`)
	reSafeHost = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
)

// splitPRI removes a leading "<PRI>" and returns the priority (-1 when there is
// none or it is out of range) and the rest.
func splitPRI(s string) (pri int, rest string) {
	m := rePRI.FindStringSubmatch(s)
	if m == nil {
		return -1, s
	}
	n, _ := strconv.Atoi(m[1])
	if n > 191 {
		return -1, s
	}
	return n, s[len(m[0]):]
}

// normalizeHeader converts an RFC 5424 message into the
// "TIMESTAMP HOST APP[PROCID]: MSG" form the vendor parsers understand, and
// returns the header's hostname. Anything else (RFC 3164 and the many vendor
// variants of it) passes through unchanged.
func normalizeHeader(body string, received time.Time) (line, host string) {
	if m := reRFC5424.FindStringSubmatch(body); m != nil {
		ts, host, app, procid, msg := m[1], m[2], m[3], m[4], strings.TrimPrefix(m[7], "\ufeff")
		if ts == "-" {
			ts = received.UTC().Format(time.RFC3339)
		}
		if host == "-" {
			host = ""
		}
		tag := app
		if procid != "-" && procid != "" {
			tag += "[" + procid + "]"
		}
		h := host
		if h == "" {
			h = "-"
		}
		return ts + " " + h + " " + tag + ": " + msg, host
	}
	if m := reHost3164.FindStringSubmatch(body); m != nil {
		return body, m[1]
	}
	return body, ""
}

// sanitize removes what must not reach storage or a terminal: invalid UTF-8
// and control characters other than tab.
func sanitize(s string) string {
	s = strings.ToValidUTF8(s, "?")
	return strings.Map(func(r rune) rune {
		if (r < 0x20 && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return '?'
		}
		return r
	}, s)
}

// process turns one raw message into finished log entries.
func (s *Server) process(m rawMsg) []collector.LogEntry {
	_, body := splitPRI(sanitize(m.text))
	body = strings.TrimSpace(body)
	if body == "" {
		return nil
	}
	line, hdrHost := normalizeHeader(body, m.received)

	dev, known := s.byIP[m.remote]
	if !known { // admit() only lets unknown sources through under AcceptUnknown
		name := m.remote.String()
		if reSafeHost.MatchString(hdrHost) {
			name = hdrHost
		}
		dev = inventory.Device{Hostname: name, Address: m.remote.String(), Vendor: "generic"}
	}
	key, ok := vendor.CanonicalKey(dev.Vendor)
	if !ok {
		key = "generic"
	}

	opts := parser.Options{Ref: m.received, Location: s.cfg.Location}
	entries := parser.Parse(key, line, dev, opts)
	if len(entries) == 0 && key != "generic" {
		// Forwarded syslog often differs from the device's own log buffer
		// format; the generic parser reads plain RFC 3164 / ISO syslog.
		entries = parser.Parse("generic", line, dev, opts)
		for i := range entries {
			entries[i].Vendor = key
		}
	}
	if len(entries) == 0 {
		// Keep what cannot be parsed, dated by its arrival: the classifier
		// still reads the text, and a line must not vanish for lack of a header.
		s.c.unparsed.Add(1)
		entries = []collector.LogEntry{s.synthesize(dev, key, line, m.received)}
	}

	var dropped int
	if entries, dropped = pipeline.DropFuture(entries, m.received, pipeline.FutureTolerance(key, false)); dropped > 0 {
		s.c.future.Add(uint64(dropped))
	}
	pipeline.Normalize(entries, 0, false)
	s.cfg.Classifier.ClassifyAll(entries)
	return pipeline.SuppressOwn(entries)
}

func (s *Server) synthesize(dev inventory.Device, vendorKey, line string, at time.Time) collector.LogEntry {
	summary := line
	if len(summary) > 300 {
		summary = summary[:300]
	}
	return collector.LogEntry{
		ID:        collector.EntryID(dev.Hostname, line),
		Timestamp: at.UTC(),
		DeviceTS:  at,
		Hostname:  dev.Hostname,
		IP:        dev.Address,
		Vendor:    vendorKey,
		Facility:  "SYS",
		Summary:   summary,
		Raw:       line,
	}
}
