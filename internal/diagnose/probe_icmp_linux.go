//go:build linux

package diagnose

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"
)

// pingSocket is an unprivileged ICMP echo socket (SOCK_DGRAM, IPPROTO_ICMP).
// The kernel owns the identifier and demultiplexes replies to the socket, so
// replies are matched by sequence number alone.
type pingSocket struct {
	fd  int
	dst syscall.SockaddrInet4
}

// openICMPSession opens an echo socket towards ip (IPv4 only).
func openICMPSession(ip net.IP) (icmpSession, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, errICMPv4Only
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd)
	s := &pingSocket{fd: fd}
	copy(s.dst.Addr[:], ip4)
	return s, nil
}

func (s *pingSocket) Close() { _ = syscall.Close(s.fd) }

func (s *pingSocket) setDF(df bool) error {
	v := syscall.IP_PMTUDISC_DONT
	if df {
		v = syscall.IP_PMTUDISC_DO
	}
	return syscall.SetsockoptInt(s.fd, syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, v)
}

func (s *pingSocket) Echo(ctx context.Context, seq, payload int, df bool, timeout time.Duration) (time.Duration, error) {
	if err := s.setDF(df); err != nil {
		return 0, err
	}
	pkt := buildEchoRequest(seq, payload)
	deadline := time.Now().Add(timeout)
	start := time.Now()
	if err := syscall.Sendto(s.fd, pkt, 0, &s.dst); err != nil {
		if errors.Is(err, syscall.EMSGSIZE) {
			return 0, errEchoTooBig
		}
		return 0, err
	}
	buf := make([]byte, 65536)
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		left := time.Until(deadline)
		if left <= 0 {
			return 0, errEchoTimeout
		}
		// Short receive timeouts keep the loop responsive to ctx.
		if left > 200*time.Millisecond {
			left = 200 * time.Millisecond
		}
		tv := syscall.NsecToTimeval(left.Nanoseconds())
		if err := syscall.SetsockoptTimeval(s.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
			return 0, err
		}
		n, _, err := syscall.Recvfrom(s.fd, buf, 0)
		if err != nil {
			switch {
			case errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EINTR):
				continue
			case errors.Is(err, syscall.EMSGSIZE):
				return 0, errEchoTooBig
			}
			return 0, err
		}
		if isEchoReply(buf[:n], seq) {
			return time.Since(start), nil
		}
	}
}
