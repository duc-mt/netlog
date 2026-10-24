//go:build linux

package sshclient

import (
	"net"
	"syscall"
	"time"
)

// DefaultTCPMSS is 1360 bytes. Standard Ethernet MTU is 1500 (MSS 1460), but
// tunnels (GRE, IPsec, VXLAN, PPPoE) reduce path MTU down to ~1400-1476.
// Clamping TCP MSS to 1360 prevents PMTU blackholes where oversized SSH banner
// and key-exchange packets get dropped by MTU-constrained links with DF set.
const DefaultTCPMSS = 1360

func newDialer(timeout time.Duration, mss int) net.Dialer {
	if mss < 0 {
		return net.Dialer{Timeout: timeout}
	}
	if mss == 0 {
		mss = DefaultTCPMSS
	}
	return net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss)
			})
			if err != nil {
				return err
			}
			_ = sockErr
			return nil
		},
	}
}
