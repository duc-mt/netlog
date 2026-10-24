//go:build !linux

package sshclient

import (
	"net"
	"time"
)

// DefaultTCPMSS is the fallback default MSS for non-Linux platforms.
const DefaultTCPMSS = 1360

func newDialer(timeout time.Duration, mss int) net.Dialer {
	return net.Dialer{
		Timeout: timeout,
	}
}
