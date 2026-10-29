//go:build !linux

package diagnose

import (
	"errors"
	"net"
)

// openICMPSession reports that unprivileged ICMP echo is only implemented for
// Linux; the probe then relies on its TCP numbers.
func openICMPSession(net.IP) (icmpSession, error) {
	return nil, errors.New("unprivileged ICMP echo is only implemented on Linux")
}
