package diagnose

import "encoding/binary"

// ICMPv4 echo packet helpers (RFC 792). They are plain byte handling and are
// compiled on every platform so they can be tested everywhere.

const (
	icmpEchoRequest = 8
	icmpEchoReply   = 0
)

// buildEchoRequest returns an ICMP echo request with the given sequence number
// and payload size. The identifier is left zero: the kernel assigns it on a
// ping socket.
func buildEchoRequest(seq, payload int) []byte {
	if payload < 0 {
		payload = 0
	}
	b := make([]byte, 8+payload)
	b[0], b[1] = icmpEchoRequest, 0
	binary.BigEndian.PutUint16(b[6:8], uint16(seq&0xffff))
	for i := 8; i < len(b); i++ {
		b[i] = "abcdefghijklmnopqrstuvwxyz"[(i-8)%26]
	}
	binary.BigEndian.PutUint16(b[2:4], checksum(b))
	return b
}

// checksum is the Internet checksum (RFC 1071) of b.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// isEchoReply reports whether b is an echo reply with the given sequence
// number. A packet that still carries its IPv4 header (some platforms deliver
// it) is accepted too.
func isEchoReply(b []byte, seq int) bool {
	if len(b) >= 20 && b[0]>>4 == 4 && b[9] == 1 { // IPv4 header, protocol ICMP
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return false
		}
		b = b[ihl:]
	}
	if len(b) < 8 || b[0] != icmpEchoReply || b[1] != 0 {
		return false
	}
	return int(b[6])<<8|int(b[7]) == seq
}
