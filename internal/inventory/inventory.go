// ==============================================================================
// Package inventory loads the device inventory from a CSV file.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-10
// Version:       1.0.0
// License:       MIT
// ==============================================================================
// Usage:         imported by cmd/netlog and the other internal packages
// Notes:         Go package implementation
// ==============================================================================
// Package inventory loads the list of target devices from a plain CSV file,
// so the device list lives outside the binary and can be edited on the
// air-gapped host with nothing more than a text editor.
package inventory

import (
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

// Device is one network device netlog polls.
type Device struct {
	Hostname        string // friendly name; also the key for stored logs, watermarks and cooldowns
	Address         string // IP or DNS name used to connect
	Port            int
	Vendor          string // platform name or alias (see internal/vendor)
	CredentialGroup string // optional group key for per-site credentials (default: "default")
	JumpHost        string // optional jump host name (e.g. "bastion-site-a"); empty = direct or global default
	Line            int    // source line number, for error messages
}

// Load reads a CSV file with the header:
//
//	hostname,address,port,vendor,credential_group,jump_host
//
// Rules, chosen to make hand-editing forgiving:
//   - blank lines and lines starting with '#' are skipped
//   - the header line is detected and skipped automatically
//   - port defaults to 22 if empty
//   - credential_group defaults to "default" if empty
//   - jump_host is optional; empty means direct connection (or use global default)
//   - a malformed line is reported and skipped -- it does not abort loading
//     the rest of the file, matching the tool's "one bad entry never stops
//     the run" philosophy
func Load(path string) ([]Device, []error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, []error{fmt.Errorf("opening inventory file %q: %w", path, err)}
	}
	defer f.Close()

	var devices []Device
	var warnings []error

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.Comment = '#'
	r.TrimLeadingSpace = true

	lineNo := 0
	headerSkipped := false

	for {
		lineNo++
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			warnings = append(warnings, fmt.Errorf("line %d: parsing CSV: %w", lineNo, err))
			continue
		}

		if len(record) == 0 {
			continue
		}

		fields := make([]string, len(record))
		for i, v := range record {
			fields[i] = strings.TrimSpace(v)
		}

		if len(fields) == 1 && fields[0] == "" {
			continue
		}

		if !headerSkipped && strings.EqualFold(fields[0], "hostname") {
			headerSkipped = true
			continue
		}
		headerSkipped = true

		dev, err := parseLine(fields, lineNo)
		if err != nil {
			warnings = append(warnings, err)
			continue
		}
		devices = append(devices, dev)
	}

	return devices, warnings
}

func parseLine(fields []string, lineNo int) (Device, error) {
	if len(fields) < 2 {
		return Device{}, fmt.Errorf("line %d: expected at least hostname,address -- got %q", lineNo, strings.Join(fields, ","))
	}

	dev := Device{
		Hostname:        fields[0],
		Address:         fields[1],
		Port:            22,
		Vendor:          "generic",
		CredentialGroup: "default",
		Line:            lineNo,
	}
	if dev.Hostname == "" || dev.Address == "" {
		return Device{}, fmt.Errorf("line %d: hostname and address are required", lineNo)
	}

	if len(fields) >= 3 && fields[2] != "" {
		port, err := strconv.Atoi(fields[2])
		if err != nil || port <= 0 || port > 65535 {
			return Device{}, fmt.Errorf("line %d: invalid port %q", lineNo, fields[2])
		}
		dev.Port = port
	}

	if len(fields) >= 4 && fields[3] != "" {
		dev.Vendor = strings.ToLower(fields[3])
	}

	if len(fields) >= 5 && fields[4] != "" {
		dev.CredentialGroup = strings.ToLower(fields[4])
	}

	if len(fields) >= 6 && fields[5] != "" {
		dev.JumpHost = strings.ToLower(fields[5])
	}

	return dev, nil
}

// Endpoint returns the host:port string for this device.
func (d Device) Endpoint() string {
	p := d.Port
	if p <= 0 {
		p = 22
	}
	return net.JoinHostPort(d.Address, strconv.Itoa(p))
}
