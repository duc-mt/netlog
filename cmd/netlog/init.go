// ==============================================================================
// Package main: initialization of default configuration files.
// Author:        Mai Tan Duc <ducmai.network@gmail.com>
// Created:       2026-10-23
// Version:       1.0.0
// License:       MIT
// ==============================================================================
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const sampleEnv = `# Copy this file to ".env" and fill in real values:
#     cp examples/.env.example .env && chmod 600 .env
# NEVER commit the real .env file. netlog only ever READS from devices, so give it
# a dedicated read-only account rather than reusing a privileged one.
#
# Settings are read from this file first, then from the process environment.
# (The older NETBACKUP_* spellings are still accepted but deprecated.)

# Default credentials (used when credential_group is empty or "default").
# Either NETLOG_PASSWORD or NETLOG_KEY_FILE (or both) can be used.
NETLOG_USERNAME=svc-netlog
NETLOG_PASSWORD=change-me
# NETLOG_KEY_FILE=/home/netops/.ssh/id_ed25519

# Optional per-site or per-group credentials (matched against the inventory's
# credential_group column, upper-cased):
# Password-based group:
# NETLOG_SITE_HCM_USERNAME=svc-hcm-netlog
# NETLOG_SITE_HCM_PASSWORD=site-hcm-pass
# SSH key-based group:
# NETLOG_SITE_DC_USERNAME=svc-dc-netlog
# NETLOG_SITE_DC_KEY_FILE=/home/netops/.ssh/id_rsa_dc

# Jump host / bastion support.
# Global default bastion used when a device has no jump_host in the inventory.
# Can also be set at runtime with: --jump-host
# NETLOG_JUMP_HOST=mgmt-gw.example.com:22
# NETLOG_JUMP_USERNAME=svc-jump
# NETLOG_JUMP_PASSWORD=jump-change-me
# NETLOG_JUMP_KEY_FILE=/home/netops/.ssh/jump_key

# Per-named-jump credentials (the jump_host name from the inventory, upper-cased).
# Lets different network segments use different bastions.
# NETLOG_JUMP_BASTION_DC_HOST=bastion-dc.example.com:22
# NETLOG_JUMP_BASTION_DC_USERNAME=svc-dc-jump
# NETLOG_JUMP_BASTION_DC_PASSWORD=dc-jump-pass
# NETLOG_JUMP_BASTION_DC_KEY_FILE=/home/netops/.ssh/dc_jump_key

# Optional Telegram Alert Notifications:
# TELEGRAM_ENABLED=false
# TELEGRAM_BOT_TOKEN="000000000:AAFg-XXXXXXXXXXXXXXXXXXXXXXXXXX"
# TELEGRAM_CHAT_ID="-1001234567890"
# TELEGRAM_MESSAGE_THREAD_ID=""
# TELEGRAM_COOLDOWN_SECONDS=300
`

const sampleInventory = `hostname,address,port,vendor,credential_group,jump_host
# One device per line. port, vendor, credential_group and jump_host are optional:
#   - port defaults to 22
#   - vendor defaults to "generic" (best-effort "show logging")
#   - credential_group defaults to "default" (NETLOG_USERNAME / NETLOG_PASSWORD or
#     NETLOG_KEY_FILE in .env); a group name selects NETLOG_<GROUP>_* instead
#   - jump_host: leave blank for direct connections; set to a bastion name or
#     host[:port] for devices reachable only through a management server.
#     The --jump-host flag sets the global default; this column overrides it.
#
# Platforms netlog can read logs from (vendor column), with common aliases:
#   vyos, cisco_ios (cisco, ios-xe), cisco_asa (asa, ftd), cisco_sb (sg350, cbs350),
#   huawei_vrp (huawei, h3c, comware), juniper_junos (junos), fortigate (fortios),
#   aruba (aos-cx), ruijie (rgos), mikrotik (RouterOS), arista (eos),
#   cumulus (Cumulus Linux; the login needs read access to /var/log/syslog),
#   paloalto (pan-os), pfsense (2.5+, needs shell access), checkpoint_gaia
#   (the login's shell must be /bin/bash), generic
# sophos is recognised but not supported yet: such devices are skipped with one
# warning per run.
#
# Cisco / Ruijie devices need "service timestamps log datetime" (ideally with
# "localtime" so log lines and "show clock" use the same time zone).
core-sw1,10.10.1.1,22,cisco_ios,site_hcm,
dist-sw1,10.50.2.1,22,huawei_vrp,site_hcm,
gw-bvu-01,10.20.1.1,22,vyos,site_dc,bastion-dc
edge-rtr1,10.20.2.1,22,juniper_junos,site_dc,bastion-dc
dc-fw1,10.20.3.1,22,fortigate,site_dc,bastion-dc
ap-ctrl1,10.40.1.1,22,aruba,default,
access-sw1,10.50.1.1,22,ruijie,site_hcm,mgmt-gw.site-hcm.example.com:22
edge-rtr2,10.20.4.1,22,mikrotik,site_dc,bastion-dc
`

func cmdInit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("netlog init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}

	fmt.Fprintln(stdout, "Initializing configuration files...")
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		if err := os.WriteFile(".env", []byte(sampleEnv), 0o600); err != nil {
			fmt.Fprintf(stderr, "error creating .env: %v\n", err)
			return exitError
		}
		fmt.Fprintln(stdout, "  [+] Created .env (chmod 600)")
	} else {
		fmt.Fprintln(stdout, "  [.] .env already exists, skipping")
	}

	if _, err := os.Stat("inventory.csv"); os.IsNotExist(err) {
		if err := os.WriteFile("inventory.csv", []byte(sampleInventory), 0o600); err != nil {
			fmt.Fprintf(stderr, "error creating inventory.csv: %v\n", err)
			return exitError
		}
		fmt.Fprintln(stdout, "  [+] Created inventory.csv")
	} else {
		fmt.Fprintln(stdout, "  [.] inventory.csv already exists, skipping")
	}

	fmt.Fprintln(stdout, "Initialization complete! Edit .env and inventory.csv to match your environment.")
	return exitOK
}
