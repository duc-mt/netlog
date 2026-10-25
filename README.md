# netlog

Network log monitor and auto-triage. `netlog` polls network devices over SSH,
normalizes their log buffers into one structure, detects anomalies and, when
something breaks, reconnects to capture **strictly read-only** diagnostics before
the evidence is lost.

- **No device changes.** It only reads the log buffer (`show logging`,
  `display logbuffer`, ...). Nothing to configure on switches or routers.
- **One static binary.** Pure Go, `CGO_ENABLED=0`, dependencies vendored, builds
  and runs fully offline (air-gap friendly).
- **No database.** Daily JSONL files you can `grep`/`jq`; plain JSON incident reports.

## Quick start (Universal Deployment)

No matter what device or OS you are using (Linux, macOS, Windows x86_64, ARM64), you can run `./run` (or `.\scripts\run.bat` on native Windows CMD). It automatically detects your host OS and architecture and launches or builds the matching binary:

```sh
./run init            # 1. Initialize .env (chmod 600) and inventory.csv templates
$EDITOR .env inventory.csv

./run                 # 2. Poll everything once (defaults to: collect)
./run --dry-run                        # Test connectivity & clock skew (no files written)
./run monitor --interval 2m            # Or run continuous monitor loop

./run query     --category FAULT --since 24h
./run timeline  --from "2026-10-20 10:10:00" --to "2026-10-20 10:25:00"
./run incidents --since 24h            # list triage reports
./run incidents --id a1b2c3d4          # view formatted triage report (or --format json)
./run report                           # last 7 days: noisy devices, who changed what, watchlist, trends
./run report    --since 24h --top 5 --format json
./run status                           # which devices could not be polled, and since when
```

### Standard Make / Direct Binary

```sh
make build            # -> bin/netlog  (also: make build-netlog)
make init             # creates .env (chmod 600) and inventory.csv from examples/
$EDITOR .env inventory.csv

bin/netlog collect --dry-run            # test connectivity and clock skew first
bin/netlog collect --data-dir data          # poll everything once (cron-friendly)
bin/netlog monitor --interval 2m            # or loop forever (systemd-friendly)
```

## Reports

`netlog report` answers "is my network doing something unusual?" where `query` and
`timeline` answer "what happened at 10:22 on SW-LAB?". It reads the stored JSONL
logs and incident reports for a window and prints nine sections (read-only; nothing
is written, and there is no daemon, dashboard or alerting). Logs are streamed, so
memory stays flat (about 16 MB for 600k entries) however long the window is.

| Section | What it shows |
| --- | --- |
| Noisy Devices | `FAULT` events per device, top N |
| Change Accountability | `CONFIG_CHANGE` + `AFTER_HOURS_CHANGE` per user (`(unknown)` last), plus the after-hours list |
| Security Watchlist | `LOGIN_FAILURE` grouped by source IP, ranked by **distinct devices hit**, then failures. `DETECTED` counts the brute-force / password-spray detections netlog derived, kept apart so they do not inflate the failure count |
| Event Volume | events per UTC day x category (`CONFIG AUTH FAULT SECURITY SYSTEM`), empty days included |
| Week-over-Week | per-category count against the equal window before it, absolute and percent (`n/a` when the earlier window is empty) |
| Triage Reach | how many triage runs could not reconnect to the device, and which devices are unreachable every time. (JSON key: `incident_closure`.) This measures reachability, not whether the problem went away: see Outages |
| Outages | link, OSPF and BGP downs paired with their recovery: count, mean time to recover, the longest outages and any still open |
| Device Health | devices netlog cannot poll or that never log (the table `netlog status` prints, minus the healthy ones) |
| Classification Coverage | per vendor, the share of lines the classifier left `UNKNOWN`: where more rules are needed |

```sh
netlog report                              # --since 7d, with the week-over-week delta
netlog report --since 24h --top 5          # delta off by default for any other window
netlog report --since 24h --compare        # force it: 24h against the 24h before it
netlog report --format json | jq .         # one object, a key per section
```

| Flag | Default | |
| --- | --- | --- |
| `--since` | `7d` | `30m`, `2h`, `24h`, `7d`, `today` |
| `--top` | `10` | rows in the noisy-device, watchlist and outage rankings |
| `--compare` | on only for exactly 7 days | force the delta on or off (`--compare=false`) |
| `--format` | `table` | `table` or `json` |
| `--data-dir` | `data` | |
| `--no-color` | | |

Rankings are fully ordered (count descending, then name / address), so output is
stable and diffable. `week_over_week` is `null` in JSON when it was not computed.

Outage pairing needs the interface or neighbor a log line names, which netlog
stores from this version on (`object` in the JSONL); older entries have none and
are counted as "untracked" rather than guessed at.

### Collection health

netlog watches the network and also itself. Every poll updates
`data/.netlog_health.json`, and `netlog status` prints it:

```
DEVICE   STATUS        LAST POLL OK      FAILS  LAST NEW LOGS     DETAIL
dist-2   FAILING       2026-10-23 13:00     47  -                 [CONNECTION_TIMEOUT_OR_UNREACHABLE] ...
quiet-3  SILENT        2026-10-24 18:59      -  2026-10-23 03:00  reachable, but no new log lines since ...
new-4    NEVER POLLED  -                     -  -                 in the inventory but never polled
core-1   OK            2026-10-24 18:59      -  2026-10-24 18:00
```

| Status | Meaning |
| --- | --- |
| `FAILING` | the last poll(s) failed; `FAILS` is the run length |
| `STALE` | nothing has tried to poll it for `--stale-after` (default 24h): is the collector running? |
| `UNPARSEABLE` | reachable, but not one line of the output could be parsed (check the log timestamp format) |
| `SILENT` | reachable, but no new log line for `--silent-after` (default 24h). A very quiet device is not necessarily broken |
| `UNSUPPORTED` | no fetch command for this platform; permanent, not an outage |
| `NEVER POLLED` | in the inventory, never attempted |

`netlog status --fail` exits 1 when any device is not `OK`, for cron and monitoring.
It also reads `inventory.csv` (`--inventory`) to find the devices never polled.

## Configuration

**`inventory.csv`**, one device per line (see `examples/inventory.csv`):

```
hostname,address,port,vendor,credential_group,jump_host
core-sw1,10.10.1.1,22,cisco_ios,site_hcm,
```

**Credentials** come from `.env` and/or the environment, all in the `NETLOG_*`
namespace (see `examples/.env.example`): `NETLOG_USERNAME`, `NETLOG_PASSWORD` or
`NETLOG_KEY_FILE`, optional per-site groups (`NETLOG_SITE_HCM_USERNAME`, ...) and
bastions (`NETLOG_JUMP_HOST`, `NETLOG_JUMP_BASTION_DC_HOST`, ...). The older
`NETBACKUP_*` spellings are still accepted as a deprecated fallback and produce a
one-time warning.

Use a dedicated **read-only** account: netlog never needs more.

## Platforms

| `vendor` value | Log command | Notes |
| --- | --- | --- |
| `vyos` | `show log tail 100` | via the op-mode wrapper |
| `cisco_ios`, `cisco_asa`, `cisco_sb` | `show logging` | needs `service timestamps log datetime` |
| `huawei_vrp` | `display logbuffer` | CMDRECORD gives "who ran what" |
| `juniper_junos` | `show log messages \| last 100` | |
| `fortigate` | `execute log filter category 1` + `execute log display` | interactive session |
| `aruba`, `ruijie`, `arista`, `paloalto`, `generic` | `show logging` (PAN-OS: `show log system`) | best-effort parser |
| `mikrotik` | `/log print` | best-effort parser |
| `pfsense` | `tail -q -n 300 /var/log/system.log /var/log/auth.log` | pfSense 2.5 or newer (plain-text logs); the login needs shell access |
| `checkpoint_gaia` | `tail -n 300 /var/log/messages` | the login's shell must be `/bin/bash` (not `clish`) |

`sophos` is recognised in the inventory but not supported yet; such devices are
skipped with one warning per run (and shown as `UNSUPPORTED` by `netlog status`).

**pfSense and Check Point were written from the platforms' documented log
formats and have not been checked against a live device.** If a version words a
line differently the line is not misparsed, only left `UNKNOWN`. Run
`netlog collect --dry-run`, then `netlog report` and look at the Classification
Coverage section: a high `UNKNOWN %` for `pfsense` or `checkpoint_gaia` means a
rule is missing, and a few sample lines are all that is needed to add it. Triage
playbooks (the read-only diagnostics run after a fault) exist for the other
platforms only; these two are collected and reported but not triaged.

## How it works

```
collect -> parse -> watermark dedup -> clock-skew correction -> classify
        -> append data/logs/YYYY-MM-DD.jsonl -> detect anomalies -> auto-triage
```

- **Watermark.** Each poll returns the whole buffer; per-device state in
  `data/.netlog_state.json` drops what was already stored (exact even for
  identical lines in one second). It only advances after the entries are on disk.
- **Clock skew.** Each poll also reads the device clock, so events from different
  devices land on one coherent timeline. Devices must print their clock and their
  log timestamps in the same time zone.
- **Anomalies.** Link flaps, OSPF/BGP neighbour loss, brute-force logins, VRRP/STP
  changes and high CPU raise triage signals; config changes are remembered so a
  fault shortly after one is annotated with its probable cause. Failed logins
  from one source address on **three or more devices within 10 minutes** raise a
  `PASSWORD_SPRAY_ATTEMPT`: a spray that tries one or two passwords per device
  never reaches the per-device brute-force threshold, and only the fleet-wide
  view sees it. Recoveries (`LINK_UP`, `OSPF_ADJ_UP`, `BGP_PEER_UP`) are stored
  so outages can be measured; HA changes, hardware faults (power, fan,
  temperature) and err-disabled ports are classified and reported but raise no
  triage.
- **Auto-triage safety gates** (compiled in, not configurable):
  1. every command must match a read-only allowlist and contain no blocked word,
     shell metacharacter or unknown pipe filter;
  2. one triage per device and event type per cooldown (5-15 min, persisted
     across cron runs);
  3. resource caps: 5 s connect and command timeouts, 50 KB per command, at most
     4 commands per run, at most 3 concurrent sessions.

## Data layout

```
data/
  logs/YYYY-MM-DD.jsonl        normalized log entries (UTC day)
  incidents/<ts>_<host>_<event>.json
  .netlog_state.json           watermarks
  .netlog_health.json          per-device poll health (netlog status)
  .netlog_cooldown.json        triage cooldowns
  .netlog.lock                 one collector per data directory (Unix)
```

## Dry run

Before committing to your first live poll, verify that every device is reachable,
credentials are correct, and clock skew is within an expected range — without
writing any log files or state:

```sh
netlog collect --dry-run                   # or: ./run --dry-run
```

The table printed to stdout shows one row per device:

```
DEVICE    ADDRESS        VENDOR      STATUS  DURATION  SKEW     NOTES
core-sw1  10.10.1.1      cisco_ios   OK      312ms     +47ms    Connected (buffer: 8214 bytes)
edge-rt1  10.10.2.1      cisco_ios   FAIL    5.001s    -        dial tcp 10.10.2.1:22: i/o timeout
```

- **STATUS** is green `OK` / red `FAIL` on colour terminals.
- **SKEW** is the measured device clock offset (positive = device is fast).
  A large skew means timestamps will be corrected by that amount; check the
  device's NTP / `clock timezone` settings if the offset seems implausible.
- **Exit code** is 0 if at least one device succeeded, 1 if every device failed.
- No files are created or modified in the `data/` directory.

## Development

```sh
make vet test         # go vet + all tests (unit tests and fuzz seed corpora)
make test-race        # race detector (needs cgo)
make fuzz             # explore new fuzz inputs, FUZZTIME=20s per target
make cross            # linux/{amd64,arm64}, windows/amd64, darwin/{amd64,arm64}
make vendor           # go mod tidy && go mod vendor (needs network, run once)
```

Layout:

```
cmd/netlog/            CLI: collect | monitor | query | timeline | incidents | report
internal/collector/    SSH polling, worker pool, clock-skew capture
internal/parser/       per-platform log parsers
internal/pipeline/     watermark, normalizer, classifier, anomaly detector
internal/triage/       allowlist, cooldown, playbooks, engine
internal/store/        JSONL writer, incident files, watermark state
internal/query/        filtering, tables, timeline
internal/report/       rankings, rollups and week-over-week deltas (netlog report)
internal/inventory/    CSV device inventory
internal/credentials/  .env / environment credential resolution
internal/sshclient/    SSH dialer (legacy algorithms, bastions)
internal/errcat/       categorized errors
internal/vendor/       platform-name canonicalization
internal/fsutil/       atomic file writes
```

Requires Go 1.26. Build, `go vet -mod=vendor ./...` and `go test -mod=vendor ./...`
all work offline from `./vendor`.
