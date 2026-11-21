# SOC engine (Member 2: SOC Detection & Correlation)

Detection and correlation for **Windows and Ubuntu** logs. It reads the logs, finds suspicious behaviour with
fixed rules, ignores approved maintenance, joins related events from different machines into **one incident**,
and keeps the evidence for every step.

Runs locally and offline (Python only, no network calls). It only **reports**: it never blocks, isolates or
changes anything on any machine. The operator decides.

![How the SOC engine works](docs/soc-map.svg)

## Quick start (from the `backend/` folder)

```bash
python -m venv .venv
.venv\Scripts\activate                 # Ubuntu: source .venv/bin/activate
pip install -r soc/requirements.txt

python -m soc sample                   # sample logs (Windows + Ubuntu, 48 h) in soc/sample_logs
python detection.py soc/sample_logs    # stage 1: alerts
python correlation.py soc/sample_logs  # stage 2: incidents -> soc/sample_logs/out/report.md + JSON
python -m soc replay soc/sample_logs   # how fast is the incident flagged?
python -m pytest soc/tests -v          # check everything works
```

## For the other parts of the project

```python
from detection import detect        # backend/detection.py
from correlation import analyse     # backend/correlation.py

alerts = detect("soc/sample_logs")["alerts"]
incidents = analyse("soc/sample_logs")["incidents"]   # JSON-ready: for llm_advisor.py and main.py
```

## How it works

| Step | File | What it does |
|---|---|---|
| 1. Parse | `soc/parsers.py` | Turns each log type into events with the same simple fields (`time, host, user, src_ip, dst_ip, action…`). Every event keeps its file, line number and original text (evidence) |
| 2. Context | `soc/detect.py` (`enrich`) | Adds: IP → known machine and role, internal or internet, night or day, admin source, how critical the host is, visitor on a public service |
| 3. Maintenance | `soc/noise.py` | Events covered by an approved change ticket (patching, backup, scans) are tagged and kept aside, never deleted. Network-sensor flows are judged by the machines at both ends |
| 4. Detect | `soc/detect.py` + `soc/rules/*.yaml` | Runs the rules (see below) |
| 5. Source health | `soc/health.py` | Notices when a log stops writing at a time of day it normally writes (learned from the baseline), so the incident can say it may be missing events. A log that is quiet every night is not silent |
| 6. Correlate | `soc/correlate.py` | Links alerts with the same account, unknown address or host within 60 min into one incident: entry → execution → lateral movement → command and control → impact. Weak alerts (severity < 5) link only by account or unknown address, so a busy server cannot glue unrelated alerts together. After a guessed or stolen logon (AUTH-001/002, CRED-*, LAT-002) the account is treated as compromised and **followed for 12 h**, so what it did next joins the incident. Each incident also gets `path` (machine-to-machine hops with account and port), `escalation` (rights gained or stolen), `compromised_accounts` and `story` (the incident in plain words, built only from the rules' findings). Adds ATT&CK, a score (P1–P3), a confidence with reasons, and suggested checks |
| 7. Threat intel | `soc/intel.py` | Joins the OSINT agent's findings (Member 1, `osint_output.json`) to incidents: a CVE on an affected host whose ATT&CK technique the incident shows, or a leaked account used in the incident. Raises the score a little, adds checks, and answers every OSINT hunt request (found in which incident, or nothing in the logs). Intel never creates an incident by itself |
| 8. Report | `soc/report.py` | `report.md` for people; `incidents.json`, `alerts.json`, `suppressed.json`, `health.json`, `intel.json` for other tools |

## Agents (`soc/agents/`)

One specialised agent per kind of system. Each owns the log formats of its system, learns its normal level from the
baseline day, and reports **what it saw** (`agents.json`, the "What each agent saw" part of `report.md`, and
`agents` in `correlation.analyse()`): volume against normal, approved-maintenance events it set aside, alerts it
raised, the incidents those fed, silent sources, and plain-language highlights.

| Agent | Reads | Typical highlights |
|---|---|---|
| Windows host | Security/System events | logons ok/failed, RDP, Kerberos tickets (RC4), services, accounts, privileged-group changes, admin shares |
| Endpoint (Sysmon) | Sysmon 1/3/10/11 | processes, connections, files, LSASS opened, programs started by Office, busiest file writer |
| Linux host | auth.log, syslog, dpkg | SSH ok/failed, sudo, root shells by non-admins, services, packages |
| Host firewall | pfirewall.log, ufw.log | allowed/blocked, NEW zone-policy violations vs known exceptions |
| Perimeter firewall | pfSense filterlog | inbound passed/blocked, most targeted, inbound to non-public ports |
| Network sensor (Zeek) | conn.log | flows, to the internet, failed, largest upload |
| Mail | gateway log, mail events | delivered/quarantined, risky attachments, clicks |
| Management plane | management-gateway sign-ins and config changes (`management_events`) | sign-ins from unfamiliar sources, unscheduled privileged changes, service loss |
| Service health | public-service health samples (`portal_health`) | traffic, latency and errors vs the first sample, failed availability checks |

**Add a system:** add one file `soc/agents/<name>.py` with `AGENT = Agent(name, title, watches, {parser: function}, highlights)`
(the parse function can live in the same file) and, if needed, a rules file in `soc/rules/`. Nothing else changes.
Agents only observe and report; none of them blocks or changes anything.

## Feeding new knowledge (plain text only)

The base is offline, so new vulnerabilities and indicators are imported by the operator in the dashboard
(**Knowledge import** view): upload a `.txt` file or paste text, press **Check**, review what is accepted and
rejected, then **Import**. Format: `Key: value` lines, blocks separated by an empty line:

```
CVE: CVE-2026-31337        Product: GateControlService   Versions: 2.4.0   KEV: yes   EPSS: 0.88
Techniques: T1543, T1562   Hosts: srv-gate-ctrl-01        Summary: ...      Reference: https://...
IP: 203.0.113.99 | Domain: bad.example | Hash: <hex> | Account: svc_sql    (+ Note:, Source:)
```

- **CVE** → a vulnerability finding (matched to `backend/data/assets.json` software or the named hosts), attached
  to incidents that show its techniques, and given to the local AI as knowledge when it explains an incident.
- **IP / Domain / Hash** → rule **IOC-001** flags every log line containing it. **Account** → attached to incidents
  using it.
- **Safety:** only UTF-8 text (no binary, no control characters, size limits); only the listed keys; every value
  checked against a strict pattern; nothing executed, opened or fetched; the stored copy in `backend/data/knowledge/`
  is rebuilt from the checked fields with the submitted SHA-256, re-checked on every load, and kept out of git.
  Withdrawing an import renames it to `.removed` (audit trail); log files are never touched.
  The local model is not retrained: it gets the knowledge as context each time it explains.

## Logs it reads

| Machine | Log | Parser | Collect with |
|---|---|---|---|
| Windows | Security + System events (JSON lines) | `windows_events` | `soc/collect/collect_windows.ps1` |
| Windows | Firewall log `pfirewall.log` | `windows_firewall` | same script |
| Ubuntu | `/var/log/auth.log` (SSH, sudo, new users) | `linux_auth` | `soc/collect/collect_linux.sh` |
| Ubuntu | `/var/log/ufw.log` (firewall) | `linux_ufw` | same script |
| Ubuntu | `/var/log/syslog` (services started) | `linux_syslog` | same script |
| Ubuntu | `/var/log/dpkg.log` (updates) | `linux_dpkg` | same script |
| Windows | Sysmon: process created (1), network connection (3), file created (11), JSON lines | `windows_sysmon` | export like the Security log |
| Network sensor | Zeek `conn.log` (JSON or default TSV) | `zeek_conn` | Zeek on a SPAN/mirror port |
| Mail gateway | Verdict log, JSON lines (`ts, direction, client_ip, from, to[], subject, attachments[], verdict, action`) | `mail_gateway` | gateway export |
| Mail events | JSON lines (`timestamp, event: email_delivered/url_clicked, user, message_id, verdict, url`) | `mail_events` | lab demo |
| Perimeter firewall | pfSense `filterlog` (syslog + CSV) | `pfsense_filterlog` | firewall syslog export |

See `soc/collect/README.md` for the one-time setup on each machine.

## Rules (`soc/rules/*.yaml`)

| Rule | Detects | ATT&CK |
|---|---|---|
| AUTH-001 | Failed, then successful remote logon (RDP or SSH) | T1110, T1078 |
| AUTH-002 | Remote logon from an address not in `assets.yaml` | T1078 |
| AUTH-003 | Password guessing: 5+ failures in 10 min | T1110.001 |
| AUTH-004 | First network logon of an account to a host | T1021 |
| NET-001 | New outbound connection to an internal machine | T1021 |
| NET-002 | New inbound connection accepted (outside visitors on a port in `public_services` are normal) | T1021 |
| NET-003 | 20+ blocked connections from one address in 10 min | T1046 |
| NET-004 | Possible bot swarm: 8+ distinct blocked sources target one system in 2 min | T1498 |
| NET-005 | Beaconing: 6+ connections from a workstation to one internet address in 60 min (sensor) | T1071.001, T1573 |
| NET-006 | Traffic to an internal service port never used in the baseline (sensor) | T1571 |
| NET-007 | Workstation connects straight to the internet, not via the proxy | T1071.001 |
| PROC-001 | Office application starts PowerShell/cmd/script host (Sysmon) | T1204.002, T1059.001 |
| PROC-002 | Encoded or hidden PowerShell command (Sysmon) | T1059.001 |
| PROC-003 | Scheduled task created by a user account (Windows 4698) | T1053.005 |
| PROC-004 | Program file written into a user profile (Sysmon) | T1105 |
| MAIL-001 | Mail with a risky attachment (.docm, .js, .iso, …) delivered to a user | T1566.001 |
| MAIL-002 | User clicked a link in a mail flagged as phishing | T1566.002, T1204.001 |
| CRED-001 | A process opened LSASS memory (credential dumping, Sysmon 10) | T1003.001 |
| CRED-002 | Credential dumping command (comsvcs MiniDump, procdump on lsass, mimikatz) | T1003.001 |
| CRED-003 | Kerberoasting: 3+ RC4 service tickets for different service accounts in 10 min | T1558.003 |
| LAT-001 | Remote execution service installed (PsExec and similar) | T1569.002, T1021.002 |
| LAT-002 | Pass-the-hash pattern: privileged account, network logon, NTLM, key length 0 | T1550.002 |
| LAT-003 | Admin share (ADMIN$, C$) opened from a workstation | T1021.002 |
| NET-008 | Connection between zones that the zone policy does not allow | T1021 |
| PRIV-001 | Account added to a privileged group (`privileged_groups`) | T1098 |
| PRIV-002 | Root shell or sudo-group change by an account that is not an admin | T1548.003 |
| PRIV-003 | Privileged account used from a machine it never used in the baseline | T1078.002 |
| AUTH-005 | Service account used for an interactive or SSH logon | T1078 |
| IMP-001 | Shadow copies or backups deleted (ransomware preparation) | T1490 |
| IMP-002 | 50+ files rewritten with an encrypted extension by one process in 5 min | T1486 |
| EXF-001 | Internal machine uploaded 50 MB+ to an internet address in one connection | T1048 |
| MGMT-001 | Admin sign-in from an unfamiliar source, then an unscheduled privileged change (same session) | T1133, T1078, T1072 |
| MGMT-002 | Service degraded after an unscheduled privileged change | T1489 |
| SVC-001 | Traffic, latency and server errors rising together while checks still pass (DDoS early warning) | T1498, T1499.002 |
| SVC-002 | Availability check failed | T1499.002 |
| IOC-001 | Activity involving an imported indicator (IP, domain or file hash) | T1071.001 |
| SYS-001 | New service installed (Windows) | T1543.003 |
| SYS-002 | Service started that never ran before (Ubuntu) | T1543.002 |
| SYS-003 | Firewall rule or setting changed | T1562.004 |
| SYS-004 | Security log cleared or audit policy changed | T1070.001, T1562.002 |
| SYS-005 | New local account created | T1136.001 |

"New" / "never before" means: not seen during the baseline (the first 24 h of logs). Night hours raise the severity.

**Add a rule:** add it to a YAML file in `soc/rules/`. Types include `match` (one event), `threshold` (N events in a
window), `distinct_threshold` (N unique values for one target), `sequence` (steps in order, same values), and
`new_value` (never seen in the baseline). No code needed.

**Add a log type:** write one `parse_...` function in `soc/parsers.py` and add it to `PARSERS`.

## Settings (in the log folder)

| File | Contains |
|---|---|
| `sources.yaml` | Which file is which: parser, host, `utc_offset` for logs in local time, how often it normally writes |
| `assets.yaml` | Known machines: host, IP, role, criticality (1–5); admin IPs; night hours; optional `internal_nets` (CIDRs, default the private ranges) and `public_services` (`[{host, ports}]`: ports a server offers to the internet on purpose); optional `users` (`[{user, role, groups, privileged, home}]`), `privileged_groups`, `zones` (`[{name, cidr}]`) and `zone_policy` (`[{from, to, ports}]`, zone/host/"any") |
| `maintenance.yaml` | Approved change tickets: hosts, time window, and what each is allowed to do |
| `osint_output.json` (optional) | Threat intel from `backend/osint_agent.py`. If the log folder has none, `backend/data/osint_output.json` is used |

Start from the files in `soc/sample_logs/` (2 machines). For a full base (50 devices, 2 days, 4 attacks, maintenance, a
silent log source, answer key) run `python backend/soc/fleet/make_fleet.py`: see [`fleet/README.md`](fleet/README.md). Real logs from the team's lab VMs
(anonymised) are in [`lab_logs/`](lab_logs/README.md); the team's KA-SAT-inspired and Kosovo DDoS replays are in
[`scenarios/`](scenarios/README.md). Later the machine list can come from `backend/data/assets.json` (Member 1).

## Output for the rest of the project

`analyse()` in `backend/correlation.py` (or `out/incidents.json`) is the hand-over to `llm_advisor.py` (Member 3) and `main.py` / the dashboard (Member 5). Each incident has:
`id, priority, score, title, start, end, stages, confidence, confidence_reasons, hosts, users, unknown_ips,
attack (ATT&CK techniques), alerts (each with its raw evidence lines), links (why they belong together), next_checks`.

## Tested (sample logs: Windows laptop + Ubuntu server)

| Criterion | Result |
|---|---|
| Whole attack (entry → lateral movement → impact) in one incident | ✅ 1 incident, P1, 9 alerts from Windows and Ubuntu |
| Time to flag after the last event | ✅ within the same minute (target < 10 min) |
| False incidents without an attack | ✅ 0 |
| Patching and backup | ✅ fully suppressed, attacker inside the patch window still found |
| A log source goes silent | ✅ still detected; confidence 75% with the reason |
| No automatic action | ✅ a test checks the engine cannot run commands, delete files or use the network |
| Speed | ✅ ~0.2 s for 48 h of logs |

## Layout

```
backend/
  detection.py          stage 1 entry point: alerts
  correlation.py        stage 2 entry point: incidents
  soc/
    parsers.py          Windows + Ubuntu logs -> common events
    detect.py           context + rule engine
    noise.py            approved maintenance kept aside
    health.py           silent log sources
    correlate.py        incidents, evidence, confidence, suggested checks
    pipeline.py         runs the two stages
    report.py           report.md + JSON
    attack.py           local MITRE ATT&CK table
    sample.py           sample log generator
    sample_logs/        generated sample logs + settings
    rules/              detection rules (YAML)
    collect/            read-only log collectors (Windows, Ubuntu)
    tests/              test_soc.py
    docs/               soc-map.svg
```
