# Synthetic base: 50 devices, 2 days of logs

A test base for the whole pipeline. `make_fleet.py` writes two days of logs for 50 machines in the real formats our parsers read, with attacks, harmless look-alikes, approved maintenance and one log source that goes silent. Everything is generated locally and is the same on every run. It uses only `10.24.x.x`, reserved documentation IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `.example` domains. No real data is used.

The device list follows Member 1's inventory, [`backend/data/assets.json`](../../data/assets.json):
- Same names and IPs (`ws-base-014`, `srv-gate-ctrl-01`, `srv-auth-01`, `srv-backup-02`).
- Their accounts exist.
- If an IP clashes with another device, the generator stops with a clear message.

## Run it (from the repository root)

```bash
python backend/soc/fleet/make_fleet.py                 # logs in backend/soc/fleet/logs (+ logs_ecs), ~5 s
python backend/soc/fleet/check_logs.py                 # sanity checks
python backend/correlation.py backend/soc/fleet/logs   # SOC report in backend/soc/fleet/logs/out/
python -m frontend --logs backend/soc/fleet/logs       # dashboard on the 50-device base
```

Options: `--out DIR` (another folder), `--no-ecs` (skip the ECS copy), `--legacy` (only the six original sources in `sources.yaml`).

The generated folders (`logs/`, `logs_ecs/`, `engine-out/`) are about 65 MB and are not committed, because one command rebuilds them. CI builds the base in a temporary folder and checks the engine against `truth.json` (`backend/soc/tests/test_fleet_scenario.py`).

## Devices
- **28 Windows workstations:** `WS-BASE-001`…`028`. 012–014 are also used by the night shift.
- **6 Windows servers:** `srv-auth-01` (domain controller + Kerberos), `DC-02`, `FS-01`, `WSUS-01`, `JUMP-01`, `PRINT-01`.
- **10 Ubuntu servers:** `srv-gate-ctrl-01/02`, `srv-logistics-db`, `srv-c2-app`, `srv-web-01`, `srv-mail-01`, `srv-proxy-01`, `srv-dns-01`, `srv-backup-02`, `srv-mon-01` (monitoring, Zeek sensor, vulnerability scanner).
- **4 gate controllers and 2 network devices:** no logs of their own. Their traffic appears in the servers' logs and in Zeek.

## Log sources (`logs/`)
| File | Format | Parser |
|---|---|---|
| `<HOST>_events.jsonl` | Windows Security/System (JSON lines, UTC) | `windows_events` |
| `<HOST>_pfirewall.log` | Windows host firewall (local time UTC+1) | `windows_firewall` |
| `<HOST>_sysmon.jsonl` | Sysmon 1/3/11 (JSON lines, UTC) | `windows_sysmon` |
| `<host>_auth.log`, `_ufw.log`, `_syslog` | Ubuntu (ISO time, UTC) | `linux_auth` / `linux_ufw` / `linux_syslog` |
| `<host>_dpkg.log` | Ubuntu packages (UTC+1) | `linux_dpkg` |
| `srv-mon-01_zeek-conn.log` | Zeek conn.log, JSON (network flows) | `zeek_conn` |
| `srv-mail-01_mailgw.jsonl` | Mail security gateway verdicts, JSON | `mail_gateway` |
| `fw-edge-01_filterlog.log` | Perimeter firewall (pfSense filterlog CSV): every connection to or from the internet | `pfsense_filterlog` |

Each log folder also holds the engine settings: `sources.yaml`, `assets.yaml` and `maintenance.yaml`. `truth.json` is the answer key: every planted line with its ATT&CK techniques. `logs_ecs/` holds one ECS 8.x document per raw line, for Sigma, ES|QL and similar tools.

## Depth: who, where, what is allowed
- **Users** (`assets.yaml` → `users`): operators, night-shift gate operators, helpdesk, IT admin (daily + `adm.win` / `adm.ops` admin accounts), a sealed domain admin, a DB admin, and service accounts (some with Kerberos SPNs). Each has a role, groups, `privileged`, and a home machine. `privileged_groups` lists the groups that matter.
- **Zones** (`zones`): NETDEV, CORE (DCs, DNS, jump host), SERVERS, USERS, DMZ, DATA, APP, OT (gate control).
- **Zone policy** (`zone_policy`): which zone or host may reach which, on which ports (for example, only the jump host administers servers; users never reach OT or DATA directly). Anything else between zones is a violation.
- **Perimeter firewall** `fw-edge-01`: passes and blocks for all internet traffic, including a forgotten RDP port-forward (used in A1).

## What happens on day 2 (2026-11-22)
Day 1 (2026-11-21) is normal operations only: it is the baseline.

| ID | What | ATT&CK |
|---|---|---|
| A1 | The challenge's night chain: RDP brute force on WS-BASE-014 → SSH to srv-gate-ctrl-01 → new service, firewall opened, new account, firewall logging off, port 4444 traffic, Windows log cleared | T1110.001, T1078, T1059.003, T1021.004, T1543.002, T1562.004, T1136.001, T1571, T1070.001 |
| A2 | SSH password spraying on srv-web-01 from outside | T1110.003 |
| A3 | Unknown device logs on to srv-logistics-db and dumps the database | T1200, T1078, T1005 |
| A4 | Phishing .docm → PowerShell → payload → scheduled task → beacons to 203.0.113.77:443 | T1566.001, T1204.002, T1059.001, T1105, T1053.005, T1071.001, T1573 |
| A5 | **Domain takeover → ransomware**: RDP password guessing on WS-BASE-021 → LSASS dump (comsvcs MiniDump) → adm.win's hash used on DC-02 (NTLM, PsExec) → new account added to Domain Admins → PsExec to FS-01 → shadow copies deleted → 150 files encrypted + ransom note | T1110.001, T1078, T1003.001, T1550.002, T1021.002, T1569.002, T1098, T1490, T1486 |
| A6 | **Kerberoasting → data theft**: 4 RC4 service tickets in 20 s from WS-BASE-009 → cracked svc_sql logs on to the logistics DB by SSH (zone violation) → pg_dump + root shell → 486 MB uploaded at night | T1558.003, T1078, T1021.004, T1005, T1548.003, T1048 |
| A8 | **Bot swarm**: 60 internet addresses hit the web portal within 90 s; the perimeter drops them | T1498 |
| B1 | Harmless: 6 mistyped passwords, then success | – |
| B2 | Harmless: night admin RDP and a new service on DC-02, under emergency ticket CHG-2026-1122-03 | – |
| B3 | Harmless: weekly authenticated vulnerability scan (CHG-VULNSCAN-WEEKLY) | – |
| B4 | Harmless: malware mail campaign, quarantined by the gateway | – |
| – | Harmless: daily PowerShell inventory script on every workstation (both days) | – |
| B5 | Harmless: admin PsExec from JUMP-01 to PRINT-01 + helpdesk RDP to WS-BASE-021, under ticket CHG-2026-1122-04 | – |
| B6 | Harmless: helpdesk adds a colleague to 'Gate Operators' (not a privileged group) | – |
| – | Harmless: Kerberos AES tickets at every logon; adm.ops root shell on every Linux server from the jump host; ~250 internet scans a day dropped at the edge | – |
| Maintenance | Patching CHG-2026-1122-01 (01:00–03:00), web firewall change CHG-2026-1122-02, nightly backup | – |
| Silent source | `srv-gate-ctrl-01` ufw log is silent 02:05–04:30 (A1 turns logging off). Zeek still sees the traffic. | – |

## Current engine result
| | Result |
|---|---|
| Attacks | A1–A4 each become one incident: A1 P1, A4 P1, A3 P2, A2 P3 |
| Maintenance | Patching, backup, firewall change, scan and emergency change: 1,450 alerts suppressed |
| Source health | Only the gate firewall log is reported silent. A1's confidence drops to 75% with that reason. |
| False incidents | 1 (B1, the mistyped passwords) |
| Time to flag | 0 min after each incident's last event |
| Speed | ~4 s for ~47,000 events |
