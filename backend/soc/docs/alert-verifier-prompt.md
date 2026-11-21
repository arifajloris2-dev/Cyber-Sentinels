# Implementation prompt: Alert Verification Engine (Cyber Sentinels)

> Paste everything below into a Claude coding session opened at the root of the `Cyber-Sentinels` repository
> (`git pull` first). It is an implementation brief: build, test and document the component; do not stop at a design.

---

You are a senior Python engineer and SOC detection specialist joining a hackathon team (European Defense Tech
Hackathon). The project is a fully offline, multi-agent cyber-defence system for a simulated military base. Your job
is to add one component, the **Alert Verification Engine**, to the existing code base, implement it, test it, and
document it. Work on the local `main` branch; commit locally when done. **Do not push**: the owner pushes.

## 1. What already exists (read these files before writing any code)

The "AI monitoring agent" in the original brief **is the SOC engine in `backend/soc/`**. Its output is the input of
your component. Do not invent another alert format, do not re-implement detection.

| Part | Where | What it gives you |
|---|---|---|
| SOC engine | `backend/soc/pipeline.py` → `run(folder: Path) -> dict` | `incidents`, `singles`, `alerts`, `suppressed`, `maintenance`, `health`, `agents`, `intel`, `cfg`, `event_list` |
| Detection agents | `backend/soc/agents/*.py`, rules in `backend/soc/rules/*.yaml` | 9 agents (Windows host, Sysmon, Linux, host firewall, perimeter, Zeek, mail, management plane, service health) and ~40 deterministic rules |
| Maintenance filter | `backend/soc/noise.py`, `maintenance.yaml` in each log folder | approved change tickets; events covered by a ticket are already set aside (`suppressed`) |
| Context | `assets.yaml` in each log folder | assets (role, criticality), `users` (role, groups, privileged, home machine, service accounts), `privileged_groups`, `zones`, `zone_policy`, `admin_ips` |
| Correlation | `backend/soc/correlate.py` | incidents with `id, priority, score, title, start, end, stages, confidence, confidence_reasons, hosts, users, unknown_ips, attack, alerts, links, why_together, next_checks, path, escalation, compromised_accounts, story`; compromised accounts are already followed for 12 h |
| Duplicate merge | `backend/soc/dedupe.py` | one fact = one alert (field `also` lists what was folded in) |
| Source health | `backend/soc/health.py` | `health[]`: `source, host, ok, silent[]` (a log that stopped writing while it normally writes) |
| Threat intel | `backend/soc/intel.py`, `backend/soc/knowledge.py` | OSINT + operator-imported CVEs / indicators attached to incidents as `incident["intel"]` |
| AI analyzer | `AI_Log_Analyzer/ai_log_analyzer.py` | `build_dashboard_incident(incident, threat_findings, sources, advisories) -> (payload, evidence_refs)` and `analyze_incident(payload, base_url, model, timeout, retries) -> dict` (local Ollama, qwen3:4b, 1–2 min per incident on a laptop CPU) |
| Dashboard | `frontend/app.py`, `frontend/data_provider.py`, `frontend/models.py` | NiceGUI console; "Close incident / Close alert" exists but is **session-only** (`DashboardPage.closed_incidents`, `closed_alerts`) |
| Test data | `backend/soc/fleet/make_fleet.py` (50 devices, `truth.json` answer key), `backend/soc/lab_logs/`, `backend/soc/scenarios/{ka_sat,kosovo_ddos}/`, `backend/soc/sample_logs/` | known attacks, look-alikes, maintenance and a silent log source |
| Tests | `backend/soc/tests/`, `frontend/tests/`, `AI_Log_Analyzer/test_validation.py` | run: `$env:PYTHONPATH="backend"; .venv\Scripts\python.exe -m pytest frontend/tests AI_Log_Analyzer/test_validation.py backend/soc/tests -q` (all must stay green) |

Read at least: `backend/soc/README.md`, `pipeline.py`, `correlate.py`, `health.py`, `noise.py`, one log folder's
`assets.yaml` + `maintenance.yaml` (generate the fleet first: `python backend/soc/fleet/make_fleet.py --no-ecs`),
`AI_Log_Analyzer/ai_log_analyzer.py` (the two functions above), `frontend/app.py` (incident detail + close logic) and
`backend/soc/tests/test_soc.py::test_engine_cannot_act_on_systems`.

## 2. What to build

A **deterministic verification layer on top of the SOC engine's incidents**. It does not detect; it judges what the
engine found, explains the verdict, keeps an audit trail, and decides which incidents the AI should explain.

For every incident (and optionally every single alert) produce:

| Verdict | Meaning |
|---|---|
| `suspicious` | evidence supports possibly malicious activity |
| `inconclusive` | not enough, missing or contradictory evidence to decide |
| `likely_benign` | strong evidence of authorized activity |

with `reasons` (each: rule id, short text, evidence ids like `source:line`) and `forward_to_ai` (True for
`suspicious` and `inconclusive`, False for `likely_benign`). `likely_benign` is recorded with its explanation, never
silently dropped.

### Verification principles (encode them as rules, test them)
- An unusual event is not automatically an attack; a successful login does not prove compromise; a legitimate
  account can still be compromised.
- Activity inside a maintenance window is not automatically safe (the ticket must ALSO cover what was done: the
  engine already does this; do not weaken it).
- **Missing evidence is never proof of normal behaviour**: a silent or missing log source on an incident host, or
  contradictory evidence → `inconclusive` at best, never `likely_benign`.
- **High-risk events are never dismissed**: any alert with severity ≥ 8, or a rule in a configurable "never benign"
  list (credential theft CRED-*, privilege escalation PRIV-001, pass-the-hash LAT-002, ransomware IMP-*, exfiltration
  EXF-001, log clearing SYS-004, imported indicator IOC-001), forces `suspicious`.
- `likely_benign` requires positive evidence: e.g. every account involved is an authorized user for the hosts involved
  (roles/groups/home machine from `assets.yaml` `users`), no compromised accounts, no unknown addresses, no zone-policy
  violation (NET-008), no rule from the never-benign list, all log sources healthy, and (where configured) the activity
  matches an authorized activity in `verification_rules.json`.
- Everything else with weak or single-source evidence → `inconclusive`.

### Configuration: `backend/soc/verification_rules.json` (JSON, documented, versioned)
- `never_benign_rules`, `high_risk_severity` (default 8)
- `authorized_activities`: list of `{account|role, hosts|zones, rules_expected, hours (optional)}` (e.g. adm.ops root
  shell from JUMP-01; helpdesk group changes to non-privileged groups)
- `inconclusive_when`: silent source on an incident host, evidence from one source only, confidence below a threshold
- thresholds used by the verdict, each with a one-line comment field (`"why"`)

Do not duplicate users, zones or maintenance tickets: read them from the log folder's `assets.yaml` /
`maintenance.yaml` (`run()` returns them in `cfg`).

### Audit log
- Append-only JSON Lines file, default `backend/data/audit/verification.jsonl` (create the folder; add a
  `.gitignore` so audit data stays local).
- One line per decision: timestamp (UTC), incident id, verdict, reasons, evidence ids, rule-set version/hash,
  engine run id, and `actor` (`"verifier"` for automatic verdicts). Also provide a function to record a **human**
  decision (`actor: "operator"`, action `close` / `reopen` / `override`, reason, note).
- Never rewrite or delete lines (the engine is not allowed to call `unlink`/`rmtree`; see the safety test).
- Repeated runs on the same data must not write duplicate lines for an unchanged verdict (key: incident id + verdict
  + evidence hash).

### AI forwarding (no new analyzer)
- Do not rewrite `ai_log_analyzer.py`. Add a small function (in your module) that, for incidents with
  `forward_to_ai=True`, builds the payload with the existing `build_dashboard_incident(...)` and calls the existing
  `analyze_incident(...)`; make the analyzer call **injectable** so tests never need Ollama.
- If Ollama is unavailable, record `ai: "unavailable"` with the error and keep the verdict; never crash.
- The AI's `triage_assessment` is shown next to the verdict but **never changes it**.

### Dashboard (small, careful changes in `frontend/`)
- Show the verdict as a badge on each incident card and in the incident header, with the reasons in the
  "Checks & intel" tab.
- Make Close / Reopen also write an operator line to the audit log (the on-screen hiding stays session-only, as the
  owner wants), and add an "Audit" list (last 50 decisions) to the Alerts view.
- Only auto-generate AI explanations for `forward_to_ai=True` incidents; `likely_benign` gets the rule-based
  overview and a "Explain anyway" button.

## 3. Files

- `backend/soc/verify.py`: verdict logic, rule loading, audit log, AI forwarding (keep it one readable module,
  ~300–400 lines; split only if clearly needed).
- `backend/soc/verification_rules.json`: configuration.
- `backend/soc/pipeline.py`: add verdicts to `run()` output (`incident["verification"] = {...}`) without changing
  existing fields.
- `backend/soc/report.py`: a "Verdict" line per incident in `report.md`; write `verification.json`.
- `frontend/app.py`, `frontend/data_provider.py`, `frontend/models.py`: the UI changes above.
- `backend/soc/tests/test_verifier.py`: tests.
- `backend/soc/README.md`: a "Verification" section (how verdicts are decided, config, audit log).

No new frameworks, databases or services. Standard library + what `requirements.txt` already has.

## 4. Tests that must pass (use the existing data, not new fake formats)

Map the team's scenarios to data that already exists:

| Scenario | Data | Expected |
|---|---|---|
| A: SSH / RDP brute force then success | fleet A1 (night chain), fleet A2 (spraying, no success), sample_logs | A1 `suspicious`; A2 `suspicious` or `inconclusive` (never benign) |
| B: phishing | fleet A4 (macro → PowerShell → beaconing), lab_logs click on a phishing link | `suspicious` |
| C: authorized activity | fleet look-alikes: PsExec under ticket CHG-2026-1122-04, helpdesk group change (B6), adm.ops daily root shell, the mistyped-password single alert (B1) | never escalated: `likely_benign` (or not an incident at all) |
| D: suspicious post-login behaviour | fleet A5 (LSASS dump → pass-the-hash → Domain Admins → ransomware), A6 (Kerberoasting → DB → exfiltration) | `suspicious`, with the never-benign rules named in the reasons |
| E: missing evidence | fleet A1 (gate firewall log silent 02:04–04:30); also a copy of a log folder with one source file removed | `inconclusive` reason present; never `likely_benign` |

Plus:
- high-risk events are never dismissed (severity ≥ 8 or never-benign rule → `suspicious`), proven by a synthetic
  incident that otherwise looks authorized;
- duplicate runs don't duplicate audit lines; duplicate alerts stay merged (dedupe is already upstream);
- invalid input (missing fields, wrong types, broken JSON config) gives a clear error/`inconclusive`, never a crash;
- the analyzer receives the payload produced by `build_dashboard_incident` (inject a fake analyzer and assert on it);
  only `forward_to_ai=True` incidents are sent;
- offline: no network imports in `backend/soc` (the existing `test_engine_cannot_act_on_systems` must still pass)
  and the verifier never blocks, disables, executes or modifies anything;
- false-positive reduction: on the 50-device base, the 7 planted attacks are `suspicious` and no look-alike is
  `suspicious`.

## 5. Constraints and done criteria

- Python 3.10+, runs on Windows and Kali Linux, fully offline, no cloud calls, no autonomous actions.
- Deterministic: the same logs give the same verdicts. Clear error handling and logging.
- Keep it small and demonstrable; prefer a working, tested prototype over extra features.
- Done when: all existing tests + your new tests pass, `python backend/correlation.py backend/soc/fleet/logs` shows
  verdicts in `report.md` and `verification.json`, the dashboard shows verdict badges and the audit list, Close/Reopen
  writes audit lines, and the README section exists. Commit locally with a clear message; do not push.
- If something you need is genuinely missing, implement against the existing interfaces anyway, state the gap
  clearly in the README and your final message, and do not claim an integration you did not test.
