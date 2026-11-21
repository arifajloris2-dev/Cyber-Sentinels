# For Member 5: agent activity and attacker path on the dashboard

The SOC engine now returns two new kinds of data. The dashboard only has to show them; nothing has to be computed in
the frontend. Both are already in `backend.soc.pipeline.run(folder)`, the result `SocPipelineProvider` uses, and in
`correlation.analyse()` and the files `agents.json` / `incidents.json`.

## 1. `result["agents"]`: what each agent saw (one entry per agent)

| Field | Example | Show as |
|---|---|---|
| `agent`, `title`, `watches` | `host_firewall`, "Host firewall agent" | card title |
| `sources`, `hosts` | 44 sources on 44 hosts | small grey line |
| `events_today` | 14104 | big number |
| `normal.per_hour`, `today.per_hour`, `today.change_pct` | 505.7 → 587.8 /h, +16 % | "+16 % vs normal" (red if > +50 %) |
| `maintenance_filtered` | 2253 | "2,253 approved-maintenance events set aside" |
| `alerts`, `alerts_by_rule`, `top_alerts[]` | 16; `{"NET-008": 3, ...}`; 3 strongest with `rule, severity, time, text` | badge + expandable list |
| `incidents` | `["INC-20261122-1604", ...]` | chips; click selects the incident |
| `silent_sources` | `["srv-gate-ctrl-01-ufw"]` | amber warning |
| `highlights` | `["11822 connections allowed, 29 blocked", "4 NEW kinds of connection between zones ... DC-02 -> FS-01:445; ..."]` | bullet list: the main content of the card |

Agents, in order: Windows host, Endpoint (Sysmon), Linux host, Host firewall, Perimeter firewall, Network sensor (Zeek), Mail.
A set without a log type simply has no card for it (for example `lab_logs` has no perimeter agent).

Suggested panel "AGENTS": one compact card per agent in a grid (7 cards), each with title, events today and trend,
alert badge, highlights, and incident chips. When an incident is selected, highlight the cards whose `incidents`
contain it ("seen by: Windows host, Endpoint, Host firewall, Network sensor").

## 2. New fields on every incident

| Field | Example | Show as |
|---|---|---|
| `story` | "It started at 16:04 UTC with: ... The activity moved WS-BASE-019 -> WS-BASE-021 -> DC-02 -> FS-01. Rights gained or stolen: 16:09 credential dumping command; ... Impact: files encrypted (ransomware)." | text block at the top of the selected incident (rule-based, available instantly; the AI explanation stays below it) |
| `path[]` | `{from: "WS-BASE-021", to: "DC-02", first, accounts: ["adm.win"], ports: [445], seen_by: [...]}` | horizontal chain of host boxes with arrows; label each arrow with port and account; tooltip = `seen_by` |
| `escalation[]` | `{time, rule, what: "pass-the-hash", detail}` | red timeline "Rights gained or stolen" |
| `compromised_accounts` | `["adm.win", "z.haliti"]` | red account chips ("followed for 12 h") |
| `stages` | can now also contain `credential theft` and `privilege escalation` | the existing stage badges already handle any value |

## Where the data comes from in `frontend/data_provider.py`
`SocPipelineProvider.load()` already calls `run(self.log_dir)`; add `"agents": result.get("agents", [])` to the
mapping and an `agents: list[Record]` field to `DashboardSnapshot` (models.py). The incident fields come through
unchanged with the incidents.

## Try it
```powershell
python backend/soc/fleet/make_fleet.py --no-ecs
python -m frontend --logs backend/soc/fleet/logs --port 8090
python backend/correlation.py backend/soc/fleet/logs     # backend/soc/fleet/logs/out/agents.json, incidents.json
```
