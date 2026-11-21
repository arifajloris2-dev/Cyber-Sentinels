# Team scenarios (offline replays)

Short, synthetic replays the team asked for. Each folder is a complete log set the engine and the dashboard can open.
The team's JSON files are kept exactly as delivered; the engine reads them through two agents added for them.

```bash
python backend/correlation.py backend/soc/scenarios/ka_sat          # report in .../ka_sat/out/
python backend/correlation.py backend/soc/scenarios/kosovo_ddos
python -m frontend --logs backend/soc/scenarios/kosovo_ddos --port 8090
```

Times are the source's `start` (in `sources.yaml`) plus each event's `offset_seconds`.

## `ka_sat/`: KA-SAT-inspired management-plane attack
`ka_sat_events.json`: in one session on `demo-management-gateway`, a remote admin sign-in from an unfamiliar source,
then 45 s later an unscheduled privileged config change, then at +120 s a monitoring alert for loss of service across
terminals. It is inspired by the February 2022 attack on a satellite network's management segment; all names and
timings are fictional.

| Read by | Rules | Result |
|---|---|---|
| Management-plane agent (`agents/management_plane.py`, parser `management_events`) | **MGMT-001**: sign-in from an unfamiliar source followed by an unscheduled privileged change in the same session (T1133, T1078, T1072); **MGMT-002**: service degraded after that change (T1489) | **1 incident** covering gateway and monitor, entry → impact |

## `kosovo_ddos/`: Kosovo government services disruption replay
`portal_health.json`: health samples for `demo-government-portal` (requests/s, p95 latency, 5xx %, availability
check), with the historical reference (CERT-EU, September 2022) and the evaluation the team defined. Two scenarios,
each judged against its **own first sample**:
- `simulated-disruption`: traffic, latency and errors rise together until the availability check fails at +120 s.
- `healthy-busy-period` (control): the same traffic jump, but latency and errors stay normal.

| Read by | Rules | Result |
|---|---|---|
| Service health agent (`agents/service_health.py`, parser `portal_health`) | **SVC-001**: traffic ×3+, p95 latency ×5+ and 2 %+ server errors together, while checks still pass (early warning, T1498, T1499.002); **SVC-002**: availability check failed (T1499.002) | Warning at **+60 s**, failure at +120 s: **lead time 60 s**. The healthy busy period raises **no alert**. One incident. |

AI explanation time is measured separately (it runs on the local model after the incident exists).

Checked in CI by `backend/soc/tests/test_team_scenarios.py`.
