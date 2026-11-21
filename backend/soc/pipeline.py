"""The two stages of the SOC engine, run on one folder of logs.

  detect()  parse -> context -> maintenance filter -> rules -> source health      (used by backend/detection.py)
  run()     detect() + correlation into incidents                                (used by backend/correlation.py)

The log folder contains the log files and three settings files:
  sources.yaml      which log file is which (parser, host, time offset, how often it normally writes)
  assets.yaml       known machines: host, ip, role, criticality; admin IPs; night hours
  maintenance.yaml  approved change tickets (patching, backup) and what they are allowed to do
  osint_output.json optional threat intel (Member 1); if absent, backend/data/osint_output.json is used
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from . import agents, dedupe, health, intel, knowledge, noise, verify
from .correlate import correlate, priority
from .detect import enrich, load_rules, run_rules
from .parsers import read_all

RULES_DIR = Path(__file__).resolve().parent / "rules"


def settings(folder: Path) -> dict:
    def y(name, default):
        p = Path(folder) / name
        return (yaml.safe_load(p.read_text(encoding="utf-8")) or default) if p.exists() else default

    s = y("sources.yaml", {})
    return {"sources": s.get("sources", []), "baseline_hours": s.get("baseline_hours", 24),
            "assets": y("assets.yaml", {"assets": []}), "maintenance": y("maintenance.yaml", {"tickets": []})}


def load(folder: Path):
    """Read and parse every log once (re-used by replay)."""
    cfg = settings(folder)
    events, stats = read_all(cfg["sources"], Path(folder))
    enrich(events, cfg["assets"], knowledge.indicators(knowledge.load()))
    return cfg, events, stats


def detect(folder: Path, until: datetime | None = None, loaded=None, rules_dir: Path = RULES_DIR) -> dict:
    """Stage 1: alerts from the deterministic rules, with approved maintenance kept aside and source health."""
    t0 = time.perf_counter()
    cfg, events, stats = loaded or load(folder)
    if until is not None:
        events = [e for e in events if e["time"] <= until]
    events = [dict(e) for e in events]  # each run tags its own copies
    empty = {"alerts": [], "suppressed": [], "maintenance": [], "health": [], "stats": stats, "events": 0, "rules": 0, "cfg": cfg,
             "agents": []}
    if not events:
        return empty
    baseline_end = events[0]["time"] + timedelta(hours=cfg["baseline_hours"])
    end = until or events[-1]["time"]
    rules = load_rules(rules_dir)

    noise.tag(events, cfg["maintenance"])
    judged, approved = noise.split(events)
    alerts = dedupe.merge(run_rules(judged, rules, baseline_end))   # one fact once, with everything that saw it
    # what the approved events WOULD have triggered: reported as suppressed, with the ticket
    would = run_rules([e for e in events if e["time"] < baseline_end] + approved, rules, baseline_end)
    by_id = {e["id"]: e for e in approved}
    suppressed = [a for a in would if all(x["id"] in by_id for x in a["evidence"])]
    for a in suppressed:
        a["ticket"] = by_id[a["evidence"][0]["id"]]["ticket"]

    src_health = health.check(events, cfg["sources"], stats, baseline_end, end)
    return {"alerts": alerts, "suppressed": suppressed, "maintenance": noise.summary(approved, suppressed, cfg["maintenance"]),
            "health": src_health, "stats": stats, "events": len(events),
            "agents": agents.summarise(events, alerts, suppressed, src_health, cfg["sources"], baseline_end, end),
            "event_list": events,   # parsed + enriched events (in memory only: the dashboard search uses them)
            "rules": len(rules), "baseline_end": baseline_end, "end": end, "cfg": cfg, "seconds": round(time.perf_counter() - t0, 3)}


def run(folder: Path, until: datetime | None = None, loaded=None, rules_dir: Path = RULES_DIR) -> dict:
    """Stage 1 + stage 2: incidents with evidence, ATT&CK mapping, confidence and suggested checks."""
    t0 = time.perf_counter()
    r = detect(folder, until, loaded, rules_dir)
    if not r["events"]:
        return {**r, "incidents": [], "singles": [], "intel": intel.load(folder)}
    incidents, singles = correlate(r["alerts"], r["cfg"]["assets"], r["health"], r["end"])
    threat = intel.load(folder)                     # OSINT findings + hunt requests (Member 1), if any
    intel.attach(incidents, threat, priority)
    incidents.sort(key=lambda x: -x["score"])
    agents.link_incidents(r.get("agents", []), incidents)
    # second opinion: suspicious / inconclusive / likely_benign with reasons (verify.py; adds `verification` only)
    checked = verify.apply(incidents, singles, r["health"], r["cfg"]["assets"])
    out = {**r, "incidents": incidents, "singles": singles, "intel": threat, "verification": checked}
    out["verification"]["run_id"] = verify.run_id(out)
    for item in incidents + singles:
        item["verification"]["engine_run"] = out["verification"]["run_id"]
    return {**out, "seconds": round(time.perf_counter() - t0, 3)}
