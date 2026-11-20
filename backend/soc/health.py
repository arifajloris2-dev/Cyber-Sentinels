"""Source health: notice when a log source stops reporting, so incidents can say their confidence is lower.

Each source learns its longest normal quiet time from the baseline. After the baseline, a gap much longer than
that (or a source that stops before the end, or never reports) is reported as silent.
"""
from __future__ import annotations

from datetime import datetime, timedelta


def check(events: list[dict], sources: list[dict], stats: list[dict], baseline_end: datetime, end: datetime) -> list[dict]:
    # a log is alive when it writes ANY readable line, not only lines that become events
    times = {s["source"]: [t for t in s.get("times", []) if t <= end] for s in stats}
    hosts = {s["source"]: s.get("host") for s in stats}
    for e in events:
        hosts[e["source"]] = hosts.get(e["source"]) or e.get("host")
    out = []
    for src in sources:
        ts = sorted(times.get(src["name"], []))
        expected = timedelta(minutes=src.get("expected_every_min", 30))
        base_gaps = [b - a for a, b in zip(ts, ts[1:]) if b <= baseline_end]
        limit = max(expected * 2, max(base_gaps) * 2 if len(base_gaps) > 10 else expected * 2)
        silent = []
        if not ts:
            silent.append({"from": None, "to": None, "minutes": None, "note": "no events at all (file missing or empty)"})
        else:
            for a, b in zip(ts, ts[1:]):
                if b > baseline_end and b - a > limit:
                    silent.append({"from": a.isoformat(timespec="minutes"), "to": b.isoformat(timespec="minutes"),
                                   "minutes": round((b - a).total_seconds() / 60)})
            if end - ts[-1] > limit:
                silent.append({"from": ts[-1].isoformat(timespec="minutes"), "to": None,
                               "minutes": round((end - ts[-1]).total_seconds() / 60), "note": "stopped reporting"})
        out.append({"source": src["name"], "host": hosts.get(src["name"]), "events": len(ts),
                    "normal_quiet_min": round(limit.total_seconds() / 60), "silent": silent, "ok": not silent})
    return out


def silent_between(health: list[dict], start: datetime, end: datetime) -> list[dict]:
    out = []
    for h in health:
        for g in h["silent"]:
            a = datetime.fromisoformat(g["from"]) if g.get("from") else None
            b = datetime.fromisoformat(g["to"]) if g.get("to") else end
            if a is None or (a <= end and b >= start):
                out.append({"source": h["source"], "host": h["host"], **g})
    return out
