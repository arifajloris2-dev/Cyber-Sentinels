"""Source health: notice when a log source stops reporting, so incidents can say their confidence is lower.

Each source learns two things from the baseline:
  - its longest normal quiet time, and
  - WHEN it normally writes: how many lines it wrote in each 30-minute slot of the day.
After the baseline, a gap is reported as silent only if it is much longer than the normal quiet time AND the baseline
says at least MIN_EXPECTED lines would normally have been written in that time. A workstation firewall that is quiet
every night is normal; a gate-server firewall that stops at 02:05 while it normally writes all night is not; a print
server that writes a few lines a day is not "silent" just because no one printed this afternoon.
A source that never reports is always silent.
"""
from __future__ import annotations

from datetime import datetime, timedelta

SLOT_MIN = 30
MIN_EXPECTED = 8               # lines the baseline expects in the gap before a missing source is reported


def _slot(t: datetime) -> int:
    return (t.hour * 60 + t.minute) // SLOT_MIN


def _expected_in(a: datetime, b: datetime, per_slot: dict[int, float]) -> float:
    """Lines the baseline would expect in the whole slots that lie inside the gap (a, b)."""
    n, t = 0.0, a + timedelta(minutes=SLOT_MIN)
    t = t.replace(minute=(t.minute // SLOT_MIN) * SLOT_MIN, second=0, microsecond=0)
    while t + timedelta(minutes=SLOT_MIN) <= b:
        n += per_slot.get(_slot(t), 0.0)
        t += timedelta(minutes=SLOT_MIN)
    return n


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
        base = [t for t in ts if t <= baseline_end]
        base_gaps = [b - a for a, b in zip(base, base[1:])]
        limit = max(expected * 2, max(base_gaps) * 2 if len(base_gaps) > 10 else expected * 2)
        # with a usable baseline, judge gaps by how much the source normally writes at that time of day
        # (a source with few lines then expects few lines in any gap, so it is not called silent for an idle afternoon)
        per_slot = None
        if base:
            days = max((baseline_end - base[0]).total_seconds() / 86400, 1.0)
            per_slot = {}
            for t in base:
                per_slot[_slot(t)] = per_slot.get(_slot(t), 0.0) + 1 / days

        def is_gap(a, b):
            if b - a <= limit:
                return False
            # only the part after the baseline counts: the baseline itself defines what is normal
            return per_slot is None or _expected_in(max(a, baseline_end), b, per_slot) >= MIN_EXPECTED

        silent = []
        if not ts:
            silent.append({"from": None, "to": None, "minutes": None, "note": "no events at all (file missing or empty)"})
        else:
            for a, b in zip(ts, ts[1:]):
                if b > baseline_end and is_gap(a, b):
                    silent.append({"from": a.isoformat(timespec="minutes"), "to": b.isoformat(timespec="minutes"),
                                   "minutes": round((b - a).total_seconds() / 60)})
            if is_gap(ts[-1], end):
                silent.append({"from": ts[-1].isoformat(timespec="minutes"), "to": None,
                               "minutes": round((end - ts[-1]).total_seconds() / 60), "note": "stopped reporting"})
        out.append({"source": src["name"], "host": hosts.get(src["name"]), "events": len(ts),
                    "normal_quiet_min": round(limit.total_seconds() / 60),
                    "normally_writes": _describe(per_slot), "silent": silent, "ok": not silent})
    return out


def _describe(per_slot: dict[int, float] | None) -> str:
    if per_slot is None:
        return "unknown (too little baseline)"
    per_day = round(sum(per_slot.values()))
    if len(per_slot) == 24 * 60 // SLOT_MIN:
        return f"around the clock, ~{per_day} lines/day"
    hours = sorted({s * SLOT_MIN // 60 for s in per_slot})
    return f"~{per_day} lines/day in {len(hours)} of 24 hours"


def silent_between(health: list[dict], start: datetime, end: datetime) -> list[dict]:
    out = []
    for h in health:
        for g in h["silent"]:
            a = datetime.fromisoformat(g["from"]) if g.get("from") else None
            b = datetime.fromisoformat(g["to"]) if g.get("to") else end
            if a is None or (a <= end and b >= start):
                out.append({"source": h["source"], "host": h["host"], **g})
    return out
