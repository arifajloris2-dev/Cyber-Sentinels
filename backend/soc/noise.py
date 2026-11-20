"""Noise filter: recognise approved maintenance BEFORE the rules run.

maintenance.yaml lists change tickets. An event is approved only if ALL of these hold:
  - its host is in the ticket's hosts
  - its time is inside the ticket's window (one-off start/end, or a daily time range)
  - it matches one of the ticket's 'allow' patterns (what the change is expected to do)
So an attacker who acts during a patch window is NOT hidden: his actions don't match the expected ones.

Approved events are never deleted: they are tagged with the ticket and reported separately.
"""
from __future__ import annotations

from datetime import datetime, time

from .events import parse_time
from .detect import matches


def _in_window(t: datetime, ticket: dict) -> bool:
    if "start" in ticket:
        return parse_time(ticket["start"]) <= t < parse_time(ticket["end"])
    if "daily" in ticket:
        a, b = (time.fromisoformat(x) for x in ticket["daily"])
        return a <= t.time() < b if a <= b else (t.time() >= a or t.time() < b)
    return False


def tag(events: list[dict], maintenance: dict) -> None:
    tickets = maintenance.get("tickets", [])
    for e in events:
        for tk in tickets:
            hosts = [h.lower() for h in tk.get("hosts", [])]
            if str(e.get("host", "")).lower() in hosts and _in_window(e["time"], tk) and any(matches(e, p) for p in tk.get("allow", [])):
                e["ticket"] = tk["id"]
                break


def split(events: list[dict]) -> tuple[list[dict], list[dict]]:
    """(events the rules judge, events approved by a ticket)"""
    return [e for e in events if not e.get("ticket")], [e for e in events if e.get("ticket")]


def summary(approved: list[dict], suppressed_alerts: list[dict], maintenance: dict) -> list[dict]:
    titles = {t["id"]: t.get("title", "") for t in maintenance.get("tickets", [])}
    out = {}
    for e in approved:
        s = out.setdefault(e["ticket"], {"ticket": e["ticket"], "title": titles.get(e["ticket"], ""), "events": 0, "hosts": set(),
                                         "first": e["time"], "last": e["time"], "alerts_suppressed": []})
        s["events"] += 1
        s["hosts"].add(e.get("host"))
        s["last"] = e["time"]
    for a in suppressed_alerts:
        if a["ticket"] in out:
            out[a["ticket"]]["alerts_suppressed"].append(f"{a['rule']}: {a['text']}")
    return [{**s, "hosts": sorted(h for h in s["hosts"] if h), "first": s["first"].isoformat(timespec="minutes"),
             "last": s["last"].isoformat(timespec="minutes")} for s in out.values()]
