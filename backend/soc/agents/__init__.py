"""SOC agents: one specialised agent per monitored kind of system.

Each agent module in this folder defines   AGENT = Agent(...)   with:
  name / title / watches   what it is and which logs it reads
  parsers                  {parser name: function}   the log formats it understands (from soc/parsers.py or its own)
  highlights(events, ctx)  short plain-language lines: what it saw that matters (counts, top talkers, oddities)

The engine reads every log through the agent that owns its parser, learns each agent's normal level from the
baseline, and reports per agent what it saw, what it filtered as approved maintenance, which alerts it raised and
which incidents those fed. Adding a new system = adding one file here with its own parser (+ a rules file);
nothing else changes. Agents only observe and report: none of them blocks or changes anything.
"""
from __future__ import annotations

import importlib
import pkgutil
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

ORDER = ["windows_host", "endpoint", "linux_host", "host_firewall", "perimeter", "network_sensor", "mail"]


@dataclass
class Agent:
    name: str
    title: str
    watches: str
    parsers: dict[str, Callable] = field(default_factory=dict)
    highlights: Callable[[list[dict], dict], list[str]] | None = None


def registry() -> list[Agent]:
    """All agents in this folder (any module that defines AGENT), in a stable order."""
    found = []
    for mod in pkgutil.iter_modules(__path__):
        m = importlib.import_module(f"{__name__}.{mod.name}")
        if isinstance(getattr(m, "AGENT", None), Agent):
            found.append(m.AGENT)
    return sorted(found, key=lambda a: (ORDER.index(a.name) if a.name in ORDER else len(ORDER), a.name))


def all_parsers() -> dict[str, Callable]:
    out = {}
    for a in registry():
        out.update(a.parsers)
    return out


def owner_of(parser: str) -> str | None:
    return next((a.name for a in registry() if parser in a.parsers), None)


def _per_hour(n: int, start: datetime | None, end: datetime | None) -> float:
    hours = max((end - start).total_seconds() / 3600, 1.0) if start and end else 1.0
    return round(n / hours, 1)


def summarise(events: list[dict], alerts: list[dict], suppressed: list[dict], health: list[dict], sources: list[dict],
              baseline_end: datetime, end: datetime) -> list[dict]:
    """What each agent saw: volume against its own baseline, what it filtered, what it raised, what it noticed."""
    agents = registry()
    src_agent = {s["name"]: owner_of(s["parser"]) for s in sources}
    first = events[0]["time"] if events else None
    out = []
    for a in agents:
        names = {s for s, owner in src_agent.items() if owner == a.name}
        if not names:
            continue
        evs = [e for e in events if e["source"] in names]
        base = [e for e in evs if e["time"] < baseline_end]
        now = [e for e in evs if e["time"] >= baseline_end]
        mine = [x for x in alerts if any(ev.get("source") in names for ev in x["evidence"])]
        quiet = [x for x in suppressed if any(ev.get("source") in names for ev in x["evidence"])]
        base_rate, now_rate = _per_hour(len(base), first, baseline_end), _per_hour(len(now), baseline_end, end)
        busiest = Counter(e["time"].hour for e in base).most_common(1)
        ctx = {"alerts": mine, "baseline": base}
        out.append({
            "agent": a.name, "title": a.title, "watches": a.watches,
            "sources": sorted(names), "hosts": len({e.get("host") for e in evs if e.get("host")}),
            "events": len(evs), "events_today": len(now),
            "normal": {"per_hour": base_rate, "busiest_hour_utc": busiest[0][0] if busiest else None},
            "today": {"per_hour": now_rate,
                      "change_pct": round((now_rate - base_rate) / base_rate * 100) if base_rate else None},
            "actions": dict(Counter(f"{e.get('type')}/{e.get('action')}" for e in (now or evs)).most_common(6)),
            "maintenance_filtered": sum(1 for e in (now or evs) if e.get("ticket")),
            "alerts": len(mine), "alerts_by_rule": dict(Counter(x["rule"] for x in mine).most_common()),
            "top_alerts": [{"rule": x["rule"], "severity": x["severity"], "time": x["time"], "text": x["text"]}
                           for x in sorted(mine, key=lambda x: (-x["severity"], x["time"]))[:3]],
            "suppressed": len(quiet),
            "silent_sources": [h["source"] for h in health if h["source"] in names and not h["ok"]],
            # highlights describe what is NOT explained by an approved ticket (the ticketed part is counted above);
            # a log set shorter than the baseline (a lab capture) is described as a whole
            "highlights": a.highlights([e for e in (now or evs) if not e.get("ticket")], ctx if now else {**ctx, "baseline": []})
            if a.highlights else [],
            "incidents": [],
        })
    return out


def link_incidents(summaries: list[dict], incidents: list[dict]) -> None:
    """Fill in which incidents each agent's evidence fed."""
    for s in summaries:
        names = set(s["sources"])
        s["incidents"] = [i["id"] for i in incidents
                          if any(ev.get("source") in names for al in i["alerts"] for ev in al["evidence"])]


# ----------------------------------------------------------------- helpers for the agent modules
def count(events, **where) -> int:
    return sum(1 for e in events if all(e.get(k) == v for k, v in where.items()))


def top(events, key: str, n: int = 1, **where):
    c = Counter(e.get(key) for e in events if e.get(key) is not None and all(e.get(k) == v for k, v in where.items()))
    return c.most_common(n)
