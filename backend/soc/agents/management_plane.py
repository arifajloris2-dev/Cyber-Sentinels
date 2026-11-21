"""Management-plane agent: admin sign-ins and configuration changes on network management systems
(e.g. a satellite/WAN management gateway), plus the service monitor that shows their effect.

Reads replay files (JSON list or JSON lines) with: session_id, offset_seconds, host, event, detail, phase, scenario.
Time = the source's `start` (sources.yaml) + offset_seconds. Events:
  remote_admin_login        -> auth/logon (remote); unfamiliar_source when the detail says so
  privileged_config_change  -> config/privileged-config-change; scheduled=False when the detail says unscheduled
  service_health_degraded   -> service/service-degraded
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..events import make_event
from ..parsers import _seen
from . import Agent, count

DEFAULT_START = "2026-11-22T09:00:00+00:00"
KINDS = {"remote_admin_login": ("auth", "logon"), "privileged_config_change": ("config", "privileged-config-change"),
         "service_health_degraded": ("service", "service-degraded")}


def _records(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8-sig").strip()
    if text.startswith("["):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def parse_management_events(path: Path, src: dict, stats: dict):
    start = datetime.fromisoformat(str(src.get("start", DEFAULT_START))).astimezone(timezone.utc)
    try:
        records = _records(path)
    except (ValueError, OSError):
        stats["errors"] += 1
        return
    for n, r in enumerate(records, 1):
        try:
            t = start + timedelta(seconds=float(r.get("offset_seconds", 0)))
            _seen(stats, t)
            kind = KINDS.get(str(r.get("event", "")).lower())
            if not kind:
                stats["skipped"] += 1
                continue
            detail = str(r.get("detail", ""))
            extra = {}
            if kind[1] == "logon":
                extra = {"outcome": "success", "logon": "remote", "unfamiliar_source": "unfamiliar" in detail.lower()}
            elif kind[1] == "privileged-config-change":
                extra = {"outcome": "success", "scheduled": "unscheduled" not in detail.lower()}
            else:
                extra = {"outcome": "failure"}
            yield make_event(src["name"], n, json.dumps(r), src["path"], t, os="network", host=r.get("host") or src.get("host"),
                             type=kind[0], action=kind[1], session=r.get("session_id"), phase=r.get("phase"),
                             scenario=r.get("scenario"), detail=detail, **extra)
        except (ValueError, TypeError):
            stats["errors"] += 1


def highlights(ev, ctx):
    lines = [f"{count(ev, action='logon')} admin sign-ins ({sum(1 for e in ev if e.get('unfamiliar_source'))} from an unfamiliar source), "
             f"{count(ev, action='privileged-config-change')} privileged config changes "
             f"({sum(1 for e in ev if e.get('scheduled') is False)} unscheduled)"]
    deg = [e for e in ev if e.get("action") == "service-degraded"]
    if deg:
        lines.append(f"service degraded on {', '.join(sorted({str(e.get('host')) for e in deg}))}: {deg[0].get('detail')}")
    return lines


AGENT = Agent("management_plane", "Management-plane agent", "Admin sign-ins and config changes on network management systems",
              {"management_events": parse_management_events}, highlights)
