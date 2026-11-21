"""Service health agent: aggregate health samples of a public service (requests/s, p95 latency, 5xx errors,
availability check), e.g. a government portal under a traffic flood.

Reads a replay file:  {"service": ..., "scenarios": [{"id": ..., "events": [{"offset_seconds", "requests_per_second",
"p95_response_ms", "http_5xx_percent", "availability_check"}]}]}   (or JSON lines with a "scenario" field).
Each scenario is judged on its own against its FIRST sample (its normal): rps_ratio and p95_ratio say how far traffic
and latency have moved. A busy period (more requests, same latency and errors) is normal; a flood that slows the
service and makes it fail is not. Time = the source's `start` + offset_seconds.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..events import make_event
from ..parsers import _seen
from . import Agent

DEFAULT_START = "2026-11-22T09:00:00+00:00"


def _scenarios(path: Path) -> tuple[str | None, list[tuple[str, list[dict]]]]:
    text = path.read_text(encoding="utf-8-sig").strip()
    if text.startswith("{"):
        d = json.loads(text)
        return d.get("service"), [(str(s.get("id", f"s{i}")), s.get("events", [])) for i, s in enumerate(d.get("scenarios", []), 1)]
    groups: dict[str, list[dict]] = {}
    for line in text.splitlines():
        if line.strip():
            r = json.loads(line)
            groups.setdefault(str(r.get("scenario", "default")), []).append(r)
    return None, list(groups.items())


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def parse_portal_health(path: Path, src: dict, stats: dict):
    start = datetime.fromisoformat(str(src.get("start", DEFAULT_START))).astimezone(timezone.utc)
    try:
        service, scenarios = _scenarios(path)
    except (ValueError, OSError):
        stats["errors"] += 1
        return
    n = 0
    for scenario, events in scenarios:
        events = sorted(events, key=lambda e: _f(e.get("offset_seconds")) or 0)
        base = events[0] if events else {}
        b_rps, b_p95 = _f(base.get("requests_per_second")) or 1.0, _f(base.get("p95_response_ms")) or 1.0
        for r in events:
            n += 1
            try:
                t = start + timedelta(seconds=float(r.get("offset_seconds", 0)))
                _seen(stats, t)
                rps, p95, err = _f(r.get("requests_per_second")), _f(r.get("p95_response_ms")), _f(r.get("http_5xx_percent"))
                ok = str(r.get("availability_check", "pass")).lower() == "pass"
                yield make_event(src["name"], n, json.dumps({"scenario": scenario, **r}), src["path"], t, os="network",
                                 host=service or src.get("host"), type="service", action="health-sample",
                                 outcome="success" if ok else "failure", availability="pass" if ok else "fail",
                                 scenario=scenario, offset_s=_f(r.get("offset_seconds")), rps=rps, p95_ms=p95, error_pct=err,
                                 rps_ratio=round(rps / b_rps, 2) if rps is not None else None,
                                 p95_ratio=round(p95 / b_p95, 2) if p95 is not None else None,
                                 detail=f"{scenario}: {rps:g} req/s, p95 {p95:g} ms, {err:g}% 5xx, check {'pass' if ok else 'FAIL'}")
            except (ValueError, TypeError):
                stats["errors"] += 1


def highlights(ev, ctx):
    lines = []
    for scenario in sorted({e.get("scenario") for e in ev if e.get("scenario")}):
        s = [e for e in ev if e.get("scenario") == scenario]
        peak = max(s, key=lambda e: e.get("p95_ms") or 0)
        fails = [e for e in s if e.get("availability") == "fail"]
        lines.append(f"{scenario}: up to {max(e.get('rps') or 0 for e in s):g} req/s (x{max(e.get('rps_ratio') or 0 for e in s):g}), "
                     f"p95 up to {peak.get('p95_ms'):g} ms (x{peak.get('p95_ratio'):g}), "
                     f"{max(e.get('error_pct') or 0 for e in s):g}% 5xx, "
                     + (f"availability check FAILED at +{fails[0].get('offset_s'):g}s" if fails else "availability checks all passed"))
    return lines


AGENT = Agent("service_health", "Service health agent", "Health samples of public services (traffic, latency, errors, availability)",
              {"portal_health": parse_portal_health}, highlights)
