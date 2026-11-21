"""Event search for the dashboard (Splunk-like, local, deterministic).

Query language (all terms must match; case-insensitive):
    field=value          exact value, * as wildcard          host=DC-02   src_ip=10.24.3.*   user=adm*
    field!=value         not this value                      outcome!=success
    field>=N  field<=N   numbers                             bytes_out>=50000000   dst_port<1024
    field>N   field<N
    word  or  "a phrase" found anywhere in the raw log line  PSEXESVC   "delete shadows"
Short names: src -> src_ip, dst -> dst_ip, port -> dst_port, sev -> severity.
"""
from __future__ import annotations

import fnmatch
import re
import shlex
from collections import Counter
from datetime import datetime, timedelta

ALIASES = {"src": "src_ip", "dst": "dst_ip", "port": "dst_port", "sev": "severity", "account": "user"}
INTERESTING = ["agent", "host", "user", "action", "outcome", "type", "src_ip", "dst_ip", "dst_port", "src_zone", "dst_zone",
               "logon", "service", "share", "group", "source"]
TERM = re.compile(r"^([A-Za-z_][\w.]*)\s*(!=|>=|<=|=|>|<)\s*(.*)$")


def parse(query: str) -> list[tuple]:
    """'host=DC-02 "delete shadows"' -> [("field", "host", "=", "DC-02"), ("text", "delete shadows")]."""
    try:
        parts = shlex.split(query or "", posix=True)
    except ValueError:                       # an unclosed quote: treat the rest as plain words
        parts = (query or "").replace('"', " ").split()
    terms = []
    for p in parts:
        m = TERM.match(p)
        if m and m[3] != "":
            terms.append(("field", ALIASES.get(m[1].lower(), m[1]), m[2], m[3]))
        elif p.upper() not in ("AND", "|", "SEARCH"):
            terms.append(("text", p))
    return terms


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _match(e: dict, term: tuple) -> bool:
    if term[0] == "text":
        return term[1].lower() in str(e.get("raw", "")).lower()
    _, field, op, want = term
    v = e.get(field)
    if op in (">=", "<=", ">", "<"):
        a, b = _num(v), _num(want)
        if a is None or b is None:
            return False
        return {">=": a >= b, "<=": a <= b, ">": a > b, "<": a < b}[op]
    hit = v is not None and fnmatch.fnmatchcase(str(v).lower(), want.lower())
    return hit if op == "=" else not hit


def search(events: list[dict], query: str, start: datetime | None = None, end: datetime | None = None,
           limit: int | None = None) -> list[dict]:
    terms = parse(query)
    out = []
    for e in events:
        t = e.get("time")
        if (start and t and t < start) or (end and t and t > end):
            continue
        if all(_match(e, term) for term in terms):
            out.append(e)
            if limit and len(out) >= limit:
                break
    return out


def field_stats(events: list[dict], fields: list[str] = INTERESTING, top: int = 6) -> dict[str, list[tuple]]:
    """'Interesting fields': for each field, its most common values and how often they occur."""
    out = {}
    for f in fields:
        c = Counter(str(e[f]) for e in events if e.get(f) not in (None, ""))
        if c:
            out[f] = c.most_common(top)
    return out


def histogram(events: list[dict], minutes: int = 60) -> list[tuple[str, int]]:
    """Events per time bucket (UTC), for the timeline chart."""
    c = Counter()
    for e in events:
        t = e.get("time")
        if isinstance(t, datetime):
            b = t.replace(minute=(t.minute // minutes) * minutes if minutes < 60 else 0, second=0, microsecond=0)
            c[b] += 1
    if not c:
        return []
    first, last, step = min(c), max(c), timedelta(minutes=minutes)
    out, t = [], first
    while t <= last:
        out.append((t.strftime("%m-%d %H:%M"), c.get(t, 0)))
        t += step
    return out
