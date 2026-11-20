"""The common event format. Every parser turns its log lines into events with these field names.

    time       when it happened (UTC)              host       machine that wrote the log
    os         windows | linux                     source     name of the log source (from sources.yaml)
    type       auth | network | config | update    action     what happened (see below)
    outcome    success | failure                    user       account involved
    src_ip     where it came from                  src_port
    dst_ip     where it went                       dst_port
    proto      tcp | udp | icmp                    direction  inbound | outbound
    logon      local | remote | network | ssh | service | unlock
    service    service name                        path       program path
    detail     extra text (e.g. firewall rule, sudo command, package)

Evidence fields, set on every event:  id ("<source>:<line>"), file, line, raw (the original line)

Actions used by the rules:
    auth:    logon, explicit-logon, admin-logon
    network: allow, block
    config:  service-installed, service-started, firewall-change, log-cleared, audit-change, account-created
    update:  update-installed
(Simple names on purpose; they map 1:1 to ECS fields such as host.name, source.ip, event.action later.)
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

MAX_RAW = 400


def parse_time(value, offset: str | None = None) -> datetime:
    """ISO-8601 (with Z or +hh:mm) or 'YYYY-MM-DD HH:MM:SS'. Times without a zone are UTC, or local with `offset`."""
    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value).strip().replace("Z", "+00:00")
        s = re.sub(r"(\.\d{6})\d+", r"\1", s)  # Python accepts at most 6 decimals
        s = re.sub(r"([+-]\d\d)(\d\d)$", r"\1:\2", s)  # journalctl writes +0100, Python wants +01:00
        dt = datetime.fromisoformat(s.replace(" ", "T", 1))
    if dt.tzinfo is None:
        if offset:
            sign = -1 if offset.startswith("-") else 1
            hh, mm = offset.lstrip("+-").split(":")
            dt = dt.replace(tzinfo=timezone(sign * timedelta(hours=int(hh), minutes=int(mm))))
        else:
            dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def make_event(source: str, line_no: int, raw: str, file: str, time, offset=None, **fields) -> dict:
    t = parse_time(time, offset)
    ev = {"id": f"{source}:{line_no}", "time": t, "source": source, "file": file, "line": line_no, "raw": raw.strip()[:MAX_RAW]}
    ev.update({k: v for k, v in fields.items() if v not in (None, "", "-")})
    return ev


def show(ev: dict) -> dict:
    """Event as plain JSON-friendly dict (time as text)."""
    return {**{k: v for k, v in ev.items() if not k.startswith("_")}, "time": ev["time"].isoformat(timespec="seconds")}
