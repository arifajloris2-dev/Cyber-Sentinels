"""Merge alerts that describe the SAME thing, so the operator sees each fact once.

Several agents often see one action: a connection WS-021 -> DC-02:445 is logged by the source host firewall
(NET-001 "new outbound"), the destination host firewall (NET-002 "new inbound"), the network sensor (NET-006 "new
internal port") and the zone policy check (NET-008). That is one fact seen four times: stronger evidence, not four rows.

Merges (deterministic; every merged alert keeps all its evidence and lists what was folded in):
  1. same connection: connection rules with the same source, destination and port within CONNECTION_WINDOW
  2. same log line: alerts whose evidence starts with the same log line (e.g. SYS-001 + LAT-001 on one PsExec install)
  3. same thing repeating: the same rule on the same machines again within REPEAT_GAP (beaconing every hour,
     three backup-deletion commands in a minute)
The kept alert is the most severe (ties: the more specific rule), with the others' rules in "also" and the
evidence of all of them.
"""
from __future__ import annotations

from datetime import timedelta

CONNECTION_RULES = {"NET-001", "NET-002", "NET-006", "NET-007", "NET-008"}
CONNECTION_WINDOW = timedelta(minutes=10)
REPEAT_GAP = timedelta(minutes=60)
# an imported-indicator hit is outside intelligence: its own fact, never folded into another alert
OWN_FACT = {"IOC-001"}
SPECIFIC = ["NET-008", "LAT-001", "LAT-002", "LAT-003", "NET-007", "NET-006", "NET-001", "NET-002", "SYS-001"]   # preferred


def _rank(a: dict) -> tuple:
    return (-a["severity"], SPECIFIC.index(a["rule"]) if a["rule"] in SPECIFIC else -1, a["time"])


def _conn_key(a: dict):
    for e in a["evidence"]:
        s, d, p = e.get("src_ip"), e.get("dst_ip"), e.get("dst_port")
        if s and d:
            return (s, d, p)
    return None


def _absorb(keep: dict, other: dict) -> None:
    keep.setdefault("also", [])
    for r in [other["rule"]] + other.get("also", []):
        if r != keep["rule"] and r not in keep["also"]:
            keep["also"].append(r)
    keep.setdefault("also_text", [])
    keep["also_text"].append(other.get("short") or other["title"])
    seen = {e.get("id") for e in keep["evidence"]}
    keep["evidence"] = (keep["evidence"] + [e for e in other["evidence"] if e.get("id") not in seen])[:25]
    keep["count"] = keep.get("count", 1) + other.get("count", 1)
    keep["time"] = min(keep["time"], other["time"])
    keep["time_end"] = max(keep["time_end"], other["time_end"])
    keep["severity"] = max(keep["severity"], other["severity"])
    keep["attack"] = list(dict.fromkeys(keep["attack"] + other["attack"]))
    for f in ("hosts", "users", "unknown_ips"):
        keep[f] = sorted(set(keep.get(f, [])) | set(other.get(f, [])))


def _merge_groups(alerts: list[dict], same) -> list[dict]:
    """Greedy, time-ordered: an alert joins the first kept alert it is 'same' as."""
    kept: list[dict] = []
    for a in sorted(alerts, key=lambda x: (x["time"], x["rule"])):
        target = next((k for k in kept if same(k, a)), None)
        if target is None:
            kept.append(a)
            continue
        if _rank(a) < _rank(target):             # the new one is better: it becomes the kept alert
            kept[kept.index(target)] = a
            _absorb(a, target)
        else:
            _absorb(target, a)
    return kept


def merge(alerts: list[dict]) -> list[dict]:
    if not alerts:
        return alerts
    alerts = [dict(a) for a in alerts]

    def same_connection(k, a):
        return (k["rule"] in CONNECTION_RULES and a["rule"] in CONNECTION_RULES and _conn_key(k) and _conn_key(k) == _conn_key(a)
                and a["time"] - k["time_end"] <= CONNECTION_WINDOW)

    def same_line(k, a):
        return (k["rule"] not in OWN_FACT and a["rule"] not in OWN_FACT and bool(k["evidence"]) and bool(a["evidence"])
                and k["evidence"][0].get("id") == a["evidence"][0].get("id"))

    def repeating(k, a):
        return k["rule"] == a["rule"] and set(k["hosts"]) == set(a["hosts"]) and a["time"] - k["time_end"] <= REPEAT_GAP

    for rule in (same_connection, same_line, repeating):
        alerts = _merge_groups(alerts, rule)
    for a in alerts:
        if a.get("also"):
            labels = list(dict.fromkeys(a.get("also_text", [])))
            a["text"] = f"{a['text']} · also seen as: {', '.join(labels[:4])}"
        a.pop("also_text", None)
    return sorted(alerts, key=lambda a: (a["time"], a["rule"]))
