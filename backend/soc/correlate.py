"""Correlation: join alerts from all hosts and log sources into incidents.

Two alerts are linked when they share an account, an unknown address or a host, and are within LINK_WINDOW of each
other. Linked alerts form one incident, told as a chain: entry -> lateral movement -> impact.
Every link keeps its reason, every alert keeps its raw log lines: that is the evidence trail.
The output is advice only: nothing here blocks, isolates or changes anything.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from .attack import STAGES, info
from .health import silent_between

LINK_WINDOW = timedelta(minutes=60)
WEAK = 5   # alerts below this severity link only through a shared account or unknown address, never "same host" alone
# assets.yaml uses 1-5 (5 = gate control, domain controllers); backend/data/assets.json uses words. One scale: 1-5.
CRITICALITY_LEVELS = {"low": 1, "medium": 2, "high": 4, "critical": 5}


def _criticality_rank(value) -> int:
    if isinstance(value, (int, float)):
        return min(5, max(1, int(value)))
    text = str(value).strip().lower()
    if text.isdigit():
        return min(5, max(1, int(text)))
    return CRITICALITY_LEVELS.get(text, 1)


def link_reason(a: dict, b: dict) -> str | None:
    """Why two alerts belong together, or None.

    A busy host (web portal, mail gateway) collects many unrelated weak alerts; joining them only because they share
    that host would build one giant false incident. So a weak alert needs a stronger tie: the same account or the
    same unknown address.
    """
    if a["time"] - LINK_WINDOW > b["time_end"] or b["time"] - LINK_WINDOW > a["time_end"]:
        return None
    ties = [("users", "same account"), ("unknown_ips", "same unknown address")]
    if min(a["severity"], b["severity"]) >= WEAK:
        ties.append(("hosts", "same host"))
    for field, label in ties:
        shared = sorted(set(a[field]) & set(b[field]))
        if shared:
            return f"{label} {', '.join(shared)}"
    return None


def priority(score: int) -> str:
    return "P1" if score >= 70 else "P2" if score >= 35 else "P3"


def _title(members: list[dict], stages: list[str], impact: list[str]) -> str:
    """Short story of the incident from what the alerts actually saw, in stage order (e.g. 'Password guessing → ...')."""
    parts = []
    for s in stages:
        for a in members:
            if a["stage"] == s and (label := a.get("short") or a["title"]) not in parts:
                parts.append(label)
                break
    title = " → ".join(parts)
    title = title[:1].upper() + title[1:]
    return title +(" on " + ", ".join(impact) if impact else "")


def correlate(alerts: list[dict], assets: dict, health: list[dict], end: datetime) -> tuple[list[dict], list[dict]]:
    """Returns (incidents, single alerts that did not become an incident)."""
    parent = list(range(len(alerts)))

    def root(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    links = []
    for i, a in enumerate(alerts):
        for j in range(i + 1, len(alerts)):
            if reason := link_reason(a, alerts[j]):
                links.append({"from": a["id"], "to": alerts[j]["id"], "reason": reason})
                parent[root(i)] = root(j)
    groups = {}
    for i, a in enumerate(alerts):
        groups.setdefault(root(i), []).append(a)

    known = {x["host"].lower(): x for x in assets.get("assets", [])}
    incidents, singles = [], []
    for members in groups.values():
        members.sort(key=lambda a: a["time"])
        if len({a["rule"] for a in members}) < 2 and max(a["severity"] for a in members) < 8:
            singles += members      # one weak signal alone is not an incident
            continue
        for a in members:
            a["stage"] = min((info(t)["stage"] for t in a["attack"]), key=STAGES.index)
        ids = {a["id"] for a in members}
        hosts = sorted({h for a in members for h in a["hosts"] if h.lower() in known})
        stages = [s for s in STAGES if any(a["stage"] == s for a in members)]
        techniques = list(dict.fromkeys(t for a in members for t in a["attack"]))
        start, stop = members[0]["time"], max(a["time_end"] for a in members)
        crit = max([_criticality_rank(known[h.lower()].get("criticality", "medium")) for h in hosts] or [1])
        score = sum(a["severity"] for a in members) + 5 * len(stages) + 3 * crit + (10 if len(hosts) > 1 else 0)
        conf, why = _confidence(members, hosts, health, start, stop)
        impact = sorted({h for a in members if a["stage"] == "impact" for h in a["hosts"] if h.lower() in known})
        title = _title(members, stages, impact)
        if any(alert["rule"] == "NET-004" for alert in members):
            target = next(
                (host for alert in members if alert["rule"] == "NET-004" for host in alert["hosts"]),
                "protected system",
            )
            title = f"Possible bot swarm targeting {target}"
        my_links = [l for l in links if l["from"] in ids]
        incidents.append({
            "id": f"INC-{start:%Y%m%d-%H%M}", "priority": priority(score), "score": score,
            "title": title, "start": start, "end": stop, "stages": stages, "confidence": conf, "confidence_reasons": why,
            "hosts": [{"host": h, "role": known[h.lower()].get("role"), "criticality": known[h.lower()].get("criticality")} for h in hosts],
            "users": sorted({u for a in members for u in a["users"]}),
            "unknown_ips": sorted({ip for a in members for ip in a["unknown_ips"]}),
            "attack": [info(t) for t in techniques], "alerts": members,
            "links": my_links, "why_together": _reasons(my_links), "next_checks": _advice(members, hosts),
        })
    incidents.sort(key=lambda x: -x["score"])
    return incidents, singles


def _reasons(links):
    counts = {}
    for l in links:
        counts[l["reason"]] = counts.get(l["reason"], 0) + 1
    return [f"{r} ({n} link{'s' if n > 1 else ''})" for r, n in sorted(counts.items(), key=lambda x: -x[1])]


def _confidence(members, hosts, health, start, stop):
    conf, why = 1.0, []
    for g in silent_between(health, start - timedelta(minutes=30), stop + timedelta(minutes=30)):
        if g["host"] in hosts or g["host"] is None:
            conf -= 0.25
            span = f"{g['from'][11:16] if g.get('from') else '?'}–{g['to'][11:16] if g.get('to') else 'end'}"
            why.append(f"log source '{g['source']}' on {g['host']} was silent {span} UTC: some events may be missing")
    if len({e["source"] for a in members for e in a["evidence"]}) == 1:
        conf -= 0.15
        why.append("all evidence comes from one log source")
    return round(max(conf, 0.1), 2), why or ["all log sources reported normally"]


def _advice(members, hosts):
    """Verification and containment ADVICE for the operator. The engine never acts."""
    out, rules = [], {a["rule"]: a for a in members}
    if a := rules.get("AUTH-001") or rules.get("AUTH-002"):
        e = a["evidence"][-1]
        out.append(("verify", f"Ask {e.get('user')} if they logged on to {e.get('host')} at {a['time_end']:%H:%M} UTC from {e.get('src_ip')}."))
        out.append(("contain, operator decides", f"If not confirmed: lock {e.get('user')} and end its sessions."))
    if any(r.startswith("NET-") or r == "AUTH-004" for r in rules) and len(hosts) > 1:
        out.append(("verify", f"Ask the owners whether {' and '.join(hosts)} should talk to each other."))
    for r in ("SYS-001", "SYS-002"):
        if a := rules.get(r):
            e = a["evidence"][-1]
            out.append(("verify", f"Check service '{e.get('service')}' on {e.get('host')}: no change ticket covers it."))
            out.append(("contain, operator decides", f"Consider isolating {e.get('host')}; check first what depends on it."))
    if a := rules.get("SYS-003"):
        out.append(("verify", f"Review the firewall change on {a['evidence'][-1].get('host')} ({a['evidence'][-1].get('detail', '')}) and undo it if not approved."))
    for a in members:
        for ip in a["unknown_ips"]:
            step = ("verify", f"Find the device behind {ip} (DHCP lease, switch port): it is not in assets.yaml.")
            if step not in out:
                out.append(step)
    return [{"type": t, "step": s} for t, s in out]
