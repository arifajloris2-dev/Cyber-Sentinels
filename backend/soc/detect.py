"""Rule engine. Rules live in soc/rules/*.yaml; this file only knows how to run them.

Five rule types (all deterministic, so the same logs always give the same alerts):
  match      one event matches                                  e.g. a service was installed
  threshold  N or more matching events per group in a window    e.g. 5 failed logons in 10 min
  distinct_threshold N or more distinct values for one target   e.g. many source IPs hitting one system
  sequence   steps in order, same field values, within a time   e.g. failed logons, then a success
  new_value  something never seen during the baseline           e.g. a laptop talks to a new machine

Conditions:  field: value | field: [a, b] (any of) | modifiers: field|not, |startswith, |contains, |re, |exists, |gte, |lte
A field that is missing never matches a positive condition.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from .events import show

SYSTEM_USERS = {"SYSTEM", "LocalSystem", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "root"}
DEFAULT_INTERNAL = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
DEFAULT_PRIVILEGED_GROUPS = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Backup Operators", "sudo", "wheel"]


def _internal(ip: str, nets: list) -> bool | None:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return a.is_loopback or any(a in n for n in nets)


# ======================================================================= context
def enrich(events: list[dict], assets: dict) -> None:
    """Add context fields the rules use. Never changes the original fields.

    assets.yaml may also list  internal_nets: [cidr, ...]  (default: the private ranges) and
    public_services: [{host, ports}]  - ports a server offers to the outside world on purpose (web portal 443, mail 25).
    """
    by_ip = {a["ip"]: a for a in assets.get("assets", []) if a.get("ip")}
    by_host = {a["host"].lower(): a for a in assets.get("assets", [])}
    admin = set(assets.get("admin_ips", []))
    nets = [ipaddress.ip_network(n) for n in assets.get("internal_nets", DEFAULT_INTERNAL)]
    public = {(p["host"].lower(), int(port)) for p in assets.get("public_services", []) for port in p.get("ports", [])}
    night_from, night_to = assets.get("night_hours", [20, 6])
    users = {str(u["user"]).lower(): u for u in assets.get("users", []) if u.get("user")}
    privileged_groups = {str(g).lower() for g in assets.get("privileged_groups", DEFAULT_PRIVILEGED_GROUPS)}
    zones = Zones(assets)
    for e in events:
        h = e["time"].hour
        e["night"] = h >= night_from or h < night_to
        u = users.get(str(e.get("user", "")).lower())
        if u:                                   # who the account is (assets.yaml users)
            e["user_role"] = u.get("role", "")
            e["user_privileged"] = bool(u.get("privileged"))
            e["user_service"] = "service" in str(u.get("role", "")).lower() or u.get("interactive") is False
            e["user_home"] = u.get("home")
        if e.get("group"):
            e["privileged_group"] = str(e["group"]).lower() in privileged_groups
        for side in ("src", "dst"):
            ip = e.get(f"{side}_ip")
            if ip:
                e[f"{side}_known"] = ip in by_ip
                e[f"{side}_internal"] = _internal(ip, nets)
                if ip in by_ip:
                    e[f"{side}_host"] = by_ip[ip]["host"]
                    e[f"{side}_role"] = by_ip[ip].get("role", "")
        e["admin_src"] = e.get("src_ip") in admin
        a = by_host.get(str(e.get("host", "")).lower(), {})
        e["criticality"] = a.get("criticality", 1)
        e["role"] = a.get("role", "")
        e["system_user"] = e.get("user") in SYSTEM_USERS
        if e.get("type") == "network":
            # outside visitors on a port the server offers to the internet on purpose: normal, not "new" each time
            target = str(e.get("dst_host") or e.get("host", "")).lower()
            e["public_service"] = (e.get("src_internal") is False and (target, e.get("dst_port")) in public)
            if zones.active and e.get("src_ip") and e.get("dst_ip"):
                zs, zd = zones.zone(e["src_ip"]), zones.zone(e["dst_ip"])
                if zs:
                    e["src_zone"] = zs
                if zd:
                    e["dst_zone"] = zd
                if zs and zd and zs != zd:      # crossing zones: does the firewall policy allow it?
                    e["zone_allowed"] = zones.allowed(zs, zd, e.get("src_host"), e.get("dst_host"), e.get("dst_port"))


class Zones:
    """Network zones and the policy between them (assets.yaml zones + zone_policy).

    zone_policy: [{from, to, ports}] where from/to is a zone name, a host name or "any". Traffic inside one zone is
    always allowed; anything between zones that no entry allows is a policy violation (often lateral movement).
    """

    def __init__(self, assets: dict):
        self.nets = [(z["name"], ipaddress.ip_network(z["cidr"])) for z in assets.get("zones", []) if z.get("cidr")]
        self.policy = assets.get("zone_policy", [])
        self.active = bool(self.nets and self.policy)
        self._cache: dict[str, str | None] = {}

    def zone(self, ip: str) -> str | None:
        if ip not in self._cache:
            try:
                a = ipaddress.ip_address(ip)
                self._cache[ip] = next((name for name, net in self.nets if a in net), None)
            except ValueError:
                self._cache[ip] = None
        return self._cache[ip]

    def allowed(self, zs: str, zd: str, hs: str | None, hd: str | None, port) -> bool:
        def side(want, zone, host):
            return want == "any" or want == zone or (host is not None and str(want).lower() == str(host).lower())
        return any(side(p.get("from"), zs, hs) and side(p.get("to"), zd, hd) and (not p.get("ports") or port in p["ports"])
                   for p in self.policy)


def _cond(e: dict, key: str, want) -> bool:
    field, _, mod = key.partition("|")
    v = e.get(field)
    wants = want if isinstance(want, list) else [want]
    if mod == "exists":
        return (v is not None) == bool(want)
    if mod == "not":
        return v not in wants
    if v is None:
        return False
    s = str(v).lower()
    if mod == "":
        return v in wants or s in [str(w).lower() for w in wants]
    if mod == "startswith":
        return any(s.startswith(str(w).lower()) for w in wants)
    if mod == "contains":
        return any(str(w).lower() in s for w in wants)
    if mod == "re":
        return any(re.search(str(w), str(v)) for w in wants)
    if mod in ("gte", "lte"):
        try:
            return any((float(v) >= float(w)) if mod == "gte" else (float(v) <= float(w)) for w in wants)
        except (TypeError, ValueError):
            return False
    raise ValueError(f"unknown condition modifier |{mod}")


def matches(e: dict, where: dict | None) -> bool:
    return all(_cond(e, k, w) for k, w in (where or {}).items())


# ======================================================================= loading + running
def load_rules(folder: Path) -> list[dict]:
    rules = []
    for f in sorted(Path(folder).glob("*.yaml")):
        for r in yaml.safe_load(f.read_text(encoding="utf-8"))["rules"]:
            for k in ("id", "type", "title", "severity", "attack"):
                if k not in r:
                    raise ValueError(f"{f.name}: rule {r.get('id', '?')} is missing '{k}'")
            r["file"] = f.name
            rules.append(r)
    ids = [r["id"] for r in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate rule ids")
    return rules


def run_rules(events: list[dict], rules: list[dict], baseline_end: datetime) -> list[dict]:
    kinds = {
        "match": _match,
        "threshold": _threshold,
        "distinct_threshold": _distinct_threshold,
        "sequence": _sequence,
        "new_value": _new_value,
    }
    alerts = []
    for r in rules:
        alerts += kinds[r["type"]](r, events, baseline_end)
    return sorted(alerts, key=lambda a: (a["time"], a["rule"]))


def make_alert(rule: dict, evs: list[dict], extra: dict | None = None) -> dict:
    evs = sorted(evs, key=lambda e: (e["time"], e["id"]))
    last = evs[-1]
    ctx = {**last, "count": len(evs), "first": f"{evs[0]['time']:%H:%M}", "last": f"{last['time']:%H:%M}", **(extra or {})}
    text = re.sub(r"\{(\w+)\}", lambda m: str(ctx.get(m.group(1), "?")), rule.get("text", rule["title"]))
    # a network sensor only watched the traffic: the machines involved are the two ends, not the sensor itself
    hosts = {x for e in evs for x in ((None if e.get("sensor") else e.get("host")), e.get("src_host"), e.get("dst_host")) if x}
    return {
        "id": f"{rule['id']}@{evs[0]['id']}", "rule": rule["id"], "title": rule["title"], "short": rule.get("short", rule["title"]),
        "text": text,
        "severity": rule["severity"] + (rule.get("night_bonus", 0) if any(e["night"] for e in evs) else 0),
        "attack": rule["attack"], "time": evs[0]["time"], "time_end": last["time"],
        "hosts": sorted(hosts), "users": sorted({e["user"] for e in evs if e.get("user") and not e["system_user"]}),
        "unknown_ips": sorted({e["src_ip"] for e in evs if e.get("src_ip") and e.get("src_known") is False}),
        "evidence": [show(e) for e in evs[:25]], "count": len(evs), **(extra or {}),
    }


def _key(e, fields):
    vals = tuple(e.get(f) for f in fields)
    return None if any(v is None for v in vals) else vals


def _match(rule, events, _):
    hits = [e for e in events if matches(e, rule.get("where"))]
    if not rule.get("group_by"):
        return [make_alert(rule, [e]) for e in hits]
    window, groups, out = timedelta(minutes=rule.get("window_min", 10)), defaultdict(list), []
    for e in hits:
        if (k := _key(e, rule["group_by"])) is not None:
            groups[k].append(e)
    for evs in groups.values():
        cur = [evs[0]]
        for e in evs[1:]:
            if e["time"] - cur[-1]["time"] <= window:
                cur.append(e)
            else:
                out.append(make_alert(rule, cur))
                cur = [e]
        out.append(make_alert(rule, cur))
    return out


def _threshold(rule, events, _):
    window, need, groups, out = timedelta(minutes=rule["window_min"]), rule["min_count"], defaultdict(list), []
    for e in events:
        if matches(e, rule.get("where")) and (k := _key(e, rule["group_by"])) is not None:
            groups[k].append(e)
    for evs in groups.values():
        i = 0
        while i < len(evs):
            j = i
            while j + 1 < len(evs) and evs[j + 1]["time"] - evs[i]["time"] <= window:
                j += 1
            if j - i + 1 >= need:
                out.append(make_alert(rule, evs[i:j + 1]))
                i = j + 1
            else:
                i += 1
    return out


def _distinct_threshold(rule, events, _):
    """Alert when enough unique values occur for one target inside a time window."""
    window = timedelta(minutes=rule["window_min"])
    need = rule["min_distinct"]
    groups = defaultdict(list)
    for event in events:
        if matches(event, rule.get("where")) and (key := _key(event, rule["group_by"])) is not None:
            groups[key].append(event)

    out = []
    for grouped_events in groups.values():
        grouped_events.sort(key=lambda event: event["time"])
        start = end = 0
        values = Counter()
        while start < len(grouped_events):
            while end < len(grouped_events) and grouped_events[end]["time"] - grouped_events[start]["time"] <= window:
                value = _key(grouped_events[end], rule["distinct_by"])
                if value is not None:
                    values[value] += 1
                end += 1
            if len(values) >= need:
                evidence = grouped_events[start:end]
                out.append(make_alert(
                    rule,
                    evidence,
                    {
                        "distinct_source_count": len(values),
                        "detected_row_markers": [
                            marker
                            for event in evidence
                            for marker in re.findall(r"CSV-ROW-\d+", event.get("raw", ""))
                        ],
                    },
                ))
                start = end
                end = start
                values.clear()
            else:
                value = _key(grouped_events[start], rule["distinct_by"])
                if value is not None:
                    values[value] -= 1
                    if not values[value]:
                        del values[value]
                start += 1
    return out


def _sequence(rule, events, _):
    """Each step needs `min_count` events (default 1), in order, with the same `by` values, all within `within_min`."""
    steps, by, within = rule["steps"], rule["by"], timedelta(minutes=rule["within_min"])
    groups = defaultdict(lambda: [[] for _ in steps])
    for e in events:
        if (k := _key(e, by)) is not None:
            for i, s in enumerate(steps):
                if matches(e, s.get("where")):
                    groups[k][i].append(e)
    out = []
    for per in groups.values():
        used = set()
        for start in per[0]:
            if start["id"] in used:
                continue
            chain, t, ok = [], start["time"], True
            for i, s in enumerate(steps):
                need = s.get("min_count", 1)
                cand = [e for e in per[i] if t <= e["time"] and e["time"] - start["time"] <= within and e["id"] not in used]
                if i + 1 < len(steps) and len(cand) >= need:
                    nxt = [e for e in per[i + 1] if e["time"] >= cand[need - 1]["time"]]
                    take = [e for e in cand if not nxt or e["time"] <= nxt[0]["time"]]
                else:
                    take = cand[:need]
                if len(take) < need:
                    ok = False
                    break
                chain += take
                t = take[-1]["time"]
            if ok:
                used |= {e["id"] for e in chain}
                out.append(make_alert(rule, chain))
    return out


def _new_value(rule, events, baseline_end):
    seen, reported, out = set(), set(), []
    for e in events:
        if not matches(e, rule.get("where")) or (k := _key(e, rule["fields"])) is None:
            continue
        if e["time"] < baseline_end:
            seen.add(k)
        elif k not in seen and k not in reported:
            reported.add(k)
            out.append(make_alert(rule, [e], {"new": " / ".join(map(str, k))}))
    return out
