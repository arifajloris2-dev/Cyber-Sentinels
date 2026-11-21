"""Alert Verification Engine: a deterministic second opinion on what the SOC engine found.

It does not detect. For every incident (and every single, not-escalated alert) it decides:

  suspicious     evidence supports possibly malicious activity
  inconclusive   not enough, missing or contradictory evidence to decide
  likely_benign  strong, positive evidence of authorized activity

with the reasons (rule id, short text, evidence ids `source:line`) and `forward_to_ai` (True unless likely_benign).
A likely_benign verdict is recorded with its explanation, never silently dropped.

Principles (each one is a check below, and a test in tests/test_verifier.py):
  - high-risk events are never dismissed: severity >= high_risk_severity or a never-benign rule -> suspicious
  - missing evidence is never proof of normal behaviour: a silent source on an incident host or low confidence ->
    inconclusive at best; evidence from one source only -> inconclusive unless an authorized activity covers it
    (the proof of authorization then comes from assets.yaml, not from the logs)
  - an unusual event is not automatically an attack, a successful logon does not prove compromise, a legitimate
    account can still be compromised: likely_benign needs positive evidence (known, non-compromised users on machines
    they may use, no unknown address, no forbidden zone traffic, every rule covered by one authorized activity)
  - maintenance windows are handled upstream (noise.py) and are not weakened here

Settings: backend/soc/verification_rules.json. Users, zones and machines come from the log folder's assets.yaml.
Audit trail: append-only JSON Lines (default backend/data/audit/verification.jsonl), one line per decision, never
rewritten or deleted; an unchanged verdict on the same evidence is not written twice.
Advice only: nothing here blocks, disables, executes or changes anything on any system.
"""
from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

RULES_FILE = Path(__file__).resolve().parent / "verification_rules.json"
AUDIT_FILE = Path(__file__).resolve().parents[1] / "data" / "audit" / "verification.jsonl"
VERDICTS = ("suspicious", "inconclusive", "likely_benign")
OPERATOR_ACTIONS = ("close", "reopen", "override")
MAX_EVIDENCE = 6


class ConfigError(ValueError):
    """verification_rules.json is missing, not JSON or has wrong types."""


# ----------------------------------------------------------------- settings
def load_rules(path: Path | str | None = None) -> dict:
    """Read and check the settings; returns them with `_hash` (sha256 of the file) for the audit trail."""
    p = Path(path) if path else RULES_FILE
    try:
        raw = p.read_bytes()
        rules = json.loads(raw.decode("utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {p.name}: {exc}") from exc
    except (UnicodeDecodeError, ValueError) as exc:
        raise ConfigError(f"{p.name} is not valid JSON: {exc}") from exc
    if not isinstance(rules, dict):
        raise ConfigError(f"{p.name} must be a JSON object")
    checks = {"high_risk_severity": (int, float), "never_benign_rules": list, "authorized_activities": list,
              "inconclusive_when": dict, "suspicious_min_concerns": int}
    for key, kind in checks.items():
        if key in rules and not isinstance(rules[key], kind):
            raise ConfigError(f"{p.name}: '{key}' has the wrong type")
    for i, act in enumerate(rules.get("authorized_activities", [])):
        if not isinstance(act, dict) or not isinstance(act.get("rules_expected"), list):
            raise ConfigError(f"{p.name}: authorized_activities[{i}] needs a 'rules_expected' list")
    rules.setdefault("high_risk_severity", 8)
    rules.setdefault("never_benign_rules", [])
    rules.setdefault("suspicious_min_concerns", 2)
    rules.setdefault("inconclusive_when", {})
    rules.setdefault("zone_violation_rules", ["NET-008"])
    rules.setdefault("shared_host_roles", [])
    rules["_hash"] = hashlib.sha256(raw).hexdigest()[:16]
    return rules


# ----------------------------------------------------------------- helpers
def _hosts(item: dict) -> list[str]:
    return [h.get("host") if isinstance(h, dict) else str(h) for h in item.get("hosts") or [] if h]


def _evidence(alerts: list[dict]) -> list[str]:
    return [str(e.get("id")) for a in alerts for e in a.get("evidence") or [] if isinstance(e, dict) and e.get("id")]


def _hour(t: Any) -> int | None:
    if isinstance(t, datetime):
        return t.hour
    if isinstance(t, str) and len(t) >= 13 and t[10] in "T ":
        try:
            return int(t[11:13])
        except ValueError:
            return None
    return None


def _never_benign(rule: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(rule, p) for p in patterns)


class _Context:
    """Users, machines and zones from the log folder's assets.yaml."""

    def __init__(self, assets: dict | None) -> None:
        assets = assets or {}
        self.users = {u.get("user"): u for u in assets.get("users") or [] if isinstance(u, dict)}
        self.machines = {a.get("host"): a for a in assets.get("assets") or [] if isinstance(a, dict)}
        self.zones = []
        for z in assets.get("zones") or []:
            try:
                self.zones.append((z["name"], ipaddress.ip_network(z["cidr"], strict=False)))
            except (KeyError, TypeError, ValueError):
                continue

    def zone(self, host: str) -> str | None:
        try:
            ip = ipaddress.ip_address(str((self.machines.get(host) or {}).get("ip")))
        except ValueError:
            return None
        return next((name for name, net in self.zones if ip in net), None)

    def may_use(self, user: str, host: str, shared_roles: list[str]) -> bool:
        u = self.users.get(user)
        if not u or u.get("interactive") is False:
            return False
        if host == u.get("home") or u.get("privileged"):
            return True
        return (self.machines.get(host) or {}).get("role") in shared_roles


def _reason(rule: str, text: str, evidence: list[str] | None = None) -> dict:
    return {"rule": rule, "text": text, "evidence": (evidence or [])[:MAX_EVIDENCE]}


# ----------------------------------------------------------------- the verdict
def verify(item: dict, assets: dict | None, health: list[dict] | None, rules: dict) -> dict:
    """Verdict for one incident or single alert (a single alert is treated as an incident of one alert)."""
    if not isinstance(item, dict):
        return _result("inconclusive", [_reason("V-INPUT", "not an incident or alert object")], [])
    alerts = item.get("alerts")
    if alerts is None and item.get("rule"):
        alerts = [item]                                    # a single alert
    if not isinstance(alerts, list) or not alerts or not all(isinstance(a, dict) and a.get("rule") for a in alerts):
        return _result("inconclusive", [_reason("V-INPUT", "incident has no readable alerts: cannot judge it")], [])
    ctx = _Context(assets)
    evidence = _evidence(alerts)
    hosts = _hosts(item)
    users = [str(u) for u in item.get("users") or []]
    compromised = [str(u) for u in item.get("compromised_accounts") or []]
    unknown = [str(ip) for ip in item.get("unknown_ips") or []]
    rule_ids = sorted({str(a["rule"]) for a in alerts})
    reasons: list[dict] = []

    # 1. high-risk events are never dismissed
    high = []
    for a in alerts:
        try:
            sev = float(a.get("severity") or 0)
        except (TypeError, ValueError):
            sev = 0.0
        ev = _evidence([a])
        if _never_benign(str(a["rule"]), rules["never_benign_rules"]):
            high.append(_reason(f"V-NEVER-BENIGN:{a['rule']}", f"{a['rule']} ({a.get('title') or a.get('short') or 'alert'}) "
                                "is never treated as benign", ev))
        elif sev >= rules["high_risk_severity"]:
            high.append(_reason(f"V-HIGH-SEVERITY:{a['rule']}", f"{a['rule']} has severity {sev:g} "
                                f"(>= {rules['high_risk_severity']})", ev))
    seen = set()
    high = [r for r in high if not (r["rule"] in seen or seen.add(r["rule"]))]

    # 2. independent warning signs
    concerns = []
    if compromised:
        concerns.append(_reason("V-COMPROMISED", f"account(s) treated as compromised: {', '.join(compromised)}", evidence))
    if unknown:
        concerns.append(_reason("V-UNKNOWN-ADDRESS", f"{len(unknown)} address(es) not in the inventory: "
                                f"{', '.join(unknown[:3])}{' …' if len(unknown) > 3 else ''}", evidence))
    zone_alerts = [a for a in alerts if a["rule"] in rules["zone_violation_rules"]]
    if zone_alerts:
        concerns.append(_reason("V-ZONE-POLICY", "traffic between zones that the zone policy does not allow",
                                _evidence(zone_alerts)))
    stages = item.get("stages") or []
    if len(stages) >= 2:
        concerns.append(_reason("V-CHAIN", f"{len(stages)} attack stages in sequence: {' → '.join(map(str, stages))}", evidence))

    # 3. missing or thin evidence
    gaps = []
    when = rules["inconclusive_when"]
    if when.get("silent_source_on_incident_host", True):
        for h in health or []:
            if isinstance(h, dict) and not h.get("ok", True) and h.get("host") in hosts:
                gaps.append(_reason("V-MISSING-EVIDENCE", f"log source '{h.get('source')}' on {h.get('host')} was silent: "
                                    "events may be missing, so normal behaviour cannot be proven"))
    sources = {i.split(":")[0] for i in evidence}
    thin = []                                   # thin evidence: positive proof of authorization can outweigh it
    if when.get("single_source", True) and len(sources) == 1:
        thin.append(_reason("V-SINGLE-SOURCE", f"all evidence comes from one log source ({next(iter(sources))})", evidence))
    conf, low = item.get("confidence"), when.get("confidence_below")
    if isinstance(conf, (int, float)) and isinstance(low, (int, float)) and conf < low:
        gaps.append(_reason("V-LOW-CONFIDENCE", f"correlation confidence {conf:.0%} is below {low:.0%}"))

    # 4. positive evidence of authorized activity
    authorized = []
    unauthorized = []
    for u in users:
        bad = [h for h in hosts if not ctx.may_use(u, h, rules["shared_host_roles"])]
        if u not in ctx.users:
            unauthorized.append(f"{u} is not a known user")
        elif bad:
            unauthorized.append(f"{u} has no reason to use {', '.join(bad)}")
    activity = _matching_activity(rules, ctx, users, hosts, rule_ids, alerts) if users and not unauthorized else None
    if activity:
        authorized.append(_reason("V-AUTHORIZED", f"matches authorized activity '{activity['name']}': "
                                  f"{activity.get('why', '')}".rstrip(": "), evidence))

    # decision
    if high:
        verdict = "suspicious"
        reasons = high + concerns + gaps + thin
    elif len(concerns) >= rules["suspicious_min_concerns"]:
        verdict = "suspicious"
        reasons = concerns + gaps + thin
    elif concerns or gaps:
        verdict = "inconclusive"
        reasons = concerns + gaps + thin + authorized
    elif authorized:
        verdict = "likely_benign"
        reasons = authorized + [_reason("V-CLEAN", "no compromised account, no unknown address, no forbidden zone traffic, "
                                        "all log sources on these machines reported normally")] + thin
    elif thin:
        verdict = "inconclusive"
        reasons = thin + [_reason("V-NOT-PROVEN-BENIGN", "no authorized activity covers " + ", ".join(rule_ids), evidence)]
    else:
        verdict = "inconclusive"
        why = "; ".join(unauthorized) if unauthorized else (
            "no account involved" if not users else "no authorized activity covers " + ", ".join(rule_ids))
        reasons = [_reason("V-NOT-PROVEN-BENIGN", f"unusual but not proven malicious or authorized: {why}", evidence)]
    return _result(verdict, reasons, evidence)


def _matching_activity(rules: dict, ctx: _Context, users: list[str], hosts: list[str], rule_ids: list[str],
                       alerts: list[dict]) -> dict | None:
    hours = [h for h in (_hour(a.get("time")) for a in alerts) if h is not None]
    for act in rules.get("authorized_activities", []):
        if not set(rule_ids) <= set(act["rules_expected"]):
            continue
        if act.get("account") and any(u != act["account"] for u in users):
            continue
        if act.get("role") and act["role"] != "*" and any((ctx.users.get(u) or {}).get("role") != act["role"] for u in users):
            continue
        if act.get("hosts") and "*" not in act["hosts"] and any(h not in act["hosts"] for h in hosts):
            continue
        if act.get("zones") and any(ctx.zone(h) not in act["zones"] for h in hosts):
            continue
        rng = act.get("hours")
        if rng and not all(rng[0] <= h < rng[1] for h in hours):
            continue
        return act
    return None


def _result(verdict: str, reasons: list[dict], evidence: list[str]) -> dict:
    digest = hashlib.sha256("\n".join(sorted(set(evidence))).encode()).hexdigest()[:16]
    return {"verdict": verdict, "forward_to_ai": verdict != "likely_benign", "reasons": reasons,
            "evidence_hash": digest}


def apply(incidents: list[dict], singles: list[dict], health: list[dict], assets: dict | None,
          rules_path: Path | str | None = None) -> dict:
    """Add `verification` to every incident and single alert. A broken settings file -> inconclusive, never a crash."""
    try:
        rules = load_rules(rules_path)
    except ConfigError as exc:
        log.error("verification settings unusable: %s", exc)
        for item in list(incidents) + list(singles):
            item["verification"] = {**_result("inconclusive", [_reason("V-CONFIG", f"verification settings unusable: {exc}")],
                                              _evidence(item.get("alerts") or [item])), "ruleset": None}
        return {"ok": False, "error": str(exc), "ruleset": None}
    ruleset = f"{rules.get('version', '?')}/{rules['_hash']}"
    for item in list(incidents) + list(singles):
        try:
            item["verification"] = {**verify(item, assets, health, rules), "ruleset": ruleset}
        except Exception as exc:                          # one odd record must not stop the others
            log.exception("verification failed for %s", item.get("id") if isinstance(item, dict) else item)
            item["verification"] = {**_result("inconclusive", [_reason("V-INPUT", f"could not be checked: {exc}")], []),
                                    "ruleset": ruleset}
    return {"ok": True, "error": None, "ruleset": ruleset}


def run_id(result: dict) -> str:
    """Same logs -> same run id (events, rules, time span)."""
    key = f"{result.get('events')}|{result.get('rules')}|{result.get('baseline_end')}|{result.get('end')}"
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def summary(items: list[dict]) -> dict[str, int]:
    out = {v: 0 for v in VERDICTS}
    for i in items:
        v = (i.get("verification") or {}).get("verdict")
        if v in out:
            out[v] += 1
    return out


# ----------------------------------------------------------------- audit trail (append-only)
class AuditLog:
    """JSON Lines, appended only. Lines are never rewritten or deleted."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else AUDIT_FILE

    def _lines(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue                              # a damaged line is skipped, never "repaired"
        return out

    def _append(self, rows: list[dict]) -> int:
        if not rows:
            return 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")
        return len(rows)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def record_verdicts(self, items: list[dict], engine_run: str | None = None) -> int:
        """One line per automatic verdict; an unchanged verdict on the same evidence is not written again."""
        latest: dict[str, tuple] = {}
        for r in self._lines():
            if r.get("actor") == "verifier":
                latest[str(r.get("incident"))] = (r.get("verdict"), r.get("evidence_hash"))
        rows = []
        for item in items:
            v = item.get("verification") or {}
            iid = str(item.get("id"))
            if not v or latest.get(iid) == (v.get("verdict"), v.get("evidence_hash")):
                continue
            latest[iid] = (v.get("verdict"), v.get("evidence_hash"))
            rows.append({"time": self._now(), "actor": "verifier", "action": "verdict", "incident": iid,
                         "verdict": v.get("verdict"), "forward_to_ai": v.get("forward_to_ai"),
                         "reasons": [{"rule": r["rule"], "text": r["text"]} for r in v.get("reasons", [])],
                         "evidence": sorted({e for r in v.get("reasons", []) for e in r.get("evidence", [])}),
                         "evidence_hash": v.get("evidence_hash"), "ruleset": v.get("ruleset"),
                         "engine_run": engine_run or v.get("engine_run")})
        return self._append(rows)

    def record_operator(self, incident_id: str, action: str, reason: str = "", note: str = "",
                        verdict: str | None = None) -> dict:
        """A human decision: close, reopen or override (the dashboard's hiding itself stays session-only)."""
        if action not in OPERATOR_ACTIONS:
            raise ValueError(f"action must be one of {', '.join(OPERATOR_ACTIONS)}")
        if verdict is not None and verdict not in VERDICTS:
            raise ValueError(f"verdict must be one of {', '.join(VERDICTS)}")
        row = {"time": self._now(), "actor": "operator", "action": action, "incident": str(incident_id),
               "reason": str(reason)[:200], "note": str(note)[:500]}
        if verdict:
            row["verdict"] = verdict
        self._append([row])
        return row

    def last(self, n: int = 50) -> list[dict]:
        return list(reversed(self._lines()[-n:]))


# ----------------------------------------------------------------- AI forwarding (existing analyzer, injectable)
def explain(incidents: list[dict], threat_findings: list[dict] | None = None, sources: list[dict] | None = None,
            advisories: dict | None = None, analyzer: Callable[..., dict] | None = None,
            builder: Callable[..., tuple] | None = None, **analyzer_kwargs: Any) -> dict[str, dict]:
    """Ask the local AI to explain the incidents with forward_to_ai=True. The AI's answer never changes the verdict.

    analyzer/builder default to AI_Log_Analyzer.analyze_incident / build_dashboard_incident (local Ollama only);
    tests pass fakes so they never need Ollama. Ollama unavailable -> ai: "unavailable" with the error, no crash.
    """
    if analyzer is None or builder is None:
        from AI_Log_Analyzer import ai_log_analyzer as ai     # imported only when actually asked

        analyzer = analyzer or ai.analyze_incident
        builder = builder or ai.build_dashboard_incident
        analyzer_kwargs.setdefault("base_url", "http://127.0.0.1:11434")
        analyzer_kwargs.setdefault("model", "qwen3:4b")
        analyzer_kwargs.setdefault("timeout", 300)
        analyzer_kwargs.setdefault("retries", 1)
    out: dict[str, dict] = {}
    for inc in incidents:
        v = inc.get("verification") or {}
        if not v.get("forward_to_ai"):
            continue
        iid = str(inc.get("id"))
        try:
            payload, _refs = builder(inc, threat_findings or [], sources or [], advisories or {})
            answer = analyzer(payload, **analyzer_kwargs)
            out[iid] = {"verdict": v.get("verdict"), "ai": "ok", "triage_assessment": answer.get("triage_assessment"),
                        "result": answer}
        except Exception as exc:                            # Ollama down, timeout, invalid answer: keep the verdict
            out[iid] = {"verdict": v.get("verdict"), "ai": "unavailable", "error": str(exc)[:300]}
    return out
