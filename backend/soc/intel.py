"""Threat intel from the OSINT agent (Member 1), joined to the SOC incidents.

Input: osint_output.json as written by backend/osint_agent.py:
    structured_threat_findings   vulnerability_exposure (CVE on an asset) and credential_exposure (leaked account)
    targeted_hunt_requests       "look in the logs for X on these assets" - addressed to the SOC
Looked for in this order: <log folder>/osint_output.json, then backend/data/osint_output.json. No file: no intel.

What it does (deterministic, advice only):
  - an incident gets a finding when they share an asset AND the finding's ATT&CK technique was seen
    (vulnerability), or when the leaked account appears in the incident (credential)
  - each matched finding raises the incident's score a little (it is corroborated from outside) and adds a check
  - every hunt request gets an answer: which incident covers it, or that the logs show nothing
Intel never creates an incident on its own: detection stays with the rules.
"""
from __future__ import annotations

import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
FILE = "osint_output.json"
BONUS = {"vulnerability_exposure": 5, "vulnerability_exposure_kev": 10, "credential_exposure": 10}
MAX_BONUS = 20


def load(folder: Path | None = None) -> dict:
    """Read the OSINT output. Returns {"source", "findings", "hunts"} (empty lists when there is none)."""
    for p in ([Path(folder) / FILE] if folder else []) + [DATA_DIR / FILE]:
        if p.exists():
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except (ValueError, OSError) as exc:
                return {"source": str(p), "error": f"unreadable: {exc}", "findings": [], "hunts": []}
            findings = [_finding(f, i) for i, f in enumerate(d.get("structured_threat_findings", []), 1)]
            return {"source": str(p), "findings": findings, "hunts": list(d.get("targeted_hunt_requests", []))}
    return {"source": None, "findings": [], "hunts": []}


def _finding(f: dict, n: int) -> dict:
    fid = f.get("cve") or (f"{f.get('post_id')}:{f.get('account')}" if f.get("account") else None) or f"finding-{n}"
    return {**f, "id": fid}


def _tech_match(seen: set[str], wanted) -> list[str]:
    """T1543 (from OSINT) matches T1543.002 (from a rule) and the other way round."""
    out = []
    for w in wanted or []:
        if any(s == w or s.startswith(w + ".") or w.startswith(s + ".") for s in seen):
            out.append(w)
    return out


def _lower(xs) -> set[str]:
    return {str(x).lower() for x in xs or []}


def _incident_view(inc: dict) -> tuple[set[str], set[str], set[str]]:
    hosts = _lower(h["host"] if isinstance(h, dict) else h for h in inc.get("hosts", []))
    users = _lower(inc.get("users", []))
    techs = {t["id"] if isinstance(t, dict) else t for t in inc.get("attack", [])}
    return hosts, users, techs


def match(finding: dict, inc: dict) -> str | None:
    """Why this finding belongs to this incident, or None."""
    hosts, users, techs = _incident_view(inc)
    assets = _lower(finding.get("affected_assets"))
    shared = sorted(assets & hosts)
    if finding.get("type") == "credential_exposure":
        acc = str(finding.get("account", "")).lower()
        if acc and acc in users:
            where = f" (OSINT lists it for {', '.join(shared)})" if shared else ""
            return f"leaked account {finding.get('account')} is used in this incident{where}"
        return None
    if shared and (t := _tech_match(techs, finding.get("mitre_techniques"))):
        return f"exposed asset {', '.join(shared)}, and the incident shows {', '.join(t)}"
    return None


def _check(f: dict, why: str) -> dict:
    if f.get("type") == "credential_exposure":
        when = f" on {f['timestamp'][:10]}" if f.get("timestamp") else ""
        return {"type": "contain, operator decides",
                "step": f"OSINT: account {f.get('account')} was leaked{when} ({f.get('source', 'OSINT')}). "
                        f"Consider resetting its password and ending its sessions."}
    kev = "known exploited, CISA KEV" if f.get("cisa_kev") else f"EPSS {f.get('epss_score', '?')}"
    summary = f.get("summary", "").rstrip(".")
    return {"type": "verify", "step": f"OSINT: {f.get('cve')} ({kev}) on {', '.join(f.get('affected_assets', []))}: "
                                      f"check whether it is patched" + (f" ({summary[:1].lower() + summary[1:]})." if summary else ".")}


def attach(incidents: list[dict], intel: dict, priority) -> None:
    """Add matched findings to each incident (in place), raise score/priority a little, answer the hunt requests."""
    for inc in incidents:
        inc["intel"], bonus = [], 0
        for f in intel.get("findings", []):
            if why := match(f, inc):
                inc["intel"].append({"id": f["id"], "type": f.get("type"), "why": why, "summary": f.get("summary", ""),
                                     "cisa_kev": f.get("cisa_kev"), "epss_score": f.get("epss_score"),
                                     "confidence": f.get("confidence"), "techniques": f.get("mitre_techniques", [])})
                key = "vulnerability_exposure_kev" if f.get("cisa_kev") else f.get("type", "")
                bonus += BONUS.get(key, 5)
                step = _check(f, why)
                if step not in inc.setdefault("next_checks", []):
                    inc["next_checks"].append(step)
                f.setdefault("matched_incidents", []).append(inc["id"])
        if inc["intel"]:
            inc["score"] += min(bonus, MAX_BONUS)
            inc["priority"] = priority(inc["score"])
    for f in intel.get("findings", []):
        f.setdefault("matched_incidents", [])
    for h in intel.get("hunts", []):
        hit = [i["id"] for i in incidents
               if _lower(h.get("target_assets")) & _incident_view(i)[0] and _tech_match(_incident_view(i)[2], h.get("mitre_techniques"))]
        h["status"] = f"found: {', '.join(hit)}" if hit else "no matching activity in these logs"
        h["incidents"] = hit
