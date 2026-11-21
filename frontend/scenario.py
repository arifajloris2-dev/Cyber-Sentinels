"""Exercise view: what was planted in the synthetic logs (truth.json) next to what the SOC engine actually found.

Only the synthetic log folders have an answer key (backend/soc/fleet/make_fleet.py writes truth.json). The dashboard
reads it as plain JSON (data only) and never uses it for detection: the engine never sees it. It is shown so the
audience can check the engine against the known story: every planted attack should be one incident, and no
harmless look-alike or approved maintenance should become one.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

STEP_ORDER = ["entry", "delivery", "credential", "execution", "persistence", "privilege", "lateral", "defense-evasion",
              "collection", "c2", "exfil", "impact"]
STEP_LABEL = {"entry": "Entry", "delivery": "Delivery", "credential": "Credential theft", "execution": "Execution",
              "persistence": "Persistence", "privilege": "Privilege escalation", "lateral": "Lateral movement",
              "defense-evasion": "Covering tracks", "collection": "Collection", "c2": "Command & control",
              "exfil": "Exfiltration", "impact": "Impact"}
ROUTINE = {"kerberos", "sudo -i", "edge noise", "inventory.ps1"}    # daily normal behaviour, both days


def load_truth(log_dir: Path | None) -> dict | None:
    if not log_dir:
        return None
    path = Path(log_dir) / "truth.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and isinstance(data.get("attacks"), dict) else None


def _evidence_ids(incident: dict) -> set[str]:
    return {str(e.get("id")) for a in incident.get("alerts") or [] for e in a.get("evidence") or [] if isinstance(e, dict)}


def _lines(truth: dict, key: str) -> set[str]:
    return {x for k, v in (truth.get("lines") or {}).items() if k == key or k.startswith(key + ":") for x in v}


def build(truth: dict | None, incidents: list[dict]) -> dict | None:
    """Compare the answer key with the incidents. None when this log folder has no answer key."""
    if not truth:
        return None
    ev = [(inc, _evidence_ids(inc)) for inc in incidents]

    def raised_by(key: str) -> list[dict]:
        lines = _lines(truth, key)
        return [inc for inc, ids in ev if lines and ids & lines]

    attacks = []
    for aid, a in (truth.get("attacks") or {}).items():
        steps = sorted({k.split(":", 1)[1] for k in truth.get("lines", {}) if k.startswith(aid + ":")},
                       key=lambda s: STEP_ORDER.index(s) if s in STEP_ORDER else 99)
        hits = raised_by(aid)
        attacks.append({**{k: v for k, v in a.items()}, "id": aid,
                        "steps": [{"key": s, "label": STEP_LABEL.get(s, s.title()),
                                   "lines": len(truth["lines"].get(f"{aid}:{s}", []))} for s in steps],
                        "lines": len(_lines(truth, aid)),
                        "incidents": [{"id": str(i.get("id")), "priority": i.get("priority"), "score": i.get("score"),
                                       "title": i.get("title")} for i in hits]})
    lookalikes, routine = [], []
    for key, text in (truth.get("lookalikes") or {}).items():
        hits = raised_by(key)
        item = {"id": key, "text": str(text), "lines": len(_lines(truth, key)),
                "incidents": [str(i.get("id")) for i in hits]}
        (routine if key in ROUTINE else lookalikes).append(item)
    maintenance = [{"key": k, "ticket": str(t), "lines": len(_lines(truth, k)),
                    "incidents": [str(i.get("id")) for i in raised_by(k)]}
                   for k, t in (truth.get("maintenance") or {}).items()]
    detected = sum(1 for a in attacks if a["incidents"])
    false_alarms = sum(1 for x in lookalikes + routine + maintenance if x["incidents"])
    return {"attacks": attacks, "lookalikes": lookalikes, "routine": routine, "maintenance": maintenance,
            "silent": truth.get("silent_source") or {}, "detected": detected, "false_alarms": false_alarms}


def summary_line(view: dict[str, Any]) -> str:
    return (f"{view['detected']} of {len(view['attacks'])} planted attacks raised as incidents · "
            f"{view['false_alarms']} harmless activities raised by mistake")
