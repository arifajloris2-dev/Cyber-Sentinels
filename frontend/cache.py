"""Precomputed results for the dashboard: the engine analysis and the AI explanations, reused while nothing changed.

The synthetic logs are deterministic, so the same logs give the same incidents and the same AI prompt. Recomputing
them on every start (engine: 5-15 s; local AI: 1-2 min per incident) only slows the demo down.

  - Engine result: stored as gzip JSON in <logs>/out/engine_cache.json.gz, valid while the log files, the rules, the
    imported knowledge and the engine code are unchanged (fingerprint of names/sizes/mtimes + rule/knowledge content).
    Plain JSON on purpose: loading it can never run code.
  - AI explanations: stored in <logs>/out/ai_explanations.json, keyed by a fingerprint of the exact prompt payload
    (incident, evidence, intel, source health) + model. Any change to what the AI would see means a new fingerprint,
    so an old explanation is never shown for changed data.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOC = ROOT / "backend" / "soc"
KNOWLEDGE = ROOT / "backend" / "data" / "knowledge"
ENGINE_FILE, AI_FILE = "engine_cache.json.gz", "ai_explanations.json"
TIME_KEYS = {"time", "time_end", "start", "end", "first", "baseline_end"}
ENGINE_KEYS = ["incidents", "singles", "alerts", "suppressed", "maintenance", "health", "agents", "intel", "event_list",
               "stats", "events", "rules", "baseline_end", "end", "seconds", "cfg", "verification"]


def _iso(o: Any) -> str:
    if isinstance(o, datetime):
        return o.isoformat(timespec="seconds")
    if isinstance(o, (set, frozenset)):
        return sorted(o)                               # type: ignore[return-value]
    return str(o)


def _revive(d: dict) -> dict:
    for k in TIME_KEYS & d.keys():
        v = d[k]
        if isinstance(v, str) and len(v) >= 19 and v[4] == "-" and "T" in v:
            try:
                d[k] = datetime.fromisoformat(v)
            except ValueError:
                pass
    return d


def _stat_lines(folder: Path, pattern: str = "*", skip: str | None = None) -> list[str]:
    out = []
    if folder.exists():
        for p in sorted(folder.rglob(pattern)):
            if p.is_file() and (skip is None or skip not in p.parts):
                st = p.stat()
                out.append(f"{p.relative_to(folder)}|{st.st_size}|{st.st_mtime_ns}")
    return out


def engine_fingerprint(log_dir: Path) -> str:
    """Changes when any log/settings file, rule, imported knowledge file or engine source file changes."""
    h = hashlib.sha256()
    for line in (_stat_lines(Path(log_dir), skip="out") + _stat_lines(SOC / "rules", "*.yaml")
                 + _stat_lines(KNOWLEDGE, "*.txt") + _stat_lines(SOC, "*.py", skip="tests")
                 + _stat_lines(SOC, "verification_rules.json")):
        h.update(line.encode() + b"\n")
    return h.hexdigest()


def load_engine(log_dir: Path) -> dict | None:
    path = Path(log_dir) / "out" / ENGINE_FILE
    if not path.exists():
        return None
    try:
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            data = json.load(fh, object_hook=_revive)
    except (OSError, ValueError):
        return None
    if data.get("fingerprint") != engine_fingerprint(log_dir):
        return None
    return data.get("result")


def save_engine(log_dir: Path, result: dict) -> Path:
    out = Path(log_dir) / "out"
    out.mkdir(parents=True, exist_ok=True)
    slim = {k: result[k] for k in ENGINE_KEYS if k in result}
    slim["stats"] = [{k: v for k, v in s.items() if k != "times"} for s in result.get("stats", [])]
    tmp, path = out / (ENGINE_FILE + ".tmp"), out / ENGINE_FILE
    with gzip.open(tmp, "wt", encoding="utf-8") as fh:
        json.dump({"fingerprint": engine_fingerprint(log_dir), "saved": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                   "result": slim}, fh, default=_iso)
    os.replace(tmp, path)
    return path


# ----------------------------------------------------------------- AI explanations
def ai_payload(incident: dict, snapshot: Any) -> tuple[dict, dict]:
    """The exact payload the dashboard sends to the local AI (shared by the dashboard and the precompute command)."""
    from AI_Log_Analyzer.ai_log_analyzer import build_dashboard_incident

    iid = str(incident.get("id"))
    # the AI sees the knowledge that matters for THIS incident first, then the operator's newest imports
    findings = sorted(snapshot.threat_findings, key=lambda f: (iid not in (f.get("matched_incidents") or []),
                                                               not str(f.get("id", "")).startswith("KB-")))
    return build_dashboard_incident(incident, findings, snapshot.sources, snapshot.advisories)


def ai_fingerprint(payload: dict, model: str) -> str:
    blob = json.dumps({"payload": payload, "model": model}, sort_keys=True, default=_iso)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class AiCache:
    """Saved AI explanations for one log folder."""

    def __init__(self, log_dir: Path | None) -> None:
        self.path = Path(log_dir) / "out" / AI_FILE if log_dir else None
        self.items: dict[str, dict] = {}
        if self.path and self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self.items = data.get("items", {}) if isinstance(data, dict) else {}
            except (OSError, ValueError):
                self.items = {}

    def get(self, fingerprint: str) -> dict | None:
        return self.items.get(fingerprint)

    def put(self, fingerprint: str, incident_id: str, model: str, result: dict, evidence_refs: dict, seconds: float) -> None:
        self.items[fingerprint] = {"incident": incident_id, "model": model, "result": result, "evidence_refs": evidence_refs,
                                   "seconds": round(seconds, 1), "created": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        self.save()

    def save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"items": self.items}, indent=1, default=_iso), encoding="utf-8")
        os.replace(tmp, self.path)
