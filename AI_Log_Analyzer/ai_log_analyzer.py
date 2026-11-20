#!/usr/bin/env python3
"""Send security incidents to a remote Ollama server (Qwen3 4B) and print
a structured JSON analysis for each one.

Usage:
    python analyze.py incident.json
    cat incident.json | python analyze.py
    python analyze.py incidents.json --output results.json
    python analyze.py incident.json --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any

import requests
from jsonschema import Draft202012Validator

log = logging.getLogger("incident-analyzer")

DEFAULT_URL = "http://192.168.1.50:11434"
DEFAULT_MODEL = "qwen3:4b"
DEFAULT_TIMEOUT = 120.0
DEFAULT_RETRIES = 2

# ---------------------------------------------------------------------------
# Output schema (passed to Ollama's "format" field and used for validation)
# ---------------------------------------------------------------------------
RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {
            "type": "string",
            "minLength": 1,
            "pattern": r"\S"
        },
        "severity": {"type": "string", "enum": ["Low", "Medium", "High", "Critical"]},
        "evidence": {"type": "array", "items": {"type": "string"}},
        "possible_attack": {
            "type": "string",
            "minLength": 1,
            "pattern": r"\S"
        },
        "uncertainty": {
            "type": "string",
            "minLength": 1,
            "pattern": r"\S"
        },
        "mitre_attack": {
            "type": "array",
            "items": {
                 "type": "object",
            "properties": {
                "id": {"type": "string"},
                "name": {"type": "string"},
            "evidence": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            },
        "required": ["id", "name", "evidence"],
        "additionalProperties": False
    }
},
        "recommendations": {"type": "array", "items": {"type": "string"}},
        "commander_summary_en": {
            "type": "string",
            "minLength": 1,
            "pattern": r"\S"
        },
        
    },
    "required": [
        "mitre_attack",
        "summary",
        "severity",
        "evidence",
        "possible_attack",
        "uncertainty",
        "recommendations",
    ],
    "additionalProperties": False,
}
MITRE_TECHNIQUES = {
    "T1110": "Brute Force",
    "T1078": "Valid Accounts"
}

def validate_mitre(report, valid_ids):
    for technique in report["mitre_attack"]:
        technique_id = technique["id"]

        if technique_id not in MITRE_TECHNIQUES:
            raise ValueError(
                f"Unknown MITRE technique: {technique_id}"
            )

        if technique["name"] != MITRE_TECHNIQUES[technique_id]:
            raise ValueError("Incorrect MITRE technique name")

        if not technique["evidence"]:
            raise ValueError("MITRE mapping has no evidence")

        if not set(technique["evidence"]).issubset(valid_ids):
            raise ValueError("Invalid MITRE evidence IDs")

    return report

VALIDATOR = Draft202012Validator(RESULT_SCHEMA)

# ---------------------------------------------------------------------------
# Prompts (kept short and concrete for a small 4B model)
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """You are a SOC analyst assistant. You receive a security incident as JSON with a list of log events.

Rules:
- Base your analysis ONLY on the provided events. Do not invent facts, IP addresses, usernames or events.
- In "evidence", list ONLY event IDs that appear in the input (for example "E1"). Include the events that support your conclusion.
- In "uncertainty", state clearly what is NOT confirmed or cannot be determined from the events.
- "severity" must be one of: Low, Medium, High, Critical.
  Low = routine noise, Medium = suspicious but no sign of success,
  High = likely compromise or successful suspicious access, Critical = confirmed compromise or active damage.
- "recommendations" must be short, practical next steps for an analyst.
- Reply with a single JSON object and nothing else.
MITRE ATT&CK Mapping:
- T1110: Brute Force
- T1078: Valid Accounts

Rules:
- Identify possible MITRE ATT&CK techniques.
- Only use techniques supported by incident evidence.
- Include supporting event IDs for each technique.
- Never invent MITRE technique IDs.
- If no technique matches, return an empty list.
- A successful login alone does not prove malicious activity.

Defensive recommendations:
- Recommend investigation and defensive actions only.
- Recommendations must be short and practical.
- Do not execute commands or change any system.
- All defensive actions require human approval.
- Do not recommend destructive actions.

Commander summaries:
- Generate commander_summary_en in English.
- Each summary must be 2-3 short sentences.
- Explain what happened, possible impact, and uncertainty.
- Use simple, non-technical language.
- Do not invent information.
"""


# One few-shot example, deliberately using different event IDs and a different
# scenario so the model learns the format rather than copying the content.
EXAMPLE_INCIDENT: dict[str, Any] = {
    "incident_id": "EXAMPLE",
    "events": [
        {"id": "X1", "timestamp": "2026-01-05T08:00:01Z", "source": "webapp", "message": "Failed login for user admin from 198.51.100.7"},
        {"id": "X2", "timestamp": "2026-01-05T08:00:04Z", "source": "webapp", "message": "Failed login for user admin from 198.51.100.7"},
        {"id": "X3", "timestamp": "2026-01-05T08:00:08Z", "source": "webapp", "message": "Failed login for user admin from 198.51.100.7"},
        {"id": "X4", "timestamp": "2026-01-05T08:00:20Z", "source": "webapp", "message": "Successful login for user admin from 198.51.100.7"},
    ],
}
EXAMPLE_OUTPUT: dict[str, Any] = {
    "summary": "Possible web admin account compromise",
    "severity": "High",
    "evidence": ["X1", "X2", "X3", "X4"],
    "possible_attack": "Credential brute-force against the web login",
    "uncertainty": "Activity after the login is not shown, so unauthorized access is not confirmed",
    "recommendations": [
        "Investigate the admin account and reset its credentials",
        "Review web application logs for actions after the login",
        "Block or rate-limit the source IP",
    ],
}


class OllamaError(RuntimeError):
    """Raised when the Ollama server cannot be reached or returns an error."""


class AnalysisError(RuntimeError):
    """Raised when the model never returned a valid response."""

    def __init__(self, message: str, raw: str = "") -> None:
        super().__init__(message)
        self.raw = raw


# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------
def load_incidents(path: str | None) -> list[dict[str, Any]]:
    """Load one incident or a list of incidents from a file or stdin."""
    text = Path(path).read_text(encoding="utf-8") if path else sys.stdin.read()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Input is not valid JSON: {exc}") from exc

    incidents = [data] if isinstance(data, dict) else data
    if not isinstance(incidents, list) or not incidents:
        raise ValueError("Input must be an incident object or a non-empty list of incidents.")

    for i, inc in enumerate(incidents, start=1):
        if not isinstance(inc, dict):
            raise ValueError(f"Incident #{i} is not a JSON object.")
        events = inc.get("events")
        if not isinstance(events, list) or not events:
            raise ValueError(f"Incident #{i} needs a non-empty 'events' list.")
        for ev in events:
            if not isinstance(ev, dict) or "id" not in ev:
                raise ValueError(f"Incident #{i} has an event without an 'id'.")
        inc.setdefault("incident_id", f"INC-{i:03d}")
    return incidents


# ---------------------------------------------------------------------------
# Prompt / request building
# ---------------------------------------------------------------------------
def build_messages(incident: dict[str, Any]) -> list[dict[str, str]]:
    """System prompt + one few-shot example + the real incident."""
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(EXAMPLE_INCIDENT, indent=2)},
        {"role": "assistant", "content": json.dumps(EXAMPLE_OUTPUT, indent=2)},
        {"role": "user", "content": json.dumps(incident, indent=2)},
    ]


def build_payload(model: str, messages: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "model": model,
        "messages": messages,
        "stream": False,
        "think": False,  # disable Qwen3 reasoning output
        "format": RESULT_SCHEMA,  # structured outputs
        "options": {"temperature": 0, "num_ctx": 8192},
    }


# ---------------------------------------------------------------------------
# Ollama call
# ---------------------------------------------------------------------------
def query_ollama(base_url: str, payload: dict[str, Any], timeout: float) -> str:
    """POST to /api/chat and return message.content."""
    url = base_url.rstrip("/") + "/api/chat"
    try:
        resp = requests.post(url, json=payload, timeout=timeout)
    except requests.exceptions.Timeout as exc:
        raise OllamaError(f"Timed out after {timeout:.0f}s waiting for {url}") from exc
    except requests.exceptions.ConnectionError as exc:
        raise OllamaError(
            f"Could not connect to {url}. Check OLLAMA_URL, that Ollama is running, "
            "that it listens on 0.0.0.0 (OLLAMA_HOST) and that the firewall allows the port."
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise OllamaError(f"Request to {url} failed: {exc}") from exc

    if resp.status_code != 200:
        hint = ""
        if resp.status_code == 404:
            hint = f" (is the model pulled? try: ollama pull {payload['model']})"
        raise OllamaError(f"Ollama returned HTTP {resp.status_code}{hint}: {resp.text[:300]}")

    try:
        return resp.json()["message"]["content"]
    except (ValueError, KeyError, TypeError) as exc:
        raise OllamaError(f"Unexpected response format from Ollama: {resp.text[:300]}") from exc


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def strip_think(text: str) -> str:
    """Remove <think>...</think> blocks (fallback if think=false is ignored)."""
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def validate_response(raw: str, valid_ids: set[str]) -> dict[str, Any]:
    """Parse, schema-check, and drop evidence IDs that are not in the incident."""
    text = strip_think(raw)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Response is not valid JSON: {exc}") from exc

    errors = sorted(VALIDATOR.iter_errors(data), key=lambda e: list(e.path))
    if errors:
        raise ValueError("Schema validation failed: " + "; ".join(e.message for e in errors))

    unknown = [e for e in data["evidence"] if e not in valid_ids]
    if unknown:
        log.warning("Dropping evidence IDs not present in the incident: %s", unknown)
        data["evidence"] = [e for e in data["evidence"] if e in valid_ids]
    return validate_mitre(data, valid_ids)

def analyze_incident(
    incident: dict[str, Any], base_url: str, model: str, timeout: float, retries: int
) -> dict[str, Any]:
    """Query the model, retrying (with error feedback) if the output is invalid."""
    valid_ids = {str(ev["id"]) for ev in incident["events"]}
    messages = build_messages(incident)
    raw = ""
    last_error = "unknown error"

    for attempt in range(retries + 1):
        raw = query_ollama(base_url, build_payload(model, messages), timeout)
        try:
            return validate_response(raw, valid_ids)
        except ValueError as exc:
            last_error = str(exc)
            log.warning("Attempt %d/%d failed: %s", attempt + 1, retries + 1, last_error)
            # Temperature is 0, so tell the model what went wrong to change the outcome.
            messages = messages + [
                {"role": "assistant", "content": raw},
                {
                    "role": "user",
                    "content": f"Your previous reply was invalid ({last_error}). "
                    "Reply again with only the corrected JSON object.",
                },
            ]

    raise AnalysisError(f"No valid response after {retries + 1} attempts: {last_error}", raw)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Analyze security incidents with a remote Ollama model.")
    p.add_argument("file", nargs="?", help="Incident JSON file (reads stdin if omitted)")
    p.add_argument("--output", "-o", help="Also save the results to this JSON file")
    p.add_argument("--dry-run", action="store_true", help="Print the request payload without contacting Ollama")
    p.add_argument("--url", default=os.environ.get("OLLAMA_URL", DEFAULT_URL), help="Ollama base URL (env: OLLAMA_URL)")
    p.add_argument("--model", default=os.environ.get("OLLAMA_MODEL", DEFAULT_MODEL), help="Model name (env: OLLAMA_MODEL)")
    p.add_argument("--timeout", type=float, default=float(os.environ.get("OLLAMA_TIMEOUT", DEFAULT_TIMEOUT)), help="Request timeout in seconds (env: OLLAMA_TIMEOUT)")
    p.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Retries on invalid model output")
    p.add_argument("--verbose", "-v", action="store_true", help="Debug logging")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,  # keep stdout clean for JSON
    )

    try:
        incidents = load_incidents(args.file)
    except (OSError, ValueError) as exc:
        log.error("%s", exc)
        return 2

    if args.dry_run:
        for inc in incidents:
            payload = build_payload(args.model, build_messages(inc))
            print(json.dumps({"url": args.url.rstrip("/") + "/api/chat", "payload": payload}, indent=2))
        return 0

    results: list[dict[str, Any]] = []
    failed = False
    for inc in incidents:
        incident_id = inc["incident_id"]
        log.info("Analyzing %s (%d events)", incident_id, len(inc["events"]))
        try:
            analysis = analyze_incident(inc, args.url, args.model, args.timeout, args.retries)
            results.append({"incident_id": incident_id, **analysis})
        except OllamaError as exc:
            log.error("%s: %s", incident_id, exc)
            results.append({"incident_id": incident_id, "error": str(exc)})
            failed = True
        except AnalysisError as exc:
            log.error("%s: %s\nRaw model response:\n%s", incident_id, exc, exc.raw)
            results.append({"incident_id": incident_id, "error": str(exc), "raw_response": exc.raw})
            failed = True

    output = results[0] if len(results) == 1 else results
    rendered = json.dumps(output, indent=2, ensure_ascii=False)
    print(rendered)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        log.info("Saved results to %s", args.output)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())