"""Shared data contract between the dashboard and project agents."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


Record = dict[str, Any]


def _records(payload: Mapping[str, Any], key: str) -> list[Record]:
    value = payload.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError(f"Dashboard field '{key}' must be a list of objects.")
    return list(value)


@dataclass(frozen=True, slots=True)
class DashboardSnapshot:
    """One dashboard refresh, independent of how each agent provides data."""

    generated_at: datetime
    incidents: list[Record]
    sources: list[Record]
    alerts: list[Record] = field(default_factory=list)
    singles: list[Record] = field(default_factory=list)
    maintenance: list[Record] = field(default_factory=list)
    threat_findings: list[Record] = field(default_factory=list)
    hunt_requests: list[Record] = field(default_factory=list)
    advisories: dict[str, Record] = field(default_factory=dict)
    evaluation: Record = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> DashboardSnapshot:
        if not isinstance(payload, Mapping):
            raise ValueError("A dashboard snapshot must be an object.")

        generated = payload.get("generated_at")
        if generated is None:
            generated_at = datetime.now(timezone.utc)
        elif isinstance(generated, datetime):
            generated_at = generated
        elif isinstance(generated, str):
            try:
                generated_at = datetime.fromisoformat(generated.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError("Dashboard field 'generated_at' must be an ISO-8601 timestamp.") from exc
        else:
            raise ValueError("Dashboard field 'generated_at' must be an ISO-8601 timestamp.")

        advisories = payload.get("advisories", {})
        if not isinstance(advisories, dict) or any(not isinstance(item, dict) for item in advisories.values()):
            raise ValueError("Dashboard field 'advisories' must map incident IDs to objects.")

        return cls(
            generated_at=generated_at,
            incidents=_records(payload, "incidents"),
            sources=_records(payload, "sources"),
            alerts=_records(payload, "alerts"),
            singles=_records(payload, "singles"),
            maintenance=_records(payload, "maintenance"),
            threat_findings=_records(payload, "threat_findings"),
            hunt_requests=_records(payload, "hunt_requests"),
            advisories=dict(advisories),
            evaluation=dict(payload.get("evaluation", {})) if isinstance(payload.get("evaluation", {}), dict) else {},
        )
