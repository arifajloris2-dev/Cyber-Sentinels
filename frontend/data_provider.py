"""Adapters that provide local agent results to the desktop dashboard."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from backend.soc.pipeline import run

from .models import DashboardSnapshot


class DashboardProvider(Protocol):
    def load(self) -> DashboardSnapshot:
        """Return a complete snapshot or raise an error for the UI to report."""


class SocPipelineProvider:
    """Run the deterministic SOC pipeline against a selected local log directory."""

    def __init__(self, log_dir: Path) -> None:
        self.log_dir = log_dir

    def load(self) -> DashboardSnapshot:
        result = run(self.log_dir)
        return DashboardSnapshot.from_mapping(
            {
                "generated_at": datetime.now(timezone.utc),
                "incidents": result.get("incidents", []),
                "sources": result.get("health", []),
                "alerts": result.get("alerts", []),
                "singles": result.get("singles", []),
                "maintenance": result.get("maintenance", []),
            }
        )
