"""Adapters that provide local agent results to the dashboard."""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Protocol

from backend.soc.pipeline import run
from backend.osint_agent import (
    DEFAULT_ASSETS,
    DEFAULT_KEV_NVD_EPSS,
    DEFAULT_OSINT_POSTS,
    run_osint_agent,
)

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


class IntegratedAgentProvider(SocPipelineProvider):
    """Combine deterministic SOC results with the completed OSINT and local AI agents."""

    def __init__(self, log_dir: Path, data_dir: Path | None = None) -> None:
        super().__init__(log_dir)
        self.data_dir = data_dir or Path(__file__).resolve().parents[1] / "backend" / "data"

    def _load_list(self, filename: str, default: list) -> list:
        path = self.data_dir / filename
        if not path.exists():
            return default
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default
        return value if isinstance(value, list) else default

    def load(self) -> DashboardSnapshot:
        soc_snapshot = super().load()
        assets = self._load_list("assets.json", DEFAULT_ASSETS)
        vuln_intel = self._load_list("cached_kev_nvd.json", DEFAULT_KEV_NVD_EPSS)
        osint_posts = self._load_list("osint_posts.json", DEFAULT_OSINT_POSTS)
        osint_result = run_osint_agent(assets, vuln_intel, osint_posts)

        return DashboardSnapshot(
            generated_at=soc_snapshot.generated_at,
            incidents=soc_snapshot.incidents,
            sources=soc_snapshot.sources,
            alerts=soc_snapshot.alerts,
            singles=soc_snapshot.singles,
            maintenance=soc_snapshot.maintenance,
            threat_findings=osint_result["structured_threat_findings"],
            hunt_requests=osint_result["targeted_hunt_requests"],
        )


class CsvSimulationProvider(IntegratedAgentProvider):
    """Stream a network-attack CSV through the SOC and compare with ground truth."""

    def __init__(self, csv_path: Path, batch_size: int = 30, interval_seconds: int = 2) -> None:
        root = Path(__file__).resolve().parents[1]
        output_dir = root / "simulation" / "output" / csv_path.stem
        super().__init__(output_dir)
        self.csv_path = csv_path.resolve()
        from simulation.csv_adapter import iter_csv_rows, reset_simulation

        self._iter_csv_rows = iter_csv_rows
        self._rows = iter_csv_rows(self.csv_path)
        self.batch_size = batch_size
        self.interval_seconds = interval_seconds
        self.next_row = 1
        self.rows_seen = 0
        self.cycle = 1
        self.cycle_start = datetime.now(timezone.utc)
        self.window_size = 300
        self._cycle_rows = 0
        self._recent_rows: deque[tuple[int, dict]] = deque(maxlen=self.window_size)
        reset_simulation(output_dir, self.cycle, self.cycle_start)

    def load(self) -> DashboardSnapshot:
        from simulation.csv_adapter import append_rows, reset_simulation

        rows = []
        for _ in range(self.batch_size):
            try:
                rows.append(next(self._rows))
            except StopIteration:
                break
        if not rows:
            self.next_row = 1
            self.cycle += 1
            self.cycle_start = datetime.now(timezone.utc)
            self._cycle_rows = 0
            self._recent_rows.clear()
            self._rows = self._iter_csv_rows(self.csv_path)
            reset_simulation(self.log_dir, self.cycle, self.cycle_start)
            for _ in range(self.batch_size):
                try:
                    rows.append(next(self._rows))
                except StopIteration:
                    break
        if rows:
            self.next_row = rows[-1][0] + 1
            self.rows_seen += len(rows)
            self._cycle_rows += len(rows)
            self._recent_rows.extend(rows)
            append_rows(self.log_dir, self.csv_path, rows[0][0], len(rows), rows=rows)
            if self._cycle_rows > self.window_size:
                recent = list(self._recent_rows)
                reset_simulation(self.log_dir, self.cycle, self.cycle_start)
                append_rows(
                    self.log_dir,
                    self.csv_path,
                    recent[0][0],
                    len(recent),
                    rows=recent,
                )
        snapshot = super().load()

        manifest_path = self.log_dir / "csv_ground_truth.json"
        ground_truth = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {"rows": []}
        detected_rows = {
            int(match)
            for alert in snapshot.alerts
            for match in (
                re.findall(
                    r"CSV-ROW-(\d+)",
                    " ".join(alert.get("detected_row_markers", []))
                    + " "
                    + " ".join(
                        str(evidence.get("raw", ""))
                        for evidence in alert.get("evidence", [])
                    ),
                )
            )
        }

        detected_attacks = missed_attacks = false_positives = 0
        for row in ground_truth["rows"]:
            row_detected = int(row["row"]) in detected_rows
            if row["attack"] and row_detected:
                detected_attacks += 1
            elif row["attack"]:
                missed_attacks += 1
            elif row_detected:
                false_positives += 1

        attack_count = sum(1 for row in ground_truth["rows"] if row["attack"])
        recall = detected_attacks / attack_count if attack_count else 0.0
        precision = detected_attacks / (detected_attacks + false_positives) if (detected_attacks + false_positives) else 0.0
        evaluation = {
            "rows_seen": self.rows_seen,
            "window_rows": len(ground_truth["rows"]),
            "ground_truth_attacks": attack_count,
            "detected_attacks": detected_attacks,
            "missed_attacks": missed_attacks,
            "false_positives": false_positives,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "cycle": self.cycle,
        }
        return DashboardSnapshot(
            generated_at=snapshot.generated_at,
            incidents=snapshot.incidents,
            sources=snapshot.sources,
            alerts=snapshot.alerts,
            singles=snapshot.singles,
            maintenance=snapshot.maintenance,
            threat_findings=snapshot.threat_findings,
            hunt_requests=snapshot.hunt_requests,
            advisories=snapshot.advisories,
            evaluation=evaluation,
        )
