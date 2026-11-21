"""NiceGUI dashboard for the local Cyber Sentinels SOC."""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nicegui import ui

from AI_Log_Analyzer.ai_log_analyzer import (
    AnalysisError,
    OllamaError,
    analyze_incident,
    build_dashboard_incident,
    check_ollama_model,
)
from frontend.data_provider import CsvSimulationProvider, DashboardProvider, IntegratedAgentProvider
from frontend.explanations import instant_overview, plain_alert_explanation
from frontend.models import DashboardSnapshot, Record

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOGS = ROOT / "backend" / "soc" / "fleet" / "logs"
FLEET_GENERATOR = ROOT / "backend" / "soc" / "fleet" / "make_fleet.py"
COLORS = {
    "background": "#f2f5f9",
    "surface": "#ffffff",
    "border": "#dce4ed",
    "ink": "#142235",
    "muted": "#66778b",
    "navy": "#142c44",
    "navy_light": "#203f5b",
    "teal": "#119879",
    "blue": "#3473d1",
    "amber": "#a85d00",
    "red": "#b9364d",
    "green": "#23774d",
}
log = logging.getLogger(__name__)


def _ensure_default_fleet_logs(log_path: Path) -> None:
    if log_path.resolve() == DEFAULT_LOGS.resolve() and not (log_path / "sources.yaml").is_file():
        subprocess.run(
            [sys.executable, str(FLEET_GENERATOR), "--no-ecs"],
            cwd=ROOT,
            check=True,
        )


def _text(value: Any, default: str = "—") -> str:
    return default if value is None or value == "" else str(value)


def _when(value: Any, fmt: str = "%Y-%m-%d %H:%M UTC") -> str:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    else:
        return _text(value)
    if result.tzinfo is None:
        return result.strftime(fmt)
    return result.astimezone(timezone.utc).strftime(fmt)


def _priority(severity: Any) -> str:
    try:
        score = int(severity)
    except (TypeError, ValueError):
        return "P3"
    return "P1" if score >= 8 else "P2" if score >= 5 else "P3"


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _format_elapsed_minutes(value: int | float) -> str:
    minutes = max(0, int(value))
    hours, remainder = divmod(minutes, 60)
    if hours and remainder:
        return f"{hours}h {remainder}m"
    if hours:
        return f"{hours}h"
    return f"{remainder}m"


def _priority_colors(priority: str) -> tuple[str, str]:
    return {
        "P1": ("#fdecef", COLORS["red"]),
        "P2": ("#fff3df", COLORS["amber"]),
        "P3": ("#eaf1fc", COLORS["blue"]),
    }.get(priority, ("#eaf1fc", COLORS["blue"]))


class DashboardPage:
    def __init__(self, provider: DashboardProvider, refresh_seconds: int | None) -> None:
        self._client = ui.context.client
        self.provider = provider
        self.refresh_seconds = refresh_seconds
        self.snapshot: DashboardSnapshot | None = None
        self.incidents: list[Record] = []
        self.selected_incident_id: str | None = None
        self.loading = False
        self.qwen_ready = False
        self.qwen_checking = False
        self.qwen_message = "Checking local Qwen3…"
        self.checked_qwen_config: tuple[str, str] | None = None
        self.qwen_results: dict[str, tuple[Record, dict[str, str]]] = {}
        self.qwen_errors: dict[str, str] = {}
        self.qwen_in_flight: set[str] = set()
        self.alert_history: list[Record] = []
        self.alert_fingerprints: set[tuple[Any, ...]] = set()
        self.ollama_url = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
        self.ollama_model = os.environ.get("OLLAMA_MODEL", "qwen3:4b")
        self._build()
        ui.timer(0.1, self.refresh, once=True)
        if self.refresh_seconds is not None:
            ui.timer(self.refresh_seconds, self.refresh)
        ui.timer(0.2, self.test_qwen, once=True)

    def _build(self) -> None:
        ui.page_title("Cyber Sentinels | Incident Operations")
        ui.add_head_html(
            """
            <style>
              body { background: #f2f5f9; color: #142235; }
              .soc-shell { max-width: 1480px; margin: 0 auto; }
              .soc-card { border: 1px solid #dce4ed; border-radius: 16px; box-shadow: 0 2px 6px #1422350b; }
              .soc-workspace { display: grid; grid-template-columns: minmax(290px, 4fr) minmax(0, 7fr); gap: 18px; align-items: start; }
              .soc-metric { flex: 1 1 175px; min-width: 155px; }
              .soc-source-table .q-table__middle { max-height: 240px; overflow-y: auto; }
              .soc-source-table .q-table thead tr th { position: sticky; top: 0; z-index: 1; background: white; }
              .soc-explanation-text { overflow-wrap: anywhere; }
              @media (max-width: 980px) { .soc-workspace { grid-template-columns: 1fr; } }
            </style>
            """
        )
        with ui.column().classes("soc-shell w-full p-4 gap-3"):
            self._build_header()
            self._build_qwen_config()
            self.status_line = ui.label("Loading SOC data…").classes("text-sm").style(
                f"color:{COLORS['muted']}"
            )
            self._build_metrics()
            with ui.element("div").classes("soc-workspace w-full"):
                with ui.column().classes("w-full gap-4"):
                    self._build_priority_queue()
                    self._build_sources()
                    self._build_member_one()
                with ui.column().classes("w-full gap-4"):
                    self._build_selected_incident()
                    self._build_explanation()
                    self._build_timeline()
            ui.label(
                "Detection and correlation remain deterministic; Member 1 intelligence is context, "
                "and no response action is automatic."
            ).classes("text-xs").style(f"color:{COLORS['muted']}")
        self._build_dialogs()

    def _build_header(self) -> None:
        with ui.row().classes("w-full items-center justify-between gap-4 flex-wrap p-4").style(
            f"background:{COLORS['navy']};border-radius:18px"
        ):
            with ui.row().classes("items-center gap-3"):
                ui.icon("shield").classes("text-3xl").style(f"color:{COLORS['teal']}")
                with ui.column().classes("gap-0"):
                    ui.label("CYBER SENTINELS").classes("text-xl font-bold text-white")
                    ui.label("DEFENSIVE OPERATIONS  /  LOCAL SOC").classes(
                        "text-xs"
                    ).style("color:#bdcbd9")
            with ui.row().classes("items-center gap-2 flex-wrap"):
                self.data_badge = ui.badge("MONITORING · STARTING").style(
                    "background:#203f5b;color:#dce8f2"
                )
                self.model_badge = ui.badge("QWEN3 · CHECKING").style(
                    "background:#203f5b;color:#dce8f2"
                )
                self.refresh_button = ui.button(
                    "Refresh", icon="refresh", on_click=self.refresh
                ).props(
                    "unelevated"
                ).style("background:#3473d1;color:white")
                self.alerts_button = ui.button(
                    "Alerts 0", icon="notifications", on_click=self.open_alert_history
                ).props("outline").style("color:white")

    def _build_qwen_config(self) -> None:
        with ui.card().classes("soc-card w-full"):
            with ui.row().classes("w-full items-end gap-3 flex-wrap"):
                self.url_input = ui.input(
                    "Ollama URL", value=self.ollama_url
                ).props("outlined dense").classes("grow min-w-[260px]")
                self.model_input = ui.input(
                    "Model", value=self.ollama_model
                ).props("outlined dense").classes("w-56")
                self.test_qwen_button = ui.button(
                    "Test Qwen", icon="wifi_tethering", on_click=self.test_qwen
                ).props("unelevated").style(f"background:{COLORS['blue']};color:white")
            self.url_input.on_value_change(self._on_qwen_config_change)
            self.model_input.on_value_change(self._on_qwen_config_change)
            self.qwen_status = ui.label(self.qwen_message).classes("text-sm").style(
                f"color:{COLORS['muted']}"
            )

    def _build_metrics(self) -> None:
        self.metric_values: dict[str, Any] = {}
        with ui.row().classes("w-full gap-3 flex-wrap"):
            for title, key, color in (
                ("OPEN INCIDENTS", "incidents", COLORS["blue"]),
                ("PRIORITY 1", "p1", COLORS["red"]),
                ("DETECTION ALERTS", "alerts", COLORS["amber"]),
                ("HEALTHY SOURCES", "sources", COLORS["green"]),
            ):
                with ui.card().classes("soc-card soc-metric p-4"):
                    ui.label(title).classes("text-xs font-bold").style(
                        f"color:{COLORS['muted']}"
                    )
                    self.metric_values[key] = ui.label("0").classes(
                        "text-3xl font-bold"
                    ).style(f"color:{color}")

    def _build_priority_queue(self) -> None:
        with ui.card().classes("soc-card w-full"):
            with ui.row().classes("w-full items-center justify-between"):
                ui.label("PRIORITY QUEUE").classes("text-sm font-bold")
                ui.label("Select an incident").classes("text-xs").style(
                    f"color:{COLORS['muted']}"
                )
            self.incident_queue = ui.column().classes("w-full gap-2 mt-3")

    def _build_sources(self) -> None:
        with ui.card().classes("soc-card w-full"):
            ui.label("LOG SOURCE HEALTH").classes("text-sm font-bold")
            self.source_table = ui.table(
                columns=[
                    {"name": "source", "label": "SOURCE", "field": "source", "align": "left"},
                    {"name": "host", "label": "HOST", "field": "host", "align": "left"},
                    {"name": "health", "label": "HEALTH", "field": "health", "align": "left"},
                ],
                rows=[],
                row_key="source",
            ).classes("soc-source-table w-full mt-2").props("flat bordered dense virtual-scroll")
            self.source_table.add_slot(
                "body-cell-health",
                """
                <q-td :props="props">
                  <q-badge
                    :style="props.value === 'HEALTHY'
                      ? 'background:#e8f5ed;color:#23774d'
                      : props.value.startsWith('SILENT')
                        ? 'background:#fdecef;color:#b9364d'
                        : 'background:#fff3df;color:#a85d00'"
                    style="border-radius:9999px;font-weight:600;padding:4px 8px"
                  >{{ props.value }}</q-badge>
                </q-td>
                """,
            )

    def _build_member_one(self) -> None:
        with ui.card().classes("soc-card w-full"):
            with ui.row().classes("w-full items-center justify-between"):
                ui.label("MEMBER 1 · THREAT INTELLIGENCE").classes("text-sm font-bold")
                self.intel_count = ui.badge("0 findings").style(
                    f"background:#e6f5f0;color:{COLORS['teal']}"
                )
            ui.label(
                "External vulnerability and credential exposure context; not a confirmed incident."
            ).classes("text-xs mt-1").style(f"color:{COLORS['muted']}")
            self.intel_container = ui.column().classes("w-full gap-2 mt-3")

    def _build_selected_incident(self) -> None:
        with ui.card().classes("soc-card w-full"):
            with ui.row().classes("w-full items-start justify-between gap-3"):
                with ui.column().classes("grow gap-1"):
                    ui.label("SELECTED INCIDENT").classes("text-xs font-bold").style(
                        f"color:{COLORS['muted']}"
                    )
                    self.incident_title = ui.label("Select an incident").classes(
                        "text-xl font-bold"
                    )
                    self.incident_meta = ui.label("Waiting for SOC results").classes(
                        "text-xs"
                    ).style(f"color:{COLORS['muted']}")
                self.priority_badge = ui.badge("—").style(
                    f"background:#eaf1fc;color:{COLORS['blue']}"
                )
            ui.separator().classes("my-3")
            ui.label("CORRELATED ATTACK PATH").classes("text-xs font-bold").style(
                f"color:{COLORS['muted']}"
            )
            self.attack_path = ui.row().classes("w-full items-center flex-wrap gap-2 mt-2")

    def _build_explanation(self) -> None:
        with ui.card().classes("soc-card w-full"):
            with ui.row().classes("w-full items-center justify-between gap-2 flex-wrap"):
                ui.label("INCIDENT EXPLANATION").classes("text-sm font-bold")
                self.ai_assessment = ui.badge("ADVISORY").style(
                    f"background:#eaf1fc;color:{COLORS['blue']}"
                )
            with ui.row().classes("w-full items-center justify-between gap-2 mt-2"):
                self.ai_status = ui.label(
                    "Qwen3 explains evidence; deterministic rules decide detection."
                ).classes("text-xs").style(f"color:{COLORS['muted']}")
                self.regenerate_button = ui.button(
                    "Regenerate explanation",
                    icon="auto_awesome",
                    on_click=self.regenerate_explanation,
                ).props("flat dense")
            self.explanation_container = ui.column().classes("w-full gap-2 mt-3")

    def _build_timeline(self) -> None:
        with ui.card().classes("soc-card w-full"):
            with ui.row().classes("w-full items-center justify-between gap-3 flex-wrap"):
                ui.label("INCIDENT TIMELINE").classes("text-sm font-bold")
                self.source_logs_button = ui.button(
                    "View source logs", icon="article", on_click=self.open_source_logs
                ).props("flat dense")
            self.timeline_table = ui.table(
                columns=[
                    {"name": "time", "label": "TIME (UTC)", "field": "time", "align": "left"},
                    {"name": "stage", "label": "STAGE", "field": "stage", "align": "left"},
                    {"name": "rule", "label": "RULE", "field": "rule", "align": "left"},
                    {
                        "name": "summary",
                        "label": "DETECTION SUMMARY",
                        "field": "summary",
                        "align": "left",
                    },
                ],
                rows=[],
                row_key="rule",
                pagination={"rowsPerPage": 8},
            ).classes("w-full mt-2").props("flat bordered dense wrap-cells")

    def _build_dialogs(self) -> None:
        with ui.dialog() as self.alert_dialog:
            with ui.card().classes("w-full").style("width:min(1100px,95vw);max-width:95vw"):
                with ui.row().classes("w-full items-center justify-between"):
                    ui.label("DETECTION ALERT HISTORY").classes("text-lg font-bold")
                    ui.button(icon="close", on_click=self.alert_dialog.close).props("flat round")
                ui.label(
                    "Deterministic detections from the current monitoring session."
                ).classes("text-sm").style(f"color:{COLORS['muted']}")
                self.alert_table = ui.table(
                    columns=[
                        {"name": "time", "label": "TIME (UTC)", "field": "time", "align": "left"},
                        {"name": "priority", "label": "LEVEL", "field": "priority", "align": "left"},
                        {"name": "rule", "label": "DETECTION", "field": "rule", "align": "left"},
                        {"name": "incident", "label": "INCIDENT", "field": "incident", "align": "left"},
                        {"name": "details", "label": "SUMMARY", "field": "details", "align": "left"},
                    ],
                    rows=[],
                    row_key="id",
                    pagination={"rowsPerPage": 12},
                ).classes("w-full mt-3").props("flat bordered dense wrap-cells")
        with ui.dialog() as self.source_dialog:
            with ui.card().classes("w-full").style("width:min(1000px,95vw);max-width:95vw"):
                with ui.row().classes("w-full items-center justify-between"):
                    ui.label("RAW SOURCE EVIDENCE").classes("text-lg font-bold")
                    ui.button(icon="close", on_click=self.source_dialog.close).props("flat round")
                self.source_log_container = ui.column().classes("w-full max-h-[70vh] overflow-auto")

    async def refresh(self) -> None:
        if self.loading:
            return
        self.loading = True
        self.refresh_button.disable()
        self.data_badge.set_text("MONITORING · LOADING")
        try:
            snapshot = await asyncio.to_thread(self.provider.load)
        except Exception as exc:
            log.exception("Dashboard data refresh failed")
            self.data_badge.set_text("DATA · ERROR")
            self.status_line.set_text(f"Unable to load SOC data: {exc}")
            self.status_line.style(f"color:{COLORS['red']}")
        else:
            first_snapshot = self.snapshot is None
            self.snapshot = snapshot
            self.incidents = sorted(
                snapshot.incidents,
                key=lambda item: (-int(item.get("score", 0)), str(item.get("id", ""))),
            )
            new_alerts = self._record_new_alerts(snapshot)
            self._render_snapshot(snapshot)
            if new_alerts and not first_snapshot:
                ui.notify(
                    f"{len(new_alerts)} new detection alert(s)",
                    type="warning",
                    position="top",
                )
        finally:
            self.loading = False
            self.refresh_button.enable()

    def _record_new_alerts(self, snapshot: DashboardSnapshot) -> list[Record]:
        alert_incidents = {
            str(alert.get("id", "")): str(incident.get("title", incident.get("id", "")))
            for incident in snapshot.incidents
            for alert in incident.get("alerts", [])
        }
        cycle = int(snapshot.evaluation.get("cycle", 0))
        created: list[Record] = []
        for alert in snapshot.alerts:
            evidence = alert.get("evidence") or []
            markers = tuple(sorted({
                marker
                for item in evidence
                for marker in re.findall(r"CSV-ROW-\d+", str(item.get("raw", "")))
            }))
            if not markers:
                markers = tuple(sorted(str(item.get("id", "")) for item in evidence))
            fingerprint = (
                cycle,
                str(alert.get("rule", "")),
                markers,
                str(alert.get("text", "")),
            )
            if fingerprint in self.alert_fingerprints:
                continue
            self.alert_fingerprints.add(fingerprint)
            record = {
                "id": f"alert-{len(self.alert_history)}",
                "time": _when(alert.get("time")),
                "priority": _priority(alert.get("severity", 0)),
                "rule": _text(alert.get("rule")),
                "incident": alert_incidents.get(str(alert.get("id", "")), "Individual alert"),
                "details": plain_alert_explanation(alert),
            }
            self.alert_history.append(record)
            created.append(record)
        self.alerts_button.set_text(f"Alerts {len(self.alert_history)}")
        self.alert_table.rows = list(reversed(self.alert_history))
        self.alert_table.update()
        return created

    def _render_snapshot(self, snapshot: DashboardSnapshot) -> None:
        evaluation = snapshot.evaluation
        if evaluation:
            self.data_badge.set_text(
                f"SIMULATION · {evaluation.get('rows_seen', 0)} events · cycle {evaluation.get('cycle', 1)}"
            )
        else:
            self.data_badge.set_text(f"MONITORING · {_when(snapshot.generated_at, '%H:%M:%S UTC')}")
        self.status_line.set_text(
            f"Updated {_when(snapshot.generated_at)} · {len(snapshot.singles)} single alerts · "
            f"{len(snapshot.maintenance)} approved maintenance records"
        )
        self.status_line.style(f"color:{COLORS['muted']}")
        p1_count = sum(incident.get("priority") == "P1" for incident in self.incidents)
        healthy = sum(bool(source.get("ok")) for source in snapshot.sources)
        self.metric_values["incidents"].set_text(str(len(self.incidents)))
        self.metric_values["p1"].set_text(str(p1_count))
        self.metric_values["alerts"].set_text(str(len(snapshot.alerts)))
        self.metric_values["sources"].set_text(f"{healthy}/{len(snapshot.sources)}")
        self.source_table.rows = [
            {
                "source": _text(source.get("source")),
                "host": _text(source.get("host")),
                "health": "HEALTHY" if source.get("ok") else self._source_warning(source),
            }
            for source in snapshot.sources
        ]
        self.source_table.update()
        self._render_priority_queue()
        self._render_member_one(snapshot)
        if self.incidents:
            if self.selected_incident_id not in {str(item.get("id", "")) for item in self.incidents}:
                self.selected_incident_id = str(self.incidents[0].get("id", ""))
                self._render_priority_queue()
            self._render_selected_incident()
        else:
            self.selected_incident_id = None
            self.incident_title.set_text("No correlated incidents")
            self.incident_meta.set_text("No incident met the deterministic correlation criteria.")
            self.priority_badge.set_text("CLEAR")
            self.priority_badge.style(
                f"background-color:#e8f5ed !important;color:{COLORS['green']} !important"
            )
            self.attack_path.clear()
            self.explanation_container.clear()
            with self.explanation_container:
                ui.label("There is no incident for Qwen3 to explain.").classes("text-sm")
            self.ai_assessment.set_text("NO INCIDENT")
            self.ai_status.set_text("The AI does not classify an empty incident list.")
            self.timeline_table.rows = []
            self.timeline_table.update()
            self.source_logs_button.disable()

    def _render_priority_queue(self) -> None:
        self.incident_queue.clear()
        with self.incident_queue:
            if not self.incidents:
                ui.label("No correlated incidents. The deterministic SOC rules found nothing to escalate.").classes(
                    "text-sm"
                ).style(f"color:{COLORS['muted']}")
                return
            for incident in self.incidents:
                priority = str(incident.get("priority", "P3"))
                _, foreground = _priority_colors(priority)
                incident_id = str(incident.get("id", "incident"))
                selected = incident_id == self.selected_incident_id
                title = _text(incident.get("title"), incident_id)
                button = ui.button(
                    f"{priority}  ·  {title}",
                    on_click=lambda event, key=incident_id: (
                        self.select_incident(key) if event.sender else None
                    ),
                ).props("flat").classes("w-full justify-start")
                button.style(
                    f"background-color:{'#eef3fa' if selected else '#ffffff'} !important;"
                    f"color:{foreground} !important;border-left:4px solid {foreground};"
                    "white-space:normal;text-align:left"
                )

    def _render_member_one(self, snapshot: DashboardSnapshot) -> None:
        findings = snapshot.threat_findings
        hunts = snapshot.hunt_requests
        self.intel_count.set_text(f"{len(findings)} findings · {len(hunts)} hunts")
        self.intel_container.clear()
        with self.intel_container:
            if not findings:
                ui.label("No cached threat-intelligence matches for the current asset inventory.").classes(
                    "text-sm"
                ).style(f"color:{COLORS['muted']}")
            for finding in findings[:8]:
                # the OSINT agent writes finding_type (older output: type)
                kind = str(finding.get("finding_type") or finding.get("type") or "threat finding")
                is_vulnerability = kind == "vulnerability_exposure" or (bool(finding.get("cve")) and not finding.get("account"))
                title = (
                    str(finding.get("cve", "Vulnerability exposure"))
                    if is_vulnerability
                    else f"Credential exposure · {_text(finding.get('account'), 'account unknown')}"
                )
                with ui.card().classes("w-full p-3").style(
                    "border:1px solid #e6ebf1;border-radius:12px;box-shadow:none"
                ):
                    with ui.row().classes("w-full items-center justify-between gap-2"):
                        ui.label(title).classes("font-bold text-sm")
                        if is_vulnerability and finding.get("cisa_kev"):
                            ui.badge("CISA KEV").style(
                                f"background-color:#fdecef !important;color:{COLORS['red']} !important"
                            )
                        elif not is_vulnerability:
                            ui.badge(
                                f"Confidence {_number(finding.get('confidence')):.0%}"
                            ).style(
                                f"background-color:#eaf1fc !important;color:{COLORS['blue']} !important"
                            )
                    ui.label(_text(finding.get("summary"))).classes("text-sm")
                    metadata = [
                        "Assets: " + ", ".join(str(item) for item in finding.get("affected_assets", [])),
                    ]
                    if is_vulnerability:
                        metadata.append(f"EPSS {_number(finding.get('epss_score')):.2f}")
                        if finding.get("osint_corroboration"):
                            metadata.append(
                                "OSINT corroboration: "
                                + ", ".join(str(item) for item in finding["osint_corroboration"])
                            )
                    elif finding.get("source"):
                        metadata.append(f"Source: {finding['source']}")
                    ui.label(" · ".join(metadata)).classes("text-xs").style(
                        f"color:{COLORS['muted']}"
                    )
            if len(findings) > 8:
                ui.label(f"{len(findings) - 8} more findings are available in the agent output.").classes(
                    "text-xs"
                ).style(f"color:{COLORS['muted']}")
            with ui.expansion(f"Targeted hunts for Member 2 ({len(hunts)})").classes("w-full"):
                if hunts:
                    for hunt in hunts[:12]:
                        ui.label(
                            f"{_text(hunt.get('hunt_id'))} · "
                            f"{', '.join(str(item) for item in hunt.get('target_assets', []))}"
                        ).classes("text-sm font-bold")
                        ui.label(_text(hunt.get("hunt_query"))).classes("text-sm")
                else:
                    ui.label("No targeted hunts were generated.").classes("text-sm")

    def _render_selected_incident(self) -> None:
        incident = next(
            (
                item for item in self.incidents
                if str(item.get("id", "")) == self.selected_incident_id
            ),
            None,
        )
        if incident is None:
            return
        incident_id = str(incident.get("id", "incident"))
        priority = str(incident.get("priority", "P3"))
        title = _text(incident.get("title"), incident_id)
        self.incident_title.set_text(title)
        confidence = incident.get("confidence")
        confidence_text = f"{confidence:.0%}" if isinstance(confidence, (int, float)) else _text(confidence)
        self.incident_meta.set_text(
            f"{incident_id} · {_when(incident.get('start'))} – "
            f"{_when(incident.get('end'), '%H:%M UTC')} · "
            f"{len(incident.get('alerts', []))} correlated alerts · confidence {confidence_text}"
        )
        background, foreground = _priority_colors(priority)
        self.priority_badge.set_text(f"{priority} · SCORE {incident.get('score', '—')}")
        self.priority_badge.style(
            f"background-color:{background} !important;color:{foreground} !important"
        )
        self.attack_path.clear()
        with self.attack_path:
            stages = incident.get("stages", [])
            for index, stage in enumerate(stages):
                ui.badge(str(stage).upper()).style(
                    f"background-color:#eaf1fc !important;color:{COLORS['blue']} !important"
                )
                if index < len(stages) - 1:
                    ui.icon("chevron_right").style(f"color:{COLORS['muted']}")
            techniques = incident.get("attack", [])
            if techniques:
                technique_text = " · ".join(
                    str(item.get("id", "")) for item in techniques[:6]
                )
                ui.label(f"ATT&CK  {technique_text}").classes("text-xs").style(
                    f"color:{COLORS['muted']}"
                )
        rows = []
        for alert in sorted(
            incident.get("alerts", []),
            key=lambda item: str(item.get("time", "")),
        ):
            summary = _text(alert.get("text"), _text(alert.get("rule")))
            if len(summary) > 180:
                summary = summary[:177] + "..."
            rows.append(
                {
                    "time": _when(alert.get("time"), "%H:%M:%S"),
                    "stage": _text(alert.get("stage"), "alert"),
                    "rule": _text(alert.get("rule")),
                    "summary": f"{summary} · {len(alert.get('evidence') or [])} evidence line(s)",
                }
            )
        self.timeline_table.rows = rows
        self.timeline_table.update()
        self.source_logs_button.enable()
        self._render_explanation(incident)

    def _render_explanation(self, incident: Record) -> None:
        incident_id = str(incident.get("id", "incident"))
        self.explanation_container.clear()
        result_refs = self.qwen_results.get(incident_id)
        error = self.qwen_errors.get(incident_id)
        if result_refs:
            result, evidence_refs = result_refs
            assessment = str(result.get("triage_assessment", "inconclusive"))
            labels = {
                "likely_suspicious": ("LIKELY SUSPICIOUS · ADVISORY", "#fdecef", COLORS["red"]),
                "possibly_authorized_or_benign": ("POSSIBLY BENIGN · ADVISORY", "#fff3df", COLORS["amber"]),
                "inconclusive": ("INCONCLUSIVE · ADVISORY", "#eaf1fc", COLORS["blue"]),
            }
            label, background, foreground = labels.get(
                assessment, ("INCONCLUSIVE · ADVISORY", "#eaf1fc", COLORS["blue"])
            )
            self.ai_assessment.set_text(label)
            self.ai_assessment.style(
                f"background-color:{background} !important;color:{foreground} !important"
            )
            self.ai_status.set_text("Qwen3 summary ready · the operator decides")
            with self.explanation_container:
                ui.label(
                    _text(result.get("commander_summary_en"), _text(result.get("summary")))
                ).classes("soc-explanation-text text-sm whitespace-pre-wrap")
                self._explanation_section("UNCERTAINTY", _text(result.get("uncertainty")))
                evidence = result.get("evidence", [])
                if evidence:
                    self._explanation_section(
                        "SUPPORTING EVIDENCE",
                        " · ".join(f"{key}: {evidence_refs.get(key, key)}" for key in evidence),
                    )
                recommendations = result.get("recommendations", [])
                if recommendations:
                    ui.label("OPERATOR CHECKS").classes("text-xs font-bold").style(
                        f"color:{COLORS['navy']}"
                    )
                    for step in recommendations:
                        ui.label(f"• {step}").classes("text-sm")
                ui.label(
                    "Advisory only. Detection and priority are determined by SOC rules; no response action is automatic."
                ).classes("text-xs").style(f"color:{COLORS['muted']}")
            return

        self.ai_assessment.set_text("ADVISORY")
        self.ai_assessment.style(f"background:#eaf1fc;color:{COLORS['blue']}")
        if error:
            self.ai_status.set_text(error)
        elif self._qwen_config_is_verified():
            self.ai_status.set_text("Qwen3 is generating locally; the dashboard remains available.")
        else:
            self.ai_status.set_text(self.qwen_message)
        with self.explanation_container:
            if self._qwen_config_is_verified() and not error:
                ui.label("Generating the incident explanation…").classes("text-sm").style(
                    f"color:{COLORS['muted']}"
                )
            else:
                ui.label(instant_overview(incident)).classes(
                    "soc-explanation-text text-sm whitespace-pre-wrap"
                )
            if error:
                ui.label(error).classes("text-xs").style(f"color:{COLORS['amber']}")
        # Start automatically only once per incident. After an error, wait for "Regenerate explanation": starting
        # again here cleared the error and retried forever, so the operator only ever saw "Generating…".
        if self._qwen_config_is_verified() and not error and incident_id not in self.qwen_in_flight:
            asyncio.create_task(self._generate_explanation(incident))

    def _explanation_section(self, title: str, text: str) -> None:
        ui.label(title).classes("text-xs font-bold").style(f"color:{COLORS['navy']}")
        ui.label(text).classes("soc-explanation-text text-sm whitespace-pre-wrap")

    def _qwen_config_is_verified(self) -> bool:
        current = (
            str(self.url_input.value or "").strip(),
            str(self.model_input.value or "").strip(),
        )
        return self.qwen_ready and current == self.checked_qwen_config

    def _on_qwen_config_change(self, event: Any) -> None:
        if event is None:
            return
        if self.checked_qwen_config is None:
            return
        current = (
            str(self.url_input.value or "").strip(),
            str(self.model_input.value or "").strip(),
        )
        if current == self.checked_qwen_config:
            return
        self.qwen_ready = False
        self.qwen_message = "Settings changed. Test Qwen to verify this endpoint and model."
        self.qwen_status.set_text(self.qwen_message)
        self.ai_status.set_text(self.qwen_message)
        self.model_badge.set_text("QWEN3 · TEST NEEDED")
        self.model_badge.style("background:#203f5b;color:#dce8f2")
        if self.selected_incident_id:
            self._render_selected_incident()

    async def test_qwen(self) -> None:
        if self.qwen_checking:
            return
        base_url = str(self.url_input.value or "").strip()
        model = str(self.model_input.value or "").strip()
        if not base_url or not model:
            self.qwen_ready = False
            self.checked_qwen_config = (base_url, model)
            self.qwen_message = "Enter both an Ollama URL and a model name."
            self.qwen_status.set_text(self.qwen_message)
            self.model_badge.set_text("QWEN3 · CONFIG NEEDED")
            self.model_badge.style("background:#8a5a18;color:white")
            return
        self.qwen_checking = True
        self.qwen_ready = False
        self.test_qwen_button.disable()
        self.url_input.disable()
        self.model_input.disable()
        self.model_badge.set_text("QWEN3 · CHECKING")
        self.model_badge.style("background:#203f5b;color:#dce8f2")
        self.qwen_message = f"Checking {model} at {base_url}…"
        self.qwen_status.set_text(self.qwen_message)
        try:
            await asyncio.to_thread(check_ollama_model, base_url, model)
        except (OllamaError, ValueError) as exc:
            log.exception("Qwen endpoint check failed")
            self.qwen_message = str(exc)
            self.model_badge.set_text("QWEN3 · UNAVAILABLE")
            self.model_badge.style("background:#8a5a18;color:white")
        else:
            self.qwen_ready = True
            self.checked_qwen_config = (base_url, model)
            self.qwen_message = f"{model} is installed and reachable at {base_url}."
            self.model_badge.set_text("QWEN3 · READY")
            self.model_badge.style(f"background:{COLORS['green']};color:white")
        finally:
            self.qwen_checking = False
            self.test_qwen_button.enable()
            self.url_input.enable()
            self.model_input.enable()
            self.qwen_status.set_text(self.qwen_message)
            if self.selected_incident_id:
                self._render_selected_incident()

    async def _generate_explanation(self, incident: Record) -> None:
        incident_id = str(incident.get("id", "incident"))
        if incident_id in self.qwen_in_flight or not self._qwen_config_is_verified():
            return
        self.qwen_in_flight.add(incident_id)
        snapshot = self.snapshot
        if snapshot is None:
            self.qwen_in_flight.discard(incident_id)
            return
        base_url = str(self.url_input.value or "").strip()
        model = str(self.model_input.value or "").strip()
        self.qwen_errors.pop(incident_id, None)
        try:
            result, evidence_refs = await asyncio.to_thread(
                self._analyze_incident,
                incident,
                snapshot,
                base_url,
                model,
            )
        except Exception as exc:  # any failure must reach the screen, never leave "Generating…" behind
            log.exception("Qwen incident explanation failed")
            reason = str(exc).split(": ", 1)[-1] if isinstance(exc, AnalysisError) else str(exc)
            self.qwen_errors[incident_id] = f"Qwen could not explain this incident ({reason[:200]}). " \
                                            "The deterministic overview is shown; use Regenerate explanation to retry."
        else:
            self.qwen_results[incident_id] = (result, evidence_refs)
        finally:
            self.qwen_in_flight.discard(incident_id)
            if not self._client.is_deleted and self.selected_incident_id == incident_id:
                self._render_selected_incident()

    @staticmethod
    def _analyze_incident(
        incident: Record,
        snapshot: DashboardSnapshot,
        base_url: str,
        model: str,
    ) -> tuple[Record, dict[str, str]]:
        payload, evidence_refs = build_dashboard_incident(
            incident,
            snapshot.threat_findings,
            snapshot.sources,
            snapshot.advisories,
        )
        result = analyze_incident(
            payload,
            base_url=base_url,
            model=model,
            timeout=240,
            retries=1,  # one retry with the validation error fed back to the model
        )
        return result, evidence_refs

    async def regenerate_explanation(self) -> None:
        if not self.selected_incident_id:
            return
        if not self._qwen_config_is_verified():
            await self.test_qwen()
            if not self._qwen_config_is_verified():
                return
        incident = next(
            (
                item for item in self.incidents
                if str(item.get("id", "")) == self.selected_incident_id
            ),
            None,
        )
        if incident is None:
            return
        self.qwen_results.pop(self.selected_incident_id, None)
        self.qwen_errors.pop(self.selected_incident_id, None)
        await self._generate_explanation(incident)

    def select_incident(self, incident_id: str) -> None:
        self.selected_incident_id = incident_id
        self._render_priority_queue()
        self._render_selected_incident()

    def _source_warning(self, source: Record) -> str:
        gaps = source.get("silent") or []
        if not gaps:
            return "CHECK"
        minutes = [
            gap.get("minutes")
            for gap in gaps
            if isinstance(gap, dict) and gap.get("minutes") is not None
        ]
        return f"SILENT {_format_elapsed_minutes(max(minutes))}" if minutes else "SILENT"

    def open_alert_history(self) -> None:
        self.alert_dialog.open()

    def open_source_logs(self) -> None:
        incident = next(
            (
                item for item in self.incidents
                if str(item.get("id", "")) == self.selected_incident_id
            ),
            None,
        )
        if incident is None:
            return
        self.source_log_container.clear()
        with self.source_log_container:
            evidence = [
                (alert, item)
                for alert in incident.get("alerts", [])
                for item in alert.get("evidence", [])
            ]
            if not evidence:
                ui.label("No raw evidence was attached to this incident.")
            for alert, item in evidence:
                with ui.card().classes("w-full p-3").style(
                    "border:1px solid #e6ebf1;border-radius:12px;box-shadow:none"
                ):
                    ui.label(
                        f"{_when(alert.get('time'))} · {_text(item.get('source'))}:"
                        f"{_text(item.get('line'))}"
                    ).classes("text-xs font-bold").style(f"color:{COLORS['muted']}")
                    ui.label(_text(item.get("raw"))).classes(
                        "text-sm whitespace-pre-wrap font-mono"
                    )
        self.source_dialog.open()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the local Cyber Sentinels NiceGUI dashboard.")
    parser.add_argument(
        "--logs",
        type=Path,
        default=DEFAULT_LOGS,
        help="Folder containing SOC logs and sources.yaml/assets.yaml/maintenance.yaml.",
    )
    parser.add_argument("--csv", type=Path, help="CSV attack dataset to replay as live telemetry.")
    parser.add_argument("--csv-batch", type=int, default=30, help="CSV rows processed per refresh.")
    parser.add_argument("--csv-interval", type=int, default=2, help="Seconds between CSV refreshes.")
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard bind address (default: localhost).")
    parser.add_argument("--port", type=int, default=8080, help="Dashboard port.")
    args = parser.parse_args(argv)
    if args.csv:
        csv_path = args.csv.resolve()
        if not csv_path.is_file():
            parser.error(f"CSV file not found: {csv_path}")
        provider: DashboardProvider = CsvSimulationProvider(
            csv_path,
            batch_size=max(1, args.csv_batch),
            interval_seconds=max(1, args.csv_interval),
        )
        refresh_seconds = max(1, args.csv_interval)
    else:
        log_path = args.logs.resolve()
        _ensure_default_fleet_logs(log_path)
        if not log_path.is_dir():
            parser.error(f"SOC log directory not found: {log_path}")
        provider = IntegratedAgentProvider(log_path)
        refresh_seconds = None

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        log.warning(
            "The dashboard has no authentication. Bind only on a trusted private network and do not port-forward it."
        )

    @ui.page("/")
    def dashboard() -> None:
        DashboardPage(provider, refresh_seconds)

    ui.run(
        title="Cyber Sentinels | Incident Operations",
        host=args.host,
        port=args.port,
        reload=False,
        show=True,
    )


if __name__ == "__main__":
    main()
