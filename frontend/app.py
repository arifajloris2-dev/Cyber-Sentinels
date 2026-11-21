"""NiceGUI SOC console for the local Cyber Sentinels engine (runs offline, advice only).

Views: Overview · Incidents · Search · Entities · Agents · Sources & intel · Alerts.
Closing an incident or an alert hides it for this browser session only; the synthetic data brings it back on reload.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
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
from backend.soc import knowledge as kb_store
from frontend import search as event_search
from frontend.data_provider import CsvSimulationProvider, DashboardProvider, IntegratedAgentProvider
from frontend.explanations import instant_overview, plain_alert_explanation
from frontend.models import DashboardSnapshot, Record

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOGS = ROOT / "backend" / "soc" / "fleet" / "logs"
FLEET_GENERATOR = ROOT / "backend" / "soc" / "fleet" / "make_fleet.py"
COLORS = {
    "background": "#eef2f7",
    "surface": "#ffffff",
    "border": "#dce4ed",
    "ink": "#142235",
    "muted": "#66778b",
    "navy": "#0f1f30",
    "navy_light": "#1b3249",
    "teal": "#119879",
    "blue": "#3473d1",
    "amber": "#c27400",
    "red": "#c2364f",
    "green": "#23774d",
    "violet": "#6a4fc9",
}
PRIORITY_COLOR = {"P1": COLORS["red"], "P2": COLORS["amber"], "P3": COLORS["blue"]}
STAGE_ICON = {"entry": "login", "execution": "terminal", "credential theft": "key", "lateral movement": "swap_horiz",
              "privilege escalation": "admin_panel_settings", "command and control": "settings_input_antenna",
              "impact": "local_fire_department"}
TACTICS = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
           "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"]
AGENT_ICON = {"windows_host": "desktop_windows", "endpoint": "memory", "linux_host": "dns", "host_firewall": "shield",
              "perimeter": "security", "network_sensor": "lan", "mail": "mail"}
CLOSE_REASONS = ["Resolved", "False positive", "Benign / authorized", "Duplicate", "Accepted risk", "Other"]
EXAMPLE_QUERIES = [
    ("Failed logons", "action=logon outcome=failure"),
    ("Admin shares", "action=share-access share=*$"),
    ("Kerberos RC4", "action=kerberos-service-ticket ticket_enc=0x17"),
    ("Root shells", "action=root-shell"),
    ("Zone violations", "zone_allowed=False action=allow"),
    ("Big uploads", "bytes_out>=10000000"),
    ("PsExec", "PSEXESVC"),
    ("LSASS access", "action=process-access target=*lsass*"),
]
KB_EXAMPLE = """# Example: a new vulnerability, an indicator and a leaked account (plain text only)
CVE: CVE-2026-31337
Product: GateControlService
Versions: 2.4.0
KEV: yes
EPSS: 0.88
Techniques: T1543, T1562
Summary: Unauthenticated configuration write in the gate management daemon.
Reference: https://example.invalid/advisory/31337

IP: 203.0.113.99
Note: data-theft server reported by an allied CERT

Account: svc_sql
Note: password offered for sale on a forum
"""
KB_HELP = [
    "CVE blocks become vulnerability exposures: matched to the asset inventory (product + version) or the hosts you name, "
    "attached to incidents that show their ATT&CK techniques, and given to the local AI whenever it explains an incident.",
    "IP, Domain and Hash blocks become indicators: rule IOC-001 flags every log line that contains them.",
    "Account blocks mark leaked accounts: attached to incidents that use them.",
    "Keys: CVE, Product, Versions, KEV, EPSS, CVSS, Techniques, Hosts, Summary, Reference, IP, Domain, Hash, Account, "
    "Note, Source. Separate blocks with an empty line; # starts a comment. Anything else is rejected.",
]
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


def _dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            d = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _when(value: Any, fmt: str = "%Y-%m-%d %H:%M UTC") -> str:
    d = _dt(value)
    if d is None:
        return _text(value)
    return d.astimezone(timezone.utc).strftime(fmt)


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


def _short(text: Any, n: int = 140) -> str:
    s = _text(text, "")
    return s if len(s) <= n else s[: n - 1] + "…"


CSS = """
<style>
  body { background: #eef2f7; color: #142235; }
  .q-drawer { background: #0f1f30 !important; }
  .soc-nav .q-tab { justify-content: flex-start; color: #b9c8d8; min-height: 44px; border-radius: 10px; margin: 2px 8px; }
  .soc-nav .q-tab--active { background: #1b3249; color: #ffffff; }
  .soc-nav .q-tab__indicator { display: none; }
  .soc-card { background: #fff; border: 1px solid #dce4ed; border-radius: 14px; box-shadow: 0 1px 3px #14223510; }
  .soc-kpi { flex: 1 1 150px; min-width: 140px; padding: 14px 16px; }
  .soc-kpi .v { font-size: 28px; font-weight: 700; line-height: 1.1; }
  .soc-kpi .k { font-size: 11px; font-weight: 700; color: #66778b; letter-spacing: .04em; }
  .soc-title { font-size: 12px; font-weight: 700; letter-spacing: .05em; color: #4d5f74; }
  .soc-grid-2 { display: grid; grid-template-columns: minmax(0, 4fr) minmax(0, 8fr); gap: 16px; align-items: start; }
  .soc-grid-2 > *, .soc-grid-3 > * { min-width: 0; }
  .q-tab-panel, .q-tab-panels { overflow: visible; }
  .soc-grid-3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
  .soc-grid-agents { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 14px; }
  .soc-inc { border: 1px solid #e3e9f0; border-left: 5px solid var(--pc); border-radius: 12px; padding: 10px 12px;
             background: #fff; cursor: pointer; }
  .soc-inc:hover { background: #f6f9fd; }
  .soc-inc.sel { background: #eef4fd; border-color: #b8cdee; border-left-color: var(--pc); }
  .soc-inc.closed { opacity: .55; }
  .soc-dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
  .soc-host { border: 1px solid #c9d6e5; border-radius: 12px; padding: 8px 12px; background: #f7faff; min-width: 120px; }
  .soc-mono { font-family: ui-monospace, Consolas, monospace; font-size: 12px; }
  .soc-tactic { background: #f6f8fb; border: 1px solid #e3e9f0; border-radius: 10px; padding: 8px; min-width: 150px; }
  .soc-tech { border-radius: 8px; padding: 4px 6px; font-size: 11px; margin-top: 4px; }
  .soc-field-val { cursor: pointer; border-radius: 6px; padding: 1px 4px; }
  .soc-field-val:hover { background: #e8f0fb; }
  .soc-table .q-table__middle { max-height: 520px; }
  .soc-explanation-text { overflow-wrap: anywhere; }
  @media (max-width: 1200px) { .soc-grid-2, .soc-grid-3 { grid-template-columns: minmax(0, 1fr); } }
</style>
"""


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
        # closed for this session only (not saved: the synthetic data shows them again after a reload)
        self.closed_incidents: dict[str, dict] = {}
        self.closed_alerts: dict[str, dict] = {}
        self.show_closed = False
        self.priority_filter = "All"
        self.incident_query = ""
        self.search_results: list[Record] = []
        self.ollama_url = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
        self.ollama_model = os.environ.get("OLLAMA_MODEL", "qwen3:4b")
        self._build()
        ui.timer(0.1, self.refresh, once=True)
        if self.refresh_seconds is not None:
            ui.timer(self.refresh_seconds, self.refresh)
        ui.timer(0.3, self.test_qwen, once=True)

    # =================================================================== layout
    def _build(self) -> None:
        ui.page_title("Cyber Sentinels | SOC console")
        ui.add_head_html(CSS)
        self._build_header()
        with ui.left_drawer(fixed=True, bordered=False).props("width=230 breakpoint=900") as self.drawer:
            with ui.row().classes("items-center gap-2 px-4 pt-4 pb-2"):
                ui.icon("shield").classes("text-3xl").style(f"color:{COLORS['teal']}")
                with ui.column().classes("gap-0"):
                    ui.label("CYBER SENTINELS").classes("text-white font-bold")
                    ui.label("LOCAL SOC CONSOLE").classes("text-xs").style("color:#8aa0b7")
            with ui.tabs().props("vertical no-caps inline-label").classes("soc-nav w-full mt-2") as self.nav:
                self.tab_overview = ui.tab("overview", "Overview", icon="dashboard")
                self.tab_incidents = ui.tab("incidents", "Incidents", icon="crisis_alert")
                self.tab_search = ui.tab("search", "Search", icon="manage_search")
                self.tab_entities = ui.tab("entities", "Entities", icon="hub")
                self.tab_agents = ui.tab("agents", "Agents", icon="smart_toy")
                self.tab_sources = ui.tab("sources", "Sources & intel", icon="sensors")
                self.tab_alerts = ui.tab("alerts", "Alerts", icon="notifications_active")
                self.tab_knowledge = ui.tab("knowledge", "Knowledge import", icon="school")
            ui.label("Advice only: nothing is blocked or changed automatically.").classes(
                "text-xs px-4 pt-6").style("color:#8aa0b7")
        with ui.column().classes("w-full p-4 gap-4").style("max-width:1600px;margin:0 auto"):
            self.status_line = ui.label("Loading SOC data…").classes("text-sm").style(f"color:{COLORS['muted']}")
            with ui.tab_panels(self.nav, value="overview").props("animated=false").classes("w-full bg-transparent") as self.panels:
                with ui.tab_panel("overview").classes("p-0"):
                    self._build_overview()
                with ui.tab_panel("incidents").classes("p-0"):
                    self._build_incidents()
                with ui.tab_panel("search").classes("p-0"):
                    self._build_search()
                with ui.tab_panel("entities").classes("p-0"):
                    self._build_entities()
                with ui.tab_panel("agents").classes("p-0"):
                    self._build_agents()
                with ui.tab_panel("sources").classes("p-0"):
                    self._build_sources()
                with ui.tab_panel("alerts").classes("p-0"):
                    self._build_alerts()
                with ui.tab_panel("knowledge").classes("p-0"):
                    self._build_knowledge()
        self._build_dialogs()

    def _build_header(self) -> None:
        with ui.header(elevated=False).classes("items-center justify-between px-4 py-2").style(
                f"background:{COLORS['navy']};border-bottom:1px solid #22384f"):
            with ui.row().classes("items-center gap-2"):
                ui.button(icon="menu", on_click=lambda: self.drawer.toggle()).props("flat round color=white dense")
                self.view_title = ui.label("Security operations").classes("text-white text-lg font-semibold")
            with ui.row().classes("items-center gap-2"):
                self.data_badge = ui.badge("MONITORING · STARTING").style("background:#1b3249;color:#dce8f2")
                self.model_badge = ui.badge("QWEN3 · CHECKING").style("background:#1b3249;color:#dce8f2")
                self.refresh_button = ui.button("Refresh", icon="refresh", on_click=self.refresh).props(
                    "unelevated dense no-caps").style(f"background:{COLORS['blue']};color:white")
                self.alerts_button = ui.button("Alerts 0", icon="notifications",
                                               on_click=lambda: self.nav.set_value("alerts")).props(
                    "outline dense no-caps").style("color:white")
                ui.button(icon="settings", on_click=lambda: self.settings_dialog.open()).props("flat round color=white dense")

    def _card(self, title: str, extra: str = "") -> Any:
        card = ui.element("div").classes(f"soc-card p-4 w-full {extra}")
        with card:
            ui.label(title).classes("soc-title")
        return card

    # ---------------------------------------------------------------- overview
    def _build_overview(self) -> None:
        self.kpi: dict[str, Any] = {}
        with ui.row().classes("w-full gap-3 flex-wrap"):
            for key, title, color, icon in (("open", "OPEN INCIDENTS", COLORS["blue"], "crisis_alert"),
                                            ("p1", "PRIORITY 1", COLORS["red"], "priority_high"),
                                            ("alerts", "OPEN ALERTS", COLORS["amber"], "notifications_active"),
                                            ("health", "HEALTHY SOURCES", COLORS["green"], "sensors"),
                                            ("agents", "AGENTS REPORTING", COLORS["violet"], "smart_toy"),
                                            ("closed", "CLOSED THIS SESSION", COLORS["muted"], "task_alt")):
                with ui.element("div").classes("soc-card soc-kpi"):
                    with ui.row().classes("items-center justify-between w-full"):
                        ui.label(title).classes("k")
                        ui.icon(icon).style(f"color:{color}")
                    self.kpi[key] = ui.label("–").classes("v").style(f"color:{color}")
        with ui.element("div").classes("soc-grid-2 w-full"):
            with self._card("ALERTS OVER TIME (UTC, by level)"):
                self.chart_alerts = ui.echart(self._empty_chart()).classes("w-full h-64")
            with self._card("OPEN INCIDENTS BY PRIORITY"):
                self.chart_priority = ui.echart(self._empty_chart()).classes("w-full h-64")
        with ui.element("div").classes("soc-grid-2 w-full"):
            with self._card("MOST ALERTED MACHINES"):
                self.chart_hosts = ui.echart(self._empty_chart()).classes("w-full h-72")
            with self._card("TOP INCIDENTS"):
                self.overview_incidents = ui.column().classes("w-full gap-2 mt-2")
        with self._card("MITRE ATT&CK COVERAGE  ·  techniques seen in open incidents"):
            self.attack_matrix = ui.row().classes("w-full gap-2 mt-2 flex-nowrap overflow-x-auto")

    @staticmethod
    def _empty_chart() -> dict:
        return {"series": [], "xAxis": {"show": False}, "yAxis": {"show": False}}

    # ---------------------------------------------------------------- incidents
    def _build_incidents(self) -> None:
        with ui.element("div").classes("soc-grid-2 w-full"):
            with ui.element("div").classes("soc-card p-3 w-full"):
                with ui.row().classes("w-full items-center justify-between"):
                    ui.label("INCIDENT QUEUE").classes("soc-title")
                    self.queue_count = ui.badge("0").style(f"background:#eaf1fc;color:{COLORS['blue']}")
                ui.input(placeholder="Filter by title, host, account…",
                         on_change=lambda e: self._set_incident_query(e.value)).props("dense outlined clearable").classes(
                    "w-full mt-2")
                with ui.row().classes("w-full items-center justify-between mt-2"):
                    ui.toggle(["All", "P1", "P2", "P3"], value="All",
                              on_change=lambda e: self._set_priority_filter(e.value)).props("dense no-caps unelevated")
                    ui.switch("Show closed", on_change=lambda e: self._set_show_closed(e.value)).props("dense")
                self.incident_queue = ui.column().classes("w-full gap-2 mt-3")
            with ui.element("div").classes("soc-card p-4 w-full"):
                with ui.row().classes("w-full items-start justify-between gap-3 no-wrap"):
                    with ui.column().classes("grow gap-1"):
                        self.incident_meta = ui.label("Waiting for SOC results").classes("text-xs").style(
                            f"color:{COLORS['muted']}")
                        self.incident_title = ui.label("Select an incident").classes("text-xl font-bold")
                        self.incident_badges = ui.row().classes("gap-2 items-center")
                    with ui.column().classes("items-end gap-2"):
                        self.priority_badge = ui.badge("—").style(f"background:#eaf1fc;color:{COLORS['blue']}")
                        self.close_button = ui.button("Close incident", icon="task_alt",
                                                      on_click=self._ask_close_incident).props("unelevated dense no-caps")
                self.attack_path = ui.row().classes("w-full items-center flex-wrap gap-1 mt-3")
                with ui.tabs().props("dense no-caps inline-label align=left").classes("mt-3") as dtabs:
                    ui.tab("story", "Story & path", icon="account_tree")
                    ui.tab("timeline", "Timeline", icon="timeline")
                    ui.tab("ai", "AI explanation", icon="auto_awesome")
                    ui.tab("evidence", "Evidence", icon="article")
                    ui.tab("checks", "Checks & intel", icon="fact_check")
                with ui.tab_panels(dtabs, value="story").props("animated=false").classes("w-full"):
                    with ui.tab_panel("story").classes("px-0"):
                        self.story_box = ui.column().classes("w-full gap-3")
                        self.chart_graph = ui.echart(self._empty_chart()).classes("w-full h-72")
                        self.escalation_box = ui.column().classes("w-full gap-1")
                    with ui.tab_panel("timeline").classes("px-0"):
                        self.timeline_table = ui.table(
                            columns=[{"name": "time", "label": "TIME (UTC)", "field": "time", "align": "left"},
                                     {"name": "stage", "label": "STAGE", "field": "stage", "align": "left"},
                                     {"name": "rule", "label": "RULE", "field": "rule", "align": "left"},
                                     {"name": "agent", "label": "SEEN BY", "field": "agent", "align": "left"},
                                     {"name": "summary", "label": "WHAT HAPPENED", "field": "summary", "align": "left"}],
                            rows=[], row_key="key", pagination={"rowsPerPage": 12},
                        ).classes("w-full soc-table").props("flat bordered dense wrap-cells")
                    with ui.tab_panel("ai").classes("px-0"):
                        with ui.row().classes("w-full items-center justify-between gap-2"):
                            self.ai_assessment = ui.badge("ADVISORY").style(f"background:#eaf1fc;color:{COLORS['blue']}")
                            self.regenerate_button = ui.button("Regenerate explanation", icon="auto_awesome",
                                                               on_click=self.regenerate_explanation).props("flat dense no-caps")
                        self.ai_status = ui.label("Qwen3 explains evidence; deterministic rules decide detection.").classes(
                            "text-xs").style(f"color:{COLORS['muted']}")
                        self.explanation_container = ui.column().classes("w-full gap-2 mt-2")
                    with ui.tab_panel("evidence").classes("px-0"):
                        self.evidence_box = ui.column().classes("w-full gap-2")
                    with ui.tab_panel("checks").classes("px-0"):
                        self.checks_box = ui.column().classes("w-full gap-2")

    # ---------------------------------------------------------------- search
    def _build_search(self) -> None:
        with ui.element("div").classes("soc-card p-4 w-full"):
            with ui.row().classes("w-full items-center gap-2 no-wrap"):
                self.search_input = ui.input(placeholder='host=DC-02 action=logon outcome=failure   ·   src_ip=10.24.3.*   ·   "delete shadows"').props(
                    "outlined dense clearable").classes("grow soc-mono")
                self.search_input.on("keydown.enter", lambda: self.run_search())
                self.search_range = ui.select({"all": "All data", "base": "Baseline day", "attack": "After baseline",
                                               "last6": "Last 6 hours"}, value="all").props("outlined dense").classes("w-40")
                ui.button("Search", icon="search", on_click=self.run_search).props("unelevated no-caps").style(
                    f"background:{COLORS['blue']};color:white")
            with ui.row().classes("gap-1 mt-2 flex-wrap items-center"):
                ui.label("Examples:").classes("text-xs").style(f"color:{COLORS['muted']}")
                for label, q in EXAMPLE_QUERIES:
                    ui.chip(label, on_click=lambda _, q=q: self._example(q)).props("dense outline clickable color=primary")
            ui.label("Syntax: field=value (use * as wildcard) · field!=value · field>=N · words or \"phrases\" search the raw line. "
                     "All terms must match.").classes("text-xs mt-1").style(f"color:{COLORS['muted']}")
        with ui.element("div").classes("soc-grid-2 w-full"):
            with ui.element("div").classes("soc-card p-3 w-full"):
                ui.label("INTERESTING FIELDS").classes("soc-title")
                ui.label("Click a value to add it to the search").classes("text-xs").style(f"color:{COLORS['muted']}")
                self.fields_box = ui.column().classes("w-full gap-1 mt-2")
            with ui.column().classes("w-full gap-3"):
                with ui.element("div").classes("soc-card p-3 w-full"):
                    with ui.row().classes("w-full items-center justify-between"):
                        ui.label("EVENTS OVER TIME").classes("soc-title")
                        self.search_count = ui.label("").classes("text-sm font-bold")
                    self.chart_search = ui.echart(self._empty_chart()).classes("w-full h-40")
                with ui.element("div").classes("soc-card p-3 w-full"):
                    self.search_table = ui.table(
                        columns=[{"name": "time", "label": "TIME (UTC)", "field": "time", "align": "left", "sortable": True},
                                 {"name": "agent", "label": "AGENT", "field": "agent", "align": "left", "sortable": True},
                                 {"name": "host", "label": "HOST", "field": "host", "align": "left", "sortable": True},
                                 {"name": "action", "label": "ACTION", "field": "action", "align": "left", "sortable": True},
                                 {"name": "user", "label": "ACCOUNT", "field": "user", "align": "left", "sortable": True},
                                 {"name": "net", "label": "FROM → TO", "field": "net", "align": "left"},
                                 {"name": "raw", "label": "RAW", "field": "raw", "align": "left"}],
                        rows=[], row_key="id", pagination={"rowsPerPage": 25},
                    ).classes("w-full soc-table").props("flat bordered dense wrap-cells")
                    self.search_table.add_slot("body-cell-raw", """
                        <q-td :props="props"><span class="soc-mono">{{ props.value }}</span></q-td>""")

    # ---------------------------------------------------------------- entities
    def _build_entities(self) -> None:
        with ui.element("div").classes("soc-card p-4 w-full"):
            with ui.row().classes("w-full items-center gap-3"):
                ui.label("ENTITY").classes("soc-title")
                self.entity_select = ui.select([], with_input=True, label="Host or account",
                                               on_change=lambda e: self.show_entity(e.value)).props(
                    "outlined dense").classes("w-96")
                ui.label("Pick a machine or an account to see everything about it.").classes("text-xs").style(
                    f"color:{COLORS['muted']}")
        self.entity_box = ui.column().classes("w-full gap-4")

    # ---------------------------------------------------------------- agents
    def _build_agents(self) -> None:
        with self._card("AGENT ACTIVITY  ·  events per hour: normal (baseline) vs now"):
            self.chart_agents = ui.echart(self._empty_chart()).classes("w-full h-64")
        self.agents_box = ui.element("div").classes("soc-grid-agents w-full")

    # ---------------------------------------------------------------- sources & intel
    def _build_sources(self) -> None:
        with ui.element("div").classes("soc-grid-2 w-full"):
            with self._card("LOG SOURCE HEALTH  ·  problems first"):
                self.source_table = ui.table(
                    columns=[{"name": "health", "label": "HEALTH", "field": "health", "align": "left", "sortable": True},
                             {"name": "source", "label": "SOURCE", "field": "source", "align": "left", "sortable": True},
                             {"name": "host", "label": "HOST", "field": "host", "align": "left", "sortable": True},
                             {"name": "agent", "label": "AGENT", "field": "agent", "align": "left", "sortable": True},
                             {"name": "events", "label": "EVENTS", "field": "events", "align": "right", "sortable": True}],
                    rows=[], row_key="source", pagination={"rowsPerPage": 15},
                ).classes("w-full soc-table mt-2").props("flat bordered dense")
                self.source_table.add_slot("body-cell-health", """
                    <q-td :props="props"><q-badge :style="props.value === 'HEALTHY' ? 'background:#e8f5ed;color:#23774d'
                      : props.value.startsWith('SILENT') ? 'background:#fdecef;color:#c2364f' : 'background:#fff3df;color:#c27400'"
                      style="border-radius:9999px;font-weight:600;padding:4px 8px">{{ props.value }}</q-badge></q-td>""")
            with ui.column().classes("w-full gap-4"):
                with self._card("THREAT INTELLIGENCE (Member 1)"):
                    self.intel_count = ui.badge("0 findings").style(f"background:#e6f5f0;color:{COLORS['teal']}")
                    self.intel_container = ui.column().classes("w-full gap-2 mt-2")
                with self._card("HUNT REQUESTS  ·  answered by the SOC"):
                    self.hunts_box = ui.column().classes("w-full gap-2 mt-2")

    # ---------------------------------------------------------------- alerts
    def _build_alerts(self) -> None:
        with ui.element("div").classes("soc-card p-4 w-full"):
            with ui.row().classes("w-full items-center justify-between"):
                ui.label("DETECTION ALERTS").classes("soc-title")
                with ui.row().classes("items-center gap-2"):
                    self.alert_filter = ui.toggle(["Open", "Closed", "All"], value="Open",
                                                  on_change=lambda: self._render_alerts()).props("dense no-caps unelevated")
            ui.label("Close an alert when it is handled. Closed alerts are hidden for this session only.").classes(
                "text-xs").style(f"color:{COLORS['muted']}")
            self.alert_table = ui.table(
                columns=[{"name": "time", "label": "TIME (UTC)", "field": "time", "align": "left", "sortable": True},
                         {"name": "priority", "label": "LEVEL", "field": "priority", "align": "left", "sortable": True},
                         {"name": "rule", "label": "RULE", "field": "rule", "align": "left", "sortable": True},
                         {"name": "hosts", "label": "MACHINES", "field": "hosts", "align": "left"},
                         {"name": "incident", "label": "INCIDENT", "field": "incident", "align": "left", "sortable": True},
                         {"name": "details", "label": "SUMMARY", "field": "details", "align": "left"},
                         {"name": "status", "label": "STATUS", "field": "status", "align": "left"},
                         {"name": "actions", "label": "", "field": "id", "align": "right"}],
                rows=[], row_key="id", pagination={"rowsPerPage": 15},
            ).classes("w-full soc-table mt-2").props("flat bordered dense wrap-cells")
            self.alert_table.add_slot("body-cell-priority", """
                <q-td :props="props"><q-badge :style="props.value === 'P1' ? 'background:#fdecef;color:#c2364f'
                  : props.value === 'P2' ? 'background:#fff3df;color:#c27400' : 'background:#eaf1fc;color:#3473d1'">{{ props.value }}</q-badge></q-td>""")
            self.alert_table.add_slot("body-cell-actions", """
                <q-td :props="props">
                  <q-btn v-if="props.row.status === 'Open'" dense flat no-caps icon="task_alt" label="Close" color="primary"
                         @click="() => $parent.$emit('close_alert', props.row)" />
                  <q-btn v-else dense flat no-caps icon="undo" label="Reopen" color="grey-8"
                         @click="() => $parent.$emit('reopen_alert', props.row)" />
                </q-td>""")
            self.alert_table.on("close_alert", lambda e: self._close_alert(e.args))
            self.alert_table.on("reopen_alert", lambda e: self._reopen_alert(e.args))

    # ---------------------------------------------------------------- knowledge import (text only)
    def _build_knowledge(self) -> None:
        self.kb_check: Any = None
        with ui.element("div").classes("soc-grid-2 w-full"):
            with ui.column().classes("w-full gap-4"):
                with self._card("IMPORT NEW KNOWLEDGE  ·  plain text only"):
                    ui.label("The base is offline, so new vulnerabilities and indicators are fed in by hand. Only a .txt file or "
                             "pasted text is accepted; it is checked line by line, nothing is executed or opened, and a clean "
                             "copy is stored apart from the logs.").classes("text-xs mt-1").style(f"color:{COLORS['muted']}")
                    self.kb_upload = ui.upload(label="Import a .txt file", auto_upload=True, max_files=1,
                                               max_file_size=kb_store.MAX_BYTES, on_upload=self._kb_uploaded,
                                               on_rejected=lambda: ui.notify("Refused: only one .txt file up to 256 KB",
                                                                             type="negative")
                                               ).props('accept=".txt,text/plain" flat bordered color=primary').classes("w-full mt-2")
                    self.kb_text = ui.textarea("...or paste the text here").props("outlined autogrow").classes("w-full soc-mono mt-2")
                    with ui.row().classes("w-full items-center gap-2 mt-1"):
                        ui.button("Check", icon="rule",
                                  on_click=lambda: self._kb_check_text(self.kb_text.value or "", "pasted text")).props(
                            "unelevated no-caps").style(f"background:{COLORS['blue']};color:white")
                        ui.button("Insert example", icon="lightbulb", on_click=lambda: self.kb_text.set_value(KB_EXAMPLE)).props(
                            "flat no-caps")
                        self.kb_label = ui.input("Label (who/what)", value="operator import").props("outlined dense").classes("grow")
                with self._card("CHECK RESULT"):
                    self.kb_preview = ui.column().classes("w-full gap-1 mt-1")
                    self.kb_import_button = ui.button("Import into the knowledge base", icon="download_done",
                                                      on_click=self._kb_import).props("unelevated no-caps").style(
                        f"background:{COLORS['green']};color:white")
                    self.kb_import_button.disable()
            with ui.column().classes("w-full gap-4"):
                with self._card("WHAT THE IMPORT DOES"):
                    for line in KB_HELP:
                        ui.label(f"- {line}").classes("text-sm")
                with self._card("KNOWLEDGE BASE"):
                    self.kb_imports = ui.column().classes("w-full gap-2 mt-2")
                    self.kb_table = ui.table(
                        columns=[{"name": "kind", "label": "TYPE", "field": "kind", "align": "left", "sortable": True},
                                 {"name": "key", "label": "ITEM", "field": "key", "align": "left", "sortable": True},
                                 {"name": "info", "label": "DETAILS", "field": "info", "align": "left"},
                                 {"name": "file", "label": "IMPORT", "field": "file", "align": "left"}],
                        rows=[], row_key="rid", pagination={"rowsPerPage": 10}).classes("w-full soc-table mt-2").props(
                        "flat bordered dense wrap-cells")

    async def _kb_uploaded(self, e: Any) -> None:
        f = e.file
        name = str(getattr(f, "name", "") or "")
        if not name.lower().endswith(".txt"):
            ui.notify(f"Refused '{name}': only .txt files are accepted", type="negative")
            self.kb_upload.reset()
            return
        data = await f.read()
        self.kb_upload.reset()
        self._kb_check_text(data, name)

    def _kb_check_text(self, data: str | bytes, origin: str) -> None:
        res = kb_store.check(data)
        self.kb_check = res if not res.error and res.records else None
        self.kb_preview.clear()
        with self.kb_preview:
            ui.label(f"Source: {origin} - SHA-256 {res.sha256[:16]}...").classes("text-xs soc-mono").style(f"color:{COLORS['muted']}")
            if res.error:
                ui.label(f"Refused: {res.error}").classes("text-sm font-bold").style(f"color:{COLORS['red']}")
            else:
                ui.label(f"{len(res.records)} record(s) accepted, {len(res.rejected)} line(s) rejected").classes(
                    "text-sm font-bold").style(f"color:{COLORS['green'] if res.records else COLORS['amber']}")
                for r in res.records:
                    ui.label(f"OK  {self._kb_describe(r)}").classes("text-sm")
                for n, line, why in res.rejected:
                    ui.label(f"REJECTED line {n}: {why}" + (f"  ({line})" if line else "")).classes("text-xs soc-mono").style(
                        f"color:{COLORS['amber']}")
        if self.kb_check:
            self.kb_import_button.enable()
        else:
            self.kb_import_button.disable()

    @staticmethod
    def _kb_describe(r: dict) -> str:
        if r["kind"] == "cve":
            extra = ", ".join(x for x in [r.get("product", ""), "/".join(r.get("versions", [])),
                                          "KEV" if r.get("kev") else "", " ".join(r.get("techniques", []))] if x)
            return f"CVE {r['cve']}" + (f" ({extra})" if extra else "") + (f": {r['summary']}" if r.get("summary") else "")
        if r["kind"] == "ioc":
            what = "IP" if r.get("ip") else "Domain" if r.get("domain") else "Hash"
            value = r.get("ip") or r.get("domain") or r.get("hash")
            return f"Indicator {what} {value}" + (f": {r['note']}" if r.get("note") else "")
        return f"Leaked account {r['account']}" + (f": {r['note']}" if r.get("note") else "")

    async def _kb_import(self) -> None:
        if not self.kb_check:
            return
        try:
            path = kb_store.save(self.kb_check, self.kb_label.value or "operator import")
        except (ValueError, OSError) as exc:
            ui.notify(f"Import failed: {exc}", type="negative")
            return
        ui.notify(f"Imported {len(self.kb_check.records)} record(s) as {path.name}; re-analysing the logs...", type="positive")
        self.kb_check = None
        self.kb_import_button.disable()
        self.kb_text.set_value("")
        self.kb_preview.clear()
        self.qwen_results.clear()          # explanations are regenerated with the new knowledge
        await self.refresh()

    def _kb_remove(self, name: str) -> None:
        if kb_store.remove(name):
            ui.notify(f"Withdrew {name} (kept as .removed for the audit trail); press Refresh to re-analyse", type="info")
        self._render_knowledge()

    def _render_knowledge(self) -> None:
        if not hasattr(self, "kb_imports"):
            return
        files = kb_store.imports()
        self.kb_imports.clear()
        with self.kb_imports:
            if not files:
                ui.label("Nothing imported yet.").classes("text-sm").style(f"color:{COLORS['muted']}")
            for m in files:
                with ui.row().classes("w-full items-center justify-between no-wrap"):
                    when = m.get("imported", "")[:16].replace("T", " ")
                    ui.label(f"{when} - {m.get('label', '')} - {m.get('records', '?')} record(s)").classes("text-sm")
                    ui.button(icon="delete", on_click=lambda _, n=m["file"]: self._kb_remove(n)).props(
                        "flat dense round").tooltip(f"Remove {m['file']}")
        rows = []
        for n, r in enumerate(kb_store.load()):
            key = r.get("cve") or r.get("ip") or r.get("domain") or r.get("hash") or r.get("account")
            rows.append({"rid": n, "kind": {"cve": "CVE", "ioc": "indicator", "account": "leaked account"}[r["kind"]],
                         "key": key, "info": _short(self._kb_describe(r), 160), "file": r.get("imported_from", "")[:20]})
        self.kb_table.rows = rows
        self.kb_table.update()

    # ---------------------------------------------------------------- dialogs
    def _build_dialogs(self) -> None:
        with ui.dialog() as self.settings_dialog, ui.card().style("width:min(640px,95vw)"):
            ui.label("LOCAL AI (Ollama)").classes("soc-title")
            self.url_input = ui.input("Ollama URL", value=self.ollama_url).props("outlined dense").classes("w-full")
            self.model_input = ui.input("Model", value=self.ollama_model).props("outlined dense").classes("w-full")
            self.url_input.on_value_change(self._on_qwen_config_change)
            self.model_input.on_value_change(self._on_qwen_config_change)
            self.qwen_status = ui.label(self.qwen_message).classes("text-sm").style(f"color:{COLORS['muted']}")
            with ui.row().classes("w-full justify-end gap-2"):
                self.test_qwen_button = ui.button("Test Qwen", icon="wifi_tethering", on_click=self.test_qwen).props(
                    "unelevated no-caps").style(f"background:{COLORS['blue']};color:white")
                ui.button("Close", on_click=self.settings_dialog.close).props("flat no-caps")
        with ui.dialog() as self.close_dialog, ui.card().style("width:min(520px,95vw)"):
            self.close_dialog_title = ui.label("Close").classes("text-lg font-bold")
            self.close_reason = ui.select(CLOSE_REASONS, value="Resolved", label="Reason").props("outlined dense").classes("w-full")
            self.close_note = ui.input("Note (optional)").props("outlined dense").classes("w-full")
            ui.label("Hidden for this session only. Reloading the page shows it again (synthetic data).").classes(
                "text-xs").style(f"color:{COLORS['muted']}")
            with ui.row().classes("w-full justify-end gap-2"):
                ui.button("Cancel", on_click=self.close_dialog.close).props("flat no-caps")
                ui.button("Close it", icon="task_alt", on_click=self._confirm_close).props("unelevated no-caps").style(
                    f"background:{COLORS['green']};color:white")
        self._closing: tuple[str, str] | None = None

    # =================================================================== data
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
            self.incidents = sorted(snapshot.incidents, key=lambda item: (-int(item.get("score", 0)), str(item.get("id", ""))))
            new_alerts = self._record_new_alerts(snapshot)
            self._render_snapshot(snapshot)
            if new_alerts and not first_snapshot:
                ui.notify(f"{len(new_alerts)} new detection alert(s)", type="warning", position="top")
        finally:
            self.loading = False
            self.refresh_button.enable()

    def _record_new_alerts(self, snapshot: DashboardSnapshot) -> list[Record]:
        cycle = int(snapshot.evaluation.get("cycle", 0))
        created: list[Record] = []
        for alert in snapshot.alerts:
            evidence = alert.get("evidence") or []
            markers = tuple(sorted({m for item in evidence for m in re.findall(r"CSV-ROW-\d+", str(item.get("raw", "")))}))
            if not markers:
                markers = tuple(sorted(str(item.get("id", "")) for item in evidence))
            fingerprint = (cycle, str(alert.get("rule", "")), markers, str(alert.get("text", "")))
            if fingerprint in self.alert_fingerprints:
                continue
            self.alert_fingerprints.add(fingerprint)
            created.append(alert)
            self.alert_history.append(alert)
        return created

    # ---------------------------------------------------------------- open/closed helpers
    def _incident_of_alert(self) -> dict[str, Record]:
        return {str(a.get("id")): inc for inc in self.incidents for a in inc.get("alerts", [])}

    def _alert_closed(self, alert: Record, owner: Record | None) -> bool:
        return str(alert.get("id")) in self.closed_alerts or (owner is not None and str(owner.get("id")) in self.closed_incidents)

    def _visible_incidents(self) -> list[Record]:
        out = []
        for inc in self.incidents:
            iid = str(inc.get("id"))
            if iid in self.closed_incidents and not self.show_closed:
                continue
            if self.priority_filter != "All" and inc.get("priority") != self.priority_filter:
                continue
            if self.incident_query:
                blob = " ".join([_text(inc.get("title"), ""), " ".join(h.get("host", "") for h in inc.get("hosts", [])),
                                 " ".join(inc.get("users", [])), iid]).lower()
                if self.incident_query.lower() not in blob:
                    continue
            out.append(inc)
        return out

    def _open_incidents(self) -> list[Record]:
        return [i for i in self.incidents if str(i.get("id")) not in self.closed_incidents]

    # =================================================================== render
    def _render_snapshot(self, snapshot: DashboardSnapshot) -> None:
        evaluation = snapshot.evaluation
        if evaluation:
            self.data_badge.set_text(f"SIMULATION · {evaluation.get('rows_seen', 0)} events · cycle {evaluation.get('cycle', 1)}")
        else:
            self.data_badge.set_text(f"MONITORING · {_when(snapshot.generated_at, '%H:%M:%S UTC')}")
        self.status_line.set_text(
            f"Updated {_when(snapshot.generated_at)} · {len(snapshot.events):,} events from {len(snapshot.sources)} log sources · "
            f"{len(snapshot.alerts)} alerts · {len(snapshot.maintenance)} approved maintenance records · closed items reset on reload")
        self.status_line.style(f"color:{COLORS['muted']}")
        if self.selected_incident_id not in {str(i.get("id")) for i in self.incidents}:
            self.selected_incident_id = str(self.incidents[0].get("id")) if self.incidents else None
        self._render_counts()
        self._render_overview()
        self._render_priority_queue()
        self._render_selected_incident()
        self._render_agents()
        self._render_sources()
        self._render_member_one(snapshot)
        self._render_alerts()
        self._render_entity_options()
        self._render_knowledge()
        if not self.search_results:
            self.run_search()

    def _render_counts(self) -> None:
        s = self.snapshot
        if s is None:
            return
        owners = self._incident_of_alert()
        open_alerts = [a for a in s.alerts if not self._alert_closed(a, owners.get(str(a.get("id"))))]
        opened = self._open_incidents()
        healthy = sum(bool(x.get("ok")) for x in s.sources)
        self.kpi["open"].set_text(str(len(opened)))
        self.kpi["p1"].set_text(str(sum(i.get("priority") == "P1" for i in opened)))
        self.kpi["alerts"].set_text(str(len(open_alerts)))
        self.kpi["health"].set_text(f"{healthy}/{len(s.sources)}")
        self.kpi["agents"].set_text(str(len(s.agents)))
        self.kpi["closed"].set_text(str(len(self.closed_incidents) + len(self.closed_alerts)))
        self.alerts_button.set_text(f"Alerts {len(open_alerts)}")

    # ---------------------------------------------------------------- overview
    def _render_overview(self) -> None:
        s = self.snapshot
        if s is None:
            return
        owners = self._incident_of_alert()
        alerts = [a for a in s.alerts if not self._alert_closed(a, owners.get(str(a.get("id"))))]
        buckets: dict[str, Counter] = {}
        for a in alerts:
            t = _dt(a.get("time"))
            if t:
                buckets.setdefault(t.strftime("%m-%d %H:00"), Counter())[_priority(a.get("severity"))] += 1
        times = sorted(buckets)
        self.chart_alerts.options.clear()
        self.chart_alerts.options.update({
            "tooltip": {"trigger": "axis"}, "legend": {"top": 0}, "grid": {"left": 36, "right": 12, "top": 30, "bottom": 40},
            "xAxis": {"type": "category", "data": times, "axisLabel": {"fontSize": 10}},
            "yAxis": {"type": "value", "minInterval": 1},
            "series": [{"name": p, "type": "bar", "stack": "a", "data": [buckets[t][p] for t in times],
                        "itemStyle": {"color": PRIORITY_COLOR[p]}} for p in ("P1", "P2", "P3")]})
        self.chart_alerts.update()
        opened = self._open_incidents()
        pc = Counter(i.get("priority", "P3") for i in opened)
        self.chart_priority.options.clear()
        self.chart_priority.options.update({
            "tooltip": {"trigger": "item"}, "legend": {"bottom": 0},
            "series": [{"type": "pie", "radius": ["45%", "72%"], "label": {"formatter": "{b}: {c}"},
                        "data": [{"name": p, "value": pc.get(p, 0), "itemStyle": {"color": PRIORITY_COLOR[p]}}
                                 for p in ("P1", "P2", "P3") if pc.get(p)]}]})
        self.chart_priority.update()
        hc = Counter(h for a in alerts for h in a.get("hosts", []))
        top = hc.most_common(10)[::-1]
        self.chart_hosts.options.clear()
        self.chart_hosts.options.update({
            "tooltip": {}, "grid": {"left": 120, "right": 20, "top": 10, "bottom": 20},
            "xAxis": {"type": "value", "minInterval": 1}, "yAxis": {"type": "category", "data": [h for h, _ in top]},
            "series": [{"type": "bar", "data": [n for _, n in top], "itemStyle": {"color": COLORS["blue"]}}]})
        self.chart_hosts.update()
        self.overview_incidents.clear()
        with self.overview_incidents:
            for inc in opened[:6]:
                self._incident_card(inc, compact=True, go=True)
            if not opened:
                ui.label("No open incidents.").classes("text-sm").style(f"color:{COLORS['muted']}")
        self._render_attack_matrix(opened)

    def _render_attack_matrix(self, incidents: list[Record]) -> None:
        tech: dict[str, dict] = {}
        for inc in incidents:
            for t in inc.get("attack", []):
                d = tech.setdefault(t.get("id"), {"name": t.get("name", ""), "tactic": t.get("tactic", ""), "n": 0, "inc": []})
                d["n"] += 1
                d["inc"].append(str(inc.get("id")))
        self.attack_matrix.clear()
        with self.attack_matrix:
            for tactic in TACTICS:
                items = sorted(((k, v) for k, v in tech.items() if v["tactic"] == tactic), key=lambda kv: -kv[1]["n"])
                with ui.element("div").classes("soc-tactic"):
                    ui.label(tactic).classes("text-xs font-bold").style(f"color:{COLORS['navy']}")
                    ui.label(f"{len(items)} technique(s)").classes("text-xs").style(f"color:{COLORS['muted']}")
                    for tid, v in items:
                        shade = min(0.15 + 0.22 * v["n"], 0.9)
                        with ui.element("div").classes("soc-tech").style(
                                f"background:rgba(194,54,79,{shade});color:{'white' if shade > .5 else COLORS['ink']}"):
                            ui.label(f"{tid}").classes("font-bold")
                            ui.label(_short(v["name"].split(": ")[-1], 34))
                            ui.tooltip(f"{v['name']} · in {v['n']} incident(s): {', '.join(v['inc'])}")

    # ---------------------------------------------------------------- incidents
    def _set_incident_query(self, value: str | None) -> None:
        self.incident_query = value or ""
        self._render_priority_queue()

    def _set_priority_filter(self, value: str) -> None:
        self.priority_filter = value
        self._render_priority_queue()

    def _set_show_closed(self, value: bool) -> None:
        self.show_closed = bool(value)
        self._render_priority_queue()

    def _incident_card(self, inc: Record, compact: bool = False, go: bool = False) -> None:
        iid = str(inc.get("id"))
        pr = str(inc.get("priority", "P3"))
        closed = iid in self.closed_incidents
        classes = "soc-inc w-full" + (" sel" if iid == self.selected_incident_id and not compact else "") + (" closed" if closed else "")
        card = ui.element("div").classes(classes).style(f"--pc:{PRIORITY_COLOR.get(pr, COLORS['blue'])}")
        card.on("click", lambda _=None, k=iid: self.select_incident(k, go=go))
        with card:
            with ui.row().classes("w-full items-center justify-between no-wrap gap-2"):
                with ui.row().classes("items-center gap-2 no-wrap"):
                    ui.badge(pr).style(f"background:{PRIORITY_COLOR.get(pr)};color:white")
                    ui.label(f"{_when(inc.get('start'), '%m-%d %H:%M')} · score {inc.get('score', '—')}").classes(
                        "text-xs").style(f"color:{COLORS['muted']}")
                if closed:
                    ui.badge(f"CLOSED · {self.closed_incidents[iid]['reason']}").style("background:#e8f5ed;color:#23774d")
            ui.label(_short(inc.get("title"), 110 if compact else 150)).classes("text-sm font-semibold mt-1")
            if not compact:
                hosts = ", ".join(h.get("host", "") for h in inc.get("hosts", [])[:4])
                ui.label(f"{hosts} · {len(inc.get('alerts', []))} alerts · {', '.join(inc.get('users', [])[:3]) or 'no account'}").classes(
                    "text-xs").style(f"color:{COLORS['muted']}")
                with ui.row().classes("gap-1 mt-1 items-center"):
                    for st in inc.get("stages", []):
                        ui.icon(STAGE_ICON.get(st, "circle")).classes("text-base").style(f"color:{COLORS['navy_light']}").tooltip(st)

    def _render_priority_queue(self) -> None:
        self.incident_queue.clear()
        visible = self._visible_incidents()
        self.queue_count.set_text(f"{len(self._open_incidents())} open")
        with self.incident_queue:
            if not visible:
                ui.label("No incidents match. The deterministic SOC rules found nothing else to escalate.").classes(
                    "text-sm").style(f"color:{COLORS['muted']}")
            for inc in visible:
                self._incident_card(inc)

    def select_incident(self, incident_id: str, go: bool = False) -> None:
        self.selected_incident_id = incident_id
        if go:
            self.nav.set_value("incidents")
        self._render_priority_queue()
        self._render_selected_incident()

    def _selected(self) -> Record | None:
        return next((i for i in self.incidents if str(i.get("id")) == self.selected_incident_id), None)

    def _agent_of_source(self) -> dict[str, str]:
        s = self.snapshot
        return {src: a.get("title", a.get("agent")) for a in (s.agents if s else []) for src in a.get("sources", [])}

    def _render_selected_incident(self) -> None:
        incident = self._selected()
        if incident is None:
            self.incident_title.set_text("No correlated incidents")
            self.incident_meta.set_text("No incident met the deterministic correlation criteria.")
            self.close_button.disable()
            return
        self.close_button.enable()
        iid = str(incident.get("id"))
        pr = str(incident.get("priority", "P3"))
        closed = iid in self.closed_incidents
        self.incident_title.set_text(_text(incident.get("title"), iid))
        conf = incident.get("confidence")
        conf_text = f"{conf:.0%}" if isinstance(conf, (int, float)) else _text(conf)
        self.incident_meta.set_text(f"{iid} · {_when(incident.get('start'))} – {_when(incident.get('end'), '%H:%M UTC')} · "
                                    f"{len(incident.get('alerts', []))} correlated alerts · confidence {conf_text}")
        bg, fg = _priority_colors(pr)
        self.priority_badge.set_text(f"{pr} · SCORE {incident.get('score', '—')}")
        self.priority_badge.style(f"background-color:{bg} !important;color:{fg} !important")
        self.close_button.set_text("Reopen incident" if closed else "Close incident")
        self.close_button.props(f"icon={'undo' if closed else 'task_alt'}")
        self.close_button.style(f"background:{COLORS['muted'] if closed else COLORS['green']};color:white")
        self.incident_badges.clear()
        with self.incident_badges:
            for acc in incident.get("compromised_accounts", []):
                ui.chip(f"compromised: {acc}", icon="person_off").props("dense").style("background:#fdecef;color:#c2364f")
            for ip in incident.get("unknown_ips", [])[:4]:
                ui.chip(ip, icon="public").props("dense outline")
            if closed:
                c = self.closed_incidents[iid]
                ui.chip(f"closed · {c['reason']}" + (f" · {c['note']}" if c.get("note") else ""), icon="task_alt").props(
                    "dense").style("background:#e8f5ed;color:#23774d")
        self.attack_path.clear()
        with self.attack_path:
            stages = incident.get("stages", [])
            for n, st in enumerate(stages):
                ui.chip(st.upper(), icon=STAGE_ICON.get(st, "circle")).props("dense").style(
                    f"background:#eaf1fc;color:{COLORS['blue']};font-weight:600")
                if n < len(stages) - 1:
                    ui.icon("chevron_right").style(f"color:{COLORS['muted']}")
        self._render_story(incident)
        self._render_timeline(incident)
        self._render_evidence(incident)
        self._render_checks(incident)
        self._render_explanation(incident)

    def _render_story(self, incident: Record) -> None:
        self.story_box.clear()
        with self.story_box:
            if incident.get("story"):
                with ui.element("div").classes("w-full p-3").style("background:#f5f8fc;border-radius:12px;border:1px solid #e3e9f0"):
                    ui.label("WHAT HAPPENED (rule-based, instant)").classes("soc-title")
                    ui.label(incident["story"]).classes("text-sm mt-1 soc-explanation-text")
            techniques = incident.get("attack", [])
            if techniques:
                with ui.row().classes("gap-1 flex-wrap"):
                    for t in techniques:
                        ui.chip(f"{t.get('id')} {t.get('name', '').split(': ')[-1]}").props("dense outline").tooltip(
                            f"{t.get('tactic')} · {t.get('name')}")
        path = incident.get("path") or []
        nodes, links = [], []
        if path:
            order = list(dict.fromkeys([path[0]["from"]] + [h["to"] for h in path] + [h["from"] for h in path]))
            nodes = [{"name": h, "x": 120 * k, "y": (k % 2) * 60, "symbolSize": 58,
                      "itemStyle": {"color": COLORS["red"] if k == 0 else COLORS["navy_light"]}} for k, h in enumerate(order)]
            links = [{"source": h["from"], "target": h["to"],
                      "label": {"show": True, "formatter": f"{'/'.join(map(str, h.get('ports', []))) or '-'}"
                                                           f"{' · ' + ', '.join(h.get('accounts', [])) if h.get('accounts') else ''}",
                                "fontSize": 10}} for h in path]
        self.chart_graph.options.clear()
        self.chart_graph.options.update({
            "title": {"text": "ATTACKER PATH" if path else "No machine-to-machine movement in this incident",
                      "textStyle": {"fontSize": 12, "color": "#4d5f74"}},
            "tooltip": {},
            "series": [{"type": "graph", "layout": "none", "roam": True, "data": nodes, "links": links,
                        "label": {"show": True, "color": "white", "fontSize": 10, "fontWeight": "bold"},
                        "edgeSymbol": ["none", "arrow"], "edgeSymbolSize": 10,
                        "lineStyle": {"width": 2, "color": COLORS["red"], "curveness": 0.15}}]})
        self.chart_graph.update()
        self.escalation_box.clear()
        with self.escalation_box:
            esc = incident.get("escalation") or []
            if esc:
                ui.label("RIGHTS GAINED OR STOLEN").classes("soc-title")
                with ui.timeline(side="right").classes("w-full"):
                    for e in esc:
                        ui.timeline_entry(_text(e.get("detail")), title=_text(e.get("what")).capitalize(),
                                          subtitle=_when(e.get("time"), "%H:%M:%S UTC"), icon="admin_panel_settings",
                                          color="red")

    def _render_timeline(self, incident: Record) -> None:
        agent_of = self._agent_of_source()
        rows = []
        for n, alert in enumerate(sorted(incident.get("alerts", []), key=lambda a: str(a.get("time", "")))):
            seen = sorted({agent_of.get(e.get("source"), e.get("source")) for e in alert.get("evidence", [])})
            rows.append({"key": n, "time": _when(alert.get("time"), "%m-%d %H:%M:%S"), "stage": _text(alert.get("stage"), "alert"),
                         "rule": _text(alert.get("rule")), "agent": ", ".join(seen),
                         "summary": f"{_short(alert.get('text'), 220)} · {len(alert.get('evidence') or [])} line(s)"})
        self.timeline_table.rows = rows
        self.timeline_table.update()

    def _render_evidence(self, incident: Record) -> None:
        self.evidence_box.clear()
        with self.evidence_box:
            items = [(a, e) for a in incident.get("alerts", []) for e in a.get("evidence", [])]
            ui.label(f"{len(items)} raw log line(s) behind this incident").classes("text-xs").style(f"color:{COLORS['muted']}")
            for alert, item in items[:150]:
                with ui.element("div").classes("w-full p-2").style("border:1px solid #e6ebf1;border-radius:10px"):
                    ui.label(f"{_when(item.get('time'), '%m-%d %H:%M:%S')} · {alert.get('rule')} · {_text(item.get('source'))}:"
                             f"{_text(item.get('line'))}").classes("text-xs font-bold").style(f"color:{COLORS['muted']}")
                    ui.label(_text(item.get("raw"))).classes("soc-mono whitespace-pre-wrap soc-explanation-text")

    def _render_checks(self, incident: Record) -> None:
        self.checks_box.clear()
        with self.checks_box:
            ui.label("SUGGESTED CHECKS (advice only: the operator decides)").classes("soc-title")
            for step in incident.get("next_checks", []):
                kind = str(step.get("type", "verify"))
                ui.label(f"{'🔍' if kind == 'verify' else '🛡'}  [{kind}] {step.get('step')}").classes("text-sm")
            for x in incident.get("intel", []):
                with ui.element("div").classes("w-full p-2 mt-1").style("background:#f1faf7;border-radius:10px"):
                    ui.label(f"OSINT {x.get('id')}: {x.get('why')}").classes("text-sm font-semibold")
                    ui.label(_text(x.get("summary"), "")).classes("text-xs")
            if incident.get("why_together"):
                ui.label("WHY THESE ALERTS BELONG TOGETHER").classes("soc-title mt-2")
                for r in incident["why_together"][:8]:
                    ui.label(f"• {r}").classes("text-xs")
            if incident.get("confidence_reasons"):
                ui.label("CONFIDENCE").classes("soc-title mt-2")
                for r in incident["confidence_reasons"]:
                    ui.label(f"• {r}").classes("text-xs")

    # ---------------------------------------------------------------- closing (session only)
    def _ask_close_incident(self) -> None:
        inc = self._selected()
        if inc is None:
            return
        iid = str(inc.get("id"))
        if iid in self.closed_incidents:
            self.closed_incidents.pop(iid)
            ui.notify(f"{iid} reopened", type="info")
            self._after_close_change()
            return
        self._closing = ("incident", iid)
        self.close_dialog_title.set_text(f"Close incident {iid}")
        self.close_note.set_value("")
        self.close_dialog.open()

    def _close_alert(self, row: dict) -> None:
        self._closing = ("alert", str(row.get("id")))
        self.close_dialog_title.set_text(f"Close alert {row.get('rule')} · {row.get('time')}")
        self.close_note.set_value("")
        self.close_dialog.open()

    def _reopen_alert(self, row: dict) -> None:
        self.closed_alerts.pop(str(row.get("id")), None)
        owner = self._incident_of_alert().get(str(row.get("id")))
        if owner is not None and str(owner.get("id")) in self.closed_incidents:
            ui.notify("This alert belongs to a closed incident; reopen the incident to reopen its alerts.", type="warning")
        self._after_close_change()

    def _confirm_close(self) -> None:
        if not self._closing:
            return
        kind, key = self._closing
        info = {"reason": self.close_reason.value or "Resolved", "note": self.close_note.value or "",
                "at": datetime.now(timezone.utc).strftime("%H:%M UTC")}
        (self.closed_incidents if kind == "incident" else self.closed_alerts)[key] = info
        self.close_dialog.close()
        ui.notify(f"{kind.capitalize()} closed ({info['reason']}) for this session", type="positive")
        self._closing = None
        self._after_close_change()

    def _after_close_change(self) -> None:
        self._render_counts()
        self._render_overview()
        self._render_priority_queue()
        self._render_selected_incident()
        self._render_alerts()

    # ---------------------------------------------------------------- alerts view
    def _render_alerts(self) -> None:
        s = self.snapshot
        if s is None:
            return
        owners = self._incident_of_alert()
        rows = []
        for a in sorted(s.alerts, key=lambda x: str(x.get("time", "")), reverse=True):
            owner = owners.get(str(a.get("id")))
            closed = self._alert_closed(a, owner)
            status = "Open" if not closed else ("Closed · " + (self.closed_alerts.get(str(a.get("id")), {}).get("reason")
                                                               or f"incident {self.closed_incidents.get(str(owner.get('id')), {}).get('reason', '')}"))
            if self.alert_filter.value == "Open" and closed or self.alert_filter.value == "Closed" and not closed:
                continue
            rows.append({"id": str(a.get("id")), "time": _when(a.get("time"), "%m-%d %H:%M:%S"),
                         "priority": _priority(a.get("severity")), "rule": _text(a.get("rule")),
                         "hosts": ", ".join(a.get("hosts", [])[:3]),
                         "incident": str(owner.get("id")) if owner else "single alert",
                         "details": _short(plain_alert_explanation(a), 200), "status": status})
        self.alert_table.rows = rows
        self.alert_table.update()

    # ---------------------------------------------------------------- agents view
    def _render_agents(self) -> None:
        s = self.snapshot
        if s is None:
            return
        agents = s.agents
        self.chart_agents.options.clear()
        self.chart_agents.options.update({
            "tooltip": {"trigger": "axis"}, "legend": {"top": 0}, "grid": {"left": 50, "right": 12, "top": 30, "bottom": 50},
            "xAxis": {"type": "category", "data": [a.get("title", "").replace(" agent", "") for a in agents],
                      "axisLabel": {"fontSize": 10, "interval": 0, "rotate": 15}},
            "yAxis": {"type": "value", "name": "events/h"},
            "series": [{"name": "normal (baseline)", "type": "bar", "data": [a.get("normal", {}).get("per_hour") for a in agents],
                        "itemStyle": {"color": "#9fb3c8"}},
                       {"name": "now", "type": "bar", "data": [a.get("today", {}).get("per_hour") for a in agents],
                        "itemStyle": {"color": COLORS["blue"]}}]})
        self.chart_agents.update()
        sel = self._selected()
        sel_id = str(sel.get("id")) if sel else None
        self.agents_box.clear()
        with self.agents_box:
            for a in agents:
                saw = sel_id in (a.get("incidents") or [])
                with ui.element("div").classes("soc-card p-4").style(
                        f"border:2px solid {COLORS['violet']}" if saw else ""):
                    with ui.row().classes("w-full items-center justify-between no-wrap"):
                        with ui.row().classes("items-center gap-2 no-wrap"):
                            ui.icon(AGENT_ICON.get(a.get("agent"), "smart_toy")).classes("text-2xl").style(f"color:{COLORS['violet']}")
                            with ui.column().classes("gap-0"):
                                ui.label(a.get("title")).classes("font-bold")
                                ui.label(_short(a.get("watches"), 60)).classes("text-xs").style(f"color:{COLORS['muted']}")
                        if a.get("alerts"):
                            ui.badge(f"{a['alerts']} alerts").style(f"background:{COLORS['red']};color:white")
                    ch = a.get("today", {}).get("change_pct")
                    with ui.row().classes("items-end gap-3 mt-2"):
                        ui.label(f"{a.get('events_today', 0):,}").classes("text-2xl font-bold")
                        ui.label(f"events now · {a.get('today', {}).get('per_hour')}/h vs normal {a.get('normal', {}).get('per_hour')}/h"
                                 + (f" ({'+' if ch > 0 else ''}{ch}%)" if ch is not None else "")).classes("text-xs mb-1").style(
                            f"color:{COLORS['red'] if ch and ch > 50 else COLORS['muted']}")
                    ui.label(f"{len(a.get('sources', []))} log source(s) on {a.get('hosts')} host(s) · "
                             f"{a.get('maintenance_filtered', 0):,} approved-maintenance events set aside").classes(
                        "text-xs").style(f"color:{COLORS['muted']}")
                    for h in a.get("highlights", [])[:5]:
                        ui.label(f"• {h}").classes("text-sm soc-explanation-text")
                    if a.get("silent_sources"):
                        ui.label(f"⚠ silent: {', '.join(a['silent_sources'])}").classes("text-sm").style(f"color:{COLORS['amber']}")
                    if a.get("incidents"):
                        with ui.row().classes("gap-1 mt-2 flex-wrap"):
                            for iid in a["incidents"][:8]:
                                ui.chip(iid, on_click=lambda _, k=iid: self.select_incident(k, go=True)).props(
                                    "dense clickable").style(
                                    f"background:{'#ece7fb' if iid == sel_id else '#f1f4f8'};color:{COLORS['ink']}")
                    if saw:
                        ui.label("saw the selected incident").classes("text-xs font-bold mt-1").style(f"color:{COLORS['violet']}")

    # ---------------------------------------------------------------- sources & intel
    def _render_sources(self) -> None:
        s = self.snapshot
        if s is None:
            return
        agent_of = self._agent_of_source()
        rows = [{"source": _text(x.get("source")), "host": _text(x.get("host")), "agent": agent_of.get(x.get("source"), "—"),
                 "events": x.get("events", 0), "health": "HEALTHY" if x.get("ok") else self._source_warning(x)} for x in s.sources]
        rows.sort(key=lambda r: (r["health"] == "HEALTHY", r["source"]))
        self.source_table.rows = rows
        self.source_table.update()
        self.hunts_box.clear()
        with self.hunts_box:
            if not s.hunt_requests:
                ui.label("No hunt requests.").classes("text-sm")
            for h in s.hunt_requests:
                found = str(h.get("status", "")).startswith("found")
                with ui.element("div").classes("w-full p-2").style(
                        f"border-left:4px solid {COLORS['red'] if found else COLORS['green']};background:#f7f9fc;border-radius:8px"):
                    ui.label(f"{_text(h.get('hunt_id'))} · {', '.join(map(str, h.get('target_assets', [])))}").classes("text-sm font-bold")
                    ui.label(_text(h.get("status"), _text(h.get("hunt_query")))).classes("text-xs")
                    for iid in h.get("incidents", []) or []:
                        ui.chip(iid, on_click=lambda _, k=iid: self.select_incident(k, go=True)).props("dense clickable outline")

    def _render_member_one(self, snapshot: DashboardSnapshot) -> None:
        findings = snapshot.threat_findings
        self.intel_count.set_text(f"{len(findings)} findings · {len(snapshot.hunt_requests)} hunts")
        self.intel_container.clear()
        with self.intel_container:
            if not findings:
                ui.label("No threat-intelligence matches for the current asset inventory.").classes("text-sm").style(
                    f"color:{COLORS['muted']}")
            for finding in findings[:10]:
                kind = str(finding.get("finding_type") or finding.get("type") or "threat finding")
                is_vuln = kind == "vulnerability_exposure" or (bool(finding.get("cve")) and not finding.get("account"))
                title = str(finding.get("cve", "Vulnerability exposure")) if is_vuln else \
                    f"Credential exposure · {_text(finding.get('account'), 'account unknown')}"
                with ui.element("div").classes("w-full p-3").style("border:1px solid #e6ebf1;border-radius:12px"):
                    with ui.row().classes("w-full items-center justify-between gap-2"):
                        ui.label(title).classes("font-bold text-sm")
                        if is_vuln and finding.get("cisa_kev"):
                            ui.badge("CISA KEV").style(f"background:#fdecef;color:{COLORS['red']}")
                        elif not is_vuln:
                            ui.badge(f"Confidence {_number(finding.get('confidence')):.0%}").style(f"background:#eaf1fc;color:{COLORS['blue']}")
                    ui.label(_text(finding.get("summary"))).classes("text-sm")
                    meta = ["Assets: " + ", ".join(str(i) for i in finding.get("affected_assets", []))]
                    if is_vuln:
                        meta.append(f"EPSS {_number(finding.get('epss_score')):.2f}")
                    elif finding.get("source"):
                        meta.append(f"Source: {finding['source']}")
                    ui.label(" · ".join(meta)).classes("text-xs").style(f"color:{COLORS['muted']}")
                    for iid in finding.get("matched_incidents", []) or []:
                        ui.chip(f"matches {iid}", on_click=lambda _, k=iid: self.select_incident(k, go=True)).props(
                            "dense clickable").style("background:#fdecef;color:#c2364f")

    # ---------------------------------------------------------------- search
    def _example(self, q: str) -> None:
        self.search_input.set_value(q)
        self.run_search()

    def _add_filter(self, field: str, value: str) -> None:
        term = f'{field}="{value}"' if " " in value else f"{field}={value}"
        current = (self.search_input.value or "").strip()
        self.search_input.set_value(f"{current} {term}".strip())
        self.run_search()

    def _range(self) -> tuple[datetime | None, datetime | None]:
        s = self.snapshot
        if s is None or not s.events:
            return None, None
        first, last = s.events[0].get("time"), s.events[-1].get("time")
        r = self.search_range.value
        if r == "base" and first:
            return first, first + timedelta(hours=24)
        if r == "attack" and first:
            return first + timedelta(hours=24), None
        if r == "last6" and last:
            return last - timedelta(hours=6), None
        return None, None

    def run_search(self) -> None:
        s = self.snapshot
        if s is None:
            return
        start, end = self._range()
        hits = event_search.search(s.events, self.search_input.value or "", start, end)
        self.search_results = hits
        self.search_count.set_text(f"{len(hits):,} events" + (" (showing newest 2,000)" if len(hits) > 2000 else ""))
        hist = event_search.histogram(hits, 60)
        self.chart_search.options.clear()
        self.chart_search.options.update({
            "tooltip": {"trigger": "axis"}, "grid": {"left": 40, "right": 10, "top": 10, "bottom": 30},
            "xAxis": {"type": "category", "data": [h[0] for h in hist], "axisLabel": {"fontSize": 9}},
            "yAxis": {"type": "value", "minInterval": 1},
            "series": [{"type": "bar", "data": [h[1] for h in hist], "itemStyle": {"color": COLORS["teal"]}}]})
        self.chart_search.update()
        rows = []
        for e in hits[-2000:][::-1]:
            src = e.get("src_host") or e.get("src_ip")
            dst = e.get("dst_host") or e.get("dst_ip")
            net = f"{src or ''} → {dst or ''}{':' + str(e['dst_port']) if e.get('dst_port') else ''}" if (src or dst) else ""
            rows.append({"id": e.get("id"), "time": _when(e.get("time"), "%m-%d %H:%M:%S"), "agent": _text(e.get("agent"), ""),
                         "host": _text(e.get("host"), ""), "action": f"{e.get('type', '')}/{e.get('action', '')}",
                         "user": _text(e.get("user"), ""), "net": net, "raw": _short(e.get("raw"), 260)})
        self.search_table.rows = rows
        self.search_table.update()
        self.fields_box.clear()
        with self.fields_box:
            for field, values in event_search.field_stats(hits).items():
                with ui.expansion(f"{field}  ({len(values)})", value=field in ("agent", "host", "action", "user")).classes(
                        "w-full").props("dense"):
                    for value, n in values:
                        with ui.row().classes("w-full items-center justify-between no-wrap soc-field-val").on(
                                "click", lambda _=None, f=field, v=value: self._add_filter(f, v)):
                            ui.label(_short(value, 34)).classes("text-xs soc-mono")
                            ui.label(f"{n:,}").classes("text-xs").style(f"color:{COLORS['muted']}")

    # ---------------------------------------------------------------- entities
    def _render_entity_options(self) -> None:
        s = self.snapshot
        if s is None:
            return
        hosts = sorted({a.get("host") for a in s.assets.get("assets", []) if a.get("host")}
                       | {e.get("host") for e in s.events[:0]})
        users = sorted({u.get("user") for u in s.assets.get("users", []) if u.get("user")}
                       | {u for inc in self.incidents for u in inc.get("users", [])})
        opts = {f"host:{h}": f"🖥 {h}" for h in hosts}
        opts.update({f"user:{u}": f"👤 {u}" for u in users})
        self.entity_select.set_options(opts)

    def show_entity(self, key: str | None) -> None:
        s = self.snapshot
        self.entity_box.clear()
        if not key or s is None:
            return
        kind, name = key.split(":", 1)
        low = name.lower()
        if kind == "host":
            info = next((a for a in s.assets.get("assets", []) if str(a.get("host")).lower() == low), {})
            evs = [e for e in s.events if str(e.get("host", "")).lower() == low or str(e.get("src_host", "")).lower() == low
                   or str(e.get("dst_host", "")).lower() == low]
            alerts = [a for a in s.alerts if name in a.get("hosts", [])]
            incs = [i for i in self.incidents if any(h.get("host") == name for h in i.get("hosts", []))]
        else:
            info = next((u for u in s.assets.get("users", []) if str(u.get("user")).lower() == low), {})
            evs = [e for e in s.events if str(e.get("user", "")).lower() == low]
            alerts = [a for a in s.alerts if name in a.get("users", [])]
            incs = [i for i in self.incidents if name in i.get("users", [])]
        with self.entity_box:
            with ui.element("div").classes("soc-grid-3 w-full"):
                with self._card("PROFILE"):
                    ui.label(f"{'🖥' if kind == 'host' else '👤'} {name}").classes("text-xl font-bold mt-1")
                    for k, v in info.items():
                        if k not in ("host", "user") and v not in (None, "", []):
                            ui.label(f"{k}: {', '.join(map(str, v)) if isinstance(v, list) else v}").classes("text-sm")
                    if kind == "host" and info.get("ip"):
                        zone = next((z["name"] for z in s.assets.get("zones", []) if self._in_cidr(info["ip"], z.get("cidr"))), None)
                        if zone:
                            ui.label(f"zone: {zone}").classes("text-sm")
                with self._card("ACTIVITY"):
                    ui.label(f"{len(evs):,} events · {len(alerts)} alerts · {len(incs)} incident(s)").classes("text-sm font-semibold mt-1")
                    for act, n in Counter(f"{e.get('type')}/{e.get('action')}" for e in evs).most_common(8):
                        ui.label(f"{act}: {n:,}").classes("text-xs soc-mono")
                with self._card("INCIDENTS"):
                    for inc in incs:
                        self._incident_card(inc, compact=True, go=True)
                    if not incs:
                        ui.label("Not part of any incident.").classes("text-sm").style(f"color:{COLORS['green']}")
            hist = event_search.histogram(evs, 60)
            with self._card("EVENTS OVER TIME"):
                ui.echart({"tooltip": {"trigger": "axis"}, "grid": {"left": 40, "right": 10, "top": 10, "bottom": 30},
                           "xAxis": {"type": "category", "data": [h[0] for h in hist], "axisLabel": {"fontSize": 9}},
                           "yAxis": {"type": "value", "minInterval": 1},
                           "series": [{"type": "bar", "data": [h[1] for h in hist], "itemStyle": {"color": COLORS["violet"]}}]}).classes(
                    "w-full h-40")
            peers = Counter()
            for e in evs:
                other = e.get("dst_host") if str(e.get("src_host", "")).lower() == low else e.get("src_host")
                if other and other.lower() != low:
                    peers[(other, e.get("dst_port"))] += 1
            with ui.element("div").classes("soc-grid-2 w-full"):
                with self._card("TALKS TO / FROM (machine, port)"):
                    for (other, port), n in peers.most_common(15):
                        ui.label(f"{other}:{port or '-'}  ·  {n:,}").classes("text-xs soc-mono")
                    if not peers:
                        ui.label("No machine-to-machine traffic recorded.").classes("text-xs")
                with self._card("ALERTS"):
                    for a in sorted(alerts, key=lambda x: str(x.get("time", "")))[-15:]:
                        ui.label(f"{_when(a.get('time'), '%m-%d %H:%M')} · {a.get('rule')} · {_short(a.get('text'), 150)}").classes("text-xs")
                    if not alerts:
                        ui.label("No alerts.").classes("text-xs")
            with self._card("RECENT EVENTS"):
                rows = [{"id": e.get("id"), "time": _when(e.get("time"), "%m-%d %H:%M:%S"), "agent": _text(e.get("agent"), ""),
                         "action": f"{e.get('type')}/{e.get('action')}", "raw": _short(e.get("raw"), 220)} for e in evs[-200:][::-1]]
                ui.table(columns=[{"name": "time", "label": "TIME", "field": "time", "align": "left"},
                                  {"name": "agent", "label": "AGENT", "field": "agent", "align": "left"},
                                  {"name": "action", "label": "ACTION", "field": "action", "align": "left"},
                                  {"name": "raw", "label": "RAW", "field": "raw", "align": "left"}],
                         rows=rows, row_key="id", pagination={"rowsPerPage": 15}).classes("w-full soc-table").props(
                    "flat bordered dense wrap-cells")

    @staticmethod
    def _in_cidr(ip: str, cidr: str | None) -> bool:
        import ipaddress
        try:
            return bool(cidr) and ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
        except ValueError:
            return False

    # =================================================================== AI explanation (unchanged logic)
    def _render_explanation(self, incident: Record) -> None:
        incident_id = str(incident.get("id", "incident"))
        self.explanation_container.clear()
        result_refs = self.qwen_results.get(incident_id)
        error = self.qwen_errors.get(incident_id)
        if result_refs:
            result, evidence_refs = result_refs
            assessment = str(result.get("triage_assessment", "inconclusive"))
            labels = {"likely_suspicious": ("LIKELY SUSPICIOUS · ADVISORY", "#fdecef", COLORS["red"]),
                      "possibly_authorized_or_benign": ("POSSIBLY BENIGN · ADVISORY", "#fff3df", COLORS["amber"]),
                      "inconclusive": ("INCONCLUSIVE · ADVISORY", "#eaf1fc", COLORS["blue"])}
            label, background, foreground = labels.get(assessment, labels["inconclusive"])
            self.ai_assessment.set_text(label)
            self.ai_assessment.style(f"background-color:{background} !important;color:{foreground} !important")
            self.ai_status.set_text("Qwen3 summary ready · the operator decides")
            with self.explanation_container:
                ui.label(_text(result.get("commander_summary_en"), _text(result.get("summary")))).classes(
                    "soc-explanation-text text-sm whitespace-pre-wrap")
                self._explanation_section("UNCERTAINTY", _text(result.get("uncertainty")))
                mitre = result.get("mitre_attack") or []
                if mitre:
                    self._explanation_section("ATT&CK (as explained by the AI)",
                                              " · ".join(f"{m.get('id')} {m.get('name')}" for m in mitre))
                evidence = result.get("evidence", [])
                if evidence:
                    self._explanation_section("SUPPORTING EVIDENCE",
                                              " · ".join(f"{key}: {evidence_refs.get(key, key)}" for key in evidence))
                recommendations = result.get("recommendations", [])
                if recommendations:
                    ui.label("OPERATOR CHECKS").classes("text-xs font-bold").style(f"color:{COLORS['navy']}")
                    for step in recommendations:
                        ui.label(f"• {step}").classes("text-sm")
                ui.label("Advisory only. Detection and priority are determined by SOC rules; no response action is automatic.").classes(
                    "text-xs").style(f"color:{COLORS['muted']}")
            return
        self.ai_assessment.set_text("ADVISORY")
        self.ai_assessment.style(f"background:#eaf1fc;color:{COLORS['blue']}")
        if error:
            self.ai_status.set_text(error)
        elif self._qwen_config_is_verified():
            self.ai_status.set_text("Qwen3 is generating locally (1-2 min on a laptop CPU); the console stays usable.")
        else:
            self.ai_status.set_text(self.qwen_message)
        with self.explanation_container:
            if self._qwen_config_is_verified() and not error:
                ui.spinner("dots", size="lg").style(f"color:{COLORS['blue']}")
                ui.label("Generating the incident explanation… meanwhile the rule-based story is on the 'Story & path' tab.").classes(
                    "text-sm").style(f"color:{COLORS['muted']}")
            else:
                ui.label(instant_overview(incident)).classes("soc-explanation-text text-sm whitespace-pre-wrap")
            if error:
                ui.label(error).classes("text-xs").style(f"color:{COLORS['amber']}")
        # Start automatically only once per incident; after an error wait for "Regenerate explanation".
        if self._qwen_config_is_verified() and not error and incident_id not in self.qwen_in_flight:
            asyncio.create_task(self._generate_explanation(incident))

    def _explanation_section(self, title: str, text: str) -> None:
        ui.label(title).classes("text-xs font-bold").style(f"color:{COLORS['navy']}")
        ui.label(text).classes("soc-explanation-text text-sm whitespace-pre-wrap")

    def _qwen_config_is_verified(self) -> bool:
        current = (str(self.url_input.value or "").strip(), str(self.model_input.value or "").strip())
        return self.qwen_ready and current == self.checked_qwen_config

    def _on_qwen_config_change(self, event: Any) -> None:
        if event is None or self.checked_qwen_config is None:
            return
        current = (str(self.url_input.value or "").strip(), str(self.model_input.value or "").strip())
        if current == self.checked_qwen_config:
            return
        self.qwen_ready = False
        self.qwen_message = "Settings changed. Test Qwen to verify this endpoint and model."
        self.qwen_status.set_text(self.qwen_message)
        self.ai_status.set_text(self.qwen_message)
        self.model_badge.set_text("QWEN3 · TEST NEEDED")
        self.model_badge.style("background:#1b3249;color:#dce8f2")
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
        self.model_badge.set_text("QWEN3 · CHECKING")
        self.model_badge.style("background:#1b3249;color:#dce8f2")
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
            self.qwen_status.set_text(self.qwen_message)
            if self.selected_incident_id and self.snapshot is not None:
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
            result, evidence_refs = await asyncio.to_thread(self._analyze_incident, incident, snapshot, base_url, model)
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
    def _analyze_incident(incident: Record, snapshot: DashboardSnapshot, base_url: str, model: str) -> tuple[Record, dict[str, str]]:
        iid = str(incident.get("id"))
        # the AI sees the knowledge that matters for THIS incident first, then the operator's newest imports
        findings = sorted(snapshot.threat_findings, key=lambda f: (iid not in (f.get("matched_incidents") or []),
                                                                   not str(f.get("id", "")).startswith("KB-")))
        payload, evidence_refs = build_dashboard_incident(incident, findings, snapshot.sources, snapshot.advisories)
        result = analyze_incident(payload, base_url=base_url, model=model, timeout=240, retries=1)
        return result, evidence_refs

    async def regenerate_explanation(self) -> None:
        if not self.selected_incident_id:
            return
        if not self._qwen_config_is_verified():
            await self.test_qwen()
            if not self._qwen_config_is_verified():
                return
        incident = self._selected()
        if incident is None:
            return
        self.qwen_results.pop(self.selected_incident_id, None)
        self.qwen_errors.pop(self.selected_incident_id, None)
        await self._generate_explanation(incident)

    def _source_warning(self, source: Record) -> str:
        gaps = source.get("silent") or []
        if not gaps:
            return "CHECK"
        minutes = [gap.get("minutes") for gap in gaps if isinstance(gap, dict) and gap.get("minutes") is not None]
        return f"SILENT {_format_elapsed_minutes(max(minutes))}" if minutes else "SILENT"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the local Cyber Sentinels NiceGUI SOC console.")
    parser.add_argument("--logs", type=Path, default=DEFAULT_LOGS,
                        help="Folder containing SOC logs and sources.yaml/assets.yaml/maintenance.yaml.")
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
        provider: DashboardProvider = CsvSimulationProvider(csv_path, batch_size=max(1, args.csv_batch),
                                                            interval_seconds=max(1, args.csv_interval))
        refresh_seconds = max(1, args.csv_interval)
    else:
        log_path = args.logs.resolve()
        _ensure_default_fleet_logs(log_path)
        if not log_path.is_dir():
            parser.error(f"SOC log directory not found: {log_path}")
        provider = IntegratedAgentProvider(log_path)
        refresh_seconds = None

    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        log.warning("The dashboard has no authentication. Bind only on a trusted private network and do not port-forward it.")

    @ui.page("/")
    def dashboard() -> None:
        DashboardPage(provider, refresh_seconds)

    ui.run(title="Cyber Sentinels | SOC console", host=args.host, port=args.port, reload=False, show=True)


if __name__ == "__main__":
    main()
