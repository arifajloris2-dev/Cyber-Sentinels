"""Local desktop incident dashboard. Run with ``python -m frontend``."""
from __future__ import annotations

import argparse
import sys
import threading
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import ttk
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from frontend.data_provider import DashboardProvider, SocPipelineProvider
from frontend.models import DashboardSnapshot, Record

COLORS = {
    "background": "#f2f5f9",
    "surface": "#ffffff",
    "border": "#dce4ed",
    "ink": "#142235",
    "muted": "#66778b",
    "navy": "#142c44",
    "navy_light": "#203f5b",
    "teal": "#119879",
    "teal_pale": "#e6f5f0",
    "blue": "#3473d1",
    "blue_pale": "#eaf1fc",
    "amber": "#a85d00",
    "amber_pale": "#fff3df",
    "red": "#b9364d",
    "red_pale": "#fdecef",
    "green": "#23774d",
    "green_pale": "#e8f5ed",
}


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


def instant_overview(incident: Record) -> str:
    """Create an immediate, rule-derived overview while the local model is working."""
    hosts = [str(host.get("host", "unknown host")) for host in incident.get("hosts", [])]
    stages = " → ".join(str(stage) for stage in incident.get("stages", [])) or "correlated activity"
    assets = ", ".join(hosts) if hosts else "asset mapping unavailable"
    return (
        f"{incident.get('priority', 'Unranked')} incident: {incident.get('title', 'Correlated activity')}. "
        f"The deterministic SOC engine linked {len(incident.get('alerts', []))} alert(s) across "
        f"{assets}. Observed path: {stages}. "
        "Qwen3 is preparing a separate advisory summary; it will not change this detection."
    )


class DashboardApp:
    def __init__(self, root: tk.Tk, provider: DashboardProvider) -> None:
        self.root = root
        self.provider = provider
        self.snapshot: DashboardSnapshot | None = None
        self.incidents: list[Record] = []
        self._selected_index: int | None = None
        self._snapshot_generation = 0
        self._ai_request: tuple[int, str] | None = None
        self._local_ai_ready = False
        self._local_ai_message = "Checking local Qwen3…"
        self.ai_explanations: dict[str, Record] = {}
        self.ai_errors: dict[str, str] = {}
        self._build()
        self.refresh()
        threading.Thread(target=self._check_local_ai_in_background, daemon=True).start()

    def _build(self) -> None:
        self.root.title("Cyber Sentinels | Incident Operations")
        self.root.geometry("1480x920")
        self.root.minsize(1120, 740)
        self.root.configure(bg=COLORS["background"])
        self._configure_styles()

        shell = tk.Frame(self.root, bg=COLORS["background"])
        shell.pack(fill="both", expand=True, padx=24, pady=20)

        self._build_header(shell)
        self._build_metrics(shell)

        workspace = tk.Frame(shell, bg=COLORS["background"])
        workspace.pack(fill="both", expand=True, pady=(18, 12))
        workspace.columnconfigure(0, weight=4)
        workspace.columnconfigure(1, weight=7)
        workspace.rowconfigure(0, weight=1)

        left = tk.Frame(workspace, bg=COLORS["background"])
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 9))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(0, weight=3)
        left.rowconfigure(1, weight=2)
        self._build_incident_queue(left)
        self._build_sources(left)

        right = tk.Frame(workspace, bg=COLORS["background"])
        right.grid(row=0, column=1, sticky="nsew", padx=(9, 0))
        right.columnconfigure(0, weight=1)
        right.rowconfigure(3, weight=1)
        self._build_incident_overview(right)
        self._build_attack_path(right)
        self._build_ai_summary(right)
        self._build_timeline(right)

        self.agent_status_var = tk.StringVar(value="OSINT pending   ·   Member 3 pending")
        self.status_var = tk.StringVar(value="Starting local dashboard…")
        footer = tk.Frame(shell, bg=COLORS["background"])
        footer.pack(fill="x")
        tk.Label(
            footer,
            textvariable=self.agent_status_var,
            bg=COLORS["background"],
            fg=COLORS["muted"],
            anchor="w",
            font=("Segoe UI", 9),
        ).pack(side="left", fill="x", expand=True)
        tk.Label(
            footer,
            textvariable=self.status_var,
            bg=COLORS["background"],
            fg=COLORS["muted"],
            anchor="e",
            font=("Segoe UI", 9),
        ).pack(side="right")

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=COLORS["surface"],
            fieldbackground=COLORS["surface"],
            foreground=COLORS["ink"],
            borderwidth=0,
            rowheight=34,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Treeview.Heading",
            background="#f5f7fa",
            foreground=COLORS["muted"],
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        style.map(
            "Treeview",
            background=[("selected", COLORS["blue_pale"])],
            foreground=[("selected", COLORS["ink"])],
        )
        style.configure(
            "Vertical.TScrollbar",
            background="#e6ebf1",
            troughcolor=COLORS["surface"],
            bordercolor=COLORS["surface"],
            arrowcolor=COLORS["muted"],
        )

    def _card(self, parent: tk.Widget, title: str) -> tuple[tk.Frame, tk.Frame]:
        card = tk.Frame(
            parent,
            bg=COLORS["surface"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        card.columnconfigure(0, weight=1)
        card.rowconfigure(1, weight=1)
        tk.Label(
            card,
            text=title,
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            anchor="w",
            font=("Segoe UI", 9, "bold"),
        ).grid(row=0, column=0, sticky="ew", padx=15, pady=(12, 8))
        body = tk.Frame(card, bg=COLORS["surface"])
        body.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
        return card, body

    def _build_header(self, parent: tk.Widget) -> None:
        header = tk.Frame(parent, bg=COLORS["navy"], padx=20, pady=16)
        header.pack(fill="x")
        brand = tk.Frame(header, bg=COLORS["navy"])
        brand.pack(side="left")
        tk.Label(
            brand,
            text="CS",
            bg=COLORS["teal"],
            fg=COLORS["surface"],
            width=3,
            height=2,
            font=("Segoe UI", 13, "bold"),
        ).pack(side="left", padx=(0, 13))
        title_block = tk.Frame(brand, bg=COLORS["navy"])
        title_block.pack(side="left")
        tk.Label(
            title_block,
            text="CYBER SENTINELS",
            bg=COLORS["navy"],
            fg=COLORS["surface"],
            font=("Segoe UI", 17, "bold"),
        ).pack(anchor="w")
        tk.Label(
            title_block,
            text="DEFENSIVE OPERATIONS  /  LOCAL SOC",
            bg=COLORS["navy"],
            fg="#bdcbd9",
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(3, 0))

        controls = tk.Frame(header, bg=COLORS["navy"])
        controls.pack(side="right")
        self.model_status_var = tk.StringVar(value="QWEN3 · CHECKING")
        self.model_status_label = tk.Label(
            controls,
            textvariable=self.model_status_var,
            bg=COLORS["navy_light"],
            fg="#dce8f2",
            padx=12,
            pady=8,
            font=("Segoe UI", 9, "bold"),
        )
        self.model_status_label.pack(side="left", padx=(0, 12))
        self.refresh_button = tk.Button(
            controls,
            text="Refresh",
            command=self.refresh,
            bg=COLORS["surface"],
            fg=COLORS["navy"],
            activebackground="#e7eef5",
            activeforeground=COLORS["navy"],
            relief="flat",
            padx=17,
            pady=9,
            font=("Segoe UI", 10, "bold"),
            cursor="hand2",
        )
        self.refresh_button.pack(side="left")

    def _build_metrics(self, parent: tk.Widget) -> None:
        row = tk.Frame(parent, bg=COLORS["background"])
        row.pack(fill="x", pady=(14, 0))
        self.metric_values: dict[str, tk.StringVar] = {}
        metrics = (
            ("OPEN INCIDENTS", "incidents", COLORS["blue"]),
            ("PRIORITY 1", "p1", COLORS["red"]),
            ("DETECTION ALERTS", "alerts", COLORS["amber"]),
            ("HEALTHY SOURCES", "sources", COLORS["teal"]),
        )
        for index, (label, key, accent) in enumerate(metrics):
            row.columnconfigure(index, weight=1, uniform="metric")
            card = tk.Frame(
                row,
                bg=COLORS["surface"],
                highlightbackground=COLORS["border"],
                highlightthickness=1,
            )
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 9, 0))
            tk.Frame(card, bg=accent, height=3).pack(fill="x")
            content = tk.Frame(card, bg=COLORS["surface"], padx=15, pady=9)
            content.pack(fill="both", expand=True)
            tk.Label(
                content,
                text=label,
                bg=COLORS["surface"],
                fg=COLORS["muted"],
                font=("Segoe UI", 8, "bold"),
            ).pack(anchor="w")
            value = tk.StringVar(value="—")
            self.metric_values[key] = value
            tk.Label(
                content,
                textvariable=value,
                bg=COLORS["surface"],
                fg=COLORS["ink"],
                font=("Segoe UI", 21, "bold"),
            ).pack(anchor="w", pady=(2, 0))

    def _build_incident_queue(self, parent: tk.Widget) -> None:
        card, body = self._card(parent, "PRIORITY QUEUE")
        card.grid(row=0, column=0, sticky="nsew", pady=(0, 9))
        body.rowconfigure(1, weight=1)
        body.columnconfigure(0, weight=1)
        tk.Label(
            body,
            text="Select an incident for its summary and evidence chain.",
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            anchor="w",
            font=("Segoe UI", 9),
        ).grid(row=0, column=0, sticky="ew", pady=(0, 7))
        self.incident_tree = ttk.Treeview(
            body,
            columns=("priority", "score", "incident"),
            show="headings",
            selectmode="browse",
        )
        for key, label, width, stretch in (
            ("priority", "LEVEL", 66, False),
            ("score", "SCORE", 60, False),
            ("incident", "INCIDENT", 210, True),
        ):
            self.incident_tree.heading(key, text=label)
            self.incident_tree.column(key, width=width, stretch=stretch)
        self.incident_tree.grid(row=1, column=0, sticky="nsew")
        self.incident_tree.bind("<<TreeviewSelect>>", self._on_incident_select)
        self.incident_tree.tag_configure("P1", foreground=COLORS["red"])
        self.incident_tree.tag_configure("P2", foreground=COLORS["amber"])
        self.incident_tree.tag_configure("P3", foreground=COLORS["blue"])

    def _build_sources(self, parent: tk.Widget) -> None:
        card, body = self._card(parent, "LOG SOURCE HEALTH")
        card.grid(row=1, column=0, sticky="nsew", pady=(9, 0))
        body.columnconfigure(0, weight=1)
        self.source_tree = ttk.Treeview(
            body,
            columns=("source", "host", "status"),
            show="headings",
            height=4,
        )
        for key, label, width in (
            ("source", "SOURCE", 155),
            ("host", "HOST", 100),
            ("status", "HEALTH", 100),
        ):
            self.source_tree.heading(key, text=label)
            self.source_tree.column(key, width=width, stretch=(key == "source"))
        self.source_tree.grid(row=0, column=0, sticky="nsew")
        self.source_tree.tag_configure("healthy", foreground=COLORS["green"])
        self.source_tree.tag_configure("warning", foreground=COLORS["amber"])

    def _build_incident_overview(self, parent: tk.Widget) -> None:
        card, body = self._card(parent, "SELECTED INCIDENT")
        card.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        body.columnconfigure(0, weight=1)
        header = tk.Frame(body, bg=COLORS["surface"])
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)
        self.incident_title = tk.Label(
            header,
            text="Select an incident",
            bg=COLORS["surface"],
            fg=COLORS["ink"],
            anchor="w",
            justify="left",
            wraplength=800,
            font=("Segoe UI", 16, "bold"),
        )
        self.incident_title.grid(row=0, column=0, sticky="ew")
        self.priority_badge = tk.Label(
            header,
            text="—",
            bg=COLORS["blue_pale"],
            fg=COLORS["blue"],
            padx=11,
            pady=6,
            font=("Segoe UI", 9, "bold"),
        )
        self.priority_badge.grid(row=0, column=1, sticky="e", padx=(12, 0))
        self.incident_meta_var = tk.StringVar(value="Waiting for SOC results")
        tk.Label(
            body,
            textvariable=self.incident_meta_var,
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            anchor="w",
            font=("Segoe UI", 9),
        ).grid(row=1, column=0, sticky="ew", pady=(7, 0))
        self.instant_overview_var = tk.StringVar(value="The dashboard is loading local incident data.")
        tk.Label(
            body,
            textvariable=self.instant_overview_var,
            bg=COLORS["surface"],
            fg=COLORS["ink"],
            anchor="w",
            justify="left",
            wraplength=980,
            font=("Segoe UI", 10),
        ).grid(row=2, column=0, sticky="ew", pady=(9, 0))

    def _build_attack_path(self, parent: tk.Widget) -> None:
        card, body = self._card(parent, "CORRELATED ATTACK PATH")
        card.grid(row=1, column=0, sticky="ew", pady=8)
        self.attack_path = tk.Frame(body, bg=COLORS["surface"])
        self.attack_path.pack(fill="x")

    def _build_ai_summary(self, parent: tk.Widget) -> None:
        card, body = self._card(parent, "QWEN3 AI SUMMARY · ADVISORY ONLY")
        card.grid(row=2, column=0, sticky="ew", pady=8)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(1, weight=1)
        bar = tk.Frame(body, bg=COLORS["surface"])
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        bar.columnconfigure(0, weight=1)
        self.ai_assessment_label = tk.Label(
            bar,
            text="WAITING",
            bg=COLORS["blue_pale"],
            fg=COLORS["blue"],
            padx=10,
            pady=5,
            font=("Segoe UI", 8, "bold"),
        )
        self.ai_assessment_label.grid(row=0, column=0, sticky="w")
        self.ai_status_var = tk.StringVar(value="Qwen3 will summarize the selected incident automatically.")
        tk.Label(
            bar,
            textvariable=self.ai_status_var,
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            anchor="e",
            font=("Segoe UI", 9),
        ).grid(row=0, column=1, sticky="e", padx=(8, 10))
        self.regenerate_button = tk.Button(
            bar,
            text="Regenerate",
            command=self._regenerate_summary,
            bg="#f1f5f9",
            fg=COLORS["ink"],
            activebackground="#e2e8f0",
            activeforeground=COLORS["ink"],
            relief="flat",
            padx=10,
            pady=5,
            font=("Segoe UI", 8, "bold"),
            cursor="hand2",
        )
        self.regenerate_button.grid(row=0, column=2, sticky="e")
        self.ai_summary_text = tk.Text(
            body,
            height=7,
            bg=COLORS["surface"],
            fg=COLORS["ink"],
            relief="flat",
            wrap="word",
            padx=0,
            pady=0,
            font=("Segoe UI", 10),
            state="disabled",
            spacing1=2,
            spacing3=3,
        )
        self.ai_summary_text.grid(row=1, column=0, sticky="nsew")
        summary_scrollbar = ttk.Scrollbar(body, orient="vertical", command=self.ai_summary_text.yview)
        summary_scrollbar.grid(row=1, column=1, sticky="ns")
        self.ai_summary_text.configure(yscrollcommand=summary_scrollbar.set)
        self.ai_summary_text.tag_configure("section", foreground=COLORS["navy"], font=("Segoe UI", 9, "bold"))
        self.ai_summary_text.tag_configure("muted", foreground=COLORS["muted"])
        self.ai_summary_text.tag_configure("assessment", foreground=COLORS["teal"], font=("Segoe UI", 10, "bold"))
        self.ai_summary_text.tag_configure("warning", foreground=COLORS["amber"], font=("Segoe UI", 10, "bold"))

    def _build_timeline(self, parent: tk.Widget) -> None:
        card, body = self._card(parent, "INCIDENT TIMELINE")
        card.grid(row=3, column=0, sticky="nsew", pady=(8, 0))
        body.rowconfigure(1, weight=1)
        body.columnconfigure(0, weight=1)
        header = tk.Frame(body, bg=COLORS["surface"])
        header.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        header.columnconfigure(0, weight=1)
        tk.Label(
            header,
            text="Concise alert summaries; original log lines are hidden.",
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            anchor="w",
            font=("Segoe UI", 9),
        ).grid(row=0, column=0, sticky="ew")
        self.raw_evidence_button = tk.Button(
            header,
            text="View source logs",
            command=self._show_source_logs,
            bg="#f1f5f9",
            fg=COLORS["ink"],
            activebackground="#e2e8f0",
            activeforeground=COLORS["ink"],
            relief="flat",
            padx=10,
            pady=5,
            font=("Segoe UI", 8, "bold"),
            cursor="hand2",
            state="disabled",
        )
        self.raw_evidence_button.grid(row=0, column=1, sticky="e", padx=(8, 0))
        self.timeline_tree = ttk.Treeview(
            body,
            columns=("time", "stage", "rule", "summary"),
            show="headings",
            height=5,
        )
        for key, label, width, stretch in (
            ("time", "TIME (UTC)", 100, False),
            ("stage", "STAGE", 120, False),
            ("rule", "RULE", 86, False),
            ("summary", "DETECTION SUMMARY", 360, True),
        ):
            self.timeline_tree.heading(key, text=label)
            self.timeline_tree.column(key, width=width, stretch=stretch)
        self.timeline_tree.grid(row=1, column=0, sticky="nsew")
        self.timeline_tree.tag_configure("odd", background="#f8fafc")

    def refresh(self) -> None:
        self.refresh_button.configure(state="disabled")
        self.status_var.set("Loading deterministic SOC results…")
        threading.Thread(target=self._load_in_background, daemon=True).start()

    def _load_in_background(self) -> None:
        try:
            snapshot = self.provider.load()
        except (OSError, ValueError, RuntimeError) as exc:
            self.root.after(0, self._show_load_error, str(exc))
            return
        self.root.after(0, self._render, snapshot)

    def _show_load_error(self, error: str) -> None:
        self.refresh_button.configure(state="normal")
        self.status_var.set(f"SOC refresh failed: {error}")

    def _render(self, snapshot: DashboardSnapshot) -> None:
        self._snapshot_generation += 1
        self.snapshot = snapshot
        self.ai_explanations.clear()
        self.ai_errors.clear()
        self.incidents = sorted(
            snapshot.incidents,
            key=lambda item: (-int(item.get("score", 0)), str(item.get("id", ""))),
        )
        p1_count = sum(1 for incident in self.incidents if incident.get("priority") == "P1")
        healthy = sum(1 for source in snapshot.sources if source.get("ok"))
        self.metric_values["incidents"].set(str(len(self.incidents)))
        self.metric_values["p1"].set(str(p1_count))
        self.metric_values["alerts"].set(str(len(snapshot.alerts)))
        self.metric_values["sources"].set(f"{healthy}/{len(snapshot.sources)}")

        self.incident_tree.delete(*self.incident_tree.get_children())
        for index, incident in enumerate(self.incidents):
            priority = str(incident.get("priority", "—"))
            self.incident_tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    priority,
                    _text(incident.get("score")),
                    _text(incident.get("title"), str(incident.get("id", "Incident"))),
                ),
                tags=(priority, "odd" if index % 2 else "even"),
            )

        self.source_tree.delete(*self.source_tree.get_children())
        for source in snapshot.sources:
            ok = bool(source.get("ok"))
            self.source_tree.insert(
                "",
                "end",
                values=(
                    _text(source.get("source")),
                    _text(source.get("host")),
                    "HEALTHY" if ok else self._source_warning(source),
                ),
                tags=("healthy" if ok else "warning",),
            )
        self._render_agent_status(snapshot)

        if self.incidents:
            self.incident_tree.selection_set("0")
            self.incident_tree.focus("0")
            self._show_incident(0)
        else:
            self._selected_index = None
            self.incident_title.configure(text="No correlated incidents")
            self.priority_badge.configure(text="CLEAR", bg=COLORS["green_pale"], fg=COLORS["green"])
            self.incident_meta_var.set("No incident met the deterministic correlation criteria.")
            self.instant_overview_var.set("No correlated incidents were returned. Detection and maintenance results remain available.")
            for child in self.attack_path.winfo_children():
                child.destroy()
            self.ai_assessment_label.configure(text="NO INCIDENT", bg=COLORS["blue_pale"], fg=COLORS["blue"])
            self.ai_status_var.set("The AI does not classify an empty incident list.")
            self._write_ai_text("No incident selected. Qwen3 will not invent an incident or classify single alerts.")
            self.timeline_tree.delete(*self.timeline_tree.get_children())
            self.raw_evidence_button.configure(state="disabled")

        self.refresh_button.configure(state="normal")
        self.status_var.set(
            f"Updated {_when(snapshot.generated_at)} · {len(snapshot.singles)} single alert(s) · "
            f"{len(snapshot.maintenance)} approved maintenance record(s) · rules decide detection"
        )

    def _source_warning(self, source: Record) -> str:
        gaps = source.get("silent") or []
        if not gaps:
            return "CHECK"
        minutes = [
            gap.get("minutes")
            for gap in gaps
            if isinstance(gap, dict) and gap.get("minutes") is not None
        ]
        return f"SILENT {max(minutes)}m" if minutes else "SILENT"

    def _render_agent_status(self, snapshot: DashboardSnapshot) -> None:
        osint = f"OSINT {len(snapshot.threat_findings)} finding(s)" if snapshot.threat_findings else "OSINT pending"
        briefings = f"Briefings {len(snapshot.advisories)}" if snapshot.advisories else "Member 3 pending"
        self.agent_status_var.set(f"{osint}   ·   {briefings}   ·   VMware logs via selected source folder")

    def _show_incident(self, index: int) -> None:
        if not 0 <= index < len(self.incidents):
            return
        self._selected_index = index
        incident = self.incidents[index]
        incident_id = str(incident.get("id", "incident"))
        priority = str(incident.get("priority", "—"))
        self.incident_title.configure(text=_text(incident.get("title"), incident_id))
        priority_colors = {
            "P1": (COLORS["red_pale"], COLORS["red"]),
            "P2": (COLORS["amber_pale"], COLORS["amber"]),
            "P3": (COLORS["blue_pale"], COLORS["blue"]),
        }
        bg, fg = priority_colors.get(priority, (COLORS["blue_pale"], COLORS["blue"]))
        self.priority_badge.configure(text=f"{priority}  ·  SCORE {incident.get('score', '—')}", bg=bg, fg=fg)
        confidence = incident.get("confidence")
        confidence_text = f"{confidence:.0%}" if isinstance(confidence, (int, float)) else _text(confidence)
        self.incident_meta_var.set(
            f"{incident_id}   ·   {_when(incident.get('start'))} – {_when(incident.get('end'), '%H:%M UTC')}   ·   "
            f"confidence {confidence_text}"
        )
        self.instant_overview_var.set(instant_overview(incident))
        self._render_attack_path(incident)
        self._render_timeline(incident)
        self.raw_evidence_button.configure(state="normal")
        self._render_ai_summary(incident)

    def _render_attack_path(self, incident: Record) -> None:
        for child in self.attack_path.winfo_children():
            child.destroy()
        stages = incident.get("stages", [])
        if not stages:
            tk.Label(
                self.attack_path,
                text="No attack stages mapped",
                bg=COLORS["surface"],
                fg=COLORS["muted"],
                font=("Segoe UI", 9),
            ).pack(anchor="w")
            return
        for index, stage in enumerate(stages):
            chip = tk.Label(
                self.attack_path,
                text=str(stage).upper(),
                bg=COLORS["blue_pale"] if index == 0 else COLORS["teal_pale"],
                fg=COLORS["blue"] if index == 0 else COLORS["teal"],
                padx=10,
                pady=6,
                font=("Segoe UI", 8, "bold"),
            )
            chip.pack(side="left", padx=(0, 8))
            if index < len(stages) - 1:
                tk.Label(
                    self.attack_path,
                    text="›",
                    bg=COLORS["surface"],
                    fg=COLORS["muted"],
                    font=("Segoe UI", 14, "bold"),
                ).pack(side="left", padx=(0, 8))
        techniques = incident.get("attack", [])
        if techniques:
            text = "  ·  ".join(str(item.get("id", "")) for item in techniques[:6])
            tk.Label(
                self.attack_path,
                text=f"ATT&CK  {text}",
                bg=COLORS["surface"],
                fg=COLORS["muted"],
                font=("Segoe UI", 9),
            ).pack(side="left", padx=(10, 0))

    def _render_timeline(self, incident: Record) -> None:
        self.timeline_tree.delete(*self.timeline_tree.get_children())
        for index, alert in enumerate(sorted(incident.get("alerts", []), key=lambda item: str(item.get("time", "")))):
            evidence = alert.get("evidence") or []
            summary = _text(alert.get("text"), _text(alert.get("rule")))
            if len(summary) > 160:
                summary = summary[:157] + "..."
            self.timeline_tree.insert(
                "",
                "end",
                values=(
                    _when(alert.get("time"), "%H:%M:%S"),
                    _text(alert.get("stage"), "alert"),
                    _text(alert.get("rule")),
                    f"{summary}  ·  {len(evidence)} evidence line(s)",
                ),
                tags=("odd",) if index % 2 else (),
            )

    def _render_ai_summary(self, incident: Record) -> None:
        incident_id = str(incident.get("id", "incident"))
        result = self.ai_explanations.get(incident_id)
        if result:
            self._show_ai_result(result)
            return
        error = self.ai_errors.get(incident_id)
        if error:
            self.ai_assessment_label.configure(
                text="AI UNAVAILABLE",
                bg=COLORS["amber_pale"],
                fg=COLORS["amber"],
            )
            self.ai_status_var.set(error)
            self._write_ai_text(instant_overview(incident), tag="warning")
            return

        self.ai_assessment_label.configure(
            text="ANALYZING" if self._local_ai_ready else "WAITING",
            bg=COLORS["blue_pale"],
            fg=COLORS["blue"],
        )
        if self._local_ai_ready:
            self.ai_status_var.set("Qwen3 is creating a short advisory summary in the background.")
        else:
            self.ai_status_var.set(self._local_ai_message)
        self._write_ai_text(instant_overview(incident), tag="muted")
        if self._local_ai_ready:
            self._start_ai_summary(incident)

    def _write_ai_text(self, text: str, tag: str = "") -> None:
        self.ai_summary_text.configure(state="normal")
        self.ai_summary_text.delete("1.0", "end")
        self.ai_summary_text.insert("1.0", text, tag)
        self.ai_summary_text.configure(state="disabled")

    def _start_ai_summary(self, incident: Record, force: bool = False) -> None:
        if self.snapshot is None or not self._local_ai_ready:
            return
        incident_id = str(incident.get("id", "incident"))
        if incident_id in self.ai_explanations and not force:
            return
        if self._ai_request is not None:
            self.ai_status_var.set("Qwen3 is finishing the current summary; this incident will follow.")
            return
        self.ai_errors.pop(incident_id, None)
        request = (self._snapshot_generation, incident_id)
        self._ai_request = request
        self.ai_assessment_label.configure(
            text="ANALYZING",
            bg=COLORS["blue_pale"],
            fg=COLORS["blue"],
        )
        self.ai_status_var.set("Qwen3 is creating a short local summary…")
        self._write_ai_text(instant_overview(incident), tag="muted")
        threading.Thread(
            target=self._ai_summary_in_background,
            args=(request, self.snapshot, incident),
            daemon=True,
        ).start()

    def _ai_summary_in_background(
        self,
        request: tuple[int, str],
        snapshot: DashboardSnapshot,
        incident: Record,
    ) -> None:
        try:
            from AI_Log_Analyzer.ai_log_analyzer import (
                AnalysisError,
                DEFAULT_MODEL,
                DEFAULT_URL,
                OllamaError,
                analyze_incident,
                build_dashboard_incident,
            )

            payload, evidence_refs = build_dashboard_incident(
                incident,
                snapshot.threat_findings,
                snapshot.sources,
                snapshot.advisories,
            )
            result = analyze_incident(
                payload,
                base_url=DEFAULT_URL,
                model=DEFAULT_MODEL,
                timeout=240,
                retries=0,
            )
        except ImportError as exc:
            self.root.after(0, self._ai_summary_failed, request, f"AI dependencies missing: {exc}")
            return
        except (ValueError, OllamaError, AnalysisError) as exc:
            self.root.after(0, self._ai_summary_failed, request, str(exc))
            return
        self.root.after(0, self._ai_summary_ready, request, incident, result, evidence_refs)

    def _ai_summary_failed(self, request: tuple[int, str], error: str) -> None:
        if self._ai_request == request:
            self._ai_request = None
        generation, incident_id = request
        if generation != self._snapshot_generation:
            self._start_selected_summary()
            return
        clean_error = error.splitlines()[0][:180]
        self.ai_errors[incident_id] = f"Qwen3 unavailable: {clean_error}"
        if self._selected_index is not None:
            selected = self.incidents[self._selected_index]
            if str(selected.get("id", "incident")) == incident_id:
                self._render_ai_summary(selected)
            else:
                self._start_selected_summary()

    def _ai_summary_ready(
        self,
        request: tuple[int, str],
        incident: Record,
        result: Record,
        evidence_refs: dict[str, str],
    ) -> None:
        if self._ai_request == request:
            self._ai_request = None
        generation, incident_id = request
        if generation != self._snapshot_generation:
            self._start_selected_summary()
            return
        self.ai_explanations[incident_id] = {**result, "evidence_refs": evidence_refs}
        if self._selected_index is not None:
            selected = self.incidents[self._selected_index]
            if str(selected.get("id", "incident")) == incident_id:
                self._show_ai_result(self.ai_explanations[incident_id])
            else:
                self._start_selected_summary()

    def _start_selected_summary(self) -> None:
        if self._selected_index is not None:
            self._render_ai_summary(self.incidents[self._selected_index])

    def _show_ai_result(self, result: Record) -> None:
        assessment = result.get("triage_assessment", "inconclusive")
        label_data = {
            "likely_suspicious": ("LIKELY SUSPICIOUS · ADVISORY", COLORS["red_pale"], COLORS["red"]),
            "possibly_authorized_or_benign": ("POSSIBLY BENIGN · ADVISORY", COLORS["amber_pale"], COLORS["amber"]),
            "inconclusive": ("INCONCLUSIVE · ADVISORY", COLORS["blue_pale"], COLORS["blue"]),
        }
        label, background, foreground = label_data.get(
            assessment,
            ("INCONCLUSIVE · ADVISORY", COLORS["blue_pale"], COLORS["blue"]),
        )
        self.ai_assessment_label.configure(text=label, bg=background, fg=foreground)
        self.ai_status_var.set("Qwen3 summary ready · the operator decides")
        lines: list[tuple[str, str]] = [
            (_text(result.get("commander_summary_en"), _text(result.get("summary"), "No summary was returned.")), "normal"),
            ("", "normal"),
            ("UNCERTAINTY", "section"),
            (_text(result.get("uncertainty"), "No uncertainty statement was returned."), "muted"),
        ]
        evidence = result.get("evidence", [])
        references = result.get("evidence_refs", {})
        if evidence:
            lines.extend(
                [
                    ("", "normal"),
                    ("SUPPORTING EVIDENCE GROUPS", "section"),
                    ("  ·  ".join(f"{key}: {references.get(key, key)}" for key in evidence), "muted"),
                ]
            )
        recommendations = result.get("recommendations", [])
        if recommendations:
            lines.extend([("", "normal"), ("OPERATOR CHECKS", "section")])
            lines.extend((f"• {step}", "normal") for step in recommendations)
        lines.extend(
            [
                ("", "normal"),
                ("Advisory only. This does not change deterministic detection or incident priority.", "muted"),
            ]
        )
        self.ai_summary_text.configure(state="normal")
        self.ai_summary_text.delete("1.0", "end")
        for text, tag in lines:
            self.ai_summary_text.insert("end", text + "\n", tag)
        self.ai_summary_text.configure(state="disabled")

    def _on_incident_select(self, _event: tk.Event) -> None:
        selection = self.incident_tree.selection()
        if selection:
            self._show_incident(int(selection[0]))

    def _check_local_ai_in_background(self) -> None:
        try:
            from AI_Log_Analyzer.ai_log_analyzer import (
                DEFAULT_MODEL,
                DEFAULT_URL,
                OllamaError,
                check_ollama_model,
            )

            check_ollama_model(DEFAULT_URL, DEFAULT_MODEL)
        except ImportError as exc:
            self.root.after(0, self._set_local_ai_status, f"Dependencies missing: {exc}", False)
        except OllamaError as exc:
            self.root.after(0, self._set_local_ai_status, str(exc), False)
        else:
            self.root.after(0, self._set_local_ai_status, f"{DEFAULT_MODEL} ready · local", True)

    def _set_local_ai_status(self, message: str, ready: bool) -> None:
        self._local_ai_ready = ready
        self._local_ai_message = message
        self.model_status_var.set(
            f"QWEN3 · READY" if ready else "QWEN3 · UNAVAILABLE"
        )
        self.model_status_label.configure(
            bg=COLORS["teal"] if ready else "#8a5a18",
            fg=COLORS["surface"],
        )
        self.ai_status_var.set(message)
        if ready:
            self._start_selected_summary()
        elif self._selected_index is not None:
            self._render_ai_summary(self.incidents[self._selected_index])

    def _regenerate_summary(self) -> None:
        if self._selected_index is None:
            return
        if not self._local_ai_ready:
            self.ai_status_var.set("Checking local Qwen3 availability…")
            threading.Thread(target=self._check_local_ai_in_background, daemon=True).start()
            return
        self._start_ai_summary(self.incidents[self._selected_index], force=True)

    def _show_source_logs(self) -> None:
        if self._selected_index is None:
            return
        incident = self.incidents[self._selected_index]
        window = tk.Toplevel(self.root)
        window.title(f"Source evidence · {incident.get('id', 'incident')}")
        window.geometry("980x620")
        window.minsize(720, 440)
        window.configure(bg=COLORS["background"])
        tk.Label(
            window,
            text="RAW SOURCE EVIDENCE",
            bg=COLORS["background"],
            fg=COLORS["ink"],
            anchor="w",
            font=("Segoe UI", 12, "bold"),
        ).pack(fill="x", padx=18, pady=(16, 5))
        tk.Label(
            window,
            text="Read-only logs for operator verification. No response actions are available here.",
            bg=COLORS["background"],
            fg=COLORS["muted"],
            anchor="w",
            font=("Segoe UI", 9),
        ).pack(fill="x", padx=18, pady=(0, 10))
        output = tk.Text(
            window,
            bg=COLORS["surface"],
            fg=COLORS["ink"],
            relief="flat",
            wrap="word",
            padx=14,
            pady=12,
            font=("Consolas", 9),
            state="normal",
        )
        output.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        for alert in sorted(incident.get("alerts", []), key=lambda item: str(item.get("time", ""))):
            output.insert(
                "end",
                f"{_when(alert.get('time'))}  {alert.get('rule', 'rule')}  {alert.get('text', '')}\n",
            )
            for item in alert.get("evidence", []):
                output.insert(
                    "end",
                    f"  {item.get('source', 'source')}:{item.get('line', '?')}  "
                    f"{item.get('raw', item.get('id', ''))}\n",
                )
            output.insert("end", "\n")
        output.configure(state="disabled")


def _enable_windows_dpi_awareness() -> None:
    if sys.platform != "win32":
        return
    import ctypes

    user32 = ctypes.windll.user32
    try:
        if user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
            return
    except AttributeError:
        pass
    try:
        if ctypes.windll.shcore.SetProcessDpiAwareness(2) == 0:
            return
    except AttributeError:
        pass
    user32.SetProcessDPIAware()


def main() -> None:
    _enable_windows_dpi_awareness()
    parser = argparse.ArgumentParser(description="Run the local Cyber Sentinels desktop dashboard.")
    parser.add_argument(
        "--logs",
        type=Path,
        default=ROOT / "backend" / "soc" / "sample_logs",
        help="Folder containing SOC logs and sources.yaml/assets.yaml/maintenance.yaml.",
    )
    args = parser.parse_args()
    root = tk.Tk()
    DashboardApp(root, SocPipelineProvider(args.logs.resolve()))
    root.mainloop()


if __name__ == "__main__":
    main()
