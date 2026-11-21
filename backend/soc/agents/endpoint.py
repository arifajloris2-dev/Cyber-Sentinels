"""Endpoint agent: Sysmon (what ran, what it connected to, what it wrote, who touched LSASS)."""
from ..parsers import parse_windows_sysmon
from . import Agent, count, top


def _exe(path) -> str:
    return str(path or "").replace("/", "\\").split("\\")[-1]


def highlights(ev, ctx):
    lines = [f"{count(ev, action='process-start')} processes started, {count(ev, action='connect')} network connections, "
             f"{count(ev, action='file-created')} files written"]
    lsass = [e for e in ev if e.get("action") == "process-access" and "lsass" in str(e.get("target", "")).lower()]
    if lsass:
        lines.append(f"LSASS memory opened {len(lsass)}x (by {', '.join(sorted({_exe(e.get('path')) for e in lsass}))})")
    office = [e for e in ev if e.get("action") == "process-start"
              and str(e.get("parent", "")).lower().endswith(("winword.exe", "excel.exe", "outlook.exe"))]
    if office:
        lines.append(f"{len(office)} programs started by Office documents")
    if (t := top(ev, "detail", action="file-created")) and t[0][1] >= 20:
        lines.append(f"busiest file writer: {_exe(t[0][0])} ({t[0][1]} files)")
    return lines


AGENT = Agent("endpoint", "Endpoint agent (Sysmon)", "Sysmon on Windows: processes, network connections, files, LSASS access",
              {"windows_sysmon": parse_windows_sysmon}, highlights)
