"""Write the results: report.md for people, JSON files for other programs (dashboard, response tools)."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


def _j(obj):
    return json.dumps(obj, indent=2, default=lambda o: o.isoformat(timespec="seconds") if isinstance(o, datetime) else str(o))


def jsonable(obj):
    """Plain JSON types only (times as ISO text): ready for an API response or a file."""
    return json.loads(_j(obj))


def write(r: dict, out: Path) -> str:
    out.mkdir(parents=True, exist_ok=True)
    (out / "incidents.json").write_text(_j(r["incidents"]), encoding="utf-8")
    (out / "alerts.json").write_text(_j(r["alerts"]), encoding="utf-8")
    (out / "suppressed.json").write_text(_j({"tickets": r["maintenance"], "alerts": r["suppressed"]}), encoding="utf-8")
    (out / "health.json").write_text(_j({"sources": r["health"], "parsing": [{k: v for k, v in s.items() if k != "times"} for s in r["stats"]]}),
                                     encoding="utf-8")
    md = markdown(r)
    (out / "report.md").write_text(md, encoding="utf-8")
    return md


def markdown(r: dict) -> str:
    L = ["# SOC report", "",
         f"{r['events']:,} events · {r['rules']} rules · {r['seconds']} s · baseline until {r['baseline_end']:%Y-%m-%d %H:%M} UTC",
         "", f"**{len(r['incidents'])} incident(s)** · {len(r['singles'])} single alert(s) not escalated · "
             f"{len(r['suppressed'])} alert(s) suppressed by approved maintenance", ""]
    for i in r["incidents"]:
        L += [f"## {i['priority']} · {i['title']}", "",
              f"`{i['id']}` · {i['start']:%Y-%m-%d %H:%M} → {i['end']:%H:%M} UTC · score {i['score']}", "",
              f"**Confidence {i['confidence']:.0%}**: " + "; ".join(i["confidence_reasons"]), "",
              "**Hosts:** " + ", ".join(f"{h['host']} ({h['role']}, criticality {h['criticality']})" for h in i["hosts"]),
              f"**Accounts:** {', '.join(i['users']) or '-'} · **Unknown addresses:** {', '.join(i['unknown_ips']) or '-'}", "",
              "| Time | Stage | Rule | What happened | Evidence (log:line) |", "|---|---|---|---|---|"]
        for a in i["alerts"]:
            ev = ", ".join(e["id"] for e in a["evidence"][:4]) + (" …" if a["count"] > 4 else "")
            L.append(f"| {a['time']:%H:%M:%S} | {a['stage']} | {a['rule']} | {a['text']} | {ev} |")
        L += ["", "**ATT&CK:** " + " → ".join(f"{t['id']} {t['name']}" for t in i["attack"]), "",
              "**Why these belong together:** " + "; ".join(i["why_together"]), "",
              "**Suggested checks** (advice only: nothing was changed on any system):"]
        L += [f"- *{s['type']}*: {s['step']}" for s in i["next_checks"]] + [""]
    if r["singles"]:
        L += ["## Single alerts (not escalated)", ""] + [f"- {a['time']:%m-%d %H:%M} {a['rule']}: {a['text']}" for a in r["singles"]] + [""]
    L += ["## Approved maintenance recognised", ""]
    L += [f"- **{m['ticket']}** {m['title']}: {m['events']} events on {', '.join(m['hosts'])}, "
          f"{len(m['alerts_suppressed'])} alert(s) suppressed" for m in r["maintenance"]] or ["- none"]
    L += ["", "## Log sources", "", "| Source | Host | Events | Status |", "|---|---|---|---|"]
    for h in r["health"]:
        st = "OK" if h["ok"] else "; ".join(f"SILENT from {g['from'][5:16].replace('T', ' ') if g.get('from') else '?'}"
                                            f" for {g['minutes']} min" if g.get("minutes") else g.get("note", "silent") for g in h["silent"])
        L.append(f"| {h['source']} | {h['host']} | {h['events']:,} | {st} |")
    return "\n".join(L) + "\n"
