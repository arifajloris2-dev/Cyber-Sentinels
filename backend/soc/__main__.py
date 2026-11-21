"""Command line.

Run from the backend/ folder:
  python -m soc sample                 make sample logs (Windows + Ubuntu) in soc/sample_logs
  python -m soc run <folder>           analyse a folder of logs; writes <folder>/out/report.md and JSON files
  python -m soc replay <folder>        feed the logs minute by minute and measure the time to flag each incident
"""
from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from pathlib import Path

from . import report
from .pipeline import load, run

SAMPLE_DIR = Path(__file__).resolve().parent / "sample_logs"


def replay(folder: Path, step_min: int = 1) -> list[dict]:
    """For each incident: how long after its last event the complete incident (all its stages) first appears."""
    loaded = load(folder)
    full = run(folder, loaded=loaded)
    results = []
    for inc in full["incidents"]:
        t = inc["end"] - timedelta(minutes=10)
        while t <= inc["end"] + timedelta(minutes=30):
            r = run(folder, until=t, loaded=loaded)
            # complete = the same incident, now containing every alert up to its last event
            if any(i["start"] == inc["start"] and i["end"] == inc["end"] and len(i["alerts"]) == len(inc["alerts"]) for i in r["incidents"]):
                results.append({"incident": inc["title"], "last_event": inc["end"], "flagged_at": t,
                                "minutes_after_last_event": round((t - inc["end"]).total_seconds() / 60, 1)})
                break
            t += timedelta(minutes=step_min)
    return results


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m soc", description="SOC detection & correlation engine")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("sample", help="make sample logs in soc/sample_logs")
    p = sub.add_parser("run", help="analyse a folder of logs")
    p.add_argument("folder")
    p.add_argument("--out", help="output folder (default: <folder>/out)")
    p = sub.add_parser("replay", help="measure time to flag")
    p.add_argument("folder")
    a = ap.parse_args(argv)

    if a.cmd == "sample":
        from .sample import generate
        generate(SAMPLE_DIR)
        print(f"Sample logs written to {SAMPLE_DIR}. Next:  python -m soc run soc/sample_logs")
    elif a.cmd == "run":
        r = run(Path(a.folder))
        out = Path(a.out) if a.out else Path(a.folder) / "out"
        sys.stdout.write(report.write(r, out))
        print(f"\nWritten: {out / 'report.md'}, incidents.json, alerts.json, suppressed.json, health.json")
    elif a.cmd == "replay":
        for x in replay(Path(a.folder)):
            title = x["incident"].replace("\u2192", "->")
            print(f"{title}: flagged {x['minutes_after_last_event']} min after its last event "
                  f"({x['last_event']:%H:%M:%S} -> {x['flagged_at']:%H:%M:%S} UTC)")


if __name__ == "__main__":
    main()
