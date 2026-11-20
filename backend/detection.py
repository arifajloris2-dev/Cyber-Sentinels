# Member 2: SOC Detection & Correlation - rregulla deterministe & filtrim zhurme
"""SOC detection: deterministic rules + noise filtering.

Reads a folder of Windows/Ubuntu logs, keeps approved maintenance (patching, backup) aside, and runs the rules in
soc/rules/*.yaml. Returns alerts; nothing here changes any system.

    from detection import detect
    result = detect("soc/sample_logs")
    result["alerts"]       # each alert: rule, title, text, severity, attack (ATT&CK ids), hosts, users, evidence (raw log lines)
    result["suppressed"]   # alerts recognised as approved maintenance, with the ticket
    result["health"]       # per log source: ok, or when it was silent

Command line (from backend/):  python detection.py soc/sample_logs
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # so `soc` is found from any working folder

from soc.pipeline import detect as _detect  # noqa: E402
from soc.report import jsonable  # noqa: E402


def detect(log_folder) -> dict:
    r = _detect(Path(log_folder))
    return jsonable({"alerts": r["alerts"], "suppressed": r["suppressed"], "maintenance": r["maintenance"],
                     "health": r["health"], "events": r["events"], "rules": r["rules"]})


if __name__ == "__main__":
    folder = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parent / "soc" / "sample_logs")
    res = detect(folder)
    print(f"{res['events']:,} events, {res['rules']} rules -> {len(res['alerts'])} alerts, "
          f"{len(res['suppressed'])} suppressed as approved maintenance")
    for a in res["alerts"]:
        print(f"  {a['time'][:16]}  {a['rule']:<8} sev {a['severity']:>2}  {a['text']}")
