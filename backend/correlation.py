# Member 2: SOC Detection & Correlation - korrelimi i ngjarjeve & incidenti i strukturuar
"""SOC correlation: joins alerts from all machines into structured incidents.

Alerts that share an account, an unknown address or a host within 60 minutes become one incident, told as a chain
(entry -> lateral movement -> impact), with the evidence (raw log lines), the reason for every link, the MITRE ATT&CK
mapping, a confidence that drops when a log source was silent, and suggested checks. Advice only: it never acts.

    from correlation import analyse
    result = analyse("soc/sample_logs")
    result["incidents"]    # what llm_advisor.py and the dashboard use (fields below)

Each incident: id, priority (P1-P3), score, title, start, end, stages, confidence, confidence_reasons, hosts, users,
unknown_ips, attack (ATT&CK techniques), alerts (with evidence), links, why_together, next_checks,
intel (OSINT findings from Member 1 that match it). Also returned: threat_findings and hunts (each hunt request
from the OSINT agent with its status: which incident covers it, or that the logs show nothing).

Command line (from backend/):  python correlation.py soc/sample_logs      (also writes <folder>/out/report.md)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # so `soc` is found from any working folder

from soc import report  # noqa: E402
from soc.pipeline import run  # noqa: E402


def analyse(log_folder) -> dict:
    r = run(Path(log_folder))
    return report.jsonable({"incidents": r["incidents"], "singles": r["singles"], "suppressed": r["suppressed"],
                            "maintenance": r["maintenance"], "health": r["health"],
                            "threat_findings": r.get("intel", {}).get("findings", []), "hunts": r.get("intel", {}).get("hunts", []),
                            "agents": r.get("agents", []),
                            "summary": {"events": r["events"], "rules": r["rules"], "alerts": len(r["alerts"]),
                                        "incidents": len(r["incidents"]), "seconds": r.get("seconds")}})


def write_report(log_folder, out_folder=None) -> Path:
    """Write report.md + incidents.json, alerts.json, suppressed.json, health.json; returns the output folder."""
    out = Path(out_folder) if out_folder else Path(log_folder) / "out"
    report.write(run(Path(log_folder)), out)
    return out


if __name__ == "__main__":
    folder = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).resolve().parent / "soc" / "sample_logs")
    out = write_report(folder)
    print((out / "report.md").read_text(encoding="utf-8"))
    print(f"Written to {out}")
