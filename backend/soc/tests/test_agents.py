"""Per-source agents: every log format has an owner, each agent reports what it saw.  Run from backend/: python -m pytest soc/tests -q"""
from pathlib import Path

from soc import agents
from soc.parsers import PARSERS
from soc.pipeline import run

SOC = Path(__file__).resolve().parent.parent


def test_every_log_format_belongs_to_exactly_one_agent():
    owners = {}
    for a in agents.registry():
        for p in a.parsers:
            assert p not in owners, f"{p} owned by {owners.get(p)} and {a.name}"
            owners[p] = a.name
    assert set(PARSERS) <= set(owners)
    assert {a.name for a in agents.registry()} >= {"windows_host", "endpoint", "linux_host", "host_firewall", "perimeter",
                                                   "network_sensor", "mail"}


def test_agents_report_on_the_sample_logs():
    r = run(SOC / "sample_logs")
    by = {a["agent"]: a for a in r["agents"]}
    assert {"windows_host", "host_firewall", "linux_host"} <= set(by)
    for a in by.values():
        assert a["events"] > 0 and a["normal"]["per_hour"] >= 0 and isinstance(a["highlights"], list)
    assert sum(a["alerts"] for a in by.values()) >= len(r["alerts"])          # every alert is attributed to an agent
    assert any(a["incidents"] for a in by.values())                           # and agents point to the incidents they fed


def test_lab_mail_agent_sees_the_click():
    r = run(SOC / "lab_logs")
    mail = next(a for a in r["agents"] if a["agent"] == "mail")
    assert mail["alerts"] == 1 and any("click" in h for h in mail["highlights"])
    win = next(a for a in r["agents"] if a["agent"] == "windows_host")
    assert win["maintenance_filtered"] > 0                                    # the VM setup was set aside, not alerted
