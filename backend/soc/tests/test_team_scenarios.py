"""Team scenarios replayed offline (backend/soc/scenarios): KA-SAT-inspired management-plane attack and the
Kosovo government portal DDoS replay with its healthy-busy control.  Run from backend/: python -m pytest soc/tests -q"""
import json
from pathlib import Path

from soc import agents
from soc.pipeline import run

SC = Path(__file__).resolve().parent.parent / "scenarios"


def test_new_agents_are_registered_without_touching_the_others():
    names = {a.name for a in agents.registry()}
    assert {"management_plane", "service_health"} <= names


def test_ka_sat_chain_is_one_incident_from_sign_in_to_service_loss():
    r = run(SC / "ka_sat")
    assert r["stats"][0]["errors"] == 0 and r["events"] == 3
    assert len(r["incidents"]) == 1
    inc = r["incidents"][0]
    assert {a["rule"] for a in inc["alerts"]} == {"MGMT-001", "MGMT-002"}
    assert {h["host"] for h in inc["hosts"]} == {"demo-management-gateway", "demo-monitor"}
    assert {"entry", "impact"} <= set(inc["stages"])


def test_kosovo_disruption_warns_before_the_failed_check_and_the_busy_period_stays_quiet():
    data = json.loads((SC / "kosovo_ddos" / "portal_health.json").read_text(encoding="utf-8"))
    fail_at = data["evaluation"]["first_simulated_failed_check_offset_seconds"]
    r = run(SC / "kosovo_ddos")
    assert r["stats"][0]["errors"] == 0 and r["events"] == 10
    warnings = [a for a in r["alerts"] if a["rule"] == "SVC-001"]
    assert warnings and all(e.get("scenario") == "simulated-disruption" for a in r["alerts"] for e in a["evidence"])
    first_warning = min(e["offset_s"] for e in warnings[0]["evidence"])
    lead_time = fail_at - first_warning
    assert first_warning == 60 and lead_time == 60          # warning 60 s before the first failed availability check
    assert not [a for a in r["alerts"] for e in a["evidence"] if e.get("scenario") == "healthy-busy-period"]
    assert len(r["incidents"]) == 1
