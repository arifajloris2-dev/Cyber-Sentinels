"""End-to-end test on the 50-device synthetic base (backend/soc/fleet/make_fleet.py), against its truth.json.

The generator builds 2 days of logs (Windows events/firewall/Sysmon, Ubuntu auth/ufw/syslog/dpkg, Zeek, mail gateway)
with 4 planted attacks, 4 harmless look-alikes, approved maintenance and one log source that goes silent.
Run from backend/:  python -m pytest soc/tests -q
"""
import subprocess
import sys
import json
from pathlib import Path

import pytest

from soc.pipeline import run

REPO = Path(__file__).resolve().parents[3]
GENERATOR = REPO / "backend" / "soc" / "fleet" / "make_fleet.py"
MAINTENANCE = ["patch", "backup", "change", "vulnscan", "emergency", "psexec-change"]
ATTACKS = ["A1", "A2", "A3", "A4", "A5", "A6", "A8"]

pytestmark = pytest.mark.skipif(not GENERATOR.exists(), reason="backend/soc/fleet/make_fleet.py not present")


@pytest.fixture(scope="module")
def fleet(tmp_path_factory):
    base = tmp_path_factory.mktemp("fleet")
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(base), "--no-ecs"], check=True, capture_output=True)
    logs = base / "logs"
    truth = json.loads((logs / "truth.json").read_text(encoding="utf-8"))
    return truth, run(logs)


def _ids(incident):
    return {e["id"] for a in incident["alerts"] for e in a["evidence"]}


def _lines(truth, prefix):
    return {x for k, v in truth["lines"].items() if k == prefix or k.startswith(prefix + ":") for x in v}


def _incident_of(r, truth, attack):
    hits = [i for i in r["incidents"] if _ids(i) & _lines(truth, attack)]
    assert len(hits) == 1, f"{attack}: expected exactly one incident, got {len(hits)}"
    return hits[0]


@pytest.mark.parametrize("attack", ATTACKS)
def test_every_planted_attack_is_one_incident(fleet, attack):
    truth, r = fleet
    _incident_of(r, truth, attack)


def test_attacks_are_separate_incidents(fleet):
    truth, r = fleet
    assert len({_incident_of(r, truth, a)["id"] for a in ATTACKS}) == len(ATTACKS)


def test_night_chain_has_entry_lateral_and_impact_across_windows_and_ubuntu(fleet):
    truth, r = fleet
    inc = _incident_of(r, truth, "A1")
    for step in ("A1:entry", "A1:lateral", "A1:defense-evasion"):
        assert _ids(inc) & set(truth["lines"][step]), f"no evidence for {step}"
    assert {"entry", "lateral movement", "impact"} <= set(inc["stages"]) and inc["priority"] == "P1"
    assert {"WS-BASE-014", "srv-gate-ctrl-01"} <= {h["host"] for h in inc["hosts"]}


def test_phishing_chain_joins_mail_endpoint_and_network(fleet):
    truth, r = fleet
    inc = _incident_of(r, truth, "A4")
    for step in ("A4:delivery", "A4:execution", "A4:c2"):
        assert _ids(inc) & set(truth["lines"][step]), f"no evidence for {step}"
    assert "h.rexhepi" in inc["users"]


def test_at_most_one_false_incident(fleet):
    truth, r = fleet
    attack_lines = set().union(*(_lines(truth, a) for a in ATTACKS))
    false = [i["title"] for i in r["incidents"] if not _ids(i) & attack_lines]
    assert len(false) <= 1, false


def test_maintenance_and_scheduled_jobs_fully_suppressed(fleet):
    truth, r = fleet
    approved = set().union(*(truth["lines"][k] for k in MAINTENANCE))
    alerted = {e["id"] for a in r["alerts"] for e in a["evidence"]}
    assert not alerted & approved
    assert {s["ticket"] for s in r["suppressed"]} >= {"CHG-2026-1122-01", "CHG-VULNSCAN-WEEKLY"}


def test_only_the_real_outage_is_reported_and_it_lowers_confidence(fleet):
    truth, r = fleet
    silent = [h["source"] for h in r["health"] if not h["ok"]]
    assert silent == [truth["silent_source"]["source"]]
    inc = _incident_of(r, truth, "A1")
    assert inc["confidence"] < 1 and any(truth["silent_source"]["source"] in w for w in inc["confidence_reasons"])


def test_domain_takeover_chain_from_password_guessing_to_ransomware(fleet):
    truth, r = fleet
    inc = _incident_of(r, truth, "A5")
    for step in ("A5:entry", "A5:credential", "A5:lateral", "A5:privilege", "A5:impact"):
        assert _ids(inc) & set(truth["lines"][step]), f"no evidence for {step}"
    rules = {a["rule"] for a in inc["alerts"]}
    assert {"CRED-001", "LAT-002", "LAT-001", "PRIV-001", "IMP-001", "IMP-002"} <= rules
    assert {"credential theft", "privilege escalation", "impact"} <= set(inc["stages"]) and inc["priority"] == "P1"
    assert {"WS-BASE-021", "DC-02", "FS-01"} <= {h["host"] for h in inc["hosts"]}


def test_kerberoasting_to_exfiltration(fleet):
    truth, r = fleet
    inc = _incident_of(r, truth, "A6")
    assert {"CRED-003", "AUTH-005", "PRIV-002", "EXF-001", "NET-008"} <= {a["rule"] for a in inc["alerts"]}


def test_zone_policy_violation_is_part_of_the_night_chain(fleet):
    truth, r = fleet
    assert "NET-008" in {a["rule"] for a in _incident_of(r, truth, "A1")["alerts"]}


def test_admin_psexec_under_ticket_and_helpdesk_group_change_stay_quiet(fleet):
    truth, r = fleet
    quiet = set(truth["lines"]["psexec-change"]) | set(truth["lines"]["B6"])
    assert not {e["id"] for a in r["alerts"] for e in a["evidence"]} & quiet


def test_each_agent_reports_what_it_saw_on_the_50_device_base(fleet):
    truth, r = fleet
    by = {a["agent"]: a for a in r["agents"]}
    assert set(by) == {"windows_host", "endpoint", "linux_host", "host_firewall", "perimeter", "network_sensor", "mail"}
    fw = " ".join(by["host_firewall"]["highlights"])
    assert "NEW kinds" in fw and "DC-02 -> FS-01:445" in fw and "WS-BASE-014 -> srv-gate-ctrl-01:22" in fw
    assert "486 MB" in " ".join(by["network_sensor"]["highlights"])
    assert "LSASS" in " ".join(by["endpoint"]["highlights"])
    assert by["host_firewall"]["silent_sources"] == [truth["silent_source"]["source"]]
    assert all(a["incidents"] for a in by.values())
