"""Real lab logs from the team's VMs (backend/soc/lab_logs): read cleanly, setup noise suppressed, phishing click found.
Run from backend/:  python -m pytest soc/tests -q
"""
import json
import re
from pathlib import Path

import pytest

from soc.pipeline import run

LAB = Path(__file__).resolve().parent.parent / "lab_logs"


@pytest.fixture(scope="module")
def lab():
    return run(LAB)


def test_real_windows_export_and_mail_events_read_without_errors(lab):
    stats = {s["source"]: s for s in lab["stats"]}
    assert stats["lab-win-events"]["events"] == 1005 and stats["lab-win-events"]["errors"] == 0
    assert stats["lab-mail-events"]["events"] == 4 and stats["lab-mail-events"]["errors"] == 0


def test_vm_setup_is_approved_maintenance_not_an_incident(lab):
    assert {m["ticket"] for m in lab["maintenance"]} == {"LAB-VM-OS-INSTALL", "LAB-VM-TOOLS"}
    assert len(lab["suppressed"]) == 23
    assert not [i for i in lab["incidents"] if any(a["rule"].startswith("SYS") for a in i["alerts"])]


def test_click_in_a_phishing_mail_is_an_incident_and_a_click_in_a_clean_mail_is_not(lab):
    hits = [a for i in lab["incidents"] for a in i["alerts"] if a["rule"] == "MAIL-002"]
    assert len(hits) == 1 and "demo-001" in hits[0]["text"] and hits[0]["users"] == ["lab-user"]
    assert len(lab["incidents"]) == 1


def test_new_windows_account_name_is_shown(lab):
    texts = [a["text"] for a in lab["suppressed"] if a["rule"] == "SYS-005"]
    assert texts and all("new account " in t and ": ?" not in t for t in texts)


def test_committed_lab_logs_hold_no_machine_sid():
    text = (LAB / "lab-win_events.jsonl").read_text(encoding="utf-8")
    assert not re.search(r"S-1-5-21-(?!0-0-0-)\d+-\d+-\d+-\d+", text), "run anonymise.py before committing"
    assert all(json.loads(line) for line in text.splitlines())
