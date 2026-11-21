"""Operator knowledge import (plain text only): strict checks, clean storage, effect on detection and intel.
Run from backend/:  python -m pytest soc/tests -q"""
import json
from pathlib import Path

import pytest

from soc import knowledge
from soc.pipeline import run

SAMPLE = Path(__file__).resolve().parent.parent / "sample_logs"
GOOD = """# new advisory
CVE: CVE-2026-31337
Product: GateControlService
Versions: 2.4.0
KEV: yes
EPSS: 0.88
Techniques: T1543, T1562
Hosts: ubu-01
Summary: Unauthenticated config write in the management daemon.
Reference: https://example.invalid/advisory

IP: 203.0.113.99
Note: data-theft server

Account: svc_sql
Note: password sold on a forum
"""


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(knowledge, "STORE", tmp_path / "kb")
    return tmp_path / "kb"


def test_valid_text_becomes_records():
    res = knowledge.check(GOOD)
    assert res.error is None and res.rejected == []
    assert [r["kind"] for r in res.records] == ["cve", "ioc", "account"]
    cve = res.records[0]
    assert cve["cve"] == "CVE-2026-31337" and cve["kev"] is True and cve["techniques"] == ["T1543", "T1562"]


@pytest.mark.parametrize("data, reason", [
    (b"\x00\x01binary", "control characters"),
    (b"\xff\xfe\x00M\x00Z", "not UTF-8"),
    ("CVE: CVE-2026-1\x07", "control characters"),
    ("x" * (knowledge.MAX_BYTES + 1), "too large"),
])
def test_binary_control_characters_and_oversize_are_refused(data, reason):
    assert reason in knowledge.check(data).error


def test_unknown_keys_and_bad_values_are_rejected_line_by_line():
    res = knowledge.check("Exec: rm -rf /\nCVE: CVE-12\nIP: 999.1.1.1\nTechniques: T1543; DROP TABLE\n"
                          "Reference: javascript:alert(1)\n<script>alert(1)</script>\n")
    reasons = " | ".join(r[2] for r in res.rejected)
    assert res.records == [] and "unknown key 'exec'" in reasons and "not a CVE id" in reasons
    assert "not an IP address" in reasons and "not ATT&CK technique ids" in reasons and "http(s)" in reasons
    assert "expected 'Key: value'" in reasons


def test_stored_copy_is_rebuilt_from_checked_fields_and_rechecked_on_load(store):
    res = knowledge.check(GOOD + "\nNote: <b>ignored on its own</b>\n")
    path = knowledge.save(res, "unit test")
    text = path.read_text(encoding="utf-8")
    assert path.parent == store and path.suffix == ".txt" and res.sha256 in text
    assert "# new advisory" not in text                     # the submitted text itself is never stored
    assert len(knowledge.load()) == 3
    path.write_text(text + "\nExec: evil\n", encoding="utf-8")   # a hand-edited store file is re-checked on load
    assert len(knowledge.load()) == 3
    assert knowledge.remove(path.name) and knowledge.load() == []
    assert (store / (path.name + ".removed")).exists()          # withdrawn, kept as an audit trail
    assert not knowledge.remove("../../etc/passwd")


def test_imported_indicator_raises_ioc_alert_and_cve_reaches_the_incident(store, tmp_path):
    truth = json.loads((SAMPLE / "truth.json").read_text(encoding="utf-8"))
    knowledge.save(knowledge.check(GOOD + f"\nIP: {truth['attacker_ip']}\nNote: reported by an allied CERT\n"), "unit test")
    r = run(SAMPLE)
    ioc = [a for a in r["alerts"] if a["rule"] == "IOC-001"]
    assert ioc and truth["attacker_ip"] in ioc[0]["text"]
    kb = [f for f in r["intel"]["findings"] if str(f["id"]).startswith("KB-")]
    assert {"KB-CVE-2026-31337", "KB-ACCT-svc_sql"} <= {f["id"] for f in kb}
    inc = next(i for i in r["incidents"] if any(a["rule"] == "IOC-001" for a in i["alerts"]))
    assert any(x["id"] == "KB-CVE-2026-31337" for x in inc.get("intel", []))   # ubu-01 + T1543 seen in the incident
