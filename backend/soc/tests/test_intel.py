"""OSINT threat intel (Member 1) joined to SOC incidents.   Run from backend/:  python -m pytest soc/tests -q"""
import json
import shutil
from pathlib import Path

from soc import intel
from soc.correlate import priority
from soc.pipeline import run

SAMPLE = Path(__file__).resolve().parent.parent / "sample_logs"

OSINT = {
    "structured_threat_findings": [
        {"type": "vulnerability_exposure", "cve": "CVE-2025-4120", "cisa_kev": True, "epss_score": 0.91,
         "affected_assets": ["srv-gate-ctrl-01"], "mitre_techniques": ["T1543", "T1562"], "summary": "Service change."},
        {"type": "vulnerability_exposure", "cve": "CVE-2099-0001", "cisa_kev": False, "epss_score": 0.1,
         "affected_assets": ["srv-gate-ctrl-01"], "mitre_techniques": ["T1190"], "summary": "Other technique."},
        {"type": "credential_exposure", "post_id": "osint-001", "account": "svc_ops_night", "timestamp": "2026-11-21T01:55:00Z",
         "affected_assets": ["ws-base-014"], "mitre_techniques": ["T1078", "T1110"], "summary": "Leaked."}],
    "targeted_hunt_requests": [
        {"hunt_id": "HUNT-CVE-2025-4120", "target_assets": ["srv-gate-ctrl-01"], "mitre_techniques": ["T1543", "T1562"]},
        {"hunt_id": "HUNT-ELSEWHERE", "target_assets": ["srv-other"], "mitre_techniques": ["T1110"]}]}


def _incident(**kw):
    base = {"id": "INC-1", "score": 60, "priority": "P2", "hosts": [{"host": "WS-BASE-014"}, {"host": "srv-gate-ctrl-01"}],
            "users": ["op_night_01", "svc_ops_night"], "attack": [{"id": "T1543.002"}, {"id": "T1110"}], "next_checks": []}
    return {**base, **kw}


def _intel(tmp_path, data=OSINT):
    (tmp_path / intel.FILE).write_text(json.dumps(data), encoding="utf-8")
    return intel.load(tmp_path)


def test_matching_needs_shared_asset_and_technique_or_the_leaked_account(tmp_path):
    inc = _incident()
    intel.attach([inc], _intel(tmp_path), priority)
    assert [x["id"] for x in inc["intel"]] == ["CVE-2025-4120", "osint-001:svc_ops_night"]   # T1190 was never seen
    assert inc["score"] == 80 and inc["priority"] == "P1"                                     # +10 KEV, +10 leaked account
    assert any("svc_ops_night" in s["step"] and s["type"] == "contain, operator decides" for s in inc["next_checks"])


def test_host_names_match_regardless_of_case(tmp_path):
    inc = _incident(hosts=[{"host": "SRV-GATE-CTRL-01"}], users=[])
    intel.attach([inc], _intel(tmp_path), priority)
    assert [x["id"] for x in inc["intel"]] == ["CVE-2025-4120"]


def test_unrelated_incident_gets_nothing_and_keeps_its_score(tmp_path):
    inc = _incident(hosts=[{"host": "FS-01"}], users=["g.kelmendi"], attack=[{"id": "T1110"}])
    intel.attach([inc], _intel(tmp_path), priority)
    assert inc["intel"] == [] and inc["score"] == 60 and inc["priority"] == "P2"


def test_every_hunt_request_gets_an_answer(tmp_path):
    data = _intel(tmp_path)
    intel.attach([_incident()], data, priority)
    status = {h["hunt_id"]: h["status"] for h in data["hunts"]}
    assert status == {"HUNT-CVE-2025-4120": "found: INC-1", "HUNT-ELSEWHERE": "no matching activity in these logs"}


def test_no_osint_file_means_no_intel(tmp_path, monkeypatch):
    monkeypatch.setattr(intel, "DATA_DIR", tmp_path / "none")
    monkeypatch.setattr("soc.knowledge.STORE", tmp_path / "no-kb")
    res = intel.load(tmp_path)
    assert (res["source"], res["findings"], res["hunts"], res["imported"]) == (None, [], [], 0)


def test_pipeline_uses_osint_file_in_the_log_folder_and_never_creates_incidents_from_intel(tmp_path):
    logs = tmp_path / "logs"
    shutil.copytree(SAMPLE, logs, ignore=shutil.ignore_patterns("out"))
    without = run(logs)
    (logs / intel.FILE).write_text(json.dumps({"structured_threat_findings": [
        {"type": "credential_exposure", "post_id": "p1", "account": "nobody", "affected_assets": ["nowhere"]}],
        "targeted_hunt_requests": []}), encoding="utf-8")
    r = run(logs)
    assert r["intel"]["source"].endswith(intel.FILE) and len(r["intel"]["findings"]) == 1
    assert len(r["incidents"]) == len(without["incidents"]) and all(i["intel"] == [] for i in r["incidents"])


def test_new_osint_format_finding_type_and_ids(tmp_path):
    """osint_agent.py writes threat_findings with finding_type (credential_exposure_osint) and its own FIND-... ids."""
    new = {"threat_findings": [
        {"id": "FIND-CVE-2025-4120", "finding_type": "vulnerability_exposure", "cve": "CVE-2025-4120", "cisa_kev": True,
         "affected_assets": ["srv-gate-ctrl-01"], "mitre_techniques": ["T1543"]},
        {"id": "FIND-osint-001-svc_ops_night", "finding_type": "credential_exposure_osint", "post_id": "osint-001",
         "account": "svc_ops_night", "timestamp": "2026-11-20T01:55:00Z", "affected_assets": ["ws-base-014"],
         "mitre_techniques": ["T1078", "T1110"]}],
        "targeted_hunt_requests": []}
    inc = _incident()
    intel.attach([inc], _intel(tmp_path, new), priority)
    assert [(x["id"], x["kind"]) for x in inc["intel"]] == [("FIND-CVE-2025-4120", "vulnerability"),
                                                           ("FIND-osint-001-svc_ops_night", "credential")]
    assert any("leaked on 2026-11-20" in s["step"] for s in inc["next_checks"])
    assert not any("None" in s["step"] for s in inc["next_checks"])
