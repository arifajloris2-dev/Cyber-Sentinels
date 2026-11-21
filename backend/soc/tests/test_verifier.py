"""Alert Verification Engine (soc/verify.py): verdicts on the team's scenarios A-E, audit trail, AI forwarding, bad input.

Uses the existing synthetic data: the 50-device base (fleet, with truth.json), sample_logs and a synthetic incident.
Run from the repo root:  $env:PYTHONPATH="backend"; python -m pytest backend/soc/tests/test_verifier.py -q
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from soc import verify
from soc.pipeline import run

REPO = Path(__file__).resolve().parents[3]
GENERATOR = REPO / "backend" / "soc" / "fleet" / "make_fleet.py"
SAMPLE = REPO / "backend" / "soc" / "sample_logs"
ATTACKS = ["A1", "A2", "A3", "A4", "A5", "A6", "A8"]
HARMLESS = ["B1", "B4", "B6", "patch", "change", "backup", "vulnscan", "emergency", "psexec-change"]
ASSETS = {
    "assets": [{"host": "WS-BASE-006", "ip": "10.24.3.6", "role": "operator workstation", "criticality": 2},
               {"host": "FS-01", "ip": "10.24.2.10", "role": "file server", "criticality": 4},
               {"host": "DC-02", "ip": "10.24.1.2", "role": "domain controller", "criticality": 5}],
    "users": [{"user": "g.kelmendi", "role": "operator", "groups": ["Operators"], "privileged": False, "home": "WS-BASE-006"}],
    "zones": [{"name": "CORE", "cidr": "10.24.1.0/24"}, {"name": "SERVERS", "cidr": "10.24.2.0/24"},
              {"name": "USERS", "cidr": "10.24.3.0/24"}],
}


def _alert(rule, severity=5, ids=("fs-01-events:1", "ws-base-006-pfirewall:2")):
    return {"rule": rule, "title": rule, "severity": severity, "time": "2026-11-22T10:15:00+00:00",
            "evidence": [{"id": i} for i in ids]}


def _single(rule="AUTH-001", severity=6, user="g.kelmendi", hosts=("FS-01", "WS-BASE-006"), **kw):
    return {"id": f"{rule}@x", **_alert(rule, severity), "users": [user], "hosts": list(hosts), **kw}


# ----------------------------------------------------------------- the 50-device base (scenarios A-E)
@pytest.fixture(scope="module")
def fleet(tmp_path_factory):
    if not GENERATOR.exists():
        pytest.skip("fleet generator not present")
    base = tmp_path_factory.mktemp("fleet")
    subprocess.run([sys.executable, str(GENERATOR), "--out", str(base), "--no-ecs"], check=True, capture_output=True)
    logs = base / "logs"
    return json.loads((logs / "truth.json").read_text(encoding="utf-8")), run(logs)


def _ids(item):
    return {e["id"] for a in (item.get("alerts") or [item]) for e in a["evidence"]}


def _lines(truth, key):
    return {x for k, v in truth["lines"].items() if k == key or k.startswith(key + ":") for x in v}


def _of(r, truth, key):
    return [i for i in r["incidents"] + r["singles"] if _ids(i) & _lines(truth, key)]


@pytest.mark.parametrize("attack", ATTACKS)
def test_every_planted_attack_is_suspicious(fleet, attack):
    truth, r = fleet
    hits = _of(r, truth, attack)
    assert hits and all(i["verification"]["verdict"] == "suspicious" for i in hits)
    assert all(i["verification"]["forward_to_ai"] for i in hits)


def test_no_lookalike_or_maintenance_is_suspicious(fleet):
    truth, r = fleet
    attack_lines = set().union(*(_lines(truth, a) for a in ATTACKS))
    for key in HARMLESS:
        for item in _of(r, truth, key):
            if not _ids(item) & attack_lines:
                assert item["verification"]["verdict"] != "suspicious", (key, item["id"])


def test_scenario_c_mistyped_password_is_likely_benign_with_explanation(fleet):
    truth, r = fleet
    (b1,) = [i for i in _of(r, truth, "B1") if not i.get("alerts")]     # the single, not-escalated alert
    v = b1["verification"]
    assert v["verdict"] == "likely_benign" and v["forward_to_ai"] is False
    assert any(x["rule"] == "V-AUTHORIZED" for x in v["reasons"])          # recorded with its reason, not dropped


@pytest.mark.parametrize("attack, rules", [("A5", {"CRED-001", "CRED-002", "LAT-002", "PRIV-001", "IMP-001"}),
                                           ("A6", {"CRED-003", "EXF-001"})])
def test_scenario_d_names_the_never_benign_rules(fleet, attack, rules):
    truth, r = fleet
    (inc,) = [i for i in _of(r, truth, attack) if i.get("alerts")]
    named = {x["rule"].split(":", 1)[1] for x in inc["verification"]["reasons"] if x["rule"].startswith("V-NEVER-BENIGN:")}
    assert rules <= named


def test_scenario_e_silent_source_gives_a_missing_evidence_reason(fleet):
    truth, r = fleet
    (a1,) = [i for i in _of(r, truth, "A1") if i.get("alerts")]
    reasons = a1["verification"]["reasons"]
    assert any(x["rule"] == "V-MISSING-EVIDENCE" and truth["silent_source"]["source"] in x["text"] for x in reasons)


def test_scenario_e_removed_log_file_is_never_benign(tmp_path):
    logs = tmp_path / "logs"
    shutil.copytree(SAMPLE, logs, ignore=shutil.ignore_patterns("out"))
    (logs / "ubu01_ufw.log").write_text("", encoding="utf-8")          # the firewall log is gone (empty)
    r = run(logs)
    items = r["incidents"] + r["singles"]
    assert items and all(i["verification"]["verdict"] != "likely_benign" for i in items)
    hit = [i for i in r["incidents"] if any(h.get("host") == "ubu-01" for h in i["hosts"])]
    assert hit and any(x["rule"] == "V-MISSING-EVIDENCE" for i in hit for x in i["verification"]["reasons"])


# ----------------------------------------------------------------- principles on a synthetic record
def test_high_risk_is_never_dismissed_even_when_everything_else_looks_authorized():
    rules = verify.load_rules()
    assert verify.verify(_single(), ASSETS, [], rules)["verdict"] == "likely_benign"          # control
    for item in (_single("CRED-001", severity=5), _single("AUTH-004", severity=9)):
        v = verify.verify(item, ASSETS, [], rules)
        assert v["verdict"] == "suspicious" and v["forward_to_ai"]


def test_missing_evidence_beats_authorization():
    rules = verify.load_rules()
    health = [{"source": "fs-01-events", "host": "FS-01", "ok": False, "silent": [{"note": "no events at all"}]}]
    v = verify.verify(_single(), ASSETS, health, rules)
    assert v["verdict"] == "inconclusive" and v["reasons"][0]["rule"] == "V-MISSING-EVIDENCE"


@pytest.mark.parametrize("change, reason", [
    ({"user": "x.unknown"}, "V-NOT-PROVEN-BENIGN"),                      # not a known user
    ({"hosts": ("DC-02", "WS-BASE-006")}, "V-NOT-PROVEN-BENIGN"),        # a machine this user has no reason to use
    ({"compromised_accounts": ["g.kelmendi"]}, "V-COMPROMISED"),          # a legitimate account can be compromised
    ({"unknown_ips": ["203.0.113.9"]}, "V-UNKNOWN-ADDRESS"),
])
def test_benign_needs_positive_evidence(change, reason):
    v = verify.verify(_single(**change), ASSETS, [], verify.load_rules())
    assert v["verdict"] == "inconclusive" and any(x["rule"] == reason for x in v["reasons"])


def test_two_warning_signs_make_it_suspicious():
    item = _single(compromised_accounts=["g.kelmendi"], unknown_ips=["203.0.113.9"])
    assert verify.verify(item, ASSETS, [], verify.load_rules())["verdict"] == "suspicious"


def test_single_source_without_authorization_is_inconclusive():
    item = {**_single("NET-002"), "evidence": [{"id": "fs-01-events:1"}], "users": []}
    v = verify.verify(item, ASSETS, [], verify.load_rules())
    assert v["verdict"] == "inconclusive" and v["reasons"][0]["rule"] == "V-SINGLE-SOURCE"


def test_same_input_same_verdict():
    rules = verify.load_rules()
    assert verify.verify(_single(), ASSETS, [], rules) == verify.verify(_single(), ASSETS, [], rules)


# ----------------------------------------------------------------- invalid input and settings
@pytest.mark.parametrize("bad", [None, "text", {}, {"alerts": "x"}, {"alerts": [{"severity": 9}]}, {"alerts": []}])
def test_invalid_input_is_inconclusive_not_a_crash(bad):
    v = verify.verify(bad, ASSETS, [], verify.load_rules())
    assert v["verdict"] == "inconclusive" and v["reasons"][0]["rule"] == "V-INPUT"


def test_odd_fields_do_not_crash():
    item = _single(severity="high")
    item.update(time=None, stages="not a list", confidence="?")
    assert verify.verify(item, {"zones": [{"name": "X", "cidr": "nonsense"}], "users": "?"}, [None], verify.load_rules())


def test_broken_settings_give_a_clear_error_and_inconclusive(tmp_path):
    bad = tmp_path / "rules.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(verify.ConfigError, match="not valid JSON"):
        verify.load_rules(bad)
    items = [_single()]
    out = verify.apply(items, [], [], ASSETS, bad)
    assert out["ok"] is False and items[0]["verification"]["verdict"] == "inconclusive"
    bad.write_text(json.dumps({"never_benign_rules": "CRED-*"}), encoding="utf-8")
    with pytest.raises(verify.ConfigError, match="wrong type"):
        verify.load_rules(bad)
    bad.write_text(json.dumps({"authorized_activities": [{"name": "no rules"}]}), encoding="utf-8")
    with pytest.raises(verify.ConfigError, match="rules_expected"):
        verify.load_rules(bad)
    with pytest.raises(verify.ConfigError, match="cannot read"):
        verify.load_rules(tmp_path / "missing.json")


# ----------------------------------------------------------------- audit trail
def test_audit_is_append_only_and_not_duplicated(tmp_path):
    audit = verify.AuditLog(tmp_path / "audit" / "verification.jsonl")
    items = [_single()]
    verify.apply(items, [], [], ASSETS)
    assert audit.record_verdicts(items, "run1") == 1
    assert audit.record_verdicts(items, "run2") == 0                       # same verdict, same evidence: no new line
    before = audit.path.read_text(encoding="utf-8")
    items[0]["compromised_accounts"] = ["g.kelmendi"]                       # the verdict changes -> one new line
    verify.apply(items, [], [], ASSETS)
    assert audit.record_verdicts(items, "run3") == 1
    audit.record_operator("AUTH-001@x", "close", "False positive", "user back from leave")
    after = audit.path.read_text(encoding="utf-8")
    assert after.startswith(before)                                         # earlier lines untouched
    rows = [json.loads(x) for x in after.splitlines()]
    assert [r["actor"] for r in rows] == ["verifier", "verifier", "operator"]
    assert rows[0]["verdict"] == "likely_benign" and rows[0]["engine_run"] == "run1" and rows[0]["ruleset"]
    assert rows[0]["evidence"] and rows[2]["reason"] == "False positive"
    assert audit.last(2)[0]["action"] == "close"                            # newest first


def test_operator_actions_are_checked(tmp_path):
    audit = verify.AuditLog(tmp_path / "a.jsonl")
    for action in ("close", "reopen", "override"):
        audit.record_operator("INC-1", action, verdict="inconclusive" if action == "override" else None)
    with pytest.raises(ValueError):
        audit.record_operator("INC-1", "delete")
    with pytest.raises(ValueError):
        audit.record_operator("INC-1", "override", verdict="harmless")
    assert len(audit.last()) == 3


# ----------------------------------------------------------------- AI forwarding
def _incidents():
    items = [{"id": "INC-1", "alerts": [_alert("CRED-001", 9)], "users": ["g.kelmendi"], "hosts": [{"host": "FS-01"}]},
             {"id": "INC-2", **_single()}]
    items[1]["alerts"] = [_alert("AUTH-001", 6)]
    verify.apply(items, [], [], ASSETS)
    return items


def test_only_forwarded_incidents_reach_the_ai_and_it_never_changes_the_verdict():
    items = _incidents()
    assert [i["verification"]["verdict"] for i in items] == ["suspicious", "likely_benign"]
    built, asked = [], []

    def builder(inc, findings, sources, advisories):
        built.append(inc["id"])
        return {"incident_id": inc["id"], "marker": "from-builder"}, {}

    def analyzer(payload, **kw):
        asked.append(payload)
        return {"summary": "ok", "triage_assessment": "possibly_authorized_or_benign"}

    out = verify.explain(items, analyzer=analyzer, builder=builder, timeout=1)
    assert built == ["INC-1"] and asked == [{"incident_id": "INC-1", "marker": "from-builder"}]
    assert out["INC-1"]["ai"] == "ok" and out["INC-1"]["verdict"] == "suspicious"
    assert items[0]["verification"]["verdict"] == "suspicious"              # the AI's opinion did not change it


def test_analyzer_receives_the_payload_of_build_dashboard_incident():
    ai = pytest.importorskip("AI_Log_Analyzer.ai_log_analyzer")
    items = _incidents()
    seen = []
    verify.explain(items, analyzer=lambda payload, **kw: seen.append(payload) or {"summary": "x"},
                   builder=ai.build_dashboard_incident)
    assert seen == [ai.build_dashboard_incident(items[0], [], [], {})[0]]


def test_ollama_unavailable_keeps_the_verdict():
    def down(payload, **kw):
        raise ConnectionError("Ollama is not running")

    out = verify.explain(_incidents(), analyzer=down, builder=lambda *a: ({}, {}))
    assert out == {"INC-1": {"verdict": "suspicious", "ai": "unavailable", "error": "Ollama is not running"}}


# ----------------------------------------------------------------- offline, advice only
def test_verifier_only_writes_its_audit_file():
    import ast
    tree = ast.parse((REPO / "backend" / "soc" / "verify.py").read_text(encoding="utf-8"))
    opens = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "open"]
    assert all(any(isinstance(a, ast.Constant) and a.value in ("a", None) for a in n.args) or not n.args for n in opens)
    calls = {getattr(n.func, "attr", getattr(n.func, "id", "")) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert not calls & {"write_text", "write_bytes", "unlink", "rmtree", "rename", "replace_file", "system", "popen"}


def test_low_priority_items_are_shaped_like_incidents(fleet):
    from soc.correlate import low_priority
    truth, r = fleet
    items = low_priority(r["singles"], r["cfg"]["assets"])
    assert {i["alerts"][0]["rule"] for i in items} >= {"AUTH-001", "PRIV-004", "MAIL-003"}
    for i in items:
        assert i["priority"] == "P3" and i["kind"] == "single" and i["id"].startswith("LOW-")
        assert i["verification"]["verdict"] != "suspicious" and i["title"][:1].isupper()
    assert not {i["id"] for i in items} & {i["id"] for i in r["incidents"]}


def test_helpdesk_may_change_normal_groups_on_the_directory_server_only():
    assets = {**ASSETS, "users": ASSETS["users"] + [{"user": "k.zeqiri", "role": "helpdesk", "home": "WS-BASE-010"}],
              "assets": ASSETS["assets"] + [{"host": "srv-auth-01", "ip": "10.24.1.10", "role": "domain controller + Kerberos auth server"}]}
    rules = verify.load_rules()
    ok = _single("PRIV-004", 3, user="k.zeqiri", hosts=("srv-auth-01",))
    assert verify.verify(ok, assets, [], rules)["verdict"] == "likely_benign"
    elsewhere = _single("PRIV-004", 3, user="k.zeqiri", hosts=("FS-01",))
    assert verify.verify(elsewhere, assets, [], rules)["verdict"] == "inconclusive"
    privileged = _single("PRIV-001", 9, user="k.zeqiri", hosts=("srv-auth-01",))
    assert verify.verify(privileged, assets, [], rules)["verdict"] == "suspicious"
