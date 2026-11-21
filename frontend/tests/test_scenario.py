"""Exercise view: the answer key is compared with the incidents by evidence line, never used for detection."""
import json

from frontend import scenario

TRUTH = {
    "attacks": {"A1": {"title": "brute force then shell", "hosts": ["WS-1"], "start": "2026-11-22T01:41:00+00:00",
                       "end": "2026-11-22T02:31:00+00:00", "techniques": ["T1110.001"]},
                "A2": {"title": "spraying", "hosts": ["srv-web-01"]}},
    "lookalikes": {"B1": "user mistypes the password", "kerberos": "AES tickets every logon"},
    "maintenance": {"patch": "CHG-1"},
    "silent_source": {"source": "fw-ufw", "from": "2026-11-22T02:05:00+00:00", "to": "2026-11-22T04:30:00+00:00"},
    "lines": {"A1:entry": ["ws-1-events:5"], "A1:impact": ["ws-1-events:9"], "A2": ["web-auth:3"],
              "B1": ["fs-events:7"], "patch": ["dc-events:1", "dc-events:2"]},
}


def _inc(iid, *ids):
    return {"id": iid, "priority": "P1", "alerts": [{"evidence": [{"id": i} for i in ids]}]}


def test_attacks_are_matched_to_incidents_by_evidence_and_lookalikes_by_mistake():
    view = scenario.build(TRUTH, [_inc("INC-1", "ws-1-events:9"), _inc("INC-2", "fs-events:7")])
    a1, a2 = view["attacks"]
    assert [i["id"] for i in a1["incidents"]] == ["INC-1"] and a2["incidents"] == []
    assert [s["label"] for s in a1["steps"]] == ["Entry", "Impact"]          # attack order, not alphabetical
    assert view["detected"] == 1 and view["false_alarms"] == 1
    assert view["lookalikes"][0]["incidents"] == ["INC-2"]                    # a look-alike raised by mistake shows
    assert [x["id"] for x in view["routine"]] == ["kerberos"]
    assert view["maintenance"][0] == {"key": "patch", "ticket": "CHG-1", "lines": 2, "incidents": []}


def test_no_answer_key_means_no_exercise_view(tmp_path):
    assert scenario.load_truth(tmp_path) is None and scenario.build(None, []) is None
    (tmp_path / "truth.json").write_text("{broken", encoding="utf-8")
    assert scenario.load_truth(tmp_path) is None
    (tmp_path / "truth.json").write_text(json.dumps({"attack": []}), encoding="utf-8")     # sample_logs' older format
    assert scenario.load_truth(tmp_path) is None
    (tmp_path / "truth.json").write_text(json.dumps(TRUTH), encoding="utf-8")
    assert scenario.load_truth(tmp_path)["attacks"]["A1"]["hosts"] == ["WS-1"]
