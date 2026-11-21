"""Tests: does the engine meet the challenge's success criteria?   Run from backend/:  python -m pytest soc/tests -v

Each scenario test builds fresh sample logs (Windows + Ubuntu, 48 h) in a temp folder and checks the result against
truth.json (which lines belong to the attack, the patching and the backup).
"""
import ast
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from soc.__main__ import replay
from soc.parsers import PARSERS
from soc.pipeline import RULES_DIR, run
from soc.detect import enrich, load_rules, matches, run_rules
from soc.sample import generate

SOC = Path(__file__).resolve().parent.parent  # backend/soc


@pytest.fixture(scope="module")
def scenario(tmp_path_factory):
    d = tmp_path_factory.mktemp("logs")
    truth = generate(d)
    return d, truth, run(d)


def ids(incident):
    return {e["id"] for a in incident["alerts"] for e in a["evidence"]}


def truth_ids(truth, kind, step=None):
    return {x["id"] for x in truth[kind] if step is None or x["step"] == step}


# ----------------------------------------------------------------- detection + correlation
def test_whole_attack_is_one_incident(scenario):
    _, truth, r = scenario
    hit = [i for i in r["incidents"] if ids(i) & truth_ids(truth, "attack")]
    assert len(hit) == 1, "all steps must be in ONE incident"
    inc = hit[0]
    assert inc["stages"] == ["entry", "lateral movement", "impact"]
    for step in ("entry", "lateral", "impact"):
        assert ids(inc) & truth_ids(truth, "attack", step), f"no evidence for the {step} step"
    assert inc["priority"] == "P1"
    assert {h["host"] for h in inc["hosts"]} == set(truth["hosts"])
    assert truth["user"] in inc["users"] and truth["attacker_ip"] in inc["unknown_ips"]


def test_windows_and_ubuntu_evidence_in_the_same_incident(scenario):
    _, _, r = scenario
    sources = {e["source"] for a in r["incidents"][0]["alerts"] for e in a["evidence"]}
    assert any(s.startswith("win01") for s in sources) and any(s.startswith("ubu01") for s in sources)


def test_attack_mapping(scenario):
    _, _, r = scenario
    got = {t["id"] for t in r["incidents"][0]["attack"]}
    assert {"T1110", "T1078", "T1021"} <= got
    assert any(t.startswith("T1543") for t in got) and any(t.startswith("T1562") for t in got)


def test_every_alert_has_raw_evidence_and_every_link_a_reason(scenario):
    _, _, r = scenario
    inc = r["incidents"][0]
    for a in inc["alerts"]:
        assert a["evidence"] and all(e["raw"] and e["line"] > 0 for e in a["evidence"])
    assert inc["links"] and all(l["reason"] for l in inc["links"])


# ----------------------------------------------------------------- noise
def test_patching_and_backup_fully_suppressed(scenario):
    _, truth, r = scenario
    noise = truth_ids(truth, "patch") | truth_ids(truth, "backup")
    assert all(not (ids(i) & noise) for i in r["incidents"])
    assert {"CHG-1042", "CHG-BACKUP"} <= {m["ticket"] for m in r["maintenance"]}
    assert r["suppressed"], "patching should trigger rules that are then recognised and suppressed"


def test_attacker_not_hidden_inside_patch_window(scenario):
    _, truth, r = scenario
    hidden = {e["id"] for a in r["suppressed"] for e in a["evidence"]}
    assert not (hidden & truth_ids(truth, "attack"))


def test_no_incident_without_attack(tmp_path):
    generate(tmp_path, attack=False)
    assert run(tmp_path)["incidents"] == []


def test_normal_days_raise_no_alerts(tmp_path):
    generate(tmp_path, attack=False, gap=False)
    r = run(tmp_path)
    assert r["alerts"] == [], [a["text"] for a in r["alerts"]]


# ----------------------------------------------------------------- missing logs
def test_silent_log_lowers_confidence_with_reason(scenario):
    _, _, r = scenario
    inc = r["incidents"][0]
    assert inc["confidence"] < 1
    assert any("ubu01-firewall" in x and "silent" in x for x in inc["confidence_reasons"])


def test_full_confidence_when_logs_complete(tmp_path):
    generate(tmp_path, gap=False)
    assert run(tmp_path)["incidents"][0]["confidence"] == 1.0


def test_detected_even_if_a_log_file_is_missing(tmp_path):
    generate(tmp_path)
    (tmp_path / "win01_pfirewall.log").unlink()
    r = run(tmp_path)
    assert len(r["incidents"]) == 1 and "impact" in r["incidents"][0]["stages"]
    assert r["incidents"][0]["confidence"] <= 0.5


def test_only_the_real_gap_is_reported(scenario):
    _, _, r = scenario
    assert [h["source"] for h in r["health"] if not h["ok"]] == ["ubu01-firewall"]


# ----------------------------------------------------------------- speed
def test_time_to_flag_under_10_minutes(scenario):
    d, _, _ = scenario
    res = replay(d)
    assert res and all(x["minutes_after_last_event"] <= 10 for x in res)


def test_fast_on_a_laptop(scenario):
    d, _, _ = scenario
    t = time.perf_counter()
    run(d)
    assert time.perf_counter() - t < 5


# ----------------------------------------------------------------- advise only
def test_engine_cannot_act_on_systems():
    banned = {"subprocess", "socket", "requests", "urllib", "http", "shutil", "ctypes", "winreg", "paramiko", "smtplib"}
    for f in SOC.glob("*.py"):
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                [node.module or ""] if isinstance(node, ast.ImportFrom) else []
            assert not any(n.split(".")[0] in banned for n in names), f"{f.name} imports {names}"
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") in {"system", "popen", "unlink", "rmtree", "kill"}:
                raise AssertionError(f"{f.name} calls {node.func.attr}()")


def test_suggestions_are_advice(scenario):
    _, _, r = scenario
    steps = r["incidents"][0]["next_checks"]
    assert steps and all(s["type"] in ("verify", "contain, operator decides") for s in steps)


# ----------------------------------------------------------------- parsers
def _parse(tmp_path, parser, text, **src):
    p = tmp_path / "log"
    p.write_text(text, encoding="utf-8")
    stats = {"skipped": 0, "errors": 0, "times": []}
    return list(PARSERS[parser](p, {"name": "t", "path": "log", **src}, stats)), stats


def test_ubuntu_auth_both_timestamp_styles(tmp_path):
    evs, _ = _parse(tmp_path, "linux_auth",
                    "2026-11-18T02:16:00.123456+00:00 ubu-01 sshd[1]: Accepted password for bob from 10.0.0.5 port 1 ssh2\n"
                    "Nov 18 02:17:00 ubu-01 sshd[1]: Failed password for invalid user x from 10.0.0.6 port 2 ssh2\n", year=2026)
    assert [(e["outcome"], e["user"], e["src_ip"], e["time"].hour, e["time"].minute) for e in evs] == \
        [("success", "bob", "10.0.0.5", 2, 16), ("failure", "x", "10.0.0.6", 2, 17)]


def test_ubuntu_sudo_firewall_and_ufw(tmp_path):
    evs, _ = _parse(tmp_path, "linux_auth", "2026-11-18T02:22:30+00:00 h sudo: bob : TTY=pts/1 ; USER=root ; COMMAND=/usr/sbin/ufw allow 4444/tcp\n")
    assert evs[0]["action"] == "firewall-change" and evs[0]["user"] == "bob"
    evs, _ = _parse(tmp_path, "linux_ufw", "2026-11-18T02:15:02+00:00 h kernel: [1.2] [UFW BLOCK] IN=eth0 OUT= MAC=x SRC=10.0.0.9 "
                                           "DST=10.0.0.1 LEN=60 PROTO=TCP SPT=5555 DPT=22 WINDOW=1 SYN URGP=0\n")
    assert (evs[0]["action"], evs[0]["direction"], evs[0]["dst_port"]) == ("block", "inbound", 22)


def test_windows_firewall_local_time(tmp_path):
    evs, _ = _parse(tmp_path, "windows_firewall",
                    "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path\n"
                    "2026-11-18 03:15:01 ALLOW TCP 10.0.0.1 10.0.0.2 5000 22 0 - 0 0 0 - - - SEND\n", utc_offset="+01:00", host="W")
    assert evs[0]["time"] == datetime(2026, 11, 18, 2, 15, 1, tzinfo=timezone.utc) and evs[0]["direction"] == "outbound"


def test_unknown_lines_are_counted_not_lost(tmp_path):
    _, stats = _parse(tmp_path, "linux_auth", "2026-11-18T02:00:00+00:00 h CRON[1]: session opened\nnot a log line\n")
    assert stats["skipped"] == 1 and stats["errors"] == 1 and len(stats["times"]) == 1


# ----------------------------------------------------------------- rules
def _ev(n, outcome, logon, ip):
    return {"id": f"t:{n}", "time": datetime(2026, 11, 18, 2, n, tzinfo=timezone.utc), "source": "t", "type": "auth",
            "action": "logon", "outcome": outcome, "logon": logon, "host": "H", "user": "u", "src_ip": ip, "raw": "x", "line": n}


def test_rule_files_are_valid():
    rules = load_rules(RULES_DIR)
    assert len(rules) >= 12 and all(
        r["type"] in ("match", "threshold", "distinct_threshold", "sequence", "new_value")
        for r in rules
    )


def test_conditions():
    e = {"user": "Bob", "dst_port": 22, "path": "C:\\ProgramData\\x.exe"}
    assert matches(e, {"user": ["bob"], "dst_port|not": [53], "path|startswith": "c:\\programdata"})
    assert not matches(e, {"src_ip": "1.2.3.4"}) and matches(e, {"src_ip|exists": False})


def test_typo_at_keyboard_is_not_an_attack():
    evs = [_ev(1, "failure", "unlock", None), _ev(2, "failure", "unlock", None), _ev(3, "success", "unlock", None)]
    enrich(evs, {})
    assert not [a for a in run_rules(evs, load_rules(RULES_DIR), evs[0]["time"] - timedelta(hours=1)) if a["rule"] == "AUTH-001"]


def test_remote_failures_then_success_is_detected():
    evs = [_ev(1, "failure", "ssh", "10.9.9.9"), _ev(2, "failure", "ssh", "10.9.9.9"), _ev(3, "success", "ssh", "10.9.9.9")]
    enrich(evs, {})
    hits = [a for a in run_rules(evs, load_rules(RULES_DIR), evs[0]["time"] - timedelta(hours=1)) if a["rule"] == "AUTH-001"]
    assert len(hits) == 1 and hits[0]["count"] == 3


def test_bot_swarm_from_many_sources_is_one_incident():
    from soc.correlate import correlate

    start = datetime(2026, 11, 18, 2, tzinfo=timezone.utc)
    events = [
        {
            "id": f"swarm:{n}",
            "time": start + timedelta(seconds=n),
            "source": "swarm",
            "file": "traffic.log",
            "line": n + 1,
            "raw": f"row {n}",
            "host": "gateway",
            "type": "network",
            "action": "block",
            "direction": "inbound",
            "src_ip": f"198.51.100.{n + 1}",
            "dst_ip": "10.0.0.10",
            "user": None,
        }
        for n in range(10)
    ]
    enrich(events, {"assets": [{"host": "gateway", "ip": "10.0.0.10", "criticality": "high"}]})
    alerts = run_rules(events, load_rules(RULES_DIR), start - timedelta(hours=1))
    swarm_alerts = [alert for alert in alerts if alert["rule"] == "NET-004"]

    incidents, singles = correlate(
        swarm_alerts,
        {"assets": [{"host": "gateway", "ip": "10.0.0.10", "criticality": "high"}]},
        [],
        start + timedelta(seconds=10),
    )

    assert len(swarm_alerts) == 1
    assert swarm_alerts[0]["distinct_source_count"] == 10
    assert len(incidents) == 1
    assert incidents[0]["attack"][0]["id"] == "T1498"
    assert singles == []
