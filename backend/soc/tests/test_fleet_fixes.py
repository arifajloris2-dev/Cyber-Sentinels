"""Tests for the fixes found by replaying the 50-device synthetic base (synthetic-fleet):

  - outside visitors on a server's public ports are not "new inbound connections"
  - weak alerts never join an incident only because they share a busy host
  - a log that is quiet at night every night is not "silent"; a log that stops while it normally writes is
  - incident titles say what was seen (no "Remote logon" for an attack without a logon)
  - new sources: Sysmon, Zeek conn.log and the mail gateway, with their rules
Run from backend/:  python -m pytest soc/tests -q
"""
import json
from datetime import datetime, timedelta, timezone

from soc.correlate import correlate, link_reason
from soc.detect import enrich, load_rules, run_rules
from soc.health import check
from soc.parsers import PARSERS
from soc.pipeline import RULES_DIR

T0 = datetime(2026, 11, 22, 10, 0, tzinfo=timezone.utc)
BASELINE_END = T0 - timedelta(hours=10)
ASSETS = {"assets": [{"host": "web", "ip": "10.1.0.10", "role": "public web portal", "criticality": 3},
                     {"host": "ws1", "ip": "10.1.3.1", "role": "operator workstation", "criticality": 2},
                     {"host": "mail", "ip": "10.1.0.20", "role": "mail gateway", "criticality": 3}],
          "internal_nets": ["10.0.0.0/8"], "public_services": [{"host": "web", "ports": [443]}]}


def _net(n, src, port, host="web", direction="inbound", t=T0, action="allow", **kw):
    return {"id": f"t:{n}", "time": t + timedelta(minutes=n), "source": "t", "type": "network", "action": action,
            "direction": direction, "host": host, "src_ip": src, "dst_ip": "10.1.0.10", "dst_port": port, "raw": "x", "line": n, **kw}


def _alerts(evs, baseline_end=BASELINE_END):
    enrich(evs, ASSETS)
    return run_rules(evs, load_rules(RULES_DIR), baseline_end)


def _parse(tmp_path, parser, text, **src):
    p = tmp_path / "log"
    p.write_text(text, encoding="utf-8")
    stats = {"skipped": 0, "errors": 0, "times": []}
    return list(PARSERS[parser](p, {"name": "t", "path": "log", **src}, stats)), stats


# ----------------------------------------------------------------- 1. public services
def test_visitors_on_public_port_are_not_new_inbound_connections():
    evs = [_net(i, f"192.0.2.{i}", 443) for i in range(1, 40)]
    assert not [a for a in _alerts(evs) if a["rule"] == "NET-002"]


def test_outside_to_a_non_public_port_still_alerts():
    hits = [a for a in _alerts([_net(1, "198.51.100.23", 22)]) if a["rule"] == "NET-002"]
    assert len(hits) == 1 and hits[0]["unknown_ips"] == ["198.51.100.23"]


# ----------------------------------------------------------------- 2. correlation safety
def _alert(rule, sev, hosts, users=(), ips=(), minute=0):
    t = T0 + timedelta(minutes=minute)
    return {"id": f"{rule}@{minute}", "rule": rule, "title": rule, "short": rule, "text": "", "severity": sev, "attack": ["T1021"],
            "time": t, "time_end": t, "hosts": list(hosts), "users": list(users), "unknown_ips": list(ips),
            "evidence": [{"id": f"s:{minute}", "source": "s"}], "count": 1}


def test_weak_alerts_do_not_link_by_host_alone():
    assert link_reason(_alert("NET-002", 4, ["web"], ips=["192.0.2.1"]), _alert("NET-002", 4, ["web"], ips=["192.0.2.2"], minute=5)) is None
    assert link_reason(_alert("NET-002", 4, ["web"], ips=["192.0.2.1"]), _alert("AUTH-003", 5, ["web"], ips=["192.0.2.1"], minute=1))
    assert link_reason(_alert("AUTH-001", 6, ["ws1"]), _alert("SYS-003", 6, ["ws1"], minute=10)) == "same host ws1"


def test_a_flood_of_weak_alerts_is_not_an_incident():
    flood = [_alert("NET-002", 4, ["web"], ips=[f"192.0.2.{i}"], minute=i) for i in range(50)]
    incidents, singles = correlate(flood, ASSETS, [], T0 + timedelta(hours=2))
    assert not incidents and len(singles) == 50


# ----------------------------------------------------------------- 3. source health
def _stats(name, times):
    return [{"source": name, "host": "h", "times": times}]


def test_quiet_every_night_is_not_silent():
    day = [BASELINE_END - timedelta(days=1) + timedelta(hours=8, minutes=5 * i) for i in range(108)]      # 08:00-17:00
    day2 = [t + timedelta(days=1) for t in day]
    h = check([], [{"name": "fw", "expected_every_min": 60}], _stats("fw", day + day2), BASELINE_END, day2[-1] + timedelta(hours=6))
    assert h[0]["ok"], h[0]["silent"]


def test_stopping_while_normally_busy_is_silent():
    base = [BASELINE_END - timedelta(days=1) + timedelta(minutes=2 * i) for i in range(720)]             # all day
    after = [BASELINE_END + timedelta(minutes=2 * i) for i in range(60)] + \
            [BASELINE_END + timedelta(hours=4, minutes=2 * i) for i in range(60)]                     # gap 02:00-04:00
    h = check([], [{"name": "fw", "expected_every_min": 15}], _stats("fw", base + after), BASELINE_END, after[-1])
    assert len(h[0]["silent"]) == 1 and h[0]["silent"][0]["minutes"] >= 120


def test_low_volume_source_is_not_silent_for_an_idle_afternoon():
    base = [BASELINE_END - timedelta(days=1) + timedelta(hours=9 + i) for i in range(8)]                 # 8 lines a day
    after = [BASELINE_END + timedelta(hours=9)]
    h = check([], [{"name": "print", "expected_every_min": 60}], _stats("print", base + after), BASELINE_END,
              BASELINE_END + timedelta(hours=23))
    assert h[0]["ok"], h[0]["silent"]


# ----------------------------------------------------------------- 4. titles
def test_title_says_password_guessing_not_remote_logon():
    a = [_alert("AUTH-003", 5, ["web"], ips=["198.51.100.23"]), _alert("NET-002", 4, ["web"], ips=["198.51.100.23"], minute=1)]
    a[0]["attack"], a[0]["short"] = ["T1110.001"], "Password guessing"
    a[1]["short"] = "new inbound connection"
    incidents, _ = correlate(a, ASSETS, [], T0 + timedelta(hours=1))
    assert incidents[0]["title"].startswith("Password guessing") and "Remote logon" not in incidents[0]["title"]


# ----------------------------------------------------------------- 5. new sources
SYSMON = {"TimeCreated": "2026-11-22T13:14:52.000Z", "Id": 1, "LogName": "Microsoft-Windows-Sysmon/Operational", "MachineName": "ws1",
          "EventData": {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "User": "BASE\\h.rexhepi",
                        "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA",
                        "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"}}


def test_sysmon_parser_and_office_spawns_powershell(tmp_path):
    evs, stats = _parse(tmp_path, "windows_sysmon", json.dumps(SYSMON) + "\n")
    assert stats["errors"] == 0 and evs[0]["user"] == "h.rexhepi" and evs[0]["parent"].endswith("WINWORD.EXE")
    rules = {a["rule"] for a in _alerts(evs)}
    assert {"PROC-001", "PROC-002"} <= rules


def test_inventory_powershell_by_system_is_not_an_alert(tmp_path):
    ok = {**SYSMON, "EventData": {"Image": SYSMON["EventData"]["Image"], "User": "NT AUTHORITY\\SYSTEM",
                                  "CommandLine": "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\\\FS-01\\it$\\inventory.ps1",
                                  "ParentImage": "C:\\Windows\\System32\\svchost.exe"}}
    evs, _ = _parse(tmp_path, "windows_sysmon", json.dumps(ok) + "\n")
    assert not [a for a in _alerts(evs) if a["rule"].startswith("PROC")]


def test_zeek_json_and_tsv(tmp_path):
    js = {"ts": 1795313167.0, "uid": "C1", "id.orig_h": "10.1.3.1", "id.orig_p": 5000, "id.resp_h": "10.1.0.10", "id.resp_p": 4444,
          "proto": "tcp", "conn_state": "SF"}
    evs, stats = _parse(tmp_path, "zeek_conn", json.dumps(js) + "\n", host="sensor")
    assert stats["errors"] == 0 and (evs[0]["action"], evs[0]["dst_port"], evs[0]["sensor"]) == ("flow", 4444, True)
    tsv = "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\n" \
          "1795313167.0\tC2\t10.1.3.1\t5000\t10.1.0.10\t22\ttcp\tREJ\n"
    evs, _ = _parse(tmp_path, "zeek_conn", tsv, host="sensor")
    assert (evs[0]["dst_port"], evs[0]["outcome"]) == (22, "failure")


def test_beaconing_seen_by_the_sensor():
    evs = [{"id": f"z:{i}", "time": T0 + timedelta(minutes=5 * i), "source": "z", "type": "network", "action": "flow", "outcome": "success",
            "host": "sensor", "sensor": True, "src_ip": "10.1.3.1", "dst_ip": "203.0.113.77", "dst_port": 443, "raw": "x", "line": i}
           for i in range(8)]
    hits = [a for a in _alerts(evs) if a["rule"] == "NET-005"]
    assert hits and "ws1" in hits[0]["hosts"] and "sensor" not in hits[0]["hosts"]


def test_mail_with_macro_attachment_delivered_vs_quarantined(tmp_path):
    rec = {"ts": "2026-11-22T13:02:11.000Z", "direction": "inbound", "client_ip": "203.0.113.140", "from": "x@bad.example",
           "to": ["h.rexhepi@base.example"], "subject": "schedule", "attachments": [{"name": "Gate.docm"}], "verdict": "suspicious",
           "action": "delivered", "score": 4.2}
    q = {**rec, "action": "quarantined", "attachments": [{"name": "Invoice.zip"}]}
    evs, stats = _parse(tmp_path, "mail_gateway", json.dumps(rec) + "\n" + json.dumps(q) + "\n", host="mail")
    assert stats["errors"] == 0 and evs[0]["user"] == "h.rexhepi"
    hits = [a for a in _alerts(evs) if a["rule"] == "MAIL-001"]
    assert len(hits) == 1 and hits[0]["users"] == ["h.rexhepi"]


def test_unknown_parser_name_is_reported_not_a_crash(tmp_path):
    from soc.parsers import read_all
    (tmp_path / "x.log").write_text("hello\n", encoding="utf-8")
    events, stats = read_all([{"name": "x", "parser": "no_such_parser", "path": "x.log"}], tmp_path)
    assert events == [] and stats[0]["errors"] == 1 and "no_such_parser" in stats[0]["note"]
