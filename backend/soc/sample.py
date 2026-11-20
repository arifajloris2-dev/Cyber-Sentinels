"""Sample logs for testing, until real logs exist: one Windows laptop + one Ubuntu server, 48 hours, real raw formats.

  WIN-01  Windows laptop   (workstation)          win01_events.jsonl, win01_pfirewall.log
  UBU-01  Ubuntu server    (gate-control server)  ubu01_auth.log, ubu01_ufw.log, ubu01_syslog, ubu01_dpkg.log

Day 1: normal work only (learned as the baseline).
Day 2: normal work, plus during the night shift:
  02:05-02:09  3 failed RDP logons on WIN-01 from an unknown address, then success          T1110 / T1078
  02:15-02:16  WIN-01 opens SSH to UBU-01 (never seen before); j.krasniqi logs on there     T1021
  02:20-02:23  on UBU-01 via sudo: new service 'gatesync', firewall opened, new account     T1543 / T1562 / T1136
  At the same time: approved patching CHG-1042 01:00-02:40 on both machines (Windows Update, apt upgrade)
  03:00 daily backup of UBU-01 to the NAS (CHG-BACKUP)
  02:25-05:40 UBU-01's firewall log (ufw.log) is silent
truth.json lists which lines belong to the attack, the patching and the backup.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

DAY1 = datetime(2026, 11, 17, tzinfo=timezone.utc)
DAY2 = DAY1 + timedelta(days=1)
LOCAL = timezone(timedelta(hours=1))     # the firewall and dpkg logs are written in local time (UTC+1)
WIN = {"host": "WIN-01", "ip": "10.20.50.17", "user": "j.krasniqi"}
UBU = {"host": "ubu-01", "ip": "10.20.30.5"}
ATTACKER, JUMP, NAS, UPDATES, DNS, PROXY, FILES = "10.20.0.99", "10.20.0.10", "10.20.0.50", "10.20.0.40", "10.20.0.2", "10.20.0.8", "10.20.20.30"
GATES = ["10.20.60.11", "10.20.60.12", "10.20.60.13", "10.20.60.14"]


class Logs:
    def __init__(self):
        self.files = {}           # file name -> list of (time, text, label)

    def add(self, name, t, text, label=None):
        self.files.setdefault(name, []).append((t, text, label))

    # ---- Windows
    def win(self, t, eid, data, log="Security", label=None):
        rec = {"TimeCreated": t.strftime("%Y-%m-%dT%H:%M:%S.000Z"), "Id": eid, "LogName": log, "MachineName": WIN["host"], "EventData": data}
        self.add("win01_events.jsonl", t, json.dumps(rec), label)

    def wfw(self, t, action, proto, src, dst, sport, dport, direction, label=None):
        lt = t.astimezone(LOCAL)
        self.add("win01_pfirewall.log", t, f"{lt:%Y-%m-%d %H:%M:%S} {action} {proto} {src} {dst} {sport} {dport} 0 - 0 0 0 - - - {direction}", label)

    # ---- Ubuntu (24.04 style timestamps)
    def ubu(self, name, t, prog, msg, label=None):
        self.add(name, t, f"{t:%Y-%m-%dT%H:%M:%S.%f}+00:00 {UBU['host']} {prog}: {msg}", label)

    def ufw(self, t, act, src, dst, spt, dpt, inbound=True, label=None):
        io = "IN=eth0 OUT=" if inbound else "IN= OUT=eth0"
        self.ubu("ubu01_ufw.log", t, "kernel", f"[{random.randint(1000, 99999)}.{random.randint(100, 999)}] [UFW {act}] {io} "
                 f"MAC=00:15:5d:01:02:03 SRC={src} DST={dst} LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID={random.randint(1, 65000)} DF "
                 f"PROTO=TCP SPT={spt} DPT={dpt} WINDOW=64240 RES=0x00 SYN URGP=0", label)

    def dpkg(self, t, pkg, old, new, label=None):
        self.add("ubu01_dpkg.log", t, f"{t.astimezone(LOCAL):%Y-%m-%d %H:%M:%S} upgrade {pkg}:amd64 {old} {new}", label)


def generate(out: Path, seed: int = 7, attack: bool = True, gap: bool = True) -> dict:
    random.seed(seed)
    rng = random.Random(seed)
    L = Logs()

    def at(day, h, m=0, s=0):
        return day + timedelta(hours=h, minutes=m, seconds=s)

    L.ubu("ubu01_syslog", at(DAY1, 0, 0, 5), "systemd[1]", "Started ssh.service - OpenBSD Secure Shell server.")
    L.ubu("ubu01_syslog", at(DAY1, 0, 0, 6), "systemd[1]", "Started gate-control.service - Gate control service.")
    for day in (DAY1, DAY2):
        # ======== WIN-01: an operator's laptop
        L.win(at(day, 7, 50 + rng.randint(0, 9)), 4624, {"TargetUserName": WIN["user"], "IpAddress": "-", "LogonType": "2"})
        L.win(at(day, 13, 2), 4625, {"TargetUserName": WIN["user"], "IpAddress": "-", "LogonType": "7"})        # typo, harmless
        L.win(at(day, 13, 2, 9), 4624, {"TargetUserName": WIN["user"], "IpAddress": "-", "LogonType": "7"})
        L.win(at(day, 10, 5), 4624, {"TargetUserName": "adm.ops", "IpAddress": JUMP, "LogonType": "3"})       # admin tools
        for _ in range(40):
            L.win(at(day, rng.uniform(0, 24)), 4624, {"TargetUserName": "SYSTEM", "IpAddress": "-", "LogonType": "5"})
        for h in range(24):
            busy = 8 <= h < 18
            for _ in range(rng.randint(20, 30) if busy else rng.randint(3, 6)):
                L.wfw(at(day, h, rng.uniform(0, 60)), "ALLOW", "UDP", WIN["ip"], DNS, rng.randint(49152, 65000), 53, "SEND")
            for _ in range(rng.randint(8, 15) if busy else rng.randint(0, 2)):
                L.wfw(at(day, h, rng.uniform(0, 60)), "ALLOW", "TCP", WIN["ip"], rng.choice([PROXY, FILES]), rng.randint(49152, 65000),
                      rng.choice([8080, 445]), "SEND")
            if rng.random() < 0.3:
                L.wfw(at(day, h, rng.uniform(0, 60)), "DROP", "UDP", f"10.20.50.{rng.randint(20, 90)}", WIN["ip"], 137, 137, "RECEIVE")
        # ======== UBU-01: the gate-control server
        L.ubu("ubu01_auth.log", at(day, 11, 20), "sshd[1201]", f"Accepted publickey for adm.ops from {JUMP} port 51515 ssh2: ED25519 SHA256:k3y")
        L.ubu("ubu01_auth.log", at(day, 11, 21), "sudo", "adm.ops : TTY=pts/0 ; PWD=/home/adm.ops ; USER=root ; COMMAND=/usr/bin/systemctl status gate-control")
        L.ubu("ubu01_auth.log", at(day, 15, 40), "sshd[1300]", f"Failed password for invalid user test from 10.20.50.{rng.randint(60, 90)} port 40022 ssh2")
        for h in range(24):
            L.ubu("ubu01_auth.log", at(day, h, 17), "CRON[900]", "pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)")
        for m in range(0, 24 * 60, 2):          # gate controllers poll the server (Modbus/TCP 502)
            L.ufw(day + timedelta(minutes=m, seconds=rng.uniform(0, 59)), "ALLOW", GATES[(m // 2) % 4], UBU["ip"], rng.randint(1024, 4000), 502)
        for _ in range(rng.randint(2, 5)):
            L.ufw(at(day, rng.uniform(0, 24)), "BLOCK", f"10.20.50.{rng.randint(60, 90)}", UBU["ip"], rng.randint(40000, 60000), 23)
        for svc, h in (("logrotate", 0.01), ("apt-daily", 6.2), ("apt-daily-upgrade", 6.6), ("man-db", 0.02), ("sysstat-collect", 12)):
            L.ubu("ubu01_syslog", at(day, h), "systemd[1]", f"Started {svc}.service - {svc}.")
        # ======== daily backup 03:00 (approved, CHG-BACKUP)
        L.ubu("ubu01_syslog", at(day, 3, 0, 1), "systemd[1]", "Started backup-rsync.service - Nightly backup.", "backup")
        for k in range(20):
            L.ufw(at(day, 3, 0, 5 + 9 * k), "ALLOW", UBU["ip"], NAS, 50000 + k, 873, inbound=False, label="backup")

    # ======== day 2: approved patching CHG-1042 01:00-02:40 on both machines
    for k in range(5):
        t = at(DAY2, 1, 5 + 8 * k)
        L.wfw(t, "ALLOW", "TCP", WIN["ip"], UPDATES, 51000 + k, 8530, "SEND", "patch")
        L.win(t + timedelta(minutes=2), 19, {"updateTitle": f"2026-11 Cumulative Update KB50{40 + k}11"}, "System", "patch")
    for k, svc in enumerate(["Microsoft Edge Update Service (edgeupdate)", "Windows Update Medic Service"]):
        L.win(at(DAY2, 1, 30 + 25 * k), 7045, {"ServiceName": svc, "ImagePath": "C:\\Program Files\\Microsoft\\Update\\svc.exe",
                                                 "AccountName": "LocalSystem"}, "System", "patch")
    L.win(at(DAY2, 2, 21), 4947, {"SubjectUserName": "SYSTEM", "RuleName": "Windows Update Delivery Optimization"}, label="patch")
    for k, (pkg, old, new) in enumerate([("openssl", "3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5"), ("libssl3t64", "3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5"),
                                         ("openssh-server", "1:9.6p1-3ubuntu13.5", "1:9.6p1-3ubuntu13.8"), ("systemd", "255.4-1ubuntu8.4", "255.4-1ubuntu8.6"),
                                         ("fwupd", "1.9.24-1", "1.9.27-1")]):
        t = at(DAY2, 1, 10 + 6 * k)
        L.ufw(t, "ALLOW", UBU["ip"], UPDATES, 52000 + k, 80, inbound=False, label="patch")
        L.dpkg(t + timedelta(seconds=40), pkg, old, new, "patch")
    L.ubu("ubu01_syslog", at(DAY2, 1, 29), "systemd[1]", "Started ssh.service - OpenBSD Secure Shell server.", "patch")
    L.ubu("ubu01_syslog", at(DAY2, 1, 40), "systemd[1]", "Started fwupd-refresh.service - Refresh fwupd metadata.", "patch")

    # ======== day 2: the attack
    if attack:
        for k in range(3):
            L.win(at(DAY2, 2, 5 + k, 7), 4625, {"TargetUserName": WIN["user"], "IpAddress": ATTACKER, "LogonType": "10"}, label="attack:entry")
        L.win(at(DAY2, 2, 9, 2), 4624, {"TargetUserName": WIN["user"], "IpAddress": ATTACKER, "LogonType": "10"}, label="attack:entry")
        L.wfw(at(DAY2, 2, 15, 1), "ALLOW", "TCP", WIN["ip"], UBU["ip"], 53122, 22, "SEND", "attack:lateral")
        L.ufw(at(DAY2, 2, 15, 2), "ALLOW", WIN["ip"], UBU["ip"], 53122, 22, label="attack:lateral")
        L.ubu("ubu01_auth.log", at(DAY2, 2, 16), "sshd[2211]", f"Accepted password for {WIN['user']} from {WIN['ip']} port 53122 ssh2", "attack:lateral")
        sudo = f"{WIN['user']} : TTY=pts/1 ; PWD=/home/{WIN['user']} ; USER=root ; COMMAND="
        L.ubu("ubu01_auth.log", at(DAY2, 2, 20), "sudo", sudo + "/usr/bin/systemctl enable --now gatesync.service", "attack:impact")
        L.ubu("ubu01_syslog", at(DAY2, 2, 20, 1), "systemd[1]", "Started gatesync.service - Gate sync agent.", "attack:impact")
        L.ubu("ubu01_auth.log", at(DAY2, 2, 22, 30), "sudo", sudo + "/usr/sbin/ufw allow 4444/tcp", "attack:impact")
        L.ubu("ubu01_auth.log", at(DAY2, 2, 23, 10), "sudo", sudo + "/usr/sbin/useradd -m -s /bin/bash svc-sync", "attack:impact")
        L.ubu("ubu01_auth.log", at(DAY2, 2, 23, 10), "useradd[2301]", "new user: name=svc-sync, UID=1002, GID=1002, home=/home/svc-sync, shell=/bin/bash", "attack:impact")

    # ======== day 2: UBU-01's firewall log goes silent
    silent = (at(DAY2, 2, 25), at(DAY2, 5, 40))
    if gap:
        L.files["ubu01_ufw.log"] = [r for r in L.files["ubu01_ufw.log"] if not (silent[0] <= r[0] < silent[1])]

    # ======== write files, answer key and settings
    out.mkdir(parents=True, exist_ok=True)
    names = {"win01_events.jsonl": "win01-events", "win01_pfirewall.log": "win01-firewall", "ubu01_auth.log": "ubu01-auth",
             "ubu01_ufw.log": "ubu01-firewall", "ubu01_syslog": "ubu01-syslog", "ubu01_dpkg.log": "ubu01-dpkg"}
    truth = {"attack": [], "patch": [], "backup": [], "attacker_ip": ATTACKER, "user": WIN["user"], "hosts": [WIN["host"], UBU["host"]],
             "last_attack_event": at(DAY2, 2, 23, 10).isoformat(), "silent": {"source": "ubu01-firewall", "from": silent[0].isoformat()} if gap else None}
    for fname, rows in L.files.items():
        header = ["#Version: 1.5", "#Software: Microsoft Windows Firewall", "#Time Format: Local",
                  "#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path"] \
            if fname.endswith("pfirewall.log") else []
        rows = sorted(rows, key=lambda r: r[0])
        with open(out / fname, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("".join(h + "\n" for h in header))
            for n, (_, text, label) in enumerate(rows, len(header) + 1):
                fh.write(text + "\n")
                if label:
                    kind, _, step = label.partition(":")
                    truth[kind].append({"id": f"{names[fname]}:{n}", "step": step or None})
    (out / "truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
    _settings(out, names)
    return truth


def _settings(out: Path, names: dict):
    parser = {"win01_events.jsonl": "windows_events", "win01_pfirewall.log": "windows_firewall", "ubu01_auth.log": "linux_auth",
              "ubu01_ufw.log": "linux_ufw", "ubu01_syslog": "linux_syslog", "ubu01_dpkg.log": "linux_dpkg"}
    host = {"win01": WIN["host"], "ubu01": UBU["host"]}
    every = {"win01_events.jsonl": 120, "win01_pfirewall.log": 30, "ubu01_auth.log": 90, "ubu01_ufw.log": 10, "ubu01_syslog": 720, "ubu01_dpkg.log": 10080}
    sources = {"baseline_hours": 24, "sources": [
        {"name": names[f], "parser": parser[f], "path": f, "host": host[f[:5]], "expected_every_min": every[f],
         **({"utc_offset": "+01:00"} if f in ("win01_pfirewall.log", "ubu01_dpkg.log") else {})} for f in parser]}
    assets = {"night_hours": [20, 6], "admin_ips": [JUMP], "assets": [
        {"host": WIN["host"], "ip": WIN["ip"], "os": "windows", "role": "operator workstation", "criticality": 2},
        {"host": UBU["host"], "ip": UBU["ip"], "os": "linux", "role": "gate-control server", "criticality": 5},
        {"host": "jump-01", "ip": JUMP, "role": "admin jump host", "criticality": 4},
        {"host": "nas-01", "ip": NAS, "role": "backup storage", "criticality": 4},
        {"host": "updates-01", "ip": UPDATES, "role": "patch server (WSUS + apt mirror)", "criticality": 3},
        {"host": "dns-01", "ip": DNS, "role": "DNS", "criticality": 3},
        {"host": "proxy-01", "ip": PROXY, "role": "web proxy", "criticality": 3},
        {"host": "files-01", "ip": FILES, "role": "file server", "criticality": 3}]
        + [{"host": f"gate-{i + 1}", "ip": ip, "role": "gate controller", "criticality": 5} for i, ip in enumerate(GATES)]}
    maintenance = {"tickets": [
        {"id": "CHG-1042", "title": "Monthly patching (Windows Update + apt)", "hosts": [WIN["host"], UBU["host"]],
         "start": f"{DAY2.date()}T01:00:00+00:00", "end": f"{DAY2.date()}T02:40:00+00:00",
         "allow": [{"action": "update-installed"},
                   {"action": "service-installed", "user": ["LocalSystem", "SYSTEM"], "path|startswith": ["C:\\Program Files\\", "C:\\Windows\\"]},
                   {"action": "firewall-change", "user": ["SYSTEM"]},
                   {"action": "service-started", "service": ["ssh", "fwupd-refresh", "packagekit", "unattended-upgrades"]},
                   {"type": "network", "dst_ip": [UPDATES]}]},
        {"id": "CHG-BACKUP", "title": "Nightly backup to nas-01", "hosts": [UBU["host"]], "daily": ["02:55", "03:30"],
         "allow": [{"service": ["backup-rsync"]}, {"type": "network", "dst_ip": [NAS]}]}]}
    for name, obj in (("sources.yaml", sources), ("assets.yaml", assets), ("maintenance.yaml", maintenance)):
        (out / name).write_text(yaml.safe_dump(obj, sort_keys=False, allow_unicode=True), encoding="utf-8")
