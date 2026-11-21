"""Log parsers: one function per log type, all producing events in the common format (see events.py).

Windows:  windows_events    Security/System events exported as JSON lines (collect/collect_windows.ps1)
          windows_firewall  %SystemRoot%\\System32\\LogFiles\\Firewall\\pfirewall.log
Ubuntu:   linux_auth        /var/log/auth.log     (SSH logons, sudo commands, new users)
          linux_ufw         /var/log/ufw.log      (firewall allow/block)
          linux_syslog      /var/log/syslog       (services started by systemd)
          linux_dpkg        /var/log/dpkg.log     (packages installed/upgraded = patching)

To support a new device: write one function `parse_x(path, src) -> iterator of events` and add it to PARSERS.
Lines a parser does not understand are counted (stats["skipped"]), never silently lost.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .events import make_event, parse_time


def _seen(stats: dict, ts, offset=None):
    """Every readable line proves the log is alive, even if no rule cares about it (used by the health check)."""
    try:
        stats["times"].append(parse_time(ts, offset))
    except ValueError:
        pass


# ======================================================================= Windows
WIN_LOGON = {"2": "local", "3": "network", "5": "service", "7": "unlock", "10": "remote", "11": "local"}
WIN_EVENTS = {   # event id -> (type, action, outcome)
    4624: ("auth", "logon", "success"), 4625: ("auth", "logon", "failure"), 4648: ("auth", "explicit-logon", "success"),
    4672: ("auth", "admin-logon", "success"), 4697: ("config", "service-installed", "success"),
    7045: ("config", "service-installed", "success"), 4946: ("config", "firewall-change", "success"),
    4947: ("config", "firewall-change", "success"), 4948: ("config", "firewall-change", "success"),
    4950: ("config", "firewall-change", "success"), 4719: ("config", "audit-change", "success"),
    1102: ("config", "log-cleared", "success"), 4720: ("config", "account-created", "success"),
    19: ("update", "update-installed", "success"), 4698: ("config", "task-created", "success"),
    4768: ("auth", "kerberos-tgt", "success"), 4769: ("auth", "kerberos-service-ticket", "success"),
    4728: ("config", "group-member-added", "success"), 4732: ("config", "group-member-added", "success"),
    4756: ("config", "group-member-added", "success"), 5140: ("file", "share-access", "success"),
}
GROUP_ADD = {4728, 4732, 4756}


def _account_name(value):
    """'j.osmani@BASE.EXAMPLE' -> 'j.osmani'; 'CN=svc_upd,OU=Users,DC=base' -> 'svc_upd'; 'BASE\\x' -> 'x'."""
    if not value:
        return None
    v = str(value)
    if v.upper().startswith("CN="):
        v = v[3:].split(",", 1)[0]
    return v.split("@", 1)[0].rsplit("\\", 1)[-1] or None


def _ip(value):
    v = str(value or "").strip()
    v = v[7:] if v.lower().startswith("::ffff:") else v
    return None if v in ("", "-", "::1", "127.0.0.1") else v


def parse_windows_events(path: Path, src: dict, stats: dict):
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
                _seen(stats, r["TimeCreated"])
                eid = int(r["Id"])
                kind = WIN_EVENTS.get(eid)
                if not kind:
                    stats["skipped"] += 1
                    continue
                d = r.get("EventData") or {}
                extra = {}
                user = d.get("TargetUserName") or d.get("SubjectUserName") or d.get("AccountName")
                detail = (f"new account {d.get('TargetUserName')}" if eid == 4720 else None) \
                    or d.get("RuleName") or d.get("updateTitle") or d.get("TaskName") or d.get("TargetServerName")
                if eid in GROUP_ADD:          # who added whom to which group (TargetUserName is the GROUP here)
                    member = _account_name(d.get("MemberName")) or d.get("MemberSid")
                    user, extra = d.get("SubjectUserName"), {"group": d.get("TargetUserName"), "member": member}
                    detail = f"{member} added to {d.get('TargetUserName')} by {d.get('SubjectUserName')}"
                elif eid in (4768, 4769):     # Kerberos: who asked, for which service, with which encryption
                    user = _account_name(d.get("TargetUserName"))
                    extra = {"ticket_enc": str(d.get("TicketEncryptionType", "")).lower() or None, "status": d.get("Status")}
                    detail = f"{d.get('ServiceName') or 'TGT'} ({extra['ticket_enc']})"
                elif eid == 5140:             # a network share was opened (ADMIN$ / C$ = remote administration)
                    user, extra = d.get("SubjectUserName"), {"share": d.get("ShareName")}
                    detail = d.get("ShareName")
                elif eid == 4624:
                    extra = {"auth_package": d.get("AuthenticationPackageName"), "logon_process": d.get("LogonProcessName"),
                             "key_length": d.get("KeyLength")}
                yield make_event(src["name"], n, line, src["path"], r["TimeCreated"], os="windows", host=r.get("MachineName"),
                                 type=kind[0], action=kind[1], outcome=kind[2], code=eid, user=_account_name(user) if eid in (4768, 4769) else user,
                                 src_ip=_ip(d.get("IpAddress")),
                                 logon=WIN_LOGON.get(str(d.get("LogonType", "")), None),
                                 service=d.get("ServiceName"), path=d.get("ImagePath") or d.get("ServiceFileName") or d.get("ApplicationPath"),
                                 detail=detail, **extra)
            except (ValueError, KeyError, TypeError):
                stats["errors"] += 1


def parse_windows_firewall(path: Path, src: dict, stats: dict):
    cols = []
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if line.startswith("#Fields:"):
                cols = line.split(":", 1)[1].split()
                continue
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != len(cols):
                stats["errors"] += 1
                continue
            r = dict(zip(cols, parts))
            _seen(stats, f"{r['date']} {r['time']}", src.get("utc_offset"))
            if r["action"] not in ("ALLOW", "DROP"):
                stats["skipped"] += 1
                continue
            yield make_event(src["name"], n, line, src["path"], f"{r['date']} {r['time']}", src.get("utc_offset"), os="windows",
                             host=src.get("host"), type="network", action="allow" if r["action"] == "ALLOW" else "block",
                             outcome="success" if r["action"] == "ALLOW" else "failure",
                             proto=r["protocol"].lower(), src_ip=r["src-ip"], dst_ip=r["dst-ip"], src_port=_int(r["src-port"]),
                             dst_port=_int(r["dst-port"]), direction={"SEND": "outbound", "RECEIVE": "inbound"}.get(r.get("path")))


# ======================================================================= Ubuntu (syslog-style lines)
# Ubuntu 24.04+:  2026-11-18T02:16:00.123456+00:00 ubu-01 sshd[2211]: message
# older Ubuntu:   Nov 18 02:16:00 ubu-01 sshd[2211]: message           (no year, no zone: set year/utc_offset)
SYSLOG = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\dT\S+|[A-Z][a-z]{2}\s+\d+\s\d\d:\d\d:\d\d)\s+(?P<host>\S+)\s+"
                    r"(?P<prog>[\w\-.@/]+)(?:\[\d+\])?:\s(?P<msg>.*)$")


def _syslog_lines(path: Path, src: dict, stats: dict):
    year = src.get("year", datetime.now().year)
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            m = SYSLOG.match(line.rstrip("\n"))
            if not m:
                stats["errors"] += 1
                continue
            ts = m["ts"]
            if not ts[0].isdigit():
                ts = datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")
            _seen(stats, ts, src.get("utc_offset"))
            yield n, line, ts, m["host"], m["prog"], m["msg"]


AUTH_FAIL = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)")
AUTH_OK = re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (\S+) from (\S+) port (\d+)")
SUDO = re.compile(r"^\s*(\S+) : .*COMMAND=(.*)$")
NEW_USER = re.compile(r"new user: name=([^,\s]+)")
ROOT_SHELL = re.compile(r"^(/usr)?/bin/(ba|z|da)?sh( -i| -l)?$|^(/usr/bin/)?su( -| root| - root)?$|^(/usr/bin/)?sudo -i$")


def parse_linux_auth(path: Path, src: dict, stats: dict):
    off = src.get("utc_offset")
    for n, line, ts, host, prog, msg in _syslog_lines(path, src, stats):
        base = dict(os="linux", host=host)
        if prog == "sshd" and (m := AUTH_FAIL.search(msg) or AUTH_OK.search(msg)):
            ok = msg.startswith("Accepted")
            yield make_event(src["name"], n, line, src["path"], ts, off, **base, type="auth", action="logon",
                             outcome="success" if ok else "failure", user=m[1], src_ip=m[2], logon="ssh")
        elif prog == "sudo" and (m := SUDO.search(msg)):
            cmd = m[2].strip()
            run_as = (re.search(r"USER=(\S+)", msg) or [None, None])[1]
            extra = {"run_as": run_as}
            if re.search(r"\b(ufw|iptables|nft)\b", cmd):
                act = "firewall-change"
            elif re.search(r"\b(useradd|adduser)\b", cmd):
                act = "account-created"
            elif (g := re.search(r"\b(?:usermod\s+.*-a?G\s+\S*\b(sudo|wheel|admin)\b|gpasswd\s+-a\s+\S+\s+(sudo|wheel|admin))", cmd)):
                act = "group-member-added"
                extra.update(group=g[1] or g[2], member=cmd.split()[-1] if g[1] else cmd.split()[-2])
            elif run_as == "root" and ROOT_SHELL.match(cmd):
                act = "root-shell"
            elif "authorized_keys" in cmd:
                act = "ssh-key-added"
            else:
                act = "sudo"
            yield make_event(src["name"], n, line, src["path"], ts, off, **base,
                             type="admin" if act in ("sudo", "root-shell") else "config",
                             action=act, outcome="success", user=m[1], detail=cmd, **extra)
        elif prog in ("useradd", "adduser") and (m := NEW_USER.search(msg)):
            yield make_event(src["name"], n, line, src["path"], ts, off, **base, type="config", action="account-created",
                             outcome="success", user=m[1], detail=f"new account {m[1]}")
        else:
            stats["skipped"] += 1


UFW = re.compile(r"\[UFW (?P<act>BLOCK|ALLOW|AUDIT)\] IN=(?P<in>\S*) OUT=(?P<out>\S*).*?SRC=(?P<src>\S+) DST=(?P<dst>\S+)"
                 r".*?PROTO=(?P<proto>\S+)(?:.*?SPT=(?P<spt>\d+) DPT=(?P<dpt>\d+))?")


def parse_linux_ufw(path: Path, src: dict, stats: dict):
    for n, line, ts, host, prog, msg in _syslog_lines(path, src, stats):
        m = UFW.search(msg)
        if not m or m["act"] == "AUDIT":
            stats["skipped"] += 1
            continue
        yield make_event(src["name"], n, line, src["path"], ts, src.get("utc_offset"), os="linux", host=host, type="network",
                         action="allow" if m["act"] == "ALLOW" else "block", outcome="success" if m["act"] == "ALLOW" else "failure",
                         proto=m["proto"].lower(), src_ip=m["src"],
                         dst_ip=m["dst"], src_port=_int(m["spt"]), dst_port=_int(m["dpt"]),
                         direction="inbound" if m["in"] and not m["out"] else "outbound" if m["out"] and not m["in"] else None)


STARTED = re.compile(r"^Started (\S+?)\.service")


def parse_linux_syslog(path: Path, src: dict, stats: dict):
    for n, line, ts, host, prog, msg in _syslog_lines(path, src, stats):
        if prog == "systemd" and (m := STARTED.match(msg)):
            yield make_event(src["name"], n, line, src["path"], ts, src.get("utc_offset"), os="linux", host=host, type="config",
                             action="service-started", outcome="success", service=m[1])
        else:
            stats["skipped"] += 1


DPKG = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (install|upgrade) (\S+?)(?::\S+)? (\S+) (\S+)$")


def parse_linux_dpkg(path: Path, src: dict, stats: dict):
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            m = DPKG.match(line.strip())
            if m:
                _seen(stats, m[1], src.get("utc_offset"))
            if not m:
                stats["skipped"] += 1
                continue
            yield make_event(src["name"], n, line, src["path"], m[1], src.get("utc_offset"), os="linux", host=src.get("host"),
                             type="update", action="update-installed", outcome="success", detail=f"{m[2]} {m[3]} {m[4]} -> {m[5]}")


def _int(v):
    return int(v) if v is not None and str(v).isdigit() else None


# ======================================================================= Sysmon (Windows, JSON lines like windows_events)
def _account(u):
    """'BASE\\h.rexhepi' -> 'h.rexhepi', 'NT AUTHORITY\\SYSTEM' -> 'SYSTEM'."""
    return str(u).rsplit("\\", 1)[-1] if u else None


def parse_windows_sysmon(path: Path, src: dict, stats: dict):
    """Microsoft-Windows-Sysmon/Operational: 1 process created, 3 network connection, 11 file created."""
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
                _seen(stats, r["TimeCreated"])
                d, eid = r.get("EventData") or {}, int(r["Id"])
                base = dict(os="windows", host=r.get("MachineName"), user=_account(d.get("User")), path=d.get("Image"), code=eid)
                if eid == 1:
                    yield make_event(src["name"], n, line, src["path"], r["TimeCreated"], **base, type="process", action="process-start",
                                     outcome="success", parent=d.get("ParentImage"), detail=d.get("CommandLine"))
                elif eid == 3:
                    yield make_event(src["name"], n, line, src["path"], r["TimeCreated"], **base, type="network", action="connect",
                                     outcome="success", proto=str(d.get("Protocol", "")).lower() or None, src_ip=d.get("SourceIp"),
                                     src_port=_int(d.get("SourcePort")), dst_ip=d.get("DestinationIp"),
                                     dst_port=_int(d.get("DestinationPort")),
                                     direction="outbound" if str(d.get("Initiated", "true")).lower() == "true" else "inbound")
                elif eid == 11:
                    yield make_event(src["name"], n, line, src["path"], r["TimeCreated"], **{**base, "path": d.get("TargetFilename")},
                                     type="file", action="file-created", outcome="success", detail=d.get("Image"))
                elif eid == 10:               # one process opened another (LSASS opened = credential dumping)
                    yield make_event(src["name"], n, line, src["path"], r["TimeCreated"],
                                     **{**base, "path": d.get("SourceImage"), "user": _account(d.get("SourceUser"))},
                                     type="process", action="process-access", outcome="success", target=d.get("TargetImage"),
                                     granted=d.get("GrantedAccess"), detail=f"{d.get('SourceImage')} -> {d.get('TargetImage')} "
                                                                            f"({d.get('GrantedAccess')})")
                else:
                    stats["skipped"] += 1
            except (ValueError, KeyError, TypeError):
                stats["errors"] += 1


# ======================================================================= Zeek conn.log (network sensor)

def parse_zeek_conn(path: Path, src: dict, stats: dict):
    """Zeek conn.log, JSON (one object per line) or the default TSV with a #fields header.

    One event per connection, seen by the sensor (host = the sensor). action 'flow' on purpose: the host-firewall
    rules (action allow/block) do not count sensor flows twice; the flow rules use their own conditions.
    """
    fields = None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                if line.startswith("#"):
                    if line.startswith("#fields"):
                        fields = line.rstrip("\n").split("\t")[1:]
                    continue
                r = json.loads(line) if line.lstrip().startswith("{") else dict(zip(fields or [], line.rstrip("\n").split("\t")))
                ts = datetime.fromtimestamp(float(r["ts"]), tz=timezone.utc)
                _seen(stats, ts)
                state = r.get("conn_state")
                yield make_event(src["name"], n, line, src["path"], ts, os="network", host=src.get("host"), sensor=True,
                                 type="network", action="flow", outcome="success" if state in ("SF", "S1", "S2", "S3", "RSTO", "RSTR") else "failure",
                                 proto=r.get("proto"), src_ip=r["id.orig_h"], src_port=_int(r.get("id.orig_p")), dst_ip=r["id.resp_h"],
                                 dst_port=_int(r.get("id.resp_p")), service=None if r.get("service") in (None, "-") else r.get("service"),
                                 conn_state=state, bytes=(_int(r.get("orig_bytes")) or 0) + (_int(r.get("resp_bytes")) or 0),
                                 bytes_out=_int(r.get("orig_bytes")) or 0)
            except (ValueError, KeyError, TypeError):
                stats["errors"] += 1


# ======================================================================= Mail security gateway (JSON lines)
def parse_mail_gateway(path: Path, src: dict, stats: dict):
    """One event per recipient: user = the recipient's account (local part), so a mail links to that user's logons/processes.

    Fields used: ts, direction, client_ip, from, to[], subject, attachments[{name}], verdict, action, score.
    """
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
                _seen(stats, r["ts"])
                names = [a.get("name", "") for a in r.get("attachments") or []]
                rcpts = r.get("to") or [None]
                for to in rcpts if r.get("direction") == "inbound" else [r.get("from")]:
                    yield make_event(src["name"], n, line, src["path"], r["ts"], os="network", host=src.get("host"), type="email",
                                     action=r.get("action"), outcome="success" if r.get("action") == "delivered" else "failure",
                                     direction=r.get("direction"), src_ip=r.get("client_ip"), sender=r.get("from"), recipient=to,
                                     user=str(to).split("@")[0] if to else None, subject=r.get("subject"),
                                     attachments=" ".join(names) or None, verdict=r.get("verdict"), score=r.get("score"),
                                     detail=f"{r.get('subject', '')} [{', '.join(names)}]" if names else r.get("subject"))
            except (ValueError, KeyError, TypeError, AttributeError):
                stats["errors"] += 1


# ======================================================================= Mail events (lab format: delivery + link clicks)
def parse_mail_events(path: Path, src: dict, stats: dict):
    """JSON lines with timestamp, event (email_delivered | url_clicked), user, message_id, verdict, url.

    Delivery -> type email, action delivered (verdict kept); click -> type email, action url-clicked (url in detail).
    message_id is kept so a click can be tied to the mail it came from.
    """
    acts = {"email_delivered": "delivered", "url_clicked": "url-clicked", "email_quarantined": "quarantined"}
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                r = json.loads(line)
                _seen(stats, r["timestamp"])
                act = acts.get(str(r.get("event", "")).lower())
                if not act:
                    stats["skipped"] += 1
                    continue
                yield make_event(src["name"], n, line, src["path"], r["timestamp"], os="network", host=src.get("host"),
                                 type="email", action=act, outcome="success", direction="inbound", user=r.get("user"),
                                 message_id=r.get("message_id"), verdict=r.get("verdict"), url=r.get("url"),
                                 detail=r.get("url") or r.get("subject") or r.get("message_id"))
            except (ValueError, KeyError, TypeError):
                stats["errors"] += 1


# ======================================================================= Perimeter firewall (pfSense filterlog)
def parse_pfsense_filterlog(path: Path, src: dict, stats: dict):
    """pfSense filterlog, IPv4 TCP/UDP: rule,sub,anchor,tracker,iface,reason,action,dir,ipver,tos,ecn,ttl,id,offset,
    flags,protonum,proto,length,src,dst,srcport,dstport,...   (action pass|block, dir in|out)"""
    for n, line, ts, host, prog, msg in _syslog_lines(path, src, stats):
        f = msg.split(",")
        if prog != "filterlog" or len(f) < 22 or f[8] != "4" or f[16] not in ("tcp", "udp"):
            stats["skipped"] += 1
            continue
        yield make_event(src["name"], n, line, src["path"], ts, src.get("utc_offset"), os="network", host=host or src.get("host"),
                         type="network", action="allow" if f[6] == "pass" else "block", outcome="success" if f[6] == "pass" else "failure",
                         direction="inbound" if f[7] == "in" else "outbound", proto=f[16], src_ip=f[18], dst_ip=f[19],
                         src_port=_int(f[20]), dst_port=_int(f[21]), rule_id=f[3], interface=f[4], perimeter=True)


PARSERS = {"windows_events": parse_windows_events, "windows_firewall": parse_windows_firewall, "linux_auth": parse_linux_auth,
           "linux_ufw": parse_linux_ufw, "linux_syslog": parse_linux_syslog, "linux_dpkg": parse_linux_dpkg,
           "windows_sysmon": parse_windows_sysmon, "zeek_conn": parse_zeek_conn, "mail_gateway": parse_mail_gateway,
           "mail_events": parse_mail_events, "pfsense_filterlog": parse_pfsense_filterlog}


def read_all(sources: list[dict], folder: Path) -> tuple[list[dict], list[dict]]:
    """Parse every source in sources.yaml through the agent that owns its format (soc/agents/).
    Returns (events sorted by time, one stats dict per source)."""
    from .agents import all_parsers, owner_of   # late import: the agents import the parse functions from this module
    parsers = {**PARSERS, **all_parsers()}
    events, all_stats = [], []
    for src in sources:
        stats = {"source": src["name"], "parser": src["parser"], "agent": owner_of(src["parser"]), "host": src.get("host"),
                 "events": 0, "skipped": 0, "errors": 0, "missing": False, "times": []}
        path = Path(folder) / src["path"]
        if src["parser"] not in parsers:
            stats["errors"] += 1
            stats["note"] = f"no parser named '{src['parser']}'"
        elif not path.exists():
            stats["missing"] = True
        else:
            for ev in parsers[src["parser"]](path, src, stats):
                if not ev.get("host"):
                    ev["host"] = src.get("host")
                events.append(ev)
                stats["events"] += 1
        all_stats.append(stats)
    events.sort(key=lambda e: (e["time"], e["id"]))
    return events, all_stats
