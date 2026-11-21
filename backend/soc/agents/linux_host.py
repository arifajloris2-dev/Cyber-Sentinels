"""Linux host agent: auth.log, syslog, dpkg (SSH logons, sudo, root shells, services, packages)."""
from ..parsers import parse_linux_auth, parse_linux_dpkg, parse_linux_syslog
from . import Agent, count, top


def highlights(ev, ctx):
    ok, bad = count(ev, action="logon", outcome="success"), count(ev, action="logon", outcome="failure")
    lines = [f"{ok} SSH logons, {bad} failed"]
    if bad and (t := top(ev, "src_ip", action="logon", outcome="failure")):
        lines.append(f"most failed SSH logons from {t[0][0]} ({t[0][1]})")
    roots = [e for e in ev if e.get("action") == "root-shell"]
    odd = [e for e in roots if not e.get("user_privileged")]
    text = f"{count(ev, action='sudo') + len(roots)} sudo commands, {len(roots)} root shells"
    if odd:
        text += f" ({len(odd)} by accounts that are not admins: {', '.join(sorted({e['user'] for e in odd}))})"
    lines.append(text)
    lines.append(f"{count(ev, action='service-started')} services started, {count(ev, action='update-installed')} packages updated")
    return lines


AGENT = Agent("linux_host", "Linux host agent", "Ubuntu auth.log, syslog and dpkg.log",
              {"linux_auth": parse_linux_auth, "linux_syslog": parse_linux_syslog, "linux_dpkg": parse_linux_dpkg}, highlights)
