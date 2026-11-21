"""Windows host agent: Security/System event logs (logons, admin rights, services, accounts, groups, Kerberos, shares)."""
from ..parsers import parse_windows_events
from . import Agent, count, top


def highlights(ev, ctx):
    ok, bad = count(ev, action="logon", outcome="success"), count(ev, action="logon", outcome="failure")
    lines = [f"{ok} successful and {bad} failed logons; {count(ev, action='logon', logon='remote')} remote (RDP)"]
    if bad and (t := top(ev, "user", action="logon", outcome="failure")):
        lines.append(f"most failed logons: {t[0][0]} ({t[0][1]})")
    rc4 = count(ev, action="kerberos-service-ticket", ticket_enc="0x17")
    lines.append(f"{count(ev, action='kerberos-service-ticket')} Kerberos service tickets, {rc4} with weak RC4")
    priv = sum(1 for e in ev if e.get("action") == "group-member-added" and e.get("privileged_group"))
    lines.append(f"{count(ev, action='service-installed')} services installed, {count(ev, action='account-created')} accounts "
                 f"created, {priv} added to privileged groups")
    admin_shares = sum(1 for e in ev if e.get("action") == "share-access" and str(e.get("share", "")).endswith("$"))
    if admin_shares:
        lines.append(f"{admin_shares} admin-share (ADMIN$/C$) opens")
    return lines


AGENT = Agent("windows_host", "Windows host agent", "Windows Security and System event logs",
              {"windows_events": parse_windows_events}, highlights)
