"""Mail agent: the mail security gateway (what reached users, what was stopped, who clicked)."""
from ..parsers import parse_mail_events, parse_mail_gateway
from . import Agent, count

RISKY = (".docm", ".xlsm", ".pptm", ".js", ".iso", ".img", ".hta", ".exe", ".lnk", ".vbs", ".one")


def highlights(ev, ctx):
    lines = [f"{count(ev, action='delivered', direction='inbound')} mails delivered, {count(ev, action='quarantined')} quarantined"]
    risky = [e for e in ev if e.get("action") == "delivered" and any(str(e.get("attachments", "")).lower().endswith(x) for x in RISKY)]
    if risky:
        lines.append(f"{len(risky)} delivered with a risky attachment ({', '.join(sorted({str(e['attachments']) for e in risky}))})")
    clicks = count(ev, action="url-clicked")
    if clicks:
        lines.append(f"{clicks} link clicks recorded")
    return lines


AGENT = Agent("mail", "Mail agent", "Mail security gateway verdicts and mail/click events",
              {"mail_gateway": parse_mail_gateway, "mail_events": parse_mail_events}, highlights)
