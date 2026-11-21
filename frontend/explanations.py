from __future__ import annotations

from typing import Any


Record = dict[str, Any]


def instant_overview(incident: Record) -> str:
    """Create one evidence-safe plain-language fallback for an incident."""
    hosts = [str(host.get("host", "unknown host")) for host in incident.get("hosts", [])]
    alerts = incident.get("alerts", [])
    techniques = ", ".join(
        str(item.get("name", item.get("id", ""))) for item in incident.get("attack", [])[:3]
    )
    priority = incident.get("priority", "Unranked")
    priority_help = {
        "P1": "High priority: an operator should review this now.",
        "P2": "Medium priority: an operator should review this soon.",
        "P3": "Lower priority: review when practical.",
    }.get(str(priority), "An operator should review the evidence.")
    if any(alert.get("rule") == "NET-004" for alert in alerts):
        swarm = next(alert for alert in alerts if alert.get("rule") == "NET-004")
        count = swarm.get("distinct_source_count", "many")
        explanation = (
            f"Possible bot swarm: the firewall blocked traffic from {count} different addresses "
            "aimed at one system in a short time. This pattern can overwhelm a service, but the "
            "traffic alone does not prove the sources are compromised."
        )
    else:
        explanations = [plain_alert_explanation(alert) for alert in alerts[:3]]
        explanation = " ".join(explanations) or "The system grouped related security events for review."
    where = ", ".join(hosts) if hosts else "the host could not be mapped to an asset"
    attack_note = f" Related technique: {techniques}." if techniques else ""
    return (
        f"{priority} incident: {incident.get('title', 'Correlated activity')}. {priority_help}\n"
        f"What happened: {explanation}\n"
        f"Where: {where}. The SOC grouped {len(alerts)} alert(s).{attack_note}\n"
        "Next step: check the evidence and confirm whether this activity was expected. "
        "No system was changed automatically."
    )


def plain_alert_explanation(alert: Record) -> str:
    rule = alert.get("rule")
    text = str(alert.get("text", "")).strip()
    if rule == "NET-004":
        sources = alert.get("distinct_source_count", "multiple")
        return (
            f"Possible bot swarm: traffic from {sources} different addresses hit the same system in a short time. "
            "The firewall blocked it. This may overwhelm the service, but an operator should verify the traffic "
            "and system impact."
        )
    if rule == "NET-003":
        return f"Repeated connection attempts from one address were blocked. {text}"
    if rule == "AUTH-001":
        return f"Several remote sign-in failures were followed by a successful sign-in. {text}"
    if rule == "AUTH-003":
        return f"Many sign-in attempts failed from the same address. {text}"
    if rule == "SYS-001":
        return f"A new Windows service was installed. An operator should verify it was approved. {text}"
    if rule == "SYS-004":
        return f"A security log or audit setting was changed. Verify this was authorized. {text}"
    return f"{alert.get('title', 'A security rule matched')}. {text}"
