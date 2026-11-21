"""Host firewall agent: Windows pfirewall.log and Ubuntu ufw.log (who talks to whom, what is blocked, zone policy)."""
from ..parsers import parse_linux_ufw, parse_windows_firewall
from . import Agent, count, top


def _violations(events) -> set:
    return {(e.get("src_host") or e.get("src_ip"), e.get("dst_host") or e.get("dst_ip"), e.get("dst_port"))
            for e in events if e.get("zone_allowed") is False and e.get("action") == "allow"}


def highlights(ev, ctx):
    lines = [f"{count(ev, action='allow')} connections allowed, {count(ev, action='block')} blocked"]
    if (t := top(ev, "src_ip", action="block")):
        lines.append(f"most blocked source: {t[0][0]} ({t[0][1]})")
    known = _violations(ctx.get("baseline", []))      # its normal: policy exceptions it already saw on the baseline day
    new = _violations(ev) - known
    if new:
        lines.append(f"{len(new)} NEW kinds of connection between zones that the policy does not allow: "
                     + "; ".join(f"{s} -> {d}:{p}" for s, d, p in sorted(new, key=str)[:4]))
    if known:
        lines.append(f"{len(known)} known policy exceptions also seen on the baseline day (old tools probing closed ports)")
    return lines


AGENT = Agent("host_firewall", "Host firewall agent", "Windows Defender Firewall and Ubuntu ufw logs on every host",
              {"windows_firewall": parse_windows_firewall, "linux_ufw": parse_linux_ufw}, highlights)
