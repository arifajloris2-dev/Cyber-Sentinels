"""Perimeter firewall agent: the edge firewall between the base and the internet."""
from ..parsers import parse_pfsense_filterlog
from . import Agent, count, top


def highlights(ev, ctx):
    inbound = [e for e in ev if e.get("direction") == "inbound"]
    blocked_from = len({e.get("src_ip") for e in inbound if e.get("action") == "block"})
    lines = [f"inbound: {count(inbound, action='allow')} passed, {count(inbound, action='block')} blocked from {blocked_from} "
             f"internet addresses; outbound: {count(ev, direction='outbound', action='allow')} passed"]
    if (t := top(inbound, "dst_ip", action="block")):
        lines.append(f"most targeted: {t[0][0]} ({t[0][1]} blocked attempts)")
    odd = [e for e in inbound if e.get("action") == "allow" and e.get("dst_port") not in (25, 443)]
    if odd:
        e = odd[0]
        lines.append(f"{len(odd)} inbound connections passed to non-public ports, e.g. "
                     f"{e.get('src_ip')} -> {e.get('dst_host') or e.get('dst_ip')}:{e.get('dst_port')}")
    return lines


AGENT = Agent("perimeter", "Perimeter firewall agent", "Edge firewall (pfSense filterlog): everything to and from the internet",
              {"pfsense_filterlog": parse_pfsense_filterlog}, highlights)
