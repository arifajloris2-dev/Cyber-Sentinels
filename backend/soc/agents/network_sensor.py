"""Network sensor agent: Zeek conn.log from the core/perimeter SPAN port (sees traffic even when a host log is silent)."""
from ..parsers import parse_zeek_conn
from . import Agent, count


def highlights(ev, ctx):
    out = [e for e in ev if e.get("src_internal") and e.get("dst_internal") is False]
    lines = [f"{len(ev)} connections, {len(out)} from inside to the internet, {count(ev, outcome='failure')} failed or rejected"]
    big = max(out, key=lambda e: e.get("bytes_out", 0), default=None)
    if big and big.get("bytes_out", 0) > 1_000_000:
        lines.append(f"largest upload: {big.get('src_host') or big.get('src_ip')} -> {big.get('dst_ip')}:{big.get('dst_port')} "
                     f"({big['bytes_out'] / 1e6:.0f} MB)")
    return lines


AGENT = Agent("network_sensor", "Network sensor agent (Zeek)", "Zeek conn.log from the core and perimeter mirror port",
              {"zeek_conn": parse_zeek_conn}, highlights)
