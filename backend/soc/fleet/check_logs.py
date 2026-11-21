"""Sanity checks for the synthetic logs (local only, read-only). Usage: py check_logs.py"""
import collections
import ipaddress
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT, ECS = ROOT / "logs", ROOT / "logs_ecs"
ok = True


def fail(msg):
    global ok
    ok = False
    print("FAIL", msg)


raw = sorted(f for f in OUT.glob("*_*") if f.suffix != ".yaml")
kinds = collections.Counter()
for f in raw:
    lines = [ln for ln in f.read_text(encoding="utf-8").splitlines() if not ln.startswith("#")]
    kinds[f.name.split("_", 1)[1]] += len(lines)
    e = ECS / (f.name.rsplit(".", 1)[0] + ".ecs.jsonl" if "." in f.name else f.name + ".ecs.jsonl")
    docs = [json.loads(x) for x in e.read_text(encoding="utf-8").splitlines()]
    if len(docs) != len(lines):
        fail(f"{f.name}: {len(lines)} raw vs {len(docs)} ECS")
    for d in docs:
        if not {"@timestamp", "event", "host", "log"} <= d.keys():
            fail(f"{e.name}: missing ECS core fields")
            break
    if f.name.endswith((".jsonl", "zeek-conn.log")):
        for ln in lines:
            json.loads(ln)

text = "\n".join(f.read_text(encoding="utf-8") for f in raw)
allowed = [ipaddress.ip_network(n) for n in ("10.24.0.0/16", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8")]
bad_ips = {ip for ip in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
           if not any(ipaddress.ip_address(ip) in n for n in allowed if all(int(p) < 256 for p in ip.split(".")))}
bad_ips = {ip for ip in bad_ips if all(int(p) < 256 for p in ip.split("."))}
if bad_ips:
    fail(f"addresses outside internal/documentation ranges: {sorted(bad_ips)[:10]}")
bad_dom = {d for d in re.findall(r"@([a-z0-9.-]+)", text) if not d.endswith(".example") and "." in d and not re.fullmatch(r"[\d.]+", d)}
if bad_dom:
    fail(f"mail domains outside .example: {sorted(bad_dom)[:10]}")

truth = json.loads((OUT / "truth.json").read_text(encoding="utf-8"))
labels = {k: len(v) for k, v in truth["lines"].items()}
for need in ["A1:entry", "A1:lateral", "A1:persistence", "A1:defense-evasion", "A1:c2", "A2", "A3", "A4:delivery", "A4:execution",
             "A4:persistence", "A4:c2", "B1", "B4", "patch", "backup", "change", "vulnscan", "emergency"]:
    if not labels.get(need):
        fail(f"no lines labelled {need}")

gate = [ln for ln in (OUT / "srv-gate-ctrl-01_ufw.log").read_text(encoding="utf-8").splitlines()
        if "2026-11-22T02:05" <= ln[:16] < "2026-11-22T04:30"]
if gate:
    fail(f"gate ufw log not silent in the outage window ({len(gate)} lines)")

print(f"{sum(kinds.values()):,} raw lines in {len(raw)} files")
for k, n in sorted(kinds.items()):
    print(f"  {k:15s} {n:>7,}")
print("planted lines:", ", ".join(f"{k}={v}" for k, v in sorted(labels.items())))
print("ALL CHECKS PASSED" if ok else "CHECKS FAILED")
