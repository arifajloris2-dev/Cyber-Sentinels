"""Operator-fed knowledge: new CVEs, threat indicators and leaked accounts, imported as PLAIN TEXT only.

The base is offline, so nothing updates itself. The operator types or uploads a small text file in the dashboard
("Knowledge" view). This module checks it strictly, shows what will be accepted, and stores a clean copy.

Accepted format: blocks separated by an empty line; each line "Key: value". Lines starting with # are comments.

    CVE: CVE-2026-12345            Product: GateControlService     Versions: 2.4.0, 2.4.1
    KEV: yes                       EPSS: 0.91                      CVSS: 9.8
    Techniques: T1543, T1562       Hosts: srv-gate-ctrl-01         Summary: free text (max 500 characters)
    Reference: https://...         (kept as text, never opened)

    IP: 203.0.113.99               Domain: bad.example             Hash: <md5/sha1/sha256 hex>
    Account: svc_ops_night         Note: free text                 Source: who reported it

Safety (why it cannot bring anything malicious in):
  - only UTF-8 text; NUL / control characters, binary content and over-long input are rejected outright
  - only the keys above; every value must match a strict pattern (CVE id, technique id, IP, domain, hex hash, ...)
  - nothing is executed, evaluated, opened or fetched; the stored copy is REBUILT from the checked fields
    (not the original text), with the SHA-256 of what was submitted and the import time
  - knowledge lives in its own folder; log files are never changed
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

STORE = Path(__file__).resolve().parents[1] / "data" / "knowledge"
MAX_BYTES = 256 * 1024
MAX_LINES = 4000
MAX_LINE = 1000
MAX_TEXT = 500
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

PATTERNS = {
    "cve": re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I),
    "technique": re.compile(r"^T\d{4}(\.\d{3})?$", re.I),
    "domain": re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I),
    "hash": re.compile(r"^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$", re.I),
    "account": re.compile(r"^[A-Za-z0-9._$@\\-]{2,64}$"),
    "host": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$"),
    "product": re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+()/-]{0,79}$"),
    "version": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~:-]{0,39}$"),
    "url": re.compile(r"^https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{1,300}$"),
}
KEYS = {"cve", "product", "versions", "kev", "epss", "cvss", "techniques", "hosts", "summary", "reference",
        "ip", "domain", "hash", "account", "note", "source"}
KIND_KEY = {"cve": "cve", "ip": "ioc", "domain": "ioc", "hash": "ioc", "account": "account"}


@dataclass
class Check:
    records: list[dict] = field(default_factory=list)
    rejected: list[tuple[int, str, str]] = field(default_factory=list)   # (line number, line, reason)
    error: str | None = None                                               # the whole input was refused
    sha256: str = ""


def _clean_text(v: str) -> str:
    v = " ".join(v.split())
    return v[:MAX_TEXT]


def _list(v: str) -> list[str]:
    return [x.strip() for x in re.split(r"[,;]", v) if x.strip()]


def _value(key: str, raw: str) -> object:
    """The checked value, or raise ValueError with a reason."""
    v = raw.strip()
    if not v:
        raise ValueError("empty value")
    if key == "cve":
        if not PATTERNS["cve"].match(v):
            raise ValueError("not a CVE id (CVE-YYYY-NNNN)")
        return v.upper()
    if key == "techniques":
        items = [x.upper() for x in _list(v)]
        bad = [x for x in items if not PATTERNS["technique"].match(x)]
        if bad:
            raise ValueError(f"not ATT&CK technique ids: {', '.join(bad[:3])}")
        return items[:20]
    if key == "hosts":
        items = _list(v)
        bad = [x for x in items if not PATTERNS["host"].match(x)]
        if bad:
            raise ValueError(f"not host names: {', '.join(bad[:3])}")
        return items[:50]
    if key == "versions":
        items = _list(v)
        bad = [x for x in items if not PATTERNS["version"].match(x)]
        if bad:
            raise ValueError(f"not versions: {', '.join(bad[:3])}")
        return items[:50]
    if key == "product":
        if not PATTERNS["product"].match(v):
            raise ValueError("product name has characters that are not allowed")
        return v
    if key == "kev":
        if v.lower() not in ("yes", "no", "true", "false"):
            raise ValueError("KEV must be yes or no")
        return v.lower() in ("yes", "true")
    if key in ("epss", "cvss"):
        try:
            n = float(v)
        except ValueError:
            raise ValueError(f"{key.upper()} must be a number") from None
        hi = 1.0 if key == "epss" else 10.0
        if not 0 <= n <= hi:
            raise ValueError(f"{key.upper()} must be between 0 and {hi:g}")
        return n
    if key == "ip":
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("not an IP address") from None
        return str(ip)
    if key == "domain":
        d = v.lower().rstrip(".")
        if not PATTERNS["domain"].match(d):
            raise ValueError("not a domain name")
        return d
    if key == "hash":
        if not PATTERNS["hash"].match(v):
            raise ValueError("not an MD5/SHA-1/SHA-256 hex hash")
        return v.lower()
    if key == "account":
        if not PATTERNS["account"].match(v):
            raise ValueError("account name has characters that are not allowed")
        return v
    if key == "reference":
        if not PATTERNS["url"].match(v):
            raise ValueError("reference must be an http(s) address (kept as text, never opened)")
        return v
    return _clean_text(v)          # summary, note, source


def check(text_or_bytes: str | bytes) -> Check:
    """Strictly check submitted text. Nothing is saved here."""
    raw = text_or_bytes.encode("utf-8") if isinstance(text_or_bytes, str) else bytes(text_or_bytes)
    res = Check(sha256=hashlib.sha256(raw).hexdigest())
    if len(raw) > MAX_BYTES:
        res.error = f"too large ({len(raw):,} bytes; at most {MAX_BYTES:,})"
        return res
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        res.error = "not UTF-8 text (binary files are not accepted)"
        return res
    if text.startswith("﻿"):
        text = text[1:]
    if CONTROL.search(text):
        res.error = "contains control characters (only plain text is accepted)"
        return res
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        res.error = f"too many lines ({len(lines):,}; at most {MAX_LINES:,})"
        return res

    block: dict = {}
    block_line = 0

    def close():
        nonlocal block
        if block:
            kinds = [KIND_KEY[k] for k in block if k in KIND_KEY]
            if len(set(kinds)) != 1:
                res.rejected.append((block_line, "", "a block needs exactly one of CVE / IP / Domain / Hash / Account"))
            else:
                block["kind"] = kinds[0]
                res.records.append(block)
        block = {}

    for n, line in enumerate(lines, 1):
        s = line.strip()
        if not s:
            close()
            continue
        if s.startswith("#"):
            continue
        if len(line) > MAX_LINE:
            res.rejected.append((n, s[:80] + "…", f"line longer than {MAX_LINE} characters"))
            continue
        if ":" not in s:
            res.rejected.append((n, s[:120], "expected 'Key: value'"))
            continue
        key, _, value = s.partition(":")
        key = key.strip().lower()
        if key not in KEYS:
            res.rejected.append((n, s[:120], f"unknown key '{key}'"))
            continue
        if key in block or (key in KIND_KEY and any(k in KIND_KEY for k in block)):
            close()                     # a second CVE/IP/... starts a new record
        try:
            block[key] = _value(key, value)
            block_line = block_line if len(block) > 1 else n
        except ValueError as exc:
            res.rejected.append((n, s[:120], str(exc)))
    close()
    return res


def _serialise(records: list[dict]) -> str:
    """Rebuild clean text from the checked fields (the stored copy never contains the submitted text itself)."""
    order = ["cve", "ip", "domain", "hash", "account", "product", "versions", "kev", "epss", "cvss", "techniques", "hosts",
             "summary", "note", "source", "reference"]
    out = []
    for r in records:
        for k in order:
            if k in r:
                v = r[k]
                v = ", ".join(v) if isinstance(v, list) else ("yes" if v is True else "no" if v is False else v)
                out.append(f"{k.capitalize() if k not in ('cve', 'ip', 'kev', 'epss', 'cvss') else k.upper()}: {v}")
        out.append("")
    return "\n".join(out)


def save(result: Check, label: str = "operator import", store: Path | None = None) -> Path:
    """Store the checked records as a clean text file. Only call after the operator confirmed the preview."""
    if result.error or not result.records:
        raise ValueError("nothing valid to import")
    store = Path(store or STORE)
    store.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc)
    safe_label = re.sub(r"[^A-Za-z0-9 ._-]", "", label)[:60] or "import"
    path = store / f"{stamp:%Y%m%dT%H%M%SZ}_{result.sha256[:12]}.txt"
    header = (f"# Cyber Sentinels knowledge import\n# imported: {stamp.isoformat(timespec='seconds')}\n# label: {safe_label}\n"
              f"# submitted sha256: {result.sha256}\n# records: {len(result.records)}\n\n")
    path.write_text(header + _serialise(result.records), encoding="utf-8")
    return path


def imports(store: Path | None = None) -> list[dict]:
    store = Path(store or STORE)
    out = []
    for p in sorted(store.glob("*.txt")) if store.exists() else []:
        meta = {"file": p.name}
        for line in p.read_text(encoding="utf-8").splitlines()[:6]:
            if line.startswith("# ") and ": " in line:
                k, _, v = line[2:].partition(": ")
                meta[k] = v
        out.append(meta)
    return out


def remove(name: str, store: Path | None = None) -> bool:
    """Withdraw an import. The file is renamed to .removed (no longer used, kept as an audit trail): nothing is
    deleted, and only a file inside the store can be touched."""
    store = Path(store or STORE)
    p = store / Path(name).name                    # never a path from outside the store
    if p.suffix == ".txt" and p.exists() and p.parent == store:
        p.rename(p.with_name(p.name + ".removed"))
        return True
    return False


def load(store: Path | None = None) -> list[dict]:
    """All imported records (each stored file is re-checked on load, so a hand-edited file cannot slip past)."""
    records = []
    for meta in imports(store):
        res = check((Path(store or STORE) / meta["file"]).read_bytes())
        for r in res.records:
            r["imported_from"] = meta["file"]
            records.append(r)
    return records


def indicators(records: list[dict]) -> dict[str, set]:
    return {"ip": {r["ip"] for r in records if r.get("ip")},
            "domain": {r["domain"] for r in records if r.get("domain")},
            "hash": {r["hash"] for r in records if r.get("hash")}}


def as_findings(records: list[dict], inventory: list[dict] | None = None) -> list[dict]:
    """Turn imported CVEs and leaked accounts into the same finding format the OSINT agent writes, so the SOC intel
    join, the dashboard and the AI use them unchanged. A CVE applies to hosts named in it and to inventory assets whose
    software name/version matches."""
    out = []
    for r in records:
        if r["kind"] == "cve":
            assets = list(r.get("hosts", []))
            for a in inventory or []:
                for sw in a.get("software", []):
                    if r.get("product") and str(sw.get("name", "")).lower() == r["product"].lower() and \
                            (not r.get("versions") or str(sw.get("version")) in r["versions"]):
                        assets.append(a.get("asset_id"))
            out.append({"id": f"KB-{r['cve']}", "finding_type": "vulnerability_exposure", "cve": r["cve"],
                        "title": f"{r['cve']} ({r.get('product', 'software')})", "cisa_kev": r.get("kev", False),
                        "epss_score": r.get("epss", 0.0), "cvss": r.get("cvss"), "affected_assets": sorted(set(filter(None, assets))),
                        "mitre_techniques": r.get("techniques", []), "summary": r.get("summary", ""),
                        "source": f"operator import ({r.get('imported_from')})", "reference": r.get("reference")})
        elif r["kind"] == "account":
            out.append({"id": f"KB-ACCT-{r['account']}", "finding_type": "credential_exposure", "account": r["account"],
                        "affected_assets": r.get("hosts", []), "mitre_techniques": ["T1078"], "confidence": 0.8,
                        "summary": r.get("note") or r.get("summary") or "Account reported as exposed (operator import)",
                        "source": f"operator import ({r.get('imported_from')})"})
    return out
