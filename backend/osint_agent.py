# Member 1: OSINT & Threat Intelligence
import json
from pathlib import Path
from typing import Any, Dict, List


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

DEFAULT_ASSETS: List[Dict[str, Any]] = [
    {
        "asset_id": "ws-base-014",
        "ip": "10.24.3.14",
        "role": "workstation",
        "accounts": ["svc_ops_night", "op_night_01"],
        "software": [{"name": "OpenSSH", "version": "8.9p1"}],
        "criticality": "high",
    },
    {
        "asset_id": "srv-gate-ctrl-01",
        "ip": "10.24.8.19",
        "role": "gate-control server",
        "accounts": ["svc_gate_daemon", "svc_ops_night"],
        "software": [{"name": "GateControlService", "version": "2.4.0"}],
        "criticality": "critical",
    },
]

DEFAULT_KEV_NVD_EPSS: List[Dict[str, Any]] = [
    {
        "cve": "CVE-2025-4120",
        "product": "GateControlService",
        "affected_versions": ["2.4.0"],
        "cisa_kev": True,
        "epss_score": 0.91,
        "cvss": 8.8,
        "mitre_techniques": ["T1543", "T1562"],
        "summary": "Unauthorized service/configuration modification on gate-control daemon.",
    },
    {
        "cve": "CVE-2024-6387",
        "product": "OpenSSH",
        "affected_versions": ["8.9p1"],
        "cisa_kev": False,
        "epss_score": 0.64,
        "cvss": 8.1,
        "mitre_techniques": ["T1110", "T1021"],
        "summary": "Remote authentication/session exposure risk.",
    },
]

DEFAULT_OSINT_POSTS: List[Dict[str, Any]] = [
    {
        "post_id": "osint-001",
        "source": "simulated_telegram_leak_channel",
        "timestamp": "2026-11-20T01:55:00Z",
        "leaked_accounts": ["svc_ops_night"],
        "referenced_cves": ["CVE-2025-4120"],
        "confidence": 0.88,
        "summary": "Simulated leak/post referencing account svc_ops_night and GateControlService v2.4.0.",
    }
]


def load_or_create_json(path: Path, default_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Lexon nje skedar JSON lokal; nese nuk ekziston ende, krijon nje shembull fillestar."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(json.dumps(default_data, indent=2, ensure_ascii=False), encoding="utf-8")
        return default_data
    return json.loads(path.read_text(encoding="utf-8"))


def run_osint_agent(
    assets: List[Dict[str, Any]],
    vuln_intel: List[Dict[str, Any]],
    osint_posts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Kthen gjetje te strukturuara (structured threat findings) dhe kerkesa per gjueti (hunt requests)."""
    findings: List[Dict[str, Any]] = []
    hunt_requests: List[Dict[str, Any]] = []

    for vuln in vuln_intel:
        matched_assets = [
            asset["asset_id"]
            for asset in assets
            for sw in asset.get("software", [])
            if sw.get("name") == vuln.get("product") and sw.get("version") in vuln.get("affected_versions", [])
        ]
        if matched_assets:
            osint_refs = [
                post["post_id"]
                for post in osint_posts
                if vuln.get("cve") in post.get("referenced_cves", [])
            ]
            findings.append({
                "type": "vulnerability_exposure",
                "cve": vuln["cve"],
                "cisa_kev": vuln.get("cisa_kev", False),
                "epss_score": vuln.get("epss_score", 0.0),
                "affected_assets": matched_assets,
                "mitre_techniques": vuln.get("mitre_techniques", []),
                "osint_corroboration": osint_refs,
                "summary": vuln.get("summary", ""),
            })
            hunt_requests.append({
                "hunt_id": f"HUNT-{vuln['cve']}",
                "target_assets": matched_assets,
                "mitre_techniques": vuln.get("mitre_techniques", []),
                "assigned_to": "Member 2 (SOC Detection & Correlation)",
                "hunt_query": (
                    f"Hunt logs for {matched_assets} covering techniques {vuln.get('mitre_techniques', [])} "
                    f"and unexpected service/configuration activity."
                ),
            })

    for post in osint_posts:
        for acct in post.get("leaked_accounts", []):
            acct_assets = [a["asset_id"] for a in assets if acct in a.get("accounts", [])]
            if acct_assets:
                findings.append({
                    "type": "credential_exposure",
                    "post_id": post["post_id"],
                    "source": post.get("source", "simulated_osint"),
                    "timestamp": post.get("timestamp", ""),
                    "account": acct,
                    "affected_assets": acct_assets,
                    "confidence": post.get("confidence", 0.5),
                    "mitre_techniques": ["T1078", "T1110"],
                    "summary": post.get("summary", ""),
                })
                hunt_requests.append({
                    "hunt_id": f"HUNT-ACCT-{acct}",
                    "target_assets": acct_assets,
                    "mitre_techniques": ["T1078", "T1110", "T1021"],
                    "assigned_to": "Member 2 (SOC Detection & Correlation)",
                    "hunt_query": (
                        f"Check failed/successful logins and internal connections for account '{acct}' "
                        f"on {acct_assets}."
                    ),
                })

    return {
        "member": "Member 1 — OSINT & Threat Intelligence",
        "structured_threat_findings": findings,
        "targeted_hunt_requests": hunt_requests,
    }


if __name__ == "__main__":
    assets_data = load_or_create_json(DATA_DIR / "assets.json", DEFAULT_ASSETS)
    kev_nvd_data = load_or_create_json(DATA_DIR / "cached_kev_nvd.json", DEFAULT_KEV_NVD_EPSS)
    osint_data = load_or_create_json(DATA_DIR / "osint_posts.json", DEFAULT_OSINT_POSTS)

    result = run_osint_agent(assets_data, kev_nvd_data, osint_data)
    output_file = DATA_DIR / "osint_output.json"
    output_file.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))