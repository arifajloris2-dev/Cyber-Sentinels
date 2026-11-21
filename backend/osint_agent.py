import json
from pathlib import Path
from typing import Any, Dict, List

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"


def load_json(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def run_osint_agent(
    assets: List[Dict[str, Any]],
    vuln_intel: List[Dict[str, Any]],
    osint_posts: List[Dict[str, Any]],
) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    hunt_requests: List[Dict[str, Any]] = []

    # 1. Perputhja e CVE (CISA KEV, NVD & EPSS) me inventarin e aseteve te bazes
    for vuln in vuln_intel:
        matched_assets = [
            asset["asset_id"]
            for asset in assets
            for sw in asset.get("software", [])
            if sw.get("name") == vuln.get("product")
            and sw.get("version") in vuln.get("affected_versions", [])
        ]
        if matched_assets:
            osint_refs = [
                post["post_id"]
                for post in osint_posts
                if vuln.get("cve") in post.get("referenced_cves", [])
            ]
            cve_id = vuln["cve"]
            finding = {
                "id": f"FIND-{cve_id}",
                "title": f"{cve_id} ({vuln.get('product', 'Software')}) on {', '.join(matched_assets)}",
                "finding_type": "vulnerability_exposure",
                "cve": cve_id,
                "cisa_kev": vuln.get("cisa_kev", False),
                "epss_score": vuln.get("epss_score", 0.0),
                "affected_assets": matched_assets,
                "mitre_techniques": vuln.get("mitre_techniques", []),
                "osint_corroboration": osint_refs,
                "summary": vuln.get("summary", ""),
            }
            findings.append(finding)
            hunt_requests.append({
                "hunt_id": f"HUNT-{cve_id}",
                "target_assets": matched_assets,
                "mitre_techniques": vuln.get("mitre_techniques", []),
                "assigned_to": "Member 2 (SOC Detection & Correlation)",
                "hunt_query": (
                    f"Check system, firewall and auth logs on {matched_assets} for unexpected config/service "
                    f"changes mapped to {vuln.get('mitre_techniques', [])}."
                ),
            })

    # 2. Perputhja e llogarive te permendura ne OSINT me llogarite e bazes
    for post in osint_posts:
        for acct in post.get("leaked_accounts", []):
            acct_assets = [a["asset_id"] for a in assets if acct in a.get("accounts", [])]
            if acct_assets:
                post_id = post.get("post_id", "OSINT")
                finding = {
                    "id": f"FIND-{post_id}-{acct}",
                    "title": f"Leaked Account '{acct}' ({post_id}) across {', '.join(acct_assets)}",
                    "finding_type": "credential_exposure_osint",
                    "post_id": post_id,
                    "source": post.get("source", "simulated_osint"),
                    "timestamp": post.get("timestamp", ""),
                    "account": acct,
                    "affected_assets": acct_assets,
                    "confidence": post.get("confidence", 0.5),
                    "mitre_techniques": ["T1078", "T1110"],
                    "summary": post.get("summary", ""),
                }
                findings.append(finding)
                hunt_requests.append({
                    "hunt_id": f"HUNT-ACCT-{acct}",
                    "target_assets": acct_assets,
                    "mitre_techniques": ["T1078", "T1110", "T1021"],
                    "assigned_to": "Member 2 (SOC Detection & Correlation)",
                    "hunt_query": (
                        f"Correlate failed/successful remote logins and unusual outbound internal connections "
                        f"for account '{acct}' across {acct_assets}."
                    ),
                })

    return {
        "member": "Member 1 — OSINT & Threat Intelligence",
        "threat_findings": findings,
        "structured_threat_findings": findings,
        "targeted_hunt_requests": hunt_requests,
    }


if __name__ == "__main__":
    assets_data = load_json(DATA_DIR / "assets.json")
    kev_nvd_data = load_json(DATA_DIR / "cached_kev_nvd.json")
    osint_data = load_json(DATA_DIR / "osint_posts.json")

    output = run_osint_agent(assets_data, kev_nvd_data, osint_data)
    out_path = DATA_DIR / "osint_output.json"
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(output, indent=2, ensure_ascii=False))