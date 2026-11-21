import json
from pathlib import Path
from typing import Any, Dict, List

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"


def load_json(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def map_threat_activity(
    assets: List[Dict[str, Any]],
    vuln_intel: List[Dict[str, Any]],
    osint_posts: List[Dict[str, Any]],
    activity_events: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """
    Lidh sinjalin e jashtem (OSINT / CVE / llogari / email) me inventarin e aseteve
    dhe gjurmon aktivitetin pasues (çfarë ndodhi pastaj) sipas kohës dhe llogarisë/hostit.
    """
    events = sorted(activity_events or [], key=lambda e: e.get("timestamp", ""))
    mapped_chains: List[Dict[str, Any]] = []

    for post in osint_posts:
        post_id = post.get("post_id", "osint-unknown")
        post_time = post.get("timestamp", "")
        cves = post.get("referenced_cves", [])

        # Gjej CVE-të e lidhura me këtë postim dhe asetet që kanë atë softuer
        matched_cves: List[Dict[str, Any]] = []
        cve_assets: List[str] = []
        for vuln in vuln_intel:
            if vuln.get("cve") in cves:
                affected = [
                    a["asset_id"]
                    for a in assets
                    for sw in a.get("software", [])
                    if sw.get("name") == vuln.get("product")
                    and sw.get("version") in vuln.get("affected_versions", [])
                ]
                matched_cves.append({
                    "cve": vuln["cve"],
                    "cisa_kev": vuln.get("cisa_kev", False),
                    "epss_score": vuln.get("epss_score", 0.0),
                    "affected_assets": affected,
                })
                for aid in affected:
                    if aid not in cve_assets:
                        cve_assets.append(aid)

        # Gjej llogaritë ose email-et e përmendura në postim
        targets: List[str] = list(post.get("leaked_accounts", []))
        if post.get("email"):
            targets.append(post["email"])

        for target in targets:
            related_assets = [
                a["asset_id"]
                for a in assets
                if target in a.get("accounts", []) or target in a.get("emails", [])
            ]
            for aid in cve_assets:
                if aid not in related_assets:
                    related_assets.append(aid)

            # Çfarë aktiviteti ka ndodhur pas postimit/rrjedhjes për këtë target ose aset?
            what_happened_next = [
                {
                    "timestamp": ev.get("timestamp", ""),
                    "host": ev.get("host", ""),
                    "account": ev.get("account") or ev.get("user") or ev.get("email", ""),
                    "stage": ev.get("stage", "activity"),
                    "action": ev.get("action") or ev.get("event") or ev.get("detail", ""),
                }
                for ev in events
                if (
                    ev.get("account") == target
                    or ev.get("user") == target
                    or ev.get("email") == target
                    or ev.get("host") in related_assets
                )
                and (not post_time or ev.get("timestamp", "") >= post_time)
            ]

            # Mbajmë vetëm zinxhirët që prekin asete të bazës ose kanë aktivitet pasues
            if related_assets or what_happened_next:
                mapped_chains.append({
                    "map_id": f"MAP-{post_id}-{target}",
                    "threat_target": target,
                    "initial_signal": {
                        "post_id": post_id,
                        "source": post.get("source", "simulated_osint"),
                        "timestamp": post_time,
                        "confidence": post.get("confidence", 0.5),
                        "summary": post.get("summary", ""),
                    },
                    "related_cves": matched_cves,
                    "impacted_assets": related_assets,
                    "what_happened_next": what_happened_next,
                })

    return {
        "member": "Member 1 — OSINT & Threat Intelligence",
        "threat_activity_chains": mapped_chains,
    }


if __name__ == "__main__":
    assets_data = load_json(DATA_DIR / "assets.json")
    kev_nvd_data = load_json(DATA_DIR / "cached_kev_nvd.json")
    osint_data = load_json(DATA_DIR / "osint_posts.json")

    # Ngjarje shembull për të treguar "çfarë ndodhi pastaj" nëse nuk ka skedar të veçantë
    sample_events_path = DATA_DIR / "sample_activity_events.json"
    if sample_events_path.exists():
        events_data = load_json(sample_events_path)
    else:
        events_data = [
            {
                "timestamp": "2026-11-21T01:45:03Z",
                "host": "ws-base-014",
                "account": "svc_ops_night",
                "stage": "entry",
                "action": "Remote logon observed on ws-base-014",
            },
            {
                "timestamp": "2026-11-21T01:52:00Z",
                "host": "srv-gate-ctrl-01",
                "account": "svc_ops_night",
                "stage": "lateral_movement",
                "action": "Internal SSH connection to srv-gate-ctrl-01",
            },
            {
                "timestamp": "2026-11-21T01:58:02Z",
                "host": "srv-gate-ctrl-01",
                "account": "svc_ops_night",
                "stage": "impact",
                "action": "Unexpected service/configuration activity on srv-gate-ctrl-01",
            },
        ]

    mapped = map_threat_activity(assets_data, kev_nvd_data, osint_data, events_data)
    out_file = DATA_DIR / "threat_activity_map.json"
    out_file.write_text(json.dumps(mapped, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(mapped, indent=2, ensure_ascii=False))