import json
from pathlib import Path
from typing import Any, Dict, List

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"


def load_json(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def detect_suspicious_sequence(steps: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Kontrollon nese ka nje sekuence te dyshimte per te njejtin target/aktivitet:
    p.sh. 1 ose me shume deshtime (failed / missed password) te ndjekura nga nje sukses (login/access),
    plus hapat qe ndodhën pas suksesit.
    """
    failed_count = 0
    success_seen_after_fail = False
    post_success_actions: List[Dict[str, Any]] = []

    for step in steps:
        text = f"{step.get('action', '')} {step.get('status', '')} {step.get('stage', '')}".lower()
        is_fail = any(k in text for k in ["fail", "miss", "invalid", "denied", "wrong password"])
        is_success = any(k in text for k in ["success", "logged on", "login", "access granted", "connected"])

        if is_fail and not success_seen_after_fail:
            failed_count += 1
        elif is_success and failed_count >= 1:
            success_seen_after_fail = True
        elif success_seen_after_fail:
            post_success_actions.append(step)

    suspicious = failed_count >= 1 and success_seen_after_fail
    reason = ""
    if suspicious:
        reason = (
            f"{failed_count} failed/missed attempt(s) followed by successful access, "
            f"with {len(post_success_actions)} follow-up action(s)."
        )

    return {
        "suspicious_fail_then_success": suspicious,
        "failed_attempts_before_success": failed_count,
        "reason": reason,
        "actions_after_success": post_success_actions,
    }


def map_threat_activity(
    assets: List[Dict[str, Any]],
    vuln_intel: List[Dict[str, Any]],
    osint_posts: List[Dict[str, Any]],
    activity_events: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    events = sorted(activity_events or [], key=lambda e: e.get("timestamp", ""))
    mapped_chains: List[Dict[str, Any]] = []

    for post in osint_posts:
        post_id = post.get("post_id", "osint-unknown")
        post_time = post.get("timestamp", "")
        cves = post.get("referenced_cves", [])

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

            what_happened_next = [
                {
                    "timestamp": ev.get("timestamp", ""),
                    "host": ev.get("host", ""),
                    "account": ev.get("account") or ev.get("user") or ev.get("email", ""),
                    "stage": ev.get("stage", "activity"),
                    "status": ev.get("status", ""),
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

            sequence_analysis = detect_suspicious_sequence(what_happened_next)

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
                    "behavior_analysis": sequence_analysis,
                })

    return {
        "member": "Member 1 — OSINT & Threat Intelligence",
        "threat_activity_chains": mapped_chains,
    }


if __name__ == "__main__":
    assets_data = load_json(DATA_DIR / "assets.json")
    kev_nvd_data = load_json(DATA_DIR / "cached_kev_nvd.json")
    osint_data = load_json(DATA_DIR / "osint_posts.json")

    sample_events_path = DATA_DIR / "sample_activity_events.json"
    if sample_events_path.exists():
        events_data = load_json(sample_events_path)
    else:
        events_data = [
            {
                "timestamp": "2026-11-21T01:41:10Z",
                "host": "ws-base-014",
                "account": "svc_ops_night",
                "stage": "entry",
                "status": "failed",
                "action": "Missed password / failed logon attempt on ws-base-014",
            },
            {
                "timestamp": "2026-11-21T01:42:05Z",
                "host": "ws-base-014",
                "account": "svc_ops_night",
                "stage": "entry",
                "status": "failed",
                "action": "Missed password / failed logon attempt on ws-base-014",
            },
            {
                "timestamp": "2026-11-21T01:45:03Z",
                "host": "ws-base-014",
                "account": "svc_ops_night",
                "stage": "entry",
                "status": "success",
                "action": "Successful login on ws-base-014 after failed attempts",
            },
            {
                "timestamp": "2026-11-21T01:52:00Z",
                "host": "srv-gate-ctrl-01",
                "account": "svc_ops_night",
                "stage": "lateral_movement",
                "status": "success",
                "action": "Internal connection to srv-gate-ctrl-01",
            },
            {
                "timestamp": "2026-11-21T01:58:02Z",
                "host": "srv-gate-ctrl-01",
                "account": "svc_ops_night",
                "stage": "impact",
                "status": "success",
                "action": "Unexpected service/configuration activity on srv-gate-ctrl-01",
            },
        ]

    mapped = map_threat_activity(assets_data, kev_nvd_data, osint_data, events_data)
    out_file = DATA_DIR / "threat_activity_map.json"
    out_file.write_text(json.dumps(mapped, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(mapped, indent=2, ensure_ascii=False))