"""MITRE ATT&CK techniques used by the rules (local copy, so the engine works offline)."""
TECHNIQUES = {
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "Persistence"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "Persistence"),
    "T1562.002": ("Impair Defenses: Disable Windows Event Logging", "Defense Evasion"),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", "Defense Evasion"),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", "Defense Evasion"),
}

# stage of the attack, used to tell the incident as a chain: entry -> lateral movement -> impact
STAGE = {"Initial Access": "entry", "Credential Access": "entry", "Discovery": "lateral movement",
         "Lateral Movement": "lateral movement", "Persistence": "impact", "Defense Evasion": "impact",
         "Collection": "impact", "Exfiltration": "impact", "Impact": "impact"}
STAGES = ["entry", "lateral movement", "impact"]


def info(tid: str) -> dict:
    name, tactic = TECHNIQUES.get(tid, ("Unknown technique", "Unknown"))
    return {"id": tid, "name": name, "tactic": tactic, "stage": STAGE.get(tactic, "impact"),
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}
