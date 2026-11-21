"""MITRE ATT&CK techniques used by the rules (local copy, so the engine works offline)."""
TECHNIQUES = {
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1200": ("Hardware Additions", "Initial Access"),
    "T1566.001": ("Phishing: Spearphishing Attachment", "Initial Access"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "Persistence"),
    "T1498": ("Network Denial of Service", "Impact"),
    "T1136.001": ("Create Account: Local Account", "Persistence"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "Persistence"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "Persistence"),
    "T1562.002": ("Impair Defenses: Disable Windows Event Logging", "Defense Evasion"),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", "Defense Evasion"),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", "Defense Evasion"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1571": ("Non-Standard Port", "Command and Control"),
    "T1573": ("Encrypted Channel", "Command and Control"),
    "T1005": ("Data from Local System", "Collection"),
}

# stage of the attack, used to tell the incident as a chain: entry -> execution -> lateral movement -> command and control -> impact
STAGE = {"Initial Access": "entry", "Credential Access": "entry", "Execution": "execution", "Discovery": "lateral movement",
         "Lateral Movement": "lateral movement", "Command and Control": "command and control", "Persistence": "impact",
         "Defense Evasion": "impact", "Collection": "impact", "Exfiltration": "impact", "Impact": "impact"}
STAGES = ["entry", "execution", "lateral movement", "command and control", "impact"]


def info(tid: str) -> dict:
    name, tactic = TECHNIQUES.get(tid, ("Unknown technique", "Unknown"))
    return {"id": tid, "name": name, "tactic": tactic, "stage": STAGE.get(tactic, "impact"),
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}
