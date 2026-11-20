import json
from ai_log_analyzer import validate_response, RESULT_SCHEMA

print(RESULT_SCHEMA["properties"]["uncertainty"])

valid_ids = {"E1", "E2", "E3"}

report = {
    "summary": "Possible SSH brute-force attack",
    "severity": "High",
    "evidence": ["E1", "E2", "E99"],
    "possible_attack": "Brute force",
    "uncertainty": "Unauthorized access is not confirmed",
    "recommendations": ["Review authentication logs"],
    "mitre_attack": [
        {
            "id": "T1110",
            "name": "Brute Force",
            "evidence": ["E1", "E2"]
        }
    ],
    "commander_summary_en": (
    "Repeated SSH login failures were followed by a successful login. "
    "This may indicate an account compromise, but unauthorized access is not confirmed."
),
    
}

result = validate_response(json.dumps(report), valid_ids)

print(json.dumps(result, indent=2))