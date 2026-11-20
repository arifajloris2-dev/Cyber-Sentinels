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
    "recommendations": ["Review authentication logs"]
}

result = validate_response(json.dumps(report), valid_ids)

print(json.dumps(result, indent=2))