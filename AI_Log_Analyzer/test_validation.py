import json

import pytest

from AI_Log_Analyzer.ai_log_analyzer import (
    OllamaError,
    RESULT_SCHEMA,
    build_dashboard_incident,
    query_ollama,
    validate_response,
)


def test_explanation_schema_does_not_assign_severity():
    assert "severity" not in RESULT_SCHEMA["properties"]
    assert "possible_attack" not in RESULT_SCHEMA["properties"]
    assert "commander_summary_en" in RESULT_SCHEMA["properties"]
    assert RESULT_SCHEMA["properties"]["triage_assessment"]["enum"] == [
        "likely_suspicious",
        "possibly_authorized_or_benign",
        "inconclusive",
    ]


def test_validation_keeps_only_evidence_ids_from_the_incident():
    report = {
        "summary": "The events show repeated authentication failures.",
        "commander_summary_en": "Several logins failed. Authorization is not established.",
        "triage_assessment": "likely_suspicious",
        "evidence": ["E1", "E2", "E99"],
        "uncertainty": "The logs do not establish whether a later login was authorized.",
        "recommendations": ["Review the account's subsequent activity."],
    }

    result = validate_response(json.dumps(report), {"E1", "E2"})

    assert result["evidence"] == ["E1", "E2"]
    assert "severity" not in result


def test_validation_rejects_explanation_without_a_valid_evidence_reference():
    report = {
        "summary": "The events show suspicious activity.",
        "commander_summary_en": "The activity needs review. The logs do not prove intent.",
        "triage_assessment": "inconclusive",
        "evidence": ["E99"],
        "uncertainty": "The events do not prove intent.",
        "recommendations": ["Verify the activity with the system owner."],
    }

    with pytest.raises(ValueError, match="valid evidence IDs"):
        validate_response(json.dumps(report), {"E1"})


def test_dashboard_adapter_includes_deterministic_and_agent_context():
    incident = {
        "id": "INC-1",
        "priority": "P2",
        "score": 42,
        "alerts": [
            {
                "time": "2026-11-20T10:01:00Z",
                "rule": "AUTH-003",
                "text": "Repeated failed logins",
                "evidence": [{"id": "log:12", "source": "auth", "line": 12, "raw": "failed login"}],
            }
        ],
    }
    threat_findings = [{"title": "Example advisory"}]
    sources = [{"source": "auth", "ok": True}]
    advisories = {"INC-1": {"explanation": "Review the account owner confirmation."}}

    payload, evidence_refs = build_dashboard_incident(incident, threat_findings, sources, advisories)

    assert payload["events"][0]["id"] == "E1"
    assert payload["context"]["deterministic_result"]["priority"] == "P2"
    assert payload["context"]["osint_findings"] == threat_findings
    assert payload["context"]["source_health"] == sources
    assert payload["context"]["other_agent_briefing"] == advisories["INC-1"]
    assert evidence_refs == {"E1": "log:12"}


def test_ollama_rejects_non_loopback_hosts_without_sending_data():
    with pytest.raises(OllamaError, match="loopback"):
        query_ollama("http://192.168.1.50:11434", {}, timeout=1)
