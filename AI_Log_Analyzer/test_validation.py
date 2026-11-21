import json

import pytest

from AI_Log_Analyzer.ai_log_analyzer import (
    OllamaError,
    RESULT_SCHEMA,
    _local_api_url,
    build_dashboard_incident,
    build_messages,
    build_payload,
    configured_ollama_url,
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
    assert payload["context"]["source_health"] == []
    assert payload["context"]["other_agent_briefing"] == advisories["INC-1"]
    assert evidence_refs == {"E1": "log:12"}


def test_dashboard_adapter_limits_source_health_to_incident_hosts_and_evidence():
    incident = {
        "id": "INC-1",
        "hosts": [{"host": "server-1"}],
        "alerts": [
            {
                "time": "2026-11-20T10:01:00Z",
                "rule": "AUTH-003",
                "evidence": [{"id": "log:12", "source": "auth-1", "raw": "failed login"}],
            }
        ],
    }
    sources = [
        {"source": "auth-1", "host": "server-1", "ok": False, "silent": [{"minutes": 90}]},
        {"source": "auth-healthy", "host": "server-1", "ok": True},
        {"source": "zeek", "host": "sensor-1", "ok": False},
        {"source": "auth-2", "host": "server-2", "ok": False},
    ]

    payload, _ = build_dashboard_incident(incident, sources=sources)

    assert payload["context"]["source_health"] == [sources[0]]


def test_ollama_payload_allows_enough_tokens_for_the_complete_json_response():
    payload = build_payload("qwen3:4b", build_messages({"events": []}))

    assert payload["options"]["num_predict"] == 768


def test_ollama_allows_private_lan_ip():
    assert _local_api_url("http://192.168.1.50:11434", "/api/tags") == (
        "http://192.168.1.50:11434/api/tags"
    )


def test_configured_ollama_url_reads_private_endpoint_from_environment(monkeypatch):
    monkeypatch.setenv("OLLAMA_URL", "http://192.168.1.50:11434")

    assert configured_ollama_url() == "http://192.168.1.50:11434"


def test_ollama_rejects_non_default_ports():
    with pytest.raises(OllamaError, match="port 11434"):
        _local_api_url("http://192.168.1.50:8080", "/api/tags")


def test_ollama_rejects_public_hosts_without_sending_data():
    with pytest.raises(OllamaError, match="private LAN"):
        query_ollama("http://203.0.113.50:11434", {}, timeout=1)
