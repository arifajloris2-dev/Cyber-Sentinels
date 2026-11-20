from datetime import datetime, timezone

import pytest

from frontend.data_provider import SocPipelineProvider
from frontend.app import instant_overview
from frontend.models import DashboardSnapshot


def test_snapshot_rejects_malformed_agent_output():
    with pytest.raises(ValueError, match="incidents"):
        DashboardSnapshot.from_mapping({"incidents": {}, "sources": []})


def test_snapshot_accepts_optional_agent_handoffs():
    snapshot = DashboardSnapshot.from_mapping(
        {
            "generated_at": "2026-11-20T12:00:00Z",
            "incidents": [],
            "sources": [],
            "threat_findings": [{"title": "External advisory"}],
            "advisories": {"INC-1": {"explanation": "Evidence-linked explanation"}},
        }
    )

    assert snapshot.generated_at == datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
    assert snapshot.threat_findings[0]["title"] == "External advisory"
    assert snapshot.advisories["INC-1"]["explanation"] == "Evidence-linked explanation"


def test_soc_provider_maps_pipeline_results_to_dashboard_snapshot():
    from pathlib import Path

    log_dir = Path(__file__).resolve().parents[2] / "backend" / "soc" / "sample_logs"
    snapshot = SocPipelineProvider(log_dir).load()

    assert snapshot.incidents
    assert snapshot.sources
    assert all("evidence" in alert for incident in snapshot.incidents for alert in incident["alerts"])


def test_instant_overview_summarizes_incident_without_exposing_raw_logs():
    incident = {
        "id": "INC-1",
        "title": "Correlated authentication activity",
        "priority": "P1",
        "alerts": [{"evidence": [{"raw": "sensitive raw log line"}]}],
        "hosts": [{"host": "server-1"}],
        "stages": ["entry", "lateral movement"],
    }

    summary = instant_overview(incident)

    assert "P1 incident" in summary
    assert "1 alert(s)" in summary
    assert "server-1" in summary
    assert "sensitive raw log line" not in summary
