from datetime import datetime, timezone

import pytest

from frontend.data_provider import IntegratedAgentProvider, SocPipelineProvider
from frontend.explanations import instant_overview
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
            "hunt_requests": [{"hunt_id": "HUNT-1", "hunt_query": "Review logs"}],
            "advisories": {"INC-1": {"explanation": "Evidence-linked explanation"}},
        }
    )

    assert snapshot.generated_at == datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)
    assert snapshot.threat_findings[0]["title"] == "External advisory"
    assert snapshot.hunt_requests[0]["hunt_id"] == "HUNT-1"
    assert snapshot.advisories["INC-1"]["explanation"] == "Evidence-linked explanation"


def test_soc_provider_maps_pipeline_results_to_dashboard_snapshot():
    from pathlib import Path

    log_dir = Path(__file__).resolve().parents[2] / "backend" / "soc" / "sample_logs"
    snapshot = SocPipelineProvider(log_dir).load()

    assert snapshot.incidents
    assert snapshot.sources
    assert all("evidence" in alert for incident in snapshot.incidents for alert in incident["alerts"])


def test_integrated_provider_adds_osint_findings():
    from pathlib import Path

    log_dir = Path(__file__).resolve().parents[2] / "backend" / "soc" / "sample_logs"
    snapshot = IntegratedAgentProvider(log_dir).load()

    assert snapshot.incidents
    assert snapshot.threat_findings
    assert snapshot.hunt_requests


def test_csv_simulation_provider_streams_and_reports_evaluation(tmp_path):
    csv_path = tmp_path / "attacks.csv"
    rows = [
        "Timestamp,Source IP Address,Destination IP Address,Source Port,"
        "Destination Port,Protocol,Packet Length,Action Taken,Attack Type,Alerts/Warnings"
    ]
    rows.extend(
        f"2023-05-30 06:33:{n:02d},198.51.100.{n + 1},84.9.164.252,50001,443,TCP,100,Logged,DDoS,Warning"
        for n in range(10)
    )
    rows.extend(
        [
            "2023-05-30 06:34:10,198.51.100.20,84.9.164.252,50003,443,TCP,100,Logged,Malware,Warning",
            "2023-05-30 06:34:11,198.51.100.21,84.9.164.252,50004,22,TCP,100,Logged,Intrusion,Warning",
        ]
    )
    rows.append(
        "2023-05-30 06:34:00,10.50.0.20,84.9.164.252,50002,443,TCP,100,Logged,Normal Traffic,None"
    )
    csv_path.write_text("\n".join(rows) + "\n", encoding="utf-8")

    from frontend.data_provider import CsvSimulationProvider

    snapshot = CsvSimulationProvider(csv_path, batch_size=13, interval_seconds=1).load()

    assert snapshot.evaluation["rows_seen"] == 13
    assert snapshot.evaluation["ground_truth_attacks"] == 12
    assert snapshot.sources
    rules = {alert["rule"] for alert in snapshot.alerts}
    assert {"NET-004", "SYS-001", "AUTH-001"} <= rules
    assert any("bot swarm" in incident["title"].lower() for incident in snapshot.incidents)


def test_csv_simulation_provider_restarts_without_an_empty_refresh(tmp_path):
    csv_path = tmp_path / "short.csv"
    csv_path.write_text(
        "Timestamp,Source IP Address,Destination IP Address,Source Port,"
        "Destination Port,Protocol,Packet Length,Action Taken,Attack Type\n"
        "2023-05-30 06:33:58,198.51.100.1,84.9.164.252,31225,443,TCP,503,Logged,Malware\n",
        encoding="utf-8",
    )
    from frontend.data_provider import CsvSimulationProvider

    provider = CsvSimulationProvider(csv_path, batch_size=1, interval_seconds=1)
    first = provider.load()
    second = provider.load()

    assert first.evaluation["window_rows"] == 1
    assert second.evaluation["window_rows"] == 1
    assert second.evaluation["cycle"] == 2
    assert second.evaluation["rows_seen"] == 2


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


def test_instant_overview_explains_bot_swarm_in_plain_language():
    summary = instant_overview(
        {
            "id": "INC-SWARM",
            "priority": "P1",
            "title": "Possible bot swarm targeting gateway",
            "hosts": [{"host": "gateway"}],
            "alerts": [
                {
                    "rule": "NET-004",
                    "distinct_source_count": 12,
                    "text": "12 different source addresses sent blocked traffic",
                }
            ],
        }
    )

    assert "Possible bot swarm" in summary
    assert "12 different addresses" in summary
    assert "does not prove" in summary
    assert "No system was changed automatically" in summary
