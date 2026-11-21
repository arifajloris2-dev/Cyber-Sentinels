from pathlib import Path
from unittest.mock import Mock

import frontend.app as dashboard_app


def test_default_log_directory_generates_fleet_when_missing(tmp_path, monkeypatch):
    log_dir = tmp_path / "fleet" / "logs"
    generator = tmp_path / "make_fleet.py"
    monkeypatch.setattr(dashboard_app, "DEFAULT_LOGS", log_dir)
    monkeypatch.setattr(dashboard_app, "FLEET_GENERATOR", generator)
    run = Mock()
    monkeypatch.setattr(dashboard_app.subprocess, "run", run)

    dashboard_app._ensure_default_fleet_logs(log_dir)

    run.assert_called_once_with(
        [dashboard_app.sys.executable, str(generator), "--no-ecs"],
        cwd=dashboard_app.ROOT,
        check=True,
    )


def test_existing_default_fleet_logs_are_not_regenerated(tmp_path, monkeypatch):
    log_dir = tmp_path / "fleet" / "logs"
    log_dir.mkdir(parents=True)
    (log_dir / "sources.yaml").touch()
    monkeypatch.setattr(dashboard_app, "DEFAULT_LOGS", log_dir)
    run = Mock()
    monkeypatch.setattr(dashboard_app.subprocess, "run", run)

    dashboard_app._ensure_default_fleet_logs(log_dir)

    run.assert_not_called()


def test_custom_log_directory_is_not_generated(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard_app, "DEFAULT_LOGS", tmp_path / "fleet" / "logs")
    run = Mock()
    monkeypatch.setattr(dashboard_app.subprocess, "run", run)

    dashboard_app._ensure_default_fleet_logs(tmp_path / "custom-logs")

    run.assert_not_called()
