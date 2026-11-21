import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import frontend.app as dashboard_app
from frontend.app import DashboardPage


def test_explanation_does_not_render_after_client_deletion(monkeypatch):
    monkeypatch.setattr(
        dashboard_app.asyncio,
        "to_thread",
        AsyncMock(return_value=({"summary": "done"}, {})),
    )
    page = DashboardPage.__new__(DashboardPage)
    page._client = SimpleNamespace(is_deleted=True)
    page.selected_incident_id = "INC-1"
    page.qwen_in_flight = set()
    page.snapshot = object()
    page.url_input = SimpleNamespace(value="http://127.0.0.1:11434")
    page.model_input = SimpleNamespace(value="qwen3:4b")
    page.qwen_errors = {}
    page.qwen_results = {}
    page._qwen_config_is_verified = lambda: True
    page._render_selected_incident = Mock()

    asyncio.run(page._generate_explanation({"id": "INC-1"}))

    assert page.qwen_in_flight == set()
    page._render_selected_incident.assert_not_called()
