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


def _page_with(incidents):
    page = DashboardPage.__new__(DashboardPage)
    page.incidents = incidents
    page.closed_incidents = {}
    page.show_closed = False
    page.priority_filter = "All"
    page.incident_query = ""
    return page


def test_show_closed_lists_only_incidents_closed_in_this_session():
    incs = [{"id": "INC-1", "priority": "P1"}, {"id": "INC-2", "priority": "P2"}]
    page = _page_with(incs)
    assert [i["id"] for i in page._visible_incidents()] == ["INC-1", "INC-2"]
    page.show_closed = True
    assert page._visible_incidents() == []                         # nothing closed yet: blank
    page.closed_incidents["INC-2"] = {"reason": "Resolved"}
    assert [i["id"] for i in page._visible_incidents()] == ["INC-2"]
    page.show_closed = False
    assert [i["id"] for i in page._visible_incidents()] == ["INC-1"]
    assert _page_with(incs).closed_incidents == {}                 # a reload starts from the beginning
