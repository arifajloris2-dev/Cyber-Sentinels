import pytest

from frontend.app import DashboardPage, _format_elapsed_minutes


@pytest.mark.parametrize(
    ("minutes", "expected"),
    [(0, "0m"), (45, "45m"), (60, "1h"), (125, "2h 5m")],
)
def test_format_elapsed_minutes(minutes, expected):
    assert _format_elapsed_minutes(minutes) == expected


def test_silent_source_uses_longest_gap_in_hours():
    page = DashboardPage.__new__(DashboardPage)

    assert page._source_warning(
        {"silent": [{"minutes": 60}, {"minutes": 125}]}
    ) == "SILENT 2h 5m"
