from datetime import datetime, timedelta, timezone

from frontend import search

T0 = datetime(2026, 11, 22, 16, 0, tzinfo=timezone.utc)
EVENTS = [
    {"id": "a:1", "time": T0, "host": "DC-02", "action": "logon", "outcome": "failure", "user": "adm.win", "src_ip": "10.24.3.21",
     "raw": "4625 logon failed"},
    {"id": "a:2", "time": T0 + timedelta(minutes=5), "host": "DC-02", "action": "logon", "outcome": "success", "user": "adm.win",
     "src_ip": "10.24.3.21", "raw": "4624 logon"},
    {"id": "b:1", "time": T0 + timedelta(hours=1), "host": "FS-01", "action": "service-installed", "service": "PSEXESVC",
     "raw": "7045 PSEXESVC installed"},
    {"id": "c:1", "time": T0 + timedelta(hours=2), "host": "srv-mon-01", "action": "flow", "bytes_out": 486000000,
     "src_ip": "10.24.6.10", "raw": "zeek flow"},
]


def test_field_terms_wildcards_negation_and_numbers():
    assert [e["id"] for e in search.search(EVENTS, "host=DC-02 outcome=failure")] == ["a:1"]
    assert [e["id"] for e in search.search(EVENTS, "src=10.24.3.*")] == ["a:1", "a:2"]
    assert [e["id"] for e in search.search(EVENTS, "host=dc-02 outcome!=failure")] == ["a:2"]
    assert [e["id"] for e in search.search(EVENTS, "bytes_out>=50000000")] == ["c:1"]


def test_free_text_and_phrases_search_the_raw_line():
    assert [e["id"] for e in search.search(EVENTS, "psexesvc")] == ["b:1"]
    assert [e["id"] for e in search.search(EVENTS, '"logon failed"')] == ["a:1"]
    assert search.search(EVENTS, '"unclosed') == []          # a broken quote does not crash


def test_time_range_field_stats_and_histogram():
    assert len(search.search(EVENTS, "", start=T0 + timedelta(minutes=30))) == 2
    stats = search.field_stats(EVENTS)
    assert stats["host"][0] == ("DC-02", 2)
    hist = search.histogram(EVENTS, 60)
    assert [n for _, n in hist] == [2, 1, 1]
