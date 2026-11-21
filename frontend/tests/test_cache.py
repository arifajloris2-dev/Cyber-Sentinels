"""Precomputed engine results and AI explanations: reused while nothing changed, never stale."""
import shutil
from pathlib import Path

import pytest

from frontend import cache, precompute
from frontend.data_provider import IntegratedAgentProvider

SAMPLE = Path(__file__).resolve().parents[2] / "backend" / "soc" / "sample_logs"


@pytest.fixture()
def logs(tmp_path):
    d = tmp_path / "logs"
    shutil.copytree(SAMPLE, d, ignore=shutil.ignore_patterns("out"))
    return d


def test_engine_result_is_reused_and_invalidated_when_a_log_changes(logs):
    p = IntegratedAgentProvider(logs)
    first = p.load()
    assert p.from_cache is False and (logs / "out" / cache.ENGINE_FILE).exists()
    second = p.load()
    assert p.from_cache is True
    assert [i["id"] for i in first.incidents] == [i["id"] for i in second.incidents]
    assert len(first.events) == len(second.events) and type(second.events[0]["time"]).__name__ == "datetime"
    log = next(f for f in logs.iterdir() if f.suffix == ".log")
    log.write_text(log.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    p.load()
    assert p.from_cache is False                    # any change to the logs means a fresh analysis


def test_ai_fingerprint_is_the_same_for_fresh_and_cached_data_and_changes_with_model(logs):
    p = IntegratedAgentProvider(logs)
    fresh, cached = p.load(), p.load()
    a, _ = cache.ai_payload(fresh.incidents[0], fresh)
    b, _ = cache.ai_payload(cached.incidents[0], cached)
    assert cache.ai_fingerprint(a, "qwen3:4b") == cache.ai_fingerprint(b, "qwen3:4b")
    assert cache.ai_fingerprint(a, "qwen3:4b") != cache.ai_fingerprint(a, "qwen2.5:7b")
    a["events"][0]["message"] += " changed"
    assert cache.ai_fingerprint(a, "qwen3:4b") != cache.ai_fingerprint(b, "qwen3:4b")


def test_precompute_explains_every_incident_once_then_reuses(logs, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(precompute, "check_ollama_model", lambda url, model: None)
    monkeypatch.setattr(precompute, "analyze_incident",
                        lambda payload, **kw: calls.append(payload["incident_id"]) or {"summary": "prepared", "evidence": ["E1"]})
    assert precompute.main(["--logs", str(logs)]) == 0
    n = len(calls)
    assert n >= 1 and len(cache.AiCache(logs).items) == n
    assert precompute.main(["--logs", str(logs)]) == 0
    assert len(calls) == n and "already prepared" in capsys.readouterr().out      # nothing asked twice


def test_cache_files_are_plain_json(logs):
    IntegratedAgentProvider(logs).load()
    import gzip
    import json
    with gzip.open(logs / "out" / cache.ENGINE_FILE, "rt", encoding="utf-8") as fh:
        assert "fingerprint" in json.load(fh)      # data only: loading it can never run code
