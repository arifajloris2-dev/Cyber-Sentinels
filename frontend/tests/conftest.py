"""Dashboard tests never write to the real audit trail (backend/data/audit)."""
import pytest


@pytest.fixture(autouse=True)
def _private_audit_file(tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_AUDIT_FILE", str(tmp_path / "audit" / "verification.jsonl"))
