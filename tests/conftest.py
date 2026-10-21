import pytest


@pytest.fixture(autouse=True)
def clean_risk_gate_env(monkeypatch):
    """Keep CI/workflow environment variables from leaking into unit tests."""
    monkeypatch.delenv("RISK_GATE_MODE", raising=False)
    monkeypatch.delenv("SONAR_CONFIGURED", raising=False)