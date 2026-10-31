"""Tests for the ThreatLens FastAPI backend."""

from fastapi.testclient import TestClient

import backend.app as api_module


client = TestClient(api_module.app)


def test_health_endpoint():
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["service"] == "ThreatLens API"


def test_invalid_ioc_returns_422():
    response = client.post(
        "/api/ioc/enrich",
        json={
            "value": "999.999.999.999",
            "ioc_type": "IP",
        },
    )

    assert response.status_code == 422


def test_invalid_ioc_type_returns_422():
    response = client.post(
        "/api/ioc/enrich",
        json={
            "value": "8.8.8.8",
            "ioc_type": "INVALID",
        },
    )

    assert response.status_code == 422


def test_enrichment_endpoint(monkeypatch):
    def fake_enrichment(value, ioc_type):
        return {
            "value": value,
            "ioc_type": ioc_type.value,
            "verdict": "Unknown",
        }

    monkeypatch.setattr(
        api_module,
        "enrich_observable",
        fake_enrichment,
    )

    response = client.post(
        "/api/ioc/enrich",
        json={
            "value": "8.8.8.8",
            "ioc_type": "IP",
        },
    )

    assert response.status_code == 200
    assert response.json()["value"] == "8.8.8.8"
    assert response.json()["ioc_type"] == "IP"
