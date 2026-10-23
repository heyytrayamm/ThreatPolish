from __future__ import annotations

import pytest


@pytest.fixture()
def fixture_provider(monkeypatch):
    from app.core.config import reset_settings_cache

    monkeypatch.setenv("TP_CRYPTO_PROVIDER", "fixture")
    reset_settings_cache()
    yield
    reset_settings_cache()


def test_refresh_yields_provenance_and_explainable_risk(client, admin_headers, fixture_provider):
    response = client.post(
        "/api/v1/crypto/refresh",
        headers=admin_headers,
        json={"symbols": ["BTC", "USDT", "SOL"]},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["provider"] == "fixture"
    assert body["synthetic"] is True
    assert len(body["refreshed"]) == 3
    assert body["events"]

    by_symbol = {item["symbol"]: item["risk"] for item in body["refreshed"]}
    assert by_symbol["USDT"]["score"] == 45
    assert any(reason["code"] == "stablecoin_depeg" for reason in by_symbol["USDT"]["reasons"])
    assert by_symbol["SOL"]["score"] == 30
    assert by_symbol["BTC"]["score"] == 0
    assert by_symbol["BTC"]["observed"]["provider"] == "fixture"
    assert by_symbol["BTC"]["observed"]["raw_digest"]

    events = client.get("/api/v1/events?module=cryptointel", headers=admin_headers).json()
    assert events["total"] == 3
    for item in events["items"]:
        assert item["provenance"]["synthetic"] is True
        assert item["event_type"] == "cryptointel.risk_observation"


def test_assets_endpoint_separates_observed_from_inferred(client, admin_headers, fixture_provider):
    client.post(
        "/api/v1/crypto/refresh", headers=admin_headers, json={"symbols": ["BTC", "USDT"]}
    )
    response = client.get("/api/v1/crypto/assets", headers=admin_headers)
    assert response.status_code == 200
    body = response.json()
    assets = {item["symbol"]: item for item in body["items"]}
    assert set(assets) == {"BTC", "USDT"}
    assert assets["BTC"]["observed"]["price_usd"] == 64000.0
    assert assets["BTC"]["inferred"]["severity"] == "info"
    assert assets["USDT"]["inferred"]["severity"] == "medium"
    assert assets["USDT"]["provenance"]["synthetic"] is True
    assert "inference, not a fact" in assets["USDT"]["disclaimer"]
    assert "No wallet addresses" in body["note"]

    history = client.get("/api/v1/crypto/assets/USDT/history", headers=admin_headers).json()
    assert len(history["points"]) == 1
    assert history["points"][0]["risk_score"] == 45


def test_refresh_respects_minimum_interval(client, admin_headers, fixture_provider):
    first = client.post(
        "/api/v1/crypto/refresh", headers=admin_headers, json={"symbols": ["BTC"]}
    )
    assert len(first.json()["refreshed"]) == 1

    second = client.post(
        "/api/v1/crypto/refresh", headers=admin_headers, json={"symbols": ["BTC"]}
    )
    assert second.status_code == 200
    assert second.json()["refreshed"] == []
    assert second.json()["skipped"][0]["symbol"] == "BTC"
    assert second.json()["events"] == []


def test_wallet_secrets_are_rejected(client, admin_headers, fixture_provider):
    response = client.post(
        "/api/v1/crypto/refresh",
        headers=admin_headers,
        json={"symbols": ["BTC"], "seed_phrase": "abandon abandon abandon"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_failed"

    private_key = client.post(
        "/api/v1/crypto/refresh",
        headers=admin_headers,
        json={"symbols": ["BTC"], "private_key": "0xdeadbeef"},
    )
    assert private_key.status_code == 422


def test_unknown_symbol_is_rejected(client, admin_headers, fixture_provider):
    response = client.post(
        "/api/v1/crypto/refresh", headers=admin_headers, json={"symbols": ["NOTACOIN"]}
    )
    assert response.status_code == 422
    assert "unsupported" in response.text.lower()
