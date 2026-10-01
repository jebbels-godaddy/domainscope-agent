"""Tests for register.py's V2 anchor wire shape.

PR review surfaced that the anchor-selection branch in register.py
chose its own field names and route. The contract is set by the
godaddy/ans V2 register handler at internal/ra/handler/registration.go:

  POST /v2/ans/agents
  body { ..., anchor: { anchorType: "...", input: "..." }, ... }

These tests pin both the route and the payload shape so a future
refactor cannot drift back to the wrong contract without flagging here.
The HTTP call is mocked through httpx.MockTransport; the tests never
hit a real RA.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from domainscope_agent import config


def _required_env(monkeypatch, tmp_path: Path, **overrides) -> None:
    """Set the env vars register.py reads."""
    base = {
        "ANS_AGENT_HOST": "agent.test",
        "ANS_AGENT_VERSION": "1.0.0",
        "ANS_RA_BASE_URL": "http://ra.test",
        "ANS_TL_BASE_URL": "http://tl.test",
        "ANS_IDENTITY_CERT_PEM": str(tmp_path / "identity.pem"),
        "ANS_ED25519_PRIVATE_KEY_PEM": str(tmp_path / "ed.key"),
        "ANS_STATE_DB": str(tmp_path / "agent.sqlite3"),
        "ANS_REGISTER_PROPAGATION_S": "0",
    }
    base.update(overrides)
    for k, v in base.items():
        monkeypatch.setenv(k, v)
    for opt in (
        "ANS_AGENT_ANCHOR_TYPE",
        "ANS_AGENT_ANCHOR_VALUE",
        "ANS_AGENT_ANCHOR_ATTESTATION_JWK",
    ):
        if opt not in overrides:
            monkeypatch.delenv(opt, raising=False)


def test_lei_register_targets_v2_endpoint_with_correct_payload_shape(
    monkeypatch, tmp_path: Path,
):
    """LEI anchor → POST /v2/ans/agents with anchor: {anchorType, input}.

    Pins all six contract points the V2 register handler enforces:
    1. Route is /v2/ans/agents (not /v1/agents/register).
    2. Body carries anchor.anchorType (not type).
    3. Body carries anchor.input (not value).
    4. version field is NOT in the body.
    5. identityCsrPEM is NOT in the body (base-only).
    6. agentHost still carries the operational FQDN.
    """
    _required_env(
        monkeypatch, tmp_path,
        ANS_AGENT_ANCHOR_TYPE="lei",
        ANS_AGENT_ANCHOR_VALUE="529900T8BM49AURSDO55",
    )

    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        # Capture only the first POST (the register call). Later
        # requests in the flow (verify-acme, verify-dns, GET details)
        # would otherwise overwrite the captured shape.
        if request.method == "POST" and "url" not in captured:
            captured["url"] = str(request.url)
            captured["path"] = request.url.path
            captured["method"] = request.method
            captured["body"] = json.loads(request.content)
        # Stub a successful register response; the rest of the
        # register flow does not run because we only care about the
        # POST shape.
        return httpx.Response(
            200,
            json={
                "status": "PENDING_VALIDATION",
                "links": [{"href": "http://ra.test/v1/agents/agent-uuid-123", "rel": "self"}],
                "challenges": [],
            },
        )

    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def fake_client(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr("httpx.Client", fake_client)

    cfg = config.load()
    # Skip the rest of the flow (verify-acme polls etc.); call register
    # via the same module entrypoint and stop after the first POST by
    # raising in the response-handling code. Easier: import and call
    # the inner generator path directly. For this test we just want
    # the first POST captured.
    from domainscope_agent import register
    try:
        register.register(cfg)
    except SystemExit:
        # The mock returns a sparse response that downstream verify
        # paths treat as a hard error; we accept the early exit.
        pass
    except httpx.HTTPError:
        pass
    except Exception:
        pass

    assert captured.get("method") == "POST", f"method: {captured}"
    assert captured.get("path") == "/v2/ans/agents", f"path: {captured.get('path')!r}"

    body = captured.get("body")
    assert isinstance(body, dict)
    assert "anchor" in body, f"missing anchor block: {body}"
    assert body["anchor"] == {
        "anchorType": "lei",
        "input": "529900T8BM49AURSDO55",
    }, f"anchor block: {body['anchor']}"
    assert body.get("agentHost") == "agent.test"
    assert "version" not in body, f"version must be absent for base-only LEI: {body}"
    assert "identityCsrPEM" not in body, (
        f"identityCsrPEM must be absent for base-only LEI: {body.keys()}"
    )


def test_fqdn_register_keeps_legacy_v1_route(monkeypatch, tmp_path: Path):
    """FQDN anchor → POST /v1/agents/register with version + identityCsrPEM.

    The legacy path is unchanged; switching to V2 only happens for
    non-FQDN anchors. Pins this to keep the FQDN flow stable.
    """
    _required_env(monkeypatch, tmp_path)  # no anchor overrides → defaults to fqdn

    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and "path" not in captured:
            captured["path"] = request.url.path
            captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "status": "PENDING_VALIDATION",
                "links": [{"href": "http://ra.test/v1/agents/agent-uuid-fqdn", "rel": "self"}],
                "challenges": [],
            },
        )

    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def fake_client(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr("httpx.Client", fake_client)

    cfg = config.load()
    from domainscope_agent import register
    try:
        register.register(cfg)
    except Exception:
        pass

    assert captured.get("path") == "/v1/agents/register", (
        f"FQDN must keep /v1/agents/register: {captured.get('path')!r}"
    )
    body = captured.get("body")
    assert isinstance(body, dict)
    assert "anchor" not in body, f"FQDN must not carry anchor block: {body.keys()}"
    assert body.get("version") == "1.0.0"
    assert body.get("agentHost") == "agent.test"


def test_malformed_attestation_jwk_fails_at_config_load(monkeypatch, tmp_path: Path):
    """A malformed JWK value MUST be rejected at config load, not after
    register.py has generated key material on disk."""
    _required_env(
        monkeypatch, tmp_path,
        ANS_AGENT_ANCHOR_TYPE="lei",
        ANS_AGENT_ANCHOR_VALUE="529900T8BM49AURSDO55",
        ANS_AGENT_ANCHOR_ATTESTATION_JWK="not{ valid }json",
    )
    with pytest.raises(RuntimeError, match="ANS_AGENT_ANCHOR_ATTESTATION_JWK"):
        config.load()


# --- Identity-cert response parsing ---


def test_extract_identity_cert_pem_picks_latest_validfrom():
    """RA returns a JSON array; choose the cert with the latest validFrom."""
    from domainscope_agent.register import _extract_identity_cert_pem

    response = [
        {
            "certificateValidFrom": "2026-01-01T00:00:00Z",
            "certificatePEM": "-----BEGIN CERTIFICATE-----\nOLD\n-----END CERTIFICATE-----\n",
            "chainPEM": "-----BEGIN CERTIFICATE-----\nOLD-CA\n-----END CERTIFICATE-----\n",
        },
        {
            "certificateValidFrom": "2026-05-01T00:00:00Z",
            "certificatePEM": "-----BEGIN CERTIFICATE-----\nNEW\n-----END CERTIFICATE-----\n",
            "chainPEM": "-----BEGIN CERTIFICATE-----\nNEW-CA\n-----END CERTIFICATE-----\n",
        },
    ]
    pem = _extract_identity_cert_pem(response)
    assert pem.startswith("-----BEGIN CERTIFICATE-----\nNEW\n")
    assert "NEW-CA" in pem
    assert "OLD" not in pem


def test_extract_identity_cert_pem_single_entry_concatenates_leaf_and_chain():
    """Fresh registrations return a one-element array. Leaf + chain form the bundle."""
    from domainscope_agent.register import _extract_identity_cert_pem

    leaf = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n"
    chain = "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----\n"
    pem = _extract_identity_cert_pem([{
        "certificateValidFrom": "2026-05-18T00:00:00Z",
        "certificatePEM": leaf,
        "chainPEM": chain,
    }])
    assert pem == leaf + chain


def test_extract_identity_cert_pem_empty_response_returns_none():
    """Base-only DID and LEI registrations get a 200 with [] from the RA;
    the helper returns None so the caller can persist state without
    aborting the registration."""
    from domainscope_agent.register import _extract_identity_cert_pem
    assert _extract_identity_cert_pem([]) is None


def test_extract_identity_cert_pem_compares_validfrom_by_instant_not_lex():
    """RFC 3339 strings with different UTC offsets can sort lexically out
    of chronological order. The helper parses to datetime and compares
    by instant so the rotation case picks the genuinely-latest cert."""
    from domainscope_agent.register import _extract_identity_cert_pem

    # Lex order: "2026-05-18T01:00:00+05:00" sorts AFTER "2026-05-18T00:30:00Z",
    # but the +05:00 entry actually represents 20:00 UTC the prior day, so it
    # is the OLDER instant. A correct parser picks the Z-suffixed entry.
    response = [
        {
            "certificateValidFrom": "2026-05-18T01:00:00+05:00",
            "certificatePEM": "-----BEGIN CERTIFICATE-----\nOFFSET\n-----END CERTIFICATE-----\n",
            "chainPEM": "-----BEGIN CERTIFICATE-----\nOFFSET-CA\n-----END CERTIFICATE-----\n",
        },
        {
            "certificateValidFrom": "2026-05-18T00:30:00Z",
            "certificatePEM": "-----BEGIN CERTIFICATE-----\nLATER\n-----END CERTIFICATE-----\n",
            "chainPEM": "-----BEGIN CERTIFICATE-----\nLATER-CA\n-----END CERTIFICATE-----\n",
        },
    ]
    pem = _extract_identity_cert_pem(response)
    assert "LATER" in pem
    assert "OFFSET" not in pem


def test_extract_identity_cert_pem_missing_leaf_raises():
    from domainscope_agent.register import _extract_identity_cert_pem
    with pytest.raises(ValueError, match="certificatePEM"):
        _extract_identity_cert_pem([{
            "certificateValidFrom": "2026-05-18T00:00:00Z",
            "chainPEM": "-----BEGIN CERTIFICATE-----\nC\n-----END CERTIFICATE-----\n",
        }])
