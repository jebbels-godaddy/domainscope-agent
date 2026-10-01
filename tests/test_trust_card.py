"""Tests for trust_card.build_trust_card.

The SDK's verify-trust-card command (godaddy/ans-sdk-go) requires a
top-level `agentId` field on the served Trust Card body to resolve the
registration without parsing the SCITT receipt envelope. These tests
pin that contract: agent_id present → top-level agentId in body;
absent → no agentId field. Production agents always pass it once
register has completed.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    generate_private_key,
)
from cryptography.x509.oid import NameOID

from domainscope_agent.trust_card import build_trust_card


def _write_self_signed_cert(out_path: Path, cn: str = "test-agent.example.com") -> None:
    key = generate_private_key(SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    out_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_ed25519_key(out_path: Path) -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    out_path.write_bytes(pem)


@pytest.fixture
def card_inputs(tmp_path: Path) -> dict[str, Any]:
    cert_path = tmp_path / "id.pem"
    ed_path = tmp_path / "ed.key"
    _write_self_signed_cert(cert_path)
    _write_ed25519_key(ed_path)
    return {
        "ans_name": "ans://v1.0.0.test-agent.example.com",
        "agent_display_name": "Test Agent",
        "agent_host": "test-agent.example.com",
        "version": "1.0.0",
        "agent_url": "https://test-agent.example.com",
        "endpoints": [
            {"protocol": "A2A", "agentUrl": "https://test-agent.example.com"},
        ],
        "identity_cert_pem_path": cert_path,
        "ed25519_private_key_pem_path": ed_path,
    }


def test_build_trust_card_includes_top_level_agent_id_when_passed(card_inputs):
    """SDK verify-trust-card resolves the registration via top-level agentId."""
    body = build_trust_card(**card_inputs, agent_id="60cb2fb1-5a0d-4123-b1be-b637240d930b")
    assert body["agentId"] == "60cb2fb1-5a0d-4123-b1be-b637240d930b"


def test_build_trust_card_omits_agent_id_when_none(card_inputs):
    """Pre-registration boot path: no agent_id, no top-level agentId field."""
    body = build_trust_card(**card_inputs)
    assert "agentId" not in body


def test_build_trust_card_agent_id_coexists_with_receipt(card_inputs):
    """agentId and transparencyReceipt are independent; both can be set."""
    body = build_trust_card(
        **card_inputs,
        agent_id="d96b9e90-605c-4307-a7eb-d72234fd90f8",
        transparency_receipt="0oRYH6QBJgRENXYXlg+iAWhhbnMtZGVtbw==",
    )
    assert body["agentId"] == "d96b9e90-605c-4307-a7eb-d72234fd90f8"
    assert body["transparencyReceipt"].startswith("0oRYH")


def test_build_trust_card_required_fields_present(card_inputs):
    """The base contract: ansName, agentHost, version, endpoints, keys."""
    body = build_trust_card(**card_inputs, agent_id=str(uuid.uuid4()))
    for required in ("ansName", "agentDisplayName", "version", "agentHost", "endpoints", "keys"):
        assert required in body, f"missing required field: {required}"
    assert isinstance(body["keys"], list) and len(body["keys"]) == 1
