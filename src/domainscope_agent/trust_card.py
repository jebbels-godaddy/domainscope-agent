"""Hybrid Trust Card builder with stapled SCITT receipt.

Produces a JSON body that satisfies both the ANS Trust Card schema
(docs/spec/ans-1-registration.md §A.3) and the Cloudflare Signature Agent Card
schema (draft-meunier-webbotauth-registry) when the agent acts as a Web Bot Auth
client. The keys/botProfile interop fields are defined in
docs/spec/ans-web-bot-auth-profile.md.

The body includes:
  - ANS fields: ansName, agentHost, version, endpoints, etc.
  - keys: JWKS with one Ed25519 JWK carrying x5c chain to the
    Identity Certificate (RFC 7517 §4.7: base64-encoded DER)
  - transparencyReceipt: the SCITT COSE_Sign1 receipt (RFC 9943)
    fetched from the TL after the agent registered. Stapling lets a
    verifier validate the registration offline without contacting
    the live TL.
  - botProfile: optional, present when the agent acts as a Web Bot
    Auth client (omitted by default for an A2A or MCP agent).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

# UUID v4 / v8 shape; agent_id arrives from the registration response
# and is opaque to the agent, but we still validate the shape so a bad
# value cannot smuggle path segments into the receipt URL.
_AGENT_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _b64url_nopad(data: bytes) -> str:
    """Base64url encoding without trailing padding (per RFC 7515 Appendix C)."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _jwk_thumbprint(jwk: dict[str, str]) -> str:
    """Compute JWK SHA-256 thumbprint per RFC 7638 §3.2 / RFC 8037 Appendix A.3."""
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return _b64url_nopad(digest)


def _ed25519_jwk_with_x5c(
    public_key: Ed25519PublicKey,
    cert_chain_der: list[bytes],
) -> dict[str, Any]:
    """Build a JWK (RFC 7517) for an Ed25519 public key with the cert chain in x5c.

    x5c values MUST be base64-encoded DER per RFC 7517 §4.7
    (standard base64, NOT base64url, NOT PEM).
    """
    raw_pubkey = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    x = _b64url_nopad(raw_pubkey)

    jwk: dict[str, Any] = {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
        "use": "sig",
    }
    jwk["kid"] = _jwk_thumbprint(jwk)
    jwk["x5c"] = [base64.b64encode(d).decode("ascii") for d in cert_chain_der]
    return jwk


def _load_cert_chain_der(pem_path: Path) -> list[bytes]:
    """Read a PEM file (one or more concatenated certs) and return DER bytes per cert."""
    pem_data = pem_path.read_bytes()
    certs = x509.load_pem_x509_certificates(pem_data)
    return [c.public_bytes(serialization.Encoding.DER) for c in certs]


def _load_ed25519_private_key(pem_path: Path) -> Ed25519PrivateKey:
    pem_data = pem_path.read_bytes()
    key = serialization.load_pem_private_key(pem_data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"expected Ed25519 private key, got {type(key).__name__}")
    return key


def fetch_scitt_receipt(tl_base_url: str, agent_id: str, timeout: float = 5.0) -> str | None:
    """Fetch the agent's SCITT COSE_Sign1 receipt from the TL.

    Args:
      tl_base_url: Base URL of the Transparency Log service
        (e.g. http://localhost:9090 in local mode, or
        https://transparency.ans.ote-godaddy.com for OTE).
      agent_id: The registered agent's UUID.
      timeout: Per-request timeout in seconds.

    Returns:
      The COSE_Sign1 receipt as base64-encoded bytes, suitable
      for embedding in the Trust Card's transparencyReceipt field.
      Returns None if the TL cannot be reached or the receipt is
      not yet available; callers should retry on a refresh schedule.

    Raises:
      httpx.HTTPStatusError: when the TL returns a non-2xx status
        other than 404 (404 returns None to signal "not yet sealed").
      ValueError: when tl_base_url is not a well-formed http(s) URL or
        agent_id is not a UUID. The caller (an agent operator at
        startup) is the trust boundary; surfacing bad input here beats
        sending malformed URLs into the network.
    """
    parsed = urlparse(tl_base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(
            f"fetch_scitt_receipt: tl_base_url must be an http(s) URL, got {tl_base_url!r}"
        )
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError(
            f"fetch_scitt_receipt: agent_id must be a UUID, got {agent_id!r}"
        )

    url = f"{tl_base_url.rstrip('/')}/v1/agents/{agent_id}/receipt"
    try:
        # follow_redirects=False prevents a malicious or misconfigured TL
        # from redirecting the receipt fetch to an internal endpoint.
        # The TL is operator-supplied configuration, not request-borne
        # user input, but defense-in-depth applies regardless.
        # nosemgrep: godaddy.python.security.packages.ssrf
        response = httpx.get(url, timeout=timeout, follow_redirects=False)
    except httpx.HTTPError:
        return None
    if response.status_code == 404:
        return None
    response.raise_for_status()
    receipt_bytes = response.content
    return base64.b64encode(receipt_bytes).decode("ascii")


def build_trust_card(
    *,
    ans_name: str,
    agent_display_name: str,
    agent_host: str,
    version: str,
    agent_url: str,
    endpoints: list[dict[str, Any]],
    identity_cert_pem_path: Path,
    ed25519_private_key_pem_path: Path,
    agent_id: str | None = None,
    transparency_receipt: str | None = None,
    bot_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the hybrid Trust Card body.

    Args:
      ans_name: ANS identifier (e.g. ans://v1.0.0.agent.example.com).
      agent_display_name: Human-readable name shown in catalogs.
      agent_host: FQDN (e.g. agent.example.com).
      version: SemVer string without the v prefix (e.g. "1.0.0").
      agent_url: HTTPS URL of the agent's primary endpoint.
      endpoints: List of endpoint records (protocol, agentUrl,
        metaDataUrl). The reference agent registers an A2A and an
        MCP endpoint; pass both here. The wire field is metaDataUrl
        (capital D) per the RA OpenAPI spec.
      identity_cert_pem_path: Path to the agent's Identity Certificate
        (PEM, may include the full chain).
      ed25519_private_key_pem_path: Path to the Ed25519 private key PEM.
      agent_id: Optional registration agentId (UUID). When present,
        embedded as the top-level `agentId` field per ANS_SPEC §4.4 so
        verifiers (e.g. ans-cli verify-trust-card) can resolve the
        registration without parsing the receipt envelope. Production
        agents SHOULD always pass this once registration has completed.
      transparency_receipt: Optional base64-encoded SCITT COSE_Sign1
        receipt from the TL. When present, embeds the receipt as
        `transparencyReceipt` per ANS_SPEC §4.4 stapling.
      bot_profile: Optional; populated only when the agent acts as a
        Web Bot Auth client.
    """
    ed_key = _load_ed25519_private_key(ed25519_private_key_pem_path)
    cert_chain_der = _load_cert_chain_der(identity_cert_pem_path)

    body: dict[str, Any] = {
        "ansName": ans_name,
        "agentDisplayName": agent_display_name,
        "version": version,
        "agentHost": agent_host,
        "endpoints": endpoints,
        "keys": [_ed25519_jwk_with_x5c(ed_key.public_key(), cert_chain_der)],
    }
    if agent_id is not None:
        body["agentId"] = agent_id
    if transparency_receipt is not None:
        body["transparencyReceipt"] = transparency_receipt
    if bot_profile is not None:
        if not any(bot_profile.values()):
            raise ValueError("botProfile is present but empty; at least one field MUST be set")
        body["botProfile"] = bot_profile
    return body
