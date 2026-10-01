"""AI Catalog builder for the ANS reference agent.

Implements the AI Catalog draft (Unofficial Draft, 14 May 2026) at Level 3
(Trusted Catalog), the specification's highest conformance tier:

  Level 1: specVersion + entries
  Level 2: Level 1 + host
  Level 3: Level 2 + trustManifest on entries with verifiable identity

The catalog indexes the agent's two artifacts:
  1. The A2A v0.3 Agent Card at /.well-known/agent-card.json
  2. The MCP server discovery document at /.well-known/mcp.json

Each entry carries a Trust Manifest with the same Ed25519 key used elsewhere
on the agent. The signature is detached JWS over the JCS-canonicalized Trust
Manifest with the signature field removed. Verifiers can recover the public
key from the JWK thumbprint (kid) and the x5c chain on the matching JWK in
the Trust Card.

Spec: https://agent-card.github.io/ai-catalog/
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from domainscope_agent.trust_card import (
    _b64url_nopad,
    _ed25519_jwk_with_x5c,
    _load_cert_chain_der,
    _load_ed25519_private_key,
)


CATALOG_SPEC_VERSION = "1.0"

A2A_CARD_MEDIA_TYPE = "application/a2a-agent-card+json"
MCP_SERVER_MEDIA_TYPE = "application/mcp-server-card+json"


def _jcs_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sign_trust_manifest(
    manifest: dict[str, Any], ed_key: Ed25519PrivateKey, kid: str
) -> str:
    """Detached JWS over the JCS-canonical Trust Manifest minus its signature.

    Returns the compact-serialized JWS suitable for the manifest's signature
    field per AI Catalog §5.6.2.
    """
    manifest_no_sig = {k: v for k, v in manifest.items() if k != "signature"}
    canonical = _jcs_bytes(manifest_no_sig)
    protected_header = {"alg": "EdDSA", "kid": kid, "typ": "trust-manifest+jws"}
    protected_b64 = _b64url_nopad(_jcs_bytes(protected_header))
    payload_b64 = _b64url_nopad(canonical)
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    signature = ed_key.sign(signing_input)
    return f"{protected_b64}..{_b64url_nopad(signature)}"


def _trust_manifest(
    *,
    identity: str,
    publisher_display_name: str,
    a2a_card_url: str,
    trust_card_url: str,
    registry_uri: str,
    ed_key: Ed25519PrivateKey,
    kid: str,
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "identity": identity,
        "trustSchema": {
            "identifier": "urn:trust:ans-trust-card-v1",
            "version": "1.0",
            "verificationMethods": ["x509", "jwk"],
        },
        "attestations": [
            {
                "type": "publisher-identity",
                "uri": trust_card_url,
                "mediaType": "application/json",
                "description": (
                    f"ANS Trust Card carrying the Identity Certificate chain "
                    f"(JWK x5c) issued by the ANS Registration Authority. "
                    f"The same Ed25519 key (kid={kid}) signs this Trust "
                    f"Manifest, the A2A AgentCard signatures field, and the "
                    f"HTTP Message Signatures over this catalog response."
                ),
            },
            {
                "type": "a2a-agent-card",
                "uri": a2a_card_url,
                "mediaType": A2A_CARD_MEDIA_TYPE,
                "description": (
                    "A2A v0.3 AgentCard with detached-JWS signatures over "
                    "its canonical bytes."
                ),
            },
        ],
        "provenance": [
            {
                "relation": "registeredWith",
                "sourceId": "https://github.com/godaddy/ans",
                "registryUri": registry_uri,
            }
        ],
    }
    manifest["signature"] = _sign_trust_manifest(manifest, ed_key, kid)
    return manifest


def build_ai_catalog(
    *,
    agent_host: str,
    agent_url: str,
    agent_display_name: str,
    ans_name: str,
    version: str,
    organization: str,
    documentation_url: str,
    registry_uri: str,
    identity_cert_pem_path: Path,
    ed25519_private_key_pem_path: Path,
) -> dict[str, Any]:
    """Build the Level-3 AI Catalog body for this agent."""
    ed_key = _load_ed25519_private_key(ed25519_private_key_pem_path)
    cert_chain_der = _load_cert_chain_der(identity_cert_pem_path)
    jwk = _ed25519_jwk_with_x5c(ed_key.public_key(), cert_chain_der)
    kid: str = jwk["kid"]

    publisher_identifier = f"did:web:{agent_host}"
    a2a_card_url = f"{agent_url}/.well-known/agent-card.json"
    mcp_discovery_url = f"{agent_url}/.well-known/mcp.json"
    trust_card_url = f"{agent_url}/.well-known/ans/trust-card.json"

    a2a_entry_id = f"{ans_name}#a2a"
    mcp_entry_id = f"{ans_name}#mcp"

    publisher: dict[str, Any] = {
        "identifier": publisher_identifier,
        "displayName": organization,
        "identityType": "did",
    }

    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    host_trust_manifest = _trust_manifest(
        identity=publisher_identifier,
        publisher_display_name=organization,
        a2a_card_url=a2a_card_url,
        trust_card_url=trust_card_url,
        registry_uri=registry_uri,
        ed_key=ed_key,
        kid=kid,
    )
    a2a_trust_manifest = _trust_manifest(
        identity=a2a_entry_id,
        publisher_display_name=organization,
        a2a_card_url=a2a_card_url,
        trust_card_url=trust_card_url,
        registry_uri=registry_uri,
        ed_key=ed_key,
        kid=kid,
    )
    mcp_trust_manifest = _trust_manifest(
        identity=mcp_entry_id,
        publisher_display_name=organization,
        a2a_card_url=a2a_card_url,
        trust_card_url=trust_card_url,
        registry_uri=registry_uri,
        ed_key=ed_key,
        kid=kid,
    )

    return {
        "specVersion": CATALOG_SPEC_VERSION,
        "host": {
            "displayName": organization,
            "identifier": publisher_identifier,
            "documentationUrl": documentation_url,
            "trustManifest": host_trust_manifest,
        },
        "entries": [
            {
                "identifier": a2a_entry_id,
                "displayName": f"{agent_display_name} (A2A)",
                "version": version,
                "mediaType": A2A_CARD_MEDIA_TYPE,
                "url": a2a_card_url,
                "description": (
                    "Public RDAP domain lookup skill over A2A v0.3 JSON-RPC."
                ),
                "tags": ["a2a", "ans", "rdap", "domain"],
                "publisher": publisher,
                "trustManifest": a2a_trust_manifest,
                "updatedAt": now_iso,
            },
            {
                "identifier": mcp_entry_id,
                "displayName": f"{agent_display_name} (MCP)",
                "version": version,
                "mediaType": MCP_SERVER_MEDIA_TYPE,
                "url": mcp_discovery_url,
                "description": (
                    "Public RDAP domain lookup tool over streamable-HTTP MCP."
                ),
                "tags": ["mcp", "ans", "rdap", "domain"],
                "publisher": publisher,
                "trustManifest": mcp_trust_manifest,
                "updatedAt": now_iso,
            },
        ],
        "metadata": {
            "ansName": ans_name,
            "trustCardUrl": trust_card_url,
        },
    }
