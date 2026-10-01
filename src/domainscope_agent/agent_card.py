"""A2A v0.3 AgentCard builder for the ANS reference agent.

Produces a complete A2A v0.3 AgentCard JSON dict. Field selection mirrors the
protobuf definition in `a2a.types.a2a_pb2.AgentCard`:

  REQUIRED:  name, description, version, supportedInterfaces, capabilities,
             defaultInputModes, defaultOutputModes, skills
  OPTIONAL:  provider, documentationUrl, securitySchemes, securityRequirements,
             signatures, iconUrl

The card is JCS-canonicalized (RFC 8785) and detached-JWS signed with the same
Ed25519 key that signs the Trust Card and the Web Bot Auth directory. Verifiers
recover the public key from the JWK thumbprint (kid) and the x5c chain on the
matching JWK in the Trust Card.

MCP availability is declared through `capabilities.extensions` per A2A v0.3
extension semantics (rather than overloading `supportedInterfaces`, which is
defined for A2A protocol bindings only).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from domainscope_agent.trust_card import (
    _b64url_nopad,
    _ed25519_jwk_with_x5c,
    _load_cert_chain_der,
    _load_ed25519_private_key,
)


A2A_PROTOCOL_VERSION = "0.3"
MCP_PROTOCOL_VERSION = "2025-03-26"


def _jcs_bytes(obj: Any) -> bytes:
    """Canonicalize per RFC 8785 (subset: sorted keys, no whitespace, UTF-8)."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sign_card(card_no_sig: dict, ed_key: Ed25519PrivateKey, kid: str) -> dict:
    """Return one AgentCardSignature entry (detached JWS) over the canonical card."""
    canonical = _jcs_bytes(card_no_sig)
    protected_header = {"alg": "EdDSA", "kid": kid, "typ": "agent-card+jws"}
    protected_b64 = _b64url_nopad(_jcs_bytes(protected_header))
    payload_b64 = _b64url_nopad(canonical)
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    signature = ed_key.sign(signing_input)
    return {
        "protected": protected_b64,
        "signature": _b64url_nopad(signature),
        "header": {"kid": kid},
    }


def build_agent_card_dict(
    *,
    agent_name: str,
    agent_description: str,
    agent_host: str,
    agent_url: str,
    version: str,
    organization: str,
    organization_url: str,
    documentation_url: str,
    icon_url: str | None,
    mcp_endpoint_url: str | None,
    identity_cert_pem_path: Path | None = None,
    ed25519_private_key_pem_path: Path | None = None,
) -> dict[str, Any]:
    """Build the A2A v0.3 AgentCard.

    When both `identity_cert_pem_path` and `ed25519_private_key_pem_path` are
    provided, the card includes a `signatures` array with one detached-JWS
    entry. Verifiers find the matching public key on the Trust Card's JWKS by
    JWK thumbprint (kid).
    """
    capabilities: dict[str, Any] = {
        "streaming": False,
        "pushNotifications": False,
        "extendedAgentCard": False,
    }
    if mcp_endpoint_url is not None:
        capabilities["extensions"] = [
            {
                "uri": "https://modelcontextprotocol.io",
                "description": "MCP server exposing the same skills as MCP tools.",
                "required": False,
                "params": {
                    "endpoint": mcp_endpoint_url,
                    "transport": "streamable-http",
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "discoveryUrl": f"{agent_url}/.well-known/mcp.json",
                },
            }
        ]

    skills = [
        {
            "id": "echo",
            "name": "Echo",
            "description": (
                "Returns the input string unchanged. The reference skill exists "
                "to demonstrate end-to-end ANS registration, A2A request "
                "handling, and MCP tool invocation against a registered agent. "
                "Production agents replace this with their actual skill set."
            ),
            "tags": ["reference", "echo", "demo"],
            "examples": [
                "Echo: hello world",
                "Echo back the registration ID 550e8400-e29b-41d4-a716-446655440000",
            ],
            "inputModes": ["text/plain", "application/json"],
            "outputModes": ["text/plain", "application/json"],
        },
    ]

    security_schemes: dict[str, Any] = {
        "ansIdentityCert": {
            "type": "mutualTLS",
            "description": (
                "ANS Identity Certificate issued by the ANS Registration "
                "Authority. The agent presents this cert during the TLS "
                "handshake; clients verify against the chain advertised in "
                f"the Trust Card's keys[].x5c at "
                f"{agent_url}/.well-known/ans/trust-card.json"
            ),
        },
        "httpMessageSignatures": {
            "type": "http",
            "scheme": "signature",
            "description": (
                "RFC 9421 HTTP Message Signatures over response components, "
                "using the Ed25519 key advertised in the Trust Card. Public "
                "key directory at "
                f"{agent_url}/.well-known/http-message-signatures-directory"
            ),
        },
    }

    card: dict[str, Any] = {
        "name": agent_name,
        "description": agent_description,
        "version": version,
        "protocolVersion": A2A_PROTOCOL_VERSION,
        "provider": {
            "organization": organization,
            "url": organization_url,
        },
        "documentationUrl": documentation_url,
        "supportedInterfaces": [
            {
                "url": agent_url,
                "protocolBinding": "jsonrpc",
                "protocolVersion": A2A_PROTOCOL_VERSION,
            }
        ],
        "capabilities": capabilities,
        "securitySchemes": security_schemes,
        "securityRequirements": [
            {"ansIdentityCert": []},
        ],
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "skills": skills,
    }
    if icon_url is not None:
        card["iconUrl"] = icon_url

    if identity_cert_pem_path is not None and ed25519_private_key_pem_path is not None:
        ed_key = _load_ed25519_private_key(ed25519_private_key_pem_path)
        cert_chain_der = _load_cert_chain_der(identity_cert_pem_path)
        jwk = _ed25519_jwk_with_x5c(ed_key.public_key(), cert_chain_der)
        kid = jwk["kid"]
        card["signatures"] = [_sign_card(card, ed_key, kid)]

    return card


def build_a2a_protobuf_card(
    *,
    agent_name: str,
    agent_description: str,
    agent_url: str,
    version: str,
    organization: str,
    organization_url: str,
    documentation_url: str,
    skills: list[dict[str, Any]],
):
    """Return the A2A SDK protobuf AgentCard.

    The A2A SDK pipeline (DefaultRequestHandlerV2) needs the protobuf form. The
    SDK also serves a JSON projection via agent_card_to_dict; the agent's own
    /.well-known/agent-card.json route serves the spec-complete dict from
    build_agent_card_dict() so the signatures field is present.
    """
    from a2a.types.a2a_pb2 import (
        AgentCard,
        AgentCapabilities,
        AgentInterface,
        AgentSkill,
        AgentProvider,
    )

    return AgentCard(
        name=agent_name,
        description=agent_description,
        version=version,
        documentation_url=documentation_url,
        provider=AgentProvider(organization=organization, url=organization_url),
        supported_interfaces=[
            AgentInterface(
                url=agent_url,
                protocol_binding="jsonrpc",
                protocol_version=A2A_PROTOCOL_VERSION,
            )
        ],
        default_input_modes=["text/plain", "application/json"],
        default_output_modes=["text/plain", "application/json"],
        capabilities=AgentCapabilities(streaming=False, push_notifications=False),
        skills=[
            AgentSkill(
                id=s["id"],
                name=s["name"],
                description=s["description"],
                tags=s["tags"],
                examples=s["examples"],
                input_modes=s["inputModes"],
                output_modes=s["outputModes"],
            )
            for s in skills
        ],
    )
