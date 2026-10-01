"""ASGI app for the ANS reference agent.

Wires the A2A JSON-RPC surface, the streamable-HTTP MCP mount, and the full
set of well-known discovery paths into one Starlette application:

  GET  /.well-known/agent-card.json                       — A2A v0.3 AgentCard (signed)
  GET  /.well-known/agent.json                            — A2A SDK alias
  GET  /.well-known/ans/trust-card.json                   — ANS Trust Card with stapled receipt
  GET  /.well-known/http-message-signatures-directory     — RFC 9421 directory (signed)
  GET  /.well-known/signature-agent-card                  — Web Bot Auth registry path
  GET  /.well-known/mcp.json                              — MCP discovery document
  GET  /.well-known/ai-catalog.json                       — AI Catalog Level-3 manifest
  POST /                                                  — A2A JSON-RPC endpoint
  POST /mcp/                                              — streamable-HTTP MCP endpoint
  GET  /health                                            — liveness probe

The same Ed25519 key signs the A2A AgentCard, the Trust Card's HTTP-message
signature directory, the AI Catalog Trust Manifests, and the published JWK
in the Trust Card's keys array. A verifier authenticating any one of those
artifacts can trust the others through the JWK thumbprint (kid).

The Trust Card body carries the latest SCITT receipt fetched from the TL
under `transparencyReceipt`. A background task refreshes the receipt on
the schedule configured by `ANS_RECEIPT_REFRESH_S` (default 5 minutes).
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

# A2A SDK proto-utils workaround. See comment in webmesh agent's a2a_server.py.
# Patches three helpers in proto_utils that read the deprecated FieldDescriptor
# `label` attribute. Must run before any A2A SDK handler is constructed.
import a2a.utils.proto_utils as _proto_utils
from a2a.utils.proto_utils import (
    ValidationDetail as _ValidationDetail,
    _append_nested_errors as _append_nested_errors,
)
from google.protobuf.descriptor import FieldDescriptor as _FieldDescriptor


def _patched_check_required_field_violation(msg, field):
    val = getattr(msg, field.name)
    if field.is_repeated:
        if not val:
            return _ValidationDetail(
                field=field.name,
                message="Field must contain at least one element.",
            )
    elif field.has_presence:
        if not msg.HasField(field.name):
            return _ValidationDetail(field=field.name, message="Field is required.")
    elif val == field.default_value:
        return _ValidationDetail(field=field.name, message="Field is required.")
    return None


def _patched_recurse_validation(msg, field):
    errors: list[_ValidationDetail] = []
    if field.type != _FieldDescriptor.TYPE_MESSAGE:
        return errors
    val = getattr(msg, field.name)
    if not field.is_repeated:
        if msg.HasField(field.name):
            sub_errs = _proto_utils._validate_proto_required_fields_internal(val)
            _append_nested_errors(errors, field.name, sub_errs)
    elif field.message_type.GetOptions().map_entry:
        for k, v in val.items():
            from google.protobuf.message import Message as _PBMessage
            if isinstance(v, _PBMessage):
                sub_errs = _proto_utils._validate_proto_required_fields_internal(v)
                _append_nested_errors(errors, f"{field.name}[{k}]", sub_errs)
    else:
        for i, item in enumerate(val):
            sub_errs = _proto_utils._validate_proto_required_fields_internal(item)
            _append_nested_errors(errors, f"{field.name}[{i}]", sub_errs)
    return errors


_proto_utils._check_required_field_violation = _patched_check_required_field_violation
_proto_utils._recurse_validation = _patched_recurse_validation


from a2a.server.request_handlers.default_request_handler_v2 import DefaultRequestHandlerV2
from a2a.server.routes.agent_card_routes import create_agent_card_routes
from a2a.server.routes.jsonrpc_routes import create_jsonrpc_routes
from a2a.server.tasks.inmemory_task_store import InMemoryTaskStore
from a2a.utils.constants import DEFAULT_RPC_URL
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from domainscope_agent import config
from domainscope_agent.agent_card import (
    A2A_PROTOCOL_VERSION,
    MCP_PROTOCOL_VERSION,
    build_a2a_protobuf_card,
    build_agent_card_dict,
)
from domainscope_agent.ai_catalog import build_ai_catalog
from domainscope_agent.directory_signer import sign_directory_response
from domainscope_agent.domain_lookup_executor import DomainLookupExecutor
from domainscope_agent.public_mcp_server import session_manager_lifespan, streamable_http_app
from domainscope_agent.state import Receipt, State
from domainscope_agent.trust_card import build_trust_card, fetch_scitt_receipt


_log = logging.getLogger("domainscope_agent")


def _agent_skills(_cfg: config.AgentConfig) -> list[dict[str, Any]]:
    """Skills published in the A2A protobuf card. Mirrors agent_card.py's dict."""
    return [
        {
            "id": "domain-lookup",
            "name": "Domain Lookup",
            "description": (
                "Looks up a domain's registration status over public RDAP: "
                "registration state, nameservers, key dates, and DNSSEC status."
            ),
            "tags": ["rdap", "domain", "dns"],
            "examples": ["example.com"],
            "inputModes": ["text/plain", "application/json"],
            "outputModes": ["text/plain", "application/json"],
        },
    ]


def _agent_description(cfg: config.AgentConfig) -> str:
    return (
        "DomainScope: looks up public domain registration data over RDAP. "
        "ANS-registered with Trust Card hosting and stapled SCITT receipt."
    )


def _build_agent_card_body(cfg: config.AgentConfig) -> dict[str, Any]:
    return build_agent_card_dict(
        agent_name="ANS Reference Agent",
        agent_description=_agent_description(cfg),
        agent_host=cfg.agent_host,
        agent_url=cfg.agent_url,
        version=cfg.version,
        organization=cfg.organization,
        organization_url=cfg.organization_url,
        documentation_url=cfg.documentation_url,
        icon_url=cfg.icon_url,
        mcp_endpoint_url=f"{cfg.agent_url}/mcp",
        identity_cert_pem_path=cfg.identity_cert_pem_path,
        ed25519_private_key_pem_path=cfg.ed25519_private_key_pem_path,
    )


def _endpoints(cfg: config.AgentConfig) -> list[dict[str, Any]]:
    # The wire-format field is metaDataUrl (capital D) per the RA OpenAPI
    # spec at ans-api-spec/api-spec.yaml. Trust Card endpoint records
    # match what register.py submits so a verifier hashing the served
    # body sees byte-identical output to what the RA sealed.
    return [
        {
            "protocol": "A2A",
            "agentUrl": cfg.agent_url,
            "metaDataUrl": f"{cfg.agent_url}/.well-known/agent-card.json",
        },
        {
            "protocol": "MCP",
            "agentUrl": f"{cfg.agent_url}/mcp",
            "metaDataUrl": f"{cfg.agent_url}/.well-known/mcp.json",
        },
    ]


def _build_trust_card_body(cfg: config.AgentConfig, state: State) -> dict[str, Any]:
    """Build the Trust Card from stored registration state.

    When a registration exists in local state, prefer its stored version
    over the env-var cfg value so the served body matches what the RA
    actually sealed at registration time. The cfg.version path remains
    as the bootstrap default for the first serve before register.py has
    persisted anything.
    """
    reg = state.get_registration(cfg.agent_host, cfg.agent_anchor_type)
    receipt_b64: str | None = None
    agent_id: str | None = None
    version = cfg.version
    if reg is not None:
        version = reg.version or cfg.version
        agent_id = reg.agent_id
        rec = state.get_receipt(reg.agent_id)
        if rec is not None:
            receipt_b64 = rec.cose_sign1_b64
    return build_trust_card(
        ans_name=cfg.ans_name,
        agent_display_name="ANS Reference Agent",
        agent_host=cfg.agent_host,
        version=version,
        agent_url=cfg.agent_url,
        endpoints=_endpoints(cfg),
        identity_cert_pem_path=cfg.identity_cert_pem_path,
        ed25519_private_key_pem_path=cfg.ed25519_private_key_pem_path,
        agent_id=agent_id,
        transparency_receipt=receipt_b64,
    )


def _build_mcp_discovery(cfg: config.AgentConfig) -> dict[str, Any]:
    """MCP server discovery document at /.well-known/mcp.json (de-facto path)."""
    return {
        "mcpVersion": MCP_PROTOCOL_VERSION,
        "endpoint": f"{cfg.agent_url}/mcp",
        "transport": "streamable-http",
        "authentication": {
            "schemes": ["none"],
            "notes": "Public RDAP domain lookup tool. No authentication.",
        },
        "agentCardUrl": f"{cfg.agent_url}/.well-known/agent-card.json",
        "trustCardUrl": f"{cfg.agent_url}/.well-known/ans/trust-card.json",
    }


def _build_ai_catalog_body(cfg: config.AgentConfig) -> dict[str, Any]:
    return build_ai_catalog(
        agent_host=cfg.agent_host,
        agent_url=cfg.agent_url,
        agent_display_name="ANS Reference Agent",
        ans_name=cfg.ans_name,
        version=cfg.version,
        organization=cfg.organization,
        documentation_url=cfg.documentation_url,
        registry_uri=cfg.ra_base_url,
        identity_cert_pem_path=cfg.identity_cert_pem_path,
        ed25519_private_key_pem_path=cfg.ed25519_private_key_pem_path,
    )


def _make_app(cfg: config.AgentConfig, state: State) -> Starlette:
    """Construct the Starlette app for the given config."""

    a2a_card = build_a2a_protobuf_card(
        agent_name="ANS Reference Agent",
        agent_description=_agent_description(cfg),
        agent_url=cfg.agent_url,
        version=cfg.version,
        organization=cfg.organization,
        organization_url=cfg.organization_url,
        documentation_url=cfg.documentation_url,
        skills=_agent_skills(cfg),
    )
    handler = DefaultRequestHandlerV2(
        agent_executor=DomainLookupExecutor(),
        task_store=InMemoryTaskStore(),
        agent_card=a2a_card,
    )
    jsonrpc_routes = create_jsonrpc_routes(
        request_handler=handler,
        rpc_url=DEFAULT_RPC_URL,
        enable_v0_3_compat=True,
    )
    a2a_card_routes = create_agent_card_routes(agent_card=a2a_card)

    async def agent_card_endpoint(_request: Request) -> JSONResponse:
        return JSONResponse(_build_agent_card_body(cfg))

    async def trust_card_endpoint(_request: Request) -> JSONResponse:
        return JSONResponse(_build_trust_card_body(cfg, state))

    async def signature_directory_endpoint(request: Request) -> Response:
        body = _build_trust_card_body(cfg, state)
        authority = request.headers.get("host", cfg.agent_host)
        sig_headers = sign_directory_response(
            authority=authority,
            ed25519_private_key_pem_path=cfg.ed25519_private_key_pem_path,
        )
        return Response(
            content=json.dumps(body),
            media_type="application/http-message-signatures-directory+json",
            headers=sig_headers,
        )

    async def signature_agent_card_endpoint(_request: Request) -> JSONResponse:
        return JSONResponse(_build_trust_card_body(cfg, state))

    async def mcp_discovery_endpoint(_request: Request) -> JSONResponse:
        return JSONResponse(_build_mcp_discovery(cfg))

    async def ai_catalog_endpoint(_request: Request) -> Response:
        return Response(
            content=json.dumps(_build_ai_catalog_body(cfg)),
            media_type="application/ai-catalog+json",
        )

    async def health_endpoint(_request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "a2aProtocolVersion": A2A_PROTOCOL_VERSION,
                "mcpProtocolVersion": MCP_PROTOCOL_VERSION,
            }
        )

    @contextlib.asynccontextmanager
    async def _lifespan(_starlette_app: Starlette):
        async with session_manager_lifespan()():
            stop = asyncio.Event()
            refresher = (
                asyncio.create_task(_receipt_refresh_loop(cfg, state, stop))
                if cfg.receipt_refresh_seconds > 0
                else None
            )
            try:
                yield
            finally:
                stop.set()
                if refresher is not None:
                    await refresher

    custom_routes = [
        Route("/.well-known/agent-card.json", agent_card_endpoint, methods=["GET"]),
        Route("/.well-known/agent.json", agent_card_endpoint, methods=["GET"]),
        Route("/.well-known/ans/trust-card.json", trust_card_endpoint, methods=["GET"]),
        Route(
            "/.well-known/http-message-signatures-directory",
            signature_directory_endpoint,
            methods=["GET"],
        ),
        Route(
            "/.well-known/signature-agent-card",
            signature_agent_card_endpoint,
            methods=["GET"],
        ),
        Route("/.well-known/mcp.json", mcp_discovery_endpoint, methods=["GET"]),
        Route("/.well-known/ai-catalog.json", ai_catalog_endpoint, methods=["GET"]),
        Mount("/mcp", app=streamable_http_app()),
        Route("/health", health_endpoint, methods=["GET"]),
    ]

    # custom_routes first: our /.well-known/agent-card.json carries the
    # signatures field and the MCP capabilities extension. The SDK's
    # create_agent_card_routes also registers that path with a thinner body;
    # putting custom_routes ahead lets our route match first.
    return Starlette(
        debug=False,
        lifespan=_lifespan,
        routes=custom_routes + a2a_card_routes + jsonrpc_routes,
    )


async def _receipt_refresh_loop(
    cfg: config.AgentConfig,
    state: State,
    stop: asyncio.Event,
) -> None:
    """Pull the latest SCITT receipt from the TL on the configured schedule."""
    while not stop.is_set():
        try:
            await _refresh_receipt(cfg, state)
        except Exception as exc:  # noqa: BLE001 — refresh failures must not crash the agent
            _log.warning("receipt refresh failed: %s", exc)
        try:
            await asyncio.wait_for(stop.wait(), timeout=cfg.receipt_refresh_seconds)
        except asyncio.TimeoutError:
            continue


async def _refresh_receipt(cfg: config.AgentConfig, state: State) -> None:
    reg = state.get_registration(cfg.agent_host, cfg.agent_anchor_type)
    if reg is None:
        return
    receipt_b64 = await asyncio.to_thread(fetch_scitt_receipt, cfg.tl_base_url, reg.agent_id)
    if receipt_b64 is None:
        return
    state.upsert_receipt(
        Receipt(
            agent_id=reg.agent_id,
            cose_sign1_b64=receipt_b64,
            fetched_at=datetime.now(UTC).isoformat(),
        )
    )


def build_app(cfg: config.AgentConfig | None = None) -> Starlette:
    """Module-level factory used by uvicorn / gunicorn (factory=True).

    Accepts an optional pre-built AgentConfig so callers that already
    loaded one (e.g. __main__.py) don't pay the cost of re-reading the
    environment, and so a single test fixture can drive both code paths.
    """
    if cfg is None:
        cfg = config.load()
    state = State(cfg.state_db_path)
    return _make_app(cfg, state)
