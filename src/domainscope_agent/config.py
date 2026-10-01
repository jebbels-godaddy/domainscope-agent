"""Runtime configuration loaded from environment variables.

The reference agent reads its configuration from env vars so the same code
runs in three modes:

  - **local**: against a developer's local RA + TL + DNS dev server
    (the four-binary stack from the godaddy/ans reference implementation).
  - **OTE**: against the GoDaddy OTE environment (real public CA cert,
    real DNS provisioning).
  - **prod**: against the GoDaddy production environment.

All defaults are hard-coded for local development; operators override
individual values by setting the matching env var directly. (Earlier
drafts proposed an ANS_AGENT_MODE switch; the implementation chose
explicit env vars instead because operators end up overriding individual
values either way.)
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AgentConfig:
    """Read-only agent configuration, loaded once at startup."""

    # Identity material
    agent_host: str
    agent_url: str
    ans_name: str
    version: str
    organization: str
    organization_url: str
    documentation_url: str
    icon_url: str | None

    # ANS endpoints
    ra_base_url: str
    tl_base_url: str

    # Local artifacts
    identity_cert_pem_path: Path
    ed25519_private_key_pem_path: Path
    state_db_path: Path

    # Network binding (set non-empty to bind a port; empty disables that protocol)
    a2a_listen: str
    mcp_listen: str

    # Receipt-staple refresh interval, seconds (0 = never refresh after startup)
    receipt_refresh_seconds: int

    # Anchor selection (PR #15-#19 in godaddy/ans).
    # Defaults to FQDN with the agent_host as the anchor value, which is
    # what 100% of pre-Plan-G registrations use. Setting anchor_type to
    # "did:web", "did:key", "did:pkh", or "lei" switches register to
    # build a V2 anchor block instead of relying on FQDN inference; the
    # registration goes through the AnchorResolver path the RA gained
    # in PR #15. anchor_value is the canonical anchor input (the LEI
    # string for lei, the DID URI for did:*, the FQDN for fqdn).
    # anchor_attestation_jwk is the LEI Option B path: the operator
    # supplies the entity's ANS attestation JWK directly, so the RA's
    # AttestationJWKSource has somewhere to find it without reaching
    # into a vLEI Option A flow that may not be available yet.
    agent_anchor_type: str
    agent_anchor_value: str
    agent_anchor_attestation_jwk: str | None


def _required(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        raise RuntimeError(f"environment variable {name} is required")
    return val


def _optional(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def load() -> AgentConfig:
    """Build AgentConfig from the current process environment.

    Required vars (no defaults):
      ANS_AGENT_HOST, ANS_AGENT_VERSION, ANS_RA_BASE_URL, ANS_TL_BASE_URL,
      ANS_IDENTITY_CERT_PEM, ANS_ED25519_PRIVATE_KEY_PEM

    Optional vars (with sensible defaults):
      ANS_AGENT_URL          → derived from ANS_AGENT_HOST
      ANS_AGENT_NAME         → "domainscope-agent"
      ANS_AGENT_ORG          → "Jeremy Ebbels"
      ANS_AGENT_ORG_URL      → ANS_AGENT_URL
      ANS_AGENT_DOC_URL      → ANS_AGENT_URL
      ANS_AGENT_ICON_URL     → unset
      ANS_STATE_DB           → "./domainscope-agent.sqlite3"
      ANS_A2A_LISTEN         → "0.0.0.0:8080" (empty disables A2A)
      ANS_MCP_LISTEN         → "0.0.0.0:8081" (empty disables MCP)
      ANS_RECEIPT_REFRESH_S  → "300" (5 minutes)
      ANS_AGENT_ANCHOR_TYPE  → "fqdn" (also: did:web, did:key, did:pkh, lei)
      ANS_AGENT_ANCHOR_VALUE → defaults to ANS_AGENT_HOST when type=fqdn;
                               required when type is did:* or lei
      ANS_AGENT_ANCHOR_ATTESTATION_JWK → JSON-encoded JWK for LEI Option B
                                          (the entity's ANS attestation key);
                                          ignored for non-lei types
    """
    agent_host = _required("ANS_AGENT_HOST")
    version = _required("ANS_AGENT_VERSION")
    agent_url = _optional("ANS_AGENT_URL", f"https://{agent_host}")

    anchor_type = _optional("ANS_AGENT_ANCHOR_TYPE", "fqdn").lower()
    valid_types = {"fqdn", "did:web", "did:key", "did:pkh", "lei"}
    if anchor_type not in valid_types:
        raise RuntimeError(
            f"ANS_AGENT_ANCHOR_TYPE={anchor_type!r} is not one of {sorted(valid_types)}"
        )
    if anchor_type == "fqdn":
        anchor_value = _optional("ANS_AGENT_ANCHOR_VALUE", agent_host)
    else:
        anchor_value = _required("ANS_AGENT_ANCHOR_VALUE")
    attestation_jwk = _optional("ANS_AGENT_ANCHOR_ATTESTATION_JWK") or None
    if anchor_type != "lei" and attestation_jwk is not None:
        # Silently ignored rather than raising: keeps a single .env file
        # workable when an operator switches between LEI and non-LEI
        # registrations on the same machine.
        attestation_jwk = None
    if attestation_jwk is not None:
        # Validate at load time so a malformed value fails before any
        # key material is generated (register.py writes EC keys to disk
        # before talking to the RA; an invalid JWK string discovered
        # mid-registration would leave key artifacts behind).
        import json as _json
        try:
            _json.loads(attestation_jwk)
        except _json.JSONDecodeError as exc:
            raise RuntimeError(
                f"ANS_AGENT_ANCHOR_ATTESTATION_JWK is not valid JSON: {exc}"
            ) from exc

    return AgentConfig(
        agent_host=agent_host,
        agent_url=agent_url,
        ans_name=f"ans://v{version}.{agent_host}",
        version=version,
        organization=_optional("ANS_AGENT_ORG", "Jeremy Ebbels"),
        organization_url=_optional("ANS_AGENT_ORG_URL", agent_url),
        documentation_url=_optional("ANS_AGENT_DOC_URL", agent_url),
        icon_url=_optional("ANS_AGENT_ICON_URL") or None,
        ra_base_url=_required("ANS_RA_BASE_URL"),
        tl_base_url=_required("ANS_TL_BASE_URL"),
        identity_cert_pem_path=Path(_required("ANS_IDENTITY_CERT_PEM")),
        ed25519_private_key_pem_path=Path(_required("ANS_ED25519_PRIVATE_KEY_PEM")),
        state_db_path=Path(_optional("ANS_STATE_DB", "./domainscope-agent.sqlite3")),
        a2a_listen=_optional("ANS_A2A_LISTEN", "0.0.0.0:8080"),
        mcp_listen=_optional("ANS_MCP_LISTEN", "0.0.0.0:8081"),
        receipt_refresh_seconds=int(_optional("ANS_RECEIPT_REFRESH_S", "300")),
        agent_anchor_type=anchor_type,
        agent_anchor_value=anchor_value,
        agent_anchor_attestation_jwk=attestation_jwk,
    )
