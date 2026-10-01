"""ANS registration flow for the reference agent.

Same registration shape works against three deployments:

  - **local**: the godaddy/ans four-binary stack (ans-ra + ans-tl + ans-dns
    + ans-verify) running on a developer's laptop. The dev DNS server
    auto-resolves the ACME challenge so registration completes without a
    real domain.
  - **OTE**: GoDaddy OTE; requires real GoDaddy DNS for the ACME DNS-01
    challenge and an OTE API key from developer.godaddy.com/keys.
  - **prod**: same shape as OTE against api.godaddy.com.

Auth is selected by env var:
  ANS_API_KEY + ANS_API_SECRET   → "Authorization: sso-key K:S"
  ANS_OAUTH_TOKEN                → "Authorization: Bearer <token>"
  (neither)                      → no auth header (local dev RA only)

Run once per agent:
  python -m domainscope_agent.register
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    generate_private_key,
)
from cryptography.x509.oid import NameOID

from domainscope_agent import config
from domainscope_agent.state import Registration, State


def _generate_csr(
    common_name: str,
    san_dns: str,
    uri_san: str | None = None,
) -> tuple[str, str]:
    """Generate an EC P-256 key and CSR. Returns (private_key_pem, csr_pem)."""
    key = generate_private_key(SECP256R1())

    san_names: list[x509.GeneralName] = [x509.DNSName(san_dns)]
    if uri_san:
        san_names.append(x509.UniformResourceIdentifier(uri_san))

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .sign(key, hashes.SHA256())
    )

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, csr_pem


def _auth_header() -> dict[str, str]:
    """Return the authorization header for the configured auth mode."""
    api_key = os.environ.get("ANS_API_KEY", "").strip()
    api_secret = os.environ.get("ANS_API_SECRET", "").strip()
    if api_key and api_secret:
        return {"Authorization": f"sso-key {api_key}:{api_secret}"}
    oauth = os.environ.get("ANS_OAUTH_TOKEN", "").strip()
    if oauth:
        return {"Authorization": f"Bearer {oauth}"}
    return {}


def _extract_agent_id(registration_response: dict) -> str:
    """Extract agentId from the RegistrationPending links[rel=self]."""
    for link in registration_response.get("links", []):
        if link.get("rel") == "self":
            return link["href"].rstrip("/").split("/")[-1]
    raise RuntimeError("RegistrationPending response had no links[rel=self].href")


def _extract_identity_cert_pem(cert_response: list[dict[str, Any]]) -> str | None:
    """Build a PEM bundle from the RA's /certificates/identity JSON response.

    Versioned FQDN registrations get one or more entries (one on first
    activation, more after rotation). Base-only DID and LEI registrations
    get an empty array because the RA issues no Identity Certificate for
    non-FQDN anchors. Returns None when the array is empty so the caller
    can skip the PEM-write step.

    When entries are present, pick the one with the latest
    certificateValidFrom and concatenate its certificatePEM + chainPEM.
    The validFrom string is parsed as an RFC 3339 datetime, not compared
    lexically, so two timestamps with different UTC offsets sort by
    instant rather than by surface text.
    """
    if not cert_response:
        return None

    def _instant(entry: dict[str, Any]) -> datetime:
        raw = entry.get("certificateValidFrom") or ""
        if not raw:
            return datetime.min.replace(tzinfo=UTC)
        # fromisoformat in Python 3.10 rejects the "Z" suffix; normalize
        # it to "+00:00" for portability across the supported versions.
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return datetime.min.replace(tzinfo=UTC)

    latest = max(cert_response, key=_instant)
    leaf = latest.get("certificatePEM") or ""
    if not leaf:
        raise ValueError("identity-cert response missing certificatePEM")
    chain = latest.get("chainPEM") or ""
    if not leaf.endswith("\n"):
        leaf += "\n"
    return leaf + chain


def register(cfg: config.AgentConfig | None = None) -> Registration:
    """Register the agent with the configured RA and persist the result.

    The flow is the standard ANS-1 lifecycle:
      1. Generate server CSR + identity CSR locally (keys never leave the host).
      2. POST /v1/agents/register with both CSRs, FQDN as the anchor.
      3. Print the ACME DNS-01 challenge record (operator adds it; the local
         dev DNS server adds it automatically).
      4. Wait for DNS propagation, trigger verify-acme.
      5. Fetch DNS records to publish (the local dev DNS server publishes
         them automatically; OTE/prod operator publishes via their DNS API).
      6. Trigger verify-dns; status reaches ACTIVE.
      7. Persist (agentHost, agentId, version) to SQLite for use by the
         Trust Card serve path.

    Returns the persisted Registration. Idempotent across runs: if an active
    registration already exists for the configured agentHost, returns it
    without re-registering.
    """
    if cfg is None:
        cfg = config.load()
    state = State(cfg.state_db_path)

    # Idempotency key is (agent_host, anchor_type) so the same FQDN
    # carrying both an FQDN registration and an LEI registration does
    # not collide. Re-running register with a different anchor type
    # creates a new row instead of returning the existing one.
    existing = state.get_registration(cfg.agent_host, cfg.agent_anchor_type)
    if existing is not None:
        print(
            f"Registration already exists for ({cfg.agent_host}, {cfg.agent_anchor_type}): "
            f"{existing.agent_id}"
        )
        return existing

    print(f"Registering {cfg.agent_host} v{cfg.version} with RA {cfg.ra_base_url}")

    server_key_pem, server_csr_pem = _generate_csr(cfg.agent_host, cfg.agent_host)
    identity_key_pem, identity_csr_pem = _generate_csr(
        cfg.agent_host,
        cfg.agent_host,
        uri_san=cfg.ans_name,
    )

    # Persist the keys next to the state DB (developer-only convenience; in
    # production these would come from a KMS or a sealed secret store).
    # Refuse to overwrite existing keys: re-running register against an
    # already-registered agent would clobber the keys backing its current
    # ANS identity, breaking the agent silently. Set ANS_AGENT_FORCE_OVERWRITE_KEYS=1
    # to opt in (when intentionally rotating).
    keys_dir = cfg.state_db_path.parent
    server_key_path = keys_dir / "agent-server.key"
    identity_key_path = keys_dir / "agent-identity.key"
    force_overwrite = os.environ.get("ANS_AGENT_FORCE_OVERWRITE_KEYS") == "1"
    for path in (server_key_path, identity_key_path):
        if path.exists() and not force_overwrite:
            print(
                f"Refusing to overwrite existing key at {path}. "
                "Set ANS_AGENT_FORCE_OVERWRITE_KEYS=1 to rotate, or remove "
                "the file manually after backing it up.",
                file=sys.stderr,
            )
            sys.exit(2)
    server_key_path.write_text(server_key_pem)
    identity_key_path.write_text(identity_key_pem)
    server_key_path.chmod(0o600)
    identity_key_path.chmod(0o600)
    print(f"Private keys written to {keys_dir} (mode 0600)")

    payload: dict[str, Any] = {
        "agentHost": cfg.agent_host,
        "version": cfg.version,
        "agentDisplayName": cfg.organization,
        "agentDescription": (
            "ANS reference agent. Demonstrates registration, Trust Card "
            "hosting with stapled SCITT receipt, A2A and MCP serving."
        ),
        "serverCsrPEM": server_csr_pem,
        "identityCsrPEM": identity_csr_pem,
        "endpoints": [
            {
                "protocol": "A2A",
                "agentUrl": cfg.agent_url,
                "metaDataUrl": f"{cfg.agent_url}/.well-known/agent-card.json",
                "transports": ["STREAMABLE-HTTP"],
                "functions": [
                    {"id": "echo", "name": "Echo", "tags": ["reference", "echo", "demo"]},
                ],
            },
            {
                "protocol": "MCP",
                "agentUrl": f"{cfg.agent_url}/mcp",
                "metaDataUrl": f"{cfg.agent_url}/.well-known/mcp.json",
                "transports": ["STREAMABLE-HTTP"],
                "functions": [
                    {"id": "echo", "name": "Echo Tool", "tags": ["reference", "echo", "demo"]},
                ],
            },
        ],
    }

    # Non-FQDN anchors take the V2 register path that PR #15 added to the
    # RA: the request carries an explicit anchor block and the RA dispatches
    # through the AnchorResolver instead of inferring FQDN from agentHost.
    # PR #14 (Plan F) and PR #15 require base-only registration for did:*
    # and lei (no versioned ANSName, no identityCsrPEM, no Identity
    # Certificate; the URI SAN binding the versioned ANS-2 path uses is
    # FQDN-shaped only). Both fields drop from the request.
    register_endpoint = "/v1/agents/register"
    if cfg.agent_anchor_type != "fqdn":
        # Wire shape per the V2 register handler:
        #   POST /v2/ans/agents  body { agentHost, anchor: { anchorType, input }, ... }
        # Source of truth: internal/ra/handler/registration.go in godaddy/ans.
        payload["anchor"] = {
            "anchorType": cfg.agent_anchor_type,
            "input": cfg.agent_anchor_value,
        }
        payload.pop("version", None)
        payload.pop("identityCsrPEM", None)
        register_endpoint = "/v2/ans/agents"
        # The operator-staged attestation JWK (LEI Option B) is RA-side
        # configuration, not request-side: the RA's StaticAttestationSource
        # holds the LEI→JWK map and the LEI resolver consults it after the
        # GLEIF lookup. ANS_AGENT_ANCHOR_ATTESTATION_JWK is parsed at config
        # load (not here) so a malformed JWK fails before any key material
        # gets generated; today there's no V2 wire field to forward it on,
        # so the value is informational only until the RA exposes a JWK
        # staging endpoint.

    headers = {"Content-Type": "application/json", **_auth_header()}
    with httpx.Client(timeout=30.0) as client:
        response = client.post(
            f"{cfg.ra_base_url}{register_endpoint}",
            json=payload,
            headers=headers,
        )
    if not response.is_success:
        print(f"Registration failed: HTTP {response.status_code}")
        print(response.text[:500])
        sys.exit(1)

    pending = response.json()
    agent_id = _extract_agent_id(pending)
    print(f"Registration accepted. agentId: {agent_id}")

    for challenge in pending.get("challenges", []):
        if challenge.get("type") == "DNS_01":
            rec = challenge.get("dnsRecord", {})
            print(
                f"ACME DNS-01 challenge:\n"
                f"  name:  {rec.get('name')}\n"
                f"  type:  TXT\n"
                f"  value: {rec.get('value')}"
            )

    # Local dev RA + ans-dns auto-publishes; OTE/prod operator must add the
    # record now. The 60 s delay is conservative for OTE/prod and effectively
    # zero for local.
    propagation_seconds = int(os.environ.get("ANS_REGISTER_PROPAGATION_S", "60"))
    if propagation_seconds > 0:
        print(f"Waiting {propagation_seconds}s for DNS propagation...")
        time.sleep(propagation_seconds)

    print("Triggering verify-acme...")
    with httpx.Client(timeout=30.0) as client:
        response = client.post(
            f"{cfg.ra_base_url}/v1/agents/{agent_id}/verify-acme",
            headers=headers,
            json={},
        )
    if not response.is_success:
        print(f"verify-acme: HTTP {response.status_code}")
        print(response.text[:300])

    print("Triggering verify-dns...")
    with httpx.Client(timeout=30.0) as client:
        response = client.post(
            f"{cfg.ra_base_url}/v1/agents/{agent_id}/verify-dns",
            headers=headers,
            json={},
        )
    if not response.is_success:
        print(f"verify-dns: HTTP {response.status_code}")
        print(response.text[:300])

    # Pull the activated registration record so we can persist
    # capabilitiesHash if the RA sealed one (Plan A/C).
    with httpx.Client(timeout=30.0) as client:
        response = client.get(
            f"{cfg.ra_base_url}/v1/agents/{agent_id}",
            headers=headers,
        )
    capabilities_hash: str | None = None
    if response.is_success:
        details = response.json()
        capabilities_hash = details.get("capabilitiesHash")

    # Fetch the Identity Certificate chain that the RA issued from the
    # identityCsrPEM submitted above. The RA returns a JSON array of cert
    # metadata objects, each carrying certificatePEM (leaf) and chainPEM
    # (issuer chain). Concatenate the most recent leaf + chain into the
    # PEM bundle the serve flow expects via ANS_IDENTITY_CERT_PEM. Base-
    # only DID and LEI registrations get an empty array; the helper
    # returns None and the agent persists state without writing a cert.
    with httpx.Client(timeout=30.0) as client:
        cert_resp = client.get(
            f"{cfg.ra_base_url}/v1/agents/{agent_id}/certificates/identity",
            headers=headers,
        )
    if cert_resp.is_success:
        pem_bundle = _extract_identity_cert_pem(cert_resp.json())
        if pem_bundle is None:
            print("Identity Certificate not issued (base-only registration)")
        else:
            identity_cert_path = cfg.identity_cert_pem_path
            identity_cert_path.parent.mkdir(parents=True, exist_ok=True)
            identity_cert_path.write_text(pem_bundle)
            identity_cert_path.chmod(0o644)
            print(f"Identity Certificate written to {identity_cert_path}")
    else:
        print(
            f"warning: identity-cert fetch returned HTTP {cert_resp.status_code}; "
            f"set ANS_IDENTITY_CERT_PEM manually before serving "
            f"(see RA endpoint /v1/agents/{agent_id}/certificates/identity).",
            file=sys.stderr,
        )

    reg = Registration(
        agent_host=cfg.agent_host,
        agent_id=agent_id,
        version=cfg.version,
        capabilities_hash=capabilities_hash,
        registered_at=datetime.now(UTC).isoformat(),
        anchor_type=cfg.agent_anchor_type,
    )
    state.upsert_registration(reg)
    print(f"Persisted registration to {cfg.state_db_path}")
    return reg


def main() -> None:
    cfg = config.load()
    register(cfg)


if __name__ == "__main__":
    main()
