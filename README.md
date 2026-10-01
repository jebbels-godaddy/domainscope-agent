# ANS Reference Agent

Reference implementation of an ANS-registered agent. Pairs with the
reference Registration Authority and Transparency Log at
[`godaddy/ans`](https://github.com/godaddy/ans).

This agent demonstrates:

- **Registration** against an ANS RA (FQDN anchor by default; the
  `godaddy/ans-sdk-go` library handles `did:web` / `did:key` /
  `did:pkh` / LEI anchors when needed).
- **Hosted Trust Card with stapled SCITT receipt.** The agent fetches its
  SCITT COSE_Sign1 receipt from the TL after registration and embeds it
  in the served Trust Card under `transparencyReceipt`. A verifier can
  validate the registration offline without contacting the live TL.
- **Dual-protocol serving.** One Starlette app exposes A2A v0.3 JSON-RPC
  at `POST /` and a streamable-HTTP MCP server at `POST /mcp/`. Both
  surfaces invoke the same domain-lookup skill/tool.
- **Discovery surfaces.** `.well-known` paths for A2A AgentCard, ANS
  Trust Card, RFC 9421 HTTP Message Signatures directory, Web Bot Auth
  Signature Agent Card, MCP discovery document, and AI Catalog Level-3
  manifest with signed Trust Manifests.

The agent is intentionally minimal: one domain-lookup skill, no LLM
dependency, no Postgres, no encounter store.

## Quick start: run locally against the reference RA

```bash
# 1. Start the reference RA + TL + dev DNS server (in godaddy/ans repo).
make demo  # brings up ans-ra, ans-tl, ans-dns

# 2. Install this agent.
pip install -e .

# 3. Configure for local mode (see env vars below).
export ANS_AGENT_HOST=agent.localdev.test
export ANS_AGENT_VERSION=1.0.0
export ANS_AGENT_URL=http://localhost:8080
export ANS_RA_BASE_URL=http://localhost:9000
export ANS_TL_BASE_URL=http://localhost:9090
export ANS_IDENTITY_CERT_PEM=./identity.pem
export ANS_ED25519_PRIVATE_KEY_PEM=./ed25519.key
export ANS_REGISTER_PROPAGATION_S=0  # local DNS auto-resolves

# 4. Generate the Ed25519 key the agent uses to sign the Trust Card.
#    The Identity Certificate is NOT generated here; the RA issues it
#    from the identityCsrPEM that register.py submits in step 5, and
#    register.py writes it to $ANS_IDENTITY_CERT_PEM after activation.
openssl genpkey -algorithm Ed25519 -out "$ANS_ED25519_PRIVATE_KEY_PEM"

# 5. Register against the local RA. This generates an EC P-256 key + CSR,
#    submits register, walks ACME DNS-01, polls verify-acme, and on
#    activation fetches the Identity Certificate chain from the RA at
#    /v1/agents/{agentId}/certificates/identity, writing it to
#    $ANS_IDENTITY_CERT_PEM. Re-running against an already-registered
#    agent refuses by default; set ANS_AGENT_FORCE_OVERWRITE_KEYS=1 to rotate.
domainscope-agent-register

# 6. Serve.
domainscope-agent
```

After step 6 the agent is reachable at `http://localhost:8080`. The
served Trust Card at `/.well-known/ans/trust-card.json` carries the
SCITT receipt fetched from the local TL. A verifier reading that
endpoint can validate the registration offline.

## Configuration

All configuration is environment-driven. The agent reads `os.environ`
once at startup.

### Required

| Variable | Purpose |
|---|---|
| `ANS_AGENT_HOST` | The agent's FQDN (or local hostname for dev). |
| `ANS_AGENT_VERSION` | SemVer string without `v` prefix (e.g. `1.0.0`). |
| `ANS_RA_BASE_URL` | RA base URL (e.g. `http://localhost:9000` or `https://api.ote-godaddy.com`). |
| `ANS_TL_BASE_URL` | TL base URL for receipt fetch. |
| `ANS_IDENTITY_CERT_PEM` | Path to the Identity Certificate (PEM, may include chain). |
| `ANS_ED25519_PRIVATE_KEY_PEM` | Path to the Ed25519 private key signing the Trust Card. |

### Optional

| Variable | Default | Purpose |
|---|---|---|
| `ANS_AGENT_URL` | `https://$ANS_AGENT_HOST` | Public URL the agent advertises in cards. |
| `ANS_AGENT_ORG` | `ANS Reference` | Organization name in cards and AI Catalog. |
| `ANS_AGENT_ORG_URL` | = `ANS_AGENT_URL` | Organization URL. |
| `ANS_AGENT_DOC_URL` | = `ANS_AGENT_URL` | Documentation URL. |
| `ANS_AGENT_ICON_URL` | unset | Icon URL for the agent card. |
| `ANS_STATE_DB` | `./domainscope-agent.sqlite3` | SQLite path for registration + receipt state. |
| `ANS_A2A_LISTEN` | `0.0.0.0:8080` | A2A server bind address. |
| `ANS_MCP_LISTEN` | `0.0.0.0:8081` | MCP stdio-bridge bind (currently mounted under `/mcp` of the A2A server; this var is reserved for future split-deploy). |
| `ANS_RECEIPT_REFRESH_S` | `300` | Receipt refresh interval in seconds. Set to `0` to fetch once at startup and never refresh. |
| `ANS_API_KEY`, `ANS_API_SECRET` | unset | OTE/prod sso-key auth header. |
| `ANS_OAUTH_TOKEN` | unset | Bearer token auth header (alternative to sso-key). |
| `ANS_REGISTER_PROPAGATION_S` | `60` | Sleep before triggering verify-acme. Set to `0` for local mode. |

### Anchor selection (Plan G)

| Variable | Default | Purpose |
|---|---|---|
| `ANS_AGENT_ANCHOR_TYPE` | `fqdn` | Anchor profile. One of `fqdn`, `did:web`, `did:key`, `did:pkh`, `lei`. Switching to a non-FQDN type takes the V2 register path the RA gained in `godaddy/ans` PR #15. |
| `ANS_AGENT_ANCHOR_VALUE` | `$ANS_AGENT_HOST` for `fqdn`; required otherwise | The canonical anchor input. The DID URI for `did:*`, the 20-character LEI string for `lei`, the FQDN for `fqdn`. |
| `ANS_AGENT_ANCHOR_ATTESTATION_JWK` | unset | LEI Option B value, validated as JSON at config load so a malformed value fails before any key material is generated. The RA's `AttestationJWKSource` is configured server-side; today there is no V2 wire field that forwards this value through register, so the env var is informational until the RA exposes a JWK staging endpoint. Silently ignored for non-LEI anchors. |

A non-FQDN registration is **base-only**: the RA's `NON_FQDN_REQUIRES_BASE_ONLY` rule rejects a versioned ANSName for `did:*` and `lei`. The request drops both `version` and `identityCsrPEM`, the RA does not issue an Identity Certificate for the registration (the X.509 URI SAN binding the versioned ANS-2 path uses is FQDN-shaped only), and the registration carries no `ansName`. The agent's local `cfg.version` continues to populate the served Trust Card body so a verifier reading the hosted card sees a coherent v-prefix string; the RA-side identity is the anchor itself.

The non-FQDN register POST goes to `/v2/ans/agents` with body `{ ..., anchor: { anchorType, input } }`. The FQDN register POST stays on `/v1/agents/register` for compatibility with the existing reference flow.

Example LEI Option B run against a local OSS demo stack:

```bash
export ANS_AGENT_ANCHOR_TYPE=lei
export ANS_AGENT_ANCHOR_VALUE=529900T8BM49AURSDO55
export ANS_AGENT_ANCHOR_ATTESTATION_JWK='{"kty":"OKP","crv":"Ed25519","x":"<base64url-pubkey>"}'
domainscope-agent-register
```

## Endpoints served

| Path | Purpose |
|---|---|
| `POST /` | A2A JSON-RPC endpoint. Invokes the domain-lookup skill. |
| `POST /mcp/` | Streamable-HTTP MCP endpoint. Invokes the lookup_domain tool. |
| `GET /.well-known/agent-card.json` | A2A v0.3 AgentCard with detached-JWS signature. |
| `GET /.well-known/agent.json` | A2A SDK alias for the same card. |
| `GET /.well-known/ans/trust-card.json` | ANS Trust Card with stapled SCITT receipt. |
| `GET /.well-known/http-message-signatures-directory` | RFC 9421 directory; response carries Signature + Signature-Input headers. |
| `GET /.well-known/signature-agent-card` | Web Bot Auth registry path; same body as the Trust Card. |
| `GET /.well-known/mcp.json` | MCP server discovery document. |
| `GET /.well-known/ai-catalog.json` | AI Catalog Level-3 manifest with signed Trust Manifests on each entry. |
| `GET /health` | Liveness probe. |

## Single-protocol starting templates

Developers who only want one of the two protocols can start from the
example subdirectories:

- `examples/a2a-only/`: strips the MCP mount and discovery document.
- `examples/mcp-only/`: strips the A2A surface; agent serves only MCP
  and the discovery paths.

## License

Apache 2.0. See `LICENSE`.
