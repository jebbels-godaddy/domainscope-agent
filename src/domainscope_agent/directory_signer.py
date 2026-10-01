"""HTTP Message Signatures directory signer.

Produces Signature and Signature-Input headers per RFC 9421 for a
directory response, using the tag defined in
draft-meunier-http-message-signatures-directory-01 §5.2.

One signature per Ed25519 key. Covered component: "@authority" with
the ";req" component parameter (the request target authority from
which the directory was fetched).

keyid is the RFC 7638 JWK SHA-256 thumbprint of the corresponding
public key, matching the "kid" used in the published JWKS so that
verifiers can look up the key by id without a second round-trip.

Signature encoding: standard Base64 with padding per RFC 9421 §3
(byte-sequence values in structured headers use sf-binary = base64).
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# ---------------------------------------------------------------------------
# Base64 helpers
# ---------------------------------------------------------------------------

def _b64url_nopad(data: bytes) -> str:
    """Base64url encoding without padding (RFC 7515 Appendix C)."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64_pad(data: bytes) -> str:
    """Standard Base64 with padding (RFC 4648 §4, required by RFC 9421 §3 sf-binary)."""
    return base64.b64encode(data).decode("ascii")


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------

def _load_private_key(pem_path: Path) -> Ed25519PrivateKey:
    pem_data = pem_path.read_bytes()
    key = serialization.load_pem_private_key(pem_data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"expected Ed25519 private key, got {type(key).__name__}")
    return key


# ---------------------------------------------------------------------------
# JWK thumbprint (RFC 7638 §3.2 for OKP / Ed25519 per RFC 8037)
# ---------------------------------------------------------------------------

def _public_key_to_jwk_minimal(public_key: Ed25519PublicKey) -> dict[str, str]:
    """Return the minimal JWK fields required for thumbprint computation."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "crv": "Ed25519",
        "kty": "OKP",
        "x": _b64url_nopad(raw),
    }


def _thumbprint_from_jwk(jwk: dict[str, str]) -> str:
    """Compute RFC 7638 thumbprint: SHA-256 of the canonical JSON of required fields."""
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return _b64url_nopad(digest)


def jwk_thumbprint_from_pem(pem_path: Path) -> str:
    """Public API: return the RFC 7638 JWK thumbprint for the Ed25519 key in *pem_path*."""
    private_key = _load_private_key(pem_path)
    jwk = _public_key_to_jwk_minimal(private_key.public_key())
    return _thumbprint_from_jwk(jwk)


# ---------------------------------------------------------------------------
# Signature base construction (RFC 9421 §2.5)
# ---------------------------------------------------------------------------

def _build_signature_base(
    *,
    authority: str,
    params_line: str,
) -> bytes:
    """Build the signature base per RFC 9421 §2.5.

    The covered component is "@authority" with the ";req" parameter,
    meaning the authority component of the original request URL.

    Signature base format (each element terminated with \\n):
      "@authority";req: <authority value>
      "@signature-params": <params_line>

    The params_line is the verbatim content of the Signature-Input
    header value (everything after "sig1=").
    """
    lines = [
        f'"@authority";req: {authority}',
        f'"@signature-params": {params_line}',
    ]
    return "\n".join(lines).encode("utf-8")


# ---------------------------------------------------------------------------
# Public signer
# ---------------------------------------------------------------------------

def sign_directory_response(
    *,
    authority: str,
    ed25519_private_key_pem_path: Path,
    label: str = "sig1",
    ttl_seconds: int = 86400,
) -> dict[str, str]:
    """Sign a directory response and return Signature + Signature-Input headers.

    Args:
      authority: The authority (host[:port]) of the directory URL, e.g.
        "agent.webmesh.ai".
      ed25519_private_key_pem_path: Path to the Ed25519 private key (PKCS8 PEM).
      label: Structured-fields label for this signature (default "sig1").
      ttl_seconds: Validity window in seconds (default 86400 = 24 h).

    Returns:
      A dict with keys "Signature" and "Signature-Input".
    """
    private_key = _load_private_key(ed25519_private_key_pem_path)
    kid = jwk_thumbprint_from_pem(ed25519_private_key_pem_path)

    created = int(time.time())
    expires = created + ttl_seconds

    # Params list: covered components, then signature parameters.
    # RFC 9421 §2.3: "@authority" with the "req" flag means the authority
    # component from the request message that prompted this response.
    covered = '"@authority";req'
    params_line = (
        f'({covered});'
        f'created={created};'
        f'expires={expires};'
        f'keyid="{kid}";'
        f'alg="ed25519";'
        f'tag="http-message-signatures-directory"'
    )

    sig_base = _build_signature_base(authority=authority, params_line=params_line)

    raw_sig = private_key.sign(sig_base)
    # RFC 9421 §3: signature values are sf-binary (standard Base64 with padding),
    # wrapped in colons per the Structured Fields byte-sequence syntax.
    sig_b64 = _b64_pad(raw_sig)
    sig_sf = f":{sig_b64}:"  # Structured Fields byte-sequence

    return {
        "Signature-Input": f"{label}=({covered});created={created};expires={expires};keyid=\"{kid}\";alg=\"ed25519\";tag=\"http-message-signatures-directory\"",
        "Signature": f"{label}={sig_sf}",
    }


# ---------------------------------------------------------------------------
# Test-only verifier
# ---------------------------------------------------------------------------

def verify_directory_signature(
    *,
    authority: str,
    signature_header: str,
    signature_input_header: str,
    ed25519_private_key_pem_path: Path,
) -> bool:
    """Verify a directory signature produced by sign_directory_response.

    This is a test-only helper. It reconstructs the signature base from
    the headers and checks the signature against the public key derived
    from the same private key file.

    Returns True if the signature is valid, False otherwise.
    """
    private_key = _load_private_key(ed25519_private_key_pem_path)
    public_key: Ed25519PublicKey = private_key.public_key()

    # Parse: Signature-Input: sig1=(<covered>);<params>
    # We need the full value after "sig1=" as the params_line.
    sig_input_value = signature_input_header
    # Strip the label prefix "sig1=" (or whatever label was used)
    eq_pos = sig_input_value.index("=")
    params_line = sig_input_value[eq_pos + 1:]

    # Parse: Signature: sig1=:<base64>:
    sig_value = signature_header
    eq_pos2 = sig_value.index("=")
    sf_bytes = sig_value[eq_pos2 + 1:]  # e.g. ":base64bytes:"
    # Strip the surrounding colons from the Structured Fields byte-sequence.
    if sf_bytes.startswith(":") and sf_bytes.endswith(":"):
        sf_bytes = sf_bytes[1:-1]
    raw_sig = base64.b64decode(sf_bytes)

    sig_base = _build_signature_base(authority=authority, params_line=params_line)

    try:
        public_key.verify(raw_sig, sig_base)
        return True
    except Exception:
        return False
