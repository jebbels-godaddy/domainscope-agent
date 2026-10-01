"""Tests for runtime configuration loading.

Focused on the anchor-selection paths the agent gained for Plan G.
The existing required-vars and defaults logic was unchanged by this
work; the new tests below pin the anchor branch behavior so a
future edit cannot regress the LEI / DID test surface.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from domainscope_agent import config


def _set_required(monkeypatch, **overrides) -> None:
    """Populate the env vars the loader requires, plus any caller overrides."""
    base = {
        "ANS_AGENT_HOST": "agent.test",
        "ANS_AGENT_VERSION": "1.0.0",
        "ANS_RA_BASE_URL": "http://localhost:18080",
        "ANS_TL_BASE_URL": "http://localhost:18081",
        "ANS_IDENTITY_CERT_PEM": "/tmp/identity.pem",
        "ANS_ED25519_PRIVATE_KEY_PEM": "/tmp/ed25519.key",
    }
    base.update(overrides)
    for k, v in base.items():
        monkeypatch.setenv(k, v)
    # The loader also reads optional anchor vars; make sure no stale value
    # from another test is sitting in the parent process env.
    for opt in (
        "ANS_AGENT_ANCHOR_TYPE",
        "ANS_AGENT_ANCHOR_VALUE",
        "ANS_AGENT_ANCHOR_ATTESTATION_JWK",
    ):
        if opt not in overrides:
            monkeypatch.delenv(opt, raising=False)


# ---------------------------------------------------------------------
# Anchor type defaults to FQDN; value defaults to the agent host.
# ---------------------------------------------------------------------

def test_anchor_defaults_to_fqdn(monkeypatch):
    _set_required(monkeypatch)
    cfg = config.load()
    assert cfg.agent_anchor_type == "fqdn"
    assert cfg.agent_anchor_value == "agent.test"
    assert cfg.agent_anchor_attestation_jwk is None


# ---------------------------------------------------------------------
# Explicit anchor types.
# ---------------------------------------------------------------------

@pytest.mark.parametrize(
    "anchor_type,anchor_value",
    [
        ("did:web", "did:web:agent.test"),
        ("did:key", "did:key:z6Mk..."),
        ("did:pkh", "did:pkh:eip155:1:0xabc..."),
        ("lei", "529900T8BM49AURSDO55"),
    ],
)
def test_non_fqdn_anchor_requires_value(monkeypatch, anchor_type, anchor_value):
    _set_required(
        monkeypatch,
        ANS_AGENT_ANCHOR_TYPE=anchor_type,
        ANS_AGENT_ANCHOR_VALUE=anchor_value,
    )
    cfg = config.load()
    assert cfg.agent_anchor_type == anchor_type
    assert cfg.agent_anchor_value == anchor_value


def test_non_fqdn_anchor_without_value_raises(monkeypatch):
    _set_required(monkeypatch, ANS_AGENT_ANCHOR_TYPE="lei")
    with pytest.raises(RuntimeError, match="ANS_AGENT_ANCHOR_VALUE"):
        config.load()


def test_unknown_anchor_type_raises(monkeypatch):
    _set_required(monkeypatch, ANS_AGENT_ANCHOR_TYPE="x509")
    with pytest.raises(RuntimeError, match="ANS_AGENT_ANCHOR_TYPE"):
        config.load()


# ---------------------------------------------------------------------
# LEI Option B: operator supplies the attestation JWK directly.
# ---------------------------------------------------------------------

def test_lei_attestation_jwk_passes_through(monkeypatch):
    jwk_str = '{"kty":"OKP","crv":"Ed25519","x":"abc"}'
    _set_required(
        monkeypatch,
        ANS_AGENT_ANCHOR_TYPE="lei",
        ANS_AGENT_ANCHOR_VALUE="529900T8BM49AURSDO55",
        ANS_AGENT_ANCHOR_ATTESTATION_JWK=jwk_str,
    )
    cfg = config.load()
    assert cfg.agent_anchor_attestation_jwk == jwk_str


def test_attestation_jwk_silently_dropped_for_non_lei(monkeypatch):
    """Carrying ANS_AGENT_ANCHOR_ATTESTATION_JWK across an FQDN run is
    harmless; the loader drops it so a single .env file works for both
    LEI and non-LEI registrations on the same machine."""
    _set_required(
        monkeypatch,
        ANS_AGENT_ANCHOR_TYPE="did:web",
        ANS_AGENT_ANCHOR_VALUE="did:web:agent.test",
        ANS_AGENT_ANCHOR_ATTESTATION_JWK='{"kty":"OKP","crv":"Ed25519","x":"abc"}',
    )
    cfg = config.load()
    assert cfg.agent_anchor_attestation_jwk is None


def test_anchor_type_lowercased(monkeypatch):
    _set_required(
        monkeypatch,
        ANS_AGENT_ANCHOR_TYPE="LEI",
        ANS_AGENT_ANCHOR_VALUE="529900T8BM49AURSDO55",
    )
    cfg = config.load()
    assert cfg.agent_anchor_type == "lei"


# ---------------------------------------------------------------------
# Sanity: pre-existing required-var loading still works.
# ---------------------------------------------------------------------

def test_required_var_missing_raises(monkeypatch):
    monkeypatch.delenv("ANS_AGENT_HOST", raising=False)
    with pytest.raises(RuntimeError, match="ANS_AGENT_HOST"):
        config.load()


def test_paths_become_path_objects(monkeypatch):
    _set_required(monkeypatch)
    cfg = config.load()
    assert isinstance(cfg.identity_cert_pem_path, Path)
    assert isinstance(cfg.ed25519_private_key_pem_path, Path)
