"""Public MCP server for domainscope-agent.

Exposes the same `lookup_domain` tool as `domainscope_agent.mcp_server` but
over streamable-HTTP so it can mount under `/mcp` inside the main Starlette
app. The stdio server in `mcp_server.py` is for direct command-line testing;
this module is the surface that remote MCP clients reach over the agent's
public HTTPS endpoint.
"""
from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from domainscope_agent.domain_lookup_executor import run_domain_lookup


_PUBLIC_HOST = os.environ.get("ANS_AGENT_HOST", "localhost")


mcp = FastMCP(
    "DomainScope Agent",
    streamable_http_path="/",
    stateless_http=True,
    json_response=True,
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[
            _PUBLIC_HOST,
            f"{_PUBLIC_HOST}:*",
            "127.0.0.1:*",
            "localhost:*",
            "[::1]:*",
        ],
        allowed_origins=[
            f"https://{_PUBLIC_HOST}",
            f"https://{_PUBLIC_HOST}:*",
            "http://127.0.0.1:*",
            "http://localhost:*",
            "http://[::1]:*",
        ],
    ),
)


@mcp.tool()
def lookup_domain(domain: str) -> str:
    """Look up a domain's registration status over public RDAP.

    Args:
        domain: A fully-qualified domain name, e.g. "example.com".
    """
    return run_domain_lookup(domain)


def streamable_http_app():
    """Return the FastMCP Starlette app for mounting under /mcp."""
    return mcp.streamable_http_app()


def session_manager_lifespan():
    """Lifespan context that starts FastMCP's session manager.

    Mount FastMCP as a sub-app and Starlette will not run its lifespan, so
    the session manager's task group never starts and POST /mcp/ returns 500.
    The parent app must pass this context manager into Starlette(lifespan=...)
    to start the manager once at boot.
    """
    return mcp.session_manager.run
