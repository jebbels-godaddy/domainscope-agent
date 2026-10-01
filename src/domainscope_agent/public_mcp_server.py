"""Public MCP server for the ANS reference agent.

Exposes the same `echo` tool as `domainscope_agent.mcp_server` but over
streamable-HTTP so it can mount under `/mcp` inside the main Starlette app.
The stdio server in `mcp_server.py` is for direct command-line testing; this
module is the surface that remote MCP clients reach over the agent's
public HTTPS endpoint.

Production agents replace the echo tool with their actual tool set, audit
each tool's outbound surface for SSRF, and decide whether to keep the
endpoint public-read or require authentication.
"""
from __future__ import annotations

import os

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings


_PUBLIC_HOST = os.environ.get("ANS_AGENT_HOST", "localhost")


mcp = FastMCP(
    "ANS Reference Agent",
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
def echo(message: str) -> str:
    """Return the input string unchanged with a small prefix.

    Demonstrates MCP tool invocation against an ANS-registered agent over
    streamable-HTTP. Production agents replace this with their actual
    tool set.

    Args:
        message: Any text. Returned with a `echo: ` prefix.
    """
    if not message:
        return "echo: (empty input)"
    return f"echo: {message}"


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
