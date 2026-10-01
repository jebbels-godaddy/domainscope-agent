"""MCP server for domainscope-agent.

Exposes one tool, `lookup_domain`, mirroring the A2A domain-lookup skill.

Run modes:
  stdio (default, for direct MCP-client testing):
    python -m domainscope_agent.mcp_server

  streamable-http (for use as the A2A back-door MCP endpoint):
    python -m domainscope_agent.mcp_server --transport streamable-http --port 8081
"""
from __future__ import annotations

import argparse

from mcp.server.fastmcp import FastMCP

from domainscope_agent.domain_lookup_executor import run_domain_lookup


mcp = FastMCP("DomainScope Agent")


@mcp.tool()
def lookup_domain(domain: str) -> str:
    """Look up a domain's registration status over public RDAP.

    Args:
        domain: A fully-qualified domain name, e.g. "example.com".
    """
    return run_domain_lookup(domain)


def main() -> None:
    """Entry point for `python -m domainscope_agent.mcp_server`."""
    parser = argparse.ArgumentParser(description="ANS reference agent MCP server")
    parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio", "streamable-http"],
        help="Transport protocol (default: stdio).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8081,
        help="Port for streamable-http transport (default: 8081).",
    )
    args = parser.parse_args()
    if args.transport == "streamable-http":
        mcp.settings.port = args.port
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
