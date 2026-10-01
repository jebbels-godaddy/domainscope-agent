"""MCP server for the ANS reference agent.

Exposes one tool, `echo`, mirroring the A2A skill of the same name. Production
agents replace this tool surface with their own; the rest of the agent
(registration, Trust Card hosting, A2A surface) is unchanged.

Run modes:
  stdio (default, for direct MCP-client testing):
    python -m domainscope_agent.mcp_server

  streamable-http (for use as the A2A back-door MCP endpoint):
    python -m domainscope_agent.mcp_server --transport streamable-http --port 8081
"""
from __future__ import annotations

import argparse

from mcp.server.fastmcp import FastMCP


mcp = FastMCP("ANS Reference Agent")


@mcp.tool()
def echo(message: str) -> str:
    """Return the input string unchanged with a small prefix.

    The reference tool exists to demonstrate end-to-end ANS registration,
    A2A request handling, and MCP tool invocation against a registered
    agent. Production agents replace this with their actual tool set.

    Args:
        message: Any text. Returned with a `echo: ` prefix.
    """
    if not message:
        return "echo: (empty input)"
    return f"echo: {message}"


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
