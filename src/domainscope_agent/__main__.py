"""Entry point: `python -m domainscope_agent`.

Reads configuration from the environment and starts the Starlette app under
uvicorn. Bind address comes from `ANS_A2A_LISTEN` (defaults to 0.0.0.0:8080).
"""
from __future__ import annotations

import sys

import uvicorn

from domainscope_agent import config
from domainscope_agent.server import build_app


def main() -> None:
    cfg = config.load()
    if not cfg.a2a_listen:
        print("ANS_A2A_LISTEN is empty; nothing to serve. Exiting.", file=sys.stderr)
        sys.exit(2)
    host, _, port = cfg.a2a_listen.rpartition(":")
    if not host:
        host = "0.0.0.0"
    app = build_app(cfg)
    uvicorn.run(app, host=host, port=int(port), log_level="info")


if __name__ == "__main__":
    main()
