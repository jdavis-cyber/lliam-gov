"""``lliam-gov proxy`` subcommand parser.

Moved out of the removed ``lliam-gov gateway`` parser module (JER-198), which
used to define both commands in one block. Handler injected to avoid importing
``main``.
"""

from __future__ import annotations

from typing import Callable


def build_proxy_parser(subparsers, *, cmd_proxy: Callable) -> None:
    """Attach the ``proxy`` subcommand to ``subparsers``."""
    # =========================================================================
    # proxy command — local OpenAI-compatible proxy that attaches the user's
    # OAuth-authenticated provider credentials to outbound requests. Lets
    # external apps (OpenViking, Karakeep, Open WebUI, ...) ride a logged-in
    # subscription without copy-pasting static API keys.
    # =========================================================================
    proxy_parser = subparsers.add_parser(
        "proxy",
        help="Local OpenAI-compatible proxy to OAuth providers",
        description=(
            "Run a local HTTP server that forwards OpenAI-compatible requests "
            "to an OAuth-authenticated provider (e.g. Nous Portal). External "
            "apps can point at the proxy with any bearer token; the proxy "
            "attaches your real credentials."
        ),
    )
    proxy_subparsers = proxy_parser.add_subparsers(dest="proxy_command")

    proxy_start = proxy_subparsers.add_parser(
        "start", help="Run the proxy in the foreground"
    )
    proxy_start.add_argument(
        "--provider",
        default="nous",
        help="Upstream provider: nous or xai (default: nous). See `lliam-gov proxy providers`.",
    )
    proxy_start.add_argument(
        "--host",
        default=None,
        help="Bind address (default: 127.0.0.1). Use 0.0.0.0 to expose on LAN.",
    )
    proxy_start.add_argument(
        "--port",
        type=int,
        default=None,
        help="Bind port (default: 8645)",
    )

    proxy_subparsers.add_parser(
        "status", help="Show which proxy upstreams are ready"
    )
    proxy_subparsers.add_parser(
        "providers", help="List available proxy upstream providers"
    )
    proxy_parser.set_defaults(func=cmd_proxy)
