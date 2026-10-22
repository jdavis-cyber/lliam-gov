"""``lliam-gov killswitch`` subcommand parser.

Handler injected to avoid importing ``main``.
"""

from __future__ import annotations

from typing import Callable


def build_killswitch_parser(subparsers, *, cmd_killswitch: Callable) -> None:
    """Attach the ``killswitch`` subcommand to ``subparsers``."""
    ks_parser = subparsers.add_parser(
        "killswitch",
        aliases=["kill-switch"],
        help="Engage, inspect or release the kill-switch (halts tools + inference)",
        description=(
            "Operator control for the durable kill-switch. 'engage' halts all "
            "tool execution and inference for every Lliam-GOV process on this "
            "host (local file write, no network). 'release' verifies the audit "
            "chain, restores the signed baseline from the local git checkout, "
            "re-verifies it, records who/when/why in the audit ledger, and only "
            "then re-enables autonomy."
        ),
    )
    ks_sub = ks_parser.add_subparsers(dest="killswitch_command", metavar="<subcommand>")

    status_p = ks_sub.add_parser("status", help="Show whether the kill-switch is engaged")
    status_p.add_argument("--json", action="store_true", help="Emit JSON")

    engage_p = ks_sub.add_parser("engage", help="Engage the kill-switch now")
    engage_p.add_argument("--reason", default="operator engaged from CLI",
                          help="Why the switch is being engaged (recorded)")
    engage_p.add_argument("--actor", default=None,
                          help="Who is engaging it (default: <user>@<host>)")
    engage_p.add_argument("--contain", action="append", default=[], metavar="CLASS",
                          help="Also contain this tool class (repeatable)")
    engage_p.add_argument("--no-forensics", action="store_true",
                          help="Skip the post-engage forensic snapshot")
    engage_p.add_argument("--json", action="store_true", help="Emit JSON")

    release_p = ks_sub.add_parser(
        "release",
        help="Verify, restore the signed baseline, and release the kill-switch",
    )
    release_p.add_argument("--reason", required=True,
                           help="Why autonomy may resume (recorded in the ledger)")
    release_p.add_argument("--actor", default=None,
                           help="Who is releasing it (default: <user>@<host>)")
    release_p.add_argument("--baseline", default=None, metavar="REF",
                           help="Baseline tag/commit to restore (default: the "
                                "authorization record's pinned baseline)")
    release_p.add_argument("--repo-root", default=None, metavar="PATH",
                           help="Deployment checkout holding the gov overlay "
                                "(default: the LLIAM_CONFIG overlay's directory)")
    release_p.add_argument("--dry-run", action="store_true",
                           help="Verify and show what would be restored; "
                                "write nothing and stay engaged")
    release_p.add_argument("--yes", action="store_true",
                           help="Confirm non-interactively (otherwise you must "
                                "type RELEASE at the prompt)")
    release_p.add_argument("--json", action="store_true", help="Emit JSON")

    ks_parser.set_defaults(func=cmd_killswitch)
