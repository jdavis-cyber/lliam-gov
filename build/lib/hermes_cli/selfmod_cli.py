"""Self-modification approval CLI (``lliam-gov proposals|approve|reject``).

LG-4.5 / AI-222. The human-oversight surface for staged self-modification
proposals: list pending, approve with a note, reject with a note. All three
run behind the 3.3.9 privileged-user ACL; decisions are principal-attributed
and audited into the hash chain by the gate module.
"""

from __future__ import annotations

import argparse
import sys


def _require_privileged(operation: str) -> bool:
    from lliam_gov.security.privileged_access import (
        PrivilegedAccessError,
        require_privileged_user,
    )

    try:
        require_privileged_user(operation)
    except PrivilegedAccessError as exc:
        print(str(exc), file=sys.stderr)
        return False
    return True


def cmd_proposals(args: argparse.Namespace) -> int:
    """List self-modification proposals (default: pending)."""
    if not _require_privileged("proposals"):
        return 1
    from lliam_gov.security.selfmod_gate import list_proposals

    status = None if args.all else "pending"
    proposals = list_proposals(status)
    if not proposals:
        print("no pending proposals" if not args.all else "no proposals")
        return 0
    for p in proposals:
        decided = f" by {p.decided_by}" if p.decided_by else ""
        print(
            f"{p.proposal_id}  [{p.status}{decided}]  {p.kind}  "
            f"{p.created_at}  {p.summary}"
        )
    return 0


def _decide(args: argparse.Namespace, *, approve: bool) -> int:
    op = "approve" if approve else "reject"
    if not _require_privileged(op):
        return 1
    from lliam_gov.security.selfmod_gate import (
        SelfModError,
        approve_proposal,
        reject_proposal,
    )

    try:
        fn = approve_proposal if approve else reject_proposal
        p = fn(args.proposal_id, args.note)
    except SelfModError as exc:
        print(f"{op} refused: {exc}", file=sys.stderr)
        return 1
    print(f"proposal {p.proposal_id} {p.status} by {p.decided_by}: {p.note}")
    if approve:
        import json

        print("payload (apply consciously — the gate never self-applies):")
        print(json.dumps(p.payload, indent=2))
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    return _decide(args, approve=True)


def cmd_reject(args: argparse.Namespace) -> int:
    return _decide(args, approve=False)


def register_selfmod_parsers(subparsers) -> None:
    """Register proposals/approve/reject on the top-level subparsers."""
    p_list = subparsers.add_parser(
        "proposals",
        help="List staged self-modification proposals (LG-4.5 review path)",
    )
    p_list.add_argument(
        "--all", action="store_true", help="Include decided proposals"
    )
    p_list.set_defaults(func=cmd_proposals)

    p_approve = subparsers.add_parser(
        "approve", help="Approve a staged self-modification proposal"
    )
    p_approve.add_argument("proposal_id")
    p_approve.add_argument(
        "--note", required=True, help="Reviewer reasoning (required evidence)"
    )
    p_approve.set_defaults(func=cmd_approve)

    p_reject = subparsers.add_parser(
        "reject", help="Reject a staged self-modification proposal"
    )
    p_reject.add_argument("proposal_id")
    p_reject.add_argument(
        "--note", required=True, help="Reviewer reasoning (required evidence)"
    )
    p_reject.set_defaults(func=cmd_reject)


__all__ = [
    "cmd_approve",
    "cmd_proposals",
    "cmd_reject",
    "register_selfmod_parsers",
]
