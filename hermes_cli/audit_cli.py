"""Governance audit commands for Lliam-GOV evidence workflows."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from lliam_gov.security.aep_export import verify_aep_export, write_aep_export
from lliam_gov.security.audit_logger import AuditChainError, verify_audit_chain


def cmd_audit(args: argparse.Namespace) -> int:
    """Dispatch ``lliam-gov audit <subcommand>``."""

    command = getattr(args, "audit_command", None)

    # SP 800-171 3.3.9: audit management is limited to privileged users.
    # The gate runs before ANY subcommand, including unknown ones, so the
    # denial can never be bypassed via dispatch quirks.
    from lliam_gov.security.privileged_access import (
        PrivilegedAccessError,
        require_privileged_user,
    )

    try:
        require_privileged_user(f"audit {command}")
    except PrivilegedAccessError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if command == "export-aep":
        return _cmd_export_aep(args)
    if command == "verify-aep":
        return _cmd_verify_aep(args)
    if command == "verify-jsonl":
        return _cmd_verify_jsonl(args)
    print(f"unknown audit subcommand: {command}", file=sys.stderr)
    return 2


def register_audit_parser(subparsers) -> None:
    """Register the top-level governance audit parser."""

    audit_parser = subparsers.add_parser(
        "audit",
        help="Governance audit evidence export and verification",
        description=(
            "Export and verify Lliam-GOV audit evidence packages. This is "
            "separate from `security audit`, which scans supply-chain risk."
        ),
    )
    audit_subparsers = audit_parser.add_subparsers(
        dest="audit_command",
        metavar="<subcommand>",
    )

    export_parser = audit_subparsers.add_parser(
        "export-aep",
        help="Export verified audit JSONL records as an AEP JSON package",
    )
    export_parser.add_argument(
        "--input",
        action="append",
        required=True,
        help="Audit JSONL file to include; repeat for multiple files",
    )
    export_parser.add_argument(
        "--output",
        required=True,
        help="Output AEP JSON path",
    )

    verify_aep_parser = audit_subparsers.add_parser(
        "verify-aep",
        help="Re-import and verify an AEP JSON package",
    )
    verify_aep_parser.add_argument("--input", required=True, help="AEP JSON path")

    verify_jsonl_parser = audit_subparsers.add_parser(
        "verify-jsonl",
        help="Verify a hash-chained audit JSONL file",
    )
    verify_jsonl_parser.add_argument("--input", required=True, help="Audit JSONL path")
    verify_jsonl_parser.add_argument(
        "--expected-last-hash",
        default=None,
        help="Optional expected final chain hash",
    )

    audit_parser.set_defaults(func=cmd_audit)


def _cmd_export_aep(args: argparse.Namespace) -> int:
    try:
        package = write_aep_export(args.input, args.output)
    except AuditChainError as exc:
        print(f"AEP export failed: {exc}", file=sys.stderr)
        return 1
    count = package["record_count"]
    plural = "" if count == 1 else "s"
    print(f"Exported {count} audit record{plural} to {Path(args.output)}")
    return 0


def _cmd_verify_aep(args: argparse.Namespace) -> int:
    try:
        verification = verify_aep_export(args.input)
    except AuditChainError as exc:
        print(f"AEP verification failed: {exc}", file=sys.stderr)
        return 1
    count = verification.record_count
    plural = "" if count == 1 else "s"
    print(f"Verified {count} audit record{plural} from {Path(args.input)}")
    return 0


def _cmd_verify_jsonl(args: argparse.Namespace) -> int:
    try:
        verification = verify_audit_chain(
            args.input,
            expected_last_hash=getattr(args, "expected_last_hash", None),
        )
    except AuditChainError as exc:
        print(f"Audit JSONL verification failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"Verified {verification.record_count} audit records "
        f"from {Path(args.input)}; last_hash={verification.last_hash}"
    )
    return 0


__all__ = ["cmd_audit", "register_audit_parser"]
