"""Self-modification gate — staged proposals + human approval (LG-4.5, AI-222).

Plan §5.5.bis / ISO 42001 human-oversight expectations. When the gate is on
(``LLIAM_GOV_SELFMOD_GATE=1``), self-modifying behavior — skill creation,
curated memory persistence, runtime tool registration — does NOT execute.
It is staged as a PROPOSAL under ``<lliam home>/selfmod/proposals/`` and
becomes live only after an explicit, principal-attributed, note-carrying
``lliam-gov approve <id>``.

Semantics:

* **Stage, never apply.** A gated dispatch returns a "staged" message to
  the model; the underlying tool handler is never invoked. Rejected
  proposals can therefore never leak into live state — there is nothing
  to roll back.
* **Approval is privileged.** approve/reject run behind the 3.3.9
  privileged-user ACL, capture the OS-authenticated principal (LG-4.1),
  and REQUIRE a free-text note (the reviewer's reasoning is part of the
  evidence, not optional).
* **Audited end to end.** ``selfmod_proposed`` / ``selfmod_approved`` /
  ``selfmod_rejected`` events land in the hash chain with the proposal id;
  payloads stay in the proposal file, params_hash in the chain (A.8.11).
* **Application is operator-driven.** Approval marks the proposal
  approved and surfaces the payload; the operator applies it consciously.
  The gate's job is to guarantee nothing self-applies.

Gated capabilities: ``selfmod`` (skills, runtime tool registration) and
``memory_write`` (curated memory persistence) per the AI-222 scope.

Maps to: ISO/IEC 42001 A.6.2.4 (human oversight of changes); SP 800-171
3.4.5 context.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

SELFMOD_GATE_ENV = "LLIAM_GOV_SELFMOD_GATE"
PROPOSALS_DIRNAME = "selfmod/proposals"

#: Capability tags whose dispatch is staged when the gate is on.
GATED_CAPABILITIES: frozenset[str] = frozenset({"selfmod", "memory_write"})

_VALID_STATUSES = {"pending", "approved", "rejected"}


class SelfModError(Exception):
    """Base class for self-modification gate failures."""


class ProposalNotFound(SelfModError):
    """No proposal with the given id exists."""


class ProposalAlreadyDecided(SelfModError):
    """The proposal was already approved or rejected."""


class NoteRequired(SelfModError):
    """Approval/rejection requires a non-empty free-text note."""


@dataclass
class Proposal:
    proposal_id: str
    kind: str
    summary: str
    payload: dict
    proposed_by: str
    created_at: str
    status: str = "pending"
    decided_by: str | None = None
    decided_at: str | None = None
    note: str | None = None


def selfmod_gate_enabled() -> bool:
    """True when self-modifying behavior must be staged for approval."""
    return os.environ.get(SELFMOD_GATE_ENV) == "1"


def _proposals_dir() -> Path:
    from hermes_constants import get_hermes_home

    d = get_hermes_home() / PROPOSALS_DIRNAME
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d


def _proposal_path(proposal_id: str) -> Path:
    # ids are generated server-side from token_hex, but never trust a
    # caller-supplied id to escape the proposals dir.
    if "/" in proposal_id or "\\" in proposal_id or ".." in proposal_id:
        raise ProposalNotFound(f"invalid proposal id {proposal_id!r}")
    return _proposals_dir() / f"{proposal_id}.json"


def _write_proposal(p: Proposal) -> None:
    path = _proposal_path(p.proposal_id)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps(asdict(p), indent=2).encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_proposal(proposal_id: str) -> Proposal:
    path = _proposal_path(proposal_id)
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        raise ProposalNotFound(f"no proposal {proposal_id!r}") from None
    return Proposal(**data)


def _audit(event_type: str, proposal: Proposal, *, error_fatal: bool) -> None:
    """Audit a gate event. Staging fails closed if the chain can't record it."""
    from lliam_gov.security.audit_logger import get_shared_audit_logger

    try:
        get_shared_audit_logger().log_event(
            event_type=event_type,
            params={
                "proposal_id": proposal.proposal_id,
                "kind": proposal.kind,
                "summary": proposal.summary,
                "status": proposal.status,
                "decided_by": proposal.decided_by,
            },
            block_reason=f"{proposal.kind}:{proposal.proposal_id}",
        )
    except Exception:
        if error_fatal:
            # Remove the staged file: an unevidenced proposal must not sit
            # in the queue looking legitimate.
            _proposal_path(proposal.proposal_id).unlink(missing_ok=True)
            raise


def propose(kind: str, summary: str, payload: dict) -> str:
    """Stage a self-modification proposal; returns the proposal id.

    Fail-closed: if the ``selfmod_proposed`` audit event cannot be written,
    the staged file is removed and the error propagates.
    """
    from lliam_gov.security.principal import get_principal

    proposal = Proposal(
        proposal_id=secrets.token_hex(6),
        kind=kind,
        summary=summary[:500],
        payload=payload,
        proposed_by=get_principal().username,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    _write_proposal(proposal)
    _audit("selfmod_proposed", proposal, error_fatal=True)
    return proposal.proposal_id


def list_proposals(status: str | None = "pending") -> list[Proposal]:
    """List proposals, newest first; the daily review path."""
    out = []
    for path in sorted(_proposals_dir().glob("*.json"), reverse=True):
        try:
            p = Proposal(**json.loads(path.read_text()))
        except (json.JSONDecodeError, TypeError):
            continue
        if status is None or p.status == status:
            out.append(p)
    return out


def _decide(proposal_id: str, *, approve: bool, note: str) -> Proposal:
    if not note or not note.strip():
        raise NoteRequired(
            "a free-text note is required: the reviewer's reasoning is part "
            "of the human-oversight evidence (ISO 42001 A.6.2.4)."
        )
    from lliam_gov.security.principal import require_principal

    principal = require_principal()
    proposal = _read_proposal(proposal_id)
    if proposal.status != "pending":
        raise ProposalAlreadyDecided(
            f"proposal {proposal_id} is already {proposal.status}"
        )
    proposal.status = "approved" if approve else "rejected"
    proposal.decided_by = principal.username
    proposal.decided_at = datetime.now(timezone.utc).isoformat()
    proposal.note = note.strip()
    _write_proposal(proposal)
    _audit(
        "selfmod_approved" if approve else "selfmod_rejected",
        proposal,
        error_fatal=True,
    )
    return proposal


def approve_proposal(proposal_id: str, note: str) -> Proposal:
    """Approve a pending proposal (principal-attributed, note required)."""
    return _decide(proposal_id, approve=True, note=note)


def reject_proposal(proposal_id: str, note: str) -> Proposal:
    """Reject a pending proposal; its payload never becomes live."""
    return _decide(proposal_id, approve=False, note=note)


__all__ = [
    "GATED_CAPABILITIES",
    "PROPOSALS_DIRNAME",
    "SELFMOD_GATE_ENV",
    "NoteRequired",
    "Proposal",
    "ProposalAlreadyDecided",
    "ProposalNotFound",
    "SelfModError",
    "approve_proposal",
    "list_proposals",
    "propose",
    "reject_proposal",
    "selfmod_gate_enabled",
]
