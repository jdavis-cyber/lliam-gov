"""Shared fail-closed startup posture gate for every Lliam-GOV entrypoint.

The five fail-closed startup gates in :mod:`lliam_cli.security_audit_startup`
used to be invoked only from the messaging gateway's ``start_gateway`` (the
gateway was removed in JER-198). Launching via the
terminal chat (``lliam-gov``), ``lliam-gov-agent`` (``run_agent.py``), the ACP
adapter (``lliam-gov-acp``), the TUI backend (``tui_gateway.entry``) or the
desktop app's backend (``lliam-gov dashboard``) ran none of them, so the
startup posture assertions only held for one launch path.

:func:`enforce_startup_posture` is that gateway block, extracted verbatim in
behaviour, so every entrypoint runs the same gate set in the same order:

1. agent NPE identity emit (LG-IA-02; non-fatal, no-op without a ledger)
2. control-plane auth (LG-IA-11/06/08)
3. provider allowlist (LG-MP-01/02)
4. model integrity (LG-MP-05/06)
5. governance artifacts (LG-GV-01/06/10)
6. audit-chain verify (LG-AU-08)

Each gate is handed the MERGED config (falling back to the raw home config on a
load failure). A gate's own blocking error propagates (fail-closed); any other
fault inside a gate is logged at debug and treated as non-fatal, exactly as the
gateway did. On the low-side posture every gate is advisory or a no-op, so this
never blocks a non-strict deployment.

Entrypoints use :func:`enforce_startup_posture_or_exit`,
which turns a blocking gate error into a one-line stderr refusal and a non-zero
exit instead of a traceback. stdout is never written (ACP and the TUI backend
speak JSON-RPC on stdout).
"""
from __future__ import annotations

import logging
import sys
from typing import Optional

from lliam_cli import security_audit_startup as _sas

logger = logging.getLogger("hermes.security_audit")

# Every blocking error a startup gate can raise. A caller that wants to refuse
# to start (rather than propagate) catches exactly these.
STARTUP_GATE_ERRORS: tuple[type[BaseException], ...] = (
    _sas.ControlPlaneAuthError,
    _sas.ProviderAllowlistError,
    _sas.ModelIntegrityError,
    _sas.GovernanceArtifactError,
    _sas.AuditChainVerificationError,
)

# Exit status for a refused start. Distinct from argparse's 2 so wrappers and
# service managers can tell "posture gate refused" from "bad arguments".
STARTUP_POSTURE_EXIT_CODE = 78  # EX_CONFIG (sysexits.h)

# Latched after one complete passing run so a process that reaches this from
# two layers (e.g. ``lliam-gov acp`` -> acp_adapter.entry.main) emits the
# identity record once. Never latched on a failure.
_STARTUP_POSTURE_ENFORCED = False


def _read_raw_config() -> Optional[dict]:
    try:
        from lliam_cli.config import read_raw_config

        return read_raw_config()
    except Exception:
        return None


def _merged_config(fallback: Optional[dict]) -> Optional[dict]:
    try:
        from lliam_cli.config import load_config

        return load_config()
    except Exception:
        return fallback


def enforce_startup_posture(
    *, raw_config: Optional[dict] = None, force: bool = False
) -> None:
    """Run the fail-closed startup gate set; raise on a blocking finding.

    ``raw_config`` is the raw home config used for the identity emit and as the
    last-resort fallback when the merged config cannot be loaded; it is read
    here when not supplied. Raises one of :data:`STARTUP_GATE_ERRORS` under a
    strict posture when a gate blocks. Returns None otherwise. Idempotent per
    process once a run completes (``force`` re-runs the sequence; the
    individual gates keep their own per-process latches).
    """
    global _STARTUP_POSTURE_ENFORCED
    if _STARTUP_POSTURE_ENFORCED and not force:
        return None

    if raw_config is None:
        raw_config = _read_raw_config()

    # LG-IA-02 (additive): record the agent NPE instance identity for this
    # process (no-op when the ledger is disabled). Emitted before the chain
    # verify so the identity binding is on record for the session.
    try:
        _sas.emit_agent_identity_at_startup(config=raw_config)
    except Exception as _ident_exc:
        logger.debug("Agent identity emit failed (non-fatal): %s", _ident_exc)

    # LG-IA-11/06/08 (additive): fail-closed control-plane auth gate. Refuses to
    # start a network-accessible API server with no API_SERVER_KEY (RCE gate) or
    # with TLS verification disabled, under strict posture.
    try:
        _sas.enforce_control_plane_auth_at_startup(
            config=_merged_config(raw_config)
        )
    except _sas.ControlPlaneAuthError:
        raise
    except Exception as _cp_exc:
        logger.debug("Control-plane auth check failed (non-fatal): %s", _cp_exc)

    # LG-MP-01/02 (additive @ P3.1): fail-closed provider-allowlist gate.
    # Refuses to start when any configured routing path (primary/fallback/MoA/
    # auxiliary/delegation) names a non-allowlisted inference provider or host,
    # under strict posture + security.provider_allowlist_enforce.
    try:
        _sas.enforce_provider_allowlist_at_startup(
            config=_merged_config(raw_config)
        )
    except _sas.ProviderAllowlistError:
        raise
    except Exception as _pa_exc:
        logger.debug("Provider-allowlist check failed (non-fatal): %s", _pa_exc)

    # LG-MP-05/06 (additive @ P3.2): fail-closed model-integrity gate. Refuses
    # to start when the signed model manifest is invalid/untrusted or the
    # configured primary model lacks a required model card, under strict posture.
    try:
        _sas.enforce_model_integrity_at_startup(
            config=_merged_config(raw_config)
        )
    except _sas.ModelIntegrityError:
        raise
    except Exception as _mi_exc:
        logger.debug("Model-integrity check failed (non-fatal): %s", _mi_exc)

    # LG-GV-01/06/10 (additive @ P4.1): fail-closed governance-artifacts gate.
    # Refuses to serve work under strict posture when the top-management layer
    # is absent or stale. Complete no-op on the low-side posture.
    try:
        _sas.enforce_governance_artifacts_at_startup(
            config=_merged_config(raw_config)
        )
    except _sas.GovernanceArtifactError:
        raise
    except Exception as _ga_exc:
        logger.debug("Governance-artifacts check failed (non-fatal): %s", _ga_exc)

    # LG-AU-08 (additive): verify the governance audit chain at startup. No-op
    # when the ledger is disabled; on a break under strict posture with
    # verify_fail_action=block this raises AuditChainVerificationError
    # (fail-closed — refuse to rely on a tampered ledger). The MERGED config is
    # passed so the overlay's strict-posture / audit block is visible.
    try:
        _sas.verify_audit_chain_at_startup(config=_merged_config(raw_config))
    except _sas.AuditChainVerificationError:
        raise
    except Exception as _verify_exc:
        logger.debug("Audit-chain startup verify failed (non-fatal): %s", _verify_exc)

    _STARTUP_POSTURE_ENFORCED = True
    return None


def enforce_startup_posture_or_exit(entrypoint: str) -> None:
    """Run :func:`enforce_startup_posture`; on a blocking gate, refuse to start.

    Prints a single refusal line to stderr (never stdout) and raises
    ``SystemExit(STARTUP_POSTURE_EXIT_CODE)``. Used by every entrypoint.
    """
    try:
        enforce_startup_posture()
    except STARTUP_GATE_ERRORS as exc:
        logger.critical(
            "[startup-posture] %s refused to start: %s: %s",
            entrypoint, type(exc).__name__, exc,
        )
        try:
            print(
                f"{entrypoint}: refusing to start — strict-posture startup gate "
                f"failed ({type(exc).__name__}): {exc}\n"
                "Repair the configuration (lliam-gov config / lliam-gov doctor / "
                "lliam-gov setup) and retry.",
                file=sys.stderr,
            )
        except Exception:
            pass
        raise SystemExit(STARTUP_POSTURE_EXIT_CODE) from exc
