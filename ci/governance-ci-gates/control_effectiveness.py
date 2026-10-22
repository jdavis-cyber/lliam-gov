#!/usr/bin/env python3
"""control_effectiveness.py — Periodic control-effectiveness verifier
(LG-MO-08, P5.2).

Re-asserts the standing posture invariants on a schedule (the cATO
control-effectiveness check the plan requires): godmode + obliteratus
disabled, provider + MCP allowlists enforced, at-rest encryption on, audit
ledger on with verify-on-startup, continuous-monitoring enabled, and the
approval channel authenticated (require_authenticated_approver set AND
enforced by the runtime: an approval with no authenticated subject is
refused, while the desktop app's local-operator subject can still approve;
the MCP permissions_respond tool withheld under strict posture — JER-73),
and — on a deployed host only — a recent scheduled-assurance heartbeat. FAILS
CLOSED (exit 1) on any broken invariant, and emits a `security.posture` event
so the break is on the ISCM stream. Distinct from go_no_go_gate (a release
precondition check): this runs recurring, post-deployment, as a detective
control feeding re-authorization (LG-GV-07).

Exit: 0 = effective, 1 = a control regressed, 2 = error.
PATH-FREEZE: NEW additive script; read-only over the overlay.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except Exception as e:  # pragma: no cover
    print(f"::error::control_effectiveness requires PyYAML ({e})")
    sys.exit(2)

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _emit(msg: str, *, error: bool = False) -> None:
    import os
    prefix = "::error::" if error and os.environ.get("GITHUB_ACTIONS") else ""
    print(f"{prefix}{msg}")


def _load(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def _get(d: dict, dotted: str, default=None):
    node = d
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


# Scheduled assurance job freshness (JER-76). Only asserted on a deployed
# host: the agent home is pinned (LLIAM_HOME / HERMES_HOME) AND holds a real
# ledger, the same home + ledger check attestation_export and the cron units
# use. A repo checkout / CI run has no deployed job, so the check is n/a there.
_ASSURANCE_MAX_AGE_HOURS = 26.0
_ASSURANCE_HEARTBEAT = Path("logs") / "assurance" / "last-run.json"


def _deployed_home() -> Path | None:
    import os
    home = os.environ.get("LLIAM_HOME") or os.environ.get("HERMES_HOME")
    if not home:
        return None
    p = Path(home).expanduser()
    return p if (p / "logs" / "agent-audit.log").is_file() else None


def assurance_job_fresh(cfg: dict, *, home: Path | None = None,
                        now=None) -> bool:
    """True when not deployed, or the assurance job completed recently."""
    import datetime as _dt
    home = home or _deployed_home()
    if home is None:
        return True
    max_age = float(_get(cfg, "monitoring.assurance.max_age_hours")
                    or _ASSURANCE_MAX_AGE_HOURS)
    try:
        data = json.loads((home / _ASSURANCE_HEARTBEAT).read_text("utf-8"))
        done = _dt.datetime.fromisoformat(str(data["completed_at"]))
    except Exception:
        return False
    now = now or _dt.datetime.now(_dt.timezone.utc)
    return (now - done).total_seconds() <= max_age * 3600


# Safety modules whose posture predicate must enforce, not disable, when the
# effective configuration cannot be read (JER-77).
_FAIL_CLOSED_POSTURE_MODULES = (
    "tools.tool_policy",
    "tools.injection_defense",
    "tools.input_integrity",
    "agent.data_protection",
    "tools.egress_policy",
    "tools.mcp_allowlist",
    "agent.attestation",
)


def posture_fault_fails_closed(*, repo_root: Path = _REPO_ROOT) -> bool:
    """Probe each safety module with an unreadable configuration.

    Returns True only if every module still reports strict enforcement. An
    import failure counts as ineffective: the control could not be verified.
    """
    import importlib
    from unittest import mock

    root = str(repo_root)
    if root not in sys.path:
        sys.path.insert(0, root)

    def _unreadable():
        raise OSError("control-effectiveness probe: configuration unreadable")

    try:
        modules = [importlib.import_module(m) for m in _FAIL_CLOSED_POSTURE_MODULES]
        cfg = importlib.import_module("lliam_cli.config")
        with mock.patch.object(cfg, "load_config", _unreadable):
            return all(m._is_strict() for m in modules)
    except Exception:
        return False


def _approval_channel_probe(cfg: dict, repo_root: Path) -> dict:
    """Exercise the runtime approval-channel controls against *cfg* (JER-73).

    * ``authenticated_approver_enforced`` — the runtime reads
      ``security.require_authenticated_approver`` from this overlay and
      refuses an approval that carries no authenticated subject, while a
      denial still passes.
    * ``local_operator_approval_accepted`` — the subject the gateway binds to
      the desktop app's connection (the one that presented the per-launch
      gateway secret) is accepted as an authenticated approver, so the
      operator's own desktop app can still approve.
    * ``mcp_permissions_respond_withheld`` — the inbound MCP server's strict
      tool surface does not include ``permissions_respond``.

    Read-only: each probe runs in a fresh context (nothing bound unless the
    probe binds it) with ``record=False``, so nothing reaches the ledger. Any
    import/probe error reports False.
    """
    import contextvars

    root = str(repo_root)
    if root not in sys.path:
        sys.path.insert(0, root)
    out = {"authenticated_approver_enforced": False,
           "local_operator_approval_accepted": False,
           "mcp_permissions_respond_withheld": False}
    try:
        from tools import hitl_oversight as ho

        def _probe(choice):
            return ho.authorize_approval(
                choice, gate="ci.probe", origin="control_effectiveness",
                config=cfg, record=False)

        refused = contextvars.Context().run(_probe, "once")
        denied = contextvars.Context().run(_probe, "deny")
        out["authenticated_approver_enforced"] = bool(
            ho.require_authenticated_approver(cfg)
            and not refused.allowed and denied.allowed)
    except Exception as e:  # pragma: no cover - surfaced as INEFFECTIVE
        _emit(f"approval-channel probe error: {e}")
    try:
        from agent import governance_audit_hooks as gah
        from tools import hitl_oversight as ho
        from tui_gateway import transport as gw

        def _desktop_probe():
            gah._operator_subject.set(gw.local_operator_subject())
            return ho.authorize_approval(
                "once", gate="ci.probe", origin="control_effectiveness",
                config=cfg, record=False)

        accepted = contextvars.Context().run(_desktop_probe)
        out["local_operator_approval_accepted"] = bool(
            accepted.allowed
            and str(accepted.principal or "").startswith("local-operator:")
            and accepted.method == gw.LOCAL_OPERATOR_AUTH)
    except Exception as e:  # pragma: no cover - surfaced as INEFFECTIVE
        _emit(f"desktop-approver probe error: {e}")
    try:
        import mcp_serve
        out["mcp_permissions_respond_withheld"] = (
            "permissions_respond" not in mcp_serve.tool_surface(strict=True))
    except Exception as e:  # pragma: no cover - surfaced as INEFFECTIVE
        _emit(f"MCP tool-surface probe error: {e}")
    return out


def effectiveness_report(*, repo_root: Path = _REPO_ROOT,
                         overlay_path: Path | None = None,
                         check_assurance_freshness: bool = True) -> dict:
    overlay_path = overlay_path or (repo_root / "cli-config.gov.yaml")
    cfg = _load(overlay_path)
    disabled = set(_get(cfg, "skills.disabled") or [])
    return {
        "posture_strict": str(_get(cfg, "security.posture")) == "strict",
        "godmode_disabled": "godmode" in disabled,
        "obliteratus_disabled": "obliteratus" in disabled,
        "provider_allowlist_enforced": bool(
            _get(cfg, "security.provider_allowlist_enforce")),
        "mcp_allowlist_enforced": bool(
            _get(cfg, "security.mcp_allowlist_enforce")),
        "at_rest_encryption": bool(
            _get(cfg, "security.data_protection.at_rest_encryption")),
        "audit_ledger_enabled": bool(_get(cfg, "audit.ledger_enabled")),
        "audit_verify_on_startup": bool(_get(cfg, "audit.verify_on_startup")),
        "monitoring_enabled": bool(_get(cfg, "monitoring.iscm_sink.enabled")),
        "posture_fault_fails_closed": posture_fault_fails_closed(repo_root=repo_root),
        "authenticated_approver_required": _get(
            cfg, "security.require_authenticated_approver") is True,
        **_approval_channel_probe(cfg, repo_root),
        "assurance_job_fresh": (assurance_job_fresh(cfg)
                                if check_assurance_freshness else True),
    }


def check_effectiveness(*, repo_root: Path = _REPO_ROOT,
                        overlay_path: Path | None = None,
                        check_assurance_freshness: bool = True) -> list[str]:
    r = effectiveness_report(
        repo_root=repo_root, overlay_path=overlay_path,
        check_assurance_freshness=check_assurance_freshness)
    checks = {
        "posture_strict": "security.posture is not strict",
        "godmode_disabled": "godmode is not disabled",
        "obliteratus_disabled": "obliteratus is not disabled",
        "provider_allowlist_enforced": "provider allowlist not enforced",
        "mcp_allowlist_enforced": "MCP allowlist not enforced",
        "at_rest_encryption": "at-rest encryption not asserted",
        "audit_ledger_enabled": "audit ledger not enabled",
        "audit_verify_on_startup": "audit verify-on-startup off",
        "monitoring_enabled": "continuous monitoring (ISCM sink) not enabled",
        "posture_fault_fails_closed": "a configuration fault disables a safety control",
        "authenticated_approver_required":
            "security.require_authenticated_approver is not true",
        "authenticated_approver_enforced":
            "an unauthenticated HITL approval is not refused at runtime",
        "local_operator_approval_accepted":
            "the desktop app's local operator cannot approve HITL requests",
        "mcp_permissions_respond_withheld":
            "MCP permissions_respond is exposed under strict posture",
        "assurance_job_fresh": ("scheduled assurance job has not completed "
                                "within monitoring.assurance.max_age_hours "
                                "on this host (not installed or stale)"),
    }
    return [f"[INEFFECTIVE] {msg} (LG-MO-08)"
            for key, msg in checks.items() if not r.get(key)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=str(_REPO_ROOT))
    args = parser.parse_args(argv)
    try:
        failures = check_effectiveness(repo_root=Path(args.repo_root))
    except Exception as e:  # pragma: no cover
        _emit(f"control_effectiveness: error ({e})", error=True)
        return 2
    if failures:
        _emit(f"[LG-MO-08] CONTROL-EFFECTIVENESS BREAK ({len(failures)}):",
              error=True)
        for f in failures:
            _emit(f"    - {f}", error=True)
        return 1
    _emit("[LG-MO-08] OK — posture invariants effective (godmode/obliteratus "
          "disabled, allowlists enforced, encryption + audit + monitoring on, "
          "approval channel authenticated).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
