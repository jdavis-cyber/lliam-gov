"""Startup audit-chain verification tests (LG-AU-08, P1.3).

Covers verify_audit_chain_at_startup: no-op when disabled, PASS on a good
chain, and the fail-closed vs advisory split on a tampered chain.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import agent.governance_audit as ga
import lliam_cli.security_audit_startup as sas


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.setattr(sas, "_CHAIN_VERIFIED", False)
    yield


def _enable_ledger(monkeypatch, tmp_path):
    path = tmp_path / "agent-audit.log"
    led = ga.GovernanceLedger(path)
    monkeypatch.setattr(ga, "ledger_enabled", lambda cfg=None: True)
    monkeypatch.setattr(ga, "resolve_ledger_path", lambda cfg=None: path)
    monkeypatch.setattr(ga, "get_ledger", lambda: led)
    return led


_STRICT_CFG = {"security": {"posture": "strict"},
               "audit": {"verify_on_startup": True, "verify_fail_action": "block"}}


def test_noop_when_ledger_disabled(monkeypatch):
    monkeypatch.setattr(ga, "ledger_enabled", lambda cfg=None: False)
    assert sas.verify_audit_chain_at_startup(config=_STRICT_CFG) is None


def test_pass_on_good_chain(monkeypatch, tmp_path):
    led = _enable_ledger(monkeypatch, tmp_path)
    led.emit("session.start", action="run", source_module="t")
    led.emit("tool.result", action="x", source_module="t")
    result = sas.verify_audit_chain_at_startup(config=_STRICT_CFG)
    assert result is not None and result["ok"] is True
    assert result["checked"] == 2


def test_strict_block_raises_on_tamper(monkeypatch, tmp_path):
    led = _enable_ledger(monkeypatch, tmp_path)
    led.emit("session.start", action="run", source_module="t")
    led.emit("tool.result", action="x", source_module="t")
    lines = led.path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["action"] = "FORGED"
    lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    led.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(sas.AuditChainVerificationError):
        sas.verify_audit_chain_at_startup(config=_STRICT_CFG)


def test_advisory_posture_alerts_but_does_not_raise(monkeypatch, tmp_path):
    led = _enable_ledger(monkeypatch, tmp_path)
    led.emit("session.start", action="run", source_module="t")
    led.emit("tool.result", action="x", source_module="t")
    lines = led.path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["action"] = "FORGED"
    lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    led.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Non-strict posture: alert-only, no raise.
    cfg = {"audit": {"verify_fail_action": "block"}}  # no strict posture
    result = sas.verify_audit_chain_at_startup(config=cfg, force=True)
    assert result is not None and result["ok"] is False


def test_verify_on_startup_false_skips(monkeypatch, tmp_path):
    _enable_ledger(monkeypatch, tmp_path)
    cfg = {"security": {"posture": "strict"},
           "audit": {"verify_on_startup": False, "verify_fail_action": "block"}}
    assert sas.verify_audit_chain_at_startup(config=cfg) is None


def test_raw_config_still_blocks_when_merged_is_strict(monkeypatch, tmp_path):
    """P1.3-review P1 regression: a caller (the gateway) that passes a raw,
    overlay-less config (no security.posture, no audit block) must STILL
    block on tamper, because the hook re-resolves posture from the merged
    load_config() rather than trusting the passed shape."""
    led = _enable_ledger(monkeypatch, tmp_path)
    led.emit("session.start", action="run", source_module="t")
    led.emit("tool.result", action="x", source_module="t")
    lines = led.path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["action"] = "FORGED"
    lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    led.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # The effective merged config IS strict (overlay loaded) even though the
    # caller handed us a raw dict with neither posture nor an audit block.
    merged = {"security": {"posture": "strict"},
              "audit": {"verify_on_startup": True, "verify_fail_action": "block"}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: merged)
    raw_shape = {"some": "home-config-without-overlay"}
    with pytest.raises(sas.AuditChainVerificationError):
        sas.verify_audit_chain_at_startup(config=raw_shape, force=True)


def test_disabled_ledger_does_not_latch_sentinel(monkeypatch):
    """A no-op (disabled) call must not latch the once-per-process sentinel,
    so a later real call still runs (P1.3-review P2 — sentinel hygiene)."""
    monkeypatch.setattr(ga, "ledger_enabled", lambda cfg=None: False)
    sas.verify_audit_chain_at_startup(config=_STRICT_CFG)
    assert sas._CHAIN_VERIFIED is False


def test_idempotent_per_process(monkeypatch, tmp_path):
    led = _enable_ledger(monkeypatch, tmp_path)
    led.emit("session.start", action="run", source_module="t")
    first = sas.verify_audit_chain_at_startup(config=_STRICT_CFG)
    assert first is not None
    # Second call (no force) is a no-op — already ran this process.
    assert sas.verify_audit_chain_at_startup(config=_STRICT_CFG) is None


def test_strict_block_fails_closed_on_permission_error(monkeypatch, tmp_path):
    """LG-AU-08 fail-closed: an unexpected PermissionError while verifying the
    chain means integrity CANNOT be confirmed. Under strict posture with
    verify_fail_action=block that must RAISE, not log-and-proceed (P1.4 review:
    the bare ``except Exception`` swallowed OSError and allowed startup)."""
    _enable_ledger(monkeypatch, tmp_path)

    def _boom(*a, **k):
        raise PermissionError("audit log not readable")

    monkeypatch.setattr(ga, "verify_chain", _boom)
    with pytest.raises(sas.AuditChainVerificationError):
        sas.verify_audit_chain_at_startup(config=_STRICT_CFG, force=True)


def test_strict_block_fails_closed_on_oserror(monkeypatch, tmp_path):
    """A generic OSError (I/O error) during verify is equally unconfirmable →
    fail closed under strict/block."""
    _enable_ledger(monkeypatch, tmp_path)

    def _boom(*a, **k):
        raise OSError("input/output error")

    monkeypatch.setattr(ga, "verify_chain", _boom)
    with pytest.raises(sas.AuditChainVerificationError):
        sas.verify_audit_chain_at_startup(config=_STRICT_CFG, force=True)


def test_advisory_posture_verify_error_does_not_raise(monkeypatch, tmp_path):
    """Advisory posture: an unconfirmable verify is reported (returns None,
    logged) but never blocks."""
    _enable_ledger(monkeypatch, tmp_path)

    def _boom(*a, **k):
        raise PermissionError("locked")

    monkeypatch.setattr(ga, "verify_chain", _boom)
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: {})  # non-strict
    cfg = {"audit": {"verify_fail_action": "block"}}  # no strict posture
    assert sas.verify_audit_chain_at_startup(config=cfg, force=True) is None


def test_missing_ledger_file_is_benign_under_strict(monkeypatch, tmp_path):
    """A genuinely absent/vanished ledger file (FileNotFoundError) is benign —
    there is no chain to verify — so it is skipped, not fail-closed. (Only an
    unexpected PermissionError/OSError is an integrity-unconfirmable failure.)"""
    _enable_ledger(monkeypatch, tmp_path)

    def _missing(*a, **k):
        raise FileNotFoundError("ledger vanished")

    monkeypatch.setattr(ga, "verify_chain", _missing)
    assert sas.verify_audit_chain_at_startup(config=_STRICT_CFG, force=True) is None


def test_verify_error_does_not_latch_sentinel(monkeypatch, tmp_path):
    """Sentinel hygiene: an unconfirmable (errored) verify under advisory
    posture must NOT latch _CHAIN_VERIFIED, so a later call retries rather than
    being permanently disabled by one transient error."""
    _enable_ledger(monkeypatch, tmp_path)
    calls = {"n": 0}

    def _boom(*a, **k):
        calls["n"] += 1
        raise PermissionError("transient")

    monkeypatch.setattr(ga, "verify_chain", _boom)
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: {})  # non-strict
    cfg = {"audit": {"verify_fail_action": "block"}}
    sas.verify_audit_chain_at_startup(config=cfg)  # no force
    assert sas._CHAIN_VERIFIED is False
    sas.verify_audit_chain_at_startup(config=cfg)  # no force → must run again
    assert calls["n"] == 2


# ---- LG-IA-05 no-default-credentials + LG-IA-02 identity emit --------------

def test_default_credential_is_flagged(monkeypatch):
    monkeypatch.setenv("PROVIDER_API_KEY", "changeme")
    findings = sas.run_security_audit(
        config={"security": {"no_default_credentials": True}}
    )
    assert any("default" in f.lower() and "PROVIDER_API_KEY" in f for f in findings)


def test_strong_credential_not_flagged(monkeypatch):
    monkeypatch.setenv("PROVIDER_API_KEY", "s0m3-str0ng-uniq-value-9f2c4b8a")
    findings = sas.run_security_audit(
        config={"security": {"no_default_credentials": True}}
    )
    assert not any("PROVIDER_API_KEY" in f for f in findings)


def test_default_credential_check_off_by_default(monkeypatch):
    monkeypatch.setenv("PROVIDER_API_KEY", "changeme")
    # Switch absent → no LG-IA-05 finding (capability-preserving default).
    findings = sas.run_security_audit(config={})
    assert not any("PROVIDER_API_KEY" in f for f in findings)


def test_default_credential_value_never_emitted(monkeypatch):
    monkeypatch.setenv("MY_SECRET", "changeme")
    findings = sas.run_security_audit(
        config={"security": {"no_default_credentials": True}}
    )
    joined = " ".join(findings)
    assert "MY_SECRET" in joined and "changeme" not in joined


def test_emit_agent_identity_noop_when_disabled(monkeypatch):
    import agent.governance_audit as ga
    monkeypatch.setattr(ga, "ledger_enabled", lambda cfg=None: False)
    assert sas.emit_agent_identity_at_startup(config=_STRICT_CFG) is None


def test_emit_agent_identity_records_config_load(monkeypatch, tmp_path):
    import agent.governance_audit as ga
    led = _enable_ledger(monkeypatch, tmp_path)
    ident = sas.emit_agent_identity_at_startup(config={"security": {"posture": "strict"}})
    assert ident is not None and ident["instance_id"].startswith("sha256:")
    recs = list(ga.iter_records(led.path))
    assert any(r["event"] == "config.load"
               and r["action"] == "agent.identity_bind" for r in recs)


def test_startup_identity_matches_operational_actor_triple(monkeypatch, tmp_path):
    """P1.4-review fix: the startup identity_bind must share code/config/
    toolset with the session's operational tool.dispatch actors (they differ
    only by the per-turn model), so an assessor can correlate them. The old
    version emitted a phantom (raw config, full toolset, model=sha256(None|None))
    that matched nothing."""
    import agent.governance_audit_hooks as gah
    from types import SimpleNamespace

    _enable_ledger(monkeypatch, tmp_path)
    merged = {"security": {"posture": "strict"},
              "agent": {"disabled_toolsets": ["computer_use", "browser"]}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: merged)

    startup = sas.emit_agent_identity_at_startup(config={"raw": "no-agent-key"})
    # Operational actor: same config + pruned toolset, real per-turn model.
    agent = SimpleNamespace(provider="bedrock-govcloud", model="claude-x",
                            enabled_toolsets=None,
                            disabled_toolsets=["computer_use", "browser"])
    import agent.agent_identity as ai
    operational = ai.compute_instance_identity(agent, config=merged)

    assert startup["code_hash"] == operational["code_hash"]
    assert startup["config_hash"] == operational["config_hash"]
    assert startup["toolset_hash"] == operational["toolset_hash"]
    # Model differs (startup is per-turn-unbound), and is marked honestly.
    assert startup["model"].get("resolved") == "per-turn"


def test_default_credential_check_covers_aws_access_key(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "changeme")
    findings = sas.run_security_audit(
        config={"security": {"no_default_credentials": True}}
    )
    assert any("AWS_ACCESS_KEY_ID" in f for f in findings)
