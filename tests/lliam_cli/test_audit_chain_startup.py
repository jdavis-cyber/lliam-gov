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
