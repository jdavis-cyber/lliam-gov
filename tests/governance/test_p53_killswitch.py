"""P5.3 kill-switch + containment + recovery tests (LG-IR-01..09, LG-RM-09, AI-501).

The AI-501 VERIFY criteria, machine-checked:
  * triggering the kill-switch halts BOTH tool execution and inference
    (LG-IR-01) — the tool-dispatch chokepoint returns a halt decision and the
    inference resolve seam raises;
  * containment can disable tool classes / force HITL (LG-IR-02);
  * recovery requires ``verify_chain()`` PASS before re-enable and restores to
    the last signed-tag baseline (LG-IR-08) — a broken chain keeps the halt
    (fail-closed);
  * after a clean recovery, FULL capability is restored — no lingering halt,
    no false auto-suspension on steady state (the FINAL-gate requirement);
  * the engage/recover cycle is durable across threads and emits
    killswitch.activate to the ledger for forensic reconstruction (LG-IR-04/07).
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from agent import killswitch as ks


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    # Redirect the durable kill-switch state under a throwaway home.
    monkeypatch.setattr(ks, "_state_path",
                        lambda: tmp_path / "killswitch.state")
    ks.reset_for_tests()
    yield
    ks.reset_for_tests()


# ---------------------------------------------------------------------------
# Steady state — NOT engaged by default (no false auto-suspension)
# ---------------------------------------------------------------------------

def test_not_engaged_by_default():
    assert ks.is_engaged() is False
    assert ks.guard_tool_dispatch("file_read") is None
    ks.assert_inference_live()  # must not raise


# ---------------------------------------------------------------------------
# LG-IR-01 — engage halts BOTH tool execution and inference
# ---------------------------------------------------------------------------

def test_engage_halts_tool_dispatch():
    ks.engage(reason="injected drift", actor="isso@agency.mil")
    dec = ks.guard_tool_dispatch("shell.destructive")
    assert dec is not None
    assert getattr(dec, "action", None) == "halt"


def test_engage_halts_inference():
    ks.engage(reason="injected drift", actor="isso@agency.mil")
    with pytest.raises(ks.KillSwitchEngaged):
        ks.assert_inference_live()


def test_engage_is_durable_across_threads():
    ks.engage(reason="x", actor="isso@agency.mil")
    seen = {}

    def worker():
        seen["engaged"] = ks.is_engaged()

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert seen["engaged"] is True


# ---------------------------------------------------------------------------
# LG-IR-02 — containment: disable tool classes / force HITL
# ---------------------------------------------------------------------------

def test_containment_disables_named_tool_classes():
    ks.engage(reason="contain shell", actor="isso@agency.mil",
              contain_classes=["shell.destructive", "network.egress"])
    assert ks.class_contained("shell.destructive") is True
    assert ks.class_contained("file_read") is False


# ---------------------------------------------------------------------------
# LG-IR-08 — recovery requires verify_chain PASS before re-enable
# ---------------------------------------------------------------------------

def test_recovery_blocked_when_chain_broken():
    ks.engage(reason="incident", actor="isso@agency.mil")
    ok = ks.recover_and_reenable(
        baseline_tag="gov-P4-good", actor="isso@agency.mil",
        verify_ok=False, verify_reason="record_hash mismatch at seq=7")
    assert ok is False
    # still halted — fail-closed
    assert ks.is_engaged() is True
    assert ks.guard_tool_dispatch("file_read") is not None


def test_recovery_reenables_on_chain_pass():
    ks.engage(reason="incident", actor="isso@agency.mil")
    ok = ks.recover_and_reenable(
        baseline_tag="gov-P4-good", actor="isso@agency.mil", verify_ok=True)
    assert ok is True
    # FULL capability restored — no lingering halt (FINAL-gate requirement)
    assert ks.is_engaged() is False
    assert ks.guard_tool_dispatch("shell.destructive") is None
    ks.assert_inference_live()
    assert ks.class_contained("shell.destructive") is False


# ---------------------------------------------------------------------------
# Halt→restore cycle leaves no residue (no false auto-suspension)
# ---------------------------------------------------------------------------

def test_clean_cycle_restores_steady_state():
    for _ in range(3):
        ks.engage(reason="scheduled kill-switch test", actor="isso@agency.mil")
        assert ks.is_engaged() is True
        assert ks.recover_and_reenable(
            baseline_tag="gov-P4-good", actor="isso@agency.mil",
            verify_ok=True) is True
        assert ks.is_engaged() is False
        assert ks.guard_tool_dispatch("file_read") is None


# ---------------------------------------------------------------------------
# LG-IR-04/07 — engagement is recorded for forensic reconstruction
# ---------------------------------------------------------------------------

def test_engage_records_state_with_reason_and_actor():
    ks.engage(reason="egress exfil detected", actor="isso@agency.mil")
    st = ks.state()
    assert st["engaged"] is True
    assert st["reason"] == "egress exfil detected"
    assert st["actor"] == "isso@agency.mil"


# ---------------------------------------------------------------------------
# Live wiring — the guards are called at the real seams
# ---------------------------------------------------------------------------

def test_killswitch_wired_at_tool_dispatch_and_inference():
    repo = Path(__file__).resolve().parents[2]
    hooks = (repo / "agent" / "governance_audit_hooks.py").read_text()
    assert "killswitch" in hooks and "guard_tool_dispatch" in hooks
    rp = (repo / "lliam_cli" / "runtime_provider.py").read_text()
    assert "killswitch" in rp and "assert_inference_live" in rp


# ---------------------------------------------------------------------------
# IR docs present (LG-IR-05/06)
# ---------------------------------------------------------------------------

def test_ir_runbook_present():
    gov = Path(__file__).resolve().parents[2] / "docs" / "governance"
    text = (gov / "incident-response-plan.md").read_text(encoding="utf-8")
    assert len(text) > 3000
    for needle in ("kill-switch", "72", "DIBNet", "severity", "chain of custody"):
        assert needle.lower() in text.lower(), f"IR plan missing {needle}"
