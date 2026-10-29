"""JER-190 — kill-switch is operable, fail-closed, and recovery verifies itself.

Covers: atomic durable state that other processes see; the tool guard and the
predispatch wiring fail CLOSED on an internal error; recovery refuses when
verification fails and, when it passes, restores the signed baseline itself,
preserves forensics with a custody manifest, and records who/when/why in the
audit ledger.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest

import agent.governance_audit as ga
import agent.governance_audit_hooks as gah
from agent import incident_recovery as ir
from agent.governance_audit import iter_records


def _actions(led):
    return [(r["action"], r.get("decision"), r.get("outcome") or {})
            for r in iter_records(led.path)]


# ---------------------------------------------------------------------------
# Durable state
# ---------------------------------------------------------------------------

def test_state_file_written_atomically(ks_home, tmp_path, monkeypatch):
    ks = ks_home
    ks.engage(reason="first", actor="isso")
    path = tmp_path / "killswitch.state"
    before = path.read_bytes()
    assert json.loads(before)["engaged"] is True
    assert oct(path.stat().st_mode & 0o777) == "0o600"

    # A crash at the rename leaves the previous state intact and no temp file.
    def boom(*a, **k):
        raise OSError("simulated crash")

    monkeypatch.setattr(ks.os, "replace", boom)
    with pytest.raises(OSError):
        ks.engage(reason="second", actor="isso")
    assert path.read_bytes() == before
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".killswitch")] == []


def test_release_by_another_process_is_seen(ks_home, tmp_path):
    ks = ks_home
    ks.engage(reason="x", actor="isso")
    assert ks.is_engaged() is True
    # Another process writes a release record (os.replace → new inode).
    tmp = tmp_path / "other.tmp"
    tmp.write_text(json.dumps({"engaged": False, "released_by": "ao"}))
    os.replace(tmp, tmp_path / "killswitch.state")
    assert ks.is_engaged() is False


def test_engage_by_another_process_is_seen(ks_home, tmp_path):
    ks = ks_home
    assert ks.is_engaged() is False
    (tmp_path / "killswitch.state").write_text(
        json.dumps({"engaged": True, "reason": "cli", "actor": "isso"}))
    assert ks.is_engaged() is True
    assert ks.guard_tool_dispatch("write_file") is not None


def test_deleted_state_file_does_not_release(ks_home, tmp_path):
    ks = ks_home
    ks.engage(reason="x", actor="isso")
    (tmp_path / "killswitch.state").unlink()
    assert ks.is_engaged() is True
    assert ks.guard_tool_dispatch("write_file") is not None


def test_corrupt_state_is_engaged(ks_home, tmp_path):
    (tmp_path / "killswitch.state").write_text("{not json")
    assert ks_home.is_engaged() is True


def test_state_file_is_write_denied_to_the_agent(monkeypatch, tmp_path):
    from agent import file_safety
    from lliam_constants import get_default_lliam_root
    assert file_safety.is_write_denied(str(get_default_lliam_root() / "killswitch.state"))


# ---------------------------------------------------------------------------
# Guard fails closed
# ---------------------------------------------------------------------------

def test_guard_exception_denies(ks_home, monkeypatch):
    ks = ks_home

    def boom():
        raise RuntimeError("state check exploded")

    monkeypatch.setattr(ks, "is_engaged", boom)
    dec = ks.guard_tool_dispatch("write_file")
    assert dec is not None
    assert dec.action == "halt"
    assert dec.code == "killswitch_guard_error"
    assert not dec.allows_execution


def test_guard_denies_even_without_guardrail_module(ks_home, monkeypatch):
    import builtins
    ks = ks_home
    ks.engage(reason="x", actor="isso")
    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "agent.tool_guardrails":
            raise ImportError("gone")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    dec = ks.guard_tool_dispatch("write_file")
    assert dec is not None and dec.should_halt and not dec.allows_execution


def test_predispatch_gate_fails_closed_when_guard_raises(ks_home, monkeypatch):
    def boom(_name):
        raise RuntimeError("guard crashed")

    monkeypatch.setattr(ks_home, "guard_tool_dispatch", boom)
    monkeypatch.setattr(gah, "_enabled_ledger", lambda: None)
    dec = gah.predispatch_gate(None, function_name="write_file", function_args={})
    assert dec is not None
    assert dec.action == "halt"
    assert dec.code == "killswitch_guard_error"


def test_tool_calls_blocked_while_engaged_at_the_dispatcher(ks_home, monkeypatch):
    import model_tools
    from tools.registry import registry
    calls = []
    monkeypatch.setattr(registry, "dispatch",
                        lambda name, args, **kw: calls.append(name) or '{"ok": 1}')
    monkeypatch.setattr(gah, "_enabled_ledger", lambda: None)
    ks_home.engage(reason="incident", actor="isso")
    out = model_tools.handle_function_call("write_file", {"path": "x", "content": "y"})
    assert calls == []
    assert "kill-switch" in json.loads(out)["error"]


# ---------------------------------------------------------------------------
# Recovery verifies and restores itself
# ---------------------------------------------------------------------------

def test_recovery_restores_drifted_baseline(ks_home, live_ledger, baseline_repo):
    ks = ks_home
    good_overlay = baseline_repo.overlay.read_bytes()
    baseline_repo.overlay.write_text(
        "security:\n  posture: permissive\n  redact_secrets: false\n")
    baseline_repo.policy.unlink()
    ks.engage(reason="drift detected", actor="isso@agency.mil")

    res = ks.recover(actor="ao@agency.mil", reason="incident closed",
                     repo_root=baseline_repo.root)
    assert res.ok, res.reason
    assert ks.is_engaged() is False
    assert baseline_repo.overlay.read_bytes() == good_overlay
    assert baseline_repo.policy.exists()
    assert sorted(res.restored) == ["cli-config.gov.yaml",
                                    "policy/provider-allowlist.yaml"]
    assert res.baseline_commit == baseline_repo.commit
    assert res.baseline_source == "authorization-record"

    # who/when/why recorded in the ledger, and the chain still verifies
    recs = [a for a in _actions(live_ledger) if a[0] == "killswitch.recover"]
    assert recs and recs[-1][1] == "allow"
    out = recs[-1][2]
    assert out["operator_reason"] == "incident closed"
    assert out["released_at"]
    assert out["previous"]["reason"] == "drift detected"
    last = list(iter_records(live_ledger.path))[-1]
    assert last["subject"]["principal"] == "ao@agency.mil"
    assert ga.verify_chain(live_ledger.path).ok

    st = ks.state()
    assert st["released_by"] == "ao@agency.mil"
    assert st["release_reason"] == "incident closed"


def test_recovery_preserves_forensics_with_custody_manifest(ks_home, live_ledger,
                                                            baseline_repo):
    ks = ks_home
    tampered = b"security:\n  posture: permissive\n"
    baseline_repo.overlay.write_bytes(tampered)
    ks.engage(reason="drift", actor="isso")
    res = ks.recover(actor="ao", reason="closed", repo_root=baseline_repo.root)
    assert res.ok, res.reason
    ev = ir.evidence_root()
    assert str(ev) in res.evidence_dir
    from pathlib import Path
    d = Path(res.evidence_dir)
    manifest = json.loads((d / "manifest.json").read_text())
    names = {i["name"]: i for i in manifest["items"]}
    assert {"agent-audit.log", "killswitch.state",
            "displaced/cli-config.gov.yaml"} <= set(names)
    displaced = (d / "items" / "displaced" / "cli-config.gov.yaml").read_bytes()
    assert displaced == tampered
    assert names["displaced/cli-config.gov.yaml"]["sha256"] == \
        hashlib.sha256(tampered).hexdigest()
    assert manifest["custody"][0]["by"] == "ao"
    # manifest hash anchored in the ledger
    sha = hashlib.sha256((d / "manifest.json").read_bytes()).hexdigest()
    custody = [a for a in _actions(live_ledger)
               if a[0] == "killswitch.forensics.preserve"]
    assert custody and custody[-1][2]["manifest_sha256"] == sha


def test_recovery_refused_on_broken_chain_and_nothing_restored(
        ks_home, live_ledger, baseline_repo):
    ks = ks_home
    baseline_repo.overlay.write_text("security:\n  posture: permissive\n")
    ks.engage(reason="incident", actor="isso")
    raw = live_ledger.path.read_bytes()
    live_ledger.path.write_bytes(raw.replace(b'"session.start"', b'"session.stop"', 1))
    res = ks.recover(actor="ao", reason="closed", repo_root=baseline_repo.root)
    assert res.ok is False
    assert "audit chain" in res.reason
    assert ks.is_engaged() is True
    assert b"permissive" in baseline_repo.overlay.read_bytes()


def test_recovery_refused_when_enabled_ledger_is_empty(ks_home, tmp_path, monkeypatch,
                                                       baseline_repo):
    led = ga.GovernanceLedger(tmp_path / "logs" / "agent-audit.log")
    monkeypatch.setattr(ga, "get_ledger", lambda: led)
    ks_home.engage(reason="x", actor="isso")
    led.path.unlink(missing_ok=True)
    res = ks_home.recover(actor="ao", reason="closed", repo_root=baseline_repo.root)
    assert res.ok is False and "missing or empty" in res.reason
    assert ks_home.is_engaged() is True


def test_recovery_refused_when_tag_moved(ks_home, live_ledger, baseline_repo):
    ks = ks_home
    (baseline_repo.root / "app.py").write_text("print('moved')\n")
    baseline_repo.git("commit", "-qam", "later")
    baseline_repo.git("tag", "-f", baseline_repo.tag)
    ks.engage(reason="x", actor="isso")
    res = ks.recover(actor="ao", reason="closed", repo_root=baseline_repo.root)
    assert res.ok is False
    assert "tag moved" in res.reason
    assert ks.is_engaged() is True


def test_recovery_refused_when_baseline_itself_drifts(ks_home, live_ledger, tmp_path):
    from tests.governance.conftest import make_baseline_repo
    bad = make_baseline_repo(
        tmp_path / "bad",
        overlay="security:\n  posture: strict\n  redact_secrets: false\n")
    local_edit = "security:\n  posture: strict\n  redact_secrets: true\n# local\n"
    bad.overlay.write_text(local_edit)
    ks_home.engage(reason="x", actor="isso")
    res = ks_home.recover(actor="ao", reason="closed", repo_root=bad.root)
    assert res.ok is False
    assert "security.redact_secrets" in res.reason
    assert ks_home.is_engaged() is True
    # an unfit baseline is never written over the deployment
    assert bad.overlay.read_text() == local_edit


def test_recovery_refused_when_release_cannot_be_recorded(ks_home, live_ledger,
                                                          baseline_repo, monkeypatch):
    ks = ks_home
    ks.engage(reason="x", actor="isso")
    real_emit = live_ledger.emit

    def emit(event, **kw):
        if kw.get("action") == "killswitch.recover" and kw.get("decision") == "allow":
            raise ga.AuditWriteError("disk full")
        return real_emit(event, **kw)

    monkeypatch.setattr(live_ledger, "emit", emit)
    res = ks.recover(actor="ao", reason="closed", repo_root=baseline_repo.root)
    assert res.ok is False
    assert "could not be recorded" in res.reason
    assert ks.is_engaged() is True


def test_operator_override_baseline_is_labelled(ks_home, live_ledger, baseline_repo):
    ks = ks_home
    ks.engage(reason="x", actor="isso")
    res = ks.recover(actor="ao", reason="closed", baseline_tag="HEAD",
                     repo_root=baseline_repo.root)
    assert res.ok, res.reason
    assert res.baseline_source == "operator-override"


def test_bad_baseline_ref_rejected(ks_home, live_ledger, baseline_repo):
    ks_home.engage(reason="x", actor="isso")
    res = ks_home.recover(actor="ao", reason="closed", baseline_tag="--output=/tmp/x",
                          repo_root=baseline_repo.root)
    assert res.ok is False and "invalid baseline ref" in res.reason


def test_recover_requires_actor_and_reason(ks_home):
    with pytest.raises(ValueError):
        ks_home.recover(actor="", reason="x")
    with pytest.raises(ValueError):
        ks_home.recover(actor="ao", reason=" ")
