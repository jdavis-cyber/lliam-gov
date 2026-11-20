"""Approved config-error regression coverage; no network or command execution."""
import pytest


def unavailable_config(*args, **kwargs):
    raise OSError("synthetic configuration read failure")


@pytest.mark.parametrize("routing_path", ["primary", "fallback", "moa", "auxiliary", "delegation"])
def test_provider_config_failure_denies_even_a_normally_approved_route(monkeypatch, routing_path):
    from lliam_cli import provider_allowlist as pa
    monkeypatch.setattr("lliam_cli.config.load_config", unavailable_config)
    assert pa.enforcement_enabled()
    decision = pa.validate_provider("lmstudio", "http://127.0.0.1:1234/v1", path=routing_path, cui=True)
    assert decision.disposition == "deny"
    assert "config" in decision.reason.lower()


@pytest.mark.parametrize("command", ["rm -rf /", "ls -la"])
def test_pdp_dispatch_seam_blocks_calls_when_config_cannot_be_read(monkeypatch, command):
    from tools import tool_policy as tp
    monkeypatch.setattr("lliam_cli.config.load_config", unavailable_config)
    decision = tp.pdp_gate("terminal", {"command": command})
    assert decision is not None and decision.should_halt
    assert "config" in decision.message.lower()


def test_tainted_session_cannot_use_allowlisted_sink_without_readable_config(monkeypatch):
    from agent import data_protection as dp
    strict = {"security": {"posture": "strict", "data_protection": {"egress_allowlist": ["approved.invalid"]}}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: strict)
    dp.reset_dp_state()
    try:
        dp.note_cui_exposure("read_file", "CUI\nSYNTHETIC TEST ONLY\nCUI", session_id="fault-session")
        assert not dp.dlp_egress_decision("https://approved.invalid", session_id="fault-session").blocked
        monkeypatch.setattr("lliam_cli.config.load_config", unavailable_config)
        assert dp.dlp_egress_decision("https://approved.invalid", allowlist=["approved.invalid"], session_id="fault-session").blocked
        assert dp.session_cui_tainted(session_id="fault-session")
        assert not dp.session_cui_tainted(session_id="other-session")
    finally:
        dp.reset_dp_state()


@pytest.mark.parametrize("strict", [False, True])
def test_readable_disabled_provider_enforcement_remains_a_noop(monkeypatch, strict):
    from lliam_cli import provider_allowlist as pa
    cfg = {"security": {"posture": "strict" if strict else "", "provider_allowlist_enforce": False}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: cfg)
    assert not pa.enforcement_enabled()
    assert pa.validate_provider("synthetic-unapproved", "https://outside.invalid", cui=True).disposition == "allow"


def test_readable_low_side_pdp_stays_permissive(monkeypatch):
    from tools import tool_policy as tp
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: {"security": {}})
    assert tp.evaluate_call("read_file", {"path": "synthetic.txt"}).allows_execution
    assert tp.pdp_gate("read_file", {"path": "synthetic.txt"}) is None


@pytest.mark.parametrize("contents", [None, "security: [", "[]", ""])
def test_selected_overlay_required_for_startup(tmp_path, monkeypatch, contents):
    from lliam_cli import startup_posture

    overlay = tmp_path / "governed.yaml"
    if contents is not None:
        overlay.write_text(contents, encoding="utf-8")
    monkeypatch.setenv("LLIAM_CONFIG", str(overlay))
    monkeypatch.setattr(startup_posture, "_STARTUP_POSTURE_ENFORCED", False)
    with pytest.raises(SystemExit) as refused:
        startup_posture.enforce_startup_posture_or_exit("test")
    assert refused.value.code == startup_posture.STARTUP_POSTURE_EXIT_CODE


@pytest.mark.parametrize("same_as_home", [False, True])
def test_governance_overlay_pins_posture_above_managed_scope(tmp_path, monkeypatch, same_as_home):
    from lliam_cli import config, managed_scope

    managed = tmp_path / "managed"
    managed.mkdir()
    (managed / "config.yaml").write_text("security:\n  posture: low\n", encoding="utf-8")
    monkeypatch.setenv("LLIAM_HOME", str(tmp_path))
    overlay = tmp_path / ("config.yaml" if same_as_home else "governed.yaml")
    overlay.write_text("security:\n  posture: strict\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_MANAGED_DIR", str(managed))
    monkeypatch.setenv("LLIAM_CONFIG", str(overlay))
    managed_scope.invalidate_managed_cache()
    assert config.load_config()["security"]["posture"] == "strict"


def test_oversight_requires_authenticated_approver_on_config_fault(monkeypatch):
    from tools import hitl_oversight as hitl

    monkeypatch.setattr("lliam_cli.config.load_config", unavailable_config)
    assert hitl.strict_fail_closed()
    assert hitl.require_authenticated_approver()
