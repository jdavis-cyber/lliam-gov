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
