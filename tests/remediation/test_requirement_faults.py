"""2026-10 requirement cases. Synthetic fixtures; no inference/network calls.

Fail-closed expectations come from BRD NSR-01 and DESIGN G4. Failing
assertions intentionally remain visible as current defects, not xfails.
"""
import os
from pathlib import Path

import pytest


def unavailable_config(*args, **kwargs):
    raise OSError("synthetic configuration read failure")


@pytest.mark.parametrize("routing_path", ["primary", "fallback", "moa", "auxiliary", "delegation"])
def test_sr01_provider_config_failure_blocks_unapproved_route(monkeypatch, routing_path):
    """TC-REQ-01: after strict validation, unreadable config must not allow CUI."""
    from lliam_cli import provider_allowlist as pa
    strict = {"security": {"posture": "strict", "provider_allowlist_enforce": True}}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: strict)
    pa.reset_provider_allowlist_cache()
    assert pa.validate_provider("unapproved-test", "https://outside.invalid", path=routing_path, cui=True).disposition == "deny"
    monkeypatch.setattr("lliam_cli.config.load_config", unavailable_config)
    assert pa.validate_provider("unapproved-test", "https://outside.invalid", path=routing_path, cui=True).disposition != "allow"


def test_sr04_config_failure_does_not_allow_hardline_command(monkeypatch):
    """TC-REQ-02: policy evaluation only; the command string is never executed."""
    from tools import tool_policy as tp
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: {"security": {"posture": "strict"}})
    tp.reset_pdp_state()
    assert not tp.evaluate_call("terminal", {"command": "rm -rf /"}).allows_execution
    monkeypatch.setattr("lliam_cli.config.load_config", unavailable_config)
    assert not tp.evaluate_call("terminal", {"command": "rm -rf /"}).allows_execution


def test_sr03_tainted_session_stays_blocked_on_config_failure(monkeypatch):
    """TC-REQ-03: taint persists; synthetic marker is not real restricted data."""
    from agent import data_protection as dp
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: {"security": {"posture": "strict"}})
    dp.reset_dp_state()
    try:
        dp.note_cui_exposure("read_file", "CUI\nSYNTHETIC TEST ONLY\nCUI")
        assert dp.dlp_egress_decision("https://outside.invalid", allowlist=[]).blocked
        monkeypatch.setattr("lliam_cli.config.load_config", unavailable_config)
        assert dp.session_cui_tainted()
        assert dp.dlp_egress_decision("https://outside.invalid", allowlist=[]).blocked
    finally:
        dp.reset_dp_state()


def test_sr20_encrypted_data_rejects_corruption_and_key_is_private(tmp_path, monkeypatch):
    """TC-REQ-04: real local crypto, persisted key and bytes in temp fixture."""
    from agent import data_protection as dp
    from cryptography.fernet import InvalidToken
    key = tmp_path / "keys" / "at-rest.key"
    monkeypatch.setenv("LLIAM_AT_REST_KEYFILE", str(key))
    payload = b"synthetic audit payload"
    token = dp.encrypt_at_rest(payload)
    assert dp.decrypt_at_rest(token) == payload
    assert payload not in token
    assert key.stat().st_mode & 0o777 == 0o600
    before = key.read_bytes()
    dp.encrypt_at_rest(b"second synthetic payload")
    assert key.read_bytes() == before
    damaged = token[:-8] + b"AAAAAAAA"
    with pytest.raises(InvalidToken):
        dp.decrypt_at_rest(damaged)


def test_sr07_safe_root_symlink_cannot_reach_credential_store(tmp_path, monkeypatch):
    """TC-REQ-05: real symlink resolution; no credential writes occur."""
    from agent import file_safety as fs
    fixture_home = tmp_path / "fixture-home"
    safe = fixture_home / "work"
    keys = fixture_home / ".ssh"
    safe.mkdir(parents=True)
    keys.mkdir()
    (safe / "alias").symlink_to(keys, target_is_directory=True)
    monkeypatch.setattr(Path, "home", lambda: fixture_home)
    monkeypatch.setattr(os.path, "expanduser", lambda p: str(fixture_home) + p[1:] if p.startswith("~") else p)
    monkeypatch.setenv("LLIAM_WRITE_SAFE_ROOT", str(safe))
    monkeypatch.setenv("HERMES_WRITE_SAFE_ROOT", str(safe))
    assert fs.is_write_denied(str(safe / "alias" / "id_ed25519"))
    assert not fs.is_write_denied(str(safe / "ordinary.txt"))


def test_sr02_injection_dispatch_with_explicit_dns_double(tmp_path, monkeypatch):
    """TC-REQ-06: existing dispatch scenario, synthetic public DNS + handler.

    Tests the real dispatch/PDP/taint funnel; does not validate live DNS,
    web fetching, model behavior, or real network egress.
    """
    import importlib.util
    import socket
    source = Path(__file__).parents[1] / "tools" / "test_injection_defense.py"
    spec = importlib.util.spec_from_file_location("requirement_injection_scenario", source)
    scenario = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scenario)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
    ])
    scenario.test_fetched_injection_page_then_egress_blocked_e2e(tmp_path, monkeypatch)


def test_sr06_unknown_skill_is_denied_by_default(monkeypatch):
    """TC-REQ-07: BRD SR-06 says skills load only from approved allowlist.

    Uses repository policy, not an invented allowlist; no plugin code loads.
    """
    from tools import tool_policy as tp
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: {"security": {"posture": "strict"}})
    tp.reset_pdp_state()
    decision, reason = tp.skill_load_decision("synthetic-unapproved-requirement-skill", meta={"name": "synthetic-unapproved-requirement-skill"})
    assert decision in {"deny", "hold"}, reason
