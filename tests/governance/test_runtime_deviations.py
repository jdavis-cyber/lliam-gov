"""SR-14 on startup, effective config reload and provider routing. No live providers."""
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from lliam_cli import config, deviations, provider_allowlist, startup_posture
from agent import governance_audit

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    overlay = tmp_path / "cli-config.gov.yaml"
    overlay.write_bytes((ROOT / overlay.name).read_bytes())
    managed = tmp_path / "operator"
    managed.mkdir()
    monkeypatch.setenv("LLIAM_CONFIG", str(overlay))
    monkeypatch.setenv("LLIAM_HOME", str(tmp_path / "profile"))
    monkeypatch.setenv("LLIAM_MANAGED_DIR", str(managed))
    monkeypatch.setattr(deviations, "_check_managed_ownership", lambda path: None)
    monkeypatch.setattr(deviations, "_runtime_started", False)
    monkeypatch.setattr(deviations, "_recorded", set())
    monkeypatch.setattr(startup_posture, "_STARTUP_POSTURE_ENFORCED", False)
    for name in ("emit_agent_identity_at_startup", "enforce_control_plane_auth_at_startup",
                 "enforce_model_integrity_at_startup", "enforce_provider_allowlist_at_startup",
                 "enforce_governance_artifacts_at_startup", "verify_audit_chain_at_startup"):
        monkeypatch.setattr(startup_posture._sas, name, lambda **kwargs: None)
    return overlay, managed / "deviation-register.yaml"


def set_config(path, section, key, value):
    content = yaml.safe_load(path.read_bytes())
    content[section][key] = value
    path.write_text(yaml.safe_dump(content))


@pytest.mark.parametrize(("section", "key", "value"), [
    ("agent", "disabled_toolsets", ["computer_use"]),
    ("security", "allowed_providers", ["ollama", "fixture-model"]),
    ("terminal", "container_cpu", 4),
])
def test_workload_start_refuses_unregistered_expansions(deployment, section, key, value):
    overlay, _ = deployment
    set_config(overlay, section, key, value)
    with pytest.raises(deviations.DeviationError):
        startup_posture.enforce_startup_posture()


def test_runtime_reload_rechecks_register_scope_and_expiry(deployment, monkeypatch):
    overlay, register = deployment
    startup_posture.enforce_startup_posture()
    set_config(overlay, "terminal", "container_cpu", 4)
    row = dict(id="fixture", status="approved", key="terminal.container_cpu", profile=deviations._scope(),
               justification="isolated test", approver=deviations._baseline()["approvers"][0],
               expiry=str(date.today() + timedelta(days=2)), **{"from": 2, "to": 4})
    receipts = []
    monkeypatch.setattr(governance_audit, "record_policy_exception", lambda *args, **kw: receipts.append(args))
    for bad in ({"to": 3}, {"from": 1}, {"profile": "someone-else"}, {"status": "revoked"}, {"status": None},
                {"expiry": "2000-01-01"}, {"approver": "unrelated"}, {"to": True}):
        register.write_text(yaml.safe_dump({"deviations": [{**row, **bad}]}))
        with pytest.raises(deviations.DeviationError):
            config.load_config_readonly()
    register.write_text(yaml.safe_dump({"deviations": [row]}))
    assert config.load_config()["terminal"]["container_cpu"] == 4
    assert len(receipts) == 1 and receipts[0][:2] == ("deviation", "fixture")
    register.write_text(yaml.safe_dump({"deviations": []}))
    with pytest.raises(deviations.DeviationError):
        config.load_config()


def test_runtime_route_requires_approval_even_when_endpoint_policy_lists_provider(deployment, monkeypatch):
    monkeypatch.setattr(provider_allowlist, "_load_policy", lambda: {"providers": [
        {"id": "fixture-model", "base_url_hosts": ["local.invalid"]},
    ]})
    result = provider_allowlist.validate_provider("fixture-model", "https://local.invalid")
    assert result.disposition == "deny"
    assert "governed provider list" in result.reason


def test_tighter_cpu_limit_needs_no_deviation_and_keeps_profile_tool_floor(deployment, monkeypatch):
    import model_tools

    overlay, _ = deployment
    set_config(overlay, "terminal", "container_cpu", 1)
    startup_posture.enforce_startup_posture()
    observed = []
    monkeypatch.setattr(model_tools, "_compute_tool_definitions", lambda enabled, disabled, *a, **kw: observed.append(disabled) or [])
    model_tools.get_tool_definitions(enabled_toolsets=["file"], disabled_toolsets=["web"])
    assert observed == [["browser", "computer_use", "web"]]


def test_missing_ledger_receipt_blocks_even_a_matching_record(deployment, monkeypatch):
    overlay, register = deployment
    set_config(overlay, "terminal", "container_cpu", 4)
    row = dict(id="fixture", status="approved", key="terminal.container_cpu", profile=deviations._scope(),
               justification="isolated test", approver=deviations._baseline()["approvers"][0],
               expiry=str(date.today() + timedelta(days=2)), **{"from": 2, "to": 4})
    register.write_text(yaml.safe_dump({"deviations": [row]}))

    def unavailable(*args, **kwargs):
        raise governance_audit.AuditWriteError("offline")

    monkeypatch.setattr(governance_audit, "record_policy_exception", unavailable)
    with pytest.raises(deviations.DeviationError):
        startup_posture.enforce_startup_posture()
    assert not deviations._recorded


def test_register_in_user_writable_directory_has_no_authority(tmp_path):
    register = tmp_path / "deviation-register.yaml"
    register.write_text("deviations: []")
    register.chmod(0o666)
    with pytest.raises(deviations.DeviationError, match="administrator"):
        deviations._check_managed_ownership(register)


def test_replacement_checkout_pin_requires_a_matching_release(tmp_path, monkeypatch):
    monkeypatch.setattr(deviations, "_ROOT", tmp_path)
    record = tmp_path / deviations.incident_recovery.AUTH_RECORD
    record.parent.mkdir(parents=True)
    record.write_text("baseline: {git_commit: fixture}\n")
    deviations._baseline.cache_clear()
    try:
        with pytest.raises(deviations.DeviationError, match="shipped release"):
            deviations._baseline()
    finally:
        deviations._baseline.cache_clear()


@pytest.mark.parametrize("key", [
    "security.spend_ceiling.per_session_tokens", "security.max_mutating_calls.per_turn",
    "security.data_protection.result_retention_ttl_seconds", "security.schema_validation.max_schema_bytes",
    "memory.governance.retention_ttl_seconds",
])
def test_positive_tighter_numeric_ceiling_allowed_and_widening_blocked(deployment, key):
    overlay, _ = deployment
    baseline = deviations._baseline()["settings"][key]
    config_doc = yaml.safe_load(overlay.read_bytes())
    config_section = config_doc
    *parents, leaf = key.split(".")
    for parent in parents:
        config_section = config_section[parent]
    config_section[leaf] = baseline - 1
    overlay.write_text(yaml.safe_dump(config_doc))
    startup_posture.enforce_startup_posture()
    config_section[leaf] = baseline + 1
    overlay.write_text(yaml.safe_dump(config_doc))
    with pytest.raises(deviations.DeviationError):
        config.load_config()


def test_tightened_provider_list_applies_to_every_route(deployment):
    overlay, _ = deployment
    set_config(overlay, "security", "allowed_providers", ["ollama"])
    result = provider_allowlist.validate_provider("lmstudio", "http://localhost")
    assert result.disposition == "deny"
    assert "governed provider list" in result.reason


def test_new_provider_requires_both_provider_and_host_approvals(deployment, monkeypatch):
    overlay, register = deployment
    base = deviations._baseline()
    before = sorted(base["security.allowed_providers"])
    after = sorted([*before, "fixture-model"])
    set_config(overlay, "security", "allowed_providers", after)
    monkeypatch.setattr(provider_allowlist, "_load_policy", lambda: {"providers": [
        {"id": "fixture-model", "base_url_hosts": ["local.invalid", "other.invalid"]},
    ]})
    common = dict(status="approved", profile=deviations._scope(), justification="isolated test",
                  approver=base["approvers"][0], expiry=str(date.today() + timedelta(days=2)))
    provider_grant = {**common, "id": "provider", "key": "security.allowed_providers", "from": before, "to": after}
    host_grant = {**common, "id": "host", "key": "provider.fixture-model.hosts", "from": [], "to": ["local.invalid"]}
    monkeypatch.setattr(governance_audit, "record_policy_exception", lambda *args, **kwargs: None)
    register.write_text(yaml.safe_dump({"deviations": [provider_grant]}))
    assert provider_allowlist.validate_provider("fixture-model", "https://local.invalid").disposition == "deny"
    register.write_text(yaml.safe_dump({"deviations": [provider_grant, host_grant]}))
    assert provider_allowlist.validate_provider("fixture-model", "https://local.invalid").disposition == "allow"
    assert provider_allowlist.validate_provider("fixture-model", "https://other.invalid").disposition == "deny"


def test_dashboard_profiles_keep_independent_governed_activation(deployment, tmp_path, monkeypatch):
    import asyncio

    from lliam_cli import web_server

    overlay, _ = deployment
    home = tmp_path / "profile"
    governed = home / "profiles" / "governed"
    low = home / "profiles" / "ordinary"
    governed.mkdir(parents=True)
    low.mkdir()
    (governed / "config.yaml").write_bytes(overlay.read_bytes())
    (low / "config.yaml").write_text("security: {posture: permissive}\n")
    monkeypatch.delenv("LLIAM_CONFIG", raising=False)
    monkeypatch.delenv("HERMES_CONFIG", raising=False)

    # Dashboard starts under its own low-side home, then serves both profiles.
    startup_posture.enforce_startup_posture()
    with web_server._config_profile_scope("governed"):
        assert "browser" in deviations.governed_disabled_toolsets()
        assert config.load_config_readonly()["security"]["posture"] == "strict"
    with web_server._profile_scope("ordinary"):
        assert config.load_config()["security"]["posture"] == "permissive"
        assert not deviations.governed_disabled_toolsets()
        assert provider_allowlist.validate_provider("fixture", "https://local.invalid").disposition == "allow"

    toggle = web_server.ToolsetToggle(profile="ordinary", enabled=False)
    assert asyncio.run(web_server.toggle_toolset("browser", toggle))["ok"]
    assert "browser" not in yaml.safe_load((low / "config.yaml").read_bytes())["platform_toolsets"]["cli"]

    # An alias of the original home retains the sticky floor after removing governance.
    (governed / "config.yaml").write_bytes((low / "config.yaml").read_bytes())
    with monkeypatch.context() as scoped:
        scoped.setenv("LLIAM_HOME", str(low / ".." / "governed"))
        for load in (config.load_config, config.load_config_readonly, deviations.governed_disabled_toolsets):
            with pytest.raises(deviations.DeviationError):
                load()
        assert provider_allowlist.validate_provider("fixture", "https://local.invalid").disposition == "deny"
    with web_server._config_profile_scope("ordinary"):
        assert config.load_config_readonly()["security"]["posture"] == "permissive"
