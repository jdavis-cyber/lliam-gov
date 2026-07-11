"""Agent NPE instance-identity tests (LG-IA-02, P1.4)."""

from __future__ import annotations

from types import SimpleNamespace

import agent.agent_identity as ai


def _agent(provider="bedrock-govcloud", model="claude-x"):
    return SimpleNamespace(provider=provider, model=model,
                           enabled_toolsets=None, disabled_toolsets=None)


def setup_function(_):
    ai.reset_identity_cache()


def test_identity_shape_and_fields():
    ident = ai.compute_instance_identity(_agent(), config={"security": {"posture": "strict"}})
    assert ident["schema"] == "lg-ia/1"
    assert ident["type"] == "npe"
    for k in ("instance_id", "code_hash", "config_hash", "toolset_hash"):
        assert ident[k].startswith("sha256:"), k
    assert ident["model"]["provider"] == "bedrock-govcloud"
    assert ident["model"]["model_hash"].startswith("sha256:")


def test_identity_is_deterministic():
    cfg = {"security": {"posture": "strict"}}
    a = ai.compute_instance_identity(_agent(), config=cfg, use_cache=False)
    b = ai.compute_instance_identity(_agent(), config=cfg, use_cache=False)
    assert a["instance_id"] == b["instance_id"]


def test_model_swap_changes_instance_id():
    cfg = {"security": {"posture": "strict"}}
    a = ai.compute_instance_identity(_agent(model="claude-x"), config=cfg, use_cache=False)
    b = ai.compute_instance_identity(_agent(model="claude-y"), config=cfg, use_cache=False)
    assert a["instance_id"] != b["instance_id"]
    assert a["model"]["model_hash"] != b["model"]["model_hash"]


def test_config_change_changes_instance_id():
    a = ai.compute_instance_identity(_agent(), config={"security": {"posture": "strict"}}, use_cache=False)
    b = ai.compute_instance_identity(_agent(), config={"security": {"posture": "permissive"}}, use_cache=False)
    assert a["instance_id"] != b["instance_id"]
    assert a["config_hash"] != b["config_hash"]


def test_config_hash_does_not_embed_secrets():
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    ident = ai.compute_instance_identity(
        _agent(), config={"providers": {"key": secret}}, use_cache=False
    )
    # The hash is a digest; the point is the derivation path redacts before
    # hashing. Recompute with the secret masked → different input, but the
    # important property is no raw secret is retained anywhere on the object.
    assert secret not in repr(ident)


def test_fail_safe_on_bad_inputs():
    # No agent, no config resolvable here → still returns a well-formed record
    # (unknown markers), never raises.
    ident = ai.compute_instance_identity(config={}, use_cache=False)
    assert ident["instance_id"].startswith("sha256:")


def test_actor_for_agent_uses_real_identity(monkeypatch):
    import agent.governance_audit_hooks as gah
    actor = gah._actor_for_agent(_agent())
    assert actor["type"] == "npe"
    assert actor["instance_id"].startswith("sha256:")  # not None anymore
    assert actor["model"]["provider"] == "bedrock-govcloud"


def test_cached_path_differentiates_toolset_scope():
    """P1.4-review fix: the DEFAULT (cached) path must give different ids to
    two same-model agents with different toolset scopes — the old
    (provider, model) cache returned a stale shared id."""
    a = SimpleNamespace(provider="p", model="m",
                        enabled_toolsets=None, disabled_toolsets=None)
    b = SimpleNamespace(provider="p", model="m",
                        enabled_toolsets=None,
                        disabled_toolsets=["computer_use", "browser"])
    ida = ai.compute_instance_identity(a)          # use_cache=True (default)
    idb = ai.compute_instance_identity(b)          # same model, pruned toolset
    assert ida["toolset_hash"] != idb["toolset_hash"]
    assert ida["instance_id"] != idb["instance_id"]


def test_cached_path_config_change_reflected():
    """config_hash is recomputed each call, so a config change flips the id
    even on the cached path (no stale identity)."""
    a = ai.compute_instance_identity(_agent(), config={"security": {"posture": "strict"}})
    b = ai.compute_instance_identity(_agent(), config={"security": {"posture": "off"}})
    assert a["instance_id"] != b["instance_id"]


def test_code_hash_covers_enforcement_modules():
    # The redaction boundary + policy gates are part of the identity surface.
    assert "agent/redact.py" in ai._CODE_SURFACE
    assert "tools/tool_policy.py" in ai._CODE_SURFACE
