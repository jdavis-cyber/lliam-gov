"""TC-REQ-12: strict skill policy at real public seams; isolated synthetic skills."""
import json
import hashlib
from pathlib import Path

import pytest


_SIGNER = "fixture-authority"
_KEY = "ephemeral-test-key"


def _signed_entry(name, path, kind="skill"):
    from agent.attestation import compute_signature
    record = {
        "kind": kind, "name": name, "source": "synthetic supplier",
        "sdl_record": "test-SDL-01", "approver": "test owner", "expires": "2099-01-01",
        "files": {f.relative_to(path).as_posix(): "sha256:" + hashlib.sha256(f.read_bytes()).hexdigest()
                  for f in path.rglob("*") if f.is_file() and "__pycache__" not in f.parts},
    }
    return {**record, "signature": compute_signature(record, _KEY), "signer": _SIGNER}


@pytest.fixture
def governed_skills(tmp_path, monkeypatch):
    from tools import skills_tool as st, tool_policy as tp
    from agent import skill_utils as su
    root = tmp_path / 'skills'
    for dirname, name in [('approved-alias', 'approved'), ('unlisted-alias', 'unlisted')]:
        folder = root / dirname
        folder.mkdir(parents=True)
        (folder / 'SKILL.md').write_text(f'---\nname: {name}\ndescription: synthetic safe skill\n---\nSYNTHETIC CONTENT\n')
        (folder / 'references').mkdir()
        (folder / 'references/data.txt').write_text('synthetic linked content')
    policy = {"policy": {"unlisted_disposition": "hold"}, "security": {
        "trusted_signers": [_SIGNER],
        "skill_allowlist": [_signed_entry(name, root / "approved-alias")
                            for name in ("approved", "safe:approved")],
    }}
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: {
        "security": {"posture": "strict", "trusted_signers": {_SIGNER: _KEY}}})
    monkeypatch.setattr(tp, 'load_skill_policy', lambda: policy)
    monkeypatch.setattr(st, 'SKILLS_DIR', root)
    monkeypatch.setattr(su, 'get_external_skills_dirs', lambda: [])
    tp._TAG_SCAN_CACHE.clear()
    return root, policy


@pytest.mark.parametrize('name,file', [('unlisted', None), ('unlisted-alias', None), ('unlisted-alias', 'references/data.txt')])
def test_hold_blocks_explicit_and_alias_and_linked_load(governed_skills, name, file):
    from tools.skills_tool import skill_view
    result = json.loads(skill_view(name, file_path=file, preprocess=False))
    assert result['success'] is False
    assert 'held' in result['error'].lower()


def test_catalog_hides_hold_preserves_approved_and_admin_inventory(governed_skills):
    from tools.skills_tool import _find_all_skills
    assert {x['name'] for x in _find_all_skills()} == {'approved'}
    assert {x['name'] for x in _find_all_skills(skip_disabled=True)} == {'approved', 'unlisted'}


def test_slash_registration_and_preload_hold(governed_skills):
    from agent.skill_commands import scan_skill_commands, _load_skill_payload
    assert '/unlisted' not in scan_skill_commands()
    assert '/approved' in scan_skill_commands()
    assert _load_skill_payload('unlisted') is None


def test_prompt_cache_rechecks_hold_activation(governed_skills, monkeypatch):
    from agent import prompt_builder as pb
    root, policy = governed_skills
    monkeypatch.setattr(pb, 'get_skills_dir', lambda: root)
    monkeypatch.setattr(pb, 'get_all_skills_dirs', lambda: [root])
    policy['policy']['unlisted_disposition'] = 'log'
    assert 'unlisted' in pb.build_skills_system_prompt()
    policy['policy']['unlisted_disposition'] = 'hold'
    assert 'unlisted' not in pb.build_skills_system_prompt()
    assert 'approved' in pb.build_skills_system_prompt()


def test_plugin_qualified_load_is_held_before_preprocessing(governed_skills, monkeypatch):
    from tools.skills_tool import _serve_plugin_skill
    from lliam_cli import plugins
    root, _ = governed_skills
    monkeypatch.setattr(plugins, '_get_disabled_plugins', lambda: set())
    result = json.loads(_serve_plugin_skill(root / 'unlisted-alias/SKILL.md', 'safe', 'unlisted', preprocess=False))
    assert result['success'] is False
    assert 'held' in result['error'].lower()


def test_approved_load_still_served(governed_skills):
    from tools.skills_tool import skill_view
    assert json.loads(skill_view('approved', preprocess=False))['success'] is True


def test_empty_hold_allowlist_does_not_allow_all(governed_skills):
    from tools.skills_tool import skill_view
    _, policy = governed_skills
    policy['security']['skill_allowlist'] = []
    assert json.loads(skill_view('approved', preprocess=False))['success'] is False


def test_hold_never_runs_inline_shell_preprocessing(governed_skills, monkeypatch):
    from tools.skills_tool import skill_view
    calls = []
    monkeypatch.setattr('agent.skill_preprocessing.preprocess_skill_content', lambda *a, **k: calls.append(a))
    assert json.loads(skill_view('unlisted'))['success'] is False
    assert calls == []


def test_log_mode_preserves_unlisted_capability_until_curation(governed_skills):
    from tools.skills_tool import skill_view
    _, policy = governed_skills
    policy['policy']['unlisted_disposition'] = 'log'
    assert json.loads(skill_view('unlisted', preprocess=False))['success'] is True


def test_low_side_does_not_activate_strict_hold(governed_skills, monkeypatch):
    from tools.skills_tool import skill_view
    monkeypatch.setattr('lliam_cli.config.load_config', lambda: {'security': {'posture': 'low-side'}})
    assert json.loads(skill_view('unlisted', preprocess=False))['success'] is True


def test_qualified_never_eligible_cannot_be_allowlisted(governed_skills):
    from tools.tool_policy import skill_load_decision
    _, policy = governed_skills
    policy['security']['skill_allowlist'].append({'name': 'safe:godmode'})
    assert skill_load_decision('safe:godmode', meta={'name': 'godmode'})[0] == 'deny'

@pytest.mark.parametrize("fault", ["signature", "source", "changed-reference", "audit-error"])
def test_signed_skill_refused_before_use_on_trust_fault(governed_skills, fault):
    from tools.skills_tool import skill_view

    root, policy = governed_skills
    folder = root / "approved-alias"
    record = policy["security"]["skill_allowlist"][0]
    if fault == "signature":
        record.pop("signature")
    elif fault == "source":
        record["source"] = "different supplier"
    elif fault == "audit-error":
        (folder / "helper.py").write_text("def invalid(")
        policy["security"]["skill_allowlist"][0] = _signed_entry("approved", folder)
    else:
        (folder / "references/data.txt").write_text("changed synthetic content")
    assert not json.loads(skill_view("approved", file_path="references/data.txt", preprocess=False))["success"]


def test_signed_plugin_checked_before_initialization(governed_skills, tmp_path):
    from lliam_cli.plugins import PluginManager, PluginManifest
    _, policy = governed_skills
    root = tmp_path / "sample"
    root.mkdir()
    code = root / "__init__.py"
    code.write_text("def register(context):\n    pass\n")
    manifest = PluginManifest(name="sample", source="user", path=str(root))
    manager = PluginManager()
    manager._load_plugin(manifest)
    assert not manager._plugins["sample"].enabled
    policy["security"]["plugin_allowlist"] = [_signed_entry("sample", root, kind="plugin")]
    manager._load_plugin(manifest)
    assert manager._plugins["sample"].enabled
    code.write_text("# updated synthetic fixture\n")
    manager._load_plugin(manifest)
    assert not manager._plugins["sample"].enabled

def test_unreadable_skill_policy_holds_and_records_load(governed_skills, monkeypatch, tmp_path):
    from agent import governance_audit as audit
    from tools import tool_policy
    from tools.skills_tool import skill_view

    ledger = audit.GovernanceLedger(tmp_path / "ledger.jsonl")
    monkeypatch.setattr(audit, "get_ledger", lambda: ledger)
    monkeypatch.setattr(tool_policy, "load_skill_policy", lambda: {})
    assert not json.loads(skill_view("approved", preprocess=False))["success"]
    assert any(row["action"] == "skill.load" and row["decision"] == "deny"
               for row in audit.iter_records(ledger.path))


def test_signed_skill_only_exposes_the_approved_files(governed_skills):
    from tools.skills_tool import skill_view

    root, _ = governed_skills
    (root / "approved-alias" / "extra.txt").write_text("unsigned synthetic content")
    result = json.loads(skill_view("approved", file_path="extra.txt", preprocess=False))
    assert not result["success"]
    assert json.loads(skill_view("approved", file_path="references/data.txt",
                                 preprocess=False))["content"] == "synthetic linked content"


def test_signed_plugin_reloads_relative_import_from_approved_version(governed_skills, tmp_path):
    from lliam_cli.plugins import PluginManager, PluginManifest

    _, policy = governed_skills
    root = tmp_path / "versioned"
    root.mkdir()
    (root / "__init__.py").write_text(
        "from .data import VERSION\ndef register(context):\n    pass\n")
    data = root / "data.py"
    data.write_text("VERSION = 1\n")
    manifest = PluginManifest(name="versioned", source="user", path=str(root))
    manager = PluginManager()
    policy["policy"]["unlisted_disposition"] = "log"
    manager._load_plugin(manifest)
    assert manager._plugins["versioned"].module.VERSION == 1
    data.write_text("VERSION = 2\n")
    policy["security"]["plugin_allowlist"] = [_signed_entry("versioned", root, kind="plugin")]
    policy["policy"]["unlisted_disposition"] = "hold"
    manager._load_plugin(manifest)
    assert manager._plugins["versioned"].module.VERSION == 2


def test_changed_cached_snapshot_is_refused(governed_skills):
    from tools.skill_attestation import verified_directory

    root, _ = governed_skills
    snapshot = verified_directory("skill", "approved", root / "approved-alias")
    file = snapshot / "references/data.txt"
    original = file.read_bytes()
    file.chmod(0o600)
    try:
        file.write_text("changed synthetic content")
        with pytest.raises(PermissionError):
            verified_directory("skill", "approved", root / "approved-alias")
    finally:
        file.write_bytes(original)
        file.chmod(0o400)


def test_discovery_uses_signed_plugin_descriptor(governed_skills, tmp_path):
    from lliam_cli.plugins import PluginManager

    _, policy = governed_skills
    root = tmp_path / "described"
    root.mkdir()
    (root / "__init__.py").write_text("def register(context):\n    pass\n")
    code_only = _signed_entry("described", root, kind="plugin")
    (root / "plugin.yaml").write_text("name: described\nkind: standalone\n")
    policy["security"]["plugin_allowlist"] = [code_only]
    manager = PluginManager()
    assert manager._scan_directory(tmp_path, "user") == []
    policy["security"]["plugin_allowlist"] = [_signed_entry("described", root, kind="plugin")]
    assert [m.key for m in manager._scan_directory(tmp_path, "user")] == ["described"]
