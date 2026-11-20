"""TC-REQ-12: strict skill policy at real public seams; isolated synthetic skills."""
import ast
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
    loaded = manager._plugins["versioned"].module
    assert loaded is not None and loaded.VERSION == 1
    data.write_text("VERSION = 2\n")
    policy["security"]["plugin_allowlist"] = [_signed_entry("versioned", root, kind="plugin")]
    policy["policy"]["unlisted_disposition"] = "hold"
    manager._load_plugin(manifest)
    reloaded = manager._plugins["versioned"].module
    assert reloaded is not None and reloaded.VERSION == 2


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


def test_bundled_plugins_import_their_own_modules_relative_to_the_loaded_package():
    plugins = Path(__file__).resolve().parents[2] / "plugins"
    absolute_imports = []
    for manifest in plugins.rglob("plugin.yaml"):
        bundle = manifest.parent
        package = ".".join(bundle.relative_to(plugins.parent).parts).replace("-", "_")
        for source in bundle.rglob("*.py"):
            tree = ast.parse(source.read_bytes(), filename=str(source))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module and not node.level:
                    imports = [f"{node.module}.{alias.name}" for alias in node.names]
                elif isinstance(node, ast.Import):
                    imports = [alias.name for alias in node.names]
                else:
                    continue
                if any(name == package or name.startswith(package + ".") for name in imports):
                    absolute_imports.append(f"{source.relative_to(plugins.parent)}:{node.lineno}")
    assert not absolute_imports, absolute_imports


def test_honcho_cli_and_its_client_load_from_the_same_verified_bundle(governed_skills, monkeypatch):
    import sys

    from plugins import memory
    from tools.skill_attestation import verified_directory

    _, policy = governed_skills
    bundle = Path(memory.__file__).parent / "honcho"
    policy["security"]["plugin_allowlist"] = [_signed_entry("memory/honcho", bundle, kind="plugin")]
    monkeypatch.setattr(memory, "_get_active_memory_provider", lambda: "honcho")
    snapshot = verified_directory("plugin", "memory/honcho", bundle)
    [command] = memory.discover_plugin_cli_commands()
    cli = sys.modules[command["setup_fn"].__module__]
    client = sys.modules[cli._host_block.__module__]
    assert cli.__file__ == str(snapshot / "cli.py")
    assert client.__file__ == str(snapshot / "client.py")


def test_registered_signed_provider_remains_in_its_verified_namespace(governed_skills):
    from lliam_cli.plugins import PluginManager, PluginManifest, get_bundled_plugins_dir
    from tools.skill_attestation import verified_directory

    _, policy = governed_skills
    key = "web/firecrawl"
    bundle = get_bundled_plugins_dir() / key
    policy["security"]["plugin_allowlist"] = [_signed_entry(key, bundle, kind="plugin")]
    snapshot = verified_directory("plugin", key, bundle)
    manifest = PluginManifest(name="firecrawl", key=key, path=str(snapshot), source="bundled")
    registered = PluginManager()._load_directory_module(manifest)
    assert registered.__file__ == str(snapshot / "__init__.py")
    assert registered.FirecrawlWebSearchProvider.__module__ == registered.__name__ + ".provider"
    assert registered.__name__ != "plugins.web.firecrawl"


def test_unapproved_meet_refuses_detached_child_before_side_effects(governed_skills, monkeypatch):
    from plugins.google_meet import process_manager

    monkeypatch.setattr(process_manager, "_read_active", lambda: pytest.fail("touched meeting state"))
    monkeypatch.setattr(process_manager.subprocess, "Popen", lambda *a, **kw: pytest.fail("launched a bot"))
    result = process_manager.start("https://meet.google.com/abc-defg-hij")
    assert result["ok"] is False
    assert "attestation" in result["error"]


def test_detached_meet_reverifies_signed_worker_in_fresh_interpreter(governed_skills, tmp_path, monkeypatch):
    import subprocess

    import yaml

    from lliam_cli.verified_meet import bot_command

    _, policy = governed_skills
    bundle = tmp_path / "google_meet"
    bundle.mkdir()
    (bundle / "__init__.py").write_text("", encoding="utf-8")
    (bundle / "meet_bot.py").write_text(
        "def run_bot():\n    print(__file__)\n    return 0\n", encoding="utf-8")
    policy["security"]["plugin_allowlist"] = [_signed_entry("google_meet", bundle, kind="plugin")]
    policy_path = tmp_path / "skill-policy.yaml"
    policy_path.write_text(yaml.safe_dump(policy), encoding="utf-8")
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump({"security": {
        "posture": "strict", "trusted_signers": {_SIGNER: _KEY},
    }}), encoding="utf-8")
    monkeypatch.setenv("LLIAM_HOME", str(tmp_path))
    monkeypatch.setenv("LLIAM_CONFIG", str(config_path))
    monkeypatch.setenv("LLIAM_SKILL_POLICY", str(policy_path))

    command = bot_command(bundle)
    assert command[1] == "-I"
    child = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True, timeout=20, check=True)
    child_file = Path(child.stdout.strip())
    assert child_file.parts[-2:] == ("google_meet", "meet_bot.py")
    assert child_file.parent not in (bundle, Path(command[-2]))

    mismatched = subprocess.run(
        [*command[:-1], "unmatched-fixture-revision"], cwd=tmp_path, capture_output=True, text=True, timeout=20)
    assert mismatched.returncode != 0
    assert "same approved plugin" in mismatched.stderr
