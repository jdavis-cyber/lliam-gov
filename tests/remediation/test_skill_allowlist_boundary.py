"""TC-REQ-12: strict skill policy at real public seams; isolated synthetic skills."""
import json
from pathlib import Path

import pytest


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
    policy = {'policy': {'unlisted_disposition': 'hold'}, 'security': {'skill_allowlist': [{'name': 'approved'}, {'name': 'safe:approved'}]}}
    monkeypatch.setattr('lliam_cli.config.load_config', lambda: {'security': {'posture': 'strict'}})
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
