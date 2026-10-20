"""Installer launchers must retain the chosen home outside a login shell."""
import json
import os
import re
import shlex
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize('override', [None, 'HERMES_HOME', 'LLIAM_HOME'])
def test_generated_launcher_pins_selected_home(tmp_path, override):
    chosen = tmp_path / "data with spaces and ' quote $dollar"
    entry = tmp_path / 'lliam-gov-entry'
    entry.write_text('#!/bin/sh\nprintf "%s\\n%s\\n" "$HERMES_HOME" "$LLIAM_HOME"\n')
    entry.chmod(0o755)
    bin_dir = tmp_path / 'bin'
    text = (REPO_ROOT / 'scripts/install.sh').read_text()
    block = re.search(r'mkdir -p "\$command_link_dir".*?chmod \+x "\$command_link_dir/lliam-gov"', text, re.S)[0]
    script = '\n'.join([
        'set -eu',
        'HERMES_BIN=' + shlex.quote(str(entry)),
        'HERMES_HOME=' + shlex.quote(str(chosen)),
        'command_link_dir=' + shlex.quote(str(bin_dir)),
        'write_shim() {', block, '}', 'write_shim',
    ])
    subprocess.run(['bash', '-c', script], check=True, capture_output=True)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(tmp_path)}
    expected = str(chosen)
    if override:
        expected = str(tmp_path / 'override home')
        env[override] = expected
    result = subprocess.run([str(bin_dir / 'lliam-gov')], env=env, text=True, capture_output=True, check=True)
    assert result.stdout.splitlines() == [expected, expected]


def test_explicit_installer_home_wins_over_inherited_new_name(tmp_path):
    selected = tmp_path / 'selected'
    env = {**os.environ, 'LLIAM_HOME': str(tmp_path / 'wrong'), 'HOME': str(tmp_path)}
    result = subprocess.run([
        'bash', str(REPO_ROOT / 'scripts/install.sh'), '--manifest', '--lliam-home', str(selected)
    ], env=env, text=True, capture_output=True, check=True)
    assert json.loads(result.stdout.splitlines()[-1])['protocol_version'] == 1


def test_fresh_installer_uses_canonical_home_and_reuses_legacy(tmp_path):
    # The real config stage must agree with CLI defaults before any override.
    env = {**os.environ, 'HOME': str(tmp_path)}
    env.pop('HERMES_HOME', None)
    env.pop('LLIAM_HOME', None)
    for leaf in ['.lliam', '.hermes']:
        if leaf == '.hermes':
            (tmp_path / leaf).mkdir()
        result = subprocess.run([
            'bash', str(REPO_ROOT / 'scripts/install.sh'), '--stage', 'config',
            '--dir', str(REPO_ROOT), '--non-interactive', '--json', '--no-skills',
        ], env=env, text=True, capture_output=True, timeout=30, check=True)
        assert json.loads(result.stdout.splitlines()[-1])['ok']
        assert (tmp_path / leaf / 'config.yaml').is_file()


def test_installer_node_floor_matches_root_engine():
    text = (REPO_ROOT / 'scripts/install.sh').read_text()
    function = re.search(r'node_satisfies_build\(\) \{.*?\n\}', text, re.S)[0]
    engine = json.loads((REPO_ROOT / 'package.json').read_text())['engines']['node']
    major, minor, patch = map(int, engine.removeprefix('>=').split('.'))
    cases = [(f'v{major - 1}.99.0', False), (f'v{major}.{minor - 1}.0', False),
             (f'v{major}.{minor}.{patch}', True), (f'v{major + 2}.0.0', True)]
    for version, accepted in cases:
        result = subprocess.run(['bash', '-c', function + '\nnode_satisfies_build ' + shlex.quote(version)])
        assert (result.returncode == 0) == accepted
