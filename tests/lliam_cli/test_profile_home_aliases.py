"""The new and legacy home names must agree after CLI profile selection."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize('mode', ['explicit', 'sticky', 'inherited', 'modern_only'])
def test_profile_startup_scopes_home_config_and_dotenv(tmp_path, mode):
    root = tmp_path / 'data'
    selected = root / 'profiles' / 'reviewer'
    selected.mkdir(parents=True)
    other = root / 'profiles' / 'other'
    other.mkdir()
    for home, marker in [(root, 'root'), (selected, 'reviewer'), (other, 'other')]:
        (home / 'config.yaml').write_text(f'timezone: {marker}\n', encoding="utf-8")
        (home / '.env').write_text(f'PROFILE_HOME_SENTINEL={marker}\n', encoding="utf-8")
    (root / 'active_profile').write_text('other' if mode in ['inherited', 'modern_only'] else 'reviewer', encoding="utf-8")
    env = {**os.environ, 'HOME': str(tmp_path), 'HERMES_HOME': str(root), 'LLIAM_HOME': str(root)}
    argv = ['lliam-gov']
    if mode == 'explicit':
        argv += ['--profile', 'reviewer']
    if mode == 'inherited':
        env['HERMES_HOME'] = env['LLIAM_HOME'] = str(selected)
    if mode == 'modern_only':
        env['LLIAM_HOME'] = str(selected)
        env.pop('HERMES_HOME')
    script = f'''
import sys, os, json
sys.argv = {argv!r}
import lliam_cli.main
from lliam_constants import get_lliam_home
from lliam_cli.config import load_config
print(json.dumps({{'home': str(get_lliam_home()), 'marker': os.getenv('PROFILE_HOME_SENTINEL'), 'timezone': load_config()['timezone']}}))
'''
    result = subprocess.run([sys.executable, '-c', script], cwd=Path(__file__).resolve().parents[2], env=env, capture_output=True, text=True, timeout=30, check=True)
    payload = json.loads(result.stdout.splitlines()[-1])
    assert payload == {'home': str(selected), 'marker': 'reviewer', 'timezone': 'reviewer'}


def test_fresh_cli_loads_dotenv_from_canonical_home(tmp_path):
    canonical = tmp_path / '.lliam'
    canonical.mkdir()
    (canonical / '.env').write_text('PROFILE_HOME_SENTINEL=canonical\n', encoding="utf-8")
    env = {**os.environ, 'HOME': str(tmp_path)}
    env.pop('HERMES_HOME', None)
    env.pop('LLIAM_HOME', None)
    script = '''
import sys, os, json
sys.argv = ['lliam-gov']
import lliam_cli.main
from lliam_constants import get_lliam_home
print(json.dumps({'home': str(get_lliam_home()), 'marker': os.getenv('PROFILE_HOME_SENTINEL')}))
'''
    result = subprocess.run([sys.executable, '-c', script], cwd=Path(__file__).resolve().parents[2], env=env, capture_output=True, text=True, timeout=30, check=True)
    assert json.loads(result.stdout.splitlines()[-1]) == {'home': str(canonical), 'marker': 'canonical'}
