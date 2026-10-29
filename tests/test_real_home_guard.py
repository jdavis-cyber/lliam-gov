"""The session guards in tests/conftest.py: real-home writes and test order.

Each end-to-end case runs a small pytest session in a subprocess with
tests/conftest.py loaded as a plugin and HOME pointed at a temporary
directory, so nothing here touches the operator's real home.
"""

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from tests import conftest as guard

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SECRET = "sk-guard-test-secret-value"


def _run_session(tmp_path, body, *args, env_extra=None):
    """Run one pytest session over ``body`` with a temporary HOME."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    test_file = tmp_path / "inner" / "test_inner.py"
    test_file.parent.mkdir(exist_ok=True)
    test_file.write_text(textwrap.dedent(body))
    env = dict(os.environ)
    env["HOME"] = str(home)
    # Start like a developer shell or scripts/run_tests.sh: no home variable,
    # so only the conftest decides where the home resolves.
    for name in ("LLIAM_HOME", guard._LEGACY_NAME.upper() + "_HOME", "LLIAM_TEST_ORDER"):
        env.pop(name, None)
    env.update(env_extra or {})
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "tests.conftest",
         "-p", "no:cacheprovider", "-q", "-o", "addopts=",
         "--rootdir", str(test_file.parent), str(test_file), *args],
        cwd=PROJECT_ROOT, env=env, capture_output=True, text=True, timeout=300,
    )
    return result, home


def test_session_fails_when_a_test_creates_a_file_in_the_real_home(tmp_path):
    result, home = _run_session(tmp_path, """
        from pathlib import Path

        def test_leaks():
            target = Path.home() / ".lliam" / "leak.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("{}")
    """)
    output = result.stdout + result.stderr
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, output
    assert "1 passed" in output
    assert f"Created: {home / '.lliam'}" in output
    assert f"Created: {home / '.lliam' / 'leak.json'}" in output


def test_session_fails_when_a_test_changes_a_credential_file_without_printing_it(tmp_path):
    lliam_home = tmp_path / "home" / ".lliam"
    lliam_home.mkdir(parents=True)
    (lliam_home / "auth.json").write_text(f'{{"token": "{SECRET}"}}')
    result, _ = _run_session(tmp_path, f"""
        from pathlib import Path

        def test_rewrites_credentials():
            auth = Path.home() / ".lliam" / "auth.json"
            auth.write_text('{{"token": "{SECRET}-rotated"}}')
    """)
    output = result.stdout + result.stderr
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, output
    assert f"Changed: {lliam_home / 'auth.json'}" in output
    assert SECRET not in output


def test_session_passes_when_the_home_is_only_resolved_through_lliam_home(tmp_path):
    # get_lliam_home() resolves to the per-test home inside a test and to the
    # session home outside one (module import), never to the real ~/.lliam.
    result, home = _run_session(tmp_path, """
        from lliam_constants import get_lliam_home
        import cron.jobs

        def test_writes_isolated_home():
            (get_lliam_home() / "gateway_state.json").write_text("{}")
            cron.jobs.CRON_DIR.mkdir(parents=True, exist_ok=True)
            (cron.jobs.CRON_DIR / "jobs.json").write_text("[]")
    """)
    output = result.stdout + result.stderr
    assert result.returncode == pytest.ExitCode.OK, output
    assert not (home / ".lliam").exists()


def test_clearing_the_environment_keeps_the_per_test_home(tmp_path):
    # With HOME gone too, a cleared environment used to resolve the home
    # from the passwd database: the real ~/.lliam.
    result, _ = _run_session(tmp_path, """
        import os
        from unittest.mock import patch
        from lliam_constants import get_lliam_home

        def test_patch_dict_clear():
            home = get_lliam_home()
            with patch.dict(os.environ, {"ONLY": "1"}, clear=True):
                assert get_lliam_home() == home
                assert "PATH" not in os.environ and os.environ["ONLY"] == "1"
            assert "PATH" in os.environ

        def test_environ_clear():
            home = get_lliam_home()
            os.environ.clear()
            assert get_lliam_home() == home
    """)
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr


def test_warn_mode_reports_without_failing(tmp_path):
    result, home = _run_session(tmp_path, """
        from pathlib import Path

        def test_leaks():
            (Path.home() / ".lliam").mkdir()
    """, "--real-home-guard=warn")
    output = result.stdout + result.stderr
    assert result.returncode == pytest.ExitCode.OK, output
    assert f"Created: {home / '.lliam'}" in output


def test_snapshot_covers_gitignored_repository_config(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(guard, "PROJECT_ROOT", repo)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    before = guard._real_home_snapshot()
    (repo / "cli-config.yaml").write_text("model:\n  default: x\n")
    created, changed, removed = guard._real_home_changes(
        before, guard._real_home_snapshot())
    assert created == [str(repo / "cli-config.yaml")]
    assert changed == [] and removed == []


_ORDER_BODY = """
    import os

    def _record(name):
        with open(os.environ["ORDER_LOG"], "a") as fh:
            fh.write(name + "\\n")

    def test_a(): _record("a")
    def test_b(): _record("b")
    def test_c(): _record("c")
    def test_d(): _record("d")
    def test_e(): _record("e")
"""


def _order(tmp_path, *args, env_extra=None):
    log = tmp_path / "order.log"
    log.unlink(missing_ok=True)
    env = {"ORDER_LOG": str(log), **(env_extra or {})}
    result, _ = _run_session(tmp_path, _ORDER_BODY, *args, env_extra=env)
    assert result.returncode == pytest.ExitCode.OK, result.stdout + result.stderr
    return log.read_text().split(), result.stdout


def test_reverse_and_seeded_random_order(tmp_path):
    assert _order(tmp_path)[0] == ["a", "b", "c", "d", "e"]
    assert _order(tmp_path, "--test-order=reverse")[0] == ["e", "d", "c", "b", "a"]
    # -v cancels the session's -q so the report header is printed.
    first, header = _order(tmp_path, "--test-order=random:1234", "-v")
    assert "test order: random:1234" in header
    assert sorted(first) == ["a", "b", "c", "d", "e"]
    assert first != ["a", "b", "c", "d", "e"]
    assert _order(tmp_path, env_extra={"LLIAM_TEST_ORDER": "random:1234"})[0] == first
