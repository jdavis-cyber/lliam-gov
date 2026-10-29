"""The session guards in tests/conftest.py: real-home writes and test order.

Each end-to-end case runs a small pytest session in a subprocess with
tests/conftest.py loaded as a plugin and every home location (HOME, and on
Windows USERPROFILE, LOCALAPPDATA, APPDATA, HOMEDRIVE/HOMEPATH) pointed at a
temporary directory, so nothing here touches the operator's real home.
"""

import os
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests import conftest as guard

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SECRET = "sk-guard-test-secret-value"


def _home_env(root):
    """Environment that puts every home lookup under ``root``.

    ``Path.home()`` reads HOME on POSIX but USERPROFILE on Windows, and the
    platform default home lives under LOCALAPPDATA on Windows.
    """
    drive, rest = os.path.splitdrive(str(root))
    return {
        "HOME": str(root),
        "USERPROFILE": str(root),
        "LOCALAPPDATA": str(root / "AppData" / "Local"),
        "APPDATA": str(root / "AppData" / "Roaming"),
        "HOMEDRIVE": drive,
        "HOMEPATH": rest,
    }


def _native_lliam_home(root):
    """Where the platform default Lliam home sits under a ``_home_env`` root."""
    if sys.platform == "win32":
        return root / "AppData" / "Local" / "lliam"
    return root / ".lliam"


def _symlink(link, target, *, target_is_directory=False):
    try:
        os.symlink(target, link, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlinks unavailable here: {exc}")


def _run_session(tmp_path, body, *args, env_extra=None):
    """Run one pytest session over ``body`` with a temporary HOME."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    test_file = tmp_path / "inner" / "test_inner.py"
    test_file.parent.mkdir(exist_ok=True)
    test_file.write_text(textwrap.dedent(body))
    env = dict(os.environ)
    env.update(_home_env(home))
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


# The probes write the platform default home, as unisolated code would.
# Indented like the probe bodies so textwrap.dedent keeps them aligned.
_DEFAULT_HOME = "\n        from lliam_constants import _get_platform_default_home as _default_home\n"


def test_session_fails_when_a_test_creates_a_file_in_the_real_home(tmp_path):
    result, home = _run_session(tmp_path, _DEFAULT_HOME + """
        def test_leaks():
            target = _default_home("lliam") / "leak.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("{}")
    """)
    output = result.stdout + result.stderr
    lliam_home = _native_lliam_home(home)
    assert result.returncode == pytest.ExitCode.TESTS_FAILED, output
    assert "1 passed" in output
    assert f"Created: {lliam_home}" in output
    assert f"Created: {lliam_home / 'leak.json'}" in output


def test_session_fails_when_a_test_changes_a_credential_file_without_printing_it(tmp_path):
    lliam_home = _native_lliam_home(tmp_path / "home")
    lliam_home.mkdir(parents=True)
    (lliam_home / "auth.json").write_text(f'{{"token": "{SECRET}"}}')
    result, _ = _run_session(tmp_path, _DEFAULT_HOME + f"""
        def test_rewrites_credentials():
            auth = _default_home("lliam") / "auth.json"
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
    assert not _native_lliam_home(home).exists()


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
    result, home = _run_session(tmp_path, _DEFAULT_HOME + """
        def test_leaks():
            _default_home("lliam").mkdir(parents=True)
    """, "--real-home-guard=warn")
    output = result.stdout + result.stderr
    assert result.returncode == pytest.ExitCode.OK, output
    assert f"Created: {_native_lliam_home(home)}" in output


@pytest.fixture
def isolated_guard(tmp_path, monkeypatch):
    """Point the snapshot functions at a disposable home and repository."""
    home = tmp_path / "home"
    home.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    for name, value in _home_env(home).items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(guard, "PROJECT_ROOT", repo)
    return SimpleNamespace(home=home, repo=repo, lliam_home=_native_lliam_home(home))


def _changes_after(write):
    before = guard._real_home_snapshot()
    write()
    return guard._real_home_changes(before, guard._real_home_snapshot())


def test_snapshot_covers_gitignored_repository_config(isolated_guard):
    config = isolated_guard.repo / "cli-config.yaml"
    created, changed, removed = _changes_after(
        lambda: config.write_text("model:\n  default: x\n"))
    assert created == [str(config)]
    assert changed == [] and removed == []


def test_snapshot_follows_a_symlinked_home(isolated_guard, tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "auth.json").write_text(f'{{"token": "{SECRET}"}}')
    isolated_guard.lliam_home.parent.mkdir(parents=True, exist_ok=True)
    _symlink(isolated_guard.lliam_home, state, target_is_directory=True)

    def write_through_link():
        (isolated_guard.lliam_home / "auth.json").write_text('{"token": "other"}')
        (isolated_guard.lliam_home / "new.json").write_text("{}")

    created, changed, removed = _changes_after(write_through_link)
    real_state = Path(os.path.realpath(state))
    assert changed == [str(real_state / "auth.json")]
    assert created == [str(real_state / "new.json")]
    assert removed == []


def test_snapshot_follows_a_symlinked_repository_config(isolated_guard, tmp_path):
    shared = tmp_path / "shared-cli-config.yaml"
    shared.write_text("model:\n  default: a\n")
    _symlink(isolated_guard.repo / "cli-config.yaml", shared)
    created, changed, removed = _changes_after(
        lambda: (isolated_guard.repo / "cli-config.yaml").write_text("model:\n  default: b\n"))
    assert changed == [os.path.realpath(shared)]
    assert created == [] and removed == []


def test_snapshot_reports_a_referent_created_through_a_dangling_link(isolated_guard, tmp_path):
    absent = tmp_path / "absent-cli-config.yaml"
    _symlink(isolated_guard.repo / "cli-config.yaml", absent)
    created, changed, removed = _changes_after(
        lambda: (isolated_guard.repo / "cli-config.yaml").write_text("x: 1\n"))
    assert created == [os.path.realpath(absent)]
    assert changed == [] and removed == []


def test_snapshot_survives_a_symlink_cycle(isolated_guard, tmp_path):
    other = tmp_path / "other"
    isolated_guard.lliam_home.parent.mkdir(parents=True, exist_ok=True)
    _symlink(isolated_guard.lliam_home, other, target_is_directory=True)
    _symlink(other, isolated_guard.lliam_home, target_is_directory=True)
    snapshot = guard._real_home_snapshot()
    assert snapshot[str(isolated_guard.lliam_home)][0] == "link"
    assert _changes_after(lambda: None) == ([], [], [])


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
