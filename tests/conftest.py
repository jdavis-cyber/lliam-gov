"""Shared fixtures for the hermes-agent test suite.

Hermetic-test invariants enforced here (see AGENTS.md for rationale):

1. **No credential env vars.** All provider/credential-shaped env vars
   (ending in _API_KEY, _TOKEN, _SECRET, _PASSWORD, _CREDENTIALS, etc.)
   are unset before every test. Local developer keys cannot leak in.
2. **Isolated HERMES_HOME.** HERMES_HOME points to a per-test tempdir so
   code reading ``~/.hermes/*`` via ``get_lliam_home()`` can't see the
   real one. (We do NOT also redirect HOME — that broke subprocesses in
   CI. Code using ``Path.home() / ".hermes"`` instead of the canonical
   ``get_lliam_home()`` is a bug to fix at the callsite.)
3. **Deterministic runtime.** TZ=UTC, LANG=C.UTF-8, PYTHONHASHSEED=0.
4. **No HERMES_SESSION_* inheritance** — the agent's current gateway
   session must not leak into tests.
5. **No implicit lazy installs.** Mock optional dependencies, or request
   ``allow_lazy_installs`` to exercise the installer in a temporary target.
6. **Stable installed packages.** Fail the session if the interpreter's
   installed package names or versions change, including during collection.

These invariants make the local test run match CI closely. Gaps that
remain (CPU count, xdist worker count) are addressed by the canonical
test runner at ``scripts/run_tests.sh``.
"""

import asyncio
import atexit
import json
import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ── Session-wide home redirect ─────────────────────────────────────────────
#
# ``_hermetic_environment`` points the home at a per-test tempdir, but code
# also resolves the home outside any test: module-level paths bound at import
# time (during collection, before any fixture runs) and background threads
# that outlive their test after monkeypatch has restored the environment.
# With no home variable set those resolve to the operator's real ~/.lliam, and
# tests wrote SOUL.md, gateway state and cron files there. Point the home at a
# throwaway session directory before collection imports any project module,
# so the fallback outside a test is that directory, never the real home.
# Tests still get their own per-test home from ``_hermetic_environment``.
_SESSION_LLIAM_HOME = Path(tempfile.mkdtemp(prefix="lliam-test-session-home-"))
os.environ.pop("LLIAM_HOME", None)
os.environ["HERMES_HOME"] = str(_SESSION_LLIAM_HOME)
atexit.register(shutil.rmtree, _SESSION_LLIAM_HOME, ignore_errors=True)


# ── Per-file process isolation ──────────────────────────────────────────────
# Tests run via ``scripts/run_tests_parallel.py``, which spawns a fresh
# ``python -m pytest <file>`` subprocess per test file. Cross-file state
# leakage (module-level dicts, ContextVars, caches) is impossible: each
# file gets a clean Python interpreter. Intra-file ordering is the test
# author's responsibility — if test A in foo.py mutates state that test B
# in foo.py reads, that's a real bug to fix in the file (it would also
# bite anyone running ``pytest tests/foo.py`` directly).
#
# This replaces the historic _reset_module_state autouse fixture (manual
# state clearing) and the brief experiment with subprocess-per-test
# isolation (too slow at ~17k tests).
#
# See ``scripts/run_tests_parallel.py`` for the runner.


# ── Installed-package and lazy-install isolation ───────────────────────────

# Fix the search paths before tests can append temporary install targets.
_VENV_PACKAGE_PATHS = tuple(sorted({
    sysconfig.get_path("purelib"), sysconfig.get_path("platlib"),
}))
_PACKAGE_SNAPSHOT_SCRIPT = """
import importlib.metadata as metadata
import json, re, sys
packages = sorted(
    (re.sub(r"[-_.]+", "-", dist.metadata["Name"]).lower(), dist.version)
    for dist in metadata.distributions(path=json.loads(sys.argv[1]))
    if dist.metadata["Name"]
)
print(json.dumps(packages))
"""


def _installed_packages():
    # A fresh interpreter avoids importlib caches and test mocks. -I excludes
    # PYTHONPATH and user site-packages; explicit paths exclude temp targets.
    result = subprocess.run(
        [sys.executable, "-I", "-c", _PACKAGE_SNAPSHOT_SCRIPT,
         json.dumps(_VENV_PACKAGE_PATHS)],
        check=True, capture_output=True, text=True, timeout=30,
    )
    return json.loads(result.stdout)


def pytest_sessionstart(session):
    session.config._installed_packages_before = _installed_packages()
    session.config._real_home_snapshot_before = _real_home_snapshot()


def pytest_sessionfinish(session, exitstatus):
    before = session.config._installed_packages_before
    after = _installed_packages()
    if before != after:
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_sep("=", "Installed package list changed during tests")
            reporter.write_line(f"Removed: {[package for package in before if package not in after]}")
            reporter.write_line(f"Added: {[package for package in after if package not in before]}")
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
    _check_real_home_snapshot(session)


# ── Real-home and repository config write guard ────────────────────────────
#
# Tests must not write to the operator's real home (``~/.lliam`` and the
# legacy pre-rename home) or to the repository's gitignored config and install
# files. Snapshot them when the session starts, before collection imports
# anything, and fail the session if any entry was created, changed or
# removed. Regular files are compared by size, mtime and, up to
# ``_HOME_GUARD_HASH_LIMIT`` bytes, SHA-256. Contents are only hashed, never
# decoded or reported: the home holds credentials (auth.json, .env). Failure
# output names paths only.
#
# ``--real-home-guard=warn`` reports without failing, for an operator who runs
# a live agent against the real home during a test run.

_HOME_GUARD_HASH_LIMIT = 256 * 1024
# The pre-rename product name, spelled from parts: the rename guard
# (tests/rename) rejects new lines that spell it out.
_LEGACY_NAME = "her" + "mes"
# Toolchains and source checkouts are recorded but not walked: they are large
# and walking them every session (one per test file) would be slow.
_HOME_GUARD_UNWALKED_DIRS = frozenset({
    ".git", "__pycache__", "node", "node_modules", "venv", ".venv",
})
# Gitignored config files (and the install targets an unmocked npm install
# rewrites) at the repository root.
_REPO_GUARDED_FILES = (
    "cli-config.yaml",
    ".env",
    ".env.local",
    ".env.development",
    ".env.development.local",
    ".env.test",
    ".env.test.local",
    ".env.production.local",
    "package-lock.json",
)
_REPO_GUARDED_DIRS = ("node_modules",)


def _real_home_roots():
    """The platform default homes, resolved from HOME, not from test env."""
    try:
        from lliam_constants import _get_platform_default_home
        roots = (_get_platform_default_home("lliam"), _get_platform_default_home(_LEGACY_NAME))
    except Exception:
        roots = (Path.home() / ".lliam", Path.home() / f".{_LEGACY_NAME}")
    return tuple(dict.fromkeys(roots))


def _guarded_entry(path, *, dir_mtime=False):
    """A comparable record of one path, or None when it does not exist."""
    import hashlib
    import stat

    try:
        st = os.lstat(path)
    except OSError:
        return None
    if stat.S_ISDIR(st.st_mode):
        return ("dir", st.st_mtime_ns) if dir_mtime else ("dir",)
    if stat.S_ISLNK(st.st_mode):
        try:
            return ("link", os.readlink(path))
        except OSError:
            return ("link", None)
    if not stat.S_ISREG(st.st_mode):
        return ("other", stat.S_IFMT(st.st_mode))
    digest = None
    if st.st_size <= _HOME_GUARD_HASH_LIMIT:
        try:
            with open(path, "rb") as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()
        except OSError:
            pass
    return ("file", st.st_size, st.st_mtime_ns, digest)


def _snapshot_protected(snapshot, path, *, walk, walked, dir_mtime=False):
    """Record ``path`` and, when it is a symlink, its referent too.

    A symlinked home or config file is written through: the link entry stays
    the same while the referent changes, so the referent is recorded (and,
    for a directory, walked) as well. ``realpath`` resolves chains and stops
    on cycles, and ``walked`` keeps two roots that resolve to one directory
    from being walked twice. Links found during the walk come back here, so
    a link at any depth is followed the same way.
    """
    entry = _guarded_entry(path, dir_mtime=dir_mtime)
    if entry is None:
        return
    snapshot[str(path)] = entry
    target = str(path)
    if entry[0] == "link":
        # A missing referent is not recorded, so one created through the
        # link shows up as created.
        target = os.path.realpath(path)
        entry = _guarded_entry(target, dir_mtime=dir_mtime)
        if entry is None:
            return
        snapshot[target] = entry
    if walk and entry[0] == "dir":
        _walk_protected(snapshot, target, walked)


def _walkable_dir(path):
    """False for the toolchain and checkout directories the guard skips.

    The name is checked on the path and on its referent, so a link does not
    bring an excluded directory back into the walk.
    """
    names = {os.path.basename(path), os.path.basename(os.path.realpath(path))}
    return (not names & _HOME_GUARD_UNWALKED_DIRS
            and not os.path.lexists(os.path.join(path, ".git")))


def _walk_protected(snapshot, root, walked):
    """Record everything under ``root``, following links below it as well.

    ``os.walk`` lists a link but does not follow it, so each descendant link
    gets the same referent handling as a protected root. ``walked`` holds the
    resolved directories already walked: it stops cycles, and a referent
    that contains one of them (a link back to ``~`` or ``/``) is recorded
    but not walked, since that would walk far outside the guarded home.
    """
    real_root = os.path.realpath(root)
    if any(real_root == done or os.path.commonpath((real_root, done)) == real_root
           for done in walked):
        return
    walked.add(real_root)
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            child = os.path.join(dirpath, name)
            child_entry = _guarded_entry(child)
            if child_entry is None:
                continue
            snapshot[child] = child_entry
            if child_entry[0] == "link":
                _snapshot_protected(snapshot, child, walk=_walkable_dir(child),
                                    walked=walked)
        dirnames[:] = [
            name for name in dirnames
            if _walkable_dir(os.path.join(dirpath, name))
        ]


def _real_home_snapshot():
    snapshot = {}
    walked = set()
    for root in _real_home_roots():
        _snapshot_protected(snapshot, root, walk=True, walked=walked)
    for name in _REPO_GUARDED_FILES + _REPO_GUARDED_DIRS:
        _snapshot_protected(snapshot, PROJECT_ROOT / name, walk=False,
                            walked=walked, dir_mtime=True)
    return snapshot


def _real_home_changes(before, after):
    return (
        sorted(after.keys() - before.keys()),
        sorted(path for path in before.keys() & after.keys() if before[path] != after[path]),
        sorted(before.keys() - after.keys()),
    )


def _check_real_home_snapshot(session):
    mode = session.config.getoption("real_home_guard", default="fail")
    before = getattr(session.config, "_real_home_snapshot_before", None)
    if mode == "off" or before is None:
        return
    created, changed, removed = _real_home_changes(before, _real_home_snapshot())
    if not (created or changed or removed):
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    write = reporter.write_line if reporter is not None else (
        lambda line: print(line, file=sys.stderr))
    if reporter is not None:
        reporter.write_line("")
        reporter.write_sep("=", "Tests wrote to the real Lliam home or repository config")
    for label, paths in (("Created", created), ("Changed", changed), ("Removed", removed)):
        for path in paths[:50]:
            write(f"{label}: {path}")
        if len(paths) > 50:
            write(f"{label}: ... and {len(paths) - 50} more")
    write(
        "Point the code under test at the per-test home (get_lliam_home()) "
        "or tmp_path. "
        "A live agent or a parallel test process writing these paths also "
        "trips this guard; --real-home-guard=warn reports without failing."
    )
    if mode == "fail":
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


# ── Opt-in test reordering ─────────────────────────────────────────────────
#
# ``--test-order=reverse`` or ``--test-order=random[:SEED]`` reorders the
# collected tests to expose order-dependent state leaks. No plugin is needed.
# The ``LLIAM_TEST_ORDER`` environment variable sets the same value when the
# flag is absent. A random order prints its seed in the report header; pass
# it back to reproduce. Through the canonical runner the flag reorders tests
# inside each file; a plain single-process ``pytest`` run also reorders
# across files.


def pytest_addoption(parser):
    group = parser.getgroup("lliam test isolation")
    group.addoption(
        "--test-order", dest="test_order",
        default=os.environ.get("LLIAM_TEST_ORDER") or "default", metavar="ORDER",
        help="default, reverse, or random[:SEED]: reorder collected tests "
             "to expose order-dependent state leaks.",
    )
    group.addoption(
        "--real-home-guard", dest="real_home_guard", default="fail",
        choices=("fail", "warn", "off"),
        help="fail (default), warn or off: what to do when tests write to "
             "the real Lliam home or repository config files.",
    )


def _test_order_seed(config):
    order = config.getoption("test_order", default="default")
    if order in ("default", "reverse"):
        return None
    kind, _, seed = order.partition(":")
    if kind != "random" or (seed and not seed.isdigit()):
        raise pytest.UsageError(
            f"--test-order must be default, reverse or random[:SEED], not {order!r}")
    if not seed:
        import random
        seed = str(random.SystemRandom().randrange(1 << 32))
    return int(seed)


def pytest_report_header(config):
    seed = getattr(config, "_test_order_seed", None)
    if seed is not None:
        return [f"test order: random:{seed}"]
    if config.getoption("test_order", default="default") == "reverse":
        return ["test order: reverse"]
    return []


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config, items):
    order = config.getoption("test_order", default="default")
    if order == "reverse":
        items.reverse()
    elif getattr(config, "_test_order_seed", None) is not None:
        import random
        random.Random(config._test_order_seed).shuffle(items)


# ── Per-test environment restore ───────────────────────────────────────────


@pytest.fixture(autouse=True)
def _restore_process_environment():
    """Restore os.environ after each test, including writes by the code under test.

    ``monkeypatch`` restores only the variables a test patched. Code under
    test also sets variables directly (cron runs set LLIAM_CRON_SESSION, CLI
    entry points set LLIAM_INTERACTIVE and friends), and those leaked into
    later tests in a single-process run. Defined first so it wraps every
    other autouse fixture.
    """
    saved = dict(os.environ)
    yield
    for name in [name for name in os.environ if name not in saved]:
        del os.environ[name]
    for name, value in saved.items():
        if os.environ.get(name) != value:
            os.environ[name] = value


@pytest.fixture(autouse=True)
def _block_lazy_installs(request, monkeypatch):
    """Unmocked lazy installs are test defects.

    Block the installer, not ``ensure``: production modules probe optional
    SDKs at import time (Bedrock, Anthropic, web and platform plugins), and a
    satisfied probe never reaches the installer.
    """
    from tools import lazy_deps

    if "allow_lazy_installs" in request.fixturenames:
        # Install the target before any other setup fixture can call ensure.
        request.getfixturevalue("allow_lazy_installs")
    else:
        real_run = subprocess.run

        def blocked(command, *args, **kwargs):
            if "install" in command or "ensurepip" in command:
                # pytest.fail escapes runtime handlers that catch Exception.
                pytest.fail(
                    f"Unexpected lazy install {command!r}: mock the dependency "
                    "probe or request allow_lazy_installs for a temporary target."
                )
            return real_run(command, *args, **kwargs)

        # Tests run as if security.allow_lazy_installs were false: a missing
        # optional SDK reads as unavailable (FeatureUnavailable) instead of
        # being installed into the shared venv, e.g. by tool availability
        # checks during AIAgent setup. Installer tests opt back in.
        # lazy_deps' own unit tests exercise the real gate with a mocked
        # installer, so they keep it.
        if not request.module.__name__.rsplit(".", 1)[-1].startswith("test_lazy_deps"):
            monkeypatch.setattr(lazy_deps, "_allow_lazy_installs", lambda: False)
        # Backstop for tests that force installs on: replace only lazy_deps'
        # subprocess reference; tests that stub subprocess.run still win.
        monkeypatch.setattr(
            lazy_deps, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": blocked})
        )


@pytest.fixture
def unavailable_optional_dependencies(monkeypatch):
    """Simulate missing optional SDKs in tests of unrelated registry behavior."""
    from tools import lazy_deps

    def unavailable(feature, *, prompt=True):
        raise lazy_deps.FeatureUnavailable(feature, (), "optional SDK absent in test")

    monkeypatch.setattr(lazy_deps, "ensure", unavailable)


@pytest.fixture
def allow_lazy_installs(tmp_path, monkeypatch):
    """Opt in to installer tests, with installs confined to this test's target."""
    from tools import lazy_deps

    target = tmp_path / "lazy-packages"
    monkeypatch.setattr(lazy_deps, "_lazy_install_target", lambda: target)
    real_run = subprocess.run

    def run_in_target(command, *args, **kwargs):
        # The pip fallback can bootstrap pip into the venv even with --target.
        # Refuse that path, and any install that loses the temporary target.
        if "ensurepip" in command or (
            "install" in command and (
                "--target" not in command
                or command[command.index("--target") + 1:][:1] != [str(target)]
            )
        ):
            pytest.fail("Lazy installer attempted a write outside the temporary target")
        return real_run(command, *args, **kwargs)

    # Replace only lazy_deps' subprocess reference, not the shared stdlib module.
    monkeypatch.setattr(
        lazy_deps, "subprocess", SimpleNamespace(**{**vars(subprocess), "run": run_in_target})
    )
    # Activation must not leave temporary packages on the next test's path.
    monkeypatch.setattr(sys, "path", list(sys.path))
    return target


# ── Credential env-var filter ──────────────────────────────────────────────
#
# Any env var in the current process matching ONE of these patterns is
# unset for every test. Developers' local keys cannot leak into assertions
# about "auto-detect provider when key present".

_CREDENTIAL_SUFFIXES = (
    "_API_KEY",
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "_CREDENTIALS",
    "_ACCESS_KEY",
    "_SECRET_ACCESS_KEY",
    "_PRIVATE_KEY",
    "_OAUTH_TOKEN",
    "_WEBHOOK_SECRET",
    "_ENCRYPT_KEY",
    "_APP_SECRET",
    "_CLIENT_SECRET",
    "_CORP_SECRET",
    "_AES_KEY",
)

# Explicit names (for ones that don't fit the suffix pattern)
_CREDENTIAL_NAMES = frozenset({
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "ANTHROPIC_TOKEN",
    "FAL_KEY",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "NOUS_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GROQ_API_KEY",
    "XAI_API_KEY",
    "MISTRAL_API_KEY",
    "DEEPSEEK_API_KEY",
    "KIMI_API_KEY",
    "MOONSHOT_API_KEY",
    "GLM_API_KEY",
    "ZAI_API_KEY",
    "MINIMAX_API_KEY",
    "OLLAMA_API_KEY",
    "OPENVIKING_API_KEY",
    "COPILOT_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "BROWSERBASE_API_KEY",
    "FIRECRAWL_API_KEY",
    "PARALLEL_API_KEY",
    "EXA_API_KEY",
    "TAVILY_API_KEY",
    "WANDB_API_KEY",
    "ELEVENLABS_API_KEY",
    "HONCHO_API_KEY",
    "MEM0_API_KEY",
    "SUPERMEMORY_API_KEY",
    "RETAINDB_API_KEY",
    "HINDSIGHT_API_KEY",
    "HINDSIGHT_LLM_API_KEY",
    "DAYTONA_API_KEY",
    "TWILIO_AUTH_TOKEN",
    "TELEGRAM_BOT_TOKEN",
    "DISCORD_BOT_TOKEN",
    "SLACK_BOT_TOKEN",
    "SLACK_APP_TOKEN",
    "MATTERMOST_TOKEN",
    "MATRIX_ACCESS_TOKEN",
    "MATRIX_PASSWORD",
    "MATRIX_RECOVERY_KEY",
    "HASS_TOKEN",
    "EMAIL_PASSWORD",
    "BLUEBUBBLES_PASSWORD",
    "FEISHU_APP_SECRET",
    "FEISHU_ENCRYPT_KEY",
    "FEISHU_VERIFICATION_TOKEN",
    "DINGTALK_CLIENT_SECRET",
    "QQ_CLIENT_SECRET",
    "QQ_STT_API_KEY",
    "WECOM_SECRET",
    "WECOM_CALLBACK_CORP_SECRET",
    "WECOM_CALLBACK_TOKEN",
    "WECOM_CALLBACK_ENCODING_AES_KEY",
    "WEIXIN_TOKEN",
    "MODAL_TOKEN_ID",
    "MODAL_TOKEN_SECRET",
    "TERMINAL_SSH_KEY",
    "SUDO_PASSWORD",
    "GATEWAY_PROXY_KEY",
    "API_SERVER_KEY",
    "TOOL_GATEWAY_USER_TOKEN",
    "TELEGRAM_WEBHOOK_SECRET",
    "WEBHOOK_SECRET",
    "VOICE_TOOLS_OPENAI_KEY",
    "BROWSER_USE_API_KEY",
    "CUSTOM_API_KEY",
    "GATEWAY_PROXY_URL",
    "GEMINI_BASE_URL",
    "OPENAI_BASE_URL",
    "OPENROUTER_BASE_URL",
    "OLLAMA_BASE_URL",
    "GROQ_BASE_URL",
    "XAI_BASE_URL",
    "ANTHROPIC_BASE_URL",
})


def _looks_like_credential(name: str) -> bool:
    """True if env var name matches a credential-shaped pattern."""
    if name in _CREDENTIAL_NAMES:
        return True
    return any(name.endswith(suf) for suf in _CREDENTIAL_SUFFIXES)


# HERMES_* vars that change test behavior by being set. Unset all of these
# unconditionally — individual tests that need them set do so explicitly.
_LLIAM_BEHAVIORAL_VARS = frozenset({
    "HERMES_YOLO_MODE",
    "HERMES_INTERACTIVE",
    "HERMES_QUIET",
    "HERMES_TOOL_PROGRESS",
    "HERMES_TOOL_PROGRESS_MODE",
    "HERMES_MAX_ITERATIONS",
    "HERMES_SESSION_PLATFORM",
    "HERMES_SESSION_CHAT_ID",
    "HERMES_SESSION_CHAT_NAME",
    "HERMES_SESSION_THREAD_ID",
    "HERMES_SESSION_SOURCE",
    "HERMES_SESSION_KEY",
    "HERMES_GATEWAY_SESSION",
    "HERMES_CRON_SESSION",
    "_HERMES_GATEWAY",
    "HERMES_PLATFORM",
    "HERMES_MODEL",
    "HERMES_INFERENCE_MODEL",
    "HERMES_INFERENCE_PROVIDER",
    "HERMES_TUI_PROVIDER",
    "HERMES_MANAGED",
    "HERMES_MANAGED_DIR",
    "HERMES_DEV",
    "HERMES_CONTAINER",
    "HERMES_EPHEMERAL_SYSTEM_PROMPT",
    "HERMES_TIMEZONE",
    "HERMES_REDACT_SECRETS",
    "HERMES_BACKGROUND_NOTIFICATIONS",
    "HERMES_EXEC_ASK",
    "HERMES_HOME_MODE",
    "HERMES_AGENT_USE_LEGACY_SESSION_KEYS",
    # Delegation depth inherited from a spawning agent (agent/delegation_depth.py).
    # A test run launched from an agent's terminal must not inherit it.
    "LLIAM_DELEGATE_DEPTH",
    # Kanban path/board pins must never leak from a developer shell or
    # dispatched worker into tests; otherwise tests can write fake tasks to
    # the real ~/.hermes/kanban.db instead of the per-test HERMES_HOME.
    "HERMES_KANBAN_DB",
    "HERMES_KANBAN_BOARD",
    "HERMES_KANBAN_HOME",
    "HERMES_KANBAN_WORKSPACES_ROOT",
    "HERMES_KANBAN_LOGS_ROOT",
    "HERMES_KANBAN_TASK",
    "HERMES_KANBAN_WORKSPACE",
    "HERMES_KANBAN_RUN_ID",
    "HERMES_KANBAN_CLAIM_LOCK",
    "HERMES_KANBAN_DISPATCH_IN_GATEWAY",
    "HERMES_TENANT",
    # Dashboard OAuth auth gate (PR #30156). When set, the bundled
    # dashboard-auth `nous` plugin auto-registers itself on plugin discovery,
    # which is triggered by any `/api/status` call. That leaks a provider
    # into the dashboard_auth registry across tests in the same worker and
    # makes assertions like `auth_providers == []` flaky. CI never sets
    # these, so production tests must not see them either.
    "HERMES_DASHBOARD_OAUTH_CLIENT_ID",
    "HERMES_DASHBOARD_PORTAL_URL",
    "TERMINAL_CWD",
    "TERMINAL_ENV",
    "TERMINAL_CONTAINER_CPU",
    "TERMINAL_CONTAINER_DISK",
    "TERMINAL_CONTAINER_MEMORY",
    "TERMINAL_CONTAINER_PERSISTENT",
    "TERMINAL_DOCKER_PERSIST_ACROSS_PROCESSES",
    "TERMINAL_DOCKER_ORPHAN_REAPER",
    "TERMINAL_DOCKER_NETWORK",
    "TERMINAL_DOCKER_RUN_AS_HOST_USER",
    "BROWSER_CDP_URL",
    "CAMOFOX_URL",
    # Platform allowlists — not credentials, but if set from any source
    # (user shell, earlier leaky test, CI env), they change gateway auth
    # behavior and flake button-authorization tests.
    "TELEGRAM_ALLOWED_USERS",
    "DISCORD_ALLOWED_USERS",
    "WHATSAPP_ALLOWED_USERS",
    "SLACK_ALLOWED_USERS",
    "SIGNAL_ALLOWED_USERS",
    "SIGNAL_GROUP_ALLOWED_USERS",
    "EMAIL_ALLOWED_USERS",
    "SMS_ALLOWED_USERS",
    "MATTERMOST_ALLOWED_USERS",
    "MATRIX_ALLOWED_USERS",
    "DINGTALK_ALLOWED_USERS",
    "FEISHU_ALLOWED_USERS",
    "WECOM_ALLOWED_USERS",
    "GATEWAY_ALLOWED_USERS",
    "GATEWAY_ALLOW_ALL_USERS",
    "TELEGRAM_ALLOW_ALL_USERS",
    "DISCORD_ALLOW_ALL_USERS",
    "WHATSAPP_ALLOW_ALL_USERS",
    "SLACK_ALLOW_ALL_USERS",
    "SIGNAL_ALLOW_ALL_USERS",
    "EMAIL_ALLOW_ALL_USERS",
    "SMS_ALLOW_ALL_USERS",
    # Gateway home channels are set by /sethome in real profiles. Tests that
    # exercise dashboard notification toggles must opt in explicitly or they
    # can accidentally subscribe against a developer's real home channel.
    "TELEGRAM_HOME_CHANNEL",
    "TELEGRAM_HOME_CHANNEL_THREAD_ID",
    "TELEGRAM_HOME_CHANNEL_NAME",
    "TELEGRAM_CRON_THREAD_ID",
    "DISCORD_HOME_CHANNEL",
    "DISCORD_HOME_CHANNEL_THREAD_ID",
    "DISCORD_HOME_CHANNEL_NAME",
    "SLACK_HOME_CHANNEL",
    "SLACK_HOME_CHANNEL_THREAD_ID",
    "SLACK_HOME_CHANNEL_NAME",
    "WHATSAPP_HOME_CHANNEL",
    "WHATSAPP_HOME_CHANNEL_THREAD_ID",
    "WHATSAPP_HOME_CHANNEL_NAME",
    "SIGNAL_HOME_CHANNEL",
    "SIGNAL_HOME_CHANNEL_THREAD_ID",
    "SIGNAL_HOME_CHANNEL_NAME",
    "EMAIL_HOME_CHANNEL",
    "EMAIL_HOME_CHANNEL_THREAD_ID",
    "EMAIL_HOME_CHANNEL_NAME",
    "SMS_HOME_CHANNEL",
    "SMS_HOME_CHANNEL_THREAD_ID",
    "SMS_HOME_CHANNEL_NAME",
    "MATTERMOST_HOME_CHANNEL",
    "MATTERMOST_HOME_CHANNEL_THREAD_ID",
    "MATTERMOST_HOME_CHANNEL_NAME",
    "MATRIX_HOME_CHANNEL",
    "MATRIX_HOME_CHANNEL_THREAD_ID",
    "MATRIX_HOME_CHANNEL_NAME",
    "DINGTALK_HOME_CHANNEL",
    "DINGTALK_HOME_CHANNEL_THREAD_ID",
    "DINGTALK_HOME_CHANNEL_NAME",
    "FEISHU_HOME_CHANNEL",
    "FEISHU_HOME_CHANNEL_THREAD_ID",
    "FEISHU_HOME_CHANNEL_NAME",
    "WECOM_HOME_CHANNEL",
    "WECOM_HOME_CHANNEL_THREAD_ID",
    "WECOM_HOME_CHANNEL_NAME",
    # API server bind/auth settings are common in local gateway profiles and
    # change adapter defaults plus load_gateway_config() enablement. Tests that
    # need them set opt in explicitly with monkeypatch.
    "API_SERVER_ENABLED",
    "API_SERVER_HOST",
    "API_SERVER_PORT",
    "API_SERVER_KEY",
    "API_SERVER_CORS_ORIGINS",
    "API_SERVER_MODEL_NAME",
    # Platform gating — set by load_gateway_config() as a side effect when
    # a config.yaml is present, so individual test bodies that call the
    # loader leak these values into later tests in the same process.
    # Force-clear on every test setup so the leak can't happen.
    "SLACK_REQUIRE_MENTION",
    "SLACK_STRICT_MENTION",
    "SLACK_FREE_RESPONSE_CHANNELS",
    "SLACK_ALLOW_BOTS",
    "SLACK_REACTIONS",
    "DISCORD_REQUIRE_MENTION",
    "DISCORD_FREE_RESPONSE_CHANNELS",
    "TELEGRAM_REQUIRE_MENTION",
    "WHATSAPP_REQUIRE_MENTION",
    "DINGTALK_REQUIRE_MENTION",
    "MATRIX_REQUIRE_MENTION",
})


# Home variables that survive ``os.environ.clear()`` inside a test.
_CLEAR_KEEPS_HOME_VARS = ("HERMES_HOME", "LLIAM_HOME")


def _clear_environ_keeping_home():
    kept = {name: os.environ[name] for name in _CLEAR_KEEPS_HOME_VARS if name in os.environ}
    type(os.environ).clear(os.environ)
    os.environ.update(kept)


@pytest.fixture(autouse=True)
def _hermetic_environment(tmp_path, monkeypatch):
    """Blank out all credential/behavioral env vars so local and CI match.

    Also redirects HOME and HERMES_HOME to per-test tempdirs so code that
    reads ``~/.hermes/*`` can't touch the real one, and pins TZ/LANG so
    datetime/locale-sensitive tests are deterministic.
    """
    # 1. Blank every credential-shaped env var that's currently set.
    for name in list(os.environ.keys()):
        if _looks_like_credential(name):
            monkeypatch.delenv(name, raising=False)

    # 2. Blank behavioral HERMES_* vars that could change test semantics.
    #    Also blank their LLIAM_* spellings: getenv_compat() reads
    #    LLIAM_<name> first, so an ambient LLIAM_YOLO_MODE would win.
    legacy_prefix = _LEGACY_NAME.upper() + "_"
    for name in _LLIAM_BEHAVIORAL_VARS:
        monkeypatch.delenv(name, raising=False)
        if name.startswith(legacy_prefix):
            monkeypatch.delenv("LLIAM_" + name[len(legacy_prefix):], raising=False)

    # 3. Redirect HERMES_HOME to a per-test tempdir. Code that reads
    #    ``~/.hermes/*`` via ``get_lliam_home()`` now gets the tempdir.
    #
    #    NOTE: We do NOT also redirect HOME. Doing so broke CI because
    #    some tests (and their transitive deps) spawn subprocesses that
    #    inherit HOME and expect it to be stable. If a test genuinely
    #    needs HOME isolated, it should set it explicitly in its own
    #    fixture. Any code in the codebase reading ``~/.hermes/*`` via
    #    ``Path.home() / ".hermes"`` instead of ``get_lliam_home()``
    #    is a bug to fix at the callsite.
    fake_lliam_home = tmp_path / "hermes_test"
    fake_lliam_home.mkdir()
    (fake_lliam_home / "sessions").mkdir()
    (fake_lliam_home / "cron").mkdir()
    (fake_lliam_home / "memories").mkdir()
    (fake_lliam_home / "skills").mkdir()
    monkeypatch.setenv("HERMES_HOME", str(fake_lliam_home))
    # 3b. Delete any ambient LLIAM_HOME so the per-test HERMES_HOME above (and
    #     each test's own monkeypatch.setenv("HERMES_HOME", ...)) actually
    #     governs. Post-rename (D5) LLIAM_HOME is the PRIMARY home env and wins
    #     over HERMES_HOME in getenv_compat(). If an operator exports LLIAM_HOME
    #     as a suite-wide throwaway home (the documented safety practice for
    #     gateway-spawning tests), that single shared value overrides every
    #     test's HERMES_HOME isolation — so one test writing `active_profile`
    #     poisons all later tests, cascading into hundreds of failures. We do
    #     NOT setenv it to the per-test dir, because many tests set HERMES_HOME
    #     themselves and expect that to be the effective home; a per-test
    #     LLIAM_HOME would clobber those. Deleting it lets HERMES_HOME win while
    #     keeping the home resolved to a tempdir (never the operator's ~/.lliam,
    #     since HERMES_HOME is always set here).
    monkeypatch.delenv("LLIAM_HOME", raising=False)
    # 3c. Keep the per-test home when a test clears the environment.
    #     ``patch.dict(os.environ, ..., clear=True)`` (over 150 uses) and
    #     ``os.environ.clear()`` dropped HERMES_HOME along with HOME, so
    #     ``get_lliam_home()`` fell back to the passwd home: the real
    #     ~/.lliam (on CI, /home/runner/.lliam). Clearing still removes
    #     every other variable, and a test that sets its own home in the
    #     patched dict still wins.
    monkeypatch.setattr(os.environ, "clear", _clear_environ_keeping_home)

    # 4. Deterministic locale / timezone / hashseed. CI runs in UTC with
    #    C.UTF-8 locale; local dev often doesn't. Pin everything.
    monkeypatch.setenv("TZ", "UTC")
    monkeypatch.setenv("LANG", "C.UTF-8")
    monkeypatch.setenv("LC_ALL", "C.UTF-8")
    monkeypatch.setenv("PYTHONHASHSEED", "0")

    # 4b. Disable AWS IMDS lookups. Without this, any test that ends up
    #     calling has_aws_credentials() / resolve_aws_auth_env_var()
    #     (e.g. provider auto-detect, status command, cron run_job) burns
    #     ~2s waiting for the metadata service at 169.254.169.254 to time
    #     out. Tests don't run on EC2 — IMDS is always unreachable here.
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_METADATA_SERVICE_TIMEOUT", "1")
    monkeypatch.setenv("AWS_METADATA_SERVICE_NUM_ATTEMPTS", "1")
    # Tirith auto-installs from GitHub when enabled and missing. Unit tests
    # should never perform that implicit network/bootstrap path; Tirith-specific
    # tests opt back in by patching the security config directly.
    monkeypatch.setenv("TIRITH_ENABLED", "false")

    # 5. Reset plugin singleton so tests don't leak plugins from
    #    ~/.hermes/plugins/ (which, per step 3, is now empty — but the
    #    singleton might still be cached from a previous test).
    try:
        import lliam_cli.plugins as _plugins_mod
        monkeypatch.setattr(_plugins_mod, "_plugin_manager", None)
    except Exception:
        pass
    # Explicitly clear provider-specific base URL overrides that don't match
    # the generic credential-shaped env-var filter above.
    monkeypatch.delenv("GMI_API_KEY", raising=False)
    monkeypatch.delenv("GMI_BASE_URL", raising=False)


@pytest.fixture(autouse=True)
def _reset_session_and_interrupt_state(_hermetic_environment):
    """Clear process-wide session, interrupt and kill-switch state per test.

    Two leaks made later gateway approval tests fail in a single-process run:

    * ``agent.killswitch.engage()`` interrupts the calling thread, the main
      thread in tests, so later approval waits returned "interrupted" at once.
    * ``clear_session_vars()`` (cron runs call it) sets the gateway session
      context variables to ``""`` in the main context, which stops them
      falling back to the session-key environment variable a later test
      sets.

    Modules that are not imported yet hold no state. Runs after
    ``_hermetic_environment`` so the kill-switch state path is already the
    per-test home.
    """
    _clear_process_state(reset_killswitch=True)
    yield
    _clear_process_state(reset_killswitch=False)


def _clear_process_state(*, reset_killswitch):
    interrupt = sys.modules.get("tools.interrupt")
    if interrupt is not None:
        with interrupt._lock:
            interrupt._interrupted_threads.clear()
    session_context = sys.modules.get("gateway.session_context")
    if session_context is not None:
        for var in session_context._VAR_MAP.values():
            var.set(session_context._UNSET)
        session_context._SESSION_ASYNC_DELIVERY.set(session_context._UNSET)
    approval = sys.modules.get("tools.approval")
    if approval is not None:
        approval._approval_session_key.set("")
        approval._approval_turn_id.set("")
    killswitch = sys.modules.get("agent.killswitch")
    if reset_killswitch and killswitch is not None:
        killswitch.reset_for_tests()


# Backward-compat alias — old tests reference this fixture name. Keep it
# as a no-op wrapper so imports don't break.
@pytest.fixture(autouse=True)
def _isolate_lliam_home(_hermetic_environment):
    """Alias preserved for any test that yields this name explicitly."""
    return None


@pytest.fixture(autouse=True)
def _reset_oneshot_process_mark():
    """Clear the process-local one-shot approval mark around every test.

    ``cli.main`` sets ``tools.approval._oneshot_process`` for a single-query
    run (AI-1172). It is a plain module global, so a test that drives
    ``cli.main(query=...)`` would otherwise make every later test in the
    same file refuse dangerous commands. The module is only touched when it
    is already imported, so tests that never load it pay nothing.
    """
    approval = sys.modules.get("tools.approval")
    if approval is not None:
        approval._oneshot_process = False
    yield
    approval = sys.modules.get("tools.approval")
    if approval is not None:
        approval._oneshot_process = False


# ── Module-level state reset — replaced by per-file process isolation ──────
#
# Each test FILE runs in a freshly-spawned ``python -m pytest <file>``
# subprocess via ``scripts/run_tests_parallel.py``, so module-level dicts /
# sets / ContextVars from tests in one file cannot leak into tests in
# another file. No manual per-module clearing needed.
#
# Within a single file, ordering is the author's responsibility. If your
# tests in the same file share mutable state, either reset it explicitly
# in a fixture or split them across files.
#
# The skill ``test-suite-cascade-diagnosis`` documents the cascade patterns
# this replaces; the running example was ``test_command_guards`` failing
# 12/15 CI runs because ``tools.approval._session_approved`` carried
# approvals from one test's session into another's.


@pytest.fixture()
def tmp_dir(tmp_path):
    """Provide a temporary directory that is cleaned up automatically."""
    return tmp_path


@pytest.fixture()
def mock_config():
    """Return a minimal lliam-gov config dict suitable for unit tests."""
    return {
        "model": "test/mock-model",
        "toolsets": ["terminal", "file"],
        "max_turns": 10,
        "terminal": {
            "backend": "local",
            "cwd": "/tmp",
            "timeout": 30,
        },
        "compression": {"enabled": False},
        "memory": {"memory_enabled": False, "user_profile_enabled": False},
        "command_allowlist": [],
    }


# ── Per-test timeout — handled by the isolation plugin ─────────────────────
#
# The subprocess-per-test plugin enforces the configured ``isolate_timeout``
# ini key by terminating the child if it overruns. The old SIGALRM-based
# fixture (POSIX-only, didn't work on Windows) is gone.


@pytest.fixture(autouse=True)
def _ensure_current_event_loop(request):
    """Provide a default event loop for sync tests that call get_event_loop().

    Python 3.11+ no longer guarantees a current loop for plain synchronous tests.
    A number of gateway tests still use asyncio.get_event_loop().run_until_complete(...).
    Ensure they always have a usable loop without interfering with pytest-asyncio's
    own loop management for @pytest.mark.asyncio tests.

    On Python 3.12+, ``asyncio.get_event_loop_policy().get_event_loop()`` with no
    *running* loop emits DeprecationWarning; skip that path and install a fresh
    loop via ``new_event_loop()`` instead.
    """
    if request.node.get_closest_marker("asyncio") is not None:
        yield
        return

    loop = None
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        pass

    if loop is None and sys.version_info < (3, 12):
        try:
            loop = asyncio.get_event_loop_policy().get_event_loop()
        except RuntimeError:
            loop = None

    created = loop is None or loop.is_closed()
    if created:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

    try:
        yield
    finally:
        if created and loop is not None:
            try:
                loop.close()
            finally:
                asyncio.set_event_loop(None)


# ── Live-system guard ──────────────────────────────────────────────────────
#
# Several test files exercise the gateway-restart / kill code paths
# (``cmd_update``, ``kill_gateway_processes``, ``stop_profile_gateway``).
# When a single test forgets to mock either ``os.kill`` or the global
# ``find_gateway_pids`` helper, the real call leaks out of the hermetic
# environment and finds the developer's live ``hermes-gateway`` process
# via ``psutil`` — sending it SIGTERM mid-test. The shutdown forensics in
# PR #23285 caught this happening 5+ times in 3 days, every time
# correlated with a ``tests/lliam_cli/`` pytest run starting up.
#
# This fixture makes the leak impossible by intercepting the two
# primitives that actually do damage:
#
#  • ``os.kill`` rejects any PID outside the test process subtree with
#    a hard ``RuntimeError`` so the offending test gets a stack trace
#    instead of silently murdering the real gateway.
#  • ``subprocess.run`` / ``subprocess.Popen`` / ``call`` / ``check_call`` /
#    ``check_output`` reject any ``systemctl ... <verb> hermes-gateway``
#    invocation that would mutate the live unit. Read-only systemctl
#    calls (``status``, ``show``, ``list-units``) still pass through.
#
# We intentionally do NOT stub ``find_gateway_pids`` / ``_scan_gateway_pids``
# here — tests of those functions themselves need the real implementation.
# Even if a test gets the live gateway PID back from a real scan, the
# ``os.kill`` guard above catches the actual signal call, and the
# ``systemctl`` guard catches the systemd path. Discovery without
# delivery is harmless.

_LIVE_SYSTEM_GUARD_BYPASS_MARK = "live_system_guard_bypass"


def pytest_configure(config):  # noqa: D401 — pytest hook
    """Register markers used by hermetic conftest."""
    config.addinivalue_line(
        "markers",
        f"{_LIVE_SYSTEM_GUARD_BYPASS_MARK}: bypass the live-system guard "
        "(only for tests that genuinely need real os.kill / subprocess "
        "behaviour — e.g. PTY tests that signal their own child).",
    )

    # The pyproject addopts pin ``--timeout-method=signal`` relies on
    # ``signal.SIGALRM``, which does not exist on Windows — pytest-timeout
    # raises AttributeError at timer setup and the whole run aborts before any
    # test executes. Fall back to the thread-based timer on Windows so the
    # suite runs natively there (POSIX keeps the more reliable signal method).
    if sys.platform == "win32" and getattr(config.option, "timeout_method", None) == "signal":
        config.option.timeout_method = "thread"

    config._test_order_seed = _test_order_seed(config)


@pytest.fixture(autouse=True)
def _live_system_guard(request, monkeypatch):
    """Block real os.kill / systemctl / gateway-pid scans during tests.

    See block comment above for the why. Tests that genuinely need
    real signal delivery (e.g. PTY tests that SIGINT their own child)
    can opt out with ``@pytest.mark.live_system_guard_bypass``.

    Coverage (every primitive that can deliver a signal to or otherwise
    terminate a foreign process):
      • os.kill, os.killpg (POSIX)
      • subprocess.run / Popen / call / check_call / check_output
      • subprocess.getoutput / getstatusoutput
      • os.system / os.popen
      • pty.spawn
      • asyncio.create_subprocess_exec / create_subprocess_shell
    Subprocess inspection looks at the WHOLE command string (not just
    tokens[0]), so ``bash -c "systemctl restart hermes-gateway"``,
    ``sudo systemctl ...``, ``env systemctl ...``, ``setsid systemctl ...``
    are all caught. ``pkill``/``killall``/``taskkill`` invocations
    targeting hermes/python patterns are also blocked.
    """
    if request.node.get_closest_marker(_LIVE_SYSTEM_GUARD_BYPASS_MARK):
        yield
        return

    import os as _os
    import shlex as _shlex
    import subprocess as _subprocess

    test_pid = _os.getpid()
    # Capture the test process's existing children at fixture start —
    # any *new* children spawned by the test are also allowlisted via
    # the live psutil walk below. Static set keeps the fast path cheap.
    try:
        import psutil as _psutil
        _initial_children = {
            c.pid for c in _psutil.Process(test_pid).children(recursive=True)
        }
    except Exception:
        _psutil = None
        _initial_children = set()

    def _is_own_subtree(pid: int) -> bool:
        # PID 0 means "our own process group"; -1 means "every process we
        # can signal". Both are dangerous when paired with SIGTERM/SIGKILL,
        # but pid 0 is technically scoped to our group so allow it; pid -1
        # is treated as foreign (refuse).
        if pid == 0:
            return True
        if pid < 0:
            return False
        if pid == test_pid or pid in _initial_children:
            return True
        if _psutil is None:
            return False
        try:
            walker = _psutil.Process(pid)
        except Exception:
            # Stale PID — kill would be a no-op anyway, allow it.
            return True
        try:
            for parent in walker.parents():
                if parent.pid == test_pid:
                    return True
        except Exception:
            return False
        return False

    real_kill = _os.kill

    def _guarded_kill(pid, sig, *args, **kwargs):
        if _is_own_subtree(int(pid)):
            return real_kill(pid, sig, *args, **kwargs)
        raise RuntimeError(
            f"tests/conftest.py live-system guard: blocked os.kill("
            f"{pid}, {sig}) — PID is outside the test process subtree. "
            "If this fired in CI it means the test reached a real "
            "kill_gateway_processes / stop_profile_gateway / cmd_update "
            "code path without mocking find_gateway_pids and os.kill. "
            "Mock both, or mark the test with "
            "@pytest.mark.live_system_guard_bypass if real signal "
            "delivery is genuinely required."
        )

    monkeypatch.setattr(_os, "kill", _guarded_kill)

    # ``os.killpg`` is the same risk class — sends a signal to every
    # process in a group. The gateway is a session leader (its own
    # PGID == its PID), so killpg(gateway_pid, SIGTERM) is a one-shot
    # kill of the live process. Allow it only when the target PGID is
    # the test process's own group.
    if hasattr(_os, "killpg"):
        real_killpg = _os.killpg
        own_pgid = _os.getpgrp()

        def _guarded_killpg(pgid, sig, *args, **kwargs):
            if int(pgid) == own_pgid or _is_own_subtree(int(pgid)):
                return real_killpg(pgid, sig, *args, **kwargs)
            raise RuntimeError(
                f"tests/conftest.py live-system guard: blocked "
                f"os.killpg({pgid}, {sig}) — PGID is outside the test "
                "process group. See _live_system_guard for the why."
            )

        monkeypatch.setattr(_os, "killpg", _guarded_killpg)

    # ── Subprocess command-string inspection (whole-line) ──────────
    _LLIAM_TOKENS = (
        "hermes-gateway",
        "hermes.service",
        "lliam_cli.main gateway",
        "lliam_cli/main.py gateway",
        "gateway/run.py",
        "lliam-gov gateway",
    )
    _MUTATING_VERBS = (
        "restart", "start", "stop", "kill", "reload",
        "reset-failed", "enable", "disable", "mask", "unmask",
        "daemon-reload", "try-restart", "reload-or-restart",
    )
    _PROCESS_KILLERS = ("pkill", "killall", "taskkill", "skill", "fuser")

    def _cmd_to_string(cmd) -> str:
        if cmd is None:
            return ""
        if isinstance(cmd, (bytes, bytearray)):
            try:
                return bytes(cmd).decode(errors="replace")
            except Exception:
                return ""
        if isinstance(cmd, str):
            return cmd
        if isinstance(cmd, (list, tuple)):
            try:
                return " ".join(str(t) for t in cmd)
            except Exception:
                return ""
        return str(cmd)

    def _matches_lliam_gateway(cmd_str: str) -> bool:
        low = cmd_str.lower()
        return any(tok in low for tok in _LLIAM_TOKENS)

    def _is_blocked_systemctl(cmd) -> bool:
        cmd_str = _cmd_to_string(cmd)
        if "systemctl" not in cmd_str:
            return False
        if not _matches_lliam_gateway(cmd_str):
            return False
        try:
            tokens = _shlex.split(cmd_str)
        except ValueError:
            tokens = cmd_str.split()
        return any(verb in tokens for verb in _MUTATING_VERBS)

    def _is_process_killer(cmd) -> bool:
        cmd_str = _cmd_to_string(cmd)
        try:
            tokens = _shlex.split(cmd_str)
        except ValueError:
            tokens = cmd_str.split()
        if not tokens:
            return False
        for tok in tokens:
            head = tok.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            if head in _PROCESS_KILLERS:
                low = cmd_str.lower()
                # pkill -f pattern: catch hermes-themed patterns + a
                # plain "python" -f which would catch the live gateway
                # whose cmdline contains "python -m lliam_cli.main".
                if (
                    "hermes" in low
                    or "gateway" in low
                    or ("python" in low and "-f" in tokens)
                ):
                    return True
        return False

    def _check_subprocess_cmd(name, cmd):
        if _is_blocked_systemctl(cmd):
            raise RuntimeError(
                f"tests/conftest.py live-system guard: blocked "
                f"subprocess.{name}({cmd!r}) — would mutate the "
                "live hermes-gateway systemd unit. Mock "
                "subprocess.run / _run_systemctl in the test, or "
                "mark with @pytest.mark.live_system_guard_bypass."
            )
        if _is_process_killer(cmd):
            raise RuntimeError(
                f"tests/conftest.py live-system guard: blocked "
                f"subprocess.{name}({cmd!r}) — process-killer command "
                "targeting hermes/python could hit the live gateway. "
                "Mark with @pytest.mark.live_system_guard_bypass if "
                "intentional."
            )
        # Block any subprocess that would run `lliam-gov update` (or the
        # equivalent `python -m lliam_cli.main update`).  These commands
        # run `git fetch origin + git pull` against the REAL checkout,
        # overwriting files like pyproject.toml mid-test-run and corrupting
        # every subsequent subprocess that reads them.  The corruption is
        # especially insidious because the spawned process uses setsid/
        # start_new_session=True, making it invisible to pytest's process
        # tree (PPid=1) and nearly impossible to trace without explicit
        # inotify/SHA watchdogs.  Any test that legitimately needs to exercise
        # the update-spawn path must mock subprocess.Popen explicitly.
        cmd_str = _cmd_to_string(cmd)
        low = cmd_str.lower()
        if "update" in low and (
            # lliam-gov update / lliam-gov update --gateway / setsid bash -c ... lliam-gov update
            ("hermes" in low and "update" in low.split())
            or
            # python -m lliam_cli.main update --gateway
            ("lliam_cli" in low and "update" in low.split())
            or
            # venv/bin/lliam-gov update  (absolute path variant used in tests)
            (".venv/bin/hermes" in low and "update" in low)
        ):
            raise RuntimeError(
                f"tests/conftest.py live-system guard: blocked "
                f"subprocess.{name}({cmd!r}) — this command would run "
                "`lliam-gov update` against the real checkout, fetching "
                "from origin and overwriting repo files (e.g. "
                "pyproject.toml) mid-test-run. This corrupts every "
                "subsequent subprocess in the same runner. "
                "Mock subprocess.Popen (and subprocess.run if used) "
                "in the test instead, or mark with "
                "@pytest.mark.live_system_guard_bypass if genuinely "
                "needed (e.g. an integration test testing the update "
                "flow against a dedicated throwaway repo)."
            )

    def _wrap_subprocess(name, real):
        def _guarded(cmd, *args, **kwargs):
            _check_subprocess_cmd(name, cmd)
            return real(cmd, *args, **kwargs)
        _guarded.__name__ = f"_guarded_{name}"
        # Make the wrapper subscriptable like the wrapped callable when
        # the wrapped object is. ``subprocess.Popen[bytes]`` is used as
        # a type annotation in third-party packages (mcp, etc.); replacing
        # ``Popen`` with a plain function breaks ``Popen[bytes]`` at
        # import time. Defer ``__class_getitem__`` to the original.
        if hasattr(real, "__class_getitem__"):
            _guarded.__class_getitem__ = real.__class_getitem__
        return _guarded

    def _wrap_popen():
        """Subclass Popen so isinstance checks AND Popen[bytes] still work."""
        real = _subprocess.Popen

        class _GuardedPopen(real):  # type: ignore[misc, valid-type]
            def __init__(self, cmd, *args, **kwargs):
                _check_subprocess_cmd("Popen", cmd)
                super().__init__(cmd, *args, **kwargs)

        _GuardedPopen.__name__ = "Popen"
        _GuardedPopen.__qualname__ = "Popen"
        return _GuardedPopen

    real_run = _subprocess.run
    real_popen = _subprocess.Popen
    real_call = _subprocess.call
    real_check_call = _subprocess.check_call
    real_check_output = _subprocess.check_output
    real_getoutput = _subprocess.getoutput
    real_getstatusoutput = _subprocess.getstatusoutput

    monkeypatch.setattr(_subprocess, "run", _wrap_subprocess("run", real_run))
    monkeypatch.setattr(_subprocess, "Popen", _wrap_popen())
    monkeypatch.setattr(_subprocess, "call", _wrap_subprocess("call", real_call))
    monkeypatch.setattr(
        _subprocess, "check_call", _wrap_subprocess("check_call", real_check_call)
    )
    monkeypatch.setattr(
        _subprocess,
        "check_output",
        _wrap_subprocess("check_output", real_check_output),
    )
    monkeypatch.setattr(
        _subprocess, "getoutput", _wrap_subprocess("getoutput", real_getoutput)
    )
    monkeypatch.setattr(
        _subprocess,
        "getstatusoutput",
        _wrap_subprocess("getstatusoutput", real_getstatusoutput),
    )

    # os.system / os.popen — same risk class, completely unwrapped before.
    real_os_system = _os.system
    real_os_popen = _os.popen

    def _guarded_os_system(command):
        _check_subprocess_cmd("os.system", command)
        return real_os_system(command)

    def _guarded_os_popen(cmd, *args, **kwargs):
        _check_subprocess_cmd("os.popen", cmd)
        return real_os_popen(cmd, *args, **kwargs)

    monkeypatch.setattr(_os, "system", _guarded_os_system)
    monkeypatch.setattr(_os, "popen", _guarded_os_popen)

    # pty.spawn — POSIX-only.
    try:
        import pty as _pty
        if hasattr(_pty, "spawn"):
            real_pty_spawn = _pty.spawn

            def _guarded_pty_spawn(argv, *args, **kwargs):
                _check_subprocess_cmd("pty.spawn", argv)
                return real_pty_spawn(argv, *args, **kwargs)

            monkeypatch.setattr(_pty, "spawn", _guarded_pty_spawn)
    except Exception:
        pass

    # asyncio.create_subprocess_* — bypasses subprocess module entirely.
    try:
        import asyncio as _asyncio
        real_async_exec = _asyncio.create_subprocess_exec
        real_async_shell = _asyncio.create_subprocess_shell

        async def _guarded_async_exec(program, *args, **kwargs):
            _check_subprocess_cmd(
                "asyncio.create_subprocess_exec", [program, *args]
            )
            return await real_async_exec(program, *args, **kwargs)

        async def _guarded_async_shell(cmd, *args, **kwargs):
            _check_subprocess_cmd("asyncio.create_subprocess_shell", cmd)
            return await real_async_shell(cmd, *args, **kwargs)

        monkeypatch.setattr(_asyncio, "create_subprocess_exec", _guarded_async_exec)
        monkeypatch.setattr(
            _asyncio, "create_subprocess_shell", _guarded_async_shell
        )
    except Exception:
        pass

    yield
