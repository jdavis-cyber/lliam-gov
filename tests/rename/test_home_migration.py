"""Task R.1 — data-home migration + env-var compatibility layer.

TDD spec for the one-time ``~/.hermes`` -> ``~/.lliam`` on-disk migration and
the ``LLIAM_`` / ``HERMES_`` env-var precedence helper.

SAFETY: every test here passes explicit ``tmp_path``-derived homes. Nothing in
this file may resolve to the operator's real ``~/.hermes`` or create a real
``~/.lliam``. ``migrate_if_needed`` only touches the paths it is given, and the
env helper is exercised via monkeypatched ``os.environ`` only.
"""

from pathlib import Path

from lliam_cli import env_compat, migrate_home  # becomes lliam_cli.* after R.2


# ─── migrate_if_needed ────────────────────────────────────────────────────────


def test_migrates_old_home_when_new_absent(tmp_path):
    old = tmp_path / ".hermes"
    new = tmp_path / ".lliam"
    (old / "sessions").mkdir(parents=True)
    (old / "config.yaml").write_text("k: v")

    migrate_home.migrate_if_needed(old, new)  # paths passed in, never hardcoded

    assert (new / "config.yaml").read_text() == "k: v"
    assert (new / "sessions").is_dir()
    assert (new / ".migrated_from_hermes").exists()
    # copy, not move — rollback source must survive.
    assert (old / "config.yaml").read_text() == "k: v"


def test_noop_when_new_exists(tmp_path):
    old = tmp_path / ".hermes"
    new = tmp_path / ".lliam"
    old.mkdir()
    new.mkdir()

    migrate_home.migrate_if_needed(old, new)  # must not raise, must not overwrite

    assert not (new / ".migrated_from_hermes").exists()


def test_noop_when_old_absent(tmp_path):
    old = tmp_path / ".hermes"  # never created
    new = tmp_path / ".lliam"

    migrate_home.migrate_if_needed(old, new)  # must not raise

    assert not new.exists()


def test_noop_when_old_equals_new(tmp_path):
    """HERMES_HOME set + LLIAM_HOME unset -> effective home IS the old home.

    Copying a directory onto itself must be impossible: guard returns before
    any filesystem write, and no migration stamp is dropped.
    """
    home = tmp_path / ".hermes"
    (home / "config.yaml").parent.mkdir(parents=True, exist_ok=True)
    (home / "config.yaml").write_text("k: v")

    migrate_home.migrate_if_needed(home, home)  # old == new -> no-op

    assert not (home / ".migrated_from_hermes").exists()
    assert (home / "config.yaml").read_text() == "k: v"  # untouched


def test_old_equals_new_after_path_normalization(tmp_path):
    """old==new detection survives str-vs-Path and trailing-slash differences."""
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text("k: v")

    # Same dir, one as ``str`` with a trailing separator, one as ``Path``.
    migrate_home.migrate_if_needed(str(home) + "/", home)

    assert not (home / ".migrated_from_hermes").exists()


def test_idempotent_second_call_is_noop(tmp_path):
    old = tmp_path / ".hermes"
    new = tmp_path / ".lliam"
    (old).mkdir()
    (old / "config.yaml").write_text("first")

    migrate_home.migrate_if_needed(old, new)
    assert (new / ".migrated_from_hermes").exists()

    # Mutate old; second call must NOT re-copy because new now exists.
    (old / "config.yaml").write_text("second")
    migrate_home.migrate_if_needed(old, new)

    assert (new / "config.yaml").read_text() == "first"  # untouched by 2nd run


def test_interrupted_copy_leaves_new_home_absent_and_retry_succeeds(
    tmp_path, monkeypatch
):
    """Crash safety: a copy that dies mid-way must NOT create ``new_home``.

    If the interrupted copy landed directly at ``new_home``, the
    ``new_home.exists()`` guard would latch onto the half-populated home forever
    and the complete legacy data would silently never be consulted again. The
    staging-then-rename pattern guarantees ``new_home`` only appears complete.
    """
    old = tmp_path / ".hermes"
    new = tmp_path / ".lliam"
    old.mkdir()
    (old / "config.yaml").write_text("k: v")

    real_copytree = migrate_home.shutil.copytree

    def _dying_copytree(src, dst, **kwargs):
        # Simulate an interruption AFTER partial content landed on disk.
        Path(dst).mkdir()
        (Path(dst) / "config.yaml").write_text("half")
        raise OSError("disk full")

    monkeypatch.setattr(migrate_home.shutil, "copytree", _dying_copytree)
    try:
        migrate_home.migrate_if_needed(old, new)
    except OSError:
        pass

    # new_home absent, no half-populated home, no leftover staging dir.
    assert not new.exists()
    assert not (tmp_path / ".lliam.migrating").exists()

    # Next launch retries cleanly and completes.
    monkeypatch.setattr(migrate_home.shutil, "copytree", real_copytree)
    migrate_home.migrate_if_needed(old, new)
    assert (new / "config.yaml").read_text() == "k: v"
    assert (new / ".migrated_from_hermes").exists()


def test_stale_staging_dir_from_prior_crash_is_discarded(tmp_path):
    """A leftover ``<new>.migrating`` dir (crash before cleanup ran) must not
    block or corrupt the retry — it is discarded and replaced by a fresh copy."""
    old = tmp_path / ".hermes"
    new = tmp_path / ".lliam"
    old.mkdir()
    (old / "config.yaml").write_text("fresh")

    stale = tmp_path / ".lliam.migrating"
    stale.mkdir()
    (stale / "config.yaml").write_text("stale-partial")

    migrate_home.migrate_if_needed(old, new)

    assert (new / "config.yaml").read_text() == "fresh"
    assert (new / ".migrated_from_hermes").exists()
    assert not stale.exists()


# ─── getenv_compat precedence ─────────────────────────────────────────────────


def test_getenv_compat_lliam_wins(monkeypatch):
    monkeypatch.setenv("LLIAM_HOME", "/new")
    monkeypatch.setenv("HERMES_HOME", "/old")
    assert env_compat.getenv_compat("HOME") == "/new"


def test_getenv_compat_falls_back_to_hermes(monkeypatch):
    monkeypatch.delenv("LLIAM_HOME", raising=False)
    monkeypatch.setenv("HERMES_HOME", "/old")
    assert env_compat.getenv_compat("HOME") == "/old"


def test_getenv_compat_default_when_neither(monkeypatch):
    monkeypatch.delenv("LLIAM_HOME", raising=False)
    monkeypatch.delenv("HERMES_HOME", raising=False)
    assert env_compat.getenv_compat("HOME", "/fallback") == "/fallback"
    assert env_compat.getenv_compat("HOME") is None


def test_getenv_compat_empty_lliam_falls_through(monkeypatch):
    """An empty (but set) LLIAM_ var must not shadow a real HERMES_ value.

    Empty env vars are how the shell represents "unset-ish"; ``or`` chaining
    treats "" as falsy so HERMES_ still wins — matching how the constants
    module strips and tests HERMES_HOME today.
    """
    monkeypatch.setenv("LLIAM_HOME", "")
    monkeypatch.setenv("HERMES_HOME", "/old")
    assert env_compat.getenv_compat("HOME") == "/old"
