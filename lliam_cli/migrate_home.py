"""One-time migration of on-disk data from the pre-rename home.

Sole Lliam-owned module permitted to name the old identifier. Callers pass the
SAME resolved old/new home paths that the constants module computes (honoring
LLIAM_HOME / HERMES_HOME / active profile), so isolated and profile homes migrate
correctly and the operator's real ~/.hermes is never touched during isolated runs.

Never invoked at import time — only from an explicit startup call site (see
``lliam_cli/main.py:main``). Importing this module must not touch the filesystem.

Credential-store survey (Task R.6, hermes -> lliam rename)
----------------------------------------------------------
No Lliam-owned OS-keychain service name exists, so there is nothing to rename
and no credential migration to add beyond this home-directory copy. Every
credential path was mapped; all are either file-based under the data home (which
this module already migrates) or owned by an external provider whose identity we
must not rewrite:

  * Lliam's own secrets are file-based under the data home. The ``lliam secrets``
    / Bitwarden Secrets Manager config lives in ``<home>/config.yaml`` under the
    ``secrets:`` key (``lliam_cli/env_loader.py:359`` ``_load_secrets_config``);
    the actual secrets live in Bitwarden's cloud, fetched via a token env var.
    API keys resolve from env / dotenv under the home (``lliam_cli/auth.py``,
    ``lliam_cli/env_loader.py``). All of this is inside the migrated home tree —
    no keychain service name is involved.
  * The macOS Keychain is touched only to READ (and clear) *Claude Code's*
    credentials under Anthropic's service name ``"Claude Code-credentials"``
    (``agent/anthropic_adapter.py:889``, ``lliam_cli/web_server.py:6245``). That
    is a third-party integration identity, not a Lliam identity — renaming it
    would break the integration. Out of scope, intentionally unchanged.
  * There is NO Python ``keyring``/``keytar`` usage and NO Lliam-owned
    ``add-generic-password`` write anywhere in the tree.

Electron ``safeStorage`` caveat (honest impact statement): the desktop shell
encrypts exactly one secret — the remote-gateway auth token stored in
``connection.json`` (``apps/desktop/electron/main.cjs`` ``encryptDesktopSecret``
/ ``decryptDesktopSecret``). On macOS, ``safeStorage`` keys its AES key to a
Keychain entry named ``"<productName> Safe Storage"``. Because R.2 changed
``productName`` from ``"Hermes"`` to ``"Lliam-GOV"``, any token encrypted by a
pre-rename build under ``"Hermes Safe Storage"`` is undecryptable by the renamed
build. This is accepted data loss for a pre-release demo app: ``decryptDesktopSecret``
returns ``""`` on failure (never crashes), the connection simply falls back to
prompting for the token or reading ``LLIAM_DESKTOP_REMOTE_TOKEN`` from the
environment, and the affected value is a re-enterable gateway token, not
irreplaceable user data. No migration is attempted because safeStorage exposes
no cross-key re-encryption path and the only user of the desktop build is a
fresh install.
"""

import shutil
from pathlib import Path

_MIGRATION_STAMP = ".migrated_from_hermes"
_MIGRATING_SUFFIX = ".migrating"


def migrate_if_needed(old_home, new_home) -> None:
    """Copy ``old_home`` -> ``new_home`` exactly once, if it is safe to do so.

    No-op (returns without touching ``old_home`` or ``new_home``) when any of:
      * ``old_home`` and ``new_home`` resolve to the same path — the effective
        home already IS the old home (HERMES_HOME set, LLIAM_HOME unset), so a
        copy would be onto itself;
      * ``new_home`` already exists — migration already ran, or a fresh new-home
        install is in progress; never overwrite;
      * ``old_home`` does not exist — nothing to migrate.

    Otherwise copies the whole tree (copy, not move — leave the rollback source
    intact) and drops a stamp file so the copy is diagnosable and idempotent.

    Crash safety: the tree is staged to a sibling temp path
    (``<new_home>.migrating``) and only renamed into place once the copy and
    stamp completed. An interrupted copy (disk full, permission error, power
    loss) therefore leaves ``new_home`` absent — the ``new_home.exists()``
    guard can never latch onto a half-populated home — and the next launch
    discards the stale staging dir and retries cleanly.
    """
    old_home, new_home = Path(old_home), Path(new_home)

    # old == new: the effective home is the legacy home. Copying onto itself
    # must be impossible. Compare on resolved paths so "/x/" (str) and Path("/x")
    # are recognised as the same directory.
    if old_home.resolve() == new_home.resolve():
        return

    if new_home.exists() or not old_home.exists():
        return

    # Stage into a sibling temp dir, then rename into place (same-directory
    # rename: atomic on POSIX). A stale staging dir left by a previously
    # interrupted run is discarded first — it is by definition incomplete.
    staging = new_home.parent / (new_home.name + _MIGRATING_SUFFIX)
    if staging.exists():
        shutil.rmtree(staging)

    try:
        shutil.copytree(old_home, staging)  # copy, don't move — keep rollback source
        (staging / _MIGRATION_STAMP).write_text("migrated by Lliam-GOV rename\n")
    except BaseException:
        # Interrupted copy: remove the partial staging tree so new_home stays
        # absent and the next launch retries from scratch.
        shutil.rmtree(staging, ignore_errors=True)
        raise

    staging.rename(new_home)
