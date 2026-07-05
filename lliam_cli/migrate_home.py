"""One-time migration of on-disk data from the pre-rename home.

Sole Lliam-owned module permitted to name the old identifier. Callers pass the
SAME resolved old/new home paths that the constants module computes (honoring
LLIAM_HOME / HERMES_HOME / active profile), so isolated and profile homes migrate
correctly and the operator's real ~/.hermes is never touched during isolated runs.

Never invoked at import time — only from an explicit startup call site (see
``hermes_cli/main.py:main``). Importing this module must not touch the filesystem.
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
