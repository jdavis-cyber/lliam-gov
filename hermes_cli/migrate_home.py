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


def migrate_if_needed(old_home, new_home) -> None:
    """Copy ``old_home`` -> ``new_home`` exactly once, if it is safe to do so.

    No-op (returns without touching the filesystem) when any of:
      * ``old_home`` and ``new_home`` resolve to the same path — the effective
        home already IS the old home (HERMES_HOME set, LLIAM_HOME unset), so a
        copy would be onto itself;
      * ``new_home`` already exists — migration already ran, or a fresh new-home
        install is in progress; never overwrite;
      * ``old_home`` does not exist — nothing to migrate.

    Otherwise copies the whole tree (copy, not move — leave the rollback source
    intact) and drops a stamp file so the copy is diagnosable and idempotent.
    """
    old_home, new_home = Path(old_home), Path(new_home)

    # old == new: the effective home is the legacy home. Copying onto itself
    # must be impossible. Compare on resolved paths so "/x/" (str) and Path("/x")
    # are recognised as the same directory.
    if old_home.resolve() == new_home.resolve():
        return

    if new_home.exists() or not old_home.exists():
        return

    shutil.copytree(old_home, new_home)  # copy, don't move — keep rollback source
    (new_home / _MIGRATION_STAMP).write_text("migrated by Lliam-GOV rename\n")
