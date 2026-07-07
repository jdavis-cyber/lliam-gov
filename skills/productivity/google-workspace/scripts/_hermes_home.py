"""Resolve HERMES_HOME for standalone skill scripts.

Skill scripts may run outside the Hermes process (e.g. system Python,
nix env, CI) where ``lliam_constants`` is not importable.  This module
provides the same ``get_lliam_home()`` and ``display_lliam_home()``
contracts as ``lliam_constants`` without requiring it on ``sys.path``.

When ``lliam_constants`` IS available it is used directly so that any
future enhancements (profile resolution, Docker detection, etc.) are
picked up automatically.  The fallback path replicates the core logic
from ``lliam_constants.py`` using only the stdlib.

All scripts under ``google-workspace/scripts/`` should import from here
instead of duplicating the ``HERMES_HOME = Path(os.getenv(...))`` pattern.
"""

from __future__ import annotations

import os
from pathlib import Path

try:
    from lliam_constants import display_lliam_home as display_lliam_home
    from lliam_constants import get_lliam_home as get_lliam_home
except (ModuleNotFoundError, ImportError):

    def get_lliam_home() -> Path:
        """Return the Hermes home directory (default: ~/.hermes).

        Mirrors ``lliam_constants.get_lliam_home()``."""
        val = os.environ.get("HERMES_HOME", "").strip()
        return Path(val) if val else Path.home() / ".hermes"

    def display_lliam_home() -> str:
        """Return a user-friendly ``~/``-shortened display string.

        Mirrors ``lliam_constants.display_lliam_home()``."""
        home = get_lliam_home()
        try:
            return "~/" + str(home.relative_to(Path.home()))
        except ValueError:
            return str(home)
