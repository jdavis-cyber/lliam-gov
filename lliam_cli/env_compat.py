"""Env-var compatibility shim for the hermes -> lliam rename.

Transition aid: read the ``LLIAM_``-prefixed variable first, fall back to the
legacy ``HERMES_``-prefixed variable, then a caller-supplied default. This lets
new operators use ``LLIAM_*`` while existing deployments (and the entire test
suite, which isolates via ``HERMES_HOME``) keep working unchanged.

Only the HOME variable is routed through this helper in Task R.1. Other
``HERMES_*`` vars are swept in later rename tasks — do not convert them here.
"""

import os


def getenv_compat(suffix: str, default: str | None = None) -> str | None:
    """Return ``LLIAM_<suffix>`` if set-and-nonempty, else ``HERMES_<suffix>``, else ``default``.

    Empty-string values are treated as unset (falsy), matching how the constants
    module strips and tests ``HERMES_HOME`` today.
    """
    return os.getenv(f"LLIAM_{suffix}") or os.getenv(f"HERMES_{suffix}") or default
