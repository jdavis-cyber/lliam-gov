"""Back-compat re-export; the implementation lives in ``agent.session_context``."""

from agent.session_context import *  # noqa: F401,F403
from agent.session_context import (  # noqa: F401
    _UNSET,
    _VAR_MAP,
    _SESSION_ASYNC_DELIVERY,
    _SESSION_ID,
    _SESSION_KEY,
    _SESSION_PLATFORM,
)
