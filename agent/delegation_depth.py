"""Delegation-depth tracking across process boundaries (``delegation.max_spawn_depth``).

In-process delegation already tracks depth on the agent object
(``AIAgent._delegate_depth``: 0 = top-level, +1 per ``delegate_task`` level).
That counter resets to 0 whenever an agent starts in a *new process* — e.g. a
child that runs ``lliam-gov chat -q ...`` through the terminal tool, or an ACP
subprocess transport. Without propagation, a shell-capable agent could chain
processes and nest without bound regardless of ``max_spawn_depth``.

This module carries the depth across that boundary:

* ``LLIAM_DELEGATE_DEPTH`` (env) — the depth of the agent the receiving process
  hosts. Absent means 0 (a process started by a human, not by an agent).
* ``agent_depth_scope(agent)`` — wraps one agent turn and records the agent's
  *effective* depth (inherited + in-process) in a ContextVar. Tool worker
  threads inherit it via ``tools.thread_context.propagate_context_to_thread``.
* ``apply_subprocess_depth_env(env)`` — called by the subprocess env builders;
  inside an agent turn it stamps ``LLIAM_DELEGATE_DEPTH=<effective depth + 1>``
  so anything the agent spawns starts one level deeper. Outside an agent turn
  (infrastructure spawns: gateway restart, dependency installs) it leaves the
  env untouched.

A malformed inherited value is never silently treated as 0 by callers that
enforce the limit: :func:`inherited_depth` raises :class:`DelegationDepthError`
and strict-posture callers fail closed on it.

Limits: the value is cooperative, like any environment variable — a shell
command can overwrite it. It bounds accidental and model-driven recursion
through the documented spawn paths; it is not a sandbox. Remote terminal
backends (docker/ssh/modal/...) build their own environments and do not
receive it.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator, Optional

#: Environment variable carrying the depth of the agent a process hosts.
ENV_VAR = "LLIAM_DELEGATE_DEPTH"

#: Value stamped into a child env when this process's own depth is unknown
#: (malformed inherited value). The child then fails closed under strict.
INVALID_MARKER = "invalid"

# Sanity bound: no real delegation tree is this deep; larger values are
# treated as malformed rather than trusted.
_MAX_REASONABLE_DEPTH = 1000

_UNSET: Any = object()
_INVALID: Any = object()

_CURRENT_DEPTH: ContextVar[Any] = ContextVar("LLIAM_DELEGATE_DEPTH_CURRENT", default=_UNSET)


class DelegationDepthError(ValueError):
    """The delegation depth could not be determined (malformed input)."""


def _parse_depth(raw: Any, *, source: str) -> int:
    if isinstance(raw, bool):
        raise DelegationDepthError(f"{source}={raw!r} is not a delegation depth")
    if isinstance(raw, int):
        value = raw
    else:
        text = str(raw).strip()
        if not text.isdigit():
            raise DelegationDepthError(f"{source}={raw!r} is not a non-negative integer")
        value = int(text)
    if value < 0 or value > _MAX_REASONABLE_DEPTH:
        raise DelegationDepthError(f"{source}={raw!r} is outside 0..{_MAX_REASONABLE_DEPTH}")
    return value


def inherited_depth() -> int:
    """Depth inherited from the spawning process (0 when not set).

    Raises :class:`DelegationDepthError` when the variable is present but
    malformed.
    """
    raw = os.environ.get(ENV_VAR)
    if raw is None or raw.strip() == "":
        return 0
    return _parse_depth(raw, source=ENV_VAR)


def effective_depth(agent: Any) -> int:
    """Inherited process depth + the agent's in-process ``_delegate_depth``.

    Raises :class:`DelegationDepthError` when either part is malformed.
    """
    local = getattr(agent, "_delegate_depth", 0)
    return inherited_depth() + _parse_depth(local, source="_delegate_depth")


def current_depth() -> Optional[int]:
    """Effective depth of the agent turn running in this context.

    Returns the ContextVar value inside :func:`agent_depth_scope`; otherwise
    the inherited process depth. ``None`` means the depth is unknown
    (malformed input).
    """
    value = _CURRENT_DEPTH.get()
    if value is _INVALID:
        return None
    if value is not _UNSET:
        return value
    try:
        return inherited_depth()
    except DelegationDepthError:
        return None


@contextmanager
def agent_depth_scope(agent: Any) -> Iterator[Optional[int]]:
    """Record ``agent``'s effective depth for the duration of one turn."""
    try:
        depth: Any = effective_depth(agent)
    except DelegationDepthError:
        depth = _INVALID
    token = _CURRENT_DEPTH.set(depth)
    try:
        yield None if depth is _INVALID else depth
    finally:
        _CURRENT_DEPTH.reset(token)


def apply_subprocess_depth_env(env: dict) -> None:
    """Stamp the child depth into ``env`` when called inside an agent turn.

    Outside an agent turn this is a no-op, so infrastructure spawns keep
    whatever the process environment already carries.
    """
    value = _CURRENT_DEPTH.get()
    if value is _UNSET:
        return
    if value is _INVALID:
        env[ENV_VAR] = INVALID_MARKER
        return
    env[ENV_VAR] = str(int(value) + 1)


__all__ = [
    "ENV_VAR",
    "INVALID_MARKER",
    "DelegationDepthError",
    "agent_depth_scope",
    "apply_subprocess_depth_env",
    "current_depth",
    "effective_depth",
    "inherited_depth",
]
