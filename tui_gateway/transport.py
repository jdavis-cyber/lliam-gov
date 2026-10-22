"""Transport abstraction for the tui_gateway JSON-RPC server.

Historically the gateway wrote every JSON frame directly to real stdout.  This
module decouples the I/O sink from the handler logic so the same dispatcher
can be driven over stdio (``tui_gateway.entry``) or WebSocket
(``tui_gateway.ws``) without duplicating code.

A :class:`Transport` is anything that can accept a JSON-serialisable dict and
forward it to its peer.  The active transport for the current request is
tracked in a :class:`contextvars.ContextVar` so handlers — including those
dispatched onto the worker pool — route their writes to the right peer.

Backward compatibility
----------------------
``tui_gateway.server.write_json`` still works without any transport bound.
When nothing is on the contextvar and no session-level transport is found,
it falls back to the module-level :class:`StdioTransport`, which wraps the
original ``_real_stdout`` + ``_stdout_lock`` pair.  Tests that monkey-patch
``server._real_stdout`` continue to work because the stdio transport resolves
the stream lazily through a callback.
"""

from __future__ import annotations

import contextvars
import errno
import hmac
import json
import logging
import os
import secrets
from lliam_cli.env_compat import getenv_compat
import threading
from typing import Any, Callable, Optional, Protocol, runtime_checkable

# Errno values that mean "the peer is gone" rather than "the host has a
# real I/O problem".  Anything outside this set re-raises so it surfaces
# in the crash log instead of looking like a clean disconnect.
_PEER_GONE_ERRNOS = frozenset({
    errno.EPIPE,        # write to closed pipe (POSIX)
    errno.ECONNRESET,   # peer reset the connection
    errno.EBADF,        # fd closed under us
    errno.ESHUTDOWN,    # transport endpoint shut down
    getattr(errno, "WSAECONNRESET", -1),  # win32 mapping (no-op on POSIX)
    getattr(errno, "WSAESHUTDOWN", -1),
} - {-1})

logger = logging.getLogger(__name__)

# Optional knob: when true, StdioTransport does not call ``stream.flush``
# after writing.  Use this on environments where a half-closed pipe (TUI
# Node parent quit while the gateway is still emitting events) makes
# flush block long enough to starve the rest of the worker pool.
#
# IMPORTANT: Python text stdout is fully buffered when attached to a
# pipe (the TUI case), so this knob ONLY makes sense when the gateway
# is launched with ``-u`` or ``PYTHONUNBUFFERED=1``.  Without one of
# those, JSON-RPC frames will accumulate in the buffer and the TUI
# will hang waiting for ``gateway.ready``.  Default stays off so the
# existing flush-after-write behaviour is unchanged.
_DISABLE_FLUSH = (getenv_compat("TUI_GATEWAY_NO_FLUSH", "") or "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}


# ── Caller authentication for socket transports (JER-73) ─────────────
#
# The stdio transport needs no handshake: ``tui_gateway.entry`` reads
# requests from an anonymous pipe that only its spawning parent (the Ink
# TUI) holds. The WebSocket transport (``tui_gateway.ws``) is a socket on
# loopback, and the dashboard's loopback ``?token=`` credential is served to
# any local process inside index.html — so under strict posture a socket
# peer that authenticated only with that token must also present this
# per-launch gateway secret.
#
# The secret never appears in HTML or on any HTTP endpoint. It is either
# pinned by the parent that spawns the dashboard (the desktop shell sets
# ``LLIAM_TUI_GATEWAY_SECRET`` in the child env and puts the same value in
# its own renderer's WS URL), or minted here per process. Comparison is
# constant time.
#
# Holding the secret is also what identifies the local operator: only the
# process that spawned this backend (the desktop shell) knows it, so a
# connection that presents it is bound as the ``local-operator`` principal
# and may approve HITL requests (LG-GV-05, see :func:`local_operator_subject`).
#
# PTY children the dashboard spawns get a *different* per-process secret,
# the child secret (``?gw_child=``). It passes the strict handshake but does
# not identify the operator: ``/api/pty`` itself accepts the loopback token
# from index.html, so whoever opened the PTY is not known to be the operator.

#: WS-upgrade query parameter carrying the gateway secret.
GATEWAY_SECRET_PARAM = "gw_secret"
#: WS-upgrade query parameter carrying the handshake-only PTY child secret.
GATEWAY_CHILD_SECRET_PARAM = "gw_child"
#: Authentication method recorded for the local operator principal.
LOCAL_OPERATOR_AUTH = "desktop-launch-secret"
#: Env var a spawning parent uses to pin the secret (LLIAM_ first, HERMES_ legacy).
GATEWAY_SECRET_ENV_SUFFIX = "TUI_GATEWAY_SECRET"
GATEWAY_SECRET_ENV_NAMES = (
    f"LLIAM_{GATEWAY_SECRET_ENV_SUFFIX}",
    f"HERMES_{GATEWAY_SECRET_ENV_SUFFIX}",
)

_gateway_secret_lock = threading.Lock()
_gateway_secret: Optional[str] = None
_gateway_child_secret: Optional[str] = None


def _adopt_pinned_gateway_secret() -> Optional[str]:
    """Take the parent-pinned secret from the env and remove it.

    Removing it keeps the value out of every subprocess this process spawns
    later (terminal tools, PTY children) — those get it only when we hand it
    to them deliberately.
    """
    pinned = getenv_compat(GATEWAY_SECRET_ENV_SUFFIX)
    for name in GATEWAY_SECRET_ENV_NAMES:
        os.environ.pop(name, None)
    pinned = (pinned or "").strip()
    return pinned or None


_gateway_secret = _adopt_pinned_gateway_secret()


def gateway_secret() -> str:
    """Return the per-launch gateway secret, minting it on first use."""
    global _gateway_secret
    with _gateway_secret_lock:
        if _gateway_secret is None:
            _gateway_secret = secrets.token_urlsafe(32)
        return _gateway_secret


def verify_gateway_secret(presented: Optional[str]) -> bool:
    """Constant-time check of *presented* against the per-launch secret."""
    if not presented:
        return False
    return hmac.compare_digest(
        str(presented).encode("utf-8"), gateway_secret().encode("utf-8")
    )


def gateway_child_secret() -> str:
    """Return the per-process PTY child secret, minting it on first use.

    Never pinned from the env and never equal to :func:`gateway_secret`.
    """
    global _gateway_child_secret
    with _gateway_secret_lock:
        if _gateway_child_secret is None:
            _gateway_child_secret = secrets.token_urlsafe(32)
        return _gateway_child_secret


def verify_gateway_child_secret(presented: Optional[str]) -> bool:
    """Constant-time check of *presented* against the PTY child secret."""
    if not presented:
        return False
    return hmac.compare_digest(
        str(presented).encode("utf-8"), gateway_child_secret().encode("utf-8")
    )


def local_operator_principal() -> str:
    """``local-operator:<os-user>@<host>`` for the account running this backend."""
    import getpass
    import socket

    try:
        user = getpass.getuser()
    except Exception:
        user = ""
    try:
        host = socket.gethostname()
    except Exception:
        host = ""
    return f"local-operator:{user or 'unknown'}@{host or 'localhost'}"


def local_operator_subject() -> dict:
    """Operator subject bound to a connection that presented the gateway secret.

    The desktop shell is the only holder of the secret, so the connection is
    the local operator's own desktop app (LG-GV-05). Approvals made over it
    are recorded with this principal.
    """
    return {"principal": local_operator_principal(), "auth": LOCAL_OPERATOR_AUTH}


def handshake_required() -> bool:
    """True when socket peers must prove the gateway secret (strict posture).

    Low-side (non-strict) deployments keep the existing behaviour.
    """
    try:
        from lliam_cli import config as _cfg
        from lliam_cli import posture_resolver as _pr

        return _pr.is_strict(_cfg.load_config())
    except Exception:
        return False


def _reset_gateway_secret_for_tests(
    value: Optional[str] = None, child: Optional[str] = None
) -> None:
    global _gateway_secret, _gateway_child_secret
    with _gateway_secret_lock:
        _gateway_secret = value
        _gateway_child_secret = child


@runtime_checkable
class Transport(Protocol):
    """Minimal interface every transport implements."""

    def write(self, obj: dict) -> bool:
        """Emit one JSON frame. Return ``False`` when the peer is gone."""

    def close(self) -> None:
        """Release any resources owned by this transport."""


_current_transport: contextvars.ContextVar[Optional[Transport]] = (
    contextvars.ContextVar(
        "hermes_gateway_transport",
        default=None,
    )
)


def current_transport() -> Optional[Transport]:
    """Return the transport bound for the current request, if any."""
    return _current_transport.get()


def bind_transport(transport: Optional[Transport]):
    """Bind *transport* for the current context. Returns a token for :func:`reset_transport`."""
    return _current_transport.set(transport)


def reset_transport(token) -> None:
    """Restore the transport binding captured by :func:`bind_transport`."""
    _current_transport.reset(token)


class StdioTransport:
    """Writes JSON frames to a stream (usually ``sys.stdout``).

    The stream is resolved via a callable so runtime monkey-patches of the
    underlying stream continue to work — this preserves the behaviour the
    existing test suite relies on (``monkeypatch.setattr(server, "_real_stdout", ...)``).
    """

    __slots__ = ("_stream_getter", "_lock")

    def __init__(self, stream_getter: Callable[[], Any], lock: threading.Lock) -> None:
        self._stream_getter = stream_getter
        self._lock = lock

    def write(self, obj: dict) -> bool:
        """Return ``True`` on success, ``False`` ONLY when the peer is gone.

        Returning ``False`` is the dispatcher's "broken stdout pipe" signal
        — ``entry.py`` calls ``sys.exit(0)`` when ``write_json`` reports
        ``False``.  So programming errors (non-JSON-safe payloads, encoding
        misconfig, unexpected ValueErrors, host I/O bugs like ENOSPC) MUST
        NOT return ``False``, otherwise a real bug looks like a clean
        disconnect and is harder to diagnose.  Those re-raise so the
        existing crash-log infrastructure records the traceback.

        Peer-gone branches:
          * ``BrokenPipeError``
          * ``ValueError("...closed file...")``
          * ``OSError`` whose errno is in :data:`_PEER_GONE_ERRNOS`
            (EPIPE / ECONNRESET / EBADF / ESHUTDOWN; plus WSA mappings
            on Windows).  Other OSError errnos (ENOSPC, EACCES, ...) are
            real host problems and re-raise.
        """
        # Serialization is OUTSIDE the lock so a large payload can't
        # block other threads emitting their own frames.  A non-JSON-safe
        # payload is a programming error: re-raise so the crash log
        # captures it instead of silently exiting via the False path.
        line = json.dumps(obj, ensure_ascii=False) + "\n"

        with self._lock:
            stream = self._stream_getter()
            try:
                stream.write(line)
            except BrokenPipeError:
                return False
            except ValueError as e:
                # ValueError("I/O operation on closed file") is the
                # ONLY ValueError that means "peer gone".  Anything
                # else — including UnicodeEncodeError, which is a
                # ValueError subclass for misconfigured locales —
                # is a real bug; re-raise so it surfaces in the crash log.
                if isinstance(e, UnicodeEncodeError) or "closed file" not in str(e):
                    raise
                return False
            except OSError as e:
                if e.errno not in _PEER_GONE_ERRNOS:
                    raise
                logger.debug("StdioTransport write peer gone: %s", e)
                return False

            # A flush that *raises* with a peer-gone errno means the
            # dispatcher should exit cleanly.  A flush that *hangs* on
            # a half-closed pipe holds the lock until it returns — see
            # ``_DISABLE_FLUSH`` for the "skip flush entirely" escape
            # hatch.
            if not _DISABLE_FLUSH:
                try:
                    stream.flush()
                except BrokenPipeError:
                    return False
                except ValueError as e:
                    if isinstance(e, UnicodeEncodeError) or "closed file" not in str(e):
                        raise
                    return False
                except OSError as e:
                    if e.errno not in _PEER_GONE_ERRNOS:
                        raise
                    logger.debug("StdioTransport flush peer gone: %s", e)
                    return False

        return True

    def close(self) -> None:
        return None


class TeeTransport:
    """Mirrors writes to one primary plus N best-effort secondaries.

    The primary's return value (and exceptions) determine the result —
    secondaries swallow failures so a wedged sidecar never stalls the
    main IO path.  Used by the PTY child so every dispatcher emit lands
    on stdio (Ink) AND on a back-WS feeding the dashboard sidebar.
    """

    __slots__ = ("_primary", "_secondaries")

    def __init__(self, primary: "Transport", *secondaries: "Transport") -> None:
        self._primary = primary
        self._secondaries = secondaries

    def write(self, obj: dict) -> bool:
        # Primary first so a slow sidecar (WS publisher) never delays Ink/stdio.
        ok = self._primary.write(obj)
        for sec in self._secondaries:
            try:
                sec.write(obj)
            except Exception:
                pass
        return ok

    def close(self) -> None:
        try:
            self._primary.close()
        finally:
            for sec in self._secondaries:
                try:
                    sec.close()
                except Exception:
                    pass
