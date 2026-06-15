"""Common provider capability contract for CLI-backed providers (AI-327).

Defines the application-level contract between Lliam-GOV and external LLM CLIs
so providers are not treated like API-key-backed SDKs:

* capability model — installed, authenticated, model list, default model,
  prompt execution, streaming, cancellation, working directory, env isolation,
  and an error taxonomy;
* normalized readiness — a single ``Readiness`` value derived from detect/auth
  probes, reportable without any API key;
* a ``ProviderReadinessReport`` shape that the backend (``/api/model/options``)
  and desktop first-run UX can render directly.

Token safety (AI-334): nothing in this module reads or stores provider secrets.
``AuthResult`` carries only a boolean ``authenticated`` signal plus a non-secret
source label — never the token value.
"""

from __future__ import annotations

import enum
import os
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Callable, Protocol, runtime_checkable

# ── Subprocess hardening constants (AI-334) ───────────────────────────────────
#
# Explicit env allowlist for provider subprocesses. When a request opts into
# env isolation (the default), the child process inherits ONLY these variables
# from the parent environment. Everything else — including any Lliam-GOV secrets
# or stray ``*_API_KEY`` values — is dropped. The provider CLI's own auth store
# lives under ``HOME`` (or an ``XDG_*`` dir), which is why those are allowed.
# Deliberately excluded: every ``ANTHROPIC_*`` / ``OPENAI_*`` / ``GOOGLE_*`` /
# ``*_API_KEY`` / ``*_TOKEN`` variable — the CLI owns auth, not the env (AI-334).
ENV_ALLOWLIST: tuple[str, ...] = (
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "TMPDIR",
    "TZ",
    # Config/data roots some CLIs use for their (CLI-owned) auth stores.
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    # Windows equivalents (parked posture-guard work owns full Windows support).
    "APPDATA",
    "LOCALAPPDATA",
    "USERPROFILE",
    "SYSTEMROOT",
)

#: Default cap on combined stdout+stderr bytes captured from a provider
#: subprocess. Prevents a runaway/compromised CLI from exhausting memory or
#: flooding logs. Overridable per request.
DEFAULT_MAX_OUTPUT_BYTES = 2_000_000


def build_isolated_env(
    allowlist: tuple[str, ...] = ENV_ALLOWLIST,
    *,
    base: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build a minimal child environment from the allowlist only.

    Pure/inspectable so the boundary is unit-testable: given a base env, the
    output contains exactly the intersection with ``allowlist`` and nothing
    secret-looking. Never raises.
    """
    src = os.environ if base is None else base
    return {k: src[k] for k in allowlist if k in src}


class Readiness(str, enum.Enum):
    """Normalized provider readiness — surfaced without requiring API keys."""

    NOT_INSTALLED = "not_installed"
    NOT_AUTHENTICATED = "not_authenticated"
    READY = "ready"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class ProviderErrorKind(str, enum.Enum):
    """Error taxonomy distinguishing the four failure surfaces (AI-329 copy)."""

    APP_SETUP = "app_setup"                      # Lliam-GOV/backend misconfig
    PROVIDER_NOT_INSTALLED = "provider_not_installed"
    PROVIDER_AUTH = "provider_auth"              # CLI present but not logged in
    PROVIDER_RATE_LIMIT = "provider_rate_limit"  # provider throttled us
    PROVIDER_EXECUTION = "provider_execution"    # CLI ran but failed
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    OUTPUT_LIMIT = "output_limit"                # CLI exceeded output-size cap


class InvocationMode(str, enum.Enum):
    """How the provider CLI is driven."""

    NON_INTERACTIVE = "non_interactive"  # one-shot subprocess, capture stdout
    INTERACTIVE = "interactive"          # long-lived interactive session
    ADAPTER_SHIM = "adapter_shim"        # local shim translates protocol


@dataclass(frozen=True)
class ProviderError:
    """Structured, user-actionable provider error."""

    kind: ProviderErrorKind
    message: str
    remediation: str = ""
    retryable: bool = False


@dataclass(frozen=True)
class DetectResult:
    """Result of probing whether the provider CLI is installed."""

    installed: bool
    path: str | None = None
    version: str | None = None


@dataclass(frozen=True)
class AuthResult:
    """Result of probing auth state.

    AI-334: ``authenticated`` is a boolean *signal* only. ``source`` is a
    non-secret label (e.g. ``"claude_code_cli_credentials"``). The token value
    is never read into this object.
    """

    authenticated: bool
    source: str = ""
    detail: str = ""
    expired: bool = False


@dataclass(frozen=True)
class HealthResult:
    """Result of an end-to-end readiness probe."""

    readiness: "Readiness"
    error: ProviderError | None = None


@dataclass(frozen=True)
class ProviderCapabilities:
    """Static declaration of what a provider adapter supports."""

    id: str
    display_name: str
    invocation_mode: InvocationMode
    supports_streaming: bool = False
    supports_cancellation: bool = False
    supports_model_list: bool = False
    # The provider CLI owns auth; Lliam-GOV never stores tokens (AI-334).
    owns_auth: bool = True


@dataclass(frozen=True)
class ProviderReadinessReport:
    """Full readiness snapshot for one provider — backend/UX render this."""

    id: str
    display_name: str
    readiness: Readiness
    detect: DetectResult
    auth: AuthResult
    models: tuple[str, ...] = ()
    default_model: str | None = None
    capabilities: ProviderCapabilities | None = None
    error: ProviderError | None = None
    setup_hint: str = ""  # exact CLI command(s) to run — never an API key
    checked_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        """JSON-safe dict for ``/api/model/options`` and desktop endpoints."""
        return asdict(self)


def normalize_readiness(detect: DetectResult, auth: AuthResult) -> Readiness:
    """Collapse detect + auth probes into a single readiness value.

    This is the heart of the contract (AI-327: "provider readiness
    normalization from mocked CLI probes"). Pure function — no I/O — so it can
    be exhaustively unit-tested against synthetic probe results.
    """
    if not detect.installed:
        return Readiness.NOT_INSTALLED
    if not auth.authenticated or auth.expired:
        return Readiness.NOT_AUTHENTICATED
    return Readiness.READY


@runtime_checkable
class CLIProvider(Protocol):
    """Structural interface every CLI-backed provider adapter satisfies."""

    @property
    def capabilities(self) -> ProviderCapabilities: ...

    def detect(self) -> DetectResult: ...

    def check_auth(self) -> AuthResult: ...

    def list_models(self) -> tuple[str, ...]: ...

    def default_model(self) -> str | None: ...

    def probe(self) -> ProviderReadinessReport: ...


@dataclass(frozen=True)
class ExecutionRequest:
    """A one-shot prompt-execution request against a provider CLI."""

    prompt: str
    model: str | None = None
    # Explicit working directory. When None, the runtime allocates a fresh,
    # empty, per-execution temp dir (AI-334: never silently inherit Lliam-GOV's
    # checkout cwd, which would expose the source tree / enable path hijack).
    cwd: str | None = None
    timeout_s: float = 120.0
    # Extra env *isolation* hint: when True the adapter starts from the minimal
    # ``ENV_ALLOWLIST`` env rather than inheriting the full parent environment.
    isolate_env: bool = True
    # Cap on combined stdout+stderr bytes captured before the runtime aborts the
    # subprocess with an OUTPUT_LIMIT error (AI-334 output-size limit).
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES


@dataclass(frozen=True)
class ExecutionResult:
    """Normalized result of a one-shot execution."""

    ok: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    error: ProviderError | None = None


class ResultEventKind(str, enum.Enum):
    """Kinds of normalized streaming result events (AI-327)."""

    TEXT = "text"                       # assistant text/token chunk
    TOOL_CALL = "tool_call"             # provider invoked a tool (structured)
    COMMAND_OUTPUT = "command_output"   # output from a command the provider ran
    ERROR = "error"                     # a ProviderError occurred
    DONE = "done"                       # terminal; data has ok/exit_code/stderr


@dataclass(frozen=True)
class ResultEvent:
    """One normalized event in a streaming execution."""

    kind: ResultEventKind
    text: str = ""
    data: dict | None = None
    error: ProviderError | None = None


class CancelToken:
    """Cooperative cancellation signal for streaming execution."""

    def __init__(self) -> None:
        import threading

        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


class BaseCLIProvider(ABC):
    """Reusable base implementing the contract from a few primitive probes.

    Subclasses provide ``capabilities``, ``detect`` and ``check_auth``; this
    base wires up ``probe()`` (detect + auth → normalized readiness + setup
    hints + error) and a default ``execute()`` skeleton with timeout,
    cancellation, cwd, env isolation, stdout/stderr capture, and structured
    error mapping.
    """

    #: Human-facing command to install the provider CLI (no API keys).
    install_hint: str = ""
    #: Human-facing command to authenticate the provider CLI (no API keys).
    auth_hint: str = ""
    #: Optional audit sink. Receives a *content-free, redacted* summary dict on
    #: every execution failure so failures are audit-visible without leaking
    #: prompt/output/secrets (AI-334). Set by the host (e.g. backend wires it to
    #: the governance audit log). Never receives raw stdout or the prompt.
    audit_hook: "Callable[[dict], None] | None" = None

    def _emit_audit(self, summary: dict) -> None:
        """Best-effort dispatch to ``audit_hook``; never raises into the stream."""
        hook = self.audit_hook
        if hook is None:
            return
        try:
            hook(summary)
        except Exception:  # pragma: no cover - audit must never break execution
            pass

    def _audit_failure(self, error: "ProviderError", stderr: str, exit_code) -> None:
        from providers.cli.redaction import redacted_snippet

        self._emit_audit(
            {
                "event": "provider_execution_failure",
                "provider": self.capabilities.id,
                "error_kind": error.kind.value,
                "exit_code": exit_code,
                # Redacted + truncated — safe to persist in an audit record.
                "stderr_snippet": redacted_snippet(stderr),
            }
        )

    @property
    @abstractmethod
    def capabilities(self) -> ProviderCapabilities: ...

    @abstractmethod
    def detect(self) -> DetectResult: ...

    @abstractmethod
    def check_auth(self) -> AuthResult: ...

    # Optional surface — sensible defaults for providers that don't expose them.
    def list_models(self) -> tuple[str, ...]:
        return ()

    def default_model(self) -> str | None:
        return None

    def _setup_hint(self, readiness: Readiness) -> str:
        if readiness is Readiness.NOT_INSTALLED:
            return self.install_hint
        if readiness is Readiness.NOT_AUTHENTICATED:
            return self.auth_hint
        return ""

    def _readiness_error(self, readiness: Readiness) -> ProviderError | None:
        if readiness is Readiness.NOT_INSTALLED:
            return ProviderError(
                kind=ProviderErrorKind.PROVIDER_NOT_INSTALLED,
                message=f"{self.capabilities.display_name} CLI is not installed.",
                remediation=self.install_hint,
            )
        if readiness is Readiness.NOT_AUTHENTICATED:
            return ProviderError(
                kind=ProviderErrorKind.PROVIDER_AUTH,
                message=f"{self.capabilities.display_name} CLI is not authenticated.",
                remediation=self.auth_hint,
            )
        return None

    def probe(self) -> ProviderReadinessReport:
        """Run detect + auth probes and normalize into a readiness report."""
        detect = self.detect()
        auth = self.check_auth() if detect.installed else AuthResult(authenticated=False)
        readiness = normalize_readiness(detect, auth)
        models = self.list_models() if readiness is Readiness.READY else ()
        return ProviderReadinessReport(
            id=self.capabilities.id,
            display_name=self.capabilities.display_name,
            readiness=readiness,
            detect=detect,
            auth=auth,
            models=tuple(models),
            default_model=self.default_model(),
            capabilities=self.capabilities,
            error=self._readiness_error(readiness),
            setup_hint=self._setup_hint(readiness),
        )

    # ── Execution runtime: streaming, cancellable, normalized ─────────────
    def _build_argv(self, request: ExecutionRequest) -> list[str]:  # pragma: no cover
        raise NotImplementedError

    def _parse_stdout_line(self, line: str) -> "ResultEvent | None":
        """Map a raw stdout line to a normalized event.

        Default: each line is a text chunk. Adapters that emit structured
        output (e.g. ``--output-format stream-json``) override this to also
        emit ``TOOL_CALL`` / ``COMMAND_OUTPUT`` events.
        """
        return ResultEvent(kind=ResultEventKind.TEXT, text=line)

    def _classify_failure(self, stderr: str, returncode: int) -> ProviderError:
        """Map a non-zero exit + stderr into the error taxonomy."""
        low = (stderr or "").lower()
        if any(s in low for s in ("rate limit", "ratelimit", "429", "quota", "overloaded")):
            return ProviderError(
                ProviderErrorKind.PROVIDER_RATE_LIMIT,
                "Provider rate-limited the request.",
                retryable=True,
            )
        if any(s in low for s in ("unauthor", "not logged in", "please run", "login", "401", "403", "authenticat")):
            return ProviderError(
                ProviderErrorKind.PROVIDER_AUTH,
                "Provider rejected auth — re-run the CLI login.",
                remediation=self.auth_hint,
            )
        return ProviderError(
            ProviderErrorKind.PROVIDER_EXECUTION,
            f"Provider CLI exited {returncode}.",
        )

    def stream(self, request: ExecutionRequest, *, cancel: "CancelToken | None" = None):
        """Execute a prompt, yielding normalized ``ResultEvent``s as they arrive.

        Spawns the provider CLI as a subprocess, streams stdout line-by-line,
        honors cancellation and timeout, isolates env (PATH/HOME only when
        ``isolate_env``), and ends with exactly one ``DONE`` event carrying
        ``ok`` / ``exit_code`` / ``stderr``. The provider CLI owns auth — we
        never read tokens (AI-334); we only spawn the already-authed CLI.
        """
        import queue
        import shutil
        import subprocess
        import tempfile
        import threading
        import time

        report = self.probe()
        if report.readiness is not Readiness.READY:
            err = report.error or ProviderError(
                ProviderErrorKind.APP_SETUP, "Provider is not ready."
            )
            yield ResultEvent(kind=ResultEventKind.ERROR, error=err)
            yield ResultEvent(
                kind=ResultEventKind.DONE,
                data={"ok": False, "exit_code": None, "stderr": ""},
            )
            return

        argv = self._build_argv(request)
        # AI-334: env allowlist — isolate to ENV_ALLOWLIST or pass full env only
        # when the caller explicitly opts out of isolation.
        env = build_isolated_env() if request.isolate_env else None

        # AI-334: explicit cwd. Never inherit Lliam-GOV's process cwd; when the
        # caller gives no cwd, run in a fresh empty per-execution temp dir that
        # we remove afterwards (mitigates malicious-cwd / path-hijack).
        owns_tmp = request.cwd is None
        cwd = tempfile.mkdtemp(prefix="lliam-prov-") if owns_tmp else request.cwd

        def _cleanup_tmp() -> None:
            if owns_tmp:
                shutil.rmtree(cwd, ignore_errors=True)

        try:
            try:
                proc = subprocess.Popen(
                    argv,
                    cwd=cwd,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
            except FileNotFoundError:
                yield ResultEvent(
                    kind=ResultEventKind.ERROR,
                    error=ProviderError(
                        ProviderErrorKind.PROVIDER_NOT_INSTALLED,
                        "Provider CLI vanished between probe and execute.",
                        remediation=self.install_hint,
                    ),
                )
                yield ResultEvent(
                    kind=ResultEventKind.DONE,
                    data={"ok": False, "exit_code": None, "stderr": ""},
                )
                return

            q: queue.Queue = queue.Queue()

            def _pump(stream, tag):
                try:
                    for line in stream:
                        q.put((tag, line))
                finally:
                    q.put((tag, None))

            for tag, st in (("out", proc.stdout), ("err", proc.stderr)):
                threading.Thread(target=_pump, args=(st, tag), daemon=True).start()

            deadline = time.monotonic() + request.timeout_s
            open_streams = 2
            stderr_parts: list[str] = []
            cancelled = False
            timed_out = False
            output_overflow = False
            output_bytes = 0
            max_bytes = max(0, int(request.max_output_bytes))

            while open_streams > 0:
                if cancel is not None and cancel.cancelled:
                    cancelled = True
                    break
                if time.monotonic() > deadline:
                    timed_out = True
                    break
                try:
                    tag, line = q.get(timeout=0.05)
                except queue.Empty:
                    continue
                if line is None:
                    open_streams -= 1
                    continue
                # AI-334: output-size limit across stdout+stderr combined.
                if max_bytes and output_bytes >= max_bytes:
                    output_overflow = True
                    break
                output_bytes += len(line.encode("utf-8", "replace"))
                if tag == "out":
                    ev = self._parse_stdout_line(line.rstrip("\n"))
                    if ev is not None:
                        yield ev
                else:
                    stderr_parts.append(line)
                if max_bytes and output_bytes >= max_bytes:
                    output_overflow = True
                    break

            stderr = "".join(stderr_parts)

            if cancelled or timed_out or output_overflow:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                if output_overflow:
                    err = ProviderError(
                        ProviderErrorKind.OUTPUT_LIMIT,
                        f"Provider output exceeded {max_bytes} bytes; aborted.",
                    )
                elif timed_out:
                    err = ProviderError(
                        ProviderErrorKind.TIMEOUT,
                        f"Provider execution exceeded {request.timeout_s}s.",
                        retryable=True,
                    )
                else:
                    err = ProviderError(
                        ProviderErrorKind.CANCELLED, "Execution cancelled."
                    )
                self._audit_failure(err, stderr, None)
                yield ResultEvent(kind=ResultEventKind.ERROR, error=err)
                yield ResultEvent(
                    kind=ResultEventKind.DONE,
                    data={
                        "ok": False,
                        "exit_code": None,
                        "stderr": stderr,
                        "cancelled": cancelled,
                        "timed_out": timed_out,
                        "output_overflow": output_overflow,
                    },
                )
                return

            returncode = proc.wait()
            if returncode == 0:
                yield ResultEvent(
                    kind=ResultEventKind.DONE,
                    data={"ok": True, "exit_code": 0, "stderr": stderr},
                )
            else:
                err = self._classify_failure(stderr, returncode)
                self._audit_failure(err, stderr, returncode)
                yield ResultEvent(kind=ResultEventKind.ERROR, error=err)
                yield ResultEvent(
                    kind=ResultEventKind.DONE,
                    data={"ok": False, "exit_code": returncode, "stderr": stderr},
                )
        finally:
            _cleanup_tmp()

    def execute(
        self, request: ExecutionRequest, *, cancel: "CancelToken | None" = None
    ) -> ExecutionResult:
        """Collect the streamed events into a single ``ExecutionResult``.

        Refuses to run unless the provider is READY (the stream emits a clean
        ``PROVIDER_AUTH`` / ``PROVIDER_NOT_INSTALLED`` error instead of an
        opaque subprocess failure).
        """
        stdout_parts: list[str] = []
        error: ProviderError | None = None
        ok = False
        exit_code: int | None = None
        stderr = ""
        for ev in self.stream(request, cancel=cancel):
            if ev.kind in (ResultEventKind.TEXT, ResultEventKind.COMMAND_OUTPUT):
                stdout_parts.append(ev.text)
            elif ev.kind is ResultEventKind.ERROR:
                error = ev.error
            elif ev.kind is ResultEventKind.DONE and ev.data:
                ok = bool(ev.data.get("ok"))
                exit_code = ev.data.get("exit_code")
                stderr = ev.data.get("stderr", "")
        return ExecutionResult(
            ok=ok,
            stdout="\n".join(stdout_parts),
            stderr=stderr,
            exit_code=exit_code,
            error=error,
        )
