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
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Protocol, runtime_checkable


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
    cwd: str | None = None
    timeout_s: float = 120.0
    # Extra env *isolation* hint: when True the adapter starts from a minimal
    # env (PATH/HOME only) rather than inheriting the full parent environment.
    isolate_env: bool = True


@dataclass(frozen=True)
class ExecutionResult:
    """Normalized result of a one-shot execution."""

    ok: bool
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    error: ProviderError | None = None


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

    # Execution skeleton — concrete adapters override _build_argv().
    def _build_argv(self, request: ExecutionRequest) -> list[str]:  # pragma: no cover
        raise NotImplementedError

    def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """One-shot execution skeleton with structured error mapping.

        Refuses to run unless the provider is READY, so callers get a clean
        ``PROVIDER_AUTH`` / ``PROVIDER_NOT_INSTALLED`` instead of an opaque
        subprocess failure.
        """
        import os
        import subprocess

        report = self.probe()
        if report.readiness is not Readiness.READY:
            return ExecutionResult(
                ok=False,
                error=report.error
                or ProviderError(
                    kind=ProviderErrorKind.APP_SETUP,
                    message="Provider is not ready.",
                ),
            )
        argv = self._build_argv(request)
        env = None
        if request.isolate_env:
            base = os.environ
            env = {k: base[k] for k in ("PATH", "HOME") if k in base}
        try:
            proc = subprocess.run(
                argv,
                cwd=request.cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=request.timeout_s,
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                ok=False,
                error=ProviderError(
                    kind=ProviderErrorKind.TIMEOUT,
                    message=f"Provider execution exceeded {request.timeout_s}s.",
                    retryable=True,
                ),
            )
        except FileNotFoundError:
            return ExecutionResult(
                ok=False,
                error=ProviderError(
                    kind=ProviderErrorKind.PROVIDER_NOT_INSTALLED,
                    message="Provider CLI vanished between probe and execute.",
                    remediation=self.install_hint,
                ),
            )
        if proc.returncode == 0:
            return ExecutionResult(
                ok=True, stdout=proc.stdout, stderr=proc.stderr, exit_code=0
            )
        return ExecutionResult(
            ok=False,
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            error=ProviderError(
                kind=ProviderErrorKind.PROVIDER_EXECUTION,
                message=f"Provider CLI exited {proc.returncode}.",
                retryable=False,
            ),
        )
