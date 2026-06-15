"""Claude Code CLI provider adapter (AI-328, first real adapter).

Detects the Anthropic Claude Code CLI, reports its authentication state, and
provides a one-shot execution path — all without ever reading or storing the
user's token (AI-334). Authentication is inferred from the *presence* of the
CLI's own credential file or an injected auth probe; the token value is never
opened.

Every external touchpoint (``which``, version ``run``, ``$HOME``, ``env``, and
an optional ``auth_probe``) is injectable so the adapter can be unit-tested
against fake CLI binaries for installed / authenticated / missing /
expired-auth / failure cases.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path

from providers.cli.contract import (
    AuthResult,
    BaseCLIProvider,
    DetectResult,
    ExecutionRequest,
    InvocationMode,
    ProviderCapabilities,
)

WhichFn = Callable[[str], "str | None"]
RunFn = Callable[[list[str]], "subprocess.CompletedProcess[str]"]
# Optional CLI-driven auth probe: returns "ok" | "expired" | "unauthenticated".
AuthProbeFn = Callable[[], str]


def _default_run(argv: list[str]) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(argv, capture_output=True, text=True, timeout=10)


class ClaudeCodeCLIProvider(BaseCLIProvider):
    """Adapter for the Anthropic Claude Code CLI (``claude``)."""

    BINARY = "claude"
    DEFAULT_MODEL = "sonnet"
    install_hint = "npm install -g @anthropic-ai/claude-code"
    auth_hint = "claude setup-token"

    def __init__(
        self,
        *,
        which: WhichFn | None = None,
        run: RunFn | None = None,
        home: Path | None = None,
        env: Mapping[str, str] | None = None,
        auth_probe: AuthProbeFn | None = None,
    ) -> None:
        self._which = which or shutil.which
        self._run = run or _default_run
        self._home = home or Path.home()
        self._env = env if env is not None else os.environ
        self._auth_probe = auth_probe

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            id="claude-code",
            display_name="Claude Code CLI",
            invocation_mode=InvocationMode.NON_INTERACTIVE,
            supports_streaming=True,
            supports_cancellation=True,
            supports_model_list=False,
            owns_auth=True,
        )

    def detect(self) -> DetectResult:
        path = self._which(self.BINARY)
        if not path:
            return DetectResult(installed=False)
        version = None
        try:
            proc = self._run([self.BINARY, "--version"])
            if proc.returncode == 0 and proc.stdout:
                version = proc.stdout.strip().splitlines()[0].strip() or None
        except (OSError, subprocess.SubprocessError):
            version = None
        return DetectResult(installed=True, path=path, version=version)

    def _credentials_path(self) -> Path:
        return self._home / ".claude" / ".credentials.json"

    def check_auth(self) -> AuthResult:
        """Infer auth state from credential *presence* — never token contents.

        Priority:
          1. injected ``auth_probe`` (a CLI call that knows its own state),
          2. presence of the Claude Code credential file,
          3. presence (boolean) of a recognized env token.
        """
        if self._auth_probe is not None:
            verdict = self._auth_probe()
            if verdict == "ok":
                return AuthResult(True, source="claude_code_cli", detail="CLI reports authenticated")
            if verdict == "expired":
                return AuthResult(
                    True, source="claude_code_cli", detail="Credentials expired", expired=True
                )
            return AuthResult(False, source="claude_code_cli", detail="CLI reports not logged in")

        if self._credentials_path().exists():
            return AuthResult(
                True,
                source="claude_code_cli_credentials",
                detail="Found ~/.claude/.credentials.json",
            )

        # Presence check only — the value is never read or stored (AI-334).
        for var in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"):
            if self._env.get(var):
                return AuthResult(True, source=f"env:{var}", detail=f"{var} is set")

        return AuthResult(
            False, source="claude_code_cli", detail="No Claude Code credentials found"
        )

    def default_model(self) -> str | None:
        return self.DEFAULT_MODEL

    def _build_argv(self, request: ExecutionRequest) -> list[str]:
        argv = [self.BINARY, "-p", request.prompt]
        if request.model:
            argv += ["--model", request.model]
        return argv
