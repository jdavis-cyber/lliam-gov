"""Gemini / Antigravity CLI provider adapter (AI-328).

Detects the Google Gemini CLI, reports auth state from credential *presence*
only (AI-334 — never reads the token), and provides one-shot execution.
All external touchpoints are injectable for hermetic tests.
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
AuthProbeFn = Callable[[], str]


def _default_run(argv: list[str]) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(argv, capture_output=True, text=True, timeout=10)


class GeminiCLIProvider(BaseCLIProvider):
    """Adapter for the Google Gemini CLI (``gemini``)."""

    BINARY = "gemini"
    DEFAULT_MODEL = "gemini-2.5-pro"  # the Gemini CLI's own default alias
    install_hint = "npm install -g @google/gemini-cli"
    auth_hint = "gemini  # complete the browser sign-in on first run"

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
            id="gemini",
            display_name="Gemini CLI",
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
        return self._home / ".gemini" / "oauth_creds.json"

    def check_auth(self) -> AuthResult:
        """Auth state from credential presence — never the token value (AI-334)."""
        if self._auth_probe is not None:
            verdict = self._auth_probe()
            if verdict == "ok":
                return AuthResult(True, source="gemini_cli", detail="CLI reports authenticated")
            if verdict == "expired":
                return AuthResult(
                    True, source="gemini_cli", detail="Credentials expired", expired=True
                )
            return AuthResult(False, source="gemini_cli", detail="CLI reports not logged in")

        if self._credentials_path().exists():
            return AuthResult(
                True,
                source="gemini_cli_credentials",
                detail="Found ~/.gemini/oauth_creds.json",
            )

        for var in ("GEMINI_API_KEY", "GOOGLE_API_KEY"):
            if self._env.get(var):
                return AuthResult(True, source=f"env:{var}", detail=f"{var} is set")

        return AuthResult(False, source="gemini_cli", detail="No Gemini credentials found")

    def default_model(self) -> str | None:
        return self.DEFAULT_MODEL

    def _build_argv(self, request: ExecutionRequest) -> list[str]:
        # Gemini CLI non-interactive prompt mode.
        argv = [self.BINARY, "-p", request.prompt]
        if request.model:
            argv += ["-m", request.model]
        return argv
