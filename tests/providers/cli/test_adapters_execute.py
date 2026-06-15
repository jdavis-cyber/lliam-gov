"""End-to-end execution for each real adapter via fake CLI binaries (AI-328).

Proves Claude Code / Codex / Gemini each spawn their CLI with the prompt and
return a normalized successful result — the selectability Katmai needs.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from providers.cli.claude_code import ClaudeCodeCLIProvider
from providers.cli.codex import CodexCLIProvider
from providers.cli.gemini import GeminiCLIProvider
from providers.cli.contract import ExecutionRequest


def _fake_bin(tmp_path: Path, name: str) -> Path:
    p = tmp_path / name
    p.write_text(f'#!/bin/bash\necho "RESP[{name}]: $*"\n')
    p.chmod(0o755)
    return p


def _run_version(argv):
    return subprocess.CompletedProcess(argv, 0, stdout="1.0.0\n", stderr="")


# (adapter class, fake binary name, credential relative path)
ADAPTERS = [
    (ClaudeCodeCLIProvider, "claude", (".claude", ".credentials.json")),
    (CodexCLIProvider, "codex", (".codex", "auth.json")),
    (GeminiCLIProvider, "gemini", (".gemini", "oauth_creds.json")),
]


@pytest.mark.parametrize("cls,binary,cred_rel", ADAPTERS)
def test_adapter_executes_real_subprocess(tmp_path, cls, binary, cred_rel):
    binp = _fake_bin(tmp_path, binary)
    creds = tmp_path.joinpath(*cred_rel)
    creds.parent.mkdir(parents=True, exist_ok=True)
    creds.write_text("present")  # presence only; contents never read (AI-334)

    provider = cls(
        which=lambda n: str(binp),
        run=_run_version,
        home=tmp_path,
        env={},
    )
    provider.BINARY = str(binp)  # route _build_argv at the fake binary (abs path)

    res = provider.execute(ExecutionRequest(prompt="ping-123"))
    assert res.ok is True, res.error
    assert res.exit_code == 0
    assert f"RESP[{binary}]" in res.stdout  # the CLI actually ran
    assert "ping-123" in res.stdout         # the prompt was forwarded


@pytest.mark.parametrize("cls,binary,cred_rel", ADAPTERS)
def test_adapter_execute_blocked_when_not_authenticated(tmp_path, cls, binary, cred_rel):
    binp = _fake_bin(tmp_path, binary)
    provider = cls(which=lambda n: str(binp), run=_run_version, home=tmp_path, env={})
    provider.BINARY = str(binp)
    # No credentials written → not authenticated → execution refused cleanly.
    res = provider.execute(ExecutionRequest(prompt="ping"))
    assert res.ok is False
    assert res.error is not None
