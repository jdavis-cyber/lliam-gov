"""Shared fixtures for the kill-switch / recovery tests (JER-190).

``baseline_repo`` builds a throwaway deployment checkout with a signed-
baseline layout (gov overlay, policy/, critical-keys policy, authorization
record pinning a tagged commit). ``live_ledger`` is a real hash-chained
ledger under the per-test home, wired in as the process ledger. Nothing
touches the real home or this checkout.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

OVERLAY = """\
security:
  posture: strict
  redact_secrets: true
audit:
  ledger_enabled: true
"""

CRITICAL_KEYS = """\
version: 1
posture_required: strict
critical_keys:
  - {key: security.posture, expect: strict, severity: critical, activated_in: P0.1}
  - {key: security.redact_secrets, expect: true, severity: critical, activated_in: P0.1}
"""

POLICY = "providers:\n  - bedrock-govcloud\n"


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), "-c", "user.name=test", "-c",
         "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
         "-c", "tag.gpgsign=false", *args],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


def make_baseline_repo(root: Path, *, overlay: str = OVERLAY,
                       tag: str = "gov-T-good",
                       critical_keys_rel: str = "policy/governed/baseline-critical-keys.yaml",
                       prior_pin: str | None = None) -> SimpleNamespace:
    """``critical_keys_rel`` places the critical-keys policy (anywhere but
    its expected path makes the baseline unverifiable); ``prior_pin`` commits an
    authorization record pinning an earlier baseline INTO the tagged commit,
    as a real release does before its post-tag re-pin."""
    (root / "policy" / "governed").mkdir(parents=True)
    (root / "cli-config.gov.yaml").write_text(overlay, encoding="utf-8")
    keys = root / critical_keys_rel
    keys.parent.mkdir(parents=True, exist_ok=True)
    keys.write_text(CRITICAL_KEYS, encoding="utf-8")
    (root / "policy" / "provider-allowlist.yaml").write_text(POLICY, encoding="utf-8")
    if prior_pin is not None:
        (root / "policy" / "governed" / "authorization-record.yaml").write_text(
            f"baseline:\n  git_tag: {prior_pin}\n", encoding="utf-8")
    (root / "app.py").write_text("print('hi')\n", encoding="utf-8")
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "baseline")
    commit = _git(root, "rev-parse", "HEAD")
    _git(root, "tag", tag)
    (root / "policy" / "governed" / "authorization-record.yaml").write_text(
        f"baseline:\n  git_tag: {tag}\n  git_commit: {commit}\n"
        "  overlay: cli-config.gov.yaml\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "authorize baseline")
    return SimpleNamespace(root=root, commit=commit, tag=tag,
                           overlay=root / "cli-config.gov.yaml",
                           policy=root / "policy" / "provider-allowlist.yaml",
                           git=lambda *a: _git(root, *a))


@pytest.fixture
def baseline_repo(tmp_path):
    return make_baseline_repo(tmp_path / "deploy")


@pytest.fixture
def ks_home(tmp_path, monkeypatch):
    """agent.killswitch with its durable state redirected under tmp."""
    from agent import killswitch as _ks
    monkeypatch.setattr(_ks, "_state_path", lambda: tmp_path / "killswitch.state")
    _ks.reset_for_tests()
    yield _ks
    _ks.reset_for_tests()


@pytest.fixture
def live_ledger(tmp_path, monkeypatch):
    """A real enabled ledger, installed as the process ledger."""
    from agent import governance_audit as ga
    from lliam_constants import get_lliam_home
    path = get_lliam_home() / "logs" / "agent-audit.log"
    led = ga.GovernanceLedger(path)
    monkeypatch.setattr(ga, "get_ledger", lambda: led)
    led.emit("session.start", action="session.start",
             source_module="tests/governance/conftest.py")
    return led
