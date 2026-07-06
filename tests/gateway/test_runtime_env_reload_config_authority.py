"""Regression tests for gateway per-turn env reload preserving config authority.

Issue #19158: startup bridges config.yaml agent.max_turns into
HERMES_MAX_ITERATIONS, but a later per-turn load_dotenv(..., override=True)
can restore a stale .env HERMES_MAX_ITERATIONS value before the next turn.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from gateway import run as gateway_run


def test_reload_runtime_env_preserves_config_max_turns(tmp_path: Path, monkeypatch) -> None:
    hermes_home = tmp_path / ".hermes"
    hermes_home.mkdir()
    (hermes_home / "config.yaml").write_text(
        yaml.safe_dump({"agent": {"max_turns": 9000}}),
        encoding="utf-8",
    )
    (hermes_home / ".env").write_text(
        "HERMES_MAX_ITERATIONS=90\nOPENROUTER_API_KEY=fresh-key\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(gateway_run, "_hermes_home", hermes_home)
    # rename R.8a: config authority is bridged into the new LLIAM_ name; a
    # stale legacy HERMES_ value in .env must not shadow it (consumers read
    # LLIAM_ first via getenv_compat).
    monkeypatch.setenv("LLIAM_MAX_ITERATIONS", "9000")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

    gateway_run._reload_runtime_env_preserving_config_authority()

    assert os.environ["OPENROUTER_API_KEY"] == "fresh-key"
    assert os.environ["LLIAM_MAX_ITERATIONS"] == "9000"


def test_reload_runtime_env_keeps_env_max_iterations_when_config_omits_key(
    tmp_path: Path, monkeypatch
) -> None:
    hermes_home = tmp_path / ".hermes"
    hermes_home.mkdir()
    (hermes_home / "config.yaml").write_text(yaml.safe_dump({"agent": {}}), encoding="utf-8")
    (hermes_home / ".env").write_text("HERMES_MAX_ITERATIONS=123\n", encoding="utf-8")

    monkeypatch.setattr(gateway_run, "_hermes_home", hermes_home)
    # rename R.8a: clear both names so the .env legacy value is the only source.
    monkeypatch.delenv("LLIAM_MAX_ITERATIONS", raising=False)
    monkeypatch.delenv("HERMES_MAX_ITERATIONS", raising=False)

    gateway_run._reload_runtime_env_preserving_config_authority()

    # config omits max_turns → the bridge does not write LLIAM_, so the legacy
    # .env value passes through under its own name (and is found via fallback).
    assert os.environ["HERMES_MAX_ITERATIONS"] == "123"


def test_current_max_iterations_reloads_before_reading(monkeypatch) -> None:
    # rename R.8a: consumers read the new LLIAM_ name first (getenv_compat).
    monkeypatch.delenv("HERMES_MAX_ITERATIONS", raising=False)
    monkeypatch.setenv("LLIAM_MAX_ITERATIONS", "90")

    def _fake_reload() -> None:
        os.environ["LLIAM_MAX_ITERATIONS"] = "200"

    monkeypatch.setattr(
        gateway_run,
        "_reload_runtime_env_preserving_config_authority",
        _fake_reload,
    )

    assert gateway_run._current_max_iterations() == 200
