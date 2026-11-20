"""Bundled memory maintenance must respect the active profile's load policy."""
import ast
import asyncio
import sys
from pathlib import Path

import pytest


def test_maintenance_modules_share_approved_sibling_state(tmp_path, monkeypatch):
    from tools import skill_attestation

    bundle = tmp_path / "fixture"
    bundle.mkdir()
    (bundle / "__init__.py").write_text("from .client import MARKER\n")
    (bundle / "client.py").write_text("MARKER = object()\n")
    checks = []

    def verified(kind, name, source):
        checks.append((kind, name, source))
        return bundle

    monkeypatch.setattr(skill_attestation, "_BUNDLED_PLUGINS", tmp_path / "sources")
    monkeypatch.setattr(skill_attestation, "verified_directory", verified)
    monkeypatch.setitem(skill_attestation._snapshot_ids, bundle, "offlinefixture")
    package = "plugins.memory.fixture__offlinefixture"
    try:
        child = skill_attestation.load_bundled_plugin_module("memory", "fixture", "client")
        parent = skill_attestation.load_bundled_plugin_module("memory", "fixture")
        assert parent.MARKER is child.MARKER
        assert Path(parent.__file__).parent == bundle == Path(child.__file__).parent
        assert checks == [("plugin", "memory/fixture", tmp_path / "sources" / "memory" / "fixture")] * 2
    finally:
        sys.modules.pop(package + ".client", None)
        sys.modules.pop(package, None)


@pytest.mark.parametrize("route", ["start_memory_oauth", "memory_oauth_status"])
def test_oauth_checks_requested_profile_before_loading_any_flow(tmp_path, monkeypatch, route):
    from fastapi import HTTPException
    from lliam_cli import memory_oauth, profiles
    from lliam_constants import get_lliam_home
    from tools import skill_attestation

    monkeypatch.setattr(profiles, "profile_exists", lambda name: True)
    monkeypatch.setattr(profiles, "get_profile_dir", lambda name: tmp_path / name)
    observed = []

    def held(kind, name, directory):
        observed.append((kind, name, get_lliam_home()))
        raise PermissionError("held")

    monkeypatch.setattr(skill_attestation, "verified_directory", held)
    with pytest.raises(HTTPException) as caught:
        asyncio.run(getattr(memory_oauth, route)("honcho", profile="review"))
    assert caught.value.status_code == 403
    assert observed == [("plugin", "memory/honcho", tmp_path / "review")]


def test_commands_keep_optional_provider_imports_behind_the_bundle_check():
    from lliam_cli import doctor, main

    for command_module in (doctor, main):
        tree = ast.parse(Path(command_module.__file__).read_text())
        assert not [
            node.module for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("plugins.memory.")
        ]
