"""Compatibility exports for bundled web and browser providers."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys

import pytest


def test_importing_core_tools_loads_no_vendor_implementations(tmp_path):
    probe = """
import sys
from tools import browser_tool, web_tools
assert not [name for name in sys.modules
            if name.startswith(('plugins.web.', 'plugins.browser.')) and name.endswith('.provider')]
"""
    subprocess.run([sys.executable, "-c", probe], check=True, env={
        **os.environ, "HOME": str(tmp_path), "LLIAM_HOME": str(tmp_path),
        "HERMES_HOME": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1",
    })


def test_low_side_wildcard_imports_include_lazy_public_providers(monkeypatch):
    from tools import browser_tool, skill_attestation, web_tools

    monkeypatch.setattr(skill_attestation, "active_policy", lambda: None)
    for module, statement, expected in (
        (web_tools, "from tools.web_tools import *", ("Firecrawl",)),
        (browser_tool, "from tools.browser_tool import *",
         ("BrowserbaseProvider", "BrowserUseProvider", "FirecrawlProvider")),
    ):
        exported = {}
        exec(statement, exported)
        for name in expected:
            assert exported[name] is getattr(module, name)


def test_approved_compatibility_exports_work_without_unselected_providers(monkeypatch):
    from agent.attestation import compute_signature
    from tools import browser_tool, skill_attestation, web_tools

    root = Path(__file__).resolve().parents[2] / "plugins"
    signer, key = "fixture-owner", "fixture-key"
    entries = []
    for name in ("web/tavily", "browser/browserbase"):
        path = root / name / "provider.py"
        record = {
            "approver": "fixture owner", "expires": "2099-01-01",
            "files": {"provider.py": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()},
            "kind": "plugin", "name": name, "sdl_record": "fixture review", "source": "fixture supplier",
        }
        entries.append({**record, "signature": compute_signature(record, key), "signer": signer})
    monkeypatch.setattr("lliam_cli.config.load_config", lambda: {
        "security": {"posture": "strict", "trusted_signers": {signer: key}},
    })
    monkeypatch.setattr(skill_attestation, "active_policy", lambda: {
        "security": {"trusted_signers": [signer], "plugin_allowlist": entries},
    })
    monkeypatch.setattr("lliam_cli.config.read_raw_config", lambda: {})
    monkeypatch.setattr(browser_tool, "_cached_cloud_provider", None)
    monkeypatch.setattr(browser_tool, "_cloud_provider_resolved", False)
    monkeypatch.setenv("BROWSERBASE_API_KEY", "fixture")
    monkeypatch.setenv("BROWSERBASE_PROJECT_ID", "fixture")

    assert web_tools._normalize_tavily_search_results({"results": []})["data"]["web"] == []
    assert "__" in web_tools._normalize_tavily_search_results.__module__
    assert not web_tools._is_tool_gateway_ready()
    provider = browser_tool._get_cloud_provider()
    assert isinstance(provider, browser_tool.BrowserbaseProvider)
    assert "__" in type(provider).__module__
    with pytest.raises(PermissionError):
        _ = web_tools._get_exa_client
    with pytest.raises(PermissionError):
        _ = browser_tool.FirecrawlProvider
