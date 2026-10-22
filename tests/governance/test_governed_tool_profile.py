"""SR-05: computer-control and browser tools are OFF in the governed profile.

Loads the shipped overlay (cli-config.gov.yaml, strict posture) through the
real config loader and checks both layers that keep these tool families away
from the model:

  1. registration: ``agent.disabled_toolsets`` removes the ``computer_use`` and
     ``browser`` toolsets from the resolved toolset of EVERY platform, so none of
     their tools are offered to the model;
  2. dispatch: a direct call to any of those tools, e.g. from nested code
     execution or the API server, is refused by the tool-risk PDP before the
     handler runs. ``deny`` is terminal and a JIT grant does not re-enable it.

Each layer has a control. With the overlay's disabled list cleared, the same
platforms DO resolve both toolsets, so the registration test cannot pass
vacuously.
"""

from __future__ import annotations

import copy

import pytest

from tests.governance._governed_profile import (
    call_tool,
    enter_governed_profile,
    stub_tool_handlers,
)

_FAMILIES = ("computer_use", "browser")


def _browser_tools() -> list[str]:
    from toolsets import TOOLSETS

    return sorted(t for t in TOOLSETS["browser"]["tools"] if t.startswith("browser_"))


def _family_tool(name: str) -> bool:
    return name == "computer_use" or name.startswith("browser_")


@pytest.fixture
def governed(tmp_path, monkeypatch):
    return enter_governed_profile(tmp_path, monkeypatch)


@pytest.fixture
def gov_config(governed):
    from lliam_cli.config import load_config

    return load_config()


def _platforms():
    from lliam_cli.tools_config import PLATFORMS

    return sorted(PLATFORMS)


# --- the overlay really is the governed profile -----------------------------

def test_overlay_is_strict_and_lists_both_families(gov_config):
    from lliam_cli import posture_resolver

    assert posture_resolver.is_strict(gov_config)
    assert set(_FAMILIES) <= set(gov_config["agent"]["disabled_toolsets"])
    assert set(_FAMILIES) <= set(gov_config["security"]["tool_denylist"])


# --- layer 1: not registered on any platform --------------------------------

@pytest.mark.parametrize("platform", _platforms())
def test_families_not_resolved_for_platform(gov_config, platform):
    from lliam_cli.tools_config import _get_platform_tools
    from toolsets import resolve_toolset

    enabled = _get_platform_tools(gov_config, platform)
    assert not set(_FAMILIES) & enabled
    tool_names = {t for ts in enabled for t in resolve_toolset(ts)}
    assert not {t for t in tool_names if _family_tool(t)}, platform


@pytest.mark.parametrize("platform", ["cli", "telegram", "discord", "slack", "cron"])
def test_control_disabled_list_is_what_removes_them(gov_config, platform):
    from lliam_cli.tools_config import _get_platform_tools

    ungoverned = copy.deepcopy(gov_config)
    ungoverned["agent"]["disabled_toolsets"] = []
    assert set(_FAMILIES) <= _get_platform_tools(ungoverned, platform)


def test_model_is_offered_no_family_schema(gov_config):
    import model_tools
    from lliam_cli.tools_config import _get_platform_tools

    enabled = sorted(_get_platform_tools(gov_config, "cli"))
    names = {d["function"]["name"]
             for d in model_tools.get_tool_definitions(enabled_toolsets=enabled,
                                                       quiet_mode=True)}
    assert names, "governed CLI profile must still expose its mission tools"
    assert not {n for n in names if _family_tool(n)}
    # The mission tools the same overlay keeps (capability preserved). Web
    # tools also stay enabled but need a provider key to be offered.
    assert {"read_file", "write_file", "patch", "search_files", "terminal"} <= names


# --- layer 2: a direct call is refused before the handler runs -------------

_CALLS = [("computer_use", {"action": "screenshot"}),
          ("computer_use", {"action": "click", "x": 10, "y": 10})]
_CALLS += [(name, {}) for name in _browser_tools()]


@pytest.mark.parametrize("name,args", _CALLS, ids=lambda v: v if isinstance(v, str) else "")
def test_direct_call_refused_by_pdp(governed, monkeypatch, name, args):
    from agent.governance_audit import iter_records
    from tools.tool_policy import evaluate_call

    decision = evaluate_call(name, args)
    assert decision.disposition == "deny", decision.reason
    assert decision.action_class in {"computer_use.desktop_control",
                                     "browser.unlisted_or_action"}

    dispatched = stub_tool_handlers(monkeypatch)
    out = call_tool(name, args)
    assert "Blocked by tool-risk policy" in out.get("error", ""), out
    assert dispatched == [], "handler ran for a denied tool"

    # The refusal itself is on the tamper-evident record.
    denials = [r for r in iter_records(governed.ledger_path)
               if r["event"] == "policy.violation" and r["action"] == f"tool.{name}"]
    assert denials and denials[-1]["decision"] == "deny"


def test_browser_navigate_refused_even_to_allowlisted_host(governed, monkeypatch):
    # api.github.com is on the egress allowlist for web/mcp; the browser
    # surface still may not reach it, and the handler never runs.
    dispatched = stub_tool_handlers(monkeypatch)
    out = call_tool("browser_navigate", {"url": "https://api.github.com/"})
    assert "Blocked by" in out.get("error", ""), out
    assert dispatched == []


@pytest.mark.parametrize("action_class,name,args", [
    ("computer_use.desktop_control", "computer_use", {"action": "screenshot"}),
    ("browser.unlisted_or_action", "browser_snapshot", {}),
])
def test_jit_grant_cannot_reenable(governed, action_class, name, args):
    import tools.tool_policy as tp
    from agent import governance_audit_hooks as gah

    # The governed overlay requires an authenticated approver (JER-73), so
    # the grant is made by a bound principal; it still must not re-enable.
    gah.set_operator_subject("isso@dashboard", auth="dashboard_auth:oauth")
    try:
        tp.grant_capability(action_class, approver="isso@dashboard")
    finally:
        gah.set_operator_subject(None)
    assert tp.evaluate_call(name, args).disposition == "deny"
    assert tp.pdp_gate(name, args).code == "pdp_deny"
