"""Capability-tagged tool dispatch (LG-4.2, AI-219).

Plan §5.3. Every tool the agent can dispatch carries a CAPABILITY TAG, and
under the governed profile (``LLIAM_GOV_CAPABILITY_ENFORCE=1``) a dispatch
is allowed only when the active session's authorized capability set covers
the tool's tag. Unauthorized dispatch is blocked and audited.

Capability vocabulary (small on purpose — tags must mean something at
review time, not mirror the toolset list):

==================  ========================================================
``fs_read``         Read files/search inside the workspace
``fs_write``        Mutate files inside the workspace
``shell_exec``      Arbitrary process execution (terminal, code execution)
``network``         Outbound web access (browser, web fetch/search) — still
                    subject to the LG-4.3 egress allowlist underneath
``messaging``       Sending messages through connected gateways
``memory_write``    Persisting agent memory / curated notes
``media_gen``       Image/video/TTS generation (provider-side effects)
``selfmod``         Self-modifying behavior: skills, runtime tool
                    registration (gated separately by LG-4.5 too)
``system_admin``    Host integration beyond the workspace (Home Assistant,
                    desktop automation)
==================  ========================================================

Classification is centralized here (toolset → tag, with per-tool-name
overrides) rather than scattered across ~40 registration sites; the
registry's ``ToolEntry`` carries the resolved tag via
:func:`capability_for_tool`. A tool whose toolset is not classified maps to
``unclassified``, which NO profile includes — new surface area is denied
until someone consciously classifies it (conservative by default).

The named governed baseline ``GOVERNED_BASELINE`` is deliberately
conservative: workspace I/O, messaging, and memory only. No shell, no
browser, no media generation, no host integration, no self-modification —
each of those must be granted explicitly via ``LLIAM_GOV_CAPABILITIES``.

Maps to: SP 800-171 3.1.2 (authorized transactions/functions); ISO 27001
A.8.2; ISO 42001 A.6.2.4 context.
"""

from __future__ import annotations

import os

CAPABILITY_ENFORCE_ENV = "LLIAM_GOV_CAPABILITY_ENFORCE"
CAPABILITIES_ENV = "LLIAM_GOV_CAPABILITIES"

UNCLASSIFIED = "unclassified"

#: The named, conservative default for CUI/governed sessions.
GOVERNED_BASELINE: frozenset[str] = frozenset(
    {"fs_read", "fs_write", "messaging", "memory_write"}
)

#: toolset -> capability tag. Unlisted toolsets resolve to UNCLASSIFIED.
_TOOLSET_CAPABILITIES: dict[str, str] = {
    "file": "fs_write",  # toolset mixes read/write; per-tool overrides below
    "session_search": "fs_read",
    "todo": "fs_read",
    "kanban": "fs_write",
    "terminal": "shell_exec",
    "code_execution": "shell_exec",
    "browser": "network",
    "web": "network",
    "x_search": "network",
    "messaging": "messaging",
    "feishu_doc": "messaging",
    "feishu_drive": "messaging",
    "memory": "memory_write",
    "vision": "fs_read",
    "image_gen": "media_gen",
    "video_gen": "media_gen",
    "video": "media_gen",
    "tts": "media_gen",
    "moa": "network",
    "skills": "selfmod",
    "homeassistant": "system_admin",
}

#: tool-name overrides win over the toolset default.
_TOOL_NAME_OVERRIDES: dict[str, str] = {
    "read_file": "fs_read",
    "search_files": "fs_read",
    "list_files": "fs_read",
    "read_lints": "fs_read",
}


class CapabilityError(Exception):
    """Base class for capability-dispatch failures."""


class CapabilityDenied(CapabilityError):
    """The active session is not authorized for the tool's capability."""


def capability_enforced() -> bool:
    """True when capability-tagged dispatch is being enforced."""
    return os.environ.get(CAPABILITY_ENFORCE_ENV) == "1"


def active_capabilities() -> frozenset[str]:
    """The session's authorized capability set.

    ``LLIAM_GOV_CAPABILITIES`` (comma-separated tags) when set, else the
    conservative :data:`GOVERNED_BASELINE`. ``unclassified`` entries in the
    env are ignored — that tag is not grantable.
    """
    raw = os.environ.get(CAPABILITIES_ENV, "").strip()
    if not raw:
        return GOVERNED_BASELINE
    return frozenset(
        t.strip() for t in raw.split(",") if t.strip() and t.strip() != UNCLASSIFIED
    )


def capability_for_tool(tool_name: str, toolset: str | None) -> str:
    """Resolve the capability tag for a registered tool."""
    if tool_name in _TOOL_NAME_OVERRIDES:
        return _TOOL_NAME_OVERRIDES[tool_name]
    if toolset is not None and toolset in _TOOLSET_CAPABILITIES:
        return _TOOLSET_CAPABILITIES[toolset]
    return UNCLASSIFIED


def _toolset_for(tool_name: str) -> str | None:
    try:
        from tools.registry import registry

        entry = registry.get_entry(tool_name)
        return entry.toolset if entry is not None else None
    except Exception:
        return None


def check_dispatch(tool_name: str, toolset: str | None = None) -> None:
    """Raise :class:`CapabilityDenied` unless dispatch is authorized.

    No-op when enforcement is off. ``toolset`` is looked up from the
    registry when not supplied. Unclassified tools are ALWAYS denied under
    enforcement — fail-closed for new surface area.
    """
    if not capability_enforced():
        return
    if toolset is None:
        toolset = _toolset_for(tool_name)
    tag = capability_for_tool(tool_name, toolset)
    if tag == UNCLASSIFIED:
        raise CapabilityDenied(
            f"tool {tool_name!r} (toolset {toolset!r}) has no capability "
            "classification; unclassified tools are denied under the "
            "governed profile (SP 800-171 3.1.2). Classify it in "
            "lliam_gov/security/capabilities.py."
        )
    if tag not in active_capabilities():
        raise CapabilityDenied(
            f"tool {tool_name!r} requires capability {tag!r}, which is not "
            f"in the active set {sorted(active_capabilities())} "
            f"({CAPABILITIES_ENV} or GOVERNED_BASELINE). "
            "Unauthorized dispatch refused (SP 800-171 3.1.2)."
        )


__all__ = [
    "CAPABILITIES_ENV",
    "CAPABILITY_ENFORCE_ENV",
    "GOVERNED_BASELINE",
    "UNCLASSIFIED",
    "CapabilityDenied",
    "CapabilityError",
    "active_capabilities",
    "capability_enforced",
    "capability_for_tool",
    "check_dispatch",
]
