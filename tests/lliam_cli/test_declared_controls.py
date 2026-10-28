"""Fail-closed behaviour of declared security controls (lliam_cli/declared_controls.py).

enforce_declared_controls_at_startup — an unenforceable spend-ceiling or
spawn-depth configuration raises under strict, is advisory otherwise, and the
shipped overlay passes.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from lliam_cli import declared_controls as dc


# --------------------------------------------------------------------------- #
# Startup configuration check
# --------------------------------------------------------------------------- #

def test_shipped_overlay_has_no_findings():
    overlay = yaml.safe_load((Path(__file__).resolve().parents[2] / "cli-config.gov.yaml").read_text())
    assert overlay["security"]["posture"] == "strict"
    assert dc.declared_control_findings(overlay) == []
    assert dc.enforce_declared_controls_at_startup(overlay) is None


def test_bad_spend_ceiling_blocks_under_strict():
    cfg = {"security": {"posture": "strict", "spend_ceiling": {"enabled": True}}}
    with pytest.raises(dc.DeclaredControlError, match="no ceiling is set"):
        dc.enforce_declared_controls_at_startup(cfg)


def test_bad_spawn_depth_blocks_under_strict():
    cfg = {"security": {"posture": "strict"}, "delegation": {"max_spawn_depth": "deep"}}
    with pytest.raises(dc.DeclaredControlError, match="max_spawn_depth"):
        dc.enforce_declared_controls_at_startup(cfg)


def test_findings_are_advisory_low_side():
    cfg = {"security": {"spend_ceiling": {"enabled": True, "per_session_tokens": -1}}}
    findings = dc.enforce_declared_controls_at_startup(cfg)
    assert findings and "per_session_tokens" in findings[0]
