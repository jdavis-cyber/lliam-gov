"""The tool-risk tiering matrix is the same file the PDP loads (LG-RM-03)."""

from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[2]


def test_tiering_matrix_is_the_pdp_policy_file():
    matrix = yaml.safe_load(
        (_REPO / "policy" / "tool-risk-policy.yaml").read_text())
    assert matrix["metadata"]["pdp_module"] == "tools/tool_policy.py"
    pdp_src = (_REPO / "tools" / "tool_policy.py").read_text()
    assert "tool-risk-policy.yaml" in pdp_src, \
        "PDP does not load policy/tool-risk-policy.yaml"
