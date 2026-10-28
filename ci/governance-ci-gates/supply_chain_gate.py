#!/usr/bin/env python3
"""supply_chain_gate.py — Lliam-GOV supply-chain artifact gate (P3.4 / LG-SS-04).

BLOCKING, locally-runnable (CI-credits-independent) gate that scans a tree for
the three categorically-unsafe supply-chain shapes and exits non-zero on a hit:

  * .pth files            — auto-execute at interpreter startup (no import).
  * base64-decode -> exec — decode fed straight into a dynamic executor
                            (the litellm attack pattern).
  * install-hook files    — sitecustomize / usercustomize / __init__.pth /
                            setup.py exec — run during install or startup.

Additive companion to the existing .github/workflows/supply-chain-audit.yml
(which scans PR diffs and posts findings); this is the deterministic gate the
governance-gates workflow and local runs invoke to hard-block. Renames nothing.
"""

from __future__ import annotations

import ast
import re
import sys
import warnings
from pathlib import Path
from typing import Any, Dict, List

_SETUP_EXEC = re.compile(r"\b(?:exec|eval)\s*\(|subprocess\.(?:Popen|call|run)\s*\(", re.I)

_INSTALL_HOOK_NAMES = {"sitecustomize.py", "usercustomize.py"}

# Directories that are never source we author (skip to keep the gate fast/clean).
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__",
              ".mypy_cache", ".pytest_cache"}


def _iter_files(root: Path):
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        if any(part in _SKIP_DIRS or part.startswith(".venv") for part in p.parts):
            continue
        yield p


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_call_name(node.value)}.{node.attr}".strip(".")
    return ""


def _python_shapes(text: str) -> set[str]:
    """Find dangerous call shapes without matching unrelated file text."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        tree = ast.parse(text)
    findings: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        descendants = list(ast.walk(node))
        nested_calls = {
            _call_name(child.func)
            for child in descendants
            if isinstance(child, ast.Call)
        }
        if name in {"exec", "eval"} and any(
            nested.endswith(("base64.b64decode", "base64.decodebytes", "base64.urlsafe_b64decode"))
            for nested in nested_calls
        ):
            findings.add("base64_exec")
        if name in {"subprocess.Popen", "subprocess.call", "subprocess.run"}:
            has_obfuscator = any(
                nested == "chr" or nested.startswith("base64.")
                for nested in nested_calls
            )
            has_hex_literal = any(
                isinstance(child, ast.Constant)
                and isinstance(child.value, str)
                and "\\x" in child.value
                for child in descendants
            )
            if has_obfuscator or has_hex_literal:
                findings.add("obfuscated_subprocess")
    return findings


def scan_tree(root: Path) -> List[Dict[str, Any]]:
    """Return a list of supply-chain findings ({kind, path, detail}). [] if clean."""
    root = Path(root)
    findings: List[Dict[str, Any]] = []
    if not root.is_dir():
        return [{"kind": "missing_root", "path": str(root),
                 "detail": "scan root is missing or not a directory — fail-closed"}]
    for p in _iter_files(root):
        name = p.name
        rel = str(p.relative_to(root))
        # .pth files — flagged by extension (auto-run at startup).
        if p.suffix == ".pth":
            findings.append({"kind": "pth_file", "path": rel,
                             "detail": ".pth files auto-execute at interpreter startup"})
            continue
        # install-hook filenames.
        if name in _INSTALL_HOOK_NAMES:
            findings.append({"kind": "install_hook", "path": rel,
                             "detail": f"{name} runs automatically at interpreter startup"})
            continue
        if p.suffix != ".py":
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            findings.append({"kind": "unreadable_source", "path": rel,
                             "detail": "source file could not be read — fail-closed"})
            continue
        if rel == "setup.py" and _SETUP_EXEC.search(text):
            findings.append({"kind": "install_hook", "path": rel,
                             "detail": "setup.py contains dynamic execution or subprocess launch"})
            continue
        try:
            shapes = _python_shapes(text)
        except SyntaxError:
            findings.append({"kind": "unparseable_source", "path": rel,
                             "detail": "Python source could not be parsed — fail-closed"})
            continue
        if "base64_exec" in shapes:
            findings.append({"kind": "base64_exec", "path": rel,
                             "detail": "base64 decode fed into exec/eval"})
        if "obfuscated_subprocess" in shapes:
            findings.append({"kind": "obfuscated_subprocess", "path": rel,
                             "detail": "subprocess with an encoded command string"})
    return findings


def run_gate(root: Path) -> int:
    findings = scan_tree(Path(root))
    if not findings:
        print("[supply-chain] OK — no .pth / base64-exec / install-hook shapes found.")
        return 0
    print(f"[supply-chain] BLOCKING — {len(findings)} supply-chain risk(s):")
    for f in findings:
        print(f"  [{f['kind']}] {f['path']} — {f['detail']}")
    return 1


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[2]
    sys.exit(run_gate(target))
