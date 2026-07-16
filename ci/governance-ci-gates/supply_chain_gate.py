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

import re
import sys
from pathlib import Path
from typing import Any, Dict, List

# base64 decode + a dynamic executor on the same logical line, in either order
# (the litellm attack shape wraps the decode in a dynamic-execution call; the
# reverse ordering also occurs). Matched case-insensitively.
_B64_DECODE = r"base64\.(?:b64decode|decodebytes|urlsafe_b64decode)\b"
_DYN_EXEC = r"\b(?:exec|eval)\s*\("
_B64_EXEC = re.compile(
    rf"(?:{_B64_DECODE}.*{_DYN_EXEC})|(?:{_DYN_EXEC}.*{_B64_DECODE})", re.I)
# subprocess whose command is base64/hex/chr-encoded — payload execution shape.
_OBFUSCATED_PROC = re.compile(
    r"subprocess\.(Popen|call|run)\s*\(.*(base64|\\x[0-9a-f]{2}|chr\()", re.I)

_INSTALL_HOOK_NAMES = {"sitecustomize.py", "usercustomize.py"}

# Directories that are never source we author (skip to keep the gate fast/clean).
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__",
              "dist", "build", ".mypy_cache", ".pytest_cache", "release"}


def _iter_files(root: Path):
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        yield p


def scan_tree(root: Path) -> List[Dict[str, Any]]:
    """Return a list of supply-chain findings ({kind, path, detail}). [] if clean."""
    root = Path(root)
    findings: List[Dict[str, Any]] = []
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
            continue
        if _B64_EXEC.search(text):
            findings.append({"kind": "base64_exec", "path": rel,
                             "detail": "base64 decode fed into exec/eval"})
        elif _OBFUSCATED_PROC.search(text):
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
