"""Pure-Python stand-in for the rename guard's ripgrep scan (TC-RC-01).

``test_no_hermes_identifiers`` scans the tree with
``rg -in --no-heading hermes <EXCLUDES> .``. When ``rg`` is not on PATH the
guard calls :func:`scan` here instead. It returns the same stdout text rg would
print, so the guard parses both through the same code.

Every rg behaviour the guard relies on is reproduced, and each one was checked
against ripgrep 14.1 on the fixture tree in ``test_hermes_scan_fallback.py``:

* file set: tracked plus untracked files that ``.gitignore`` /
  ``.git/info/exclude`` / ``core.excludesFile`` do not ignore. rg also skips
  TRACKED files that match an ignore rule, so those are dropped too. Hidden
  entries (any path component starting with ``.``) and symlinks are skipped,
  because rg does not search them by default;
* ``-g '!glob'`` overrides use gitignore glob rules. A glob with no ``/`` matches
  at any depth, a glob with a ``/`` is anchored at the root, ``*`` stops at
  ``/``, and a matching directory excludes everything beneath it;
* encoding: a UTF-8 BOM is stripped and UTF-16 LE/BE files with a BOM are
  transcoded, as rg's default ``--encoding auto`` does;
* binary files: rg stops at the first NUL byte. A NUL in the first 64 KiB read
  hides the whole file. A later NUL hides the read buffer that contains it, and
  if anything matched before it rg prints a "stopped searching binary file
  after match" WARNING line on stdout. The 64 KiB read buffer is simulated
  exactly. Where the boundaries cannot be reproduced (lines longer than the
  buffer, transcoded files), every line before the NUL is reported instead.
  That is a superset of rg's output, so the guard can only get stricter;
* matching: ``-i`` uses Unicode simple case folding (so ``ſ`` U+017F matches
  ``s``). Python's ``re.IGNORECASE`` folds the same way for every letter of
  ``hermes``. Lines split on ``\\n`` only, so ``\\r`` stays in the line text,
  as rg prints it.

Glob syntax the stand-in cannot reproduce exactly raises ``ValueError``, and
ignore-file setups it cannot reproduce raise ``RuntimeError``. A new EXCLUDES
entry can therefore never silently mean something different on the two paths.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

PATTERN = "hermes"

# grep-searcher's DEFAULT_BUFFER_CAPACITY (ripgrep's line-buffer read size).
_RG_BUFFER = 64 * 1024

_MATCH = re.compile(PATTERN, re.IGNORECASE)

_UNSUPPORTED_GLOB_CHARS = set("[]{}\\")

# rg (unlike git) also honors these ignore files; the stand-in does not
# implement them, so their presence is a hard error rather than a divergence.
_RG_ONLY_IGNORE_FILES = (".ignore", ".rgignore")


# --------------------------------------------------------------------------- #
# -g '!glob' overrides (gitignore glob semantics)
# --------------------------------------------------------------------------- #

def _glob_to_regex(glob: str) -> "re.Pattern[str]":
    """Translate one gitignore-style glob to an anchored regex (ripgrep rules)."""
    if not glob or glob.endswith("/") or glob.startswith("!"):
        raise ValueError(f"unsupported exclude glob {glob!r}")
    bad = _UNSUPPORTED_GLOB_CHARS.intersection(glob)
    if bad:
        raise ValueError(f"unsupported glob syntax {sorted(bad)} in {glob!r}")
    g = glob[1:] if glob.startswith("/") else glob
    # ignore::gitignore: no '/' => may match at any level ('**/' prefix);
    # a trailing '/**' matches everything INSIDE the directory ('/**/*').
    if "/" not in glob and not g.startswith("**/"):
        g = "**/" + g
    if g.endswith("/**"):
        g += "/*"
    out: List[str] = []
    i = 0
    while i < len(g):
        if g.startswith("**/", i) and (i == 0 or g[i - 1] == "/"):
            out.append("(?:.*/)?")
            i += 3
            continue
        c = g[i]
        if c == "*":
            if g.startswith("**", i):
                raise ValueError(f"unsupported '**' position in {glob!r}")
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("".join(out) + r"\Z", re.DOTALL)


def parse_excludes(excludes: Sequence[str]) -> List["re.Pattern[str]"]:
    """Compile an rg ``["-g", "!glob", ...]`` exclude list."""
    if len(excludes) % 2:
        raise ValueError("EXCLUDES must be '-g' / '!glob' pairs")
    compiled = []
    for flag, glob in zip(excludes[0::2], excludes[1::2]):
        if flag != "-g" or not glob.startswith("!"):
            raise ValueError(f"only '-g !glob' excludes are supported, got {flag} {glob}")
        compiled.append(_glob_to_regex(glob[1:]))
    return compiled


def _excluded(rel: str, globs: Sequence["re.Pattern[str]"]) -> bool:
    """True if the file or any ancestor directory matches an exclude glob."""
    parts = rel.split("/")
    for depth in range(1, len(parts) + 1):
        prefix = "/".join(parts[:depth])
        if any(rx.match(prefix) for rx in globs):
            return True
    return False


# --------------------------------------------------------------------------- #
# File set (rg's default ignore handling inside a git work tree)
# --------------------------------------------------------------------------- #

def _git_paths(root: Path, *args: str) -> List[str]:
    out = subprocess.run(
        ["git", "-c", "core.quotePath=false", "ls-files", "-z", *args],
        cwd=root, capture_output=True, check=True,
    ).stdout
    return [os.fsdecode(p) for p in out.split(b"\0") if p]


def _candidate_files(root: Path) -> List[str]:
    if (root / ".git").exists():
        listed = _git_paths(root, "--cached", "--others", "--exclude-standard")
        # rg applies .gitignore to every path, tracked or not.
        ignored = set(_git_paths(root, "--cached", "--ignored", "--exclude-standard"))
        rels = [p for p in listed if p not in ignored]
    else:
        # Outside a git work tree rg applies no .gitignore at all.
        rels = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            base = Path(dirpath).relative_to(root).as_posix()
            for name in filenames:
                rels.append(name if base == "." else f"{base}/{name}")
    for rel in rels:
        if rel.rsplit("/", 1)[-1] in _RG_ONLY_IGNORE_FILES:
            raise RuntimeError(
                f"{rel}: rg honors .ignore/.rgignore files and this stand-in "
                "does not; extend tests/rename/_hermes_scan.py first")
    return sorted(set(rels))


def _hidden(rel: str) -> bool:
    return any(part.startswith(".") for part in rel.split("/"))


# --------------------------------------------------------------------------- #
# Per-file decode + binary handling
# --------------------------------------------------------------------------- #

def _transcode(raw: bytes) -> Tuple[bytes, bool]:
    """rg --encoding auto: strip a UTF-8 BOM, transcode BOM'd UTF-16."""
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:], False
    for bom, codec in ((b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be")):
        if raw.startswith(bom):
            return raw[2:].decode(codec, errors="replace").encode("utf-8"), True
    return raw, False


def _searched_prefix(data: bytes, transcoded: bool) -> Tuple[bytes, Optional[int]]:
    """Return (the bytes rg searches, NUL offset or None).

    No NUL: everything is searched. Otherwise this simulates rg's 64 KiB
    line-buffer reads. Each read ends at the last line terminator, and the read
    that contains the NUL is discarded, not searched.
    """
    nul = data.find(b"\0")
    if nul < 0:
        return data, None
    if transcoded:
        return data[:data.rfind(b"\n", 0, nul) + 1], nul   # superset (see module doc)
    searched_end = 0       # end of the lines rg has already searched
    read_off = 0           # absolute offset of the next read
    while True:
        while True:
            free = _RG_BUFFER - (read_off - searched_end)
            if free <= 0:  # a line longer than the buffer: rg grows it
                return data[:data.rfind(b"\n", 0, nul) + 1], nul   # superset
            new = data[read_off:read_off + free]
            if b"\0" in new:
                return data[:searched_end], nul
            read_off += len(new)
            lt = new.rfind(b"\n")
            if lt >= 0:
                searched_end = read_off - len(new) + lt + 1
                break


def _scan_file(rel: str, raw: bytes) -> List[str]:
    data, transcoded = _transcode(raw)
    searched, nul = _searched_prefix(data, transcoded)
    lines: List[str] = []
    chunks = searched.split(b"\n")
    if searched.endswith(b"\n"):
        chunks.pop()   # the empty piece after the final terminator is not a line
    for lineno, chunk in enumerate(chunks, start=1):
        text = chunk.decode("utf-8", errors="replace")
        if _MATCH.search(text):
            lines.append(f"./{rel}:{lineno}:{text}")
    if nul is not None and lines:
        lines.append(
            f"./{rel}: WARNING: stopped searching binary file after match "
            f'(found "\\0" byte around offset {nul})'
        )
    return lines


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

def iter_scan_lines(repo_root: Path, excludes: Sequence[str]) -> Iterable[str]:
    root = Path(repo_root)
    globs = parse_excludes(excludes)
    for rel in _candidate_files(root):
        if _hidden(rel) or _excluded(rel, globs):
            continue
        path = root / rel
        if path.is_symlink() or not path.is_file():
            continue
        yield from _scan_file(rel, path.read_bytes())


def scan(repo_root: Path, excludes: Sequence[str]) -> str:
    """stdout text equivalent to ``rg -in --no-heading hermes <excludes> .``."""
    lines = list(iter_scan_lines(repo_root, excludes))
    return "".join(line + "\n" for line in lines)
