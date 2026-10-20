"""TC-RC-01: the rename guard's pure-Python scan matches ripgrep exactly.

``test_no_hermes_identifiers`` uses ``rg`` when it is on PATH and
``tests/rename/_hermes_scan.scan`` when it is not. This file builds a small git
work tree that hits every rg rule the guard depends on, then checks the scan
against two references:

* ``_RG_REFERENCE``: the output ripgrep 14.1.1 printed for this exact fixture
  (``rg -in --no-heading hermes <EXCLUDES> .``). It is pinned here so the proof
  also runs on machines with no rg installed;
* a live ``rg`` run, whenever rg is on PATH.

Both comparisons are line-for-line multisets. A drift in either direction fails
the test, so the fallback can never quietly scan less than rg does.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections import Counter
from pathlib import Path

import pytest

from tests.rename import _hermes_scan
from tests.rename.test_no_hermes_identifiers import EXCLUDES


def _w(root: Path, rel: str, data: bytes) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)


def _build_fixture(root: Path) -> None:
    w = lambda rel, data: _w(root, rel, data)  # noqa: E731
    # Plain matches: case-insensitive, CRLF, lone CR, form feed, no final LF.
    w("plain.txt", b"one\nHermes two\nthree HERMES\nno\n")
    w("crlf.txt", b"a hermes\r\nb\r\n")
    w("cr_only.txt", b"a hermes\rb hermes\n")
    w("ff.txt", b"x hermes\x0cy\n")
    w("nonl.txt", b"x\nlast hermes")
    # Unicode simple case folding: LATIN SMALL LETTER LONG S folds to 's'.
    w("longs.txt", "hermeſ long s\n".encode())
    # Encodings: BOM'd UTF-16 is transcoded, a UTF-8 BOM is stripped, invalid
    # UTF-8 still matches on its valid bytes.
    w("u16le.txt", "﻿hermes utf16\nline2 hermes\n".encode("utf-16-le"))
    w("u16be.txt", "﻿hermes be\n".encode("utf-16-be"))
    w("u8bom.txt", "﻿hermes bom\n".encode("utf-8"))
    w("bad_utf8.txt", b"ok \xc3\x28 hermes \xff here\n")
    # Binary: a NUL inside the first 64 KiB read hides the whole file; a later
    # NUL hides only the read that holds it, plus rg prints a WARNING line.
    w("bin_start.bin", b"\x00hermes\n")
    w("bin_mid.bin", b"hermes before\n" + b"x" * 100 + b"\x00\nhermes after\n")
    for off in (65535, 65536, 70000):
        head = b"hermes first\n"
        w(f"nul_{off}.bin", head + b"z" * (off - len(head) - 1) + b"\n\x00hermes x\n")
    w("bin_late.bin", b"hermes early\n" + (b"y" * 79 + b"\n") * 3000
      + b"hermes late\n\x00\nhermes post\n")
    w("late_match.bin", b"a\n" * 40000 + b"hermes mid\n" + b"b\n" * 40000 + b"\x00\n")
    # Every EXCLUDES glob shape: anchored vs any-depth, '*' not crossing '/',
    # a matching directory excluding its whole subtree.
    w("evidence/top.txt", b"hermes\n")
    w("a/evidence/nested.txt", b"hermes nested evidence\n")
    w("sub/NOTICE", b"hermes notice\n")
    w("NOTICE/inner.txt", b"hermes in notice dir\n")
    w("LICENSES/x.txt", b"hermes license dir\n")
    w("x/ATTRIBUTION.md", b"hermes attribution\n")
    w("pkg/node_modules/m/i.js", b"hermes\n")
    w("pkg/dist/o.js", b"hermes\n")
    w("pkg/build/out.txt", b"hermes\n")
    w("pkg/builder/kept.txt", b"hermes builder kept\n")
    w("pkg/x.egg-info/PKG", b"hermes\n")
    w("deep/thing.lock", b"hermes\n")
    w("deep/package-lock.json", b"hermes\n")
    w("graphify-out/g.json", b"hermes\n")
    w("docs/upstream/u.md", b"hermes\n")
    w("docs/governance/plans/p.md", b"hermes\n")
    w("docs/governance/verification/R8e-keep-register.md", b"hermes\n")
    w("docs/governance/verification/sub/R8e-keep-register.md", b"hermes sub\n")
    w("docs/governance/verification/R-rename-report.md", b"hermes\n")
    w("docs/governance/verification/R-rename-report.md.bak", b"hermes bak\n")
    # Hidden files/dirs, gitignored files (tracked and untracked), a symlink.
    w(".hidden.txt", b"hermes\n")
    w(".hdir/f.txt", b"hermes\n")
    w("ignored_untracked.log", b"hermes\n")
    w("tracked_ignored.log", b"hermes tracked ignored\n")
    w(".gitignore", b"*.log\n")
    os.symlink("plain.txt", root / "link.txt")


# ripgrep 14.1.1 on _build_fixture(), `rg -in --no-heading hermes <EXCLUDES> .`
_RG_REFERENCE = [
    "./a/evidence/nested.txt:1:hermes nested evidence",
    "./bad_utf8.txt:1:ok �( hermes � here",
    "./bin_late.bin:1:hermes early",
    './bin_late.bin: WARNING: stopped searching binary file after match '
    '(found "\\0" byte around offset 240025)',
    "./cr_only.txt:1:a hermes\rb hermes",
    "./crlf.txt:1:a hermes\r",
    "./docs/governance/verification/R-rename-report.md.bak:1:hermes bak",
    "./docs/governance/verification/sub/R8e-keep-register.md:1:hermes sub",
    "./ff.txt:1:x hermes\x0cy",
    "./late_match.bin:40001:hermes mid",
    './late_match.bin: WARNING: stopped searching binary file after match '
    '(found "\\0" byte around offset 160011)',
    "./longs.txt:1:hermeſ long s",
    "./nonl.txt:2:last hermes",
    "./nul_65536.bin:1:hermes first",
    './nul_65536.bin: WARNING: stopped searching binary file after match '
    '(found "\\0" byte around offset 65536)',
    "./nul_70000.bin:1:hermes first",
    './nul_70000.bin: WARNING: stopped searching binary file after match '
    '(found "\\0" byte around offset 70000)',
    "./pkg/builder/kept.txt:1:hermes builder kept",
    "./plain.txt:2:Hermes two",
    "./plain.txt:3:three HERMES",
    "./u16be.txt:1:hermes be",
    "./u16le.txt:1:hermes utf16",
    "./u16le.txt:2:line2 hermes",
    "./u8bom.txt:1:hermes bom",
]


@pytest.fixture
def fixture_repo(tmp_path, monkeypatch):
    # Hermetic git: no system/global config or global excludes file can change
    # what either scanner treats as ignored.
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", "."], cwd=root, check=True)
    _build_fixture(root)
    subprocess.run(["git", "add", "-f", "tracked_ignored.log", "plain.txt"],
                   cwd=root, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t",
         "commit", "-q", "-m", "fixture"],
        cwd=root, check=True,
    )
    return root


def _lines(stdout: str) -> Counter:
    return Counter(line for line in stdout.split("\n") if line)


def test_fallback_matches_pinned_ripgrep_output(fixture_repo):
    got = _lines(_hermes_scan.scan(fixture_repo, EXCLUDES))
    want = Counter(_RG_REFERENCE)
    assert got == want, (
        f"only fallback: {sorted((got - want).elements())}\n"
        f"only rg: {sorted((want - got).elements())}"
    )


def test_fallback_matches_live_ripgrep_when_installed(fixture_repo):
    rg = shutil.which("rg")
    py = _lines(_hermes_scan.scan(fixture_repo, EXCLUDES))
    if rg is None:
        # Without rg the pinned reference above is the proof; the fallback
        # must at least be what the guard actually runs.
        assert py == Counter(_RG_REFERENCE)
        return
    res = subprocess.run(
        [rg, "-in", "--no-heading", "hermes", *EXCLUDES, "."],
        cwd=fixture_repo, capture_output=True,
    )
    assert res.returncode in (0, 1), res.stderr
    live = _lines(res.stdout.decode("utf-8", errors="replace"))
    assert py == live, (
        f"only fallback: {sorted((py - live).elements())}\n"
        f"only rg: {sorted((live - py).elements())}"
    )


def test_guard_parse_path_sees_same_offenders_on_both_engines(fixture_repo):
    """The guard's own line parser yields the same (path, text) records."""
    def records(stdout):
        out = []
        for raw in stdout.splitlines():
            parts = raw.split(":", 2)
            if len(parts) == 3:
                out.append((parts[0], parts[2]))
        return Counter(out)

    py = records(_hermes_scan.scan(fixture_repo, EXCLUDES))
    ref = records("".join(line + "\n" for line in _RG_REFERENCE))
    assert py == ref


def test_guard_excludes_all_translate():
    # Every EXCLUDES entry the guard ships must be a glob the fallback
    # reproduces exactly; anything else raises instead of diverging.
    assert len(_hermes_scan.parse_excludes(EXCLUDES)) == len(EXCLUDES) // 2


@pytest.mark.parametrize("bad", [
    ["-g", "!foo/[ab]/**"],     # character class
    ["-g", "!{a,b}/**"],        # alternation
    ["-g", "!build/"],          # directory-only form
    ["-g", "!a**b"],            # '**' not a whole path component
    ["-g", "keep/**"],          # whitelist (non-negated) glob
    ["--hidden"],               # not a '-g' pair
])
def test_unsupported_exclude_syntax_is_rejected(bad):
    with pytest.raises(ValueError):
        _hermes_scan.parse_excludes(bad)


def test_rg_only_ignore_file_is_a_hard_error(fixture_repo):
    (fixture_repo / "sub" / ".rgignore").write_text("*\n")
    with pytest.raises(RuntimeError, match="rgignore"):
        _hermes_scan.scan(fixture_repo, EXCLUDES)
