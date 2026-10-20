"""TC-RC-01: the rename guard's pure-Python scan matches ripgrep.

``test_no_hermes_identifiers`` uses ``rg`` when it is on PATH and
``tests/rename/_hermes_scan.scan`` when it is not. This file builds a small git
work tree that hits every rg rule the guard depends on, then checks the scan
against two references:

* ``_RG_REFERENCE``: the output ripgrep 14.1.1 printed for this exact fixture
  (``rg -in --no-heading hermes <EXCLUDES> .``). It is pinned here so the proof
  also runs on machines with no rg installed;
* a live ``rg`` run, whenever rg is on PATH.

Text files (no NUL byte) must match line-for-line in both directions, because
every rg version prints the same lines for them. Binary files are different:
how much text before the first NUL rg shows depends on its read-buffer size and
read() sizes, so ripgrep versions disagree (14.1.1 and 15.1.0 differ on a NUL
at offset 65536). For those the fallback reports every match before the NUL,
and the check is one-way: every binary-file line rg prints must also be in the
fallback's output. A drift that would let the fallback scan less than rg fails
the test either way. The exact 14.1.1 binary output is checked against the
pinned reference only, and against live rg only when live rg is 14.1.1.
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


# What the fallback reports for the binary fixtures: every match before the
# first NUL, plus the WARNING line. Version-independent by construction.
_FALLBACK_BINARY = [
    "./bin_late.bin:1:hermes early",
    "./bin_late.bin:3002:hermes late",
    './bin_late.bin: WARNING: stopped searching binary file after match '
    '(found "\\0" byte around offset 240025)',
    "./bin_mid.bin:1:hermes before",
    './bin_mid.bin: WARNING: stopped searching binary file after match '
    '(found "\\0" byte around offset 114)',
    "./late_match.bin:40001:hermes mid",
    './late_match.bin: WARNING: stopped searching binary file after match '
    '(found "\\0" byte around offset 160011)',
    "./nul_65535.bin:1:hermes first",
    './nul_65535.bin: WARNING: stopped searching binary file after match '
    '(found "\\0" byte around offset 65535)',
    "./nul_65536.bin:1:hermes first",
    './nul_65536.bin: WARNING: stopped searching binary file after match '
    '(found "\\0" byte around offset 65536)',
    "./nul_70000.bin:1:hermes first",
    './nul_70000.bin: WARNING: stopped searching binary file after match '
    '(found "\\0" byte around offset 70000)',
]


def _lines(stdout: str) -> Counter:
    return Counter(line for line in stdout.split("\n") if line)


def _is_binary(root: Path, path: str) -> bool:
    """rg's view: the file still holds a NUL after BOM handling/transcoding."""
    assert path.startswith("./"), path
    return b"\0" in _hermes_scan._transcode((root / path[2:]).read_bytes())


def _split(root: Path, items: Counter, path_of) -> "tuple[Counter, Counter]":
    text, binary = Counter(), Counter()
    for item, n in items.items():
        (binary if _is_binary(root, path_of(item)) else text)[item] += n
    return text, binary


def _line_path(line: str) -> str:
    return line.split(":", 1)[0]


def _assert_covers_rg(root: Path, py: Counter, rg: Counter, path_of=_line_path):
    """Text files: exact. Binary files: the fallback holds every rg line."""
    py_text, py_bin = _split(root, py, path_of)
    rg_text, rg_bin = _split(root, rg, path_of)
    assert py_text == rg_text, (
        f"only fallback: {sorted((py_text - rg_text).elements())}\n"
        f"only rg: {sorted((rg_text - py_text).elements())}"
    )
    missed = rg_bin - py_bin
    assert not missed, (
        f"rg reports binary-file lines the fallback misses: {sorted(missed.elements())}"
    )


def _assert_pinned(root: Path, py: Counter) -> None:
    _assert_covers_rg(root, py, Counter(_RG_REFERENCE))
    _, py_bin = _split(root, py, _line_path)
    assert py_bin == Counter(_FALLBACK_BINARY), (
        f"only fallback: {sorted((py_bin - Counter(_FALLBACK_BINARY)).elements())}\n"
        f"only expected: {sorted((Counter(_FALLBACK_BINARY) - py_bin).elements())}"
    )


def test_fallback_matches_pinned_ripgrep_output(fixture_repo):
    _assert_pinned(fixture_repo, _lines(_hermes_scan.scan(fixture_repo, EXCLUDES)))


def test_pinned_reference_hides_only_binary_lines_the_fallback_reports(fixture_repo):
    # 14.1.1 drops some pre-NUL matches (its 64 KiB read holding the NUL is
    # discarded); the fallback reports them. Nothing else may differ.
    extra = Counter(_FALLBACK_BINARY) - Counter(_RG_REFERENCE)
    assert extra and all(_is_binary(fixture_repo, _line_path(x)) for x in extra)


def test_fallback_matches_live_ripgrep_when_installed(fixture_repo):
    rg = shutil.which("rg")
    py = _lines(_hermes_scan.scan(fixture_repo, EXCLUDES))
    if rg is None:
        # Without rg the pinned reference above is the proof; the fallback
        # must at least be what the guard actually runs.
        _assert_pinned(fixture_repo, py)
        return
    res = subprocess.run(
        [rg, "-in", "--no-heading", "hermes", *EXCLUDES, "."],
        cwd=fixture_repo, capture_output=True,
    )
    assert res.returncode in (0, 1), res.stderr
    live = _lines(res.stdout.decode("utf-8", errors="replace"))
    _assert_covers_rg(fixture_repo, py, live)
    version = subprocess.run([rg, "--version"], capture_output=True, text=True)
    if version.stdout.startswith("ripgrep 14.1.1 "):
        # The pinned reference must be what that rg really prints.
        assert live == Counter(_RG_REFERENCE), (
            f"only live: {sorted((live - Counter(_RG_REFERENCE)).elements())}\n"
            f"only pinned: {sorted((Counter(_RG_REFERENCE) - live).elements())}"
        )


def test_guard_parse_path_sees_same_offenders_on_both_engines(fixture_repo):
    """The guard's own line parser sees every rg offender on the fallback too."""
    def records(stdout):
        out = []
        for raw in stdout.splitlines():
            parts = raw.split(":", 2)
            if len(parts) == 3:
                out.append((parts[0], parts[2]))
        return Counter(out)

    py = records(_hermes_scan.scan(fixture_repo, EXCLUDES))
    ref = records("".join(line + "\n" for line in _RG_REFERENCE))
    _assert_covers_rg(fixture_repo, py, ref, path_of=lambda rec: rec[0])


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
