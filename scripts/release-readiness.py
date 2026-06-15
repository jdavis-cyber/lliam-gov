#!/usr/bin/env python3
"""Local release-readiness gate for Lliam-GOV desktop releases (AI-337).

Runs offline (no GitHub Actions). Validates the release invariants a deployable
build depends on:

  * desktop app metadata: appId, product/executable name, icon, artifactName
  * per-OS packaging metadata (macOS hardened runtime + entitlements, Windows
    target/metadata, Linux target)
  * install-stamp validity (when a build has produced one)
  * generated-artifact leakage (nothing under build/dist/release/node_modules is
    tracked in git)
  * lockfile presence

Exit code 0 = ready (only INFO/WARN); 1 = one or more FAILs. Intended to be run
before tagging a release and from the local merge gate (scripts/local-gate.sh).

Usage:
    python3 scripts/release-readiness.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DESKTOP_PKG = REPO / "apps" / "desktop" / "package.json"

FAILS: list[str] = []
WARNS: list[str] = []
INFOS: list[str] = []


def fail(msg: str) -> None:
    FAILS.append(msg)


def warn(msg: str) -> None:
    WARNS.append(msg)


def info(msg: str) -> None:
    INFOS.append(msg)


def load_desktop_pkg() -> dict:
    try:
        return json.loads(DESKTOP_PKG.read_text())
    except Exception as exc:  # noqa: BLE001
        fail(f"cannot read {DESKTOP_PKG.relative_to(REPO)}: {exc}")
        return {}


def check_metadata(pkg: dict) -> None:
    build = pkg.get("build") or {}
    if not build:
        fail("apps/desktop/package.json has no electron-builder `build` block")
        return

    app_id = build.get("appId", "")
    if not re.match(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$", app_id):
        fail(f"build.appId is not reverse-DNS: {app_id!r}")
    else:
        info(f"appId = {app_id}")

    # Branding: user-visible product/bundle names must be Lliam-GOV.
    if build.get("productName") != "Lliam-GOV":
        fail(f"build.productName must be 'Lliam-GOV' (got {build.get('productName')!r})")
    bundle_name = ((build.get("mac") or {}).get("extendInfo") or {}).get("CFBundleName")
    if bundle_name not in (None, "Lliam-GOV"):
        fail(f"mac CFBundleName must be 'Lliam-GOV' (got {bundle_name!r})")

    if not build.get("icon"):
        fail("build.icon is not set")

    artifact = build.get("artifactName", "")
    if "${version}" not in artifact:
        fail(f"build.artifactName should embed ${{version}} (got {artifact!r})")

    version = pkg.get("version", "")
    if not re.match(r"^\d+\.\d+\.\d+", str(version)):
        fail(f"apps/desktop version is not semver: {version!r}")
    else:
        info(f"desktop version = {version}")


def check_per_os(pkg: dict) -> None:
    build = pkg.get("build") or {}
    mac = build.get("mac") or {}
    if mac.get("hardenedRuntime") is not True:
        fail("mac.hardenedRuntime must be true")
    ent = mac.get("entitlements")
    if ent and not (REPO / "apps" / "desktop" / ent).exists():
        warn(f"mac entitlements file missing on disk: {ent}")

    win = build.get("win") or {}
    if not win.get("target"):
        fail("win.target is empty (need nsis/msi)")
    # Authenticode signing is intentionally deferred — flag, don't fail.
    if win.get("signAndEditExecutable") is False:
        warn("Windows Authenticode signing is OFF (pending signing certs — Jerome)")

    linux = build.get("linux") or {}
    if not linux.get("target"):
        fail("linux.target is empty (need AppImage/deb/rpm)")

    # Notarization hook present but certs pending.
    if build.get("afterSign"):
        warn("macOS notarization hook present but Developer ID signing pending certs (Jerome)")


def check_install_stamp() -> None:
    stamp = REPO / "apps" / "desktop" / "build" / "install-stamp.json"
    if not stamp.exists():
        info("install-stamp.json absent (generated at build time) — skipping stamp validation")
        return
    try:
        data = json.loads(stamp.read_text())
    except Exception as exc:  # noqa: BLE001
        fail(f"install-stamp.json is unreadable: {exc}")
        return
    if data.get("schemaVersion") != 1:
        fail(f"install-stamp schemaVersion != 1: {data.get('schemaVersion')!r}")
    if not re.match(r"^[0-9a-f]{7,40}$", str(data.get("commit", ""))):
        fail(f"install-stamp commit is not a SHA: {data.get('commit')!r}")
    else:
        info(f"install-stamp commit = {str(data['commit'])[:12]}")


# Generated outputs that must never be tracked. Scoped to the desktop release
# artifacts + any node_modules (nested or root). Deliberately NOT a blanket
# `*/dist/` match: some plugins ship source-committed dashboard bundles under
# their own dist/, which are intentional and out of scope here.
LEAK_PREFIXES = (
    "apps/desktop/build/",
    "apps/desktop/dist/",
    "apps/desktop/release/",
    "node_modules/",
    "dist/",
    "release/",
)
LEAK_SUBSTR = ("/node_modules/",)


def check_leakage() -> None:
    try:
        out = subprocess.run(
            ["git", "ls-files"], cwd=REPO, capture_output=True, text=True, check=True
        ).stdout
    except Exception as exc:  # noqa: BLE001
        warn(f"could not run `git ls-files` for leakage check: {exc}")
        return
    tracked = out.splitlines()
    leaked = [
        p
        for p in tracked
        if p.startswith(LEAK_PREFIXES) or any(s in p for s in LEAK_SUBSTR)
    ]
    # Allow committed source under web/dist etc. only if not a generated bundle —
    # keep the check strict for the known generated roots above.
    if leaked:
        fail(f"generated artifacts are tracked in git ({len(leaked)} paths), e.g. {leaked[:5]}")
    else:
        info("no generated build/dist/release/node_modules artifacts are tracked")


def check_lockfiles() -> None:
    def tracked(path: str) -> bool:
        r = subprocess.run(
            ["git", "ls-files", "--error-unmatch", path],
            cwd=REPO,
            capture_output=True,
            text=True,
        )
        return r.returncode == 0

    if tracked("package-lock.json"):
        info("root package-lock.json tracked")
    else:
        warn("root package-lock.json not tracked")
    if tracked("uv.lock"):
        info("uv.lock tracked")
    else:
        warn("uv.lock not tracked")
    if not tracked("apps/desktop/package-lock.json"):
        warn("apps/desktop/package-lock.json is not tracked (desktop install not lockfile-pinned)")


def main() -> int:
    pkg = load_desktop_pkg()
    if pkg:
        check_metadata(pkg)
        check_per_os(pkg)
    check_install_stamp()
    check_leakage()
    check_lockfiles()

    print("== Lliam-GOV release-readiness ==")
    for m in INFOS:
        print(f"  INFO  {m}")
    for m in WARNS:
        print(f"  WARN  {m}")
    for m in FAILS:
        print(f"  FAIL  {m}")
    print(f"-- {len(FAILS)} fail, {len(WARNS)} warn, {len(INFOS)} info --")
    if FAILS:
        print("NOT READY: resolve FAILs above.")
        return 1
    print("READY (warnings are non-blocking; review before tagging).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
