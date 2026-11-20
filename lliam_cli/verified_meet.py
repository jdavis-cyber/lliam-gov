"""Launch the detached Meet bot with its own copy of the approved bundle."""

from __future__ import annotations

import sys
from importlib import import_module
from pathlib import Path


def bot_command(directory: Path) -> list[str]:
    from tools.skill_attestation import verified_directory, verified_module_name

    bundle = verified_directory("plugin", "google_meet", directory)
    identity = verified_module_name("google_meet", bundle)
    if identity == "google_meet":
        return [sys.executable, "-m", "plugins.google_meet.meet_bot"]
    return [sys.executable, "-I", str(Path(__file__).resolve()), str(bundle), identity]


def run_verified_bot(parent_bundle: Path, expected_identity: str) -> int:
    from lliam_cli.plugins import PluginManager, PluginManifest
    from tools.skill_attestation import verified_directory, verified_module_name

    # Re-read the child's effective policy and verify every file before any
    # plugin import. The detached process now owns the snapshot it will use.
    bundle = verified_directory("plugin", "google_meet", parent_bundle)
    identity = verified_module_name("google_meet", bundle)
    if identity == "google_meet" or identity != expected_identity:
        raise PermissionError("Meet bot requires the same approved plugin as its parent")
    manifest = PluginManifest(name="google_meet", source="bundled", path=str(bundle))
    package = PluginManager()._load_directory_module(manifest)
    return import_module(".meet_bot", package.__name__).run_bot()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("Expected a verified Meet bundle and its identity")
    # The parent starts this trusted script by absolute path under -I. An
    # editable checkout and an installed package both resolve their own host.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    try:
        sys.exit(run_verified_bot(Path(sys.argv[1]), sys.argv[2]))
    except (ImportError, OSError, ValueError) as exc:
        sys.exit(f"Meet bot startup refused: {exc}")
