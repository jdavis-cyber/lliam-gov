"""Build and verify detached worker commands for bundled plugins."""

from __future__ import annotations

import re
import sys
from importlib import import_module, util
from pathlib import Path


def _validate_names(plugin: str, module: str, function: str) -> None:
    if not all(re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", part) for part in plugin.split("/")):
        raise ValueError("Invalid bundled plugin identity")
    if not all(part.isidentifier() and not part.startswith("__") for part in (module, function)):
        raise ValueError("Invalid package-local worker entry point")


def _worker_file(bundle: Path, module: str) -> Path:
    worker = bundle / f"{module}.py"
    if not (bundle / "__init__.py").is_file() or not worker.is_file():
        raise PermissionError("Worker entry point is absent from the approved plugin")
    return worker


def worker_command(plugin: str, module: str, function: str, *, directory: Path) -> list[str]:
    """Pin the revision of the running plugin before detaching its worker."""
    from tools.skill_attestation import verified_directory, verified_module_name

    _validate_names(plugin, module, function)
    bundle = verified_directory("plugin", plugin, directory)
    identity = verified_module_name(plugin, bundle)
    if identity == plugin:
        return [sys.executable, "-m", f"plugins.{plugin.replace('/', '.')}.{module}"]
    _worker_file(bundle, module)
    return [sys.executable, "-I", str(Path(__file__).resolve()), plugin, module, function, identity]


def run_verified_worker(plugin: str, module: str, function: str, expected_identity: str) -> int:
    from lliam_cli.plugins import PluginManager, PluginManifest, get_bundled_plugins_dir
    from tools.skill_attestation import verified_directory, verified_module_name

    _validate_names(plugin, module, function)
    # The parent can exit immediately after Popen. Reconstruct the child's
    # own snapshot from the installed source, including packaged/Nix installs.
    bundle = verified_directory("plugin", plugin, get_bundled_plugins_dir() / plugin)
    identity = verified_module_name(plugin, bundle)
    if identity == plugin or identity != expected_identity:
        raise PermissionError("Worker requires the same approved plugin as its parent")
    worker_file = _worker_file(bundle, module)
    sys.argv = [str(worker_file)]
    manifest = PluginManifest(name=plugin, source="bundled", path=str(bundle))
    parent = PluginManager()._load_directory_module(manifest)
    qualified = f"{parent.__name__}.{module}"
    spec = util.find_spec(qualified)
    if spec is None or spec.origin != str(worker_file):
        raise PermissionError("Worker module is outside the approved plugin")
    worker = vars(import_module(qualified)).get(function)
    if not callable(worker) or getattr(worker, "__module__", None) != qualified:
        raise PermissionError("Worker function is absent from the approved module")
    return worker()


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit("Expected plugin, worker module, function and approved revision")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    try:
        sys.exit(run_verified_worker(*sys.argv[1:]))
    except (ImportError, OSError, ValueError) as exc:
        sys.exit(f"Plugin worker startup refused: {exc}")
