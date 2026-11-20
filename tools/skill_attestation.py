"""Verify owner-signed skill and plugin bundles under an activated SR-06 policy."""

from __future__ import annotations

import datetime
import hashlib
import importlib
import importlib.machinery
import importlib.util
import logging
import os
import stat
import sys
import tempfile
import threading
from pathlib import Path, PurePosixPath
from types import CodeType, ModuleType
from typing import overload

from agent.attestation import verify_manifest
from lliam_cli.provisioning import is_unprovisioned

if sys.version_info >= (3, 13):
    from ntpath import isreserved as _is_windows_reserved
else:
    from pathlib import PureWindowsPath

    def _is_windows_reserved(part: str) -> bool:
        return PureWindowsPath(part).is_reserved()

_log = logging.getLogger(__name__)
_lock = threading.Lock()
_import_lock = threading.RLock()
_BUNDLED_PLUGINS = Path(__file__).resolve().parents[1] / "plugins"
_snapshots: dict[str, tuple[tempfile.TemporaryDirectory, Path]] = {}
_snapshot_ids: dict[Path, str] = {}
_snapshot_directories: set[str] = set()


class _SnapshotSourceLoader(importlib.machinery.SourceFileLoader):
    """Compile approved source directly, without reading or writing a bytecode cache."""

    def get_code(self, fullname: str) -> CodeType:
        path = self.get_filename(fullname)
        return self.source_to_code(self.get_data(path), path)


def _snapshot_path_hook(path: str) -> importlib.machinery.FileFinder:
    """Let normal imports use their usual finders outside published snapshots."""
    if path not in _snapshot_directories:
        raise ImportError
    return importlib.machinery.FileFinder(
        path,
        (importlib.machinery.ExtensionFileLoader, importlib.machinery.EXTENSION_SUFFIXES),
        (_SnapshotSourceLoader, importlib.machinery.SOURCE_SUFFIXES),
    )


def artifact_module_spec(name: str, path: str | Path, **options) -> importlib.machinery.ModuleSpec | None:
    """Choose the same source-only loader for explicit snapshot file imports."""
    source = Path(path)
    if str(source.parent) in _snapshot_directories and source.suffix in importlib.machinery.SOURCE_SUFFIXES:
        options["loader"] = _SnapshotSourceLoader(name, str(source))
    return importlib.util.spec_from_file_location(name, path, **options)


def verified_module_name(name: str, directory: Path) -> str:
    """Keep relative imports and cached modules scoped to the approved revision."""
    signature = _snapshot_ids.get(directory)
    return f"{name}__{signature}" if signature else name


def _check_snapshot(snapshot: Path, files: dict[str, bytes], executables: set[str]) -> None:
    """Reject cached snapshots containing replacement, additional or missing files."""
    expected_dirs = {parent for label in files for parent in Path(label).parents}
    seen = set()
    pending = [snapshot]
    while pending:
        directory = pending.pop()
        if directory.is_symlink() or directory.relative_to(snapshot) not in expected_dirs:
            raise PermissionError("Unapproved directory in cached artifact")
        for entry in directory.iterdir():
            if entry.is_dir():
                pending.append(entry)
                continue
            name = entry.relative_to(snapshot).as_posix()
            if (entry.is_symlink() or not entry.is_file() or name not in files
                    or entry.read_bytes() != files[name]):
                raise PermissionError("Cached artifact differs from signed inventory")
            if os.name == "posix" and stat.S_IMODE(entry.stat().st_mode) != (0o500 if name in executables else 0o400):
                raise PermissionError("Cached artifact permissions changed")
            seen.add(name)
    if seen != files.keys():
        raise PermissionError("Cached artifact is missing approved files")


def active_policy() -> dict | None:
    from lliam_cli import config, posture_resolver
    from tools.tool_policy import load_skill_policy

    cfg = config.load_config()
    if not isinstance(cfg, dict) or not isinstance(cfg.get("security", {}), dict):
        raise PermissionError("Invalid skill security configuration")
    if not posture_resolver.is_strict(cfg):
        return None
    policy = load_skill_policy()
    mode = (policy.get("policy") or {}).get("unlisted_disposition")
    if mode not in {"hold", "log"}:
        raise PermissionError("Skill policy unreadable or missing a valid disposition")
    configured = ((cfg.get("security") or {}).get("skill_policy") or {}).get("unlisted_disposition")
    if configured == "hold" and mode != "hold":
        raise PermissionError("Required skill hold policy is unavailable")
    return policy if mode == "hold" else None


def _verified_files(kind: str, name: str, path: Path | None, policy: dict):
    security = policy["security"]
    if kind == "plugin" and name in security.get("plugin_denylist", []):
        raise PermissionError("Plugin is explicitly denied")
    entries = [row for row in security.get(f"{kind}_allowlist", [])
               if isinstance(row, dict) and row.get("name") == name]
    if len(entries) != 1 or path is None:
        raise PermissionError(f"No unique directory attestation for {kind} {name!r}")
    row = entries[0]
    signers = security.get("trusted_signers")
    if not isinstance(signers, list) or row.get("kind") != kind or row.get("signer") not in signers:
        raise PermissionError("Unapproved artifact kind or signer")
    for field in ("source", "sdl_record", "approver"):
        if not isinstance(row.get(field), str) or is_unprovisioned(row[field]):
            raise PermissionError(f"Missing authenticated {field}")
    if datetime.date.fromisoformat(str(row["expires"])) < datetime.datetime.now(datetime.timezone.utc).date():
        raise PermissionError("Artifact approval expired")
    verdict = verify_manifest(row)
    if not verdict.valid:
        raise PermissionError(verdict.reason)
    expected = row.get("files")
    if not isinstance(expected, dict) or not expected or (kind == "skill" and "SKILL.md" not in expected):
        raise PermissionError("Missing signed file inventory")
    executables = row.get("executables", [])
    if not isinstance(executables, list) or not set(executables) <= expected.keys():
        raise PermissionError("Invalid signed executable inventory")
    files = {}
    root = path.resolve(strict=True)
    for label, digest in expected.items():
        rel = PurePosixPath(label)
        if (not rel.parts or rel.is_absolute() or ".." in rel.parts or rel.as_posix() != label
                or "\\" in label or ":" in label or "__pycache__" in rel.parts
                or any(_is_windows_reserved(part) for part in rel.parts)
                or rel.suffix.lower() in {".pyc", ".pyo"}):
            raise PermissionError("Invalid signed artifact path")
        candidate = root.joinpath(*rel.parts)
        if candidate.resolve(strict=True) != candidate or not stat.S_ISREG(candidate.stat().st_mode):
            raise PermissionError(f"Signed artifact is not a regular file: {label}")
        data = candidate.read_bytes()
        if digest != "sha256:" + hashlib.sha256(data).hexdigest():
            raise PermissionError(f"Artifact content differs from approved digest: {label}")
        if label.endswith(".py"):
            from tools.skills_ast_audit import ast_scan_source
            if ast_scan_source(data.decode("utf-8"), label, strict=True):
                raise PermissionError(f"Python audit requires review: {label}")
        files[label] = data
    return row["signature"], files, set(executables), root


def record_refusal(kind: str, name: str, reason: str) -> None:
    """Record a refused runtime load, including when the ledger is unavailable."""
    _log.warning("%s %r held: %s", kind, name, reason)
    try:
        from agent import governance_audit
        governance_audit.emit("policy.violation", action=f"{kind}.load", decision="deny",
                              resource={"type": kind, "name": name},
                              outcome={"reason": reason}, source_module=__name__)
    except Exception:
        _log.exception("Unable to record %s load refusal", kind)


@overload
def verified_directory(kind: str, name: str, path: Path, *, check_only: bool = False) -> Path: ...


@overload
def verified_directory(kind: str, name: str, path: None, *, check_only: bool = False) -> None: ...


def verified_directory(kind: str, name: str, path: Path | None, *, check_only: bool = False) -> Path | None:
    """Supply only the verified bytes to consumers, including lazy Python imports."""
    try:
        policy = active_policy()
        if policy is None:
            return path
        signature, files, executables, root = _verified_files(kind, name, path, policy)
        if check_only:
            return path
        with _lock:
            if signature in _snapshots:
                snapshot = _snapshots[signature][1]
                _check_snapshot(snapshot, files, executables)
                return snapshot
            temporary = tempfile.TemporaryDirectory(prefix="lliam-attested-")
            snapshot = Path(temporary.name).resolve() / (root.name or "bundle")
            snapshot.mkdir()
            for label, data in files.items():
                target = snapshot / label
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as out:
                    out.write(data)
                target.chmod(0o500 if label in executables else 0o400)
            directories = [directory for directory, _, _ in os.walk(snapshot, topdown=False)]
            for directory in directories:
                Path(directory).chmod(0o500)
                sys.path_importer_cache.pop(directory, None)
            # Relative imports use the package's normal search path, including
            # lazy imports after importlib invalidates its finder caches.
            _snapshot_directories.update(directories)
            if _snapshot_path_hook not in sys.path_hooks:
                sys.path_hooks.insert(0, _snapshot_path_hook)
            _snapshots[signature] = temporary, snapshot
            _snapshot_ids[snapshot] = signature
            return snapshot
    except Exception as exc:
        if not check_only:
            record_refusal(kind, name, str(exc))
        raise PermissionError(f"{kind} {name!r} held: {exc}") from exc


def load_bundled_plugin_module(category: str, provider: str, submodule: str | None = None) -> ModuleType:
    """Import from the verified revision under hold, and the normal package otherwise."""
    parts = (category, provider) if submodule is None else (category, provider, submodule)
    if not all(part.isidentifier() for part in parts):
        raise ImportError("Invalid bundled plugin module name")
    base = f"plugins.{category}.{provider}"
    directory = verified_directory("plugin", f"{category}/{provider}", _BUNDLED_PLUGINS / category / provider)
    package = verified_module_name(base, directory)
    if package == base:
        return importlib.import_module(f"{base}.{submodule}" if submodule else base)

    with _import_lock:
        cached = sys.modules.get(package)
        if submodule:
            if cached is None:
                shell = importlib.machinery.ModuleSpec(package, loader=None, is_package=True)
                shell.submodule_search_locations = [str(directory)]
                sys.modules[package] = importlib.util.module_from_spec(shell)
            return importlib.import_module(f"{package}.{submodule}")
        if cached is not None and getattr(cached, "__file__", None):
            return cached
        spec = artifact_module_spec(
            package, directory / "__init__.py", submodule_search_locations=[str(directory)]
        )
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot load bundled package {base!r}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[package] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            if cached is None:
                sys.modules.pop(package, None)
            else:
                sys.modules[package] = cached
            raise
        return module
