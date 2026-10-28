"""Incident recovery primitives for the kill-switch (LG-IR-04/07/08).

Recovery used to trust a caller-supplied ``verify_ok`` flag. These helpers do
the verification and the restore themselves, using the repo's existing
verifiers:

* :func:`verify_audit_chain` — ``agent.governance_audit.verify_chain`` over
  the live ledger (fail-closed: an enabled ledger that is missing, empty,
  unreadable, or broken FAILS).
* :func:`resolve_baseline` — the signed baseline of record
  (``docs/governance/authorization-record.yaml`` ``baseline.git_tag`` /
  ``git_commit``) or an operator-named tag, resolved in the LOCAL git
  checkout (no fetch, no network). A tag that no longer points at the pinned
  commit is refused.
* :func:`check_baseline_content` — run the baseline-drift gate's critical-
  key check (``ci/governance-ci-gates/baseline_drift_gate.py``) over the
  baseline commit's overlay BEFORE anything is written, so an unfit
  baseline never lands.
* :func:`restore_baseline` / :func:`verify_restored` — rewrite the
  baseline-controlled files (the gov overlay, ``policy/``, and the
  critical-keys policy) from the baseline commit, then confirm the bytes
  match.
* :func:`preserve_forensics` — the governance evidence store: copies the
  ledger, the kill-switch state and every displaced file into
  ``<home>/logs/incident-evidence/<id>/`` (inside the agent write-denied
  logs tree) with a SHA-256 custody manifest, and anchors the manifest hash
  in the hash-chained ledger. This replaces the oss-forensics optional
  skill's evidence store, which the governed profile denies.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import os
import re
import subprocess
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

_log = logging.getLogger("hermes.incident_recovery")

AUTH_RECORD = "docs/governance/authorization-record.yaml"
CRITICAL_KEYS = "docs/governance/baseline-critical-keys.yaml"
DEFAULT_OVERLAY = "cli-config.gov.yaml"
# Baseline-controlled paths besides the overlay (files or directory prefixes).
BASELINE_EXTRA_PATHS = ("policy", CRITICAL_KEYS)

_CODE_ROOT = Path(__file__).resolve().parents[1]
_DRIFT_GATE = _CODE_ROOT / "ci" / "governance-ci-gates" / "baseline_drift_gate.py"
_ENV_LOCK = threading.Lock()
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/@+-]{0,199}")


class BaselineError(RuntimeError):
    """The signed baseline cannot be resolved or trusted."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Audit chain
# ---------------------------------------------------------------------------

@dataclass
class ChainCheck:
    ok: bool
    reason: str
    ledger_enabled: bool
    ledger_path: Optional[Path] = None
    checked: int = 0

    def as_dict(self) -> dict:
        return {"ok": self.ok, "reason": self.reason,
                "ledger_enabled": self.ledger_enabled,
                "ledger_path": str(self.ledger_path) if self.ledger_path else None,
                "checked": self.checked}


def ledger_path_or_none() -> Optional[Path]:
    """Path of the enabled process ledger, or None when disabled/unavailable."""
    try:
        from agent import governance_audit as ga
        led = ga.get_ledger()
    except Exception:
        return None
    path = getattr(led, "path", None) if led is not None else None
    return Path(path) if path else None


def verify_audit_chain(ledger_path: Optional[Path] = None) -> ChainCheck:
    """Verify the live audit chain. Never raises; failures are ``ok=False``."""
    try:
        from agent import governance_audit as ga
    except Exception as e:
        return ChainCheck(False, f"governance audit module unavailable ({e})", True)
    if ledger_path is not None:
        path = Path(ledger_path)
    else:
        try:
            led = ga.get_ledger()
        except Exception as e:
            return ChainCheck(False, f"audit ledger unavailable ({e})", True)
        if led is None:
            return ChainCheck(True, "audit ledger disabled in this profile "
                              "(no chain to verify)", False)
        raw = getattr(led, "path", None)
        if not raw:
            return ChainCheck(False, "audit ledger unavailable ("
                              f"{getattr(led, 'reason', 'no path')})", True)
        path = Path(raw)
    try:
        if not path.exists() or path.stat().st_size == 0:
            return ChainCheck(False, f"audit ledger {path} is missing or empty — "
                              "the incident record cannot be confirmed", True, path)
        res = ga.verify_chain(path)
    except Exception as e:
        return ChainCheck(False, f"verify_chain could not complete ({e})", True, path)
    if not res.ok:
        return ChainCheck(False, f"chain break at seq={res.break_seq}: {res.reason}",
                          True, path, res.checked)
    if res.checked == 0:
        return ChainCheck(False, "verify_chain checked 0 records", True, path)
    return ChainCheck(True, f"verify_chain PASS ({res.checked} records)", True,
                      path, res.checked)


# ---------------------------------------------------------------------------
# Signed baseline
# ---------------------------------------------------------------------------

@dataclass
class Baseline:
    root: Path
    ref: str
    commit: str
    source: str            # authorization-record | operator-override
    overlay: str
    files: dict[str, str]  # rel path -> git file mode
    signature: str
    _blobs: dict[str, bytes] = field(default_factory=dict, repr=False)

    def blob(self, rel: str) -> bytes:
        if rel not in self._blobs:
            self._blobs[rel] = _git(self.root, "cat-file", "blob",
                                    f"{self.commit}:{rel}", binary=True)
        return self._blobs[rel]


def _git(root: Path, *args: str, binary: bool = False):
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    try:
        proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                              stdin=subprocess.DEVNULL, timeout=60, env=env)
    except FileNotFoundError as e:
        raise BaselineError("git is not available") from e
    except subprocess.TimeoutExpired as e:
        raise BaselineError(f"git {args[0]} timed out") from e
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise BaselineError(f"git {' '.join(args[:2])} failed: {err or proc.returncode}")
    return proc.stdout if binary else proc.stdout.decode("utf-8", "replace")


def default_repo_root() -> Path:
    """The deployment checkout holding the gov overlay (same resolution the
    startup governance-artifacts gate uses)."""
    from lliam_cli.security_audit_startup import _gov_repo_root
    return _gov_repo_root()


def _load_yaml(path: Path) -> dict:
    import yaml
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise BaselineError(f"{path} is not a YAML mapping")
    return data


def resolve_baseline(*, repo_root: Optional[Path] = None,
                     ref: Optional[str] = None) -> Baseline:
    """Resolve the baseline commit and its controlled files (local git only)."""
    root = Path(repo_root) if repo_root is not None else default_repo_root()
    if not root.is_dir():
        raise BaselineError(f"repo root {root} does not exist")
    if _git(root, "rev-parse", "--is-inside-work-tree").strip() != "true":
        raise BaselineError(f"{root} is not a git work tree")

    rb: dict = {}
    rec_path = root / AUTH_RECORD
    if rec_path.exists():
        rb = dict(_load_yaml(rec_path).get("baseline") or {})
    pinned_tag = str(rb.get("git_tag") or "").strip()
    pinned = str(rb.get("git_commit") or "").strip().lower()

    if ref is not None:
        ref = str(ref).strip()
        if not _REF_RE.fullmatch(ref) or ".." in ref:
            raise BaselineError(f"invalid baseline ref {ref!r}")
    want = ref or pinned_tag or pinned
    if not want:
        raise BaselineError(f"no baseline pinned in {AUTH_RECORD}; name one "
                            "with --baseline")
    commit = _git(root, "rev-parse", "--verify", "--quiet",
                  f"{want}^{{commit}}").strip().lower()
    if not commit:
        raise BaselineError(f"baseline ref {want!r} not found in the local checkout")

    from_record = ref is None or ref == pinned_tag or (
        pinned and ref.lower() == pinned[:len(ref)])
    source = "authorization-record" if from_record else "operator-override"
    if from_record and pinned and not commit.startswith(pinned):
        raise BaselineError(
            f"baseline {want!r} resolves to {commit[:12]} but {AUTH_RECORD} "
            f"pins {pinned[:12]} — tag moved or record stale; refusing")

    overlay = str(rb.get("overlay") or DEFAULT_OVERLAY).strip()
    listing = _git(root, "ls-tree", "-r", "-z", "--full-tree", commit, "--",
                   overlay, *BASELINE_EXTRA_PATHS, binary=True)
    files: dict[str, str] = {}
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        meta, _, rel = entry.partition(b"\t")
        mode, otype, _sha = meta.decode().split(" ", 2)
        if otype != "blob" or mode == "120000":  # skip submodules / symlinks
            continue
        files[rel.decode("utf-8")] = mode
    if overlay not in files:
        raise BaselineError(f"baseline {commit[:12]} has no {overlay}")

    raw_commit = _git(root, "cat-file", "commit", commit)
    signature = "unsigned"
    if "\ngpgsig " in raw_commit:
        signature = "signed (gpgsig present; key not verified locally)"
        try:
            _git(root, "verify-commit", commit)
            signature = "signed (verified)"
        except BaselineError:
            pass
    return Baseline(root=root, ref=want, commit=commit, source=source,
                    overlay=overlay, files=files, signature=signature)


def _safe_target(b: Baseline, rel: str) -> Path:
    root = b.root.resolve()
    target = b.root / rel
    parent = target.parent.resolve()
    if parent != root and root not in parent.parents:
        raise BaselineError(f"baseline path {rel!r} escapes the repo root")
    return target


def drifted_paths(b: Baseline) -> list[str]:
    """Baseline-controlled files whose working copy differs (or is missing)."""
    out = []
    for rel in sorted(b.files):
        target = _safe_target(b, rel)
        try:
            cur = target.read_bytes() if not target.is_symlink() else None
        except FileNotFoundError:
            cur = None
        if cur != b.blob(rel):
            out.append(rel)
    return out


def restore_baseline(b: Baseline, paths: list[str]) -> list[str]:
    """Atomically rewrite ``paths`` from the baseline commit."""
    restored = []
    for rel in paths:
        target = _safe_target(b, rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_symlink():
            target.unlink()
        fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".restore",
                                   dir=str(target.parent))
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(b.blob(rel))
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o755 if b.files.get(rel) == "100755" else 0o644)
            os.replace(tmp, target)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        restored.append(rel)
    return restored


def _load_drift_gate():
    spec = importlib.util.spec_from_file_location("_lg_baseline_drift_gate", _DRIFT_GATE)
    if spec is None or spec.loader is None:
        raise ImportError(str(_DRIFT_GATE))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _effective_config(overlay_bytes: bytes) -> dict:
    """Effective config for a candidate overlay, resolved the way the
    baseline-drift gate does (``load_config`` with the overlay selected:
    DEFAULT + home + overlay + posture_resolver). Falls back to the bare
    overlay YAML — the gate's own fallback — when the loader is unavailable."""
    import yaml
    with tempfile.TemporaryDirectory(prefix="lg-baseline-") as td:
        ov = Path(td) / "cli-config.gov.yaml"
        ov.write_bytes(overlay_bytes)
        with _ENV_LOCK:
            prior = os.environ.get("LLIAM_CONFIG")
            os.environ["LLIAM_CONFIG"] = str(ov)
            try:
                from lliam_cli.config import load_config
                cfg = load_config()
                if isinstance(cfg, dict):
                    return cfg
            except Exception as e:
                _log.warning("effective config load failed (%s); using overlay "
                             "YAML", e)
            finally:
                if prior is None:
                    os.environ.pop("LLIAM_CONFIG", None)
                else:
                    os.environ["LLIAM_CONFIG"] = prior
    data = yaml.safe_load(overlay_bytes.decode("utf-8")) or {}
    if not isinstance(data, dict):
        raise BaselineError("baseline overlay is not a YAML mapping")
    return data


def check_baseline_content(b: Baseline) -> list[str]:
    """Run the baseline-drift gate's critical-key check over the BASELINE
    commit's own overlay + critical-keys policy, before anything is written.
    Empty list = the baseline is fit to restore."""
    if CRITICAL_KEYS not in b.files:
        return [f"baseline {b.commit[:12]} has no {CRITICAL_KEYS} to verify against"]
    try:
        gate = _load_drift_gate()
    except Exception as e:
        return [f"baseline drift verifier unavailable ({e})"]
    try:
        import yaml
        keys = yaml.safe_load(b.blob(CRITICAL_KEYS).decode("utf-8")) or {}
        cfg = _effective_config(b.blob(b.overlay))
    except Exception as e:
        return [f"baseline content unreadable ({e})"]
    required = keys.get("posture_required", "strict")
    posture = gate._get(cfg, "security.posture")
    if posture != required:
        return [f"baseline overlay security.posture={posture!r}, expected {required!r}"]
    problems = []
    for entry in keys.get("critical_keys") or []:
        if entry.get("severity") != "critical":
            continue
        val = gate._get(cfg, entry["key"])
        if not gate._matches(val, entry):
            shown = "MISSING" if val is gate._MISSING else repr(val)
            want = entry.get("expect", entry.get("expect_contains"))
            problems.append(f"critical key {entry['key']} drifted "
                            f"(expected {want!r}, got {shown})")
    return problems


def verify_restored(b: Baseline) -> list[str]:
    """Confirm every baseline-controlled file now matches its baseline blob."""
    problems = []
    for rel in sorted(b.files):
        target = _safe_target(b, rel)
        try:
            cur = target.read_bytes()
        except FileNotFoundError:
            problems.append(f"{rel} missing after restore")
            continue
        if _sha256(cur) != _sha256(b.blob(rel)):
            problems.append(f"{rel} does not match baseline {b.commit[:12]}")
    return problems


def code_drift_notes(b: Baseline) -> list[str]:
    """Advisory notes about code outside the restored baseline set."""
    notes = []
    try:
        if subprocess.run(["git", "-C", str(b.root), "merge-base", "--is-ancestor",
                           b.commit, "HEAD"], capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=60).returncode != 0:
            notes.append(f"HEAD does not descend from baseline {b.commit[:12]}")
        dirty = [ln[3:] for ln in _git(b.root, "status", "--porcelain",
                                       "--untracked-files=no").splitlines()
                 if ln[3:] not in b.files]
        if dirty:
            notes.append(f"{len(dirty)} tracked file(s) modified outside the "
                         f"baseline set: {', '.join(dirty[:5])}")
    except Exception as e:
        notes.append(f"code drift check unavailable ({e})")
    if not b.signature.startswith("signed"):
        notes.append(f"baseline commit {b.commit[:12]} is {b.signature}")
    return notes


# ---------------------------------------------------------------------------
# Forensic custody (governance evidence store)
# ---------------------------------------------------------------------------

def evidence_root() -> Path:
    from lliam_constants import get_lliam_home
    return get_lliam_home() / "logs" / "incident-evidence"


def _safe_rel(name: str) -> Path:
    parts = [p for p in Path(name).parts if p not in ("", ".", "..", "/", "\\")]
    if not parts:
        raise ValueError(f"bad evidence item name {name!r}")
    return Path(*parts)


def preserve_forensics(*, files: dict[str, Path], actor: str, reason: str) -> dict:
    """Copy ``files`` into a new evidence directory with a custody manifest.

    Returns the manifest plus ``evidence_dir`` and ``manifest_sha256``. The
    manifest hash is recorded in the audit ledger (best-effort), so the
    copies are anchored in the tamper-evident chain.
    """
    when = _now()
    incident = f"{when.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    out_dir = evidence_root() / incident
    out_dir.mkdir(parents=True, mode=0o700)
    items = []
    for name, src in sorted(files.items()):
        data = Path(src).read_bytes()
        dest = out_dir / "items" / _safe_rel(name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        try:
            os.chmod(dest, 0o400)
        except OSError:
            pass
        items.append({"name": str(_safe_rel(name)), "source": str(src),
                      "sha256": _sha256(data), "bytes": len(data)})
    stamp = when.isoformat(timespec="seconds").replace("+00:00", "Z")
    manifest = {
        "schema": "lg-ir/custody/1",
        "incident": incident,
        "collected_at": stamp,
        "collected_by": str(actor),
        "reason": str(reason),
        "items": items,
        "custody": [{"at": stamp, "by": str(actor), "action": "collected",
                     "note": str(reason)}],
    }
    blob = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8")
    mpath = out_dir / "manifest.json"
    mpath.write_bytes(blob)
    try:
        os.chmod(mpath, 0o400)
    except OSError:
        pass
    manifest_sha = _sha256(blob)
    _emit_custody(out_dir, manifest_sha, items, actor)
    return dict(manifest, evidence_dir=str(out_dir), manifest_sha256=manifest_sha)


def _emit_custody(out_dir: Path, manifest_sha: str, items: list, actor: str) -> None:
    try:
        from agent import governance_audit as ga
        led = ga.get_ledger()
        if led is not None:
            led.emit(
                "killswitch.activate",
                action="killswitch.forensics.preserve",
                decision="n/a",
                severity="notice",
                outcome={"status": "preserved", "evidence_dir": str(out_dir),
                         "manifest_sha256": manifest_sha,
                         "items": [{k: i[k] for k in ("name", "sha256", "bytes")}
                                   for i in items]},
                subject={"principal": actor},
                source_module="agent/incident_recovery.py:preserve_forensics",
            )
    except Exception as e:
        _log.warning("custody record not written to the ledger: %s", e)


__all__: list[Any] = [
    "BaselineError", "Baseline", "ChainCheck", "verify_audit_chain",
    "resolve_baseline", "drifted_paths", "restore_baseline",
    "check_baseline_content", "verify_restored",
    "code_drift_notes", "preserve_forensics", "evidence_root",
    "ledger_path_or_none", "default_repo_root",
]
