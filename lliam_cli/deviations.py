"""Enforce the operator deviation register before a governed change takes effect."""
from __future__ import annotations

import datetime as dt
import json
import stat
from contextvars import ContextVar
from functools import lru_cache
from pathlib import Path

import yaml

from agent import incident_recovery
from lliam_cli import managed_scope, posture_resolver
from lliam_cli.env_compat import getenv_compat
from lliam_constants import get_lliam_home

_ROOT = Path(__file__).resolve().parents[1]
_MISSING = object()


class DeviationError(ValueError):
    """A governed deviation has no applicable approval or durable receipt."""


@lru_cache(maxsize=1)
def _baseline():
    # Wheels, Nix builds and shallow checkouts ship the reviewed contract for
    # the release pin. Never derive expected values from the running overlay.
    packaged = yaml.safe_load(Path(__file__).with_name("governed-baseline.yaml").read_bytes())
    record = _ROOT / incident_recovery.AUTH_RECORD
    if record.exists():
        pin = yaml.safe_load(record.read_bytes())["baseline"]["git_commit"]
        if pin != packaged["commit"]:
            raise DeviationError("Authorization pin differs from the shipped release baseline")
    return packaged


def _field(config, key):
    for part in key.split("."):
        if not isinstance(config, dict) or part not in config:
            return _MISSING
        config = config[part]
    return config


def _typed(value):
    # YAML/Python booleans compare equal to integers. Records bind the actual type.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _scope():
    from lliam_cli.profiles import get_active_profile_name

    name = get_active_profile_name()
    # Distinct custom homes must never share a grant just because they both
    # have the display name "custom".
    return str(get_lliam_home().resolve()) if name == "custom" else name


def _entries():
    directory = managed_scope.get_managed_dir()
    if directory is None:
        raise DeviationError("No managed deviation register is configured")
    register = directory / "deviation-register.yaml"
    if not register.is_file() or register.is_symlink():
        raise DeviationError("A managed deviation register is required")
    register = register.resolve(strict=True)
    _check_managed_ownership(register)
    rows = yaml.safe_load(register.read_bytes())["deviations"]
    if not isinstance(rows, list):
        raise DeviationError("The managed deviation register is invalid")
    return rows


def _check_managed_ownership(register):
    # MANAGED_DIR is a bootstrap override. A user-writable location cannot
    # become approval authority just by selecting it in the environment.
    for path in (register, *register.parents):
        st = path.stat()
        if st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise DeviationError("The deviation register must be administrator-controlled")


def _approval(rows, profile, key, before, after, approvers):
    today = dt.datetime.now(dt.timezone.utc).date()
    for row in rows:
        if not isinstance(row, dict) or row.get("key") != key or row.get("profile") != profile:
            continue
        if (row.get("approver") not in approvers or row.get("status") != "approved"
                or not isinstance(row.get("id"), str) or not row["id"].strip()
                or not isinstance(row.get("justification"), str) or not row["justification"].strip()):
            continue
        if "from" not in row or "to" not in row:
            continue
        try:
            expiry = dt.date.fromisoformat(str(row["expiry"]))
        except (KeyError, ValueError):
            continue
        if expiry >= today and _typed(row["from"]) == _typed(before) and _typed(row["to"]) == _typed(after):
            return row["id"]
    raise DeviationError(f"{key} requires an approved, unexpired deviation for profile {profile}")


def _changes(config, base):
    mandatory = {
        "security.posture", "audit.ledger_enabled", "security.provider_allowlist_enforce",
        "security.require_tls", "security.require_authenticated_approver", "security.deny_on_no_approver",
        "security.safe_serialization_only", "security.model_hash_verify", "security.egress.mode",
    }
    for key, before in base["settings"].items():
        after = _field(config, key)
        if after is _MISSING:
            raise DeviationError(f"Missing governed setting {key}")
        if type(before) is type(after) and before == after:
            continue
        if key == "security.egress.mode" and before == "allowlist" and after == "deny_all":
            # Air-gapped mode accepts no destinations, including allowlisted ones.
            continue
        if type(before) in (int, float):
            # These fields are release-pinned upper bounds. Zero can disable a
            # guard; only a positive, tighter ceiling is inherently acceptable.
            if type(after) is not type(before) and not (
                key.endswith("_cost_usd") and type(after) is float
            ):
                raise DeviationError(f"Invalid type for governed setting {key}")
            if 0 < after <= before:
                continue
        elif type(after) is not type(before):
            raise DeviationError(f"Invalid type for governed setting {key}")
        if key in mandatory or (
            key == "approvals.mode" and after not in {"manual", "smart"}
        ):
            raise DeviationError(f"{key} is mandatory in a governed profile")
        yield key, before, after

    for key in ("agent.disabled_toolsets", "security.allowed_providers", "security.tool_denylist", "skills.disabled"):
        before, after = base[key], _field(config, key)
        if not isinstance(after, list) or not all(isinstance(item, str) for item in after):
            raise DeviationError(f"Invalid governed list {key}")
        if key == "security.allowed_providers":
            changed = set(after) - set(before)
        else:
            changed = set(before) - set(after)
        if not changed:
            continue
        if key == "security.tool_denylist":
            raise DeviationError(f"{key} contains terminal deny rules")
        if key == "skills.disabled":
            raise DeviationError("Mandatory skill denials cannot be waived")
        yield key, sorted(set(before)), sorted(set(after))


# Startup enables reload checks for every profile served by this process.
# Successful governance activation is sticky only for the same resolved home.
_runtime_started = False
_governed_homes: set[Path] = set()
_recording = ContextVar("deviation_receipt_config", default=None)
_recorded = set()


def _accept(config, changes, base):
    if not changes:
        return
    from agent.governance_audit import record_policy_exception

    profile = _scope()
    approvers = base["approvers"]
    entries = _entries()
    receipts = [
        (_approval(entries, profile, key, before, after, approvers), key, _typed(after))
        for key, before, after in changes
    ]
    # The ledger reads its config while writing. Only this already-validated
    # config may be reused for that synchronous nested read.
    token = _recording.set(config)
    try:
        for reference, key, value in receipts:
            receipt = (str(get_lliam_home()), profile, reference, key, value)
            if receipt not in _recorded:
                record_policy_exception("deviation", reference, f"{profile}:{key}={value}", source=__name__)
                _recorded.add(receipt)
    finally:
        _recording.reset(token)


def _check(config, *, provider=None):
    nested = _recording.get()
    if nested is not None:
        if nested != config:
            raise DeviationError("Configuration changed while recording a deviation")
        return
    try:
        base = _baseline()
        if provider is None:
            changes = list(_changes(config, base))
        else:
            slug, host = provider
            key = "security.allowed_providers"
            allowed = _field(config, key)
            if not isinstance(allowed, list) or slug not in allowed:
                raise DeviationError(f"Provider {slug} must be in the governed provider list")
            changes = []
            if slug not in base[key]:
                changes.append((key, sorted(base[key]), sorted(set(allowed))))
            hosts = base["hosts"].get(slug, [])
            if not host:
                raise DeviationError("The governed provider endpoint must identify its host")
            if host not in hosts:
                changes.append((f"provider.{slug}.hosts", sorted(hosts), sorted(set(hosts) | {host})))
        _accept(config, changes, base)
    except DeviationError:
        raise
    except Exception as exc:
        raise DeviationError("Could not verify the pinned baseline or record the deviation") from exc


def _governed_config(config):
    selected = getenv_compat("CONFIG") or ""
    gov = (config or {}).get("governance", {})
    if not isinstance(gov, dict):
        raise DeviationError("Invalid governance configuration")
    return (posture_resolver.is_strict(config) or Path(selected).name == "cli-config.gov.yaml"
            or bool(gov.get("authorization_id")))


def activate(config):
    global _runtime_started
    home = get_lliam_home().resolve()
    if home in _governed_homes or _governed_config(config):
        _check(config)
        _governed_homes.add(home)
    _runtime_started = True


def check_reload(config):
    if _runtime_started:
        activate(config)
    return config


def check_provider(config, slug, host):
    if get_lliam_home().resolve() in _governed_homes or _governed_config(config):
        _check(config, provider=(slug, host))


def governed_disabled_toolsets():
    if not _runtime_started:
        return ()
    from lliam_cli.config import load_config_readonly

    # A tool request can be the first config read for this dashboard profile.
    config = load_config_readonly()
    if get_lliam_home().resolve() in _governed_homes:
        return config["agent"]["disabled_toolsets"]
    return ()
