"""Startup security posture audit (warn-on-load, never blocks).

Surfaces dangerous host / deployment posture at process start so operators
get an at-a-glance "you're exposed" signal. Motivated by the June 2026
MCP-config persistence campaign, where compromised boxes ran as root with an
exposed dashboard / API server and no firewall — and nothing ever told the
operator. These checks are advisory: they emit ``logger.warning`` records
and return human-readable strings; they never raise or block startup.

Checks (each is independent and fail-safe — any internal error is swallowed
and simply yields no finding):

1. Running as root (POSIX uid 0).
2. SSH daemon present with password authentication enabled.
3. Running inside a container with no persistent volume mount over the
   HERMES_HOME data dir (state is ephemeral — lost on container restart).
4. A network-accessible gateway listener (dashboard / API server) with no
   authentication configured.
5. Strict posture reading credentials from a plaintext ``.env`` while the
   managed secret source (``secrets.bitwarden``) is disabled (LG-IA-04).

Cross-platform: the root and SSH checks are POSIX-only and no-op on Windows.
Everything is best-effort and read-only.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("hermes.security_audit")

# Sentinel so the audit only runs once per process even if both the CLI and
# gateway startup paths call it.
_AUDIT_RAN = False


def _is_root() -> bool:
    """True when the process runs as POSIX uid 0. Always False on Windows."""
    getuid = getattr(os, "geteuid", None) or getattr(os, "getuid", None)
    if getuid is None:
        return False
    try:
        return getuid() == 0
    except Exception:
        return False


def _running_as_root() -> Optional[str]:
    if not _is_root():
        return None
    return (
        "Running as ROOT. The agent's terminal/file tools execute with full "
        "root privileges — a single prompt-injection or exposed endpoint is a "
        "full host compromise. Run Lliam-GOV as an unprivileged user (or in a "
        "sandboxed terminal backend / container with a non-root user)."
    )


_SSHD_CONFIG_PATHS = (
    "/etc/ssh/sshd_config",
)
_SSHD_CONFIG_DIR = "/etc/ssh/sshd_config.d"


def _iter_sshd_config_lines() -> list[str]:
    """Yield non-comment lines from sshd_config + its drop-in directory."""
    lines: list[str] = []
    paths: list[Path] = [Path(p) for p in _SSHD_CONFIG_PATHS]
    try:
        d = Path(_SSHD_CONFIG_DIR)
        if d.is_dir():
            paths.extend(sorted(d.glob("*.conf")))
    except Exception:
        pass
    for p in paths:
        try:
            for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = raw.strip()
                if stripped and not stripped.startswith("#"):
                    lines.append(stripped)
        except Exception:
            continue
    return lines


def _ssh_password_auth_enabled() -> Optional[str]:
    """Warn when an SSH daemon has password authentication enabled.

    Password auth on a public SSH daemon is the classic brute-force surface
    and pairs badly with a root-capable agent box. POSIX-only; returns None
    when there's no sshd config to read (e.g. Windows, or SSH not installed).
    """
    lines = _iter_sshd_config_lines()
    if not lines:
        return None
    # Last directive wins in sshd_config. Default (no directive) is "yes".
    verdict = "yes"
    saw_directive = False
    for line in lines:
        m = re.match(r"(?i)^PasswordAuthentication\s+(\w+)", line)
        if m:
            verdict = m.group(1).lower()
            saw_directive = True
    if verdict == "no":
        return None
    qualifier = "" if saw_directive else " (default — no explicit directive)"
    return (
        f"SSH password authentication is ENABLED{qualifier}. Password auth is "
        "brute-forceable and dangerous on an internet-facing box. Set "
        "'PasswordAuthentication no' in sshd_config and use key-based auth."
    )


def _in_container() -> bool:
    """Best-effort container detection (Docker / Podman / generic OCI)."""
    if os.path.exists("/.dockerenv"):
        return True
    from lliam_cli.env_compat import getenv_compat

    if getenv_compat("DESKTOP_CHILD_PID"):
        return False  # desktop child, not a server container
    try:
        cgroup = Path("/proc/1/cgroup").read_text(encoding="utf-8", errors="replace")
        if any(tok in cgroup for tok in ("docker", "containerd", "kubepods", "libpod")):
            return True
    except Exception:
        pass
    return False


def _path_is_mounted(path: Path) -> bool:
    """True if *path* sits on (or under) a real mount point per /proc/mounts.

    Container overlay/root filesystems are ephemeral; a bind/volume mount over
    the data dir shows up as a distinct mount entry. We treat the path as
    persisted when a mountpoint at or above it is NOT the container root
    overlay.
    """
    try:
        target = path.resolve()
    except Exception:
        target = path
    try:
        mounts = Path("/proc/mounts").read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return True  # can't tell — fail safe (no warning)
    best = None
    best_fstype = ""
    for line in mounts:
        parts = line.split()
        if len(parts) < 3:
            continue
        mountpoint, fstype = parts[1], parts[2]
        try:
            mp = Path(mountpoint)
        except Exception:
            continue
        if mp == target or mp in target.parents:
            # Longest matching mountpoint wins (most specific).
            if best is None or len(str(mp)) > len(str(best)):
                best = mp
                best_fstype = fstype
    if best is None:
        return True
    # overlay / tmpfs over the data dir = ephemeral container storage.
    return best_fstype not in ("overlay", "tmpfs", "aufs")


def _container_no_volume_mount(lliam_home: Optional[Path]) -> Optional[str]:
    if not _in_container():
        return None
    home = lliam_home or Path(
        os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes"))
    )
    try:
        if _path_is_mounted(home):
            return None
    except Exception:
        return None
    return (
        f"Running in a container but the data dir ({home}) is NOT on a "
        "persistent volume mount — sessions, memory, skills, and API keys are "
        "ephemeral and lost on container restart. Mount a host volume over the "
        "HERMES_HOME data directory."
    )


# Known default / placeholder credential values that must never authenticate a
# CUI system (LG-IA-05 no-default-credentials). Compared case-insensitively.
_DEFAULT_CREDENTIAL_VALUES = frozenset({
    "", "changeme", "change-me", "password", "passw0rd", "admin", "default",
    "secret", "test", "testkey", "test-key", "example", "placeholder",
    "your-api-key", "your_api_key", "xxx", "todo", "none", "null",
})

# Credential-bearing env var name substrings (checked against os.environ).
# Broadened to cover the in-scope AWS/bedrock provider (ACCESS_KEY / AWS_) and
# common bare forms (KEY / PASSWD / CREDENTIAL / APIKEY) — P1.4-review gap.
_CREDENTIAL_NAME_HINTS = (
    "API_KEY", "APIKEY", "API_SERVER_KEY", "_TOKEN", "_SECRET",
    "_PASSWORD", "PASSWD", "ACCESS_KEY", "SECRET_KEY", "CREDENTIAL",
    "DASHBOARD_DRAIN", "PRIVATE_KEY", "_KEY",
)


def _default_credentials_in_use(config: Optional[dict]) -> list[str]:
    """Warn when a credential is set to a known default/placeholder (LG-IA-05).

    Only fires under the no-default-credentials switch. Reads env-var names that
    look credential-bearing and flags any whose value is a known default. Values
    themselves are NEVER emitted — only the offending variable name.
    """
    cfg = config or {}
    sec = cfg.get("security") or {}
    if not (isinstance(sec, dict) and sec.get("no_default_credentials")):
        return []
    findings: list[str] = []
    try:
        for name, value in os.environ.items():
            if not any(h in name.upper() for h in _CREDENTIAL_NAME_HINTS):
                continue
            if value is None:
                continue
            if value.strip().casefold() in _DEFAULT_CREDENTIAL_VALUES:
                findings.append(
                    f"Credential env var {name} is set to a known default/"
                    "placeholder value. Rotate it to a strong, unique secret "
                    "(LG-IA-05 no-default-credentials)."
                )
    except Exception:
        pass
    return findings


def _plaintext_env_secrets_of_record(
    config: Optional[dict], lliam_home: Optional[Path]
) -> list[str]:
    """Warn when strict posture reads credentials from a plaintext .env (LG-IA-04).

    The managed secret source of record is ``secrets.bitwarden``. When it is
    disabled under strict posture and the data dir's ``.env`` still carries
    credential-bearing variables, say so at startup. Only variable NAMES are
    reported, never values. Advisory: Bitwarden provisioning is an operator
    action, so this never blocks or enables anything.
    """
    cfg = config or {}
    try:
        from lliam_cli import posture_resolver as _pr
        if not _pr.is_strict(cfg):
            return []
    except Exception:
        return []
    secrets_cfg = cfg.get("secrets") or {}
    bitwarden = secrets_cfg.get("bitwarden") if isinstance(secrets_cfg, dict) else None
    if isinstance(bitwarden, dict) and bitwarden.get("enabled"):
        return []
    if lliam_home is None:
        from lliam_constants import get_lliam_home
        lliam_home = get_lliam_home()
    env_path = Path(lliam_home) / ".env"
    if not env_path.is_file():
        return []
    from dotenv import dotenv_values
    names = sorted(
        name for name, value in dotenv_values(env_path).items()
        if name and value and any(h in name.upper() for h in _CREDENTIAL_NAME_HINTS)
    )
    if not names:
        return []
    return [
        f"Strict posture is reading {len(names)} credential(s) ({', '.join(names)}) "
        f"from plaintext {env_path} while secrets.bitwarden.enabled is false — the "
        "managed secret source of record is not provisioned (LG-IA-04). Provision "
        "secrets.bitwarden and move these credentials off .env."
    ]


def _network_listener_without_auth(config: Optional[dict]) -> list[str]:
    """Warn about network-accessible agent listeners with no auth (LG-IA-11).

    This used to detect the messaging gateway's OpenAI-compatible API server
    bound to a network address without a strong ``API_SERVER_KEY``. The
    messaging gateway and its API server were removed (JER-198): Lliam-GOV
    has no inbound agent API listener any more, so there is nothing to
    report. The dashboard's own non-loopback bind is refused/gated by the
    dashboard auth guards in ``lliam_cli/web_server.py``.
    """
    return []


def _tls_verification_disabled() -> list[str]:
    """Report a genuine runtime TLS trust-store bypass (LG-IA-08).

    Historically this flagged ``SKIP_SSL_GUARD`` / ``SKIP_SSL_VERIFY`` /
    ``INSECURE_SKIP_VERIFY``. That was a control overclaim: ``SKIP_SSL_GUARD``
    only skips the *CA-bundle preflight* in ``agent/ssl_guard.py`` (a broken
    bundle then fails loudly at request time — it never yields silent
    unverified TLS), and the other two names have no runtime consumer at all.
    None of them disables certificate verification.

    No environment variable in this runtime disables certificate verification:
    provider and MCP calls go through httpx/OpenAI, which verify against the
    trust store on every request regardless of these vars. Claiming otherwise
    both misleads operators and — under strict + require_tls — would wrongly
    refuse a legitimate start (e.g. an operator skipping the preflight for a
    custom corporate CA bundle). If a real runtime verification bypass is ever
    introduced, detect it here.
    """
    return []


class ControlPlaneAuthError(RuntimeError):
    """A network-accessible control plane is unauthenticated under strict posture.

    Raised only when the effective posture is strict, the relevant require-*
    switch is on, AND a network-accessible endpoint (API server / dashboard)
    has no authenticator. An unauthenticated network endpoint that dispatches
    terminal-capable agent work is remote code execution — a CUI deployment
    must refuse to start rather than expose it (LG-IA-11 / LG-IA-06).
    """


# Sentinel so the control-plane gate runs once per process.
_CONTROL_PLANE_CHECKED = False


class ProviderAllowlistError(RuntimeError):
    """A configured routing path names a non-allowlisted inference provider.

    Raised only when the effective posture is strict AND
    ``security.provider_allowlist_enforce`` is on, when any of the five routing
    paths (primary / fallback / MoA / auxiliary / delegation) resolves to a
    provider or base_url host that is not on the approved allowlist. Routing CUI
    to a non-vetted / non-US endpoint is CUI spillage — a CUI deployment must
    refuse to start rather than silently egress off-boundary (LG-MP-01/02).
    """


# Sentinel so the provider-allowlist gate runs once per process.
_PROVIDER_ALLOWLIST_CHECKED = False


class ModelIntegrityError(RuntimeError):
    """A model-integrity precondition failed under strict posture.

    Raised when the signed model manifest is invalid/untrusted (LG-MP-06) or a
    configured model lacks a required model card (LG-MP-05). Routing CUI through
    an unattested model or an undocumented model violates supply-chain integrity
    — a CUI deployment refuses to start rather than proceed unverified.
    """


# Sentinel so the model-integrity gate runs once per process.
_MODEL_INTEGRITY_CHECKED = False


def enforce_model_integrity_at_startup(
    *, config: Optional[dict] = None, force: bool = False
) -> Optional[list[str]]:
    """Fail-closed gate for model integrity (LG-MP-05/06).

    Under strict posture: (a) verifies the signed manifest
    (security.model_manifest_path) against security.trusted_signers — a bad or
    untrusted signature blocks; (b) if security.require_model_card is set,
    verifies the configured primary model has a card. Advisory (returns
    findings) when non-strict. Idempotent per process.
    """
    global _MODEL_INTEGRITY_CHECKED
    if _MODEL_INTEGRITY_CHECKED and not force:
        return None

    if isinstance(config, dict) and config.get("security"):
        eff = config
    else:
        try:
            from lliam_cli import config as _cfg
            eff = _cfg.load_config()
        except Exception:
            eff = config or {}

    sec = eff.get("security") or {}
    try:
        import agent.attestation as att
    except Exception as e:
        finding = f"model attestation control unavailable — fail-closed ({e})"
        if _effective_is_strict(eff):
            raise ModelIntegrityError(finding) from e
        logger.warning("[model-integrity] (advisory — not strict) %s", finding)
        return [finding]

    blocking: list[str] = []

    # (a) LG-MP-06 — signed manifest verification.
    manifest_path = str(sec.get("model_manifest_path") or "").strip()
    if manifest_path:
        try:
            import yaml
            from pathlib import Path as _P
            mp = _P(manifest_path).expanduser()
            if not mp.is_absolute() and not mp.is_file():
                mp = _P(__file__).resolve().parent.parent / mp
            if not mp.is_file():
                blocking.append(f"model manifest '{manifest_path}' is missing — fail-closed (LG-MP-06)")
            else:
                manifest = yaml.safe_load(mp.read_text(encoding="utf-8")) or {}
                verdict = att.verify_manifest(manifest)
                if not verdict.valid:
                    blocking.append(f"model manifest: {verdict.reason}")
                signed_primary = str(((manifest or {}).get("models") or {}).get("primary") or "").strip()
                if not signed_primary:
                    blocking.append("model manifest has no signed models.primary — fail-closed (LG-MP-06)")
                else:
                    model = eff.get("model") or {}
                    if isinstance(model, dict):
                        provider = str(model.get("provider") or "").strip()
                        model_name = str(model.get("model") or model.get("default") or "").strip()
                    else:
                        raw = str(model or "").strip()
                        if "/" in raw:
                            provider, model_name = raw.split("/", 1)
                        else:
                            provider, model_name = "", raw
                    configured_primary = model_name if "/" in model_name else (
                        f"{provider}/{model_name}" if provider and model_name else model_name)
                    if configured_primary and configured_primary != signed_primary:
                        blocking.append(
                            f"configured primary '{configured_primary}' does not match signed manifest "
                            f"'{signed_primary}' (LG-MP-06)"
                        )
        except Exception as e:
            blocking.append(f"model manifest could not be verified — fail-closed ({e})")

    # (b) LG-MP-05 — the configured primary model must have a card.
    if att.require_model_card():
        model = eff.get("model") or {}
        if isinstance(model, dict):
            provider = str(model.get("provider") or "").strip()
            model_name = str(model.get("model") or model.get("default") or "").strip()
        else:
            raw = str(model or "").strip()
            if "/" in raw:
                provider, model_name = raw.split("/", 1)
            else:
                provider, model_name = "", raw
        model_id = model_name if "/" in model_name else (
            f"{provider}/{model_name}" if provider and model_name else model_name)
        if model_id and not att.model_cui_eligible(model_id):
            blocking.append(f"primary model '{model_id}' has no model card / is not CUI-eligible (LG-MP-05)")

    _MODEL_INTEGRITY_CHECKED = True
    if not blocking:
        return None

    strict = _effective_is_strict(eff)
    if not strict:
        for f in blocking:
            logger.warning("[model-integrity] (advisory — not strict) %s", f)
        return blocking

    for f in blocking:
        logger.critical("[model-integrity] BLOCKING: %s", f)
    try:
        from agent import governance_audit as ga
        led = ga.get_ledger()
        if led is not None:
            led.emit(
                "security.error",
                action="model.integrity_violation",
                decision="halt",
                severity="critical",
                outcome={"status": "blocked", "class": "model_integrity",
                         "error": "; ".join(blocking)[:1000]},
                source_module="lliam_cli/security_audit_startup.py:enforce_model_integrity_at_startup",
            )
    except Exception:
        pass
    raise ModelIntegrityError("; ".join(blocking))


def _iter_configured_provider_routes(cfg: dict):
    """Yield (path, provider, base_url) for every configured routing path.

    Reads the real config keys: model (primary), fallback_providers (fallback),
    moa.presets.*.{reference_models[],aggregator} (moa), auxiliary.<task> (aux),
    delegation (delegation). Blank slots are skipped (a blank primary is the
    resolver's own fail-closed concern, not a spillage route).
    """
    def _emit(path, slot):
        if isinstance(slot, dict):
            provider = str(slot.get("provider") or "").strip()
            base_url = str(slot.get("base_url") or "").strip()
        else:
            raw = str(slot or "").strip()
            provider = raw.partition("/")[0] if raw else ""
            base_url = ""
        if provider:
            return (path, provider, base_url)
        return None

    routes = []
    r = _emit("primary", cfg.get("model") or {})
    if r:
        routes.append(r)
    for fb in cfg.get("fallback_providers") or []:
        r = _emit("fallback", fb)
        if r:
            routes.append(r)
    r = _emit("fallback", cfg.get("fallback_model") or {})
    if r:
        routes.append(r)
    moa = cfg.get("moa") or {}
    active_preset = str(moa.get("active_preset") or "").strip()
    active = (moa.get("presets") or {}).get(active_preset) if active_preset else None
    for _name, preset in ((active_preset, active),):
        if not isinstance(preset, dict):
            continue
        if preset.get("enabled") is False:
            continue
        for ref in preset.get("reference_models") or []:
            r = _emit("moa", ref)
            if r:
                routes.append(r)
        r = _emit("moa", preset.get("aggregator") or {})
        if r:
            routes.append(r)
    aux = cfg.get("auxiliary") or {}
    for _task, slot in aux.items():
        if isinstance(slot, dict) and str(slot.get("provider") or "").strip().lower() == "auto":
            continue
        r = _emit("auxiliary", slot)
        if r:
            routes.append(r)
    r = _emit("delegation", cfg.get("delegation") or {})
    if r:
        routes.append(r)
    return routes


def enforce_provider_allowlist_at_startup(
    *, config: Optional[dict] = None, force: bool = False
) -> Optional[list[str]]:
    """Fail-closed gate for the approved-provider allowlist (LG-MP-01/02).

    Validates every configured routing path against
    policy/provider-allowlist.yaml via ``provider_allowlist.validate_provider``.
    A ``deny`` verdict on any path is a blocking finding under strict posture +
    ``security.provider_allowlist_enforce``: logs ``critical``, appends a
    ``security.error`` alert to the ledger, and raises
    :class:`ProviderAllowlistError`. Advisory (returns findings, no raise) when
    non-strict or the flag is off. Returns None when there is nothing to report.
    Idempotent per process.
    """
    global _PROVIDER_ALLOWLIST_CHECKED
    if _PROVIDER_ALLOWLIST_CHECKED and not force:
        return None

    if isinstance(config, dict) and config.get("security"):
        eff = config
    else:
        try:
            from lliam_cli import config as _cfg
            eff = _cfg.load_config()
        except Exception:
            eff = config or {}

    try:
        from lliam_cli import provider_allowlist as pa
    except Exception as e:
        finding = f"provider allowlist control unavailable — fail-closed ({e})"
        if _effective_is_strict(eff):
            raise ProviderAllowlistError(finding) from e
        logger.warning("[provider-allowlist] (advisory — not strict) %s", finding)
        return [finding]

    if not pa.enforcement_enabled():
        _PROVIDER_ALLOWLIST_CHECKED = True
        return None

    blocking: list[str] = []
    for path, provider, base_url in _iter_configured_provider_routes(eff):
        try:
            decision = pa.validate_provider(provider, base_url, path=path, cui=True)
        except Exception:
            # Fail-closed: a validator fault on an enforced profile is a block.
            blocking.append(f"{path}: provider '{provider}' could not be validated (fail-closed)")
            continue
        if decision.disposition == "deny":
            blocking.append(f"{path}: {decision.reason}")

    _PROVIDER_ALLOWLIST_CHECKED = True
    if not blocking:
        return None

    strict = _effective_is_strict(eff)
    if not strict:
        for f in blocking:
            logger.warning("[provider-allowlist] (advisory — not strict) %s", f)
        return blocking

    for f in blocking:
        logger.critical("[provider-allowlist] BLOCKING: %s", f)
    try:
        from agent import governance_audit as ga
        led = ga.get_ledger()
        if led is not None:
            led.emit(
                "security.error",
                action="provider.non_allowlisted_route",
                decision="halt",
                severity="critical",
                outcome={"status": "blocked", "class": "provider_allowlist",
                         "error": "; ".join(blocking)[:1000]},
                source_module="lliam_cli/security_audit_startup.py:enforce_provider_allowlist_at_startup",
            )
    except Exception:
        pass
    raise ProviderAllowlistError("; ".join(blocking))


def enforce_control_plane_auth_at_startup(
    *, config: Optional[dict] = None, force: bool = False
) -> Optional[list[str]]:
    """Fail-closed gate for control-plane authentication (LG-IA-11/06/08).

    Resolves the EFFECTIVE MERGED config (not a raw passed shape — same fix
    class as the P1.3 startup gate) for both the require-* switches and the
    strict-posture decision. Findings:

      * API server network-accessible with no ``API_SERVER_KEY`` (LG-IA-11 RCE
        gate) — blocking under strict + ``security.api_server_key_required``.
      * TLS verification disabled (LG-IA-08) — blocking under strict +
        ``security.require_tls``.

    On a blocking finding: logs ``critical``, appends a ``security.error``
    alert to the ledger, and raises :class:`ControlPlaneAuthError`. Advisory
    (non-strict, or switch off): returns the findings without raising.
    Returns None when there is nothing to report. Idempotent per process.
    """
    global _CONTROL_PLANE_CHECKED
    if _CONTROL_PLANE_CHECKED and not force:
        return None

    # Prefer a passed config that actually carries control-plane state
    # (security / platforms); otherwise resolve the merged config so the
    # overlay's require-* switches and the api_server block are present. (The
    # audit-specific _effective_config keys on an 'audit' block, which the
    # gateway's control-plane config need not have — using it here would drop
    # the passed platforms block, the P1.3/P1.4 review lesson applied.)
    if isinstance(config, dict) and (config.get("security") or config.get("platforms")):
        eff = config
    else:
        try:
            from lliam_cli import config as _cfg
            eff = _cfg.load_config()
        except Exception:
            eff = config or {}
    sec = eff.get("security") if isinstance(eff, dict) else {}
    sec = sec if isinstance(sec, dict) else {}

    blocking: list[str] = []
    advisory: list[str] = []

    # LG-IA-11 — API-server key (the RCE gate).
    api_findings = _network_listener_without_auth(eff)
    if api_findings:
        (blocking if sec.get("api_server_key_required") else advisory).extend(api_findings)
    # LG-IA-08 — verified TLS.
    tls_findings = _tls_verification_disabled()
    if tls_findings:
        (blocking if sec.get("require_tls") else advisory).extend(tls_findings)

    if not blocking and not advisory:
        _CONTROL_PLANE_CHECKED = True
        return None

    _CONTROL_PLANE_CHECKED = True
    for f in advisory:
        logger.warning("[control-plane] %s", f)
    # Log blocking findings even when we won't raise (switch on but non-strict),
    # so a keyless network endpoint is never operator-invisible.
    strict = _effective_is_strict(config)
    if blocking and not strict:
        for f in blocking:
            logger.warning("[control-plane] (advisory — not strict) %s", f)

    if blocking and strict:
        for f in blocking:
            logger.critical("[control-plane] BLOCKING: %s", f)
        try:
            from agent import governance_audit as ga
            led = ga.get_ledger()
            if led is not None:
                led.emit(
                    "security.error",
                    action="control_plane.unauthenticated",
                    decision="halt",
                    severity="critical",
                    outcome={"status": "blocked", "class": "control_plane_unauth",
                             "error": "; ".join(blocking)[:1000]},
                    source_module="lliam_cli/security_audit_startup.py:enforce_control_plane_auth_at_startup",
                )
        except Exception:
            pass
        raise ControlPlaneAuthError("; ".join(blocking))

    return blocking + advisory


def run_security_audit(
    *, lliam_home: Optional[Path] = None, config: Optional[dict] = None
) -> list[str]:
    """Run all checks and return a list of human-readable warning strings.

    Pure: no logging, no side effects. Each check is independently
    fail-safe. Used directly by tests; the logging wrapper is
    :func:`log_startup_security_warnings`.
    """
    findings: list[str] = []
    for check in (
        _running_as_root,
        _ssh_password_auth_enabled,
    ):
        try:
            r = check()
            if r:
                findings.append(r)
        except Exception:
            continue
    try:
        r = _container_no_volume_mount(lliam_home)
        if r:
            findings.append(r)
    except Exception:
        pass
    try:
        findings.extend(_network_listener_without_auth(config))
    except Exception:
        pass
    try:
        findings.extend(_default_credentials_in_use(config))
    except Exception:
        pass
    try:
        findings.extend(_plaintext_env_secrets_of_record(config, lliam_home))
    except Exception:
        pass
    try:
        findings.extend(_tls_verification_disabled())
    except Exception:
        pass
    return findings


def emit_agent_identity_at_startup(*, config: Optional[dict] = None) -> Optional[dict]:
    """Compute and record the agent NPE identity at startup (LG-IA-02).

    No-op (returns None) when the audit ledger is disabled — identity is only
    meaningful as an audit binding. Emits a ``config.load`` record carrying the
    instance identity so the running binding is attributable, and returns the
    identity dict (also for tests). Never raises.

    The startup identity is computed from the EFFECTIVE MERGED config and the
    config-resolved (pruned) toolset, so its ``code_hash`` / ``config_hash`` /
    ``toolset_hash`` MATCH the session's operational ``tool.dispatch`` actors
    (P1.4-review fix — the earlier version passed a raw config + no toolset,
    yielding a phantom that matched no real record). The serving model is
    resolved per-turn, so at startup ``model`` is marked ``resolved:
    per-turn`` rather than faking a value — an assessor correlates startup to
    operational records on the code/config/toolset triple.
    """
    try:
        from agent import governance_audit as ga
        if not ga.ledger_enabled():
            return None
        from agent.agent_identity import compute_instance_identity

        # Resolve the effective merged config + the pruned toolset it defines,
        # so the startup binding equals the operational one on code/config/tool.
        merged = config
        try:
            if not (isinstance(config, dict) and config.get("agent")):
                from lliam_cli import config as _cfg
                merged = _cfg.load_config()
        except Exception:
            merged = config
        disabled = None
        try:
            disabled = ((merged or {}).get("agent") or {}).get("disabled_toolsets")
        except Exception:
            disabled = None

        identity = compute_instance_identity(
            config=merged, disabled_toolsets=disabled,
        )
        # Model binds per-turn; mark it honestly instead of sha256("None|None").
        if not identity["model"].get("model") and not identity["model"].get("provider"):
            identity = dict(identity)
            identity["model"] = {"provider": None, "model": None,
                                 "resolved": "per-turn"}
        led = ga.get_ledger()
        if led is not None:
            led.emit(
                "config.load",
                action="agent.identity_bind",
                actor=identity,
                outcome={"status": "success", "class": "identity_bind"},
                source_module="lliam_cli/security_audit_startup.py:emit_agent_identity_at_startup",
            )
        return identity
    except Exception as e:
        logger.debug("agent identity emit skipped: %s", e)
        return None


def log_startup_security_warnings(
    *,
    lliam_home: Optional[Path] = None,
    config: Optional[dict] = None,
    force: bool = False,
) -> list[str]:
    """Run the audit once per process and emit each finding via logger.warning.

    Returns the findings (also for tests). Never raises. Idempotent unless
    ``force=True`` (used by tests).
    """
    global _AUDIT_RAN
    if _AUDIT_RAN and not force:
        return []
    _AUDIT_RAN = True
    try:
        findings = run_security_audit(lliam_home=lliam_home, config=config)
    except Exception:
        return []
    if findings:
        logger.warning(
            "Security posture audit found %d issue(s) — review your deployment:",
            len(findings),
        )
        for i, f in enumerate(findings, 1):
            logger.warning("  [security %d/%d] %s", i, len(findings), f)
    return findings


# ---------------------------------------------------------------------------
# Audit-chain integrity verification at startup (LG-AU-08, P1.3)
# ---------------------------------------------------------------------------

# Sentinel so the chain verification runs once per process.
_CHAIN_VERIFIED = False


class AuditChainVerificationError(RuntimeError):
    """Startup audit-chain verification FAILED under a blocking posture.

    Raised only when the governance ledger is enabled, ``verify_chain``
    reports a break, AND the effective posture requires blocking
    (``audit.verify_fail_action: block`` on strict posture). A broken chain
    means the tamper-evidence record can no longer be trusted, so a CUI
    deployment must refuse to rely on it rather than proceed silently.
    """


def verify_audit_chain_at_startup(
    *, config: Optional[dict] = None, force: bool = False
) -> Optional[dict]:
    """Verify the governance audit chain once at startup (LG-AU-08).

    No-op (returns None) when the ledger is disabled — the shipped/low-side
    profile has no ledger. On a good chain, logs at debug and returns the
    PASS result dict. On a break:

      * always logs ``logger.critical`` and appends a ``security.error``
        alert to the ledger (the break itself is auditable);
      * if ``audit.verify_fail_action`` is ``block`` (the gov-overlay
        default) and the posture is strict, raises
        :class:`AuditChainVerificationError` so the caller can refuse a
        high-risk start (spec §4.3);
      * otherwise (advisory posture) returns the FAIL result dict without
        raising.

    The posture and audit settings are resolved from the EFFECTIVE merged
    config (``load_config()``), NOT from the raw config a caller happens to
    pass: ``security.posture: strict`` is injected by the gov overlay and
    only exists post-merge, so trusting a raw-shaped ``config`` here would
    silently make the fail-closed block inert (the exact defect the P1.3
    review caught). The ``config`` argument is honored only when it already
    carries a strict posture / audit block (tests, explicit callers).

    Idempotent per process unless ``force=True`` (tests): the sentinel is
    latched only after a verification actually completes, so a transient
    read error does not permanently disable the control.
    """
    global _CHAIN_VERIFIED
    if _CHAIN_VERIFIED and not force:
        return None
    try:
        from agent import governance_audit as ga
    except Exception as e:  # pragma: no cover - import guard
        logger.debug("audit-chain verify skipped (import failed): %s", e)
        return None
    if not ga.ledger_enabled():
        return None

    eff_cfg = _effective_config(config)
    audit_cfg = {}
    try:
        audit_cfg = dict(eff_cfg.get("audit") or {})
    except Exception:
        audit_cfg = {}
    if not audit_cfg.get("verify_on_startup", True):
        return None

    # verify_chain never raises on a tampered/garbage ledger — it returns a
    # FAIL result (an unparseable line is itself a break, not a "non-fatal"
    # shrug). A genuinely absent/vanished file is the only benign error.
    try:
        result = ga.verify_chain()
    except FileNotFoundError as e:
        # A genuinely absent/vanished ledger file is benign: there is no chain
        # to verify. Skip without latching (never blocks).
        logger.warning("audit-chain verify skipped (ledger file absent): %s", e)
        return None
    except (PermissionError, OSError) as e:
        # An unexpected filesystem error means integrity CANNOT be confirmed.
        # Under a blocking posture that is a fail-closed condition, not a shrug:
        # refuse to proceed as if the tamper-evidence record were trustworthy
        # (the P1.4 review finding — the old bare ``except`` swallowed this and
        # allowed startup). Do NOT latch the sentinel: a transient error must
        # not permanently disable the control.
        fail_action = str(audit_cfg.get("verify_fail_action", "block")).lower()
        if fail_action == "block" and _effective_is_strict(config):
            logger.critical(
                "audit-chain verify could not complete (%s) — failing closed "
                "under strict posture", e,
            )
            raise AuditChainVerificationError(
                f"audit-chain verification could not complete: {e}"
            ) from e
        logger.warning("audit-chain verify errored (treated as unverified): %s", e)
        return None
    except Exception as e:
        logger.warning("audit-chain verify errored (treated as unverified): %s", e)
        return None
    _CHAIN_VERIFIED = True  # a verification actually completed

    if result.ok:
        logger.debug(
            "audit-chain verify PASS (%d records, %s)",
            result.checked, result.ledger_path,
        )
        return result.as_dict()

    logger.critical(
        "AUDIT-CHAIN VERIFY FAILED at seq=%s: %s (ledger=%s) — the "
        "tamper-evidence record cannot be trusted",
        result.break_seq, result.reason, result.ledger_path,
    )
    # The break is itself a security event. Best-effort append (the ledger
    # may be the compromised artifact; the alert is corroborating).
    try:
        led = ga.get_ledger()
        if led is not None:
            led.emit(
                "security.error",
                action="ledger.chain_verify_failed",
                decision="halt",
                severity="critical",
                outcome={
                    "status": "failure",
                    "class": "chain_verify_failed",
                    "error": result.reason,
                },
                resource={"type": "ledger", "path": result.ledger_path,
                          "break_seq": result.break_seq},
                source_module="lliam_cli/security_audit_startup.py:verify_audit_chain_at_startup",
            )
    except Exception:
        pass

    fail_action = str(audit_cfg.get("verify_fail_action", "block")).lower()
    if fail_action == "block" and _effective_is_strict(config):
        raise AuditChainVerificationError(
            f"audit-chain verification failed at seq={result.break_seq}: "
            f"{result.reason}"
        )
    return result.as_dict()


def _effective_config(config: Optional[dict]) -> dict:
    """Return the config to read audit settings from.

    Prefer a passed config that already carries an ``audit`` block (tests /
    explicit callers); otherwise resolve the real merged config via
    ``load_config()`` so overlay-injected keys are present. Falls back to
    whatever was passed on a load failure.
    """
    if isinstance(config, dict) and "audit" in config:
        return config
    try:
        from lliam_cli import config as _cfg
        return _cfg.load_config()
    except Exception:
        return config or {}


def _effective_is_strict(config: Optional[dict]) -> bool:
    """True when the EFFECTIVE posture is strict.

    Checks the passed config first (a test/caller that already supplied a
    strict posture), then falls back to the merged ``load_config()`` — so a
    caller that passes a raw, overlay-less config (e.g. the gateway's
    ``read_raw_config()``) cannot silently defeat the fail-closed block.
    """
    try:
        from lliam_cli import posture_resolver as _pr
    except Exception:
        return False
    try:
        if config is not None and _pr.is_strict(config):
            return True
    except Exception:
        pass
    try:
        from lliam_cli import config as _cfg
        return bool(_pr.is_strict(_cfg.load_config()))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# LG-GV-01/03/06/10 (additive @ P4.1): top-management governance artifacts.
# ---------------------------------------------------------------------------

class GovernanceArtifactError(RuntimeError):
    """Raised when a mandatory top-management governance artifact is absent,
    placeholder-valued, or expired under strict posture (LG-GV-01/06/10)."""


_GOVERNANCE_ARTIFACTS_CHECKED = False

# Values that can never satisfy a mandatory governance field (fail-closed on
# absent/placeholder — an unfilled template must not pass the gate).
_GOV_PLACEHOLDER_TOKENS = (
    "replace", "placeholder", "example", "changeme", "pending", "tbd", "fixme",
)


def _gov_is_placeholder(value: Any) -> bool:
    if value is None:
        return True
    text = str(value).strip()
    if not text or text.lower() in {"null", "none"}:
        return True
    if "${" in text:  # unresolved env interpolation
        return True
    lowered = text.lower()
    return any(tok in lowered for tok in _GOV_PLACEHOLDER_TOKENS)


def _gov_as_date(value: Any):
    import datetime as _dt
    if isinstance(value, _dt.datetime):
        return value.date()
    if isinstance(value, _dt.date):
        return value
    try:
        return _dt.date.fromisoformat(str(value).strip()[:10])
    except Exception:
        return None


def _gov_repo_root(repo_root: Optional[Path] = None) -> Path:
    """Directory the governance artifacts resolve against.

    Explicit override first (tests); else the directory containing the gov
    overlay named by the existing HERMES_CONFIG / LLIAM_CONFIG selector (the
    overlay lives at the repo root); else this checkout's root.
    """
    if repo_root is not None:
        return Path(repo_root)
    for var in ("HERMES_CONFIG", "LLIAM_CONFIG"):
        raw = os.environ.get(var, "").strip()
        if raw:
            try:
                return Path(raw).expanduser().resolve().parent
            except Exception:
                pass
    return Path(__file__).resolve().parent.parent


def enforce_governance_artifacts_at_startup(
    *, config: Optional[dict] = None, repo_root: Optional[Path] = None,
    force: bool = False,
) -> None:
    """Fail-closed mandatory-artifacts gate (LG-GV-01/03/06/10, P4.1).

    Under strict posture, before serving work, verify the top-management
    governance layer is real and current:

    * LG-GV-01 — ``governance.policy_id`` / ``policy_version`` /
      ``policy_approved_by`` present and non-placeholder;
      ``policy_review_date`` is not past due; the AI policy file exists when
      ``governance.policy_path`` names one.
    * LG-GV-03 — when ``governance.registers.regulatory`` names a register,
      it exists and carries obligations.
    * LG-GV-06 — the signed authorization record exists, matches
      ``governance.authorization_id``, is decision=authorized and unexpired.
    * LG-GV-10 — any baseline-denied high-risk skill that has been re-enabled
      carries a valid, signed, unexpired CAIO waiver; never-waivable
      capabilities (godmode/obliteratus) block regardless of waivers.

    Complete no-op on the low-side posture (low-side deployments do not load
    the governance overlay; nothing is required of them). Idempotent per
    process (``force`` re-runs).
    """
    global _GOVERNANCE_ARTIFACTS_CHECKED
    if _GOVERNANCE_ARTIFACTS_CHECKED and not force:
        return None

    if isinstance(config, dict) and config.get("governance"):
        eff = config
    else:
        try:
            from lliam_cli import config as _cfg
            eff = _cfg.load_config()
        except Exception:
            eff = config or {}
    if not isinstance(eff, dict):
        eff = {}

    if not _effective_is_strict(eff):
        _GOVERNANCE_ARTIFACTS_CHECKED = True
        return None

    import datetime as _dt
    import yaml as _yaml

    today = _dt.date.today()
    root = _gov_repo_root(repo_root)
    gov = eff.get("governance") or {}
    blocking: list[str] = []

    if not gov:
        blocking.append("governance block missing from effective config "
                        "(LG-GV-01)")
    else:
        registers = gov.get("registers") or {}

        # LG-GV-01 — policy identity of record.
        for field in ("policy_id", "policy_version", "policy_approved_by"):
            if _gov_is_placeholder(gov.get(field)):
                blocking.append(f"governance.{field} is absent or a "
                                f"placeholder (LG-GV-01)")
        review = _gov_as_date(gov.get("policy_review_date"))
        if review is None:
            blocking.append("governance.policy_review_date is absent or "
                            "unparseable (LG-GV-01)")
        elif review < today:
            blocking.append(f"AI policy review is past due ({review}) "
                            f"(LG-GV-01)")
        # The policy document itself lives in the operator's management-system
        # library; check a local copy only when one is configured.
        policy_rel = str(gov.get("policy_path") or "")
        if policy_rel and not (root / policy_rel).is_file():
            blocking.append(f"ai-policy file '{policy_rel}' is missing "
                            f"(LG-GV-01)")

        # LG-GV-03 — regulatory register present and populated, when one is
        # configured (it is otherwise held outside the repository).
        reg_rel = str(registers.get("regulatory") or "")
        reg_file = root / reg_rel
        if reg_rel and not reg_file.is_file():
            blocking.append(f"regulatory register '{reg_rel}' is missing "
                            f"(LG-GV-03)")
        elif reg_rel:
            try:
                reg_data = _yaml.safe_load(
                    reg_file.read_text(encoding="utf-8")) or {}
                if not reg_data.get("obligations"):
                    blocking.append("regulatory register has no obligations "
                                    "(LG-GV-03)")
            except Exception as e:
                blocking.append(f"regulatory register unreadable ({e}) "
                                f"(LG-GV-03)")

        # LG-GV-06 — signed go/no-go authorization record.
        auth_rel = str(registers.get("authorization")
                       or "policy/governed/authorization-record.yaml")
        auth_file = root / auth_rel
        if not auth_file.is_file():
            blocking.append(f"authorization record '{auth_rel}' is missing "
                            f"(LG-GV-06)")
        else:
            try:
                record = _yaml.safe_load(
                    auth_file.read_text(encoding="utf-8")) or {}
            except Exception as e:
                record = None
                blocking.append(f"authorization record unreadable ({e}) "
                                f"(LG-GV-06)")
            if isinstance(record, dict):
                cfg_id = gov.get("authorization_id")
                if _gov_is_placeholder(cfg_id):
                    blocking.append("governance.authorization_id is absent "
                                    "or a placeholder (LG-GV-06)")
                elif str(record.get("authorization_id")) != str(cfg_id):
                    blocking.append(
                        f"authorization_id mismatch: record has "
                        f"'{record.get('authorization_id')}', config expects "
                        f"'{cfg_id}' (LG-GV-06)")
                if str(record.get("decision", "")).lower() != "authorized":
                    blocking.append(
                        f"authorization decision is "
                        f"'{record.get('decision')}' — not 'authorized' "
                        f"(LG-GV-06)")
                expires = _gov_as_date(record.get("expires"))
                if expires is None:
                    blocking.append("authorization record has no parseable "
                                    "'expires' date (LG-GV-06)")
                elif expires < today:
                    blocking.append(f"authorization expired ({expires}) "
                                    f"(LG-GV-06)")
                official = ((record.get("authorizing_official") or {})
                            .get("principal"))
                if _gov_is_placeholder(official):
                    blocking.append("authorization record has no "
                                    "authorizing-official principal "
                                    "(LG-GV-06)")

        # LG-GV-10 — CAIO waiver register gates high-risk enablement.
        wav_rel = str(registers.get("waiver")
                      or "policy/governed/waiver-register.yaml")
        wav_file = root / wav_rel
        if not wav_file.is_file():
            blocking.append(f"waiver register '{wav_rel}' is missing "
                            f"(LG-GV-10)")
        else:
            try:
                wav = _yaml.safe_load(
                    wav_file.read_text(encoding="utf-8")) or {}
            except Exception as e:
                wav = None
                blocking.append(f"waiver register unreadable ({e}) "
                                f"(LG-GV-10)")
            if isinstance(wav, dict):
                never = set(wav.get("never_waivable") or [])
                denied = list(wav.get("baseline_denied_skills") or [])
                disabled = set((eff.get("skills") or {}).get("disabled") or [])
                valid_waivers: dict[str, dict] = {}
                for entry in (wav.get("waivers") or []):
                    if not isinstance(entry, dict):
                        continue
                    cap = entry.get("capability")
                    exp = _gov_as_date(entry.get("expires"))
                    if (cap
                            and not _gov_is_placeholder(entry.get("waiver_id"))
                            and not _gov_is_placeholder(entry.get("signed_by"))
                            and exp is not None and exp >= today):
                        valid_waivers[str(cap)] = entry
                for skill in denied:
                    if skill in disabled:
                        continue
                    if skill in never:
                        blocking.append(
                            f"'{skill}' is enabled but NEVER waivable — "
                            f"mandatory deny (LG-GV-10 / LG-SC-01)")
                    elif skill not in valid_waivers:
                        blocking.append(
                            f"high-risk skill '{skill}' is enabled without a "
                            f"valid, signed, unexpired CAIO waiver (LG-GV-10)")

    _GOVERNANCE_ARTIFACTS_CHECKED = True
    if not blocking:
        return None

    for f in blocking:
        logger.critical("[governance-artifacts] BLOCKING: %s", f)
    try:
        from agent import governance_audit as ga
        led = ga.get_ledger()
        if led is not None:
            led.emit(
                "security.error",
                action="governance.artifacts_violation",
                decision="halt",
                severity="critical",
                outcome={"status": "blocked", "class": "governance_artifacts",
                         "error": "; ".join(blocking)[:1000]},
                source_module="lliam_cli/security_audit_startup.py:enforce_governance_artifacts_at_startup",
            )
    except Exception:
        pass
    raise GovernanceArtifactError("; ".join(blocking))
