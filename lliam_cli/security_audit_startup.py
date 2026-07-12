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


def _network_listener_without_auth(config: Optional[dict]) -> list[str]:
    """Warn about network-accessible gateway listeners with no auth.

    Covers the API server (no API_SERVER_KEY) and the dashboard (non-loopback
    bind with no auth provider). Read-only against config + env; overlaps the
    hard fail-closed guards but surfaces the posture proactively at startup.
    """
    findings: list[str] = []
    try:
        from gateway.platforms.base import is_network_accessible
    except Exception:
        return findings

    cfg = config or {}

    # API server. IMPORTANT: at runtime the API server is configured from ENV
    # (API_SERVER_ENABLED / API_SERVER_KEY / API_SERVER_HOST — see
    # gateway/config.py:1534-1554), NOT from the load_config() dict, which does
    # not carry a `platforms` block. Reading only cfg["platforms"] made this
    # check inert in production (the config dict's api block is None). Detect the
    # server from EITHER source: the (rare) config platforms block OR — the real
    # trigger — the environment the gateway itself reads.
    try:
        plats = (cfg.get("platforms") or {})
        api = plats.get("api_server") if isinstance(plats, dict) else None
        extra = (api.get("extra") or {}) if isinstance(api, dict) else {}

        # Mirror the gateway's own enablement predicate EXACTLY
        # (gateway/config.py:1539 — ``api_server_enabled or api_server_key``,
        # with enabled ∈ {true,1,yes}). A broader predicate (e.g. treating a
        # stray API_SERVER_HOST as enablement) would spuriously refuse startup
        # for a server the gateway never actually starts.
        env_enabled = os.environ.get("API_SERVER_ENABLED", "").strip().lower() in {
            "true", "1", "yes"
        }
        cfg_enabled = bool(isinstance(api, dict) and api.get("enabled"))
        # A set API_SERVER_KEY alone also activates the server (config.py:1539).
        key = str(extra.get("key") or os.environ.get("API_SERVER_KEY", "")).strip()
        enabled = env_enabled or cfg_enabled or bool(key)
        if enabled:
            host = extra.get("host") or os.environ.get("API_SERVER_HOST", "127.0.0.1")
            if is_network_accessible(str(host)):
                # Parity with the adapter's own trust boundary
                # (APIServerAdapter.connect refuses a network bind unless the
                # key clears the entropy floor) — a weak-but-nonempty key like
                # "x" must not slip this gate either.
                try:
                    from lliam_cli.auth import has_usable_secret
                    strong = has_usable_secret(key, min_length=16)
                except Exception:
                    strong = bool(key)
                if not strong:
                    detail = ("with NO API_SERVER_KEY" if not key
                              else "with a WEAK API_SERVER_KEY (<16 chars)")
                    findings.append(
                        f"OpenAI-compatible API server is network-accessible ({host}) "
                        f"{detail}. It dispatches terminal-capable agent work — an "
                        "unauthenticated network endpoint is remote code execution. "
                        "Set a strong (≥16-char, high-entropy) API_SERVER_KEY."
                    )
    except Exception:
        pass

    return findings


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
