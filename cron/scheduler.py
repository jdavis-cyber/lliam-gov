"""
Cron job scheduler - executes due jobs.

Provides tick() which checks for due jobs and runs them. The desktop
backend calls this every 60 seconds from a background thread. Job output is
saved locally (there are no chat-platform delivery targets).

Uses a file-based lock (~/.hermes/cron/.tick.lock) so only one tick
runs at a time if multiple processes overlap.
"""

import atexit
import concurrent.futures
import contextvars
import json
import logging
import os
from lliam_cli.env_compat import getenv_compat
import shutil
import subprocess
import sys
import threading

# fcntl is Unix-only; on Windows use msvcrt for file locking
try:
    import fcntl
except ImportError:
    fcntl = None
    try:
        import msvcrt
    except ImportError:
        msvcrt = None
from pathlib import Path
from typing import Optional

# Add parent directory to path for imports BEFORE repo-level imports.
# Without this, standalone invocations (e.g. after `lliam-gov update` reloads
# the module) fail with ModuleNotFoundError for lliam_time et al.
sys.path.insert(0, str(Path(__file__).parent.parent))

from lliam_constants import get_lliam_home
from lliam_cli._subprocess_compat import windows_hide_flags
from lliam_cli.config import load_config, _expand_env_vars
from lliam_time import now as _lliam_now

logger = logging.getLogger(__name__)


class CronPromptInjectionBlocked(Exception):
    """Raised by _build_job_prompt when the fully-assembled prompt trips the
    injection scanner. Caught in run_job so the operator sees a clean
    "job blocked" delivery instead of the scheduler crashing.

    Assembled-prompt scanning (including loaded skill content) plugs the
    gap from #3968: create-time scanning only covers the user-supplied
    prompt field; skill content loaded at runtime was never scanned, so a
    malicious skill could carry an injection payload that reached the
    non-interactive (auto-approve) cron agent.
    """


def _resolve_cron_disabled_toolsets(cfg: dict) -> list[str]:
    """Toolsets a cron-spawned agent must never receive.

    Three protected toolsets are always disabled in cron context:
      - ``cronjob`` — would let a cron-spawned agent schedule more cron jobs
      - ``messaging`` — interactive, needs a live gateway session
      - ``clarify`` — interactive, blocks waiting for user input

    User-level ``agent.disabled_toolsets`` from config.yaml is layered on top
    so per-job ``enabled_toolsets`` cannot bypass policy that applies to
    ordinary agent runs (#25752 — LLM-supplied enabled_toolsets was widening
    past config.yaml's denylist).
    """
    disabled = ["cronjob", "messaging", "clarify"]
    agent_cfg = (cfg or {}).get("agent") or {}
    user_disabled = agent_cfg.get("disabled_toolsets") or []
    for name in user_disabled:
        name = str(name).strip()
        if name and name not in disabled:
            disabled.append(name)
    return disabled


def _merge_mcp_into_per_job_toolsets(per_job: list[str], cfg: dict) -> list[str]:
    """Layer enabled MCP servers onto a per-job ``enabled_toolsets`` allowlist.

    A per-job list scopes the *native* toolsets, but on its own it silently
    drops every MCP server: ``discover_mcp_tools()`` registers the tools into
    the global registry, yet ``get_tool_definitions(enabled_toolsets=...)``
    only keeps toolsets named in the list. The agent then rejects every
    ``mcp_*`` call with "Unknown tool". This restores parity with
    ``_get_platform_tools`` MCP semantics:

      * ``no_mcp`` sentinel present  -> no MCP servers (sentinel stripped)
      * one or more MCP server names already listed -> treat as an allowlist,
        add nothing further (the user named exactly the servers they want)
      * otherwise -> union in every globally-enabled MCP server
    """
    result = [t for t in per_job if t != "no_mcp"]
    if "no_mcp" in per_job:
        return result
    # lazy import: avoid heavy lliam_cli import at cron module load (matches
    # _resolve_cron_enabled_toolsets' fallback) and share one MCP-membership
    # computation with the gateway/CLI platform resolver.
    from lliam_cli.tools_config import enabled_mcp_server_names
    enabled_mcp = enabled_mcp_server_names(cfg)
    if set(result) & enabled_mcp:
        return result
    for name in sorted(enabled_mcp):
        if name not in result:
            result.append(name)
    return result


def _resolve_cron_enabled_toolsets(job: dict, cfg: dict) -> list[str] | None:
    """Resolve the toolset list for a cron job.

    Precedence:
    1. Per-job ``enabled_toolsets`` (set via ``cronjob`` tool on create/update).
       Keeps the agent's job-scoped toolset override intact — #6130. Enabled
       MCP servers are layered on per ``_merge_mcp_into_per_job_toolsets`` so a
       native-toolset allowlist does not silently strip MCP tools.
    2. Per-platform ``lliam-gov tools`` config for the ``cron`` platform.
       Mirrors gateway behavior (``_get_platform_tools(cfg, platform_key)``)
       so users can gate cron toolsets globally without recreating every job.
    3. ``None`` on any lookup failure — AIAgent loads the full default set
       (legacy behavior before this change, preserved as the safety net).

    _DEFAULT_OFF_TOOLSETS ({moa, homeassistant, rl}) are removed by
    ``_get_platform_tools`` for unconfigured platforms, so fresh installs
    get cron WITHOUT ``moa`` by default (issue reported by Norbert —
    surprise $4.63 run).
    """
    per_job = job.get("enabled_toolsets")
    if per_job:
        return _merge_mcp_into_per_job_toolsets(list(per_job), cfg or {})
    try:
        from lliam_cli.tools_config import _get_platform_tools  # lazy: avoid heavy import at cron module load
        return sorted(_get_platform_tools(cfg or {}, "cron"))
    except Exception as exc:
        logger.warning(
            "Cron toolset resolution failed, falling back to full default toolset: %s",
            exc,
        )
        return None


from cron.jobs import get_due_jobs, mark_job_run, save_job_output, advance_next_run

# Sentinel final response for runs that intentionally made no AI call (e.g. a
# pre-run script produced no output or its wake gate said skip).
SILENT_MARKER = "[SILENT]"


# ---------------------------------------------------------------------------
# Persistent thread pool for parallel cron jobs.
# The tick function submits jobs here and returns immediately so the ticker
# thread is never blocked by long-running jobs (e.g. the fixer running 15+ min).
# ---------------------------------------------------------------------------
_parallel_pool: Optional[concurrent.futures.ThreadPoolExecutor] = None
_parallel_pool_max_workers: Optional[int] = None
_running_job_ids: set = set()
_running_lock = threading.Lock()

# Sequential (env-mutating) cron jobs — workdir jobs that touch
# process-global runtime state — must run one at a time, but must NOT block the
# ticker thread.  A persistent single-thread executor preserves ordering across
# ticks while keeping dispatch fire-and-forget, the same as the parallel pool.
_sequential_pool: Optional[concurrent.futures.ThreadPoolExecutor] = None


def _get_parallel_pool(max_workers: Optional[int]) -> concurrent.futures.ThreadPoolExecutor:
    """Return (or create) the persistent parallel pool."""
    global _parallel_pool, _parallel_pool_max_workers
    if _parallel_pool is None or _parallel_pool_max_workers != max_workers:
        if _parallel_pool is not None:
            _parallel_pool.shutdown(wait=False, cancel_futures=False)
        _parallel_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="cron-parallel",
        )
        _parallel_pool_max_workers = max_workers
    return _parallel_pool


def _get_sequential_pool() -> concurrent.futures.ThreadPoolExecutor:
    """Return (or create) the persistent single-thread sequential pool.

    A single worker guarantees env-mutating jobs never overlap, even
    across ticks: a job queued by a newer tick waits for the previous tick's
    sequential jobs to finish rather than corrupting their os.environ
    state.
    """
    global _sequential_pool
    if _sequential_pool is None:
        _sequential_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="cron-seq",
        )
    return _sequential_pool


def _shutdown_parallel_pool() -> None:
    """Shut down the persistent pools on process exit."""
    global _parallel_pool, _parallel_pool_max_workers, _sequential_pool
    if _parallel_pool is not None:
        _parallel_pool.shutdown(wait=True, cancel_futures=False)
        _parallel_pool = None
        _parallel_pool_max_workers = None
    if _sequential_pool is not None:
        _sequential_pool.shutdown(wait=True, cancel_futures=False)
        _sequential_pool = None


atexit.register(_shutdown_parallel_pool)


# Backward-compatible module override used by tests and emergency monkeypatches.
_lliam_home: Path | None = None


def _get_lliam_home() -> Path:
    """Resolve Lliam-GOV home dynamically while preserving test monkeypatch hooks.

    Cron is per-profile by design (#4707): the in-process ticker runs inside a
    profile-scoped backend, so resolving the active HERMES_HOME at call time
    means a profile's jobs are stored AND executed under that profile's home
    (its .env, config.yaml, scripts, skills). Do not freeze this at import or
    anchor it at the shared default root — either re-breaks profile isolation.
    """
    return _lliam_home or get_lliam_home()


def _get_lock_paths() -> tuple[Path, Path]:
    """Resolve cron lock paths at call time so profile/env changes are honored."""
    lliam_home = _get_lliam_home()
    lock_dir = lliam_home / "cron"
    return lock_dir, lock_dir / ".tick.lock"


def _cron_job_origin_log_suffix(job: dict) -> str:
    """Return safe provenance details for security warnings about a cron job.

    The scheduler normally has no live HTTP request object when it detects a
    bad stored ``context_from`` reference. Including the job's saved origin
    makes future probe logs actionable without exposing secrets: platform/chat
    metadata for gateway-created jobs, and optional source-IP fields for API
    surfaces that persist them in origin metadata.
    """
    origin = job.get("origin")
    if not isinstance(origin, dict):
        return ""

    fields = []
    for key in ("platform", "chat_id", "thread_id", "source_ip", "remote", "forwarded_for"):
        value = origin.get(key)
        if value is None:
            continue
        text = str(value).replace("\r", " ").replace("\n", " ").strip()
        if text:
            fields.append(f"origin_{key}={text[:200]!r}")
    return " " + " ".join(fields) if fields else ""


_DEFAULT_SCRIPT_TIMEOUT = 120  # seconds
# Backward-compatible module override used by tests and emergency monkeypatches.
_SCRIPT_TIMEOUT = _DEFAULT_SCRIPT_TIMEOUT


def _get_script_timeout() -> int:
    """Resolve cron pre-run script timeout from module/env/config with a safe default."""
    if _SCRIPT_TIMEOUT != _DEFAULT_SCRIPT_TIMEOUT:
        try:
            timeout = int(float(_SCRIPT_TIMEOUT))
            if timeout > 0:
                return timeout
        except Exception:
            logger.warning("Invalid patched _SCRIPT_TIMEOUT=%r; using env/config/default", _SCRIPT_TIMEOUT)

    env_value = getenv_compat("CRON_SCRIPT_TIMEOUT", "").strip()
    if env_value:
        try:
            timeout = int(float(env_value))
            if timeout > 0:
                return timeout
        except Exception:
            logger.warning("Invalid HERMES_CRON_SCRIPT_TIMEOUT=%r; using config/default", env_value)

    try:
        cfg = load_config() or {}
        cron_cfg = cfg.get("cron", {}) if isinstance(cfg, dict) else {}
        configured = cron_cfg.get("script_timeout_seconds")
        if configured is not None:
            timeout = int(float(configured))
            if timeout > 0:
                return timeout
    except Exception as exc:
        logger.debug("Failed to load cron script timeout from config: %s", exc)

    return _DEFAULT_SCRIPT_TIMEOUT


def _run_job_script(script_path: str) -> tuple[bool, str]:
    """Execute a cron job's data-collection script and capture its output.

    Scripts must reside within HERMES_HOME/scripts/.  Both relative and
    absolute paths are resolved and validated against this directory to
    prevent arbitrary script execution via path traversal or absolute
    path injection.

    Supported interpreters (chosen by file extension):

    * ``.sh`` / ``.bash`` — run with ``/bin/bash``
    * anything else — run with the current Python interpreter
      (``sys.executable``), preserving the original behaviour for
      Python-based pre-check and data-collection scripts.

    Shell support lets ``no_agent=True`` jobs ship classic bash watchdogs
    (the `memory-watchdog.sh` pattern) without wrapping them in Python.

    Subprocess environment is passed through ``_sanitize_subprocess_env`` so
    provider credentials and other Lliam-managed secrets are not inherited
    (SECURITY.md §2.3), matching terminal and MCP child processes.

    Args:
        script_path: Path to the script.  Relative paths are resolved
            against HERMES_HOME/scripts/.  Absolute and ~-prefixed paths
            are also validated to ensure they stay within the scripts dir.

    Returns:
        (success, output) — on failure *output* contains the error message so the
        LLM can report the problem to the user.
    """
    scripts_dir = _get_lliam_home() / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    scripts_dir_resolved = scripts_dir.resolve()

    raw = Path(script_path).expanduser()
    if raw.is_absolute():
        path = raw.resolve()
    else:
        path = (scripts_dir / raw).resolve()

    # Guard against path traversal, absolute path injection, and symlink
    # escape — scripts MUST reside within HERMES_HOME/scripts/.
    try:
        path.relative_to(scripts_dir_resolved)
    except ValueError:
        return False, (
            f"Blocked: script path resolves outside the scripts directory "
            f"({scripts_dir_resolved}): {script_path!r}"
        )

    if not path.exists():
        return False, f"Script not found: {path}"
    if not path.is_file():
        return False, f"Script path is not a file: {path}"

    script_timeout = _get_script_timeout()

    # Pick an interpreter by extension.  Bash for .sh/.bash, Python for
    # everything else.  We deliberately do NOT honour the file's own
    # shebang: the scripts dir is trusted, but keeping the interpreter
    # choice explicit here keeps the allowed surface small and auditable.
    suffix = path.suffix.lower()
    if suffix in {".sh", ".bash"}:
        # Resolve bash dynamically so Windows (Git Bash) and Linux/macOS
        # all work.  On native Windows without Git for Windows installed
        # shutil.which returns None — fall back to a clear error rather
        # than a FileNotFoundError with a confusing "[WinError 2]"
        # traceback.
        _bash = shutil.which("bash") or (
            "/bin/bash" if os.path.isfile("/bin/bash") else None
        )
        if _bash is None:
            return False, (
                f"Cannot run .sh/.bash script {path.name!r}: bash not found on PATH. "
                "On Windows, install Git for Windows (which ships Git Bash) "
                "or rewrite the script as Python (.py)."
            )
        argv = [_bash, str(path)]
    else:
        argv = [sys.executable, str(path)]

    try:
        from tools.environments.local import _sanitize_subprocess_env

        popen_kwargs = {"creationflags": windows_hide_flags()} if sys.platform == "win32" else {}
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=script_timeout,
            cwd=str(path.parent),
            env=_sanitize_subprocess_env(os.environ.copy()),
            **popen_kwargs,
        )
        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()

        # Redact secrets from both stdout and stderr before any return path.
        try:
            from agent.redact import redact_sensitive_text
            stdout = redact_sensitive_text(stdout)
            stderr = redact_sensitive_text(stderr)
        except Exception:
            pass

        if result.returncode != 0:
            parts = [f"Script exited with code {result.returncode}"]
            if stderr:
                parts.append(f"stderr:\n{stderr}")
            if stdout:
                parts.append(f"stdout:\n{stdout}")
            return False, "\n".join(parts)

        return True, stdout

    except subprocess.TimeoutExpired:
        return False, f"Script timed out after {script_timeout}s: {path}"
    except Exception as exc:
        return False, f"Script execution failed: {exc}"


def _parse_wake_gate(script_output: str) -> bool:
    """Parse the last non-empty stdout line of a cron job's pre-check script
    as a wake gate.

    The convention (ported from nanoclaw #1232): if the last stdout line is
    JSON like ``{"wakeAgent": false}``, the agent is skipped entirely — no
    LLM run, no delivery. Any other output (non-JSON, missing flag, gate
    absent, or ``wakeAgent: true``) means wake the agent normally.

    Returns True if the agent should wake, False to skip.
    """
    if not script_output:
        return True
    stripped_lines = [line for line in script_output.splitlines() if line.strip()]
    if not stripped_lines:
        return True
    last_line = stripped_lines[-1].strip()
    try:
        gate = json.loads(last_line)
    except (json.JSONDecodeError, ValueError):
        return True
    if not isinstance(gate, dict):
        return True
    return gate.get("wakeAgent", True) is not False


def _build_job_prompt(job: dict, prerun_script: Optional[tuple] = None) -> str:
    """Build the effective prompt for a cron job, optionally loading one or more skills first.

    Args:
        job: The cron job dict.
        prerun_script: Optional ``(success, stdout)`` from a script that has
            already been executed by the caller (e.g. for a wake-gate check).
            When provided, the script is not re-executed and the cached
            result is used for prompt injection. When omitted, the script
            (if any) runs inline as before.
    """
    user_prompt = str(job.get("prompt") or "")
    prompt = user_prompt
    skills = job.get("skills")
    # True when runtime-collected DATA (script stdout, upstream-job output)
    # has been injected into the prompt. Data content legitimately quotes
    # command-shape strings (a triage feed ingesting a bug report that
    # pastes `rm -rf /`), so it must not be scanned with the strict
    # user-prompt pattern set — see _scan_assembled_cron_prompt.
    has_injected_data = False

    # Run data-collection script if configured, inject output as context.
    script_path = job.get("script")
    if script_path:
        if prerun_script is not None:
            success, script_output = prerun_script
        else:
            success, script_output = _run_job_script(script_path)
        if success:
            if script_output:
                prompt = (
                    "## Script Output\n"
                    "The following data was collected by a pre-run script. "
                    "Use it as context for your analysis.\n\n"
                    f"```\n{script_output}\n```\n\n"
                    f"{prompt}"
                )
                has_injected_data = True
            else:
                # Script produced no output — nothing to report, skip AI call.
                return None
        else:
            prompt = (
                "## Script Error\n"
                "The data-collection script failed. Report this to the user.\n\n"
                f"```\n{script_output}\n```\n\n"
                f"{prompt}"
            )
            has_injected_data = True

    # Inject output from referenced cron jobs as context.
    context_from = job.get("context_from")
    if context_from:
        from cron.jobs import OUTPUT_DIR
        if isinstance(context_from, str):
            context_from = [context_from]
        for source_job_id in context_from:
            # Guard against path traversal — valid job IDs are 12-char hex strings
            if not source_job_id or not all(c in "0123456789abcdef" for c in source_job_id):
                logger.warning(
                    "context_from: skipping invalid job_id %r for job_id=%r name=%r%s",
                    source_job_id,
                    job.get("id"),
                    job.get("name"),
                    _cron_job_origin_log_suffix(job),
                )
                continue
            try:
                job_output_dir = OUTPUT_DIR / source_job_id
                if not job_output_dir.exists():
                    continue  # silent skip — no output yet
                output_files = sorted(
                    job_output_dir.glob("*.md"),
                    key=lambda f: f.stat().st_mtime,
                    reverse=True,
                )
                if not output_files:
                    continue  # silent skip — no output yet
                latest_output = output_files[0].read_text(encoding="utf-8").strip()
                # Truncate to 8K characters to avoid prompt bloat
                _MAX_CONTEXT_CHARS = 8000
                if len(latest_output) > _MAX_CONTEXT_CHARS:
                    latest_output = latest_output[:_MAX_CONTEXT_CHARS] + "\n\n[... output truncated ...]"
                if latest_output:
                    prompt = (
                        f"## Output from job '{source_job_id}'\n"
                        "The following is the most recent output from a preceding "
                        "cron job. Use it as context for your analysis.\n\n"
                        f"```\n{latest_output}\n```\n\n"
                        f"{prompt}"
                    )
                    has_injected_data = True
                else:
                    continue  # silent skip — empty output
            except (OSError, PermissionError) as e:
                logger.warning("context_from: failed to read output for job %r: %s", source_job_id, e)
                # silent skip — do not pollute the prompt with error messages

    # Always prepend cron execution guidance so the agent knows where its
    # output goes.
    cron_hint = (
        "[IMPORTANT: You are running as a scheduled cron job. "
        "OUTPUT: Your final response is saved as this job's output, which "
        "the user reviews in the desktop Cron screen. Just produce your "
        "report/output as your final response.]\n\n"
    )
    prompt = cron_hint + prompt
    if skills is None:
        legacy = job.get("skill")
        skills = [legacy] if legacy else []
    elif isinstance(skills, str):
        skills = [skills]

    skill_names = [str(name).strip() for name in skills if str(name).strip()]
    if not skill_names:
        return _scan_assembled_cron_prompt(
            prompt,
            job,
            has_skills=False,
            has_injected_data=has_injected_data,
            user_prompt=user_prompt,
        )

    from tools.skills_tool import skill_view
    from tools.skill_usage import bump_use
    from agent.skill_bundles import build_bundle_invocation_message, resolve_bundle_command_key

    parts = []
    skipped: list[str] = []
    for skill_name in skill_names:
        # Cron jobs historically accepted only skill names here, but the CLI/gateway
        # slash-command path lets bundles shadow skills with the same slug. Mirror
        # that behavior so `skills: ["my-bundle"]` expands bundle members instead
        # of being treated as a missing skill.
        bundle_key = resolve_bundle_command_key(skill_name.lstrip("/"))
        if bundle_key:
            bundle_payload = build_bundle_invocation_message(
                bundle_key,
                user_instruction="",
                task_id=str(job.get("id") or "") or None,
            )
            if bundle_payload:
                bundle_message, _loaded_bundle_skills, _missing_bundle_skills = bundle_payload
                if parts:
                    parts.append("")
                parts.append(bundle_message)
                continue
            logger.warning(
                "Cron job '%s': bundle '%s' could not load any skills, skipping",
                job.get("name", job.get("id")),
                skill_name,
            )
            skipped.append(skill_name)
            continue

        try:
            loaded = json.loads(skill_view(skill_name))
        except (json.JSONDecodeError, TypeError):
            logger.warning("Cron job '%s': skill '%s' returned invalid JSON, skipping", job.get("name", job.get("id")), skill_name)
            skipped.append(skill_name)
            continue
        if not loaded.get("success"):
            error = loaded.get("error") or f"Failed to load skill '{skill_name}'"
            logger.warning("Cron job '%s': skill not found, skipping — %s", job.get("name", job.get("id")), error)
            skipped.append(skill_name)
            continue

        # Bump usage so the curator sees this skill as actively used.
        try:
            bump_use(skill_name)
        except Exception:
            logger.debug("Cron job: failed to bump skill usage for '%s'", skill_name, exc_info=True)

        content = str(loaded.get("content") or "").strip()
        if parts:
            parts.append("")
        parts.extend(
            [
                f'[IMPORTANT: The user has invoked the "{skill_name}" skill, indicating they want you to follow its instructions. The full skill content is loaded below.]',
                "",
                content,
            ]
        )

    if skipped:
        notice = (
            f"[IMPORTANT: The following skill(s) were listed for this job but could not be found "
            f"and were skipped: {', '.join(skipped)}. "
            f"Start your response with a brief notice so the user is aware, e.g.: "
            f"'⚠️ Skill(s) not found and skipped: {', '.join(skipped)}']"
        )
        parts.insert(0, notice)

    if prompt:
        parts.extend(["", f"The user has provided the following instruction alongside the skill invocation: {prompt}"])
    return _scan_assembled_cron_prompt("\n".join(parts), job, has_skills=True)


def _scan_assembled_cron_prompt(
    assembled: str,
    job: dict,
    *,
    has_skills: bool = False,
    has_injected_data: bool = False,
    user_prompt: Optional[str] = None,
) -> str:
    """Scan the fully-assembled cron prompt for injection patterns. Raises
    ``CronPromptInjectionBlocked`` when a match fires so ``run_job`` can
    surface a clear refusal to the operator.

    Plugs the #3968 gap: ``_scan_cron_prompt`` runs on the user-supplied
    prompt at create/update, but skill content is loaded from disk at
    runtime and was never scanned. Since cron runs non-interactively
    (auto-approves tool calls), a malicious skill carrying an injection
    payload bypassed every gate.

    Two pattern tiers, selected by what the assembled prompt CONTAINS,
    not just whether skills are attached:

    - When the assembled prompt is essentially the user prompt + the cron
      hint (no skills, no injected data), the STRICT ``_scan_cron_prompt``
      patterns apply: a bare ``rm -rf /`` in a small directive prompt is a
      smoking gun, not prose.
    - When the assembled prompt includes runtime-loaded content — skill
      markdown (``has_skills=True``) or DATA injected from a job script's
      stdout / an upstream job's output (``has_injected_data=True``) — the
      LOOSER ``_scan_cron_skill_assembled`` pattern set is used: only
      unambiguous prompt-injection directives block; command-shape
      patterns are dropped and invisible unicode is sanitized (stripped +
      logged) rather than blocked, to avoid false-positives that
      permanently kill a job. Skill bodies are vetted at install time by
      ``skills_guard.py``; script output is produced by operator-authored
      code, the same trust class — and data feeds (e.g. a triage bot
      ingesting bug reports) legitimately quote dangerous commands.

    When the looser tier is selected because of injected data only,
    ``user_prompt`` (the raw, pre-assembly prompt) is additionally scanned
    with the STRICT set so the user-authored surface keeps the full
    create/update-time guarantee at runtime (defense-in-depth for legacy
    jobs that predate the create-time scanner).
    """
    from tools.cronjob_tools import _scan_cron_prompt, _scan_cron_skill_assembled

    if has_skills or has_injected_data:
        # Runtime-loaded content (vetted skill markdown and/or data from
        # operator-authored scripts) legitimately contains command-shape
        # strings. Invisible unicode is sanitized (not blocked) so a stray
        # zero-width space can't permanently kill the job; the cleaned
        # prompt is what actually runs.
        cleaned, scan_error = _scan_cron_skill_assembled(assembled)
        assembled = cleaned
        if not scan_error and not has_skills and user_prompt:
            # Data-injection path: keep the strict guarantee on the
            # user-authored prompt itself.
            scan_error = _scan_cron_prompt(user_prompt)
    else:
        scan_error = _scan_cron_prompt(assembled)
    if scan_error:
        job_label = job.get("name") or job.get("id") or "<unknown>"
        logger.warning(
            "Cron job '%s': assembled prompt blocked by injection scanner — %s",
            job_label,
            scan_error,
        )
        raise CronPromptInjectionBlocked(scan_error)
    return assembled


def run_job(job: dict) -> tuple[bool, str, str, Optional[str]]:
    """
    Execute a single cron job.
    
    Returns:
        Tuple of (success, full_output_doc, final_response, error_message)
    """
    job_id = job["id"]
    job_name = str(job.get("name") or job.get("prompt") or job_id or "cron job")

    # ---------------------------------------------------------------
    # no_agent short-circuit — the script IS the job, no LLM involvement.
    # ---------------------------------------------------------------
    # This mirrors the classic "run a bash script on a timer, send its
    # stdout to telegram" watchdog pattern. The agent path is skipped
    # entirely: no AIAgent, no prompt, no tool loop, no token spend.
    #
    # We check this BEFORE importing run_agent / constructing SessionDB so
    # a pure-script tick never pays for the agent machinery it isn't going
    # to use. Keep this block self-contained.
    #
    # Semantics:
    #   - script stdout (trimmed) → delivered verbatim as the final message
    #   - empty stdout            → silent run (no delivery, success=True)
    #   - non-zero exit / timeout → delivered as an error alert, success=False
    #   - wakeAgent=false gate    → treated like empty stdout (silent), since
    #                               the whole point of no_agent is that there
    #                               is no agent to wake
    if job.get("no_agent"):
        script_path = job.get("script")
        if not script_path:
            err = "no_agent=True but no script is set for this job"
            logger.error("Job '%s': %s", job_id, err)
            return False, "", "", err

        # Apply workdir if configured — lets scripts use predictable relative
        # paths. For no_agent jobs this is just the subprocess cwd (not an
        # agent TERMINAL_CWD bridge).
        _job_workdir = (job.get("workdir") or "").strip() or None
        _prior_cwd = None
        if _job_workdir and Path(_job_workdir).is_dir():
            _prior_cwd = os.getcwd()
            try:
                os.chdir(_job_workdir)
            except OSError:
                _prior_cwd = None

        try:
            ok, output = _run_job_script(script_path)
        finally:
            if _prior_cwd is not None:
                try:
                    os.chdir(_prior_cwd)
                except OSError:
                    pass

        now_iso = _lliam_now().strftime("%Y-%m-%d %H:%M:%S")

        if not ok:
            # Script crashed / timed out / exited non-zero.  Deliver the
            # error so the user knows the watchdog itself broke — silent
            # failure for an alerting job is the worst-case outcome.
            alert = (
                f"⚠ Cron watchdog '{job_name}' script failed\n\n"
                f"{output}\n\n"
                f"Time: {now_iso}"
            )
            doc = (
                f"# Cron Job: {job_name}\n\n"
                f"**Job ID:** {job_id}\n"
                f"**Run Time:** {now_iso}\n"
                f"**Mode:** no_agent (script)\n"
                f"**Status:** script failed\n\n"
                f"{output}\n"
            )
            return False, doc, alert, output

        # Honour the wakeAgent gate as a silent signal — `wakeAgent: false`
        # means "nothing to report this tick", same as empty stdout.
        if not _parse_wake_gate(output):
            logger.info(
                "Job '%s' (no_agent): wakeAgent=false gate — silent run", job_id
            )
            silent_doc = (
                f"# Cron Job: {job_name}\n\n"
                f"**Job ID:** {job_id}\n"
                f"**Run Time:** {now_iso}\n"
                f"**Mode:** no_agent (script)\n"
                f"**Status:** silent (wakeAgent=false)\n"
            )
            return True, silent_doc, SILENT_MARKER, None

        if not output.strip():
            logger.info("Job '%s' (no_agent): empty stdout — silent run", job_id)
            silent_doc = (
                f"# Cron Job: {job_name}\n\n"
                f"**Job ID:** {job_id}\n"
                f"**Run Time:** {now_iso}\n"
                f"**Mode:** no_agent (script)\n"
                f"**Status:** silent (empty output)\n"
            )
            return True, silent_doc, SILENT_MARKER, None

        doc = (
            f"# Cron Job: {job_name}\n\n"
            f"**Job ID:** {job_id}\n"
            f"**Run Time:** {now_iso}\n"
            f"**Mode:** no_agent (script)\n\n"
            f"---\n\n"
            f"{output}\n"
        )
        return True, doc, output, None

    # ---------------------------------------------------------------
    # Default (LLM) path — import and construct the agent machinery now
    # that we know we actually need it. Doing these imports here instead of
    # at module top keeps no_agent ticks from paying for AIAgent / SessionDB
    # construction costs.
    # ---------------------------------------------------------------
    from run_agent import AIAgent

    # Initialize SQLite session store so cron job messages are persisted
    # and discoverable via session_search (same pattern as gateway/run.py).
    _session_db = None
    try:
        from lliam_state import SessionDB
        _session_db = SessionDB()
    except Exception as e:
        logger.debug("Job '%s': SQLite session store not available: %s", job.get("id", "?"), e)

    # Wake-gate: if this job has a pre-check script, run it BEFORE building
    # the prompt so a ``{"wakeAgent": false}`` response can short-circuit
    # the whole agent run. We pass the result into _build_job_prompt so
    # the script is only executed once.
    prerun_script = None
    script_path = job.get("script")
    if script_path:
        prerun_script = _run_job_script(script_path)
        _ran_ok, _script_output = prerun_script
        if _ran_ok and not _parse_wake_gate(_script_output):
            logger.info(
                "Job '%s' (ID: %s): wakeAgent=false, skipping agent run",
                job_name, job_id,
            )
            silent_doc = (
                f"# Cron Job: {job_name}\n\n"
                f"**Job ID:** {job_id}\n"
                f"**Run Time:** {_lliam_now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                "Script gate returned `wakeAgent=false` — agent skipped.\n"
            )
            return True, silent_doc, SILENT_MARKER, None

    try:
        prompt = _build_job_prompt(job, prerun_script=prerun_script)
    except CronPromptInjectionBlocked as block_exc:
        # Assembled prompt (user prompt + loaded skill content) tripped the
        # injection scanner. Refuse to run the agent this tick and surface
        # a clear failure to the operator so they see WHY the scheduled job
        # didn't run and can audit the offending skill.
        logger.warning(
            "Job '%s' (ID: %s): blocked by prompt-injection scanner — %s",
            job_name, job_id, block_exc,
        )
        blocked_doc = (
            f"# Cron Job: {job_name}\n\n"
            f"**Job ID:** {job_id}\n"
            f"**Run Time:** {_lliam_now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"**Status:** BLOCKED\n\n"
            "The assembled prompt (user prompt + loaded skill content) tripped "
            "the cron injection scanner and the agent was NOT run.\n\n"
            f"**Scanner result:** {block_exc}\n\n"
            "Audit the skill(s) attached to this job for prompt-injection "
            "payloads or invisible-unicode markers. If the skill is legitimate "
            "and the match is a false positive, rephrase the content to avoid "
            "the threat pattern (`tools/cronjob_tools.py::_CRON_THREAT_PATTERNS`)."
        )
        return False, blocked_doc, "", str(block_exc)
    if prompt is None:
        logger.info("Job '%s': script produced no output, skipping AI call.", job_name)
        return True, "", SILENT_MARKER, None
    _cron_session_id = f"cron_{job_id}_{_lliam_now().strftime('%Y%m%d_%H%M%S')}"

    logger.info("Running job '%s' (ID: %s)", job_name, job_id)
    logger.info("Prompt: %s", prompt[:100])

    agent = None

    # Use ContextVars for per-job session/delivery state so parallel jobs
    # don't clobber each other's targets (os.environ is process-global).
    from agent.session_context import set_session_vars, clear_session_vars, _VAR_MAP

    # Cron execution is an internal scheduler context. Clear the
    # HERMES_SESSION_* contextvars so tools (background-process notification
    # routing, TTS format choice, per-platform skill filters, the prompt cache
    # key) never behave as if a live chat session were driving the agent.
    # The HERMES_CRON_AUTO_DELIVER_* vars are kept blank: cron output is
    # delivered locally only.
    _ctx_tokens = set_session_vars(
        platform="",
        chat_id="",
        chat_name="",
    )
    _cron_delivery_vars = (
        "HERMES_CRON_AUTO_DELIVER_PLATFORM",
        "HERMES_CRON_AUTO_DELIVER_CHAT_ID",
        "HERMES_CRON_AUTO_DELIVER_THREAD_ID",
    )
    for _var_name in _cron_delivery_vars:
        _VAR_MAP[_var_name].set("")

    # Per-job working directory.  When set (and validated at create/update
    # time), we point TERMINAL_CWD at it so:
    #   - build_context_files_prompt() picks up AGENTS.md / CLAUDE.md /
    #     .cursorrules from the job's project dir, AND
    #   - the terminal, file, and code-exec tools run commands from there.
    #
    # tick() serializes workdir-jobs outside the parallel pool, so mutating
    # os.environ["TERMINAL_CWD"] here is safe for those jobs.  For workdir-less
    # jobs we leave TERMINAL_CWD untouched — preserves the original behaviour
    # (skip_context_files=True, tools use whatever cwd the scheduler has).
    _job_workdir = (job.get("workdir") or "").strip() or None
    if _job_workdir and not Path(_job_workdir).is_dir():
        # Directory was removed between create-time validation and now.  Log
        # and drop back to old behaviour rather than crashing the job.
        logger.warning(
            "Job '%s': configured workdir %r no longer exists — running without it",
            job_id, _job_workdir,
        )
        _job_workdir = None
    _prior_terminal_cwd = os.environ.get("TERMINAL_CWD", "_UNSET_")
    if _job_workdir:
        os.environ["TERMINAL_CWD"] = _job_workdir
        logger.info("Job '%s': using workdir %s", job_id, _job_workdir)

    # Mark this as a cron session so the approval system can apply cron_mode.
    # Context-local, set right before the try and reset in its finally: the
    # gateway runs this scheduler in-process, and a process-wide env var would
    # make every later (or concurrent) live gateway turn look like cron
    # (AI-1172).
    from tools.approval import reset_cron_session, set_cron_session
    _cron_marker_token = set_cron_session()

    try:
        # Re-read .env and config.yaml fresh every run so provider/key
        # changes take effect without a gateway restart.
        from dotenv import load_dotenv
        try:
            load_dotenv(str(_get_lliam_home() / ".env"), override=True, encoding="utf-8")
        except UnicodeDecodeError:
            load_dotenv(str(_get_lliam_home() / ".env"), override=True, encoding="latin-1")

        # Model resolution precedence: per-job override > HERMES_MODEL env >
        # config.yaml ``model:`` (string or ``{default: ...}``). The per-job
        # value is intentionally re-read from storage every tick so a
        # ``cronjob action=update model=...`` after a failed run takes effect
        # on the next tick — there is no in-memory cache.
        model = job.get("model") or getenv_compat("MODEL") or ""

        # Load config.yaml for model, reasoning, prefill, toolsets, provider routing
        _cfg = {}
        try:
            import yaml
            _cfg_path = str(_get_lliam_home() / "config.yaml")
            if os.path.exists(_cfg_path):
                with open(_cfg_path, encoding="utf-8") as _f:
                    _cfg = yaml.safe_load(_f) or {}
                # Managed scope: a scheduled job must honor administrator-pinned
                # model / reasoning / toolsets / provider_routing too. This loader
                # builds its own dict, so overlay managed values via the shared
                # helper (fail-open, no-op when no managed scope).
                try:
                    from lliam_cli import managed_scope
                    _cfg = managed_scope.apply_managed_overlay(_cfg)
                except Exception:
                    pass
                _cfg = _expand_env_vars(_cfg)
                # Coerce null/missing to {} so a falsy default never
                # clobbers an already-resolved env value with ``None``.
                _model_cfg = _cfg.get("model") or {}
                if not job.get("model"):
                    if isinstance(_model_cfg, str):
                        model = _model_cfg
                    elif isinstance(_model_cfg, dict):
                        # Mirror the CLI/oneshot resolution: prefer ``default``,
                        # accept a ``model`` alias, overwrite only when truthy.
                        _default = _model_cfg.get("default") or _model_cfg.get("model")
                        if _default:
                            model = _default
        except Exception as e:
            logger.warning("Job '%s': failed to load config.yaml, using defaults: %s", job_id, e)

        # Fail fast if no model resolved from job / env / config.yaml: an empty
        # model otherwise reaches the provider as an opaque 400 (#23979).
        if not (isinstance(model, str) and model.strip()):
            raise RuntimeError(
                f"Cron job '{job_name}' has no model configured "
                f"(job.model={job.get('model')!r}, "
                f"HERMES_MODEL={os.getenv('HERMES_MODEL', '')!r}, "
                "config.yaml model.default missing or empty). "
                f"Set a per-job model via "
                f"`cronjob action=update job_id={job_id} model=<name>` or set a "
                "default with `lliam-gov model <name>`."
            )

        # Apply IPv4 preference if configured.
        try:
            from lliam_constants import apply_ipv4_preference
            _net_cfg = _cfg.get("network", {})
            if isinstance(_net_cfg, dict) and _net_cfg.get("force_ipv4"):
                apply_ipv4_preference(force=True)
        except Exception:
            pass

        # Reasoning config from config.yaml
        from lliam_constants import parse_reasoning_effort
        effort = str(_cfg.get("agent", {}).get("reasoning_effort", "")).strip()
        reasoning_config = parse_reasoning_effort(effort)

        # Prefill messages from env or config.yaml. The top-level
        # prefill_messages_file key is canonical; agent.prefill_messages_file is
        # retained as a legacy fallback for older CLI/godmode configs.
        prefill_messages = None
        agent_cfg = _cfg.get("agent", {}) if isinstance(_cfg.get("agent", {}), dict) else {}
        prefill_file = (
            getenv_compat("PREFILL_MESSAGES_FILE", "")
            or _cfg.get("prefill_messages_file", "")
            or agent_cfg.get("prefill_messages_file", "")
        )
        if prefill_file:
            pfpath = Path(prefill_file).expanduser()
            if not pfpath.is_absolute():
                pfpath = _get_lliam_home() / pfpath
            if pfpath.exists():
                try:
                    with open(pfpath, "r", encoding="utf-8") as _pf:
                        prefill_messages = json.load(_pf)
                    if not isinstance(prefill_messages, list):
                        prefill_messages = None
                except Exception as e:
                    logger.warning("Job '%s': failed to parse prefill messages file '%s': %s", job_id, pfpath, e)
                    prefill_messages = None

        # Max iterations
        max_iterations = _cfg.get("agent", {}).get("max_turns") or _cfg.get("max_turns") or 90

        # Provider routing
        pr = _cfg.get("provider_routing") or {}

        from lliam_cli.runtime_provider import (
            resolve_runtime_provider,
            format_runtime_provider_error,
        )
        from lliam_cli.auth import AuthError
        try:
            # Do not inject HERMES_INFERENCE_PROVIDER here. resolve_runtime_provider()
            # already prefers persisted config over stale shell/env overrides when
            # no explicit provider is requested. Passing the env var here short-
            # circuits that precedence and can resurrect old providers (for
            # example DeepSeek) for cron jobs that do not pin provider/model.
            runtime_kwargs = {
                "requested": job.get("provider"),
            }
            if job.get("base_url"):
                runtime_kwargs["explicit_base_url"] = job.get("base_url")
            runtime = resolve_runtime_provider(**runtime_kwargs)
        except AuthError as auth_exc:
            # Primary provider auth failed — try fallback chain before giving up.
            logger.warning("Job '%s': primary auth failed (%s), trying fallback", job_id, auth_exc)
            fb = _cfg.get("fallback_providers") or _cfg.get("fallback_model")
            fb_list = (fb if isinstance(fb, list) else [fb]) if fb else []
            runtime = None
            for entry in fb_list:
                if not isinstance(entry, dict):
                    continue
                try:
                    fb_kwargs = {"requested": entry.get("provider")}
                    if entry.get("base_url"):
                        fb_kwargs["explicit_base_url"] = entry["base_url"]
                    if entry.get("api_key"):
                        fb_kwargs["explicit_api_key"] = entry["api_key"]
                    fb_kwargs["governance_path"] = "fallback"
                    runtime = resolve_runtime_provider(**fb_kwargs)
                    logger.info("Job '%s': fallback resolved to %s", job_id, runtime.get("provider"))
                    break
                except Exception as fb_exc:
                    logger.debug("Job '%s': fallback %s failed: %s", job_id, entry.get("provider"), fb_exc)
            if runtime is None:
                raise RuntimeError(format_runtime_provider_error(auth_exc)) from auth_exc
        except Exception as exc:
            message = format_runtime_provider_error(exc)
            raise RuntimeError(message) from exc

        # Provider/model-drift fail-closed guard (#44585).
        #
        # An UNPINNED job (no explicit job["provider"]/["model"]) follows the
        # global default, which can change after the job was created — a switch
        # to a paid PROVIDER (e.g. nous) OR a paid MODEL on the same provider
        # (e.g. claude-fable-5 on openrouter). Without a guard the job would
        # silently inherit that change and spend real money on every tick — the
        # $7.73 incident named BOTH a provider and a model.
        #
        # create_job() snapshots whatever resolution would have picked at
        # creation for each unpinned axis (job["provider_snapshot"] /
        # job["model_snapshot"]). Here, for each axis that (a) has a snapshot and
        # (b) is unpinned and (c) currently resolves to a DIFFERENT value, we
        # fail closed: skip this run, make NO paid call, and deliver a loud,
        # actionable alert telling the user to pin the axis explicitly.
        #
        # Back-compat: an axis with no snapshot (pre-existing jobs, no_agent, or
        # any axis whose creation-time resolution failed) behaves exactly as
        # before — the guard never engages for it. Pinned axes are unaffected.
        _drift: list[str] = []
        _provider_snapshot = (job.get("provider_snapshot") or "").strip().lower()
        if _provider_snapshot and not (job.get("provider") or "").strip():
            _current_provider = str(runtime.get("provider") or "").strip().lower()
            if _current_provider and _current_provider != _provider_snapshot:
                _drift.append(
                    f"provider '{_provider_snapshot}' -> '{_current_provider}'"
                )
        _model_snapshot = (job.get("model_snapshot") or "").strip().lower()
        if _model_snapshot and not (job.get("model") or "").strip():
            _current_model = str(model or "").strip().lower()
            if _current_model and _current_model != _model_snapshot:
                _drift.append(
                    f"model '{_model_snapshot}' -> '{_current_model}'"
                )
        if _drift:
            _changes = "; ".join(_drift)
            logger.warning(
                "Job '%s': SKIPPED — global inference config drifted since "
                "creation (%s) and this job is unpinned. Skipped to prevent "
                "unintended spend. Pin explicitly to proceed: "
                "`cronjob action=update job_id=%s provider=<p> model=<m>`.",
                job_id,
                _changes,
                job_id,
            )
            raise RuntimeError(
                f"Skipped to prevent unintended spend: global inference config "
                f"drifted since this job was created ({_changes}), and this job "
                f"is unpinned. No inference call was made. To run on the new "
                f"config, pin it explicitly: `cronjob action=update "
                f"job_id={job_id} provider=<provider> model=<model>` "
                f"(or pin the original values to keep them). See #44585."
            )

        fallback_model = _cfg.get("fallback_providers") or _cfg.get("fallback_model") or None
        credential_pool = None
        runtime_provider = str(runtime.get("provider") or "").strip().lower()
        if runtime_provider:
            try:
                from agent.credential_pool import load_pool
                pool = load_pool(runtime_provider)
                if pool.has_credentials():
                    credential_pool = pool
                    logger.info(
                        "Job '%s': loaded credential pool for provider %s with %d entries",
                        job_id,
                        runtime_provider,
                        len(pool.entries()),
                    )
            except Exception as e:
                logger.debug("Job '%s': failed to load credential pool for %s: %s", job_id, runtime_provider, e)

        # Initialize MCP servers so configured mcp_servers are available to
        # the agent's tool registry before AIAgent is constructed. Without
        # this, cron jobs never saw any MCP tools — only the gateway / CLI
        # paths called discover_mcp_tools() at startup. Idempotent: subsequent
        # ticks short-circuit on already-connected servers inside
        # register_mcp_servers(). Non-fatal on failure: a broken MCP server
        # shouldn't kill an otherwise-working cron job. See #4219.
        try:
            from tools.mcp_tool import discover_mcp_tools
            _mcp_tools = discover_mcp_tools()
            if _mcp_tools:
                logger.info(
                    "Job '%s': %d MCP tool(s) available",
                    job_id, len(_mcp_tools),
                )
        except Exception as _mcp_exc:
            logger.warning(
                "Job '%s': MCP initialization failed (non-fatal): %s",
                job_id, _mcp_exc,
            )

        agent = AIAgent(
            model=model,
            api_key=runtime.get("api_key"),
            base_url=runtime.get("base_url"),
            provider=runtime.get("provider"),
            api_mode=runtime.get("api_mode"),
            acp_command=runtime.get("command"),
            acp_args=runtime.get("args"),
            max_iterations=max_iterations,
            reasoning_config=reasoning_config,
            prefill_messages=prefill_messages,
            fallback_model=fallback_model,
            credential_pool=credential_pool,
            providers_allowed=pr.get("only"),
            providers_ignored=pr.get("ignore"),
            providers_order=pr.get("order"),
            provider_sort=pr.get("sort"),
            openrouter_min_coding_score=(_cfg.get("openrouter") or {}).get("min_coding_score"),
            enabled_toolsets=_resolve_cron_enabled_toolsets(job, _cfg),
            disabled_toolsets=_resolve_cron_disabled_toolsets(_cfg),
            quiet_mode=True,
            # Cron jobs should always inherit the user's SOUL.md identity from
            # HERMES_HOME. When a workdir is configured, also inject project
            # context files (AGENTS.md / CLAUDE.md / .cursorrules) from there.
            # Without a workdir, keep cwd context discovery disabled.
            skip_context_files=not bool(_job_workdir),
            load_soul_identity=True,
            skip_memory=True,  # Cron system prompts would corrupt user representations
            platform="cron",
            session_id=_cron_session_id,
            session_db=_session_db,
        )
        
        # Run the agent with an *inactivity*-based timeout: the job can run
        # for hours if it's actively calling tools / receiving stream tokens,
        # but a hung API call or stuck tool with no activity for the configured
        # duration is caught and killed.  Default 600s (10 min inactivity);
        # override via HERMES_CRON_TIMEOUT env var.  0 = unlimited.
        #
        # Uses the agent's built-in activity tracker (updated by
        # _touch_activity() on every tool call, API call, and stream delta).
        _raw_cron_timeout = getenv_compat("CRON_TIMEOUT", "").strip()
        if _raw_cron_timeout:
            try:
                _cron_timeout = float(_raw_cron_timeout)
            except (ValueError, TypeError):
                logger.warning(
                    "Invalid HERMES_CRON_TIMEOUT=%r; using default 600s",
                    _raw_cron_timeout,
                )
                _cron_timeout = 600.0
        else:
            _cron_timeout = 600.0
        _cron_inactivity_limit = _cron_timeout if _cron_timeout > 0 else None
        _POLL_INTERVAL = 5.0
        _cron_pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        # Preserve scheduler-scoped ContextVar state (for example skill-declared
        # env passthrough registrations) when the cron run hops into the worker
        # thread used for inactivity timeout monitoring.
        _cron_context = contextvars.copy_context()
        _cron_future = _cron_pool.submit(_cron_context.run, agent.run_conversation, prompt)
        _inactivity_timeout = False
        try:
            if _cron_inactivity_limit is None:
                # Unlimited — just wait for the result.
                result = _cron_future.result()
            else:
                result = None
                while True:
                    done, _ = concurrent.futures.wait(
                        {_cron_future}, timeout=_POLL_INTERVAL,
                    )
                    if done:
                        result = _cron_future.result()
                        break
                    # Agent still running — check inactivity.
                    _idle_secs = 0.0
                    if hasattr(agent, "get_activity_summary"):
                        try:
                            _act = agent.get_activity_summary()
                            _idle_secs = _act.get("seconds_since_activity", 0.0)
                        except Exception:
                            pass
                    if _idle_secs >= _cron_inactivity_limit:
                        _inactivity_timeout = True
                        break
        except Exception:
            _cron_pool.shutdown(wait=False, cancel_futures=True)
            raise
        finally:
            _cron_pool.shutdown(wait=False, cancel_futures=True)

        if _inactivity_timeout:
            # Build diagnostic summary from the agent's activity tracker.
            _activity = {}
            if hasattr(agent, "get_activity_summary"):
                try:
                    _activity = agent.get_activity_summary()
                except Exception:
                    pass
            _last_desc = _activity.get("last_activity_desc", "unknown")
            _secs_ago = _activity.get("seconds_since_activity", 0)
            _cur_tool = _activity.get("current_tool")
            _iter_n = _activity.get("api_call_count", 0)
            _iter_max = _activity.get("max_iterations", 0)

            logger.error(
                "Job '%s' idle for %.0fs (inactivity limit %.0fs) "
                "| last_activity=%s | iteration=%s/%s | tool=%s",
                job_name, _secs_ago, _cron_inactivity_limit,
                _last_desc, _iter_n, _iter_max,
                _cur_tool or "none",
            )
            if hasattr(agent, "interrupt"):
                agent.interrupt("Cron job timed out (inactivity)")
            raise TimeoutError(
                f"Cron job '{job_name}' idle for "
                f"{int(_secs_ago)}s (limit {int(_cron_inactivity_limit)}s) "
                f"— last activity: {_last_desc}"
            )

        # Guard against non-dict returns from run_conversation under error conditions
        if not isinstance(result, dict):
            raise RuntimeError(
                f"agent.run_conversation returned {type(result).__name__} instead of dict: {result!r}"
            )

        # If the agent itself reported failure (e.g. all retries exhausted on
        # API errors, model abort, mid-run interrupt), do not silently mark the
        # job as successful. run_agent populates `failed=True`/`completed=False`
        # on these paths and may put the error into `final_response`, which
        # would otherwise be delivered as if it were the agent's reply and the
        # job's `last_status` set to "ok". Raise so the except handler below
        # builds the proper failure tuple. (issue #17855)
        turn_exit_reason = str(result.get("turn_exit_reason") or "")
        final_response_text = (result.get("final_response") or "").strip()
        max_iteration_summary = (
            result.get("failed") is not True
            and result.get("completed") is False
            and turn_exit_reason.startswith("max_iterations_reached(")
            and bool(final_response_text)
        )
        if result.get("failed") is True or (result.get("completed") is False and not max_iteration_summary):
            _err_text = (
                result.get("error")
                or final_response_text
                or "agent reported failure"
            )
            raise RuntimeError(_err_text)
        if max_iteration_summary:
            logger.warning(
                "Job '%s' reached the iteration limit but produced a final fallback response; "
                "delivering the response instead of failing the cron run",
                job_name,
            )

        final_response = result.get("final_response", "") or ""
        # Strip leaked placeholder text that upstream may inject on empty completions.
        if final_response.strip() == "(No response generated)":
            final_response = ""
        # Cron silence on abnormal empty turns.  The turn-completion explainer
        # (#34452) replaces a blank/empty model turn with a "⚠️ No reply: …"
        # string so interactive surfaces (CLI/gateway) explain why the box is
        # empty.  In a cron context that turns a previously-silent empty turn
        # into a delivered warning (Manfredi's Telegram symptom).  Detect the
        # explainer text deterministically (via the same formatter that
        # produced it) and treat it as empty so the empty-response suppression
        # and soft-failure marking below apply — restoring pre-#34452 silence
        # for scheduled jobs without disabling the explainer everywhere.
        if final_response.strip() and turn_exit_reason:
            try:
                _explainer_text = AIAgent._format_turn_completion_explanation(turn_exit_reason)
            except Exception:
                _explainer_text = ""
            if _explainer_text and final_response.strip() == _explainer_text.strip():
                logger.info(
                    "Job '%s': abnormal empty turn (%s) — suppressing explainer for cron delivery",
                    job_id,
                    turn_exit_reason,
                )
                final_response = ""
        # Use a separate variable for log display; keep final_response clean
        # for delivery logic (empty response = no delivery).
        logged_response = final_response if final_response else "(No response generated)"
        
        output = f"""# Cron Job: {job_name}

**Job ID:** {job_id}
**Run Time:** {_lliam_now().strftime('%Y-%m-%d %H:%M:%S')}
**Schedule:** {job.get('schedule_display', 'N/A')}

## Prompt

{prompt}

## Response

{logged_response}
"""
        
        logger.info("Job '%s' completed successfully", job_name)
        return True, output, final_response, None
        
    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        logger.exception("Job '%s' failed: %s", job_name, error_msg)
        
        output = f"""# Cron Job: {job_name} (FAILED)

**Job ID:** {job_id}
**Run Time:** {_lliam_now().strftime('%Y-%m-%d %H:%M:%S')}
**Schedule:** {job.get('schedule_display', 'N/A')}

## Prompt

{prompt}

## Error

```
{error_msg}
```
"""
        return False, output, "", error_msg

    finally:
        # Restore TERMINAL_CWD to whatever it was before this job ran.  We
        # only ever mutate it when the job has a workdir; see the setup block
        # at the top of run_job for the serialization guarantee.
        if _job_workdir:
            if _prior_terminal_cwd == "_UNSET_":
                os.environ.pop("TERMINAL_CWD", None)
            else:
                os.environ["TERMINAL_CWD"] = _prior_terminal_cwd
        # Clean up ContextVar session/delivery state for this job.
        reset_cron_session(_cron_marker_token)
        clear_session_vars(_ctx_tokens)
        for _var_name in _cron_delivery_vars:
            _VAR_MAP[_var_name].set("")
        if _session_db:
            # Title the cron session from the job (name → short prompt → id) so
            # sidebars/history show a meaningful label instead of the injected
            # "[IMPORTANT: …]" hint that is the session's first message. Set here
            # (not at create time) so the agent's own INSERT keeps model /
            # system_prompt; this only UPDATEs the title column. The run-time
            # suffix keeps it unique against the sessions.title index across runs.
            try:
                _title_base = " ".join(job_name.split())[:60].strip() or f"cron {job_id}"
                _cron_title = f"{_title_base} · {_lliam_now().strftime('%b %d %H:%M')}"
                _session_db.set_session_title(_cron_session_id, _cron_title)
            except (Exception, KeyboardInterrupt) as e:
                logger.debug("Job '%s': failed to set cron session title: %s", job_id, e)
            try:
                _session_db.end_session(_cron_session_id, "cron_complete")
            except (Exception, KeyboardInterrupt) as e:
                logger.debug("Job '%s': failed to end session: %s", job_id, e)
            try:
                _session_db.close()
            except (Exception, KeyboardInterrupt) as e:
                logger.debug("Job '%s': failed to close SQLite session store: %s", job_id, e)
        # Release subprocesses, terminal sandboxes, browser daemons, and the
        # main OpenAI/httpx client held by this ephemeral cron agent. Without
        # this, a gateway that ticks cron every N minutes leaks fds per job
        # until it hits EMFILE (#10200 / "too many open files").
        try:
            if agent is not None:
                agent.close()
        except (Exception, KeyboardInterrupt) as e:
            logger.debug("Job '%s': failed to close agent resources: %s", job_id, e)
        # Each cron run spins up a short-lived worker thread whose event loop
        # dies as soon as the ``ThreadPoolExecutor`` shuts down. Any async
        # httpx clients cached under that loop are now unusable — reap them
        # so their transports don't accumulate in the process-global cache.
        try:
            from agent.auxiliary_client import cleanup_stale_async_clients
            cleanup_stale_async_clients()
        except Exception as e:
            logger.debug("Job '%s': failed to reap stale auxiliary clients: %s", job_id, e)


def run_one_job(job: dict, *, verbose: bool = False) -> bool:
    """Run ONE due job end-to-end: execute → save output → mark.

    This is the shared firing body extracted from ``tick``'s per-job closure so
    that BOTH the built-in ticker and an external provider's ``fire_due`` (e.g.
    Chronos) run the identical sequence — no duplicated correctness.

    Output is delivered locally only: it is saved under the cron output
    directory (shown in the desktop Cron screen and ``cronjob action='list'``).
    There are no chat-platform delivery targets (JER-198).

    It does NOT decide whether the job is due, claim it, or compute the next
    run — those are the caller's concern (``tick`` advances ``next_run_at``
    under the file lock before dispatch; an external provider claims via the
    store CAS). This function only fires the given job once.

    Returns True if the job was processed (even if the job itself failed —
    failure is recorded via ``mark_job_run``), False only if processing raised.
    """
    try:
        success, output, final_response, error = run_job(job)

        output_file = save_job_output(job["id"], output)
        if verbose:
            logger.info("Output saved to: %s", output_file)

        # Treat empty final_response as a soft failure so last_status
        # is not "ok" — the agent ran but produced nothing useful.
        # (issue #8585)
        if success and not final_response.strip():
            success = False
            error = "Agent completed but produced empty response (model error, timeout, or misconfiguration)"

        mark_job_run(job["id"], success, error)
        return True

    except Exception as e:
        logger.error("Error processing job %s: %s", job['id'], e)
        mark_job_run(job["id"], False, str(e))
        return False


def _notify_provider_jobs_changed() -> None:
    """Best-effort: tell the active scheduler provider the job set changed.

    Called by the consumer surfaces (model tool / CLI / REST) AFTER a
    successful store mutation (create/update/remove/pause/resume) so an external
    provider (Chronos) can re-provision/cancel the affected one-shot via NAS.
    No-op for the built-in (it re-reads jobs.json each tick), so the default
    path is unchanged. Lives here (not in cron/jobs.py) to keep the store free
    of provider imports — avoids an import cycle and keeps jobs.py low-coupling.
    Never raises into the caller.
    """
    try:
        from cron.scheduler_provider import resolve_cron_scheduler
        resolve_cron_scheduler().on_jobs_changed()
    except Exception as e:
        logger.debug("on_jobs_changed notify failed: %s", e)


def tick(verbose: bool = True, sync: bool = True) -> int:
    """
    Check and run all due jobs.
    
    Uses a file lock so only one tick runs at a time, even if the desktop
    backend's in-process ticker and a manual tick overlap.
    
    Args:
        verbose: Whether to print status messages
    
    Returns:
        Number of jobs executed (0 if another tick is already running)
    """
    lock_dir, lock_file = _get_lock_paths()
    lock_dir.mkdir(parents=True, exist_ok=True)

    # Cross-platform file locking: fcntl on Unix, msvcrt on Windows
    lock_fd = None
    try:
        lock_fd = open(lock_file, "w", encoding="utf-8")
        if fcntl:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        elif msvcrt:
            msvcrt.locking(lock_fd.fileno(), msvcrt.LK_NBLCK, 1)
    except (OSError, IOError):
        logger.debug("Tick skipped — another instance holds the lock")
        if lock_fd is not None:
            lock_fd.close()
        return 0

    try:
        due_jobs = get_due_jobs()

        if verbose and not due_jobs:
            logger.info("%s - No jobs due", _lliam_now().strftime('%H:%M:%S'))
            return 0

        if verbose:
            logger.info("%s - %s job(s) due", _lliam_now().strftime('%H:%M:%S'), len(due_jobs))

        # Advance next_run_at for all recurring jobs FIRST, under the file lock,
        # before any execution begins.  This preserves at-most-once semantics.
        # For parallel jobs that are already running, advance_next_run keeps
        # bumping next_run_at forward so the grace window never expires.
        # mark_job_run() overwrites next_run_at on completion.
        for job in due_jobs:
            advance_next_run(job["id"])

        # Resolve max parallel workers: env var > config.yaml > unbounded.
        # Set HERMES_CRON_MAX_PARALLEL=1 to restore old serial behaviour.
        _max_workers: Optional[int] = None
        try:
            _env_par = getenv_compat("CRON_MAX_PARALLEL", "").strip()
            if _env_par:
                _max_workers = int(_env_par) or None
        except (ValueError, TypeError):
            logger.warning("Invalid HERMES_CRON_MAX_PARALLEL value; defaulting to unbounded")
        if _max_workers is None:
            try:
                _ucfg = load_config() or {}
                _cfg_par = (
                    _ucfg.get("cron", {}) if isinstance(_ucfg, dict) else {}
                ).get("max_parallel_jobs")
                if _cfg_par is not None:
                    _max_workers = int(_cfg_par) or None
            except Exception:
                pass

        if verbose:
            logger.info(
                "Running %d job(s) in parallel (max_workers=%s)",
                len(due_jobs),
                _max_workers if _max_workers else "unbounded",
            )

        def _process_job(job: dict) -> bool:
            """Run one due job end-to-end. Thin wrapper around the shared
            module-level ``run_one_job`` so ``tick`` and external providers
            (Chronos ``fire_due``) use the identical execute→save→deliver→mark
            body."""
            return run_one_job(job, verbose=verbose)

        # Partition due jobs: those with a per-job workdir mutate
        # os.environ["TERMINAL_CWD"] inside run_job, which is process-global —
        # so they MUST run sequentially to avoid corrupting each other.  Jobs
        # without a workdir leave env untouched and stay parallel-safe.
        sequential_jobs = [j for j in due_jobs if (j.get("workdir") or "").strip()]
        parallel_jobs = [j for j in due_jobs if not (j.get("workdir") or "").strip()]

        _results: list = []
        _all_futures: list = []

        def _submit_with_guard(job: dict, pool: concurrent.futures.ThreadPoolExecutor):
            """Submit a job fire-and-forget with the in-flight dedup guard.

            Returns the future, or None if the job was skipped because a prior
            tick's run of the same job is still in flight.  The running-set
            membership is released in the worker's finally block.
            """
            job_id = job["id"]
            with _running_lock:
                if job_id in _running_job_ids:
                    logger.info("Job '%s' already running — skipping", job.get("name", job_id))
                    return None
                _running_job_ids.add(job_id)
            _ctx = contextvars.copy_context()

            def _run_and_release(j=job, ctx=_ctx):
                try:
                    return ctx.run(_process_job, j)
                finally:
                    with _running_lock:
                        _running_job_ids.discard(j["id"])

            return pool.submit(_run_and_release)

        # Sequential pass for env-mutating (workdir) jobs.
        # Queued to a persistent single-thread pool so they run one at a time
        # WITHOUT blocking the ticker thread — a long workdir job no
        # longer starves the rest of the schedule (same fix as the parallel
        # pass, just serialized).  The in-flight guard prevents a still-running
        # job from being re-queued on the next tick.
        if sequential_jobs:
            seq_pool = _get_sequential_pool()
            for job in sequential_jobs:
                fut = _submit_with_guard(job, seq_pool)
                if fut is None:
                    continue
                _all_futures.append(fut)
                if not sync:
                    _results.append(True)  # optimistically counted

        # Parallel pass — persistent pool, non-blocking dispatch.
        # Jobs that are already running (from a previous tick) are skipped.
        # mark_job_run() updates next_run_at on completion, so the next tick
        # after completion finds the job due again naturally.  No catch-up
        # queue needed.
        if parallel_jobs:
            pool = _get_parallel_pool(_max_workers)
            for job in parallel_jobs:
                fut = _submit_with_guard(job, pool)
                if fut is None:
                    continue
                _all_futures.append(fut)
                if not sync:
                    _results.append(True)  # optimistically counted

        # Best-effort sweep of MCP stdio subprocesses that survived their
        # session teardown.  Must run AFTER jobs finish so active sessions
        # (including live user chats) are never touched — only PIDs explicitly
        # detected as orphans in tools.mcp_tool._run_stdio's finally block are
        # reaped.
        def _sweep_mcp_orphans() -> None:
            try:
                from tools.mcp_tool import _kill_orphaned_mcp_children
                _kill_orphaned_mcp_children()
            except Exception as _e:
                logger.debug("Post-tick MCP orphan cleanup failed: %s", _e)

        if sync:
            # Sync mode (tests / manual ticks): wait for all dispatched jobs,
            # collect results, then sweep once.
            for f in concurrent.futures.as_completed(_all_futures):
                try:
                    _results.append(f.result())
                except Exception as exc:
                    logger.error("Cron job future failed: %s", exc)
                    _results.append(False)
            _sweep_mcp_orphans()
            return sum(_results)

        # Async (gateway ticker) mode: don't block.  Sweep orphans via a
        # done-callback fired after the LAST dispatched job completes, so the
        # sweep still happens after jobs finish without stalling the tick.
        if _all_futures:
            _remaining = [len(_all_futures)]

            def _on_done(_f: concurrent.futures.Future) -> None:
                _remaining[0] -= 1
                try:
                    _exc = _f.exception()
                    if _exc is not None:
                        logger.error("Cron job future failed in async mode: %s", _exc, exc_info=(type(_exc), _exc, _exc.__traceback__))
                except Exception:
                    pass
                if _remaining[0] <= 0:
                    _sweep_mcp_orphans()

            for _f in _all_futures:
                _f.add_done_callback(_on_done)
        else:
            # Nothing dispatched (all skipped / no due jobs) — sweep inline.
            _sweep_mcp_orphans()

        return sum(_results)
    finally:
        if fcntl:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except (OSError, IOError):
                pass
        elif msvcrt:
            try:
                msvcrt.locking(lock_fd.fileno(), msvcrt.LK_UNLCK, 1)
            except (OSError, IOError):
                pass
        lock_fd.close()


if __name__ == "__main__":
    tick(verbose=True)
