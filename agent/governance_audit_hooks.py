"""Dispatch-chokepoint wiring for the governance audit ledger (P1.2).

NEW ADDITIVE module (PATH-FREEZE honored): the glue between the existing
tool-dispatch seams and ``agent/governance_audit.py``. Realizes LG-AU-02
(single audit-generation chokepoint — no tool/skill/MCP executes
off-the-books), LG-AU-10 (unified accountability record: dashboard-auth
forward + operator subject binding), LG-MC-03 (write-origin/provenance
tagging) and LG-QT-03 (output traceable to model/provider/tool call).

Wiring points (all additive call sites — no dispatcher renamed):
  * ``agent/tool_executor.py`` — both dispatch paths call
    :func:`predispatch_gate` after the existing plugin/guardrail block
    evaluation and before execution. The gate emits ``tool.dispatch``;
    per LG-AU-09 a high-risk action whose record cannot be written gets a
    ``ToolGuardrailDecision``-style halt back and does not run.
  * ``model_tools._emit_post_tool_call_hook`` — the universal terminal-
    outcome funnel (success / error / blocked / cancelled, both dispatch
    paths, inline dispatch and ``handle_function_call``) calls
    :func:`record_outcome`.
  * ``lliam_cli/dashboard_auth/audit.py`` ``audit_log()`` — forwards each
    auth event into the chained ledger via :func:`forward_auth_event`
    (additive bridge; the auth log's never-block-auth semantics are
    preserved: the forward can never raise).

Operator subject (LG-AU-10): the authenticated principal lives at the
HTTP/ACP layer, not on the agent. :func:`set_operator_subject` exposes a
contextvar those layers stamp; records read it at emit time. The full
principal plumb through the gateway/ACP session lands with the operator-
authn step (P1.5 / AI-520); until then ``subject.principal`` is None for
locally-driven sessions, which is accurate.

Capability preservation: every function no-ops (cheaply) when the ledger
is disabled. The ONLY behavioral change is the intended LG-AU-09
guarantee at the dispatch gate, scoped to high-risk actions during an
audit-write outage.
"""

from __future__ import annotations

import contextvars
import logging
from types import SimpleNamespace
from typing import Any, Optional

_log = logging.getLogger(__name__)

_SOURCE_DISPATCH = "agent/tool_executor.py:predispatch"
_SOURCE_OUTCOME = "model_tools.py:_emit_post_tool_call_hook"
_SOURCE_AUTH_BRIDGE = "lliam_cli/dashboard_auth/audit.py:audit_log"

# ---------------------------------------------------------------------------
# Operator subject context (LG-AU-10)
# ---------------------------------------------------------------------------

_operator_subject: contextvars.ContextVar[Optional[dict]] = contextvars.ContextVar(
    "lliam_gov_operator_subject", default=None
)


def set_operator_subject(
    principal: Optional[str],
    *,
    auth: Optional[str] = None,
    delegation_path: Optional[list[str]] = None,
) -> None:
    """Bind the authenticated operator principal for subsequent records.

    Called by the auth/ACP layers once a principal is known for the
    active context (dashboard token auth, ACP session bind). Clearing:
    pass ``principal=None``.
    """
    if principal is None:
        _operator_subject.set(None)
        return
    subject: dict[str, Any] = {"principal": principal}
    if auth:
        subject["auth"] = auth
    if delegation_path:
        subject["delegation_path"] = list(delegation_path)
    _operator_subject.set(subject)


def _current_subject() -> dict:
    return _operator_subject.get() or {"principal": None}


# ---------------------------------------------------------------------------
# Risk classification (feeds the LG-AU-09 fail-closed scope)
# ---------------------------------------------------------------------------

# Known read-only / session-internal tools: no fail-closed gating — per the
# spec's bounded availability trade, idempotent reads proceed even during an
# audit-write outage (their failure degrades to a logged warning inside the
# ledger).
_READ_ONLY_TOOLS: frozenset[str] = frozenset({
    "read_file", "search_files", "session_search", "skills_list",
    "skill_view", "todo", "clarify", "read_terminal", "project_list",
    "browser_snapshot", "browser_console", "browser_get_images",
    "feishu_doc_read",
    "feishu_drive_list_comments", "feishu_drive_list_comment_replies",
})

_RISK_BY_TOOL: dict[str, frozenset[str]] = {
    "write_file": frozenset({"mutating"}),
    "patch": frozenset({"mutating"}),
    "terminal": frozenset({"mutating", "privileged"}),
    "process": frozenset({"mutating", "privileged"}),
    "execute_code": frozenset({"mutating", "privileged"}),
    "memory": frozenset({"mutating"}),
    "skill_manage": frozenset({"mutating"}),
    "project_create": frozenset({"mutating"}),
    "project_switch": frozenset({"mutating"}),
    "delegate_task": frozenset({"mutating", "privileged"}),
    "computer_use": frozenset({"mutating", "privileged", "high_impact"}),
    "text_to_speech": frozenset({"egress"}),
    # Vision/video analysis ships local media to an external provider — the
    # dispatch is external egress, not a read-only local op, so its record is
    # part of the fail-closed guarantee during an audit-write outage.
    "vision_analyze": frozenset({"egress"}),
    "video_analyze": frozenset({"egress"}),
    # Web search/extract (and X search) send the query or URL to an external
    # provider, so session content can leave in a search query. Classed as
    # egress (not the default "mutating") the PDP resolves them to
    # network.egress, and the injection-taint (LG-PI-06) and CUI-taint
    # (LG-DP-10) escalations apply to them exactly as to other egress.
    "web_search": frozenset({"egress"}),
    "web_extract": frozenset({"egress"}),
    "x_search": frozenset({"egress"}),
    # Media generation ships the prompt to an external provider.
    "image_generate": frozenset({"egress"}),
    "video_generate": frozenset({"egress"}),
    # Outbound messaging: content leaves the boundary and posts state.
    "discord": frozenset({"egress", "mutating"}),
    "discord_admin": frozenset({"egress", "mutating"}),
    "yb_send_dm": frozenset({"egress", "mutating"}),
    "yb_send_sticker": frozenset({"egress", "mutating"}),
    "feishu_drive_add_comment": frozenset({"egress", "mutating"}),
    "feishu_drive_reply_comment": frozenset({"egress", "mutating"}),
}

# Browser actions (navigate/click/type/...) drive egress + page mutation.
_BROWSER_ACTION_RISK = frozenset({"egress", "mutating"})

# Unknown tools — including every MCP tool — default to the conservative
# scope: an MCP tool can have arbitrary side effects, so its dispatch
# record is part of the fail-closed guarantee. Known read-only MCP tools
# can be tuned via the deviation register, never silently.
_DEFAULT_RISK = frozenset({"mutating"})


def classify_risk(function_name: str, function_args: Optional[dict] = None) -> frozenset[str]:
    """Map a tool invocation to its LG-AU-09 risk classes ({} = low-risk)."""
    name = function_name or ""
    if name in _READ_ONLY_TOOLS:
        return frozenset()
    if name in _RISK_BY_TOOL:
        return _RISK_BY_TOOL[name]
    if name.startswith("browser_"):
        return _BROWSER_ACTION_RISK
    return _DEFAULT_RISK


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _enabled_ledger():
    """The process ledger, or None — never raises (observer safety)."""
    try:
        from agent import governance_audit as ga
        return ga.get_ledger()
    except Exception:
        return None


def _actor_for_agent(agent) -> dict:
    """NPE actor with the real instance identity (LG-IA-02 / LG-QT-03).

    The identity binds code + resolved config/posture + resolved toolset +
    serving model into one ``instance_id`` (agent/agent_identity.py). Falls
    back to a provider/model-only stub if identity derivation is unavailable,
    so audit emission never breaks on identity.
    """
    try:
        from agent.agent_identity import compute_instance_identity
        return compute_instance_identity(agent)
    except Exception:
        actor: dict[str, Any] = {"type": "npe", "instance_id": None}
        try:
            provider = getattr(agent, "provider", None)
            model = getattr(agent, "model", None)
            if provider or model:
                actor["model"] = {"provider": provider, "model": model}
        except Exception:
            pass
        return actor


# Session -> NPE actor cache (LG-QT-03). Outcome and PDP-denial records are
# emitted without the agent in hand; they carry the instance identity last
# derived for their session (or correlation id) so every record of one
# operation names the same instance. Bounded LRU; refreshed on every
# dispatch, so a mid-session identity change shows up on the next record.
import threading as _threading  # noqa: E402  (kept beside its only user)
from collections import OrderedDict as _OrderedDict  # noqa: E402

_ACTOR_CACHE_MAX = 256
_session_actors: "_OrderedDict[str, dict]" = _OrderedDict()
_session_actors_lock = _threading.Lock()


def _remember_actor(keys, actor: dict, *, overwrite: bool = True) -> None:
    if not isinstance(actor, dict) or not actor.get("instance_id"):
        return
    with _session_actors_lock:
        for key in keys:
            if not key:
                continue
            if not overwrite and key in _session_actors:
                continue
            _session_actors[key] = actor
            _session_actors.move_to_end(key)
        while len(_session_actors) > _ACTOR_CACHE_MAX:
            _session_actors.popitem(last=False)


def _cached_actor(*, task_id: str = "", session_id: str = "") -> Optional[dict]:
    with _session_actors_lock:
        for key in (
            f"agent:{session_id}" if session_id else "",
            _correlation_id(task_id=task_id, session_id=session_id) or "",
        ):
            if key and key in _session_actors:
                _session_actors.move_to_end(key)
                return _session_actors[key]
    return None


def bind_session_actor(agent) -> None:
    """Cache ``agent``'s instance identity for its session. Never raises.

    Called at the executor's PDP seam so a call denied before it reaches
    :func:`predispatch_gate` still yields records that carry the instance id.
    Cheap after the first call per session (cache hit).
    """
    try:
        sid = getattr(agent, "session_id", "") or ""
        if not sid or _enabled_ledger() is None:
            return
        with _session_actors_lock:
            if f"agent:{sid}" in _session_actors:
                return
        _remember_actor([f"agent:{sid}"], _actor_for_agent(agent))
    except Exception:
        pass


def _record_actor(*, task_id: str = "", session_id: str = "") -> dict:
    """Actor for a record emitted without the agent (outcome / PDP denial)."""
    actor = _cached_actor(task_id=task_id, session_id=session_id)
    if actor is not None:
        return actor
    # No agent ever dispatched in this session (a direct caller of the
    # public dispatcher): derive the agent-less identity the dispatch record
    # of that path uses, and cache it under the correlation id.
    actor = _actor_for_agent(None)
    _remember_actor(
        [_correlation_id(task_id=task_id, session_id=session_id)], actor,
        overwrite=False,
    )
    return actor


def _dispatch_actor(agent, *, task_id: str = "") -> dict:
    """Instance identity for a dispatch record, cached for later records."""
    actor = _actor_for_agent(agent)
    sid = (getattr(agent, "session_id", "") or "") if agent is not None else ""
    keys = [_correlation_id(agent, task_id=task_id)]
    if sid:
        keys.append(f"agent:{sid}")
    # An agent-less identity (direct dispatcher callers) never replaces one
    # derived from a real agent under a shared correlation id.
    _remember_actor(keys, actor, overwrite=agent is not None)
    return actor


def _dispatch_resource(function_name: str, function_args: Optional[dict]) -> dict:
    """Resource block for ``tool.dispatch`` with a non-secret args digest.

    ``args_digest`` is a SHA-256 over the REDACTED, canonical arguments
    (prefix-truncated), so identical calls share a digest and distinct
    targets do not, without any secret entering the hash. LG-MO-01 keys its
    runaway-loop signature on it.
    """
    resource: dict[str, Any] = {"type": "tool", "name": function_name}
    try:
        import hashlib
        import json
        from agent import governance_audit as ga

        redacted = ga._redact_value(ga._jsonify(dict(function_args or {})))
        canon = json.dumps(
            redacted, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        resource["args_digest"] = (
            "sha256:" + hashlib.sha256(canon).hexdigest()[:32]
        )
    except Exception:
        pass
    return resource


def _trace_for(
    agent=None,
    *,
    tool_call_id: str = "",
    task_id: str = "",
    session_id: str = "",
    turn_id: str = "",
    api_request_id: str = "",
    middleware_trace: Optional[list] = None,
) -> dict:
    """Write-origin / provenance trace block (LG-MC-03, LG-AU-10)."""
    if agent is not None:
        session_id = session_id or (getattr(agent, "session_id", "") or "")
        turn_id = turn_id or (getattr(agent, "_current_turn_id", "") or "")
        api_request_id = api_request_id or (
            getattr(agent, "_current_api_request_id", "") or ""
        )
    trace: dict[str, Any] = {}
    for key, value in (
        ("tool_call_id", tool_call_id),
        ("task_id", task_id),
        ("session_id", session_id),
        ("turn_id", turn_id),
        ("api_request_id", api_request_id),
    ):
        if value:
            trace[key] = value
    if middleware_trace:
        # Names only — the middleware payloads themselves are not audit
        # content; the trace records WHICH request middleware touched the
        # args (write-origin provenance), not what they contained.
        try:
            names = [
                str(entry.get("name") or entry.get("middleware") or entry)
                for entry in middleware_trace
                if entry
            ]
            if names:
                trace["middleware"] = names[:16]
        except Exception:
            pass
    return trace


def _correlation_id(agent=None, *, task_id: str = "", session_id: str = "") -> Optional[str]:
    """One logical-operation trace id: task id, else session id (LG-AU-10)."""
    if task_id:
        return f"task-{task_id}"
    if agent is not None:
        sid = getattr(agent, "session_id", "") or ""
        if sid:
            return f"sess-{sid}"
    if session_id:
        return f"sess-{session_id}"
    return None  # ledger falls back to its process-level session id


def _killswitch_guard_failure(function_name: str, err: BaseException):
    """Blocking decision for a kill-switch guard that could not run."""
    message = ("Blocked (fail-closed): the kill-switch guard could not run "
               f"({type(err).__name__}); tool execution is denied (LG-IR-01).")
    try:
        from agent.tool_guardrails import ToolGuardrailDecision
        return ToolGuardrailDecision(action="halt", code="killswitch_guard_error",
                                     message=message, tool_name=function_name)
    except Exception:
        return SimpleNamespace(action="halt", code="killswitch_guard_error",
                               message=message, tool_name=function_name, count=0,
                               signature=None, allows_execution=False,
                               should_halt=True)


# ---------------------------------------------------------------------------
# 1. Pre-dispatch gate (LG-AU-02 + LG-AU-09) — called from tool_executor
# ---------------------------------------------------------------------------

def predispatch_gate(
    agent,
    *,
    function_name: str,
    function_args: dict,
    tool_call_id: str = "",
    effective_task_id: str = "",
    middleware_trace: Optional[list] = None,
):
    """Emit ``tool.dispatch`` for an about-to-execute tool call.

    Returns None when the action may proceed (record written, ledger
    disabled, or a low-risk record degraded to a warning). Returns a
    blocking ``ToolGuardrailDecision`` (action="halt") when a HIGH-RISK
    action's audit record could not be written — the caller must not
    execute it (LG-AU-09). Never raises.
    """
    # LG-IR-01 (additive @ P5.3): the kill-switch halts ALL tool execution
    # when engaged — checked before the audit/PDP path so a contained agent
    # cannot act even if the ledger is disabled. No-op unengaged; fail-CLOSED
    # when the check itself errors (JER-190): the call is denied.
    try:
        from agent import killswitch as _ks
        _halt = _ks.guard_tool_dispatch(function_name)
    except Exception as e:
        _log.error("kill-switch guard unavailable — denying %s (fail-closed): %s",
                   function_name, e)
        return _killswitch_guard_failure(function_name, e)
    if _halt is not None:
        return _halt

    ledger = _enabled_ledger()
    if ledger is None:
        return None
    risk = classify_risk(function_name, function_args)
    try:
        from agent import governance_audit as ga
        try:
            ledger.emit(
                "tool.dispatch",
                action=f"tool.{function_name}",
                parameters=dict(function_args or {}),
                risk_scope=set(risk),
                actor=_dispatch_actor(agent, task_id=effective_task_id),
                subject=_current_subject(),
                resource=_dispatch_resource(function_name, function_args),
                correlation_id=_correlation_id(agent, task_id=effective_task_id),
                trace=_trace_for(
                    agent,
                    tool_call_id=tool_call_id,
                    task_id=effective_task_id,
                    middleware_trace=middleware_trace,
                ),
                source_module=_SOURCE_DISPATCH,
            )
            return None
        except ga.AuditWriteError as e:
            from agent.tool_guardrails import ToolGuardrailDecision
            _log.error(
                "LG-AU-09 fail-closed: blocking %s — audit record could not "
                "be written", function_name,
            )
            return ToolGuardrailDecision(
                action="halt",
                code="audit_write_failure",
                message=(
                    "Blocked (fail-closed): this action's audit record could "
                    f"not be written and its risk scope {sorted(risk)} "
                    "requires a persisted record before execution "
                    f"(LG-AU-09). Underlying error: {e}"
                ),
                tool_name=function_name,
            )
    except Exception as e:
        # The gate itself must never break dispatch for reasons other than
        # the explicit fail-closed contract above.
        _log.warning("governance predispatch gate error (non-blocking): %s", e)
        return None


# ---------------------------------------------------------------------------
# 2. Terminal-outcome record (LG-AU-02) — called from model_tools funnel
# ---------------------------------------------------------------------------

_BLOCK_ERROR_TYPES = {"guardrail_block", "plugin_block", "tool_scope_block"}


def record_outcome(
    *,
    function_name: str,
    function_args: Optional[dict],
    status: Optional[str],
    error_type: Optional[str] = None,
    error_message: Optional[str] = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    turn_id: str = "",
    api_request_id: str = "",
    duration_ms: int = 0,
    middleware_trace: Optional[list] = None,
) -> None:
    """Record one terminal tool outcome. Post-facto: never gates, never raises.

    Blocked outcomes become ``policy.violation`` (the denial itself is
    auditable — LG-AU-07's "denial is itself audited" pattern generalized);
    everything else is ``tool.result``. Tool result CONTENT is not
    persisted — only status/class/redacted error (spec §3.1 outcome shape).
    """
    blocked = (status == "blocked") or (error_type in _BLOCK_ERROR_TYPES)
    # LG-IR-03 (JER-190): governance circuit-breaker — a run of consecutive
    # blocked calls in a session within a window trips the kill-switch. Fed
    # whether or not the ledger is on; off unless the gov overlay enables it.
    try:
        from agent import governance_breaker as _gb
        _gb.observe_outcome(blocked=blocked, session_id=session_id or "",
                            tool=function_name, detail=error_message or "")
    except Exception as e:
        _log.error("governance circuit-breaker feed failed: %s", e)

    ledger = _enabled_ledger()
    if ledger is None:
        return
    try:
        if blocked:
            event, decision, severity = "policy.violation", "deny", "warning"
            out_status = "blocked"
        elif status == "cancelled":
            event, decision, severity = "tool.result", "halt", "notice"
            out_status = "failure"
        elif status == "error" or error_type or error_message:
            event, decision, severity = "tool.result", "n/a", "notice"
            out_status = "failure"
        else:
            event, decision, severity = "tool.result", "n/a", "info"
            out_status = "success"
        outcome: dict[str, Any] = {"status": out_status, "class": error_type}
        if error_message:
            outcome["error"] = str(error_message)[:2000]
        ledger.emit(
            event,
            action=f"tool.{function_name}",
            decision=decision,
            severity=severity,
            parameters=dict(function_args or {}),
            outcome=outcome,
            actor=_record_actor(task_id=task_id, session_id=session_id),
            subject=_current_subject(),
            resource={"type": "tool", "name": function_name},
            correlation_id=_correlation_id(task_id=task_id, session_id=session_id),
            trace=_trace_for(
                tool_call_id=tool_call_id,
                task_id=task_id,
                session_id=session_id,
                turn_id=turn_id,
                api_request_id=api_request_id,
                middleware_trace=middleware_trace,
            ),
            source_module=_SOURCE_OUTCOME,
            # Post-facto record: the action already ran; a write failure
            # here must warn, not raise (risk_scope omitted on purpose).
        )
    except Exception as e:
        _log.warning("governance outcome record failed (non-blocking): %s", e)


def denial_record_context(
    *, task_id: str = "", session_id: str = "", tool_call_id: str = "",
) -> dict:
    """Correlation fields for a denial recorded off the outcome funnel.

    The tool-risk PDP records its own ``policy.violation``; this gives it the
    same correlation id, instance identity and trace as the terminal outcome
    record of the same call, so both land in ONE session (LG-AU-10) and the
    monitors can pair them into one alert. Never raises.
    """
    try:
        return {
            "actor": _record_actor(task_id=task_id, session_id=session_id),
            "subject": _current_subject(),
            "correlation_id": _correlation_id(
                task_id=task_id, session_id=session_id),
            "trace": _trace_for(
                tool_call_id=tool_call_id, task_id=task_id,
                session_id=session_id,
            ),
        }
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# 3. Dashboard-auth bridge (LG-AU-10) — called from dashboard_auth.audit_log
# ---------------------------------------------------------------------------

def forward_auth_event(event_value: str, entry: dict) -> None:
    """Forward one dashboard-auth event into the chained ledger.

    Additive bridge (spec §4.4): the auth log stays the auth-event writer;
    this cross-references the operator's authentication into the unified
    record as an ``agent.lifecycle`` subject-binding event sharing the
    correlation space. NEVER raises and never gates — auth must not fail
    because the governance ledger broke (the auth log's own contract).
    """
    ledger = _enabled_ledger()
    if ledger is None:
        return
    try:
        subject: dict[str, Any] = {"principal": None}
        for key in ("principal", "user", "username", "subject"):
            if entry.get(key):
                subject = {"principal": str(entry[key])}
                break
        session_ref = str(
            entry.get("session_id") or entry.get("sid") or ""
        )
        ledger.emit(
            "agent.lifecycle",
            action=f"dashboard_auth.{event_value}",
            decision="n/a",
            subject=subject,
            outcome={
                "status": "failure" if "failure" in event_value or "rejected" in event_value
                else "success",
                "class": event_value,
            },
            correlation_id=f"sess-{session_ref}" if session_ref else None,
            source_module=_SOURCE_AUTH_BRIDGE,
        )
    except Exception:
        # Deliberately silent beyond debug — never-block-auth, and the
        # auth event itself is already durably in dashboard-auth.log.
        _log.debug("dashboard-auth ledger forward failed", exc_info=True)
