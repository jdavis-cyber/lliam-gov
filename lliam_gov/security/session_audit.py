"""Session and conversation audit helpers for Lliam-GOV."""

from __future__ import annotations

import os
from typing import Any

from lliam_gov.security.audit_logger import AuditLogger, AuditLoggerError


def audit_session_event(
    agent: Any,
    event_type: str,
    *,
    params: dict[str, Any] | None = None,
    duration_ms: int | None = None,
    error: str | None = None,
    blocked: bool = False,
    block_reason: str | None = None,
) -> None:
    """Append a session/conversation audit event or raise fail-closed."""

    logger = getattr(agent, "_lliam_audit_logger", None)
    if logger is None:
        logger = AuditLogger(
            session_id=getattr(agent, "session_id", None),
            principal=_principal(agent),
        )
        agent._lliam_audit_logger = logger

    logger.log_event(
        event_type=event_type,
        session_id=getattr(agent, "session_id", None),
        principal=_principal(agent),
        model_id=getattr(agent, "model", None) or None,
        params=params or {},
        duration_ms=duration_ms,
        blocked=blocked,
        block_reason=block_reason,
        error=error,
    )


def audit_failure_result(agent: Any, exc: AuditLoggerError) -> dict[str, Any]:
    """Return the standard fail-closed conversation result for audit failure."""

    message = f"Audit logging failed closed: {exc}"
    return {
        "final_response": message,
        "last_reasoning": None,
        "messages": [],
        "api_calls": 0,
        "completed": False,
        "turn_exit_reason": "audit_logging_failed_closed",
        "failed": True,
        "partial": False,
        "interrupted": False,
        "response_transformed": False,
        "response_previewed": False,
        "model": getattr(agent, "model", None),
        "provider": getattr(agent, "provider", None),
        "base_url": getattr(agent, "base_url", None),
        "input_tokens": getattr(agent, "session_input_tokens", 0),
        "output_tokens": getattr(agent, "session_output_tokens", 0),
        "cache_read_tokens": getattr(agent, "session_cache_read_tokens", 0),
        "cache_write_tokens": getattr(agent, "session_cache_write_tokens", 0),
        "reasoning_tokens": getattr(agent, "session_reasoning_tokens", 0),
        "prompt_tokens": getattr(agent, "session_prompt_tokens", 0),
        "completion_tokens": getattr(agent, "session_completion_tokens", 0),
        "total_tokens": getattr(agent, "session_total_tokens", 0),
        "last_prompt_tokens": 0,
        "estimated_cost_usd": getattr(agent, "session_estimated_cost_usd", 0.0),
        "cost_status": getattr(agent, "session_cost_status", None),
        "cost_source": getattr(agent, "session_cost_source", None),
        "session_id": getattr(agent, "session_id", None),
    }


def session_open_params(agent: Any) -> dict[str, Any]:
    return {
        "api_mode": getattr(agent, "api_mode", None),
        "platform": getattr(agent, "platform", None) or "",
        "provider": getattr(agent, "provider", None) or "",
        "tool_count": len(getattr(agent, "tools", None) or []),
    }


def turn_start_params(
    agent: Any,
    *,
    conversation_history: list[dict[str, Any]] | None,
    stream_callback: Any,
    task_id: str,
) -> dict[str, Any]:
    return {
        "has_stream_callback": stream_callback is not None,
        "history_count": len(conversation_history or []),
        "platform": getattr(agent, "platform", None) or "",
        "provider": getattr(agent, "provider", None) or "",
        "task_id": task_id,
    }


def turn_end_params(
    agent: Any,
    *,
    api_call_count: int,
    completed: bool,
    failed: bool,
    interrupted: bool,
    message_count: int,
    turn_exit_reason: str,
) -> dict[str, Any]:
    return {
        "api_calls": api_call_count,
        "completed": completed,
        "failed": failed,
        "interrupted": interrupted,
        "message_count": message_count,
        "platform": getattr(agent, "platform", None) or "",
        "provider": getattr(agent, "provider", None) or "",
        "turn_exit_reason": turn_exit_reason,
    }


def _principal(agent: Any) -> str:
    return (
        getattr(agent, "_user_id", None)
        or os.getenv("USER")
        or os.getenv("LOGNAME")
        or "unknown"
    )


__all__ = [
    "audit_failure_result",
    "audit_session_event",
    "session_open_params",
    "turn_end_params",
    "turn_start_params",
]
