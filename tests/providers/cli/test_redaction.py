"""Tests for credential/secret redaction on the provider boundary (AI-334)."""

from __future__ import annotations

from providers.cli.redaction import (
    REDACTION_MARKER,
    redact_secrets,
    redacted_snippet,
)


def test_redacts_none_and_empty():
    assert redact_secrets(None) == ""
    assert redact_secrets("") == ""


def test_redacts_api_key_assignment():
    out = redact_secrets("ANTHROPIC_API_KEY=sk-ant-abcdef123456 next")
    assert "sk-ant-abcdef123456" not in out
    assert REDACTION_MARKER in out
    # The variable name is preserved so the log still says *what* was scrubbed.
    assert "ANTHROPIC_API_KEY" in out
    assert "next" in out


def test_redacts_bearer_header():
    out = redact_secrets("Authorization: Bearer abcDEF1234567890token")
    assert "abcDEF1234567890token" not in out
    assert REDACTION_MARKER in out


def test_redacts_openai_and_anthropic_prefixes():
    assert "sk-ant-" not in redact_secrets("leak sk-ant-0123456789abcdef trailing").replace(
        REDACTION_MARKER, ""
    )
    out = redact_secrets("token sk-ABCDEFGHIJKLMNOP0123 end")
    assert "sk-ABCDEFGHIJKLMNOP0123" not in out


def test_redacts_github_slack_aws_jwt():
    samples = [
        "ghp_0123456789abcdefghijABCDEFGHIJ012345",
        "xoxb-1111111111-2222222222-aaaaaaaaaaaa",
        "AKIAIOSFODNN7EXAMPLE",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123456",
    ]
    for s in samples:
        out = redact_secrets(f"value {s} here")
        assert s not in out, s
        assert REDACTION_MARKER in out


def test_does_not_overredact_plain_text():
    text = "Provider exited 3. Could not connect to host example.com on port 443."
    assert redact_secrets(text) == text


def test_idempotent():
    once = redact_secrets("password=hunter2supersecret")
    twice = redact_secrets(once)
    assert once == twice


def test_redacted_snippet_truncates():
    long = "TOKEN=" + ("a" * 500)
    snip = redacted_snippet(long, limit=40)
    assert len(snip) <= 40 + len("…[truncated]")
    assert "aaaa" not in snip or snip.endswith("…[truncated]")
    assert REDACTION_MARKER in snip
