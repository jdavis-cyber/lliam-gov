# Phase 1 — Post-Trim Test Noise Floor

**Date:** 2026-05-25
**Plan reference:** Hermes-to-Lliam ISO 42001 Plan, Rev. 3, §9 Phase 1 exit criterion ("test suite at baseline noise floor or better")
**Branch:** `phase1/facelift-and-trim`
**Commits covered:** `c9a4447`, `c610dab`, `14f54d7`, `1a77193`, plus the test-cleanup work in this commit
**Host:** Mac mini (darwin 25.5.0, Apple Silicon), Python 3.13.7 via uv-managed venv at `~/.venvs/lliam-gov`

## Result — exit criterion met

| Metric | Phase 0 baseline | Phase 1 post-trim | Delta |
|---|---:|---:|---:|
| Test files discovered | 1,197 | 1,152 | -45 |
| Tests collected | 26,225 | 24,246 | -1,979 |
| Tests passed | 25,942 | 23,998 | -1,944 |
| Tests failed | **37** | **37** | **0** |
| Files with ≥1 failure | **12** | **12** | **0** |
| Wall-clock | 389.1s | 360.7s | -28.4s |

**Failing file set is identical to Phase 0 baseline** (12/12 match by name and per-file failure count):

| File | Phase 0 fails | Phase 1 fails |
|---|---:|---:|
| `tests/agent/lsp/test_client_e2e.py` | 2 | 2 |
| `tests/acp/test_edit_approval.py` | 3 | 3 |
| `tests/agent/test_anthropic_adapter.py` | 5 | 5 |
| `tests/gateway/test_shutdown_forensics.py` | 1 | 1 |
| `tests/hermes_cli/test_gateway_wsl.py` | 2 | 2 |
| `tests/hermes_cli/test_gateway_service.py` | 6 | 6 |
| `tests/skills/test_openclaw_migration.py` | 1 | 1 |
| `tests/test_live_system_guard_self_test.py` | 4 | 4 |
| `tests/tools/test_cross_profile_guard.py` | 7 | 7 |
| `tests/tools/test_file_staleness.py` | 3 | 3 |
| `tests/tools/test_file_state_registry.py` | 2 | 2 |
| `tests/test_tui_gateway_server.py` | 1 | 1 |

Per plan §9 Phase 1 exit, this is "test suite at baseline noise floor."

## Test count attrition (expected)

Tests dropped from 26,225 → 24,246 because per plan §6.5 ("tests that depend on removed platforms are themselves removed (whole-test removal, not skipping)") the following 44 test files were deleted:

```
tests/gateway/test_api_server.py
tests/gateway/test_api_server_bind_guard.py
tests/gateway/test_api_server_jobs.py
tests/gateway/test_api_server_multimodal.py
tests/gateway/test_api_server_normalize.py
tests/gateway/test_api_server_runs.py
tests/gateway/test_api_server_toolset.py
tests/gateway/test_bluebubbles.py
tests/gateway/test_dingtalk.py
tests/gateway/test_feishu.py
tests/gateway/test_feishu_approval_buttons.py
tests/gateway/test_feishu_bot_admission.py
tests/gateway/test_feishu_comment.py
tests/gateway/test_feishu_comment_rules.py
tests/gateway/test_feishu_onboard.py
tests/gateway/test_homeassistant.py
tests/gateway/test_matrix.py
tests/gateway/test_matrix_exec_approval.py
tests/gateway/test_matrix_mention.py
tests/gateway/test_msgraph_webhook.py
tests/gateway/test_qqbot.py
tests/gateway/test_setup_feishu.py
tests/gateway/test_signal.py
tests/gateway/test_signal_format.py
tests/gateway/test_signal_rate_limit.py
tests/gateway/test_sms.py
tests/gateway/test_sse_agent_cancel.py
tests/gateway/test_webhook_adapter.py
tests/gateway/test_webhook_deliver_only.py
tests/gateway/test_webhook_dynamic_routes.py
tests/gateway/test_webhook_integration.py
tests/gateway/test_webhook_signature_rate_limit.py
tests/gateway/test_wecom.py
tests/gateway/test_wecom_callback.py
tests/gateway/test_weixin.py
tests/gateway/test_whatsapp_connect.py
tests/gateway/test_whatsapp_formatting.py
tests/gateway/test_whatsapp_group_gating.py
tests/gateway/test_whatsapp_reply_prefix.py
tests/gateway/platforms/test_yuanbao_recall_db_only.py
tests/test_yuanbao_integration.py
tests/test_yuanbao_markdown.py
tests/test_yuanbao_pipeline.py
tests/test_yuanbao_proto.py
tests/tools/test_signal_media.py
```

Plus three test files had platform-specific test classes excised in-place (Discord and Telegram classes preserved where present):

- `tests/gateway/test_text_batching.py`: removed `TestMatrixTextBatching`, `TestWeComTextBatching`, `TestFeishuAdaptiveDelay`. Kept `TestDiscordTextBatching` and `TestTelegramAdaptiveDelay`.
- `tests/gateway/test_ws_auth_retry.py`: removed `TestMatrixSyncAuthRetry`. Kept `TestMattermostWSAuthRetry`.
- `tests/gateway/test_weak_credential_guard.py`: removed `TestAPIServerPlaceholderKeyGuard`. Kept `TestPlatformTokenPlaceholderGuard`.
- `tests/gateway/test_stream_consumer_thread_routing.py`: removed `TestFeishuFallbackThreadRouting`. Kept `TestInitialReplyToId` and `TestOverflowFirstMessage`.
- `tests/gateway/test_platform_http_client_limits.py`: removed `TestWhatsappTypingLeakFix` and pruned the import-test to the retained adapters (Telegram, Slack).

## Tests updated for facelift-induced default changes

Five test files had assertions that hard-coded `~/.hermes` or `"hermes-agent[X]"` strings. Updated to expect `~/.lliam-gov` and `"lliam-gov[X]"`:

- `tests/test_hermes_constants.py` (1 assert)
- `tests/test_hermes_home_profile_warning.py` (5 asserts via replace_all)
- `tests/hermes_cli/test_apply_profile_override.py` (3 asserts via replace_all)
- `tests/hermes_cli/test_config.py` (1 assert)
- `tests/hermes_cli/test_kanban_core_functionality.py` (1 path)
- `tests/hermes_cli/test_gateway_service.py` (9 asserts via sed)
- `tests/test_termux_all_extra_compat.py` (3 asserts)
- `tests/tools/test_tirith_security.py` (1 assert)
- `tests/tools/test_windows_native_support.py` (parametrize pruned)

Also: `hermes_cli/gateway.py:_hermes_home_for_target_user` had two `Path.home() / ".hermes"` bypass-site literals that were among the ~20 sites flagged in `hermes_constants.py`'s docstring. Flipped to `.lliam-gov` because the systemd-unit generator must agree with the runtime default.

## Bonus: 0 new failures introduced

The 12-file failure set in Phase 1 is identical to Phase 0 by name and per-file count. The facelift + gateway trim + dashboard hardening introduced **zero new failures** beyond the upstream baseline noise floor. Test attrition is entirely from the planned platform-test removal.

## Phase 1 follow-ups deferred (tracked in commit messages)

1. **~20 `Path.home() / ".hermes"` bypass sites** still live across `mcp_serve.py`, `tools/mcp_oauth.py`, `hermes_cli/*`, `gateway/platforms/telegram.py`, `agent/secret_sources/bitwarden.py`, `agent/lsp/install.py`, several plugin adapters. Operators must set `HERMES_HOME=~/.lliam-gov` explicitly to avoid split-brain state directory until these are flipped. Plan §6.2 named "the HERMES_HOME / data-root constant" singular — strict reading is honored; flagged in `hermes_constants.py` docstring for follow-up.
2. **Dead `Platform` enum members** for removed platforms remain in `gateway/config.py` to avoid AttributeError fan-out across `tools/send_message_tool.py`, `gateway/session.py`, `gateway/config.py`, etc. Plan §6.5 underestimated this fan-out; the planned cleanup is its own commit.
