# Lliam-GOV rebuild status (clean Hermes base + governance overlay)

**Base:** upstream `NousResearch/hermes-agent` **v2026.6.5** (`3c231eb`), imported clean.
The Electron desktop app (`apps/desktop`) ships in this base and runs on OpenAI out
of the box. Provider/subscription work and the Hermes→Lliam rebrand are deferred.

The governance overlay (`lliam_gov/security/`), its tests (`tests/lliam_gov/`), and the
compliance evidence (`evidence/`, `docs/governance/`) are carried forward verbatim and
re-wired into the clean base one guardrail at a time, each verified before commit.

## Wired + verified

| Guardrail | Control | Files | Verification |
|---|---|---|---|
| State encryption at rest (decrypt-on-read / encrypt-on-write) | SP 800-171 3.13.16 / 3.5.10 | `hermes_cli/auth.py`, `hermes_cli/main.py`, `agent/auxiliary_client.py`, `tools/managed_tool_gateway.py`, `tools/xai_http.py` | `test_state_codec`, `test_encrypted_file`, `test_auth_store_encryption` (30 pass) |
| Capability-tagged tool dispatch | SP 800-171 3.1.2 | `model_tools.py`, `tools/registry.py` | `test_capabilities` + dispatch regression |
| Self-modification approval gate | ISO 42001 A.6.2.4 | `model_tools.py` | `test_selfmod_gate` |
| CUI marking + chain of custody | SP 800-171 3.1; AI-223 | `model_tools.py` | `test_cui` |
| Tool-dispatch audit (always-on, append-only, fail-closed) | SP 800-171 3.3.x | `model_tools.py` | `test_audit_logger` + dispatch regression (70 pass total) |
| Egress allowlist + TLS (fail-closed) | SP 800-171 3.13.1/3.13.8; ISO 27001 A.8.20-23 | `agent/agent_init.py` | `test_egress` (full sweep 161 pass) |

Governance CLIs carried (not yet registered in dispatch): `hermes_cli/audit_cli.py`,
`hermes_cli/key_cli.py`, `hermes_cli/selfmod_cli.py`.

Full overlay sweep: **161/163 `tests/lliam_gov/` pass.** The 2 failures are the
principal-binding **production-root refusal** firing because the CI container runs as
uid 0 — the guardrail working as designed (SP 800-171 3.1.1); both pass for a normal
operator account.

## Remaining (mapped, not yet wired)

Each integration point below is identified by the fork's pre-scrap commit (`a1c7fc3`).

| Guardrail | Control | Files / sites | Risk |
|---|---|---|---|
| Session audit (session_open / turn_start / turn_end / failure) | SP 800-171 3.3.x | `agent/conversation_loop.py` (~L360 turn-start block, ~L4144 turn-end block; import L70-77), `run_agent.py` (~L2220 session_close on agent close) | High — deep weave into the conversation loop; needs a live turn to verify |
| Messaging-gateway narrowing + auth-deny audit | ISO 27001 A.8.x | `gateway/run.py` (~L6268), `gateway/platforms/slack.py` (~L81), `gateway/platforms/email.py` (~L458) | Medium — adapter deny-path audit; verify with `tests/gateway/test_adapter_inbound_auth_audit.py` |
| Backup CUI encryption at rest (fail-closed) | SP 800-171 3.8.9 | `hermes_cli/backup.py` (port `_backup_encryption_enabled`, `_backup_key_manager`, `encrypt_backup_archive`, `decrypt_backup_archive`, `_looks_like_encrypted_backup` + create/restore call sites) | Medium — feature port; verify with `tests/hermes_cli/test_backup_encryption.py` |
| Privileged-user ACL + AEP export + runtime/FIPS guard reachability | SP 800-171 3.3.9; LG-4.4 | register `audit`/`key`/`selfmod` governance CLIs in `hermes_cli/main.py` dispatch (privileged ACL lives in the carried CLIs) | Medium — verify with `tests/hermes_cli/test_key_cli.py`, `tests/lliam_gov/test_cli_exit_codes.py` |
| Dashboard/desktop gateway loopback-only (remove `--host`/`--insecure`) | ISO 27001 A.8.22 | `hermes_cli/web_server.py` | Low |

## Then (Phase 3–4)

- Reconcile `evidence/control-matrix.csv` `current_state` per control against the
  re-wired tree; re-capture `evidence/audit/*-test.txt` on a non-root operator host.
- Regenerate the CycloneDX SBOM; restore dependency-review and CI security gates.

## CI note

The repository's GitHub Actions are in a known outage (jobs fail in ~3 s, logs 404);
the fork has been merging under "governance override — Actions outage". Local
verification is used instead: `uv lock --check` clean, `ruff` clean on the overlay,
attribution/LICENSE present, and the overlay test suite green as above.
