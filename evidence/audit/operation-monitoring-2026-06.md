# Lliam-GOV — AI System Operation & Monitoring (ISO/IEC 42001 A.6.2.6)

**Document date:** 2026-06-11 (AI-281, WBS LG-3.9 held-back control)
**System:** Lliam-GOV — governance-grade agent runtime (Hermes fork), single-operator profile
**Operator / owner:** Jerome Davis (Lliam home owner account, per SP 800-171 3.3.9 ACL)
**Review cadence for this document:** each phase gate, and at any change to the monitoring stack

ISO/IEC 42001 A.6.2.6 requires the organization to define and document the
necessary elements for the ongoing operation of the AI system, at minimum
system and performance monitoring, repairs, updates, and support.

## 1. Ongoing operation

| Element | Mechanism |
|---|---|
| Runtime profile | macOS dev/prod host; production requires FIPS backend (`runtime_guard.fips_check`, fail-closed) and `LLIAM_GOV_ENCRYPT_STATE=1`. Dev opt-out only via `LLIAM_GOV_ALLOW_NON_FIPS=1` (plan decision D3). |
| Entry points | Slack, email, Telegram gateways + local CLI/TUI only (LG-1.3 surface trim); dashboard is loopback-only with break-glass flags physically removed (LG-1.4). |
| Privileged operations | Audit and key management CLIs limited to the home-owner account (`lliam_gov/security/privileged_access.py`, SP 800-171 3.3.9). |
| Updates | `hermes update` snapshots critical state before pulling (quick snapshot set); dependency updates land via Dependabot PRs gated by CI. |
| Backups / repair | `lliam-gov backup` (encrypted at rest under the production profile, SP 800-171 3.8.9); restore via `lliam-gov import`. Fresh backup REQUIRED after every `rotate-key` (pre-rotation encrypted backups are unrecoverable by design). |

## 2. System monitoring

- **Tamper-evident audit chain** (`lliam_gov/security/audit_logger.py`): hash-chained JSONL with monthly rotation records, at minimum: `session_open`/`session_close`, conversation-loop events, tool dispatch (fail-closed wrapper), gateway inbound auth decisions, `key_rotation`, with deterministic `params_hash` and sensitive-value masking (ISO 27001 A.8.11).
- **Fail-closed operation** (SP 800-171 3.3.4): if the audit file cannot be opened or written, the instrumented operation refuses to proceed — an audit-logging failure halts the action rather than running unevidenced. This is the alerting mechanism for audit failure: the system stops and the error surfaces to the operator at the point of use.
- **Chain verification:** `lliam-gov audit verify-jsonl --input <chain>` detects truncation, reordering, and tampering (InvalidTag / chain-break). Portable evidence via `lliam-gov audit export-aep` and `verify-aep` round-trip.

## 3. Performance monitoring

- **Test noise floor:** baseline documented at `evidence/phase2/noise-floor-2026-05-26.md`; CI runs the sharded suite on every PR (blocking ruff, type-diff, e2e, 6 test shards).
- **Operating evidence:** 24-hour smoke runs per `docs/operate/phase3-smoke-runbook.md` capture environment, chain growth, rotation, AEP round-trip, and encryption-at-rest posture under `evidence/phase3/smoke-*/` with SHA-256 manifests.

## 4. Review cadence

| Activity | Cadence | Record |
|---|---|---|
| Audit-chain verification (`verify-jsonl`) | Monthly, and before any matrix flip | Command output committed under `evidence/audit/` |
| AEP export of the prior month's chain | Monthly | `evidence/` AEP JSON |
| Control-matrix review (`evidence/control-matrix.csv`) | Each phase gate / release | PR review trail |
| Dependency review (Dependabot + OSV scan) | Per PR (automated) | CI logs |
| This document | Each phase gate | Git history |

## 5. Support and escalation

Single-operator profile: the operator is the support path. Failures surface
fail-closed at the CLI/runtime with actionable messages (FIPS gate, encrypt-state
gate, privileged-ACL denial, audit-chain failure). Unresolvable failures are
tracked as Linear issues in the Lliam-GOV Build project and, where they affect
control posture, as control-matrix state reversions (flip-back discipline per
the Phase-3 smoke runbook §5.7).
