# Lliam-GOV Control-Matrix Crosswalk (AI-226, WBS LG-5.2)

**Date:** 2026-06-12. Self-attestation-prep crosswalk: every row in
`evidence/control-matrix.csv` mapped to its implementation owner, test
coverage, and evidence artifact — or to a documented out-of-band owner
where the control is governance/operational rather than code.

**Coverage:** 55 rows — 32 implemented, 22 not_implemented, 1 scaffolded.

`current_state` is updated ONLY where committed code + tests + a real
evidence artifact prove the state (DoD: no aspirational flips). Rows that
remain `not_implemented` carry an objective owner and the reason they are
not yet evidenced (Phase 6 integration, Katmai-owned governance, ongoing
operation, or the FIPS POA&M).

## Implemented — code + test + evidence on `main`

| Control | Owner | Evidence | Test |
|---|---|---|---|
| SP800-171_3.1.1 | lliam_gov/security/principal.py + gateway allowl | evidence/audit/principal-binding-test.txt | tests/lliam_gov/test_principal |
| SP800-171_3.1.2 | lliam_gov/security/capabilities.py | evidence/audit/capability-dispatch-test.txt | tests/lliam_gov/test_capabilities |
| SP800-171_3.1.13 | lliam_gov/security/egress.py | evidence/audit/egress-policy-test.txt | tests/lliam_gov/test_egress |
| SP800-171_3.1.20 | lliam_gov/security/egress.py | evidence/audit/egress-policy-test.txt | tests/lliam_gov/test_egress |
| SP800-171_3.3.1 | lliam_gov/security/audit_logger.py | evidence/phase3/smoke-20260610T004426Z/04-audit-end. | (suite) |
| SP800-171_3.3.2 | lliam_gov/security/audit_logger.py (principal fi | evidence/phase3/smoke-20260610T004426Z/aep-export-20 | (suite) |
| SP800-171_3.3.4 | lliam_gov/security/audit_logger.py fail-closed b | evidence/phase3/smoke-20260610T004426Z/07-audit-fail | (suite) |
| SP800-171_3.3.8 | lliam_gov/security/audit_logger.py (mode 0600, h | evidence/phase3/smoke-20260610T004426Z/05-aep-export | (suite) |
| SP800-171_3.3.9 | lliam-gov audit / rotate-key CLI ACL | evidence/audit/privileged-acl-test.txt | (suite) |
| SP800-171_3.4.6 | gateway/platforms/{slack,email,telegram}.py (oth | evidence/phase1/noise-floor-2026-05-25.md | (suite) |
| SP800-171_3.5.10 | lliam_gov/security/key_manager.py (keyring-only  | evidence/phase3/smoke-20260610T004426Z/03-rotate-key | (suite) |
| SP800-171_3.8.9 | lliam_gov/security/key_manager.py (AES-256-GCM o | evidence/audit/backup-encryption-test.txt | (suite) |
| SP800-171_3.13.1 | lliam_gov/security/egress.py + gateway/platforms | evidence/audit/egress-policy-test.txt | tests/lliam_gov/test_egress |
| SP800-171_3.13.8 | lliam_gov/security/egress.py (TLS 1.2+, verify=T | evidence/audit/egress-policy-test.txt | tests/lliam_gov/test_egress |
| SP800-171_3.13.16 | lliam_gov/security/key_manager.py | evidence/phase3/smoke-20260610T004426Z/06-managed-st | (suite) |
| SP800-171_3.14.2 | evidence/sbom/ + hermes_cli/security_advisories. | evidence/sbom/cyclonedx-2026-06-12.json | tests/scripts/test_phase5_pentest |
| SP800-171_3.14.3 | evidence/sbom/ + hermes_cli/security_advisories. | evidence/sbom/dependency-bump-2026-06-12.md | tests/scripts/test_phase5_pentest |
| ISO42001_A.4.3 | lliam_gov/security/key_manager.py + lliam_gov/se | evidence/phase3/smoke-20260610T004426Z/06-managed-st | (suite) |
| ISO42001_A.6.2.4 | lliam_gov/security/selfmod_gate.py | evidence/audit/selfmod-gate-test.txt | tests/lliam_gov/test_selfmod_gate |
| ISO42001_A.6.2.6 | docs/operate/phase3-smoke-runbook.md + lliam_gov | evidence/audit/operation-monitoring-2026-06.md | (suite) |
| ISO42001_A.6.2.8 | lliam_gov/security/audit_logger.py | evidence/phase3/smoke-20260610T004426Z/02-audit-begi | (suite) |
| ISO27001_A.5.32 | NOTICE + LICENSE (MIT compliance) | NOTICE | (suite) |
| ISO27001_A.8.5 | lliam_gov/security/principal.py + gateway Bearer | evidence/audit/principal-binding-test.txt | tests/lliam_gov/test_principal |
| ISO27001_A.8.10 | lliam_gov/security/cui.py on-delete sanitization | evidence/audit/cui-custody-test.txt | tests/lliam_gov/test_cui |
| ISO27001_A.8.11 | lliam_gov/security/audit_logger.py params_hash p | evidence/phase3/smoke-20260610T004426Z/08-params-mas | (suite) |
| ISO27001_A.8.12 | lliam_gov/security/egress.py allowlist + lliam_g | evidence/audit/egress-policy-test.txt | tests/lliam_gov/test_egress |
| ISO27001_A.8.15 | lliam_gov/security/audit_logger.py | evidence/phase3/smoke-20260610T004426Z/04-audit-end. | (suite) |
| ISO27001_A.8.21 | lliam_gov/security/egress.py (TLS 1.2+, verify=T | evidence/audit/egress-policy-test.txt | tests/lliam_gov/test_egress |
| ISO27001_A.8.22 | hermes_cli/web_server.py + hermes_cli/main.py (l | evidence/audit/dashboard-bind-test.txt | (suite) |
| ISO27001_A.8.23 | lliam_gov/security/egress.py allowlist | evidence/audit/egress-policy-test.txt | tests/lliam_gov/test_egress |
| ISO27001_A.8.24 | lliam_gov/security/key_manager.py + lliam_gov/se | evidence/phase3/smoke-20260610T004426Z/06-managed-st | (suite) |
| ISO27001_A.8.30 | Hermes upstream lineage | NOTICE | (suite) |

## Not-implemented — objective owner + reason

| Control | Owner / location | Reason not yet evidenced |
|---|---|---|
| SP800-171_3.13.11 | lliam_gov/security/runtime_guard.py (FIPS-OpenSSL  | FIPS-validated crypto — **POA&M (AI-282)**, blocked on external FIPS-OpenSSL module availability |
| ISO42001_A.3.2 | lliam_gov/security/principal.py + AIMS RACI | Katmai-owned governance / out-of-band (AIMS program, not Lliam code) |
| ISO42001_A.5.2 | lliam_gov/security/selfmod_gate.py + docs/governan | Governance/operator documentation — authored or pending Phase 6 program integration |
| ISO42001_A.6.1.2 | docs/governance/control-matrix.md + plan §1 | Governance/operator documentation — authored or pending Phase 6 program integration |
| ISO42001_A.7.4 | lliam_gov/security/audit_logger.py + evidence/sbom | Recurring SCA/advisory cadence — evidenced per quarterly cycle (Phase 6 operation) |
| ISO42001_Clause_4 | AIMS scope (Katmai-owned) | Katmai-owned governance / out-of-band (AIMS program, not Lliam code) |
| ISO42001_Clause_6 | Hardening overlay design | AIMS management-system clause — ongoing operation, evidenced at the program level (Phase 6, AI-230/231) |
| ISO42001_Clause_7.5 | lliam_gov/security/audit_logger.py + this matrix + | AIMS management-system clause — ongoing operation, evidenced at the program level (Phase 6, AI-230/231) |
| ISO42001_Clause_8 | Hardening overlay live operation | AIMS management-system clause — ongoing operation, evidenced at the program level (Phase 6, AI-230/231) |
| ISO42001_Clause_9.1 | evidence/sbom/ + hermes_cli/security_advisories.py | AIMS management-system clause — ongoing operation, evidenced at the program level (Phase 6, AI-230/231) |
| ISO42001_Clause_10 | Quarterly improvement cycle | AIMS management-system clause — ongoing operation, evidenced at the program level (Phase 6, AI-230/231) |
| ISO27001_A.5.7 | evidence/sbom/ + hermes_cli/security_advisories.py | Recurring SCA/advisory cadence — evidenced per quarterly cycle (Phase 6 operation) |
| ISO27001_A.5.20 | evidence/sbom/ + hermes_cli/security_advisories.py | Recurring SCA/advisory cadence — evidenced per quarterly cycle (Phase 6 operation) |
| ISO27001_A.5.21 | evidence/sbom/ + hermes_cli/security_advisories.py | Recurring SCA/advisory cadence — evidenced per quarterly cycle (Phase 6 operation) |
| ISO27001_A.5.22 | Quarterly Hermes CHANGELOG review | Recurring SCA/advisory cadence — evidenced per quarterly cycle (Phase 6 operation) |
| ISO27001_A.5.23 | Operator runbook (model-endpoint posture) | Governance/operator documentation — authored or pending Phase 6 program integration |
| ISO27001_A.5.31 | GOVERNANCE_ONLY (Jerome as AIMS PM; Jack as author | Katmai-owned governance / out-of-band (AIMS program, not Lliam code) |
| ISO27001_A.6.3 | docs/operate/* operator runbook | Governance/operator documentation — authored or pending Phase 6 program integration |
| ISO27001_A.8.6 | lliam_gov/security/audit_logger.py monthly rotatio | Phase 6 program integration (AI-230..234) or ongoing-operation evidence |
| ISO27001_A.8.8 | evidence/sbom/ + hermes_cli/security_advisories.py | Recurring SCA/advisory cadence — evidenced per quarterly cycle (Phase 6 operation) |
| ISO27001_A.8.16 | lliam_gov/security/audit_logger.py review cadence | Phase 6 program integration (AI-230..234) or ongoing-operation evidence |
| ISO27001_A.8.28 | Hermes upstream practice + PR review | Phase 6 program integration (AI-230..234) or ongoing-operation evidence |

## Scaffolded

- **ISO27001_A.8.20** — lliam_gov/security/egress.py + gateway/platforms/{slack,email,telegram}.py (othe (partial; completion tracked for Phase 6).

## Attestation note

32 of 55 rows are implemented with objective code+test+evidence on `main`.
The remaining 23 are: 1 FIPS POA&M (AI-282), Katmai-owned AIMS governance
controls, recurring-operation clauses evidenced per cycle, and Phase 6
program-integration items (AI-230..234). No implemented row has a dead
evidence pointer (verified 2026-06-12).