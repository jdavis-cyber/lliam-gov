# Lliam-GOV rebuild status (clean Hermes base + governance overlay)

**Base:** upstream `NousResearch/hermes-agent` **v2026.6.5** (`3c231eb`), imported clean.
The Electron desktop app (`apps/desktop`) ships in this base and runs on OpenAI out
of the box. Provider/subscription work and the Hermes→Lliam rebrand are deferred.

The governance overlay (`lliam_gov/security/`), its tests (`tests/lliam_gov/`), and the
compliance evidence (`evidence/`, `docs/governance/`) were carried forward verbatim and
re-wired into the clean base one guardrail at a time, each verified before commit.

## Wired + verified — all core guardrails

| Guardrail | Control | Verification |
|---|---|---|
| State encryption at rest (decrypt-on-read / encrypt-on-write) | SP 800-171 3.13.16 / 3.5.10 | state_codec / encrypted_file / auth_store_encryption tests |
| Capability-tagged tool dispatch | SP 800-171 3.1.2 | test_capabilities + dispatch regression |
| Self-modification approval gate | ISO 42001 A.6.2.4 | test_selfmod_gate |
| CUI marking + chain of custody | SP 800-171 3.1 | test_cui |
| Tool-dispatch audit (always-on, append-only, fail-closed) | SP 800-171 3.3.x | test_audit_logger + dispatch regression |
| Egress allowlist + TLS (fail-closed) | SP 800-171 3.13.1/3.13.8; ISO 27001 A.8.20-23 | test_egress |
| Governance CLIs + privileged-user ACL + AEP export + key rotation | SP 800-171 3.3.9; LG-3.8 | test_key_cli, test_cli_exit_codes, test_privileged_access, test_aep_export |
| Backup CUI encryption at rest (fail-closed) | SP 800-171 3.8.9 | test_backup_encryption (9) |
| Messaging-gateway narrowing + auth-deny audit | ISO 27001 A.8.15 | test_adapter_inbound_auth_audit, test_gateway_audit (17) |
| Session audit (open / turn-start / turn-end / close) | SP 800-171 3.3.x | upstream run_agent suite (379) + import smoke |
| Dashboard / desktop backend loopback-only | ISO 27001 A.8.22 | start_server host forced 127.0.0.1, auth gate engaged |
| Principal binding + production-root refusal | SP 800-171 3.1.1/3.1.2; ISO 27001 A.8.5 | test_principal (passes for operator; refuses root) |

Full overlay sweep: **`tests/lliam_gov/` 179/180 pass.** The 1 failure is the
production-root refusal firing because the CI container runs as uid 0 — the control
working as designed; it passes for a normal operator account.

## Notes / partial scope

- **Dashboard loopback (A.8.22):** enforced at the single `start_server` dispatch
  (`cmd_dashboard`), which forces `127.0.0.1` + auth gate regardless of `--host`/
  `--insecure`. The upstream flags still parse but are ignored; physically removing the
  argument definitions (and auditing other binders like `gateway`/`proxy`) is follow-up
  hardening, not required for the dashboard to be loopback-only.
- **Session audit turn-end:** an audit-write failure at turn end is logged (the turn has
  already completed); turn-start remains fail-closed (a turn that cannot be audited does
  not run).

## Phase 3 — compliance evidence (done, 2026-06-16)

- Re-ran the full overlay suite **as a non-root operator** (uid 1000): `tests/lliam_gov/`
  green, including the principal / production-root-refusal checks that fail under root.
  Captured in `evidence/audit/operator-suite-2026-06-16.txt`.
- Re-ran the adversarial harnesses as operator: **chaos** (audit/keyring/egress/self-mod
  all fail closed) and **pentest** (self-mod / path-traversal / audit-tamper / TLS-downgrade
  all refused). Fresh artifacts in `evidence/phase5/{chaos,pentest}/` (dated 2026-06-16).
- Reconciled `evidence/control-matrix.csv`: **42/55 controls** now carry implementation or
  evidence (34 `evidence_captured`, 5 `implemented`, 3 `tested`). The 13 remaining
  `not_implemented` are organization-owned AIMS clauses, operating-cadence controls, and
  FIPS-validated crypto (completes on a FIPS-OpenSSL host) — not overclaimed.
- Authored the ISO 42001 AIMS documented-information set
  (`docs/governance/aims/aims-documented-information.md`): objectives (A.6.1.2), RACI
  (A.3.2), impact assessment (A.5.2), data resources (A.7.4), documented-information index
  (Clause 7.5).

## Phase 4 — supply chain + CI gates (done, 2026-06-16)

- Regenerated the CycloneDX 1.6 SBOM from the rebuilt environment
  (`evidence/sbom/cyclonedx-2026-06-16.json`, 76 components).
- Ran `pip-audit` (`evidence/sbom/pip-audit-2026-06-16.json`): 17 advisories in 5 upstream-
  pinned packages, triaged with a remediation path in
  `evidence/sbom/dependency-review-2026-06-16.md` (not auto-bumped — `starlette` crosses
  minor versions touching the web server and needs live-dashboard validation).
- Added `.github/workflows/lliam-gov-governance.yml`: runs the overlay suite + chaos +
  pentest harnesses + attribution check on every PR/push (the CI control artifact;
  upstream osv-scanner / supply-chain-audit / lint gates are retained).
- Regenerated the release-evidence manifest (`evidence/release/manifest.json`): 8 present,
  5 PENDING (signing / checksums / QA — decision-gated, reported truthfully, never fabricated).

## Deferred by request

Provider/subscription work (Claude Code / Codex), Hermes→Lliam rebrand, and the
upstream dependency-bump (tracked in the dependency review). Organization-owned AIMS
management-system clauses (4/6/8/9/10) accrue operating evidence over the AIMS cycle.

## CI note

The repository's GitHub Actions are in a known outage (jobs fail in ~3 s, logs 404); the
fork has been merging under "governance override — Actions outage". Local verification is
used instead: `uv lock --check` clean, `ruff` clean on the overlay, attribution/LICENSE
present, and the overlay + upstream regression suites green as above.
