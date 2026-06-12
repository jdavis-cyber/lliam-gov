# Lliam-GOV — Operator Runbooks (LG-4.7 / AI-224)

**Review cadence:** each phase gate. Runbook drift (a procedure that no longer
matches the code) is a finding — log it as a Linear issue and fix the runbook
in the same PR as the behavior change.

These runbooks cover the Phase 3/4 control surface. The Phase 3 smoke
procedure lives separately in `phase3-smoke-runbook.md`; the production
environment itself in `production-profile.md`.

---

## RB-1 — Install + FIPS provisioning

1. Clone to the production host; create the home: `mkdir -m 700 ~/.lliam-gov`.
2. Apply `production.env.example` to the launch environment (`HERMES_HOME` explicit).
3. **FIPS:** provision a FIPS-validated OpenSSL and a `cryptography` build
   linked against it. Until the FIPS module path is resolved (POA&M AI-282),
   production startup will fail closed at the FIPS probe — that is correct
   behavior, not a bug. Do NOT set `LLIAM_GOV_ALLOW_NON_FIPS` on this host.
4. First start runs `production_posture_check()`; resolve each failure in the
   order printed (principal → FIPS → encrypt-state → workspace → umask → Keychain).
5. Verify: `lliam-gov audit verify-jsonl --input ~/.lliam-gov/audit/<current-month>.jsonl`.

## RB-2 — Audit export (monthly + on demand)

1. Verify the chain first: `lliam-gov audit verify-jsonl --input <chain.jsonl>`.
2. Export: `lliam-gov audit export-aep --input <chain.jsonl> --output evidence/aep-<YYYY-MM>.json`.
3. Re-import check: `lliam-gov audit verify-aep --input evidence/aep-<YYYY-MM>.json`.
4. Commit the AEP under `evidence/`; never commit raw chains containing live
   session ids unless reviewed. AEP exports carry `params_hash` only — no raw
   payloads, secrets, or CUI.
5. All three commands require the privileged operator (home owner, 3.3.9).

## RB-3 — Key rotation

1. `lliam-gov rotate-key` (privileged; requires `LLIAM_GOV_ENCRYPT_STATE=1` + FIPS gate).
2. **Immediately take a fresh backup** (`hermes backup`) — encrypted backups
   are bound to the current key; pre-rotation `.zip.enc` archives are
   unrecoverable by design.
3. Confirm the `key_rotation` event landed: verify the current month's chain.

## RB-4 — CUI marking

1. Mark a zone: `python -c "from lliam_gov.security.cui import mark_path; mark_path('/path/to/cui-zone', 'CUI//SP-PRIV')"`.
2. From then on, tool dispatch touching that zone emits `cui_access` custody
   events (marker + destination + params_hash) automatically.
3. Sanitized delete: `sanitize_delete(path)` — best-effort overwrite + audited
   `cui_delete`. On APFS the encryption-at-rest posture is the real backstop.
4. **Policy reminder:** CUI status never blocks routing (§5.6 decision).
   Network denial is the egress allowlist's job (RB-5).

## RB-5 — Egress allowlist management

1. Allowlist lives at `$HERMES_HOME/egress-allowlist.txt` — one `host`,
   `host:port`, or `*.suffix` per line; `#` comments. Bare host = port 443.
2. Adding an endpoint is a change-controlled act: PR the allowlist change
   with a one-line justification per entry.
3. Misconfiguration is fail-closed: an empty/missing file under enforcement
   denies all non-loopback egress. If the agent suddenly cannot reach its
   model provider, check the allowlist FIRST.
4. Denials are in the chain as `egress_denied` (host:port in `block_reason`).
   Review monthly during RB-2 for exfiltration attempts and broken configs.

## RB-6 — Self-modification approvals (daily review path)

1. `lliam-gov proposals` — list pending staged self-modifications.
2. Review the payload in `$HERMES_HOME/selfmod/proposals/<id>.json`.
3. Decide: `lliam-gov approve <id> --note "<reasoning>"` or
   `lliam-gov reject <id> --note "<reasoning>"`. The note is mandatory
   evidence (ISO 42001 A.6.2.4); decisions are principal-attributed and
   chain-audited.
4. Approval surfaces the payload but NEVER self-applies — apply consciously,
   then re-run the relevant verification (tests, smoke).
5. Cadence: check pending proposals at least daily when the gate is active.

## RB-7 — Incident / fail-closed handling

Lliam-GOV controls fail closed by design. When the system refuses to operate:

| Symptom | Likely control | First response |
|---|---|---|
| `ProductionRootRefused` | LG-4.1 | Run as the operator account; never sudo the agent. |
| `FipsNotAvailable` | LG-3.1 | FIPS provisioning regressed (RB-1.3). Do not set the dev override on production. |
| `WorkspaceNotHardened` / `UmaskTooPermissive` | LG-4.4 | `chmod 700 $HERMES_HOME`; investigate what loosened it — that's the incident. |
| `KeychainUnavailable` | LG-4.4 | Unlock/repair Keychain. Protected ops stay down until the probe passes. |
| `Audit logging failed closed` | LG-3.4 / 3.3.4 | Disk/permissions on `$HERMES_HOME/audit/`. The halt IS the alert — do not bypass; fix the chain, then verify it before resuming. |
| `EgressDenied` storm | LG-4.3 | Either allowlist misconfig (fix file) or actual exfiltration attempt (preserve the chain, investigate the session). |
| Staged proposals appearing unexpectedly | LG-4.5 | The agent attempted self-modification. Review before approving anything; reject by default. |

**Evidence preservation:** before any remediation that touches
`$HERMES_HOME`, copy the current month's audit chain and run RB-2. Incidents
without a preserved chain are findings against the process, not just the system.
