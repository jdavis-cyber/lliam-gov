# Phase-3 Smoke-Run Runbook (LG-3.9 / AI-217)

**Purpose:** execute the 24-hour smoke run that is the **Phase-3 EXIT gate**
(completion plan §3/§4, AI-217 row): the agent operates continuously with
state encryption and audit logging enabled, survives a **live key rotation**,
and at the end the hash-chained audit log **verifies, AEP-exports, and
re-imports clean**. The captured artifacts under `evidence/phase3/smoke-<ts>/`
are the operating evidence that lets eligible control-matrix rows flip.

**Controls evidenced:** SP 800-171 3.3.1 / 3.3.2 / 3.3.8 (audit chain),
3.5.10 / 3.8.9 / 3.13.16 (credentials/CUI at rest, key management);
ISO/IEC 27001 A.8.15 / A.8.24; ISO/IEC 42001 Clause 9.1, A.4.3, A.6.2.8.

**Prerequisites (all met as of 2026-06-09):** AI-214, AI-215, AI-216 merged to
`main` (PRs #18–#21). Run on the **Mac mini dev host** — key material is
macOS-Keychain-anchored (`lliam_gov/security/key_manager.py`), so the run
cannot execute in CI or a cloud container.

---

## 0. Pre-flight (~15 minutes hands-on)

```bash
cd /Volumes/WORKSPACE/1-Projects/lliam-gov
git pull origin main
find . -name '._*' -type f ! -path './.git/*' -delete   # exFAT sidecars

export UV_PROJECT_ENVIRONMENT=/Users/just_jerome/.venvs/lliam-gov
uv run python scripts/run_tests_parallel.py
```

The full suite must stay within the Phase-2 noise floor
(`evidence/phase2/noise-floor-2026-05-26.md`: ⊆ 11 files / 36 fails, zero
collection errors). If it exceeds the floor, **stop** — do not smoke-test on a
regressed tree.

In Linear: move **AI-217** to *In Progress*.

## 1. Environment for the run

Set these in the shell that will run the agent **and** every
`phase3_smoke_evidence.py` command (they must see the same flags):

```bash
export UV_PROJECT_ENVIRONMENT=/Users/just_jerome/.venvs/lliam-gov
export LLIAM_GOV_ENCRYPT_STATE=1      # encrypt-on-write gate (state_codec.py)
export LLIAM_GOV_ALLOW_NON_FIPS=1     # dev override, sanctioned for smoke (plan D3)
```

`LLIAM_GOV_ALLOW_NON_FIPS=1` is the approved development-host deviation: FIPS
OpenSSL provisioning lands at the Phase-6 Katmai install (decision D3). The
override is recorded in the evidence environment snapshot, so the deviation is
documented, not silent.

Keep the Mac awake for the full window:

```bash
caffeinate -is &
```

## 2. `begin` — preflight + start snapshot

```bash
uv run python scripts/phase3_smoke_evidence.py begin
```

Creates `evidence/phase3/smoke-<timestamp>/` and captures:

- `00-environment.txt` — host, principal, git HEAD, env flags, FIPS-override note
- `01-managed-state-begin.txt` — at-rest posture of each managed state file
- `02-audit-begin.txt` — pre-run audit-chain verification + record baseline

`begin` refuses to start if `LLIAM_GOV_ENCRYPT_STATE` is not `1`, or if a
pre-existing audit chain fails verification.

**If `begin` reports a PLAINTEXT managed file, run `migrate` before starting
the agent.** This matters: `rotate-key` *skips* plaintext files (see
`rekey_files()` in `lliam_gov/security/encrypted_file.py`), so rotating over
a plaintext store would silently prove nothing:

```bash
uv run python scripts/phase3_smoke_evidence.py migrate
```

The first Keychain access pops a macOS authorization prompt — approve it
("Always Allow" for the run) before walking away, or the run stalls.

## 3. Start the agent and operate for 24 hours

Start `lliam-gov` in your normal operating mode (same shell, flags exported)
and use it as you ordinarily would. The evidence needs **real activity**, not
an idle process: the `finish` gate requires the audit-record count to have
grown over the run. Aim for several sessions spread across the window with
ordinary tool dispatches; no scripted load is required.

If no managed credential file exists yet (`begin` warns about this),
authenticate at least one provider early in the run so the at-rest evidence
is non-vacuous.

## 4. `rotate` — live mid-run key rotation (once, any time after a few hours)

```bash
uv run python scripts/phase3_smoke_evidence.py rotate
```

Runs `lliam-gov rotate-key` while the agent is live, then asserts the managed
state is encrypted under the new key, the audit chain still verifies, and the
`key_rotation` event landed in the chain (`03-rotate-key.txt`).

**Known accepted risk** (tripwire in `lliam_gov/security/state_codec.py`,
AI-216 decision 2026-05-31): with today's single-file managed set the crash
window between key rotation and re-encrypt is microseconds and accepted for
the single-operator profile. Do not add a second managed path without the
`rekey_files()` refactor described at the tripwire.

If `rotate` fails: **stop the run, preserve `~/.lliam-gov` and the run
directory as-is**, and investigate before anything else writes state.

## 5. `finish` — end-of-run verification (after ≥ 24 h)

```bash
uv run python scripts/phase3_smoke_evidence.py finish
```

Captures `04-audit-end.txt`, `05-aep-export.txt` (AEP export **and**
re-import verification), `06-managed-state-end.txt`, then writes `summary.md`
with the gate table and `MANIFEST.sha256` over the run directory. Gates:

| gate | meaning |
|---|---|
| `duration` | elapsed ≥ 24 h |
| `audit_chain_verifies` | every monthly JSONL hash chain verifies |
| `audit_activity` | record count grew during the run |
| `aep_export` / `aep_reimport_verifies` | AEP exports and re-imports clean |
| `state_encrypted_at_rest` | managed state present and encrypted, none plaintext |
| `live_key_rotation` | step 4 ran and succeeded |

A shorter window (`--min-hours N`) is possible but is recorded as a
**DEVIATION** in `summary.md` and must be justified in the AI-217 PR
description. Default to the full 24 hours.

## 6. Commit the evidence

```bash
git checkout -b claude/ai-217-phase3-smoke
find . -name '._*' -type f ! -path './.git/*' -delete
git add evidence/phase3/smoke-*/
git commit   # feat(phase3): commit 24h smoke evidence (AI-217, WBS LG-3.9)
```

In the same PR (and only with `summary.md` showing **OVERALL: PASS**), flip
the control-matrix `current_state` rows that this evidence proves — never
ahead of it (plan §5.7). Open the PR, move AI-217 to *In Review*, and report
at the phase boundary. AI-195 (Phase-3 parent) closes only after this PR
merges with all of 3.6–3.9 Done.

## Troubleshooting

- **`rotate-key refused: state encryption is disabled`** — the shell lost
  `LLIAM_GOV_ENCRYPT_STATE=1`; re-export and retry.
- **`rotate-key refused` with a FIPS message** — `LLIAM_GOV_ALLOW_NON_FIPS=1`
  is not set in this shell (dev hosts only; see §1).
- **Keychain prompt re-appears or hangs** — the venv binary changed identity
  (rebuilt env); approve again, or pre-authorize with "Always Allow".
- **Any chain/AEP verification failure** — treat as a real finding, not a
  flake: preserve the run directory and `~/.lliam-gov/audit/` untouched,
  file the failure on AI-217, and do not flip any matrix row.
- **Noise-floor breach in pre-flight** — fix or bisect first; the smoke run
  must start from a green-baseline tree.
