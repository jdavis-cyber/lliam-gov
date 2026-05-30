# Lliam-GOV — End-to-End Build Completion Plan

**Prepared for:** Jerome Davis
**Prepared by:** Claude (Opus 4.8 · 1M · Max Effort), Claude Code session
**Date:** 2026-05-30
**Repo:** `jdavis-cyber/lliam-gov` · local `/Volumes/WORKSPACE/1-Projects/lliam-gov`
**Linear project:** Lliam-GOV Build (`60a51de4-6ae1-4406-9e3d-3ce2d86cc1f5`) · team AI Program Management
**Canonical plan of record:** *Hermes-to-Lliam ISO 42001 Plan — Comprehensive Edition, Revision 3* (2026-05-25), `/Volumes/WORKSPACE/0-Orientation/Hermes-to-Lliam-ISO42001-Plan-COMPREHENSIVE-v3-2026-05-25.docx`
**Status:** ✅ **APPROVED — Jerome, 2026-05-30.** All §7 decisions accepted per recommendation **except** pen-test (AI-228) and the Katmai IT review, which **WAIT for Jerome's explicit go and gate no build work** (see §7). D2 held: Linear team estimation is disabled. Build execution by this Claude Code (Opus 4.8) session, Phase 4+; Phase-3 finish begins on confirm.

---

## 0. Repo identity & the parallel-effort framing (read first)

This session was spawned in `/Volumes/WORKSPACE/1-Projects/lliam_ai_agent` — **not** the build repo. Per Rev. 3 plan §7 and Open Brain continuity (2026-05-25/26), `lliam_ai_agent` is **Lliam-OPS**, the Node/TypeScript agent. The build in question is **Lliam-GOV**, a separate Python fork of Hermes Agent v0.14.0 at the sibling path `/Volumes/WORKSPACE/1-Projects/lliam-gov` (GitHub `jdavis-cyber/lliam-gov`). The Linear issues AI-192…AI-235 and the `codex/ai-2*` branches all belong to Lliam-GOV. **All of this plan targets `lliam-gov`.**

**Parallel-effort framing (Jerome, 2026-05-30):** Lliam-GOV is a **parallel candidate-replacement**, not yet the designated AIMS target. **Lliam-OPS (`lliam_ai_agent`) remains the original/current AIMS target** for ISO 42001 evidence. If Lliam-GOV proves out, Jerome will **switch them** — promoting Lliam-GOV and retiring Lliam-OPS as the AIMS artifact. Two direct consequences for this plan:
- **Lliam-GOV is NOT currently tracked on the ISO-cert WBS dashboard** (`katmai-ims/dashboard/state.json`, the 225-task cert WBS). It is a *parallel* build with its own Linear project ("Lliam-GOV Build", `LG-*` WBS). Do not assume the cert dashboard reflects Lliam-GOV progress — it doesn't, by design.
- **Phase 6 (AIMS asset-inventory registration AI-233 + audit-notebook ingest AI-230) is CONDITIONAL** on Jerome's explicit decision to make the swap. Until that decision, Phases 0–5 build and prove Lliam-GOV; Phase 6 promotes it only on green-light (see Open Decision **D9**). Lliam-OPS is not edited as part of this plan.

---

## 1. Current state of the repository

### 1.1 Branch posture
| Item | State |
|---|---|
| `origin/main` HEAD | `89cc536` — *[codex] Harden audit chain lifecycle (#16)*, merged **2026-05-30 13:25Z** |
| Local `main` | `4fc6f5e` — **1 commit behind** origin; needs `git pull --ff-only` |
| Checked-out branch | `codex/fix-audit-review-findings` (`9aa6e37`) — **already merged as PR #16; now stale** |
| Branch protection | Plan §8.2 calls for required-PR + required-CI-green + signed tags on `main` — *verify it is actually configured in GitHub settings* |

### 1.2 Clean vs WIP / uncommitted
- **No real WIP.** Working tree shows only exFAT **AppleDouble `._*` sidecar files** and untracked `heartbeats/` / `handoffs/` scratch — noise, not work. Standing rule: `find . -name '._*' -type f ! -path './.git/*' -delete` before every commit.
- Five **stale merged branches** to prune (all merged to `main` via PRs #11–#16): `codex/ai-210-audit-logger`, `codex/ai-211-aep-export`, `codex/ai-213-tool-dispatch-audit`, `codex/ai-235-agent-loop-tool-audit`, `codex/fix-audit-review-findings`; plus `phase2/noise-floor-recalibration` and `phase3/encryption-and-audit` (already `[gone]` on remote).
- Four **superpowers worktrees** still bound to those branches under `~/.config/superpowers/worktrees/lliam-gov/` — remove with the branches.

### 1.3 CI state
- **Green on latest `main`** (`89cc536`): *Tests* ✅ and *Lint (ruff + ty)* ✅ at 2026-05-30 13:25Z.
- Active workflows: `tests.yml`, `lint.yml`, `osv-scanner.yml`, `supply-chain-audit.yml`, `history-check.yml`, `uv-lockfile-check.yml`, `docker-lint.yml`. Many upstream Hermes workflows intentionally `.disabled`.
- `osv-scanner.yml` runs with `upload-sarif: false` + `fail-on-vuln: false` (code scanning not enabled on this private repo) — OSV still scans and logs. One transient *Tests* failure on 2026-05-29 13:31Z (an AI-213 run) was resolved by the next push.

### 1.4 Test coverage / noise floor
- Baseline noise floor (Phase-2 recalibrated, `evidence/phase2/noise-floor-2026-05-26.md`): **11 files / 36 fails under `uv sync --extra all`, zero collection errors** — one file / one fail *below* the Phase-0/1 baseline. **Every phase exit requires failing set ⊆ this baseline.**
- Run discipline: `UV_PROJECT_ENVIRONMENT=/Users/just_jerome/.venvs/lliam-gov uv run python scripts/run_tests_parallel.py` (plain `pytest -q` wedges; APFS venv required — exFAT corrupts wheel RECORDs).
- Phase-3 modules added so far carry focused green unit suites (key_manager + runtime_guard = 22 passed at merge; audit logger, AEP, session/loop/tool audit each merged green).

### 1.5 Audit-log of recent commits (Phase 3 to date)
`main` history shows a clean per-issue merge train: PR #8 (Phase 2 matrix) → #9 (noise-floor recal) → #10 (key_manager + FIPS probe) → #11 (AI-210 audit logger core) → #12 (AI-211 AEP export) → #13 (AI-213 fail-closed tool dispatch) → #14 (AI-235 agent-loop audit) → #15 (AI-212 session lifecycle audit) → #16 (audit chain hardening). This is the commit pattern to continue.

---

## 2. Linear issue inventory — mapped to WBS

Project totals: **44 issues — 19 Done, 24 Backlog, 1 In Progress.** WBS prefix `LG-X.Y.Z`. Labels in use: `lliam-gov`, `iso-42001`, `iso-27001`, `cmmc-l2`, `security-hardening`, `evidence`, `Phase 0…6`, `interview-open`.

### 2.1 Done (19) — Phases 0–2 complete, Phase 3 ~70% complete
| WBS | Issue | Title |
|---|---|---|
| LG-0 / .1 / .2 | AI-192/199/200 | Phase 0 — preserve & relocate baseline, attribution, noise floor |
| LG-1 / .1–.4 | AI-193/201/202/203/204 | Phase 1 — facelift, NOTICE, gateway trim, dashboard break-glass removal |
| LG-2 / .1–.4 | AI-194/205/206/207/208 | Phase 2 — control matrix (55 rows), 800-171 + ISO 42001/27001 re-verify, CSV+mirror |
| LG-3.1 | AI-209 | AES-256-GCM key manager + FIPS runtime probe |
| LG-3.2 | AI-210 | Hash-chained audit logger core |
| LG-3.3 | AI-211 | AEP export + audit re-import |
| LG-3.4 | AI-212 | Session-lifecycle + conversation-loop audit |
| LG-3.5 | AI-213 | Fail-closed tool-dispatch audit |
| LG-3.5.1 | AI-235 | Agent-loop tool-dispatch audit paths |

### 2.2 Remaining open work (25 issues)
**Phase 3 — finish core hardening (4 leaves + parent):**
| WBS | Issue | Title | Notes |
|---|---|---|---|
| LG-3 | **AI-195** | Phase 3 parent | **In Progress** — close when 3.6–3.9 done |
| LG-3.6 | AI-214 | Audit retained gateway inbound auth events | `interview-open` |
| LG-3.7 | AI-215 | **EncryptedFile abstraction + route persisted state** | `interview-open` — the linchpin |
| LG-3.8 | AI-216 | `rotate-key` + `audit export-aep` CLI commands | `interview-open` |
| LG-3.9 | AI-217 | 24-hour smoke evidence + flip matrix rows | `interview-open` — **Phase 3 EXIT gate** |

**Phase 4 — boundary hardening (7 leaves + parent AI-196):** AI-218 principal binding/root refusal (LG-4.1) · AI-219 capability-tagged tool dispatch (4.2) · AI-220 egress allowlist + TLS (4.3) · AI-221 runtime guard: workspace/umask/Keychain (4.4) · AI-222 gate dynamic self-improvement behind human approval (4.5) · AI-223 CUI marking + audit-only chain of custody (4.6) · AI-224 production profile + operator runbooks (4.7).

**Phase 5 — evidence & self-attestation (5 leaves + parent AI-197):** AI-225 AEP evidence exports per control (LG-5.1) · AI-226 map every matrix row → code/tests/evidence (5.2) · AI-227 SBOM + dependency-review record (5.3) · AI-228 focused pen-test + remediate (5.4) · AI-229 chaos fail-closed exercises (5.5).

**Phase 6 — Katmai AIMS integration (5 leaves + parent AI-198):** AI-230 ingest evidence into Katmai ISO 42001 Audit notebook (LG-6.1) · AI-231 update Master Map + orientation (6.2) · AI-232 update global/workspace agent instructions (6.3) · AI-233 register Lliam-GOV in AIMS asset inventory (6.4) · AI-234 install + run on Katmai MacBook (6.5).

> **All open issues have `estimate = None`.** Estimates below are this plan's proposal (see §7 Open Decision D2).

---

## 3. Critical-path sequence

```
Phase 3 (finish) ──> Phase 4 ──> Phase 5 ──> Phase 6 ──> [Katmai IT review = milestone, not gate]
   │
   ├─ AI-214 gateway-auth audit ─┐ (parallelizable)
   ├─ AI-215 EncryptedFile  ─────┤──> AI-216 CLI (needs key_mgr+audit+EncryptedFile)
   └──────────────────────────────┴──> AI-217 24h smoke + matrix flip  = PHASE 3 EXIT
```

**Why this order:**
1. **AI-215 (EncryptedFile wiring) is the true linchpin.** `key_manager.py` exists, but persisted state under `~/.lliam-gov` is *not yet routed through it*. Until it is, the at-rest encryption controls (800-171 §3.8.9 / §3.13.16; ISO 27001 A.8.24; ISO 42001 A.8.4) are scaffolded, not satisfied. Everything that claims "encrypted at rest" depends on this.
2. **AI-216 (CLI) depends on backing APIs** — `rotate-key` needs key_manager's atomic re-key; `export-aep` needs the audit logger. Sequence after AI-215.
3. **AI-214 (gateway-auth audit) is parallelizable** — touches only the three retained adapters; no dependency on AI-215/216.
4. **AI-217 is the Phase-3 EXIT gate** — the 24-hour smoke run must re-import the audit log clean and AEP-export correctly, then flip *only* the control-matrix rows that now have code + evidence. Cannot start until 3.6–3.8 land.
5. **Phase 4 → 5 → 6 are strictly sequential by the plan's exit gates.** Phase 5 evidence is generated *against* Phase-4-hardened controls; Phase 6 remediations land against documented (Phase-5) controls, not ad-hoc.

**ISO 42001 audit dependencies / sign-off gates:**
- **Phase 2 exit gate (control set sign-off) is already MET** — Jerome signed off in writing 2026-05-25 (Open Brain `iso42001/decision`). The 55-row matrix is locked for Phase-3 entry.
- **Phase 3 / 5 exits are evidence-producing, not CB-gated** — they populate `evidence/` and flip matrix `current_state` rows. These rows are the audit currency.
- **Phase 6 is the convergence with the ISO 42001 cert program — and the swap point.** AI-230 ingests the Lliam-GOV evidence package into the **Katmai ISO 42001 Audit** NotebookLM (`fab3c86a-…`); AI-233 registers Lliam-GOV as an in-scope AI system in the **AIMS asset inventory**. **This is gated on Jerome's decision to swap Lliam-GOV in for Lliam-OPS as the AIMS target (D9).** Until then, Lliam-GOV is proven in parallel; it becomes load-bearing *operating evidence* only after the swap is authorized.
- **Katmai IT review + pen-test gate NOTHING (Jerome, 2026-05-30).** The Katmai IT posture/documentation review, the company-laptop install (AI-234), and the pen-test (AI-228) all **wait for Jerome's explicit go**, which itself follows **Katmai committing to allow the install**. They are off the critical path entirely — Phases 0–5 proceed regardless. Evidence supplied to Katmai at that point is **outside ISO 42001 scope/controls** and is provided only after that commitment, never beforehand.
- **Alignment surface:** the ISO-cert WBS (225 tasks) lives in `katmai-ims/dashboard/state.json` and syncs to Linear via `katmai-ims/scripts/linear_state_sync.py`. The `LG-*` build WBS is *distinct* from that cert WBS; they meet at Phase 6 (asset inventory + audit-notebook ingest). No need to reconcile the two WBS trees before Phase 6.

---

## 4. Phase-by-phase work breakdown (effort · acceptance · risk)

Effort key: **S** ≈ ≤0.5 day · **M** ≈ 1–2 days · **L** ≈ 3–5 days · **XL** ≈ 1 week+.

### Phase 3 — finish core hardening  (remaining ≈ M–L total)
| Issue | Eff | "Done" means | Risk |
|---|---|---|---|
| AI-214 LG-3.6 | M | Success + failed inbound auth events logged with principal/source metadata; secrets scrubbed; removed adapters not reintroduced; adapter-level tests cover the path | L — touches only 3 files; scrubber must not leak tokens/bodies |
| AI-215 LG-3.7 | **L** | `EncryptedFile` abstraction exists; session state, conversation DBs, credential/auth cache, relevant backups assessed and routed through AES-GCM; CI/search guard for plain workspace writes; round-trip + tamper tests | **M-H** — broad blast radius across persisted-state writers; risk of missing a writer or breaking upstream Hermes state I/O |
| AI-216 LG-3.8 | M | `lliam-gov rotate-key` atomic re-key; `audit export-aep` writes AEP to documented path; both validate principal/runtime prereqs; CLI help + operator docs updated | L — atomic swap (write-new/fsync/swap/unlink) must be crash-safe |
| AI-217 LG-3.9 | M | 24-h run completes; audit log verifies + AEP-exports clean; `evidence/phase3/` committed; matrix rows flipped *only where evidence proves it*; noise floor not exceeded | M — 24-h wall-clock; FIPS dev-override (`LLIAM_GOV_ALLOW_NON_FIPS=1`) acceptable for smoke |
| AI-195 LG-3 | S | Parent — transition to Done only when 3.6–3.9 truly complete | — |

### Phase 4 — boundary hardening  (≈ 2–3 weeks; plan estimate)
| Issue | Eff | "Done" means (per §5.3–§5.6) | Risk |
|---|---|---|---|
| AI-218 4.1 | M | euid-0 refusal in production profile; OS-uid principal binding | L |
| AI-219 4.2 | L | Every tool declares a capability tag; loop checks authorized set before dispatch; conservative default set named | M — fan-out across the 98-file tool tree |
| AI-220 4.3 | L | `egress.py` httpx wrapper; non-allowlisted dest → `EgressDenied` + AU event; TLS ≥1.2, `verify=True`, no skip-verify flag exists; CI guard on raw httpx import | **M-H** — every adapter must route through wrapper; missing one defeats control |
| AI-221 4.4 | M | runtime_guard completes workspace 0700, umask 0077, Keychain probe, sync-path overlap warning | L |
| AI-222 4.5 | L | Self-mod proposals staged to `pending/`; `lliam-gov approve <id>` single-key + required note + AU events; agent operates as if change not live until approved | M — must intercept *every* self-mod write path |
| AI-223 4.6 | M | CUI structural marking (metadata, **no denial logic**); `cui_access` AU events with destination metadata; on-delete sanitize | M — governance-not-code boundary must be respected (plan §5.6) |
| AI-224 4.7 | M | Production profile config as default; `docs/operate/` runbook drafts | L |

### Phase 5 — evidence & self-attestation  (≈ 1.5–2 weeks)
| Issue | Eff | "Done" means | Risk |
|---|---|---|---|
| AI-225 5.1 | M | AEP exports covering each applicable control | L |
| AI-226 5.2 | L | Every matrix row → code lines + test cases + audit signatures; 100% mapped | M — completeness audit |
| AI-227 5.3 | S | CycloneDX SBOM under `evidence/sbom/`; dependency-review record | L |
| AI-228 5.4 | M | Focused pen-test (grounded in Pen-Test notebook `d0b83dce-…`); CMMC-L2-relevant findings empty or remediated | ⛔ **WAITS for Jerome's go — gates nothing.** Removed from Phase-5 critical path; Phase 5 exits without it. Katmai-facing, out-of-ISO-scope. |
| AI-229 5.5 | M | Chaos: kill audit→fail-closed; kill keyring→fail-closed; kill egress-deny→fail-closed; reject self-mod→no live leak | M — destructive tests; run in isolated workspace |

### Phase 6 — Katmai AIMS integration  (≈ 1 week + external review)
| Issue | Eff | "Done" means | Risk |
|---|---|---|---|
| AI-230 6.1 | S | Evidence package ingested into Katmai ISO 42001 Audit notebook | L |
| AI-231 6.2 | S | Master Map + 0-Orientation updated | L |
| AI-232 6.3 | S | Global/workspace `CLAUDE.md` updated with Lliam-GOV identity (plan §6 deferral now lands) | L |
| AI-233 6.4 | S | Lliam-GOV registered in AIMS asset inventory | L |
| AI-234 6.5 | M | Installed + running on Katmai MacBook; **Jerome installs personally** (not a gate); FIPS-OpenSSL provisioned | **M-H** — R6 FIPS provisioning + R5 MDM/EDR conflicts |

**Cumulative remaining effort:** ≈ **6–8 weeks** of focused work (Phase 3 finish ≈ 1 week; 4 ≈ 2–3 wk; 5 ≈ 1.5–2 wk; 6 ≈ 1 wk). Calendar elapsed depends on eCRM load (R12, likelihood **H**) and the Katmai IT review schedule.

---

## 5. Commit-discipline plan

1. **One issue → one branch → one PR** (continue the established #11–#16 pattern). No mega-branches.
2. **Branch naming:** `codex/ai-NNN-slug` (matches history) or `phaseN/slug`. *(If execution moves to Claude Code, propose `claude/ai-NNN-slug` to distinguish authorship — see D4.)*
3. **Small slices:** AI-215 is large enough to land as 2 PRs if needed (abstraction first, then writer routing) rather than one XL diff.
4. **Commit-message convention** (conventional commits + traceability):
   `feat(phase3): add EncryptedFile abstraction and route session state (AI-215, WBS LG-3.7)`
   Body cites plan section (§5.1) and control-matrix rows touched. Tie every commit to **AI-NNN + WBS LG-X.Y.Z**.
5. **Pre-commit hygiene (mandatory, exFAT):** `find . -name '._*' -type f ! -path './.git/*' -delete` then the parallel test script with the APFS venv. Husky `pre-commit` hook is present — keep it.
6. **Rebase on `main` before opening each PR** so CI runs against current tip; resolve any noise-floor drift.
7. **Matrix-row flips are evidence-gated:** never change `evidence/control-matrix.csv` `current_state` until the code *and* the evidence artifact both exist (AI-217 / AI-226 discipline).
8. **Linear discipline (Jerome's standing rule):** transition an issue to **Done only when truly complete**; never delete; act on Jerome's issue comments; parent issues (AI-195/196/197/198) flip to Done only after all their leaves are Done.

---

## 6. GitHub push plan

- **PR strategy: per-issue PRs into `main`** (not a per-phase mega-PR). Rationale: matches the clean #11–#16 train, keeps CI signal per-control, and makes the audit trail itself ISO-42001 documented information. *Phase parent issues are not PRs* — they close when their leaves merge.
- **CI gates that must pass before merge:** *Tests* ✅ and *Lint (ruff + ty)* ✅ (required); *OSV* + *supply-chain-audit* advisory (review logs, non-blocking). Noise floor must stay ⊆ baseline.
- **Review path:** agent opens PR → Jerome reviews → **Jerome authorizes merge** (self-merge via the `+` operator, his established pattern). **No push or merge without explicit instruction** (handoff operating rule + brief).
- **Release tagging:** signed tags on release points (plan §8.2); SBOM + sigstore/cosign signature at release tags (AI-227 / §5.7).
- **Pre-flight cleanup (pending D7 approval):** `git fetch --all --prune` → fast-forward local `main` to `89cc536` → delete the 5 merged `codex/*` branches + 2 `[gone]` branches → remove the 4 stale superpowers worktrees. Verify branch-protection rules on `main` are actually set in GitHub.
- **Gateway-trim guard (R4):** confirm a CI check asserts the removed-adapter set stays absent, so an upstream cherry-pick can't silently reintroduce a platform.

---

## 7. Open decisions — only Jerome can make these

| # | Decision | Why it's yours | Recommendation |
|---|---|---|---|
| **D1** | **`interview-open` label** on AI-214…217 — do these need the discussion-cycle interview pass, or are they green-lit for direct execution? | The label gates whether the executor may start | Green-light directly — DoDs are already precise; clear the label |
| **D2** | **Set S/M/L/XL estimates** in Linear (all currently `None`)? | Linear hygiene / your board | Yes — apply §4 estimates so the board reflects load |
| **D3** | **FIPS-OpenSSL provisioning (R6)** — when/where do we provision FIPS-mode OpenSSL? Dev (Mac mini) can run `LLIAM_GOV_ALLOW_NON_FIPS=1`; Katmai MacBook cannot | Host/runtime decision; DoD hard requirement | Dev with non-FIPS override through Phase 5; provision FIPS on Katmai MacBook at Phase 6 install |
| **D4** | **Execution engine** — Phase 3 was Codex (`codex/*` branches). Who runs Phases 4–6: Codex, this Claude Code/Opus 4.8 session, or both? | Tooling + branch-naming convention | This session (Opus 4.8 Max Effort) for Phase 4+; adopt `claude/ai-NNN-*` prefix |
| **D5** | **Katmai IT review** | External stakeholder | ⛔ **DECIDED — WAIT for Jerome.** Gates **no build work.** The Katmai IT posture/documentation review + company-laptop install wait until Katmai commits to allowing install; Katmai-facing evidence (out of ISO 42001 scope/controls) is supplied only then, never beforehand. |
| **D6** | **Pen-test (AI-228)** + chaos (AI-229) | Authorization + scope | ⛔ **DECIDED — pen-test (AI-228) WAITs for Jerome's go and gates nothing.** Chaos (AI-229) proceeds as internal build validation (flag if it should also wait). |
| **D7** | **Authorize git hygiene now** — ff-pull local `main`, prune 7 stale branches + 4 worktrees? | Touches your local repo | Yes — safe, all merged |
| **D8** | **Confirm per-issue PR strategy** (§6) over per-phase mega-PRs? | Review cadence | Per-issue (recommended) |
| **D9** | **The swap** — promote Lliam-GOV to AIMS target and retire Lliam-OPS, or keep both parallel? Gates Phase 6 (AI-230/233 registration + notebook ingest) | This is the strategic call; Lliam-GOV is currently a parallel candidate, not the cert artifact | Build + prove through Phase 5 first; decide the swap at the Phase-5→6 boundary on evidence |

---

## 8. Immediate next action (on green-light)

1. Resolve D1–D8 (above).
2. Git hygiene (D7): ff-pull `main` → `89cc536`; prune merged branches + worktrees.
3. Start **AI-214** (parallelizable) and **AI-215** (linchpin) as the first two Phase-3 PRs.
4. Land AI-216 → run AI-217 24-h smoke → flip eligible matrix rows → close AI-195 → Phase 3 exit.
5. Proceed to Phase 4 per §4 sequence.

*No code will be written or pushed until you approve this plan and the open decisions.*
