/goal Complete the Lliam-GOV build to its Phase-5 exit (Phases 3→4→5), shipping clean per-issue PRs against `main`. Lliam-GOV is a governance-hardened Python fork of Hermes Agent that serves as ISO 42001 / CMMC L2 / ISO 27001 operating evidence. The plan is approved; your job is execution.

# Lliam-GOV — Build Completion Handoff (2026-05-30)

## 0. Orient first (do these before any edit)
- **Working dir:** `/Volumes/WORKSPACE/1-Projects/lliam-gov` — GitHub `jdavis-cyber/lliam-gov` (private).
- **DO NOT confuse repos.** `/Volumes/WORKSPACE/1-Projects/lliam_ai_agent` is **Lliam-OPS** (Node/TS, dormant). **Never edit it.** It is reference-only. Lliam-GOV is the Python repo above. Lliam-GOV is a **parallel candidate-replacement**; Lliam-OPS is still the nominal AIMS target until Jerome decides to swap (see D9).
- **Read in order:**
  1. `docs/plans/2026-05-30-lliam-gov-completion-plan.md` (THE approved plan — repo copy; mirrors Drive Doc `1W_hDoU3-PBKflxSoG-Y3d7FlAR8nBX752HuqTh3y31E` and Linear AI-240)
  2. `/Volumes/WORKSPACE/0-Orientation/Hermes-to-Lliam-ISO42001-Plan-COMPREHENSIVE-v3-2026-05-25.docx` (canonical design of record — §5 hardening overlay, §9 phases, §11 decisions)
  3. `handoffs/2026-05-28-Codex-Continuation-Handoff.md` (operating rules, prior slice)
  4. `docs/governance/control-matrix.md` + `evidence/control-matrix.csv` (the 55-row control matrix — your evidence ledger)
- **Open Brain (memory):** read before working — `list_thoughts`, then `search_thoughts "lliam_gov"`. Write after each meaningful slice with tag `lliam_gov` + `decision`/`continuity`/`lesson`. Local server `http://127.0.0.1:3741`.

## 1. Current state (verify with git on entry)
- `main` @ `89cc536` ("[codex] Harden audit chain lifecycle (#16)"). CI green (Tests + Lint ruff/ty).
- **Phases 0–2 Done. Phase 3 ~70% done.** Done so far: key_manager + FIPS probe (AI-209), hash-chained audit logger (AI-210), AEP export (AI-211), session/loop audit (AI-212/235), fail-closed tool dispatch (AI-213).
- Repo is clean: stale worktrees/branches already pruned. One extra local branch `docs/2026-05-30-completion-plan` holds the plan commit (unpushed) — leave it or PR it.
- **Noise floor (must stay ⊆):** 11 files / 36 fails under `--extra all`, zero collection errors (`evidence/phase2/noise-floor-2026-05-26.md`).

## 2. What to build — sequence is the critical path
**Phase 3 finish (start here), one issue → one branch → one PR:**
1. **AI-214 / LG-3.6** — audit retained gateway inbound auth events (slack/email/telegram); scrub secrets + payloads; don't reintroduce removed adapters. *Parallelizable.*
2. **AI-215 / LG-3.7** — **the linchpin.** Add an `EncryptedFile` abstraction and route persisted state under `~/.lliam-gov` (session state, conversation DBs, credential/auth cache, backups) through AES-256-GCM via the existing `lliam_gov/security/key_manager.py`. Add a CI/search guard for plain workspace writes. Round-trip + tamper tests. May land as 2 PRs (abstraction, then writer routing).
3. **AI-216 / LG-3.8** — `lliam-gov rotate-key` (atomic re-key) + `lliam-gov audit export-aep` CLI; validate principal/runtime prereqs; update CLI help + operator docs. *Depends on AI-215 + audit logger.*
4. **AI-217 / LG-3.9** — 24-h smoke run; audit log re-imports clean + AEP-exports; commit `evidence/phase3/`; flip control-matrix `current_state` rows **only where code + evidence both exist**. **This is the Phase-3 EXIT gate.**
5. Transition parent **AI-195 / LG-3** → Done only when 3.6–3.9 are truly complete.

**Phase 4 — boundary hardening (after Phase 3), per plan §5.3–§5.6:** AI-218 principal binding/root refusal · AI-219 capability-tagged tool dispatch · AI-220 egress allowlist + TLS wrapper (CI guard on raw httpx) · AI-221 runtime_guard workspace/umask/Keychain · AI-222 human-approval gate over dynamic self-improvement · AI-223 CUI marking + audit (**marking/audit only — NO code-level egress denial**) · AI-224 production profile + operator runbooks. Close parent AI-196.

**Phase 5 — evidence (after Phase 4):** AI-225 AEP exports per control · AI-226 map every matrix row → code/tests/evidence · AI-227 SBOM + dependency-review · AI-229 chaos fail-closed exercises (internal validation — proceed). Close parent AI-197. **SKIP AI-228 (pen-test) — see §3.**

## 3. Hard carve-outs (Jerome, 2026-05-30 — gate NOTHING)
- **AI-228 (pen-test): DO NOT RUN.** Waits for Jerome's explicit go. Phase 5 exits without it.
- **Katmai IT review + company-laptop install (AI-234) + all Phase 6 Katmai-facing items: DO NOT START.** They wait until Katmai commits to allowing the install; Katmai-facing evidence is **outside ISO 42001 scope/controls** and supplied only then. Phase 6 also depends on the **D9 swap decision** (promote Lliam-GOV / retire Lliam-OPS) — Jerome decides at the Phase-5→6 boundary on evidence.
- Net: **build only through Phase 5 (minus AI-228). Stop there and report.** Do not touch Phase 6 unless Jerome explicitly green-lights.

## 4. Commit & PR discipline
- One Linear issue → one branch → one PR into `main`. Branch prefix **`claude/ai-NNN-slug`**.
- Commit message: `feat(phaseN): <subject> (AI-NNN, WBS LG-X.Y.Z)` + body citing plan §ref and matrix rows touched. End with: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **Before every commit:** `find . -name '._*' -type f ! -path './.git/*' -delete` (exFAT sidecars), then run tests.
- **NEVER flip a control-matrix `current_state` row until the code AND the evidence artifact both exist.**
- **Linear discipline:** transition to **Done only when truly complete**; never delete; act on Jerome's comments; parent issues close only after all leaves Done.

## 5. Build/test environment (non-negotiable)
- Always: `export UV_PROJECT_ENVIRONMENT=/Users/just_jerome/.venvs/lliam-gov` (APFS venv; exFAT corrupts wheels).
- Full suite: `uv run python scripts/run_tests_parallel.py` (plain `pytest -q` wedges).
- Focused: `uv run pytest -q tests/lliam_gov/<file>`.
- FIPS is a production hard-gate; **dev override** `LLIAM_GOV_ALLOW_NON_FIPS=1` for local/smoke runs.
- Keep internal Hermes package names (`hermes/`, `hermes_cli/`) — the rebrand is a facelift only (plan §6). New code goes under `lliam_gov/security/`.

## 6. Approval gates — what needs Jerome, not you
- **No `git push` and no PR merge without Jerome's explicit instruction.** Open PRs and report; he self-merges via the `+` operator.
- Don't delete remote branches, don't enable Linear team estimation (currently off), don't start AI-228 / Katmai work.
- Brief Jerome before committing if a design choice is ambiguous.

## 7. Linear access (no OAuth needed)
- `set -a; source ~/.codex/ea-routines/env; set +a` exposes `LINEAR_API_KEY`. Endpoint `https://api.linear.app/graphql`, header `Authorization: $LINEAR_API_KEY`.
- Project "Lliam-GOV Build" `60a51de4-6ae1-4406-9e3d-3ce2d86cc1f5` · team AI `083645e6-474f-44fb-9f6c-53de959cfba8`.
- State IDs: Backlog `e89ca31e-…` · In Progress `588bb630-68fa-482f-ac63-01966137a8c8` · In Review `155fcbb2-0570-4c39-b6e3-52023c26f0f8` · Done `0a306af0-4f09-4660-b43d-29719b835689` · For Jerome `b37592be-f21a-4a0f-a65c-6a3946ce04fb`.
- Move an issue to **In Progress** when you start it; **In Review** when its PR is open; **Done** only after merge + evidence.

## 8. Definition of done for this handoff
Phases 3, 4, and 5 (excluding AI-228) complete: all leaf issues Done with merged PRs; control matrix rows flipped where evidence exists; `evidence/` populated (phase3 smoke, SBOM, dependency review, chaos results); noise floor never exceeded; parents AI-195/196/197 Done. Phase 6 left untouched, pending Jerome's swap + Katmai go. Report status + open PRs to Jerome at each phase boundary.

**Success loop:** pick the lowest-WBS available issue on the critical path → branch → TDD the slice → green focused tests + noise floor ⊆ baseline → open PR → update Linear → capture Open Brain → next. Stop and ask Jerome at each phase exit and on any ambiguity.
