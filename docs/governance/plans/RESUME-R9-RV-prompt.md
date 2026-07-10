# Resume Prompt — Lliam-GOV Phase R: finish R.8e-3c → R.9 → R.V (then P1–P6)

> Paste the block below into a fresh Claude Code session started in the **dedicated clone** `~/dev/lliam-gov` (NOT the PKA copy). It resumes the Katmai Adoption Build Plan mid–Phase R. The hermes→lliam rename is ~99% done but the guard is **NOT yet green** — a subagent driving the final sweep was cut off by a session limit with **~61 un-allowlisted lines remaining and the keep-register unwritten** (HEAD `c513453`, tree clean, all work committed+pushed). Three steps remain to close Phase R: **finish R.8e-3c** (drive guard green + write keep-register), then **R.9** (control-matrix/CI/nix path refs), then **R.V** (verify gate + PR). After Jerome merges, tag `gov-R-good` and Phase 1 begins.

---

You are continuing execution of the Katmai Adoption Build Plan for Lliam-GOV, mid–Phase R. Read the plan in full first: `/Users/just_jerome/Desktop/My_PKA/PKM/01_Projects/lliam-gov/docs/governance/plans/2026-07-02-katmai-adoption-build-plan.md`. Also read the session-state memory at `~/.claude/projects/-Users-just-jerome-Desktop-My-PKA-PKM-01-Projects-lliam-gov/memory/phase-r-rename-session-state.md`.

REQUIRED SUB-SKILL: `superpowers:subagent-driven-development` — drive task-by-task with implementer + two-stage review (spec, then quality) and a full-suite gate after each risky step.

## Current truth (verified — confirm before acting)
- Dedicated work clone: `~/dev/lliam-gov`, branch `rename/hermes-to-lliam` at HEAD `c513453` (pushed to `jdavis-cyber/lliam-gov`, tree clean). The live install and the PKA copy stay untouched.
- **Guard is NOT green yet.** The guard test `tests/rename/test_no_hermes_identifiers.py` was already REDESIGNED to a token-level keep-pattern allowlist (that part is done and committed). Running it now reports **~61 un-allowlisted `hermes` lines remaining** — each is either a real Lliam-owned rename target or a legitimate keep that still needs a keep-pattern added. The keep-register doc `docs/governance/verification/R8e-keep-register.md` was **NOT written** — create it as part of finishing R.8e-3c.
- The last full-suite run at this exact HEAD was NOT re-verified (agent was cut off) — **re-run the full suite first** to confirm it's still at floor before building on it. Expect floor + documented flakes; investigate anything else.
- Remaining Phase R steps: **finish R.8e-3c** (guard → green + keep-register), then **R.9** (matrix/CI/nix path refs), then **R.V** (verify gate + PR). After Jerome merges → tag `gov-R-good`, re-impose PATH-FREEZE, start **P1** (AI-516 first).

## STEP 0 (do FIRST) — finish R.8e-3c: drive the guard GREEN + write the keep-register
1. Re-run the full suite (`python scripts/run_tests_parallel.py`) + collection-error check; confirm at floor. If a prior R.8e-3c commit regressed something, fix it (check the last few commits `git log --oneline cc9300e..HEAD`).
2. Run the guard: `python -m pytest tests/rename/test_no_hermes_identifiers.py -q`. It lists the ~61 un-allowlisted lines. For EACH: adjudicate real-miss (rename to lliam-gov/Lliam-GOV) vs legitimate keep (add a keep-pattern to the guard's allowlist WITH a rationale). Use the keep taxonomy at the bottom of this doc. When unsure, KEEP + document (over-keeping is safe; never rename a test-asserted value, external wire tag, client-id, or binary-DETECTION string).
3. Write `docs/governance/verification/R8e-keep-register.md`: every keep pattern/category → its rationale (this is the assessor-facing justification that "guard green = every survivor is a documented, justified keep"). Include the env-fallback decision: `getenv_compat` HERMES_ fallback + `--hermes-root` alias are KEPT for one release (safer for operator scripts), documented here.
4. Guard GREEN (`pytest tests/rename/test_no_hermes_identifiers.py` passes). Full suite == floor. ruff clean. Commit: `refactor(rename): drive guard green + keep-register (R.8e-3c complete)`. Push. THEN proceed to R.9.

## Environment (CRITICAL — the harness has footguns)
- Python: `source ~/dev/lliam-gov/.venv/bin/activate` (Python 3.13; repo requires <3.14). Install extra: `uv pip install -e ".[acp]"`.
- Node: **`export PATH="/opt/homebrew/opt/node@22/bin:$PATH"` for ALL node/npm work.** System node is 25, which breaks jsdom → ~109 false desktop-test failures. node@22 is installed as an unlinked keg.
- Test floors (ZERO new failures beyond these):
  - pytest: `~/dev/lliam-gov-baseline/branch-noise-floor.txt` (60 entries) + 2 documented flakes that vary by run: `test_base_environment...test_concurrent_writes_never_tear_the_snapshot` and `test_windows_subprocess...fuzzy_file_listing_hides_git_windows` (verify any suspected flake in isolation — passes alone = flake).
  - desktop `test:ui`: 19–20 failed / 945–946 passed (node 22 only).
- **Always check collection ERRORS, not just FAILED lines**: `python -m pytest tests/ --collect-only -q 2>&1 | grep -ciE 'error(s)? during collection'` must be 0. (An earlier sweep renamed an import but not its file — masked as collection errors. Don't repeat.)
- Full suite: `python scripts/run_tests_parallel.py` (~10–12 min, 20 workers). Compare FAILED set to the floor by name; test-method renames can make floor entries look "non-floor" — update the floor file's test names when that happens.
- **⚠️ ALWAYS isolate the data home for test runs.** Prefix every suite invocation with a throwaway home: `HERMES_HOME=/tmp/lliam-testhome LLIAM_HOME=/tmp/lliam-testhome python scripts/run_tests_parallel.py`. WHY: the gateway/platform tests (`tests/gateway/test_feishu.py`, telegram/discord/etc.) spawn REAL gateway subprocesses; without an isolated home they resolve the new D5 default `~/.lliam` and start a live gateway there with an auto-restart supervisor — which on 2026-07-07 produced a runaway loop on Jerome's Mac (repeated Chrome xAI/X OAuth prompts + "Partial answer" voice, ~15–20×/hr, burning API budget). Cleaned up by moving the ephemeral restart-state files to `~/.lliam/.gateway-state-backup-*`. Never run the suite against the real home. (This test-isolation defect is also worth logging as a governance finding — a test spawning a networked gateway + browser OAuth against the operator home is a least-privilege/egress failure the P2 controls should catch.)

## R.9 — control-matrix + CI + nix (branch: continue on `rename/hermes-to-lliam`)
Per plan Task R.9. Do the work; commit in groups; full-suite gate.
1. **`docs/governance/control-matrix.md`** — rewrite owner-module paths from `hermes_cli/...` to `lliam_cli/...` (e.g. `hermes_cli/web_server.py`, `hermes_cli/main.py`, `hermes_cli/security_advisories.py`) so P1–P6 evidence references resolve. Check the whole matrix for stale `hermes_*` module/path refs.
2. **CI workflows** `.github/workflows/*.yml` + `.github/actions/**` — update references to renamed modules/scripts/package name/artifact names. Specifically: `upload_to_pypi.yml` (dist name → `lliam-gov-agent`), any `docker-publish` image name if it embeds `hermes`, the `hermes-smoke-test`→`lliam-smoke-test` action (already renamed in R.8b — verify refs resolve), test-slice/duration path lists if they enumerate `tests/hermes_cli` (now `tests/lliam_cli`). Keep CI internally consistent so it stays green.
3. **`nix/nixosModules.nix`** — deferred from R.8b (dense runtime/config contracts). Adjudicate `hermes` refs: Lliam-owned option/attr names → rename; OS-user/`/opt/hermes` install-identity + upstream refs → KEEP (consistent with the R8e keep-register). If nix isn't installed, verify by `rg` cross-file consistency + note that `nix flake check` couldn't run.
4. Re-run the guard test — must STAY GREEN (if R.9 introduces a new `hermes` path ref, either it's a real rename or add it to the keep-register + guard allowlist with rationale).
5. Full suite == floor; ruff clean; typechecks clean (if any TS/CI touched). Commit: `chore(rename): matrix/CI/nix paths -> lliam (R.9)`.

## R.V — rename verify gate + PR (plan Task R.V)
Write `docs/governance/verification/R-rename-report.md` capturing evidence that the build is **renamed AND unbroken**:
- Guard test GREEN (token-level allowlist) — cite the keep-register.
- Full pytest == floor (no new failures/collection-errors vs the pre-rename noise floor); note the floor is a stable, characterized set (macOS `/private/tmp` path-assertion family + live-OAuth-credential family + documented flakes + the intentional guard, which is now green).
- Fresh-clone governed install works: `cd /tmp && rm -rf lliam-freshclone && git clone ~/dev/lliam-gov lliam-freshclone && cd lliam-freshclone && uv venv --python 3.13 .venv && source .venv/bin/activate && uv pip install -e ".[acp]" && lliam-gov --help && lliam-gov version` — usage shows `lliam-gov`, no `hermes` in the usage line, version prints.
- Desktop: `cd apps/desktop && npm ci && npm run build && npm run test:ui` (node 22, at floor); `npm run pack` produces a `Lliam-GOV-*` / `Lliam-GOV.app` artifact with `CFBundleIdentifier=com.secondorderstrategy.lliam-gov` (`plutil -p .../Info.plist | grep -i bundleident`).
- **Desktop IPC bridge round-trip** — deferred from R.5 (headless env couldn't launch the GUI). Attempt a real dev-launch bridge proof if a display is available (isolated `LLIAM_HOME=/tmp/lliam-rv HERMES_HOME=/tmp/lliam-rv`); if not possible, document exactly what was verified instead (channel symmetry was already proven statically; media protocol confirmed live in electron process args at R.5) and mark GUI round-trip as an accepted residual for the AI-326 deploy workstream.
- **Attribution unchanged**: `git diff pre-rename-baseline -- NOTICE ATTRIBUTION.md LICENSE docs/upstream` is empty.
- Then: `gh pr create --base main --title "[R] hermes->lliam rename (core + electron + data migration + full rebrand)"` with a body summarizing the phase, the keep-register, and the two open product decisions below. **DO NOT MERGE.** Post the PR link, say "ready for your merge," and stop for Jerome. After he confirms merge: `git tag gov-R-good && git push origin gov-R-good`, re-impose PATH-FREEZE, then begin Phase 1 (open Linear AI-516 first).

## Two product decisions to put in the PR body / R-report for Jerome (not blockers)
1. Website install/download still points at the upstream host `hermes-agent.nousresearch.com`; root README uses fork URLs. Self-host a fork docs/download site, or leave pointing upstream?
2. `website/docusaurus.config.ts` `organizationName: NousResearch` + `editUrl` point at the upstream repo. Repoint to `jdavis-cyber/lliam-gov` if the fork publishes its own docs?

## Approval boundary (unchanged from the original task)
- ALLOWED autonomously: commits, pushing branches, opening PRs against `jdavis-cyber/lliam-gov`, Linear status writes.
- **YOU DO NOT MERGE.** Post the PR, say "ready for your merge," continue any independent work, and wait for Jerome's confirmation before tagging `gov-R-good`.
- FORBIDDEN without explicit OK: external sends (email/Slack), money movement, destructive deletes, writes to Katmai/Navy systems.

## Linear (keep the board honest — MCP `mcp__plugin_linear_linear__*`)
Project "Lliam-GOV Build", issue **AI-341** (Phase R). It's In Progress with a full comment history of R.0–R.8e. On R.9 done + R.V PR open: comment with branch+SHAs+report path, move to In Review. On confirmed merge + `gov-R-good` tag: move to Done. Then P1 issues: AI-516→517→518, and AI-519/520/479 parallel, all feeding AI-480 (P1.V). If Linear is unreachable, say so in the checkpoint — never silently skip it.

## Keeps reference (do not "fix" these — they are documented, in the R8e keep-register)
Legacy `~/.hermes` paths + migration source; `HERMES_*` env (kept fallback, keep-for-one-release); contract literals (`"hermes_home"` kwargs/JSON keys, `"hermes_pkce"`, `X-Hermes-*` headers, `hermes_client_tag`); legacy detection markers (`hermes-gateway`/`hermes.service`/`ai.hermes.gateway`/`s6-setuidgid hermes`/`main-hermes`); external-registered ids (OAuth `hermes-cli`, wire tags `hermes-agent` for exa/ntfy/copilot/honcho/portal, OpenRouter `X-Title`, ACP registry name); docker/nix OS install identity (`/opt/hermes`, `hermes` user); upstream D4 (`nous_hermes`, `hermes-agent`/`Hermes-4`, the two `hermes-agent` skill dirs, all Nous attribution); incident name `hermes-0day`; contributor email `hermesagent26@`; arbitrary test fixture data; `--hermes-root` deprecated alias. The `docker/` tree is a whole-tree keep.
