# Lliam-GOV — Katmai Adoption Build Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Every phase closes with a verify gate and a pushed `gov-*-good` git tag before the next phase starts.

**Goal:** Take the governance-grade Hermes fork (`jdavis-cyber/lliam-gov`) to an assessor-ready, Katmai-adoptable state: (1) rename every Hermes identity marker to Lliam across the core Python app/harness *and* the shipped Electron desktop app without breaking either, then (2) implement all outstanding governance controls (Rev4-Hardening Phases 1–6, the 188-control crosswalk) so the build carries ISO/IEC 42001, CMMC L2 / NIST SP 800-171 r3, and ISO/IEC 27001 operating evidence.

**Architecture:** The repo is a Python package (`hermes-agent`, entry point `hermes` → `hermes_cli.main:main`) plus an Electron desktop shell at `apps/desktop/` that spawns the Python CLI as a subprocess and talks to it over a loopback HTTP gateway + IPC. Phase-0 hardening is already on `main` (a config overlay `cli-config.gov.yaml` + `policy/*.yaml`, deny-listed godmode, verification reports under `docs/governance/verification/`). The P1–P6 governance controls attach *additively* at the tool-dispatch chokepoint and are **new modules created by those phases** (e.g. `agent/governance_audit.py` in P1.1) — there is **no** pre-existing `lliam_gov/security/` overlay to build into; that path in the older stale-clone survey does not exist on canonical `main`.

**Tech Stack:** Python 3.11–3.13, pytest (~850 test files, per-file subprocess isolation), Electron 40 + electron-builder 26 + React/TypeScript (Vite), `@hermes/*` internal npm workspaces, GitHub Actions CI, macOS Keychain / hardened-runtime signing + notarization.

> **⚑ BASELINE (verified 2026-07-02): This plan is measured against the canonical GitHub repo at HEAD `7a945c4` (PR #82), tag `gov-P0-good` present.** An earlier draft was accidentally measured against a *stale local mirror whose git history is unrelated to GitHub*; that mirror is archived at `PKM/04_Archives/lliam-gov-STALE-mirror-backup-2026-07-02/` and the PKA project folder is now a fresh full clone of canonical. All numbers, paths, and current-state claims below reflect canonical `main`.

**Authoritative sources (read before building):**
- Repo: `/Users/just_jerome/Desktop/My_PKA/PKM/01_Projects/lliam-gov` — now a full clone of canonical `jdavis-cyber/lliam-gov` (HEAD `7a945c4`).
- Governance state on `main`: `docs/governance/verification/` (P0.1–P0.V reports — Phase 0 complete), `docs/governance/deviation-register.{md,yaml}`, `cli-config.gov.yaml`, `policy/{tool-risk-policy,skills-allowlist,input-trust-policy}.yaml`. The **188-control crosswalk** lives in the separate governance package (`~/Desktop/Lliam-GOV-Governance/02_Crosswalk/` / Drive), not in the repo — each Linear issue cites the relevant `LG-*` control IDs.
- Linear backlog (per-issue scope is the source of truth for control detail): project **Lliam-GOV Build**, issues **AI-341** (rename) and **AI-479…AI-520** (Rev4 P1–P6). This plan synthesizes and sequences them; it does not replace their acceptance criteria.
- Rename inventory: this plan's §Phase R + **Appendix A** are built from a measured survey of canonical `main` (2026-07-02): **3,428 files** mention `hermes` after excluding generated output and frozen audit logs. Completeness is guaranteed by the Task R.0 guard test, not by a hand list.

---

## Decisions locked for this plan (Jerome, 2026-07-02)

| # | Decision | Choice | Consequence |
|---|----------|--------|-------------|
| D1 | Rename ordering | **Rename early** — after the two open In-Review PRs (AI-522, AI-326) land, before P1 | PATH-FREEZE is formally *lifted* for Phase R only, then re-imposed. All P1–P6 evidence, ledgers, SSP, SBOM, and AEP exports are generated **once** against the final Lliam identity — no hermes-named artifacts handed to auditors, no regeneration pass. |
| D2 | Rename depth | **Clean break + auto-migration** | Every Lliam-owned identifier becomes `lliam`. First launch of the renamed build auto-migrates on-disk data from the old hermes paths. No permanent compat aliases. The only surviving `hermes` string in Lliam-owned code is inside the one-time migration routine. |
| D3 | Plan scope | **Controls + rename only** | AI-326 (signed/notarized multi-platform distribution) stays its own workstream and runs *after* Phase 6. Phase R still updates the Electron app's identifiers and build config because the rename requires it. |
| D4 | Upstream attribution | **Preserve, never rename** | `NOTICE`, `ATTRIBUTION.md`, `LICENSE`, and "Built on Hermes Agent by Nous Research (MIT)" credit lines are **out of rename scope**. The rename touches Lliam's *own* identity, not the upstream credit. This is a correctness requirement, not a nicety — MIT attribution is a license obligation. |
| D5 | Runtime identifier surface | CLI `lliam-gov` (honors AI-341); short alias `lliam`; data dir `~/.lliam`; env prefix `LLIAM_`; product display `Lliam-GOV`; Electron appId `com.secondorderstrategy.lliam-gov` **(CONFIRMED by Jerome 2026-07-02)** | See §R naming table. appId locked to `com.secondorderstrategy.lliam-gov` — it keys the macOS Keychain, update feed, and code signature; R.7 no longer needs a confirmation step, just applies it. |

### The PATH-FREEZE resolution (why rename-early is safe here)

Every Rev4 issue carries: *"PATH-FREEZE (additive only — never rename existing Hermes/Lliam modules, files, CLI commands, or identifiers)."* That constraint exists because an **interleaved** rename — renaming modules while simultaneously landing behavior changes — is what broke earlier builds (per AI-507). Rename-early removes the conflict entirely: Phase R is a **pure, behavior-preserving, test-gated rename with zero control logic in flight**. Once `gov-R-good` is tagged, PATH-FREEZE is re-imposed verbatim for P1–P6, and every subsequent issue's "never rename" clause is satisfied because there is nothing left named `hermes` to rename. The Linear issues' branch names (`harden/phase-1-identity-audit`, etc.) and module references get a one-time search-replace as the final step of Phase R so P1+ builders find the paths they expect.

---

## Phase order & gating

```
PRE  → land AI-522 (P0.1 verify PR) + AI-326 (deploy PR) → confirm gov-P0-good tag exists
R    → hermes→lliam rename (core + Electron + data migration)      → tag gov-R-good     [PATH-FREEZE lifted here only]
P1   → Identity, Audit & Accountability   (AI-516,517,518,519,520,479,480)  → tag gov-P1-good
P2   → Authorization, Oversight & Egress  (AI-481…487)             → tag gov-P2-good
P3   → Supply Chain & Provider Governance (AI-488…492)             → tag gov-P3-good
P4   → Management System, Risk & Impact   (AI-493…498)             → tag gov-P4-good
P5   → Continuous Monitoring & cATO       (AI-499…503)             → tag gov-P5-good
P6   → Promotion / Cutover to Live        (AI-505,507,509)         → tag gov-P6-good
(then AI-326 DEPLOY packages the hardened, renamed build — separate workstream)
```

**Every phase, no exceptions:** work in a dedicated clone on the phase branch with an isolated `LLIAM_HOME` (your live install stays untouched until P6); small reviewable commits; the path-freeze CI guard must pass (P1+); write a verification report to `docs/governance/verification/<step>-report.md`; the `.V` verify gate must prove **hardened AND still capable** before the `gov-PN-good` tag is pushed.

---

# PRE-FLIGHT

### Task PRE.1: Land open work and confirm the baseline

**Files:** none (git/CI operations)

- [ ] **Step 1: Confirm the two open PRs are merged or explicitly deferred**

```bash
cd ~/dev/lliam-gov 2>/dev/null || git clone git@github.com:jdavis-cyber/lliam-gov.git ~/dev/lliam-gov && cd ~/dev/lliam-gov
gh pr list --state open   # expect AI-522 (P0.1 verify) and AI-326 (deploy) — merge or note as parallel
```

Expected: both PRs merged to `main`, OR a written note in the phase-R report that they proceed in parallel and Phase R rebases on them.

- [ ] **Step 2: Confirm Phase 0 is complete** — ✅ **verified 2026-07-02: `gov-P0-good` is present on canonical `main`**, and `docs/governance/verification/P0.1–P0.V-report.md` + `policy/` scaffolds + deny-listed godmode (`policy/skills-allowlist.yaml`) are in place. Re-confirm after cloning:

```bash
git tag | grep gov-P0-good     # present on canonical — P1's ledger extends Phase-0 redaction/tool_policy
```

If somehow absent, STOP — the Rev4 spine assumes Phase 0's hardened baseline (permissive defaults handled via the overlay, godmode deny-listed, tool_policy scaffold). Do not proceed.

- [ ] **Step 3: Full green test baseline + tag the pre-rename restore point**

```bash
python scripts/run_tests_parallel.py 2>&1 | tee /tmp/pre-rename-pytest.log
cd apps/desktop && npm ci && npm run test:ui && cd ../..
git tag pre-rename-baseline && git push origin pre-rename-baseline
```

Expected: test suite at its known-green state (record the pass/fail count as the noise floor; the rename must not regress it). This tag is the rollback point for the entire rename.

---

# PHASE R — Hermes → Lliam rename (core + Electron + data)

> **PATH-FREEZE is LIFTED for this phase only.** Behavior-preserving rename, no control logic. Branch: `rename/hermes-to-lliam`. The safety net is the full test suite (green at `pre-rename-baseline`) run after every sub-task — the rename is correct iff the suite stays green and a fresh-clone governed install still launches.

## ⚑ How a non-developer steers this phase (read this first)

**You do not need to read code to keep this on the rails.** This rename touches thousands of references — nobody, human or AI, renames them by working through a checklist by hand. Instead the plan uses two automatic machines that *you can see the result of*, and the rule is that a red result is not allowed to be called "done."

**The two machines:**
1. **The test suite (a tripwire).** The app ships with ~850 automated tests. After *every* rename step the agent must run the whole suite. If a rename missed something, a test turns **red** — the miss is caught instantly and automatically. The app cannot be "quietly broken"; broken shows up as red.
2. **The guard test (a completeness check).** It scans the entire repo and only passes when zero to-be-renamed `hermes` references remain (attribution, generated files, and audit logs excluded). It turning **green** *is* the definition of "the rename is complete." That is your coverage guarantee, done by a machine instead of by hoping a list was complete.

**Your three levers — no coding required:**
- **The one question at every checkpoint:** *"Did the full test suite pass — yes or no?"* If the answer is anything but a clean yes, it is **not done**. You never have to understand a failure; you just decline to accept "finished" without a green. A good agent will show you the pass/fail line.
- **The undo button:** before any renaming, Task PRE.1 tags a restore point called **`pre-rename-baseline`** — a photograph of the app while it fully works. If anything ever looks wrong, say **"roll back to the pre-rename-baseline"** and the app returns to that exact working state. Nothing in this phase is one-way.
- **The blessing gate:** the rename is not trusted until the **`gov-R-good`** tag exists, and that tag is only allowed after a *fresh copy* of the app installs and launches cleanly on its own. Until you see that tag, treat the rename as in-progress.

**What "done" looks like, in plain words:** the guard test is green, the full test suite is green (same as before we started), a brand-new copy of the app opens and runs, and the desktop app's window opens and talks to its backend. All four, or it's not done.

### Naming map (the single source of truth for every substitution)

| Category | Old (hermes) | New (lliam) | Rename kind |
|----------|--------------|-------------|-------------|
| pip distribution | `hermes-agent` | `lliam-gov-agent` | code |
| Python pkg dir | `hermes_cli/` | `lliam_cli/` | `git mv` + imports |
| Root modules | `hermes_constants.py`, `hermes_logging.py`, `hermes_time.py`, `hermes_bootstrap.py`, `hermes_state.py` | `lliam_*.py` | `git mv` + imports |
| Console scripts | `hermes`, `hermes-agent`, `hermes-acp` | `lliam-gov`, `lliam-gov-agent`, `lliam-gov-acp` (+ short `lliam`→`lliam-gov`) | pyproject |
| argparse prog | `hermes` | `lliam-gov` | code |
| Env var prefix | `HERMES_*` (HERMES_HOME, HERMES_CONFIG, HERMES_PROFILE, HERMES_WRITE_SAFE_ROOT, HERMES_DESKTOP_*, HERMES_ACCEPT_HOOKS, …) | `LLIAM_*` | code + migration |
| Data home (POSIX) | `~/.hermes/` | `~/.lliam/` | migration |
| Data home (Windows) | `%LOCALAPPDATA%\hermes\` | `%LOCALAPPDATA%\lliam\` | migration |
| Config keys | `security.tirith_*`, `tool_loop_guardrails.*` (unprefixed — mostly safe) | unchanged unless prefixed `hermes` | audit only |
| Electron npm name | `hermes` / `@hermes/shared` / `@hermes/ink` (`packages/hermes-ink`) | `lliam-gov` / `@lliam-gov/shared` / `@lliam-gov/ink` | package + workspace — **PENDING** |
| Electron productName | ~~`Hermes`~~ **already `Lliam-GOV` on canonical** | — | ✅ **DONE (verify only, do not re-change)** |
| Electron `executableName` | ~~`Hermes`~~ **already `Lliam-GOV`** | — | ✅ **DONE (verify only)** |
| Electron appId | `com.nousresearch.hermes` | `com.secondorderstrategy.lliam-gov` (CONFIRMED, D5) | build + Keychain + updater — **PENDING** |
| macOS bundle | `CFBundleName/Executable/DisplayName` — **check each; some may already be Lliam-GOV** | `Lliam-GOV` | build config — verify then fix any residual |
| IPC channels | `hermes:bootstrap:get`, `hermes:*` | `lliam:*` | code (both sides) — **PENDING** |
| Custom protocol | `hermes-media://` **and the scheme named `"Hermes Protocol"`** | `lliam-media://` / `"Lliam-GOV Protocol"` | code (both sides) — **PENDING** |
| TS files | `apps/desktop/src/hermes.ts`, `src/types/hermes.ts`, `src/app/session/hooks/use-hermes-config.ts` | `lliam.ts` / `use-lliam-config.ts` | `git mv` + imports |
| Desktop image assets | `apps/desktop/public/hermes.png`, `hermes-sprite.png`, `hermes-frames/hermes-frame-*.png` | `lliam*.png` | `git mv` + update every reference in code/CSS |
| Docker service defs | `docker/s6-rc.d/main-hermes/`, `docker/hermes-exec-shim.sh`, `setup-hermes.sh` | `main-lliam` / `lliam-exec-shim.sh` / `setup-lliam.sh` | `git mv` + update service refs |
| Packaging manifests | `packaging/homebrew/hermes-agent.rb`, `nix/hermes-agent.nix`, `scripts/hermes-gateway`, `MANIFEST.in`, `Dockerfile`, `flake.nix` | `lliam-gov-agent.*` / `lliam-gov-gateway` | `git mv` + edit |
| Keychain service | `hermes` / `com.nousresearch.hermes` | new appId | migration |
| **Upstream credit** | "Hermes Agent", "Nous Research", NOTICE/ATTRIBUTION | **UNCHANGED (D4)** | **do not touch** |
| **Generated / historical (NEVER rename)** | `graphify-out/`, `build/`, `dist/`, `*.egg-info/`, `evidence/` audit logs, `uv.lock`/`package-lock.json` | regenerate (graphify/build/lock) or leave frozen (evidence) | **excluded from rename + guard test** |

> **Scope carve-out (added 2026-07-02 after measuring the real repo — see Appendix A):** the raw repo has **3,948 files** mentioning `hermes`, but ~1,080 of those are *generated output* (`graphify-out/`, `build/`, `dist/`, `*.egg-info/`) and ~20+ are *historical `evidence/` audit logs*. **Generated output is regenerated, never hand-renamed. Audit logs are frozen — editing a historical audit record is evidence tampering and is forbidden.** After those exclusions the true rename surface is **~2,865 files**, and only the handful with `hermes` in their *filename* (Appendix A) need a `git mv`; the rest are text references the sweep + guard test cover.

### Task R.0: Build the rename inventory as a test fixture

**Files:** Create `tests/rename/test_no_hermes_identifiers.py`, `scripts/rename/inventory.sh`

- [ ] **Step 1: Write the inventory script** (separates Lliam-owned refs from upstream-attribution refs)

```bash
# scripts/rename/inventory.sh
#!/usr/bin/env bash
# Lliam-owned hermes identifiers (must reach 0 except the migration routine).
# EXCLUDES: (a) upstream attribution — D4, license obligation;
#           (b) generated output — regenerated, never hand-renamed;
#           (c) historical evidence/audit logs — frozen, editing them is tampering.
# These exclusion globs MUST match the guard test below exactly.
rg -i --stats hermes \
  -g '!**/node_modules/**' -g '!**/.git/**' -g '!**/dist/**' -g '!**/build/**' \
  -g '!**/*.egg-info/**' -g '!graphify-out/**' -g '!evidence/**' \
  -g '!**/*.lock' -g '!**/package-lock.json' \
  -g '!NOTICE' -g '!ATTRIBUTION*' -g '!LICENSE*' -g '!docs/upstream/**' \
  .
```

The same exclusion set is reused everywhere in Phase R. Define it once as a shell array so the inventory script, the guard test, and the "full suite green" checks can't drift apart:

```bash
# scripts/rename/exclude_globs.sh  — sourced by the other rename scripts
HERMES_EXCLUDES=(
  -g '!**/node_modules/**' -g '!**/.git/**' -g '!**/dist/**' -g '!**/build/**'
  -g '!**/*.egg-info/**' -g '!graphify-out/**' -g '!evidence/**'
  -g '!**/*.lock' -g '!**/package-lock.json'
  -g '!NOTICE' -g '!ATTRIBUTION*' -g '!LICENSE*' -g '!docs/upstream/**'
)
```

- [ ] **Step 2: Write the guard test** (this is the definition of "rename complete"). Its exclusion list is the same set — keep the two in sync; if you add an exclusion in one, add it in both.

```python
# tests/rename/test_no_hermes_identifiers.py
import subprocess

# Exclusions MUST mirror scripts/rename/exclude_globs.sh
EXCLUDES = [
    "-g", "!**/node_modules/**", "-g", "!**/.git/**", "-g", "!**/dist/**",
    "-g", "!**/build/**", "-g", "!**/*.egg-info/**", "-g", "!graphify-out/**",
    "-g", "!evidence/**", "-g", "!**/*.lock", "-g", "!**/package-lock.json",
    "-g", "!NOTICE", "-g", "!ATTRIBUTION*", "-g", "!LICENSE*", "-g", "!docs/upstream/**",
]
ALLOWED = {
    # the one-time migration routine is the sole Lliam-owned file allowed to name the old path
    "lliam_cli/migrate_home.py",
    # keep for one release if the HERMES_ env fallback is retained (R.8 decision); else remove
    "lliam_cli/env_compat.py",
}

def test_no_lliam_owned_hermes_refs():
    out = subprocess.run(
        ["rg", "-il", "hermes", *EXCLUDES, "."],
        capture_output=True, text=True).stdout.split()
    offenders = [f for f in out if f.lstrip("./") not in ALLOWED]
    assert not offenders, f"Lliam-owned hermes identifiers remain: {offenders}"
```

- [ ] **Step 3: Run it — expect FAIL listing the real code surface (~2,865 files, per Appendix A).** `pytest tests/rename/test_no_hermes_identifiers.py -v`. This test going green is the exit criterion for R.8. Commit the fixture. `git commit -m "test(rename): add hermes-identifier guard (currently red)"`

### Task R.1: Data-home + env-var layer with one-time migration (do this FIRST — everything else depends on it)

**Files:** Create `lliam_cli/migrate_home.py`; Modify `hermes_constants.py` (→ becomes `lliam_constants.py` in R.2, but edit in place now)

- [ ] **Step 1: Failing test — new home resolves, old data migrates once**

```python
# tests/rename/test_home_migration.py
import os, pathlib
from lliam_cli import migrate_home   # module exists after this task

def test_migrates_old_home_when_new_absent(tmp_path, monkeypatch):
    old = tmp_path / ".hermes"; new = tmp_path / ".lliam"
    (old / "sessions").mkdir(parents=True); (old / "config.yaml").write_text("k: v")
    monkeypatch.setattr(migrate_home, "OLD_HOME", old)
    monkeypatch.setattr(migrate_home, "NEW_HOME", new)
    migrate_home.migrate_if_needed()
    assert (new / "config.yaml").read_text() == "k: v"
    assert (new / ".migrated_from_hermes").exists()

def test_noop_when_new_exists(tmp_path, monkeypatch):
    old = tmp_path / ".hermes"; new = tmp_path / ".lliam"
    old.mkdir(); new.mkdir()
    monkeypatch.setattr(migrate_home, "OLD_HOME", old)
    monkeypatch.setattr(migrate_home, "NEW_HOME", new)
    migrate_home.migrate_if_needed()   # must not raise, must not overwrite
    assert not (new / ".migrated_from_hermes").exists()
```

- [ ] **Step 2: Implement `lliam_cli/migrate_home.py`** (the ONLY file allowed to name `hermes`)

```python
"""One-time migration of on-disk data from the pre-rename ~/.hermes home.
This is the sole Lliam-owned module permitted to reference the old identifier."""
import os, shutil
from pathlib import Path

OLD_HOME = Path(os.path.expanduser("~/.hermes"))
NEW_HOME = Path(os.path.expanduser("~/.lliam"))

def migrate_if_needed() -> None:
    if NEW_HOME.exists() or not OLD_HOME.exists():
        return
    shutil.copytree(OLD_HOME, NEW_HOME)          # copy, don't move — leave rollback source intact
    (NEW_HOME / ".migrated_from_hermes").write_text("migrated by Lliam-GOV rename\n")
```

- [ ] **Step 3: Wire env-var fallback during the migration window.** In the home-resolution code (currently `hermes_constants.py`), read `LLIAM_HOME` first, fall back to `HERMES_HOME` if set (so an operator mid-transition isn't stranded), default to `~/.lliam`. Call `migrate_home.migrate_if_needed()` at startup before any home access. Apply the same LLIAM_→HERMES_ read-fallback for every `HERMES_*` env var via a small helper `getenv_compat("HOME", ...)`.

```python
def getenv_compat(suffix: str, default: str | None = None) -> str | None:
    return os.getenv(f"LLIAM_{suffix}") or os.getenv(f"HERMES_{suffix}") or default
```

- [ ] **Step 4: Tests PASS; run full suite — still green.** `pytest tests/rename/test_home_migration.py -v && python scripts/run_tests_parallel.py`. Commit. `git commit -m "feat(rename): LLIAM_ home + one-time ~/.hermes migration with env fallback"`

**Note:** the `HERMES_*` fallback reads are a transition aid, not a permanent alias — they live only in `getenv_compat` and are removed at R.8's cleanup once the guard test is otherwise green (the helper itself is allowlisted like `migrate_home`, or inlined and dropped). Decide at R.8 whether to keep the fallback for one release (safer for any operator scripts) or drop it (cleaner). Recommend keep-for-one-release, documented in the rename report.

### Task R.2: Rename Python packages, root modules, and imports

**Files:** `git mv` `hermes_cli/`→`lliam_cli/`, `hermes_*.py`→`lliam_*.py`; update all imports repo-wide

- [ ] **Step 1: Move directories and modules with git (preserves history)**

```bash
git mv hermes_cli lliam_cli
for m in constants logging time bootstrap state; do git mv hermes_$m.py lliam_$m.py; done
```

- [ ] **Step 2: Rewrite imports and references** (mechanical, but scoped — NOT the attribution files)

```bash
# import paths and module refs only
rg -l --type py 'hermes_cli|hermes_constants|hermes_logging|hermes_time|hermes_bootstrap|hermes_state' \
  -g '!docs/upstream/**' \
  | xargs sed -i '' -E \
    -e 's/hermes_cli/lliam_cli/g' \
    -e 's/hermes_(constants|logging|time|bootstrap|state)/lliam_\1/g'
```

- [ ] **Step 3: Run the full suite — expect green** (imports are the highest-risk category; the suite is the proof). `python scripts/run_tests_parallel.py`. Fix any missed dynamic imports (`importlib`, string module paths in config, plugin manifests) until green.

- [ ] **Step 4: Commit.** `git commit -m "refactor(rename): hermes_cli->lliam_cli + root hermes_*.py->lliam_*.py"`

### Task R.3: Entry points, CLI prog-name, config keys

**Files:** Modify `pyproject.toml`, `setup.py` (if live), `cli.py`, the `hermes` bash shim

- [ ] **Step 1: pyproject scripts + package name**

```toml
# pyproject.toml
[project]
name = "lliam-gov-agent"          # was hermes-agent
[project.scripts]
lliam-gov = "lliam_cli.main:main"        # was hermes
lliam-gov-agent = "run_agent:main"       # was hermes-agent
lliam-gov-acp = "acp_adapter.entry:main" # was hermes-acp
```

- [ ] **Step 2: argparse prog + rename the bash shim** — `git mv hermes lliam-gov`; inside it and in `cli.py` set `prog="lliam-gov"`. Grep help/usage strings for a hardcoded `hermes` program name.

- [ ] **Step 3: Editable reinstall + smoke the CLI**

```bash
uv pip install -e . && lliam-gov --help && lliam-gov version
```

Expected: help renders with `lliam-gov` usage; version prints; no `hermes` in the usage line. Commit. `git commit -m "refactor(rename): console scripts + prog-name -> lliam-gov"`

### Task R.4: Electron core identifiers + build config

**Files:** Modify `apps/desktop/package.json`, `apps/desktop/electron/entitlements.mac.plist`, build scripts under `apps/desktop/scripts/`

- [ ] **Step 1: package.json name/productName/appId/bundle**

```json
{
  "name": "lliam-gov",
  "productName": "Lliam-GOV",
  "build": {
    "appId": "com.secondorderstrategy.lliam-gov",
    "executableName": "Lliam-GOV",
    "artifactName": "Lliam-GOV-${version}-${os}-${arch}.${ext}",
    "mac": { "CFBundleDisplayName": "Lliam-GOV", "CFBundleName": "Lliam-GOV", "CFBundleExecutable": "Lliam-GOV",
             "NSMicrophoneUsageDescription": "Lliam-GOV uses the microphone for voice input." },
    "win": { "shortcutName": "Lliam-GOV" },
    "linux": { "synopsis": "Native desktop shell for Lliam-GOV (governed Hermes Agent fork)." }
  }
}
```

- [ ] **Step 2: Update the `@hermes/*` workspaces** — `git mv packages/hermes-ink packages/lliam-gov-ink`; rename `@hermes/shared`→`@lliam-gov/shared`, `@hermes/ink`→`@lliam-gov/ink` in every `package.json` `name` + dependency reference and every TS import.

```bash
rg -l '@hermes/' apps packages -g '*.json' -g '*.ts' -g '*.tsx' | xargs sed -i '' 's|@hermes/|@lliam-gov/|g'
```

- [ ] **Step 3: `npm ci` from clean + typecheck + UI tests** — `cd apps/desktop && rm -rf node_modules && npm ci && npm run build && npm run test:ui`. Expected: builds and unit tests green. Commit. `git commit -m "refactor(rename): electron app identity + @hermes->@lliam-gov workspaces"`

### Task R.5: Electron IPC channels, protocol handler, desktop env vars

**Files:** Modify `apps/desktop/electron/main.cjs`, `apps/desktop/src/hermes.ts`→`lliam.ts`, `src/types/hermes.ts`→`types/lliam.ts`, preload/renderer

- [ ] **Step 1: Rename IPC channels on BOTH sides** — every `ipcMain.handle("hermes:…")` and matching `ipcRenderer.invoke("hermes:…")` → `"lliam:…"`. These must change together or the renderer↔main bridge breaks silently. Grep both `electron/` and `src/`.

- [ ] **Step 2: Rename the custom protocol** `hermes-media://`→`lliam-media://` at registration (`protocol.registerSchemesAsPrivileged` / `registerFileProtocol` in main.cjs) and at every use site in the renderer. Rename `HERMES_DESKTOP_*` env vars → `LLIAM_DESKTOP_*` (the desktop spawns the Python subprocess with these — keep the `getenv_compat` fallback so a mid-transition subprocess still resolves them).

- [ ] **Step 3: `git mv` the TS files and fix imports** — `apps/desktop/src/hermes.ts`→`lliam.ts`, `src/types/hermes.ts`→`types/lliam.ts`, `src/global.d.ts` global type names.

- [ ] **Step 4: Build + launch the desktop app in dev, exercise the bridge** — `npm run dev` (or the repo's dev target), confirm the renderer reaches the Python backend (a prompt round-trips), video/media protocol loads, no console errors about missing `hermes:*` channels. This is the integration proof the IPC rename didn't break the shell. Commit. `git commit -m "refactor(rename): IPC channels, protocol, desktop env vars -> lliam"`

### Task R.6: Keychain / credential-store service names + migration

**Files:** Modify wherever the credential service name is set (search `keytar`, `keychain`, `service=`, `com.nousresearch.hermes` in both Python and Electron)

- [ ] **Step 1: Find the service identifier** — `rg -i 'keytar|keychain|com\.nousresearch\.hermes|service_name|SERVICE ='`. Credentials stored under the old service become invisible after the appId change.

- [ ] **Step 2: Add credential migration** — on first run under the new service name, if the new service has no entry and the old one does, copy the secret across (mirror the `migrate_home` pattern; this file is allowlisted or calls into `migrate_home`). If the store is file-based under `~/.lliam` it already moved in R.1 — verify which.

- [ ] **Step 3: Test credential round-trip** under the new service name (store→read), and the migration path (seed old→launch→read from new). Commit. `git commit -m "feat(rename): credential-store service rename + migration"`

### Task R.7: appId confirmation + signing/notarization identifiers

**Files:** `apps/desktop/package.json` build block, `scripts/notarize.cjs`, entitlements

- [ ] **Step 1: Apply the confirmed appId** `com.secondorderstrategy.lliam-gov` (locked by Jerome 2026-07-02, D5). It permanently keys the code signature, macOS Keychain service, and the electron-updater feed — do not change it later or installed clients and stored credentials orphan.
- [ ] **Step 2: Update notarize/sign config** to the confirmed appId and the correct Apple Developer ID / Authenticode identity (cert provisioning itself is AI-326's job — here just point the config at the right identifiers so an eventual signed build is coherent).
- [ ] **Step 3: Ad-hoc pack to prove the build config is internally consistent** — `npm run pack` (unsigned/ad-hoc). Expected: an artifact named `Lliam-GOV-<version>-...` is produced. Commit. `git commit -m "chore(rename): align signing/notarization identifiers to new appId"`

### Task R.8: User-visible strings, cleanup, and the guard test goes green

**Files:** TUI banners/help/setup prompts, dashboard titles, gateway message headers — Lliam-owned strings only

- [ ] **Step 1: Rename Lliam-owned visible strings** — banners, `--help` epilogs, setup-wizard prompts, window titles, gateway email/Slack headers that say "Hermes Agent" *as this product's name*. **Leave** every "Built on Hermes Agent by Nous Research" attribution and `docs/upstream/*` (D4).
- [ ] **Step 2: Decide the env fallback fate** (from R.1 note) — keep `getenv_compat` HERMES_ fallback for one release (recommended) or drop it. Add the chosen file(s) to the guard test's `ALLOWED` set if kept.
- [ ] **Step 3: Run the guard test — expect GREEN.** `pytest tests/rename/test_no_hermes_identifiers.py -v`. Any remaining offender is either a real miss (fix it) or legitimate attribution (add a `-g '!path'` exclusion with a comment). Commit. `git commit -m "refactor(rename): visible strings -> Lliam-GOV; guard test green"`

### Task R.9: Rename the phase branch references for P1+ and update governance docs

**Files:** `docs/governance/control-matrix.md` (owner module paths), CI workflow files, `.github/`

- [ ] **Step 1: Update control-matrix owner paths** — the matrix names `lliam_gov/security/*.py` (already lliam) but also `hermes_cli/web_server.py`, `hermes_cli/main.py`, `hermes_cli/security_advisories.py` as owners. Rewrite those to `lliam_cli/...` so P1–P6 evidence references resolve.
- [ ] **Step 2: Update CI workflow references** to renamed modules/scripts/package name (`.github/workflows/*.yml`, `upload_to_pypi.yml` package name, `docker-publish.yml` image name if it embeds `hermes`).
- [ ] **Step 3: Full suite + fresh-clone governed install proof**

```bash
python scripts/run_tests_parallel.py         # green, no regression vs pre-rename noise floor
cd /tmp && rm -rf lliam-freshclone && git clone ~/dev/lliam-gov lliam-freshclone && cd lliam-freshclone
uv pip install -e . && lliam-gov --help && lliam-gov version   # governed install works from clean clone
```

- [ ] **Step 4: Commit + open PR.** `git commit -m "chore(rename): matrix/CI paths -> lliam; fresh-clone verified"` then `gh pr create --base main --title "[R] hermes->lliam rename (core + electron + data migration)"`.

### Task R.V: Rename verify gate

- [ ] **Step 1: Prove renamed AND unbroken** — write `docs/governance/verification/R-rename-report.md` capturing: guard test green; full pytest green vs. pre-rename noise floor (no new failures); fresh-clone `lliam-gov --help`/`version` works; desktop `npm run build` + IPC round-trip works; `npm run pack` produces `Lliam-GOV-*` artifact; data-migration test green; **attribution files unchanged** (`git diff pre-rename-baseline -- NOTICE ATTRIBUTION.md LICENSE docs/upstream` is empty).
- [ ] **Step 2: Tag and re-impose PATH-FREEZE.** After merge: `git tag gov-R-good && git push origin gov-R-good`. From here, PATH-FREEZE is back in force — P1–P6 add only; nothing named lliam gets renamed again.

---
# GOVERNANCE PHASES P1–P6

> **Calibration note:** the Linear issues (AI-479…AI-520) already carry full, assessor-grade scope, controls, and DoD per step — this plan does **not** duplicate that detail. For each phase it gives: the branch, the ordered issue list with the one-line objective + the module/file each creates + the control family + the concrete verify check, and the phase's capability-preservation gate. **The builder opens the named Linear issue for the authoritative acceptance criteria and reference-doc pointers**, and implements test-first against them. Every issue's standing constraint is the re-imposed **PATH-FREEZE (additive only) · capability-preserving graduated enforcement (allow low / log medium / HITL high / deny only categorically-unsafe) · CUI floor = SP 800-171 r3 / CMMC L2.**

Each phase runs in the dedicated clone on its `harden/phase-N-*` branch with isolated `LLIAM_HOME`, small commits, path-freeze CI guard passing, a `docs/governance/verification/<step>-report.md` per step, and a PR to `jdavis-cyber/lliam-gov`. The `.V` gate must prove *hardened AND still capable* before the `gov-PN-good` tag is pushed.

---

## Phase 1 — Identity, Audit & Accountability  ·  branch `harden/phase-1-identity-audit`

The accountability engine: a hash-chained ledger wired at the one dispatch chokepoint, plus operator/agent identity, MFA, and the API-key gate. Ledger is **record-then-proceed** — it must add **zero** functional blocks.

| Issue | Objective | Creates / touches | Controls | Verify check (TDD target) |
|-------|-----------|-------------------|----------|---------------------------|
| **AI-516** P1.1 | Append-only hash-chained audit ledger | `agent/governance_audit.py`; `audit:` block in `cli-config.gov.yaml` | LG-AU-01..07,09 | Emit sample events → valid `prev_hash`+sha256 chain; ledger written to `$LLIAM_HOME/logs` (outside workspace, on write-denylist); redacted record shown; fail-closed on audit-write failure for high-risk |
| **AI-517** P1.2 | Wire ledger at dispatch chokepoint (100%) | dispatch `before_call`/`after_call` hooks | LG-AU-02,10; MC-03; QT-03 | Tool-Dispatch Audit Coverage Matrix = 100% of registered tools/skills/MCPs emit an event; output traceable to model/provider/prompt/skill version |
| **AI-518** P1.3 | Chain-integrity verification | `verify_chain()` in `governance_audit.py`; CI/cron gate under `ci/governance-ci-gates/` | LG-AU-08 | PASS on good ledger; tamper one record → FAIL at startup + in CI |
| **AI-519** P1.4 | Agent identity + managed credentials | `docs/governance/agent_identity.yaml`; `secret_scope` isolation | LG-IA-01..05,10 | Profile A credential invisible to profile B; agent identity bound to code+config+model hash; secrets from managed source (Bitwarden/1Password) |
| **AI-520** P1.5 | Operator authn, MFA, endpoint auth, API-key gate | dashboard/ACP login; `API_SERVER_KEY` in `.env.gov` | LG-IA-06..09,11 | Networked API refuses keyless request; MFA enforced on dashboard + ACP; provider/MCP call validates TLS/cert-pin |
| **AI-479** P1.6 | Roles, RACI & SoD bindings | `docs/governance/roles-raci.md`, `roles.yaml`; `role_bindings` in overlay | LG-GV-04,05 | `role_bindings` resolve to authenticated dashboard principals; SoD conflict report clean (Approver ≠ Engineer; Auditor independent) |

- [ ] **AI-480 P1.V — verify gate:** run the full §6 capability corpus; confirm **no new functional blocks** (ledger is record-then-proceed); all six exit criteria met. Write `P1-capability-preservation-report.md`; `git tag gov-P1-good && git push`.

**Sequencing inside P1:** AI-516 → AI-517 (needs ledger) → AI-518 (needs ledger) ; AI-519, AI-520, AI-479 can parallelize after 516; all feed AI-480.

---

## Phase 2 — Authorization, Oversight & Egress  ·  branch `harden/phase-2-authz-egress`

The graduated enforcement layer — *the* capability-preservation checkpoint. Low/medium risk must stay unblocked (no approval fatigue); only HIGH-risk, CUI-tainted egress, and hardline/sudo-stdin may newly block.

| Issue | Objective | Creates / touches | Controls | Verify check |
|-------|-----------|-------------------|----------|--------------|
| **AI-481** P2.1 | Tool-risk Policy Decision Point | `tools/tool_policy.py` (extend P0 scaffold); `policy/tool-risk-policy.yaml` | LG-AZ-01,06,07,08,10,12; RM-08 | Low-risk allow+log; high-risk → HITL; action-budget cap trips a runaway loop. **Draft the capability×impact tiering matrix here from the baseline overlay; AI-494 formalizes it** |
| **AI-482** P2.2 | Human-in-the-loop oversight gates | HITL approval gates bound to the PDP | LG-HO-01..10 | High-risk proceeds WITH approver, DENIED without; low/medium NOT gated; non-interactive auto-approve → fail-closed DENY; sudo-stdin unconditionally blocked |
| **AI-483** P2.3 | Prompt-injection defense + output handling | injection detector; tool-result classifier; sink validation | LG-PI-04,06,09 | Indirect-injection payload in a fetched page does NOT auto-trigger egress/exec — routes to HITL or blocked |
| **AI-484** P2.4 | Data protection, DLP taint-gate, encryption | `security.cui_redaction` pack; at-rest crypto wrapper; DLP taint module | LG-DP-01..11 | Secret redacted from provider prompt + ledger; CUI-tainted session cannot egress to non-allowlisted sink; at-rest encryption attested |
| **AI-485** P2.5 | Network egress boundary | `policy/egress-allowlist.yaml`; `deploy/docker-compose.gov.override.yml` (squid enclave); air-gap profile | LG-NE-01..06 | Allowlisted domain fetch succeeds; non-allowlisted domain + metadata endpoint blocked at proxy (deny-by-default); SSRF/private-IP always blocked |
| **AI-486** P2.6 | Memory governance | per-session partition; read/write split; retention TTL; secure purge | LG-MC-02,04..07 | Session A memory invisible to session B; critical write → HITL; TTL sweep purges expired entries |

- [ ] **AI-487 P2.V — verify gate:** full corpus incl. high-risk; **only** acceptable new blocks are (a) CUI-tainted egress to non-allowlisted sinks, (b) hardline/sudo-stdin, (c) high-risk with no approver. Any other broken capability → STOP. Write `P2-capability-preservation-report.md`; `git tag gov-P2-good`.

**Sequencing:** AI-481 (PDP) first — AI-482/483 bind to it; AI-484/485/486 parallelize; all feed AI-487.

---

## Phase 3 — Supply Chain & Provider Governance  ·  branch `harden/phase-3-supply-chain`

Only *non-allowlisted* routes may block. Authorized in-boundary providers (Bedrock GovCloud, Azure Gov, on-prem LM Studio/Ollama/vLLM) must route on all five paths; approved attested skills + least-privilege MCPs still load.

| Issue | Objective | Creates / touches | Controls | Verify check |
|-------|-----------|-------------------|----------|--------------|
| **AI-488** P3.1 | Approved-provider allowlist, all 5 routing paths | `policy/provider-allowlist.yaml`; validator in `runtime_provider`/`fallback_config`/`moa_config` (additive) | LG-MP-01..04,08; GV-09 | Multi-path conformance test: approved provider routes on primary/fallback/MoA-ref/MoA-agg/delegation; non-allowlisted base_url fail-closed on each; no silent non-US route |
| **AI-489** P3.2 | Model integrity: cards, attestation, ban pickle | `docs/governance/model-cards/` + `model-cards.yaml`; `model_manifest.yaml`; load-time serialization guard | LG-MP-05..08 | Cardless model refused for CUI; pickle/.pt-without-weights_only refused; attestation mismatch blocks a high-impact action |
| **AI-490** P3.3 | MCP & skill supply-chain vetting | `policy/mcp-allowlist.yaml`; skill attestation; `docs/governance/supplier-vetting-register.md` | LG-SC-03..05,07..09; TP-03 | Allowlisted least-privilege MCP loads/functions; non-allowlisted or write-broad server rejected; unsigned skill refused; TLS/mTLS + origin/payload limits on HTTP MCP |
| **AI-491** P3.4 | Supply-chain CI gates + SBOM/AI-BOM | OSV scan gate; `.pth`/base64-exec/install-hook block; SBOM + machine-readable AI-BOM (extend P0 gates) | LG-SS-02..06; IN-02,03 | OSV gate fails on a seeded vulnerable dep; SBOM + AI-BOM artifacts produced + reconciled to baseline |

- [ ] **AI-492 P3.V — verify gate:** authorized in-boundary provider routes on every path; approved skill + allowlisted MCP still function; only non-allowlisted provider / unsigned skill / pickle load block. Write `P3-capability-preservation-report.md`; `git tag gov-P3-good`.

---

## Phase 4 — Management System, Risk & Impact  ·  branch `harden/phase-4-mgmt-system`

Mostly adapting the already-written assessor-ready GOV-package docs into the repo and **binding each to a real enforced config point** — no new runtime blocks; the only new "block" is CI failing a non-compliant change.

| Issue | Objective | Creates / touches | Controls | Verify check |
|-------|-----------|-------------------|----------|--------------|
| **AI-493** P4.1 | Top-management policy + authorization registers | `ai-policy.md`; `regulatory-register.yaml`; `authorization-record.yaml`; `waiver-register.yaml`; `governance:` block | LG-GV-01,03,06,10 (DFARS, 800-171r3, CMMC L2, OMB M-25-21) | Registers version-controlled; regulatory register's control bindings resolve to real enforced config points |
| **AI-494** P4.2 | Risk, impact assessment, SoA & POA&M | `risk-assessment-process.md`; `threat-risk-register.yaml`; **capability×impact tiering matrix (the one the P2 PDP consumes)**; `SoA.md`; `poam.yaml` | LG-RM-01..07,09 | SoA lists **all 188 controls** w/ applicability+status; godmode excluded w/ justification; tiering matrix == the one AI-481's PDP loads; high-impact (M-25-21) determination has a signature block |
| **AI-495** P4.3 | System inventory + SSP | `boundary-scope.md`; asset/CUI maps; host inventory; `docs/governance/SSP.md` | LG-IN-01,04..07 | Every 800-171 r3 family in the SSP cites a **real, enforced** config point (reconciled to P0–P3) |
| **AI-496** P4.4 | QMS + privacy/bias + fairness CI gate | QMS process maps; privacy registers; bias register (SP 1270); fairness CI gate | LG-QT-01..09; PF-01..07 | Fairness gate runs in CI; AI-disclosure/privacy notice present; nonconforming-output control documented |
| **AI-497** P4.5 | Secure-development governance + personnel/supplier | traceability matrix; V&V gates; `CODEOWNERS` + branch protection; red-team suite; go/no-go checklist; training register | LG-SD-02..08; TP-01,02,04,08 | V&V + prompt-injection red-team corpus run in CI; CODEOWNERS + branch protection enforced; evidence register indexes artifacts |

- [ ] **AI-498 P4.V — verify gate:** docs **reconcile to enforcement** (SSP → real config points; SoA excludes godmode; high-impact determinations signed); fairness CI + V&V PASS without forcing capability rollback; no new *runtime* block. Write `P4-capability-preservation-report.md`; `git tag gov-P4-good`.

**Coupling:** AI-494's tiering matrix must equal the one AI-481 drafted — reconcile them here. AI-495 SSP requires P0–P3 enforcement in place to cite.

---

## Phase 5 — Continuous Monitoring & cATO  ·  branch `harden/phase-5-monitoring-cato`

Turns the ledger into a live monitored control plane and produces the **final assessor-ready baseline (188 controls)**. No false auto-suspensions on steady state; scheduled kill-switch test must halt then cleanly restore full capability.

| Issue | Objective | Creates / touches | Controls | Verify check |
|-------|-----------|-------------------|----------|--------------|
| **AI-499** P5.1 | ISCM/SIEM streaming + runtime monitors | `monitoring.iscm_sink` in `governance_audit.py`; anomaly/drift/runaway monitors | LG-MO-01..06 | Events reach SIEM sink; injected egress anomaly + injected runaway loop both alert; near-real-time notify named staff |
| **AI-500** P5.2 | Scheduled red-team + control-effectiveness cron | scheduled adversarial eval; control-effectiveness verifier; output monitoring | LG-MO-07..10; PF-08,09 | Scheduled red-team job runs + reports; effectiveness job confirms godmode-disabled + allowlists enforced + audit-integrity |
| **AI-501** P5.3 | Incident response, kill-switch & recovery | kill-switch/containment/circuit-breaker; IR runbook | LG-IR-01..09 (DFARS/DIBNet 72-hr) | Kill-switch → tool exec + inference halt; recover to last signed-tag baseline; `verify_chain()` PASS before re-enable |
| **AI-502** P5.4 | cATO loop + autonomy classification + reciprocity export | cATO re-auth tied to ISCM; L0–L5 autonomy tiers; portable attestation export | LG-GV-07,08; TP-05..07 | Injected posture-break/drift → auto-suspend; portable signed attestation export produced |

- [ ] **AI-503 P5.V — FINAL verify gate:** entire standing corpus; NO false auto-suspensions; scheduled kill-switch test halts + cleanly restores; cATO auto-suspends only on real injected drift. Write `FINAL-hardening-completion-report.md` — control-by-control status for **all 188**, per-phase capability reports, outstanding POA&M, go/no-go. This is the assessor-ready hardened baseline. `git tag gov-P5-good`.

---

## Phase 6 — Promotion / Cutover to Live  ·  branch `harden/phase-6-cutover`

> **This phase operates ON the live install** (the "isolated LLIAM_HOME" execution header from the issue template does NOT apply here — that's boilerplate carryover; P6 by design touches `~/.lliam`). Because hardening was additive + path-frozen, promotion is *update-to-a-newer-commit-of-the-same-fork + enable the overlay* — **not a re-fork** — so it does not trigger rename fragility (the rename already happened in Phase R and is baked into `gov-P5-good`).

- [ ] **AI-505 P6.1 — Pre-cutover backup + restore point.** HARD STOP: only after `gov-P0-good … gov-P5-good` all exist and are pushed. Copy `~/.lliam` → `~/.lliam.pre-harden-backup`; copy `~/Library/Application Support/Lliam-GOV` → `.pre-harden-backup` sibling; tag live checkout `pre-harden-live`. Report all three restore points; do NOT proceed until confirmed.
- [ ] **AI-507 P6.2 — Promote verified baseline to live.** In the live checkout: `git fetch` + checkout `gov-P5-good`; place overlay (`cli-config.gov.yaml`, `policy/` allowlists, `deploy/` override, `docs/governance/`) in the live home; merge real credentials into `.env.gov`; enable overlay permanently via `export LLIAM_CONFIG=$LLIAM_HOME/cli-config.gov.yaml` + `.env.gov` levers (`LLIAM_REDACT_SECRETS`, `LLIAM_WRITE_SAFE_ROOT`, `API_SERVER_KEY`, …) in shell profile; if using the desktop GUI, rebuild (`npm run pack` + ad-hoc codesign) — **no productName/identifier changes (they're already Lliam from Phase R)**. Confirm `LLIAM_CONFIG` resolves the overlay in a fresh login shell.
- [ ] **AI-509 P6.V — Cutover verification + rollback drill.** Prove on the LIVE app: (A) HARDENED — godmode/offensive disabled, deny-by-default egress, provider allowlist enforced, ledger writing + `verify_chain()` PASS, strict posture active; (B) STILL CAPABLE — full corpus (safe-root coding, CUI-marked analysis, approved-provider call, allowlisted web/MCP call, high-risk action with approver); (C) ROLLBACK DRILL — unset `LLIAM_CONFIG` → stock behavior; re-enable; confirm `~/.lliam.pre-harden-backup` intact; (D) write `P6-cutover-record.md`, keep `pre-harden-live` + backups ≥30 days. `git tag gov-P6-good`.

---

# After this plan

- **AI-326 DEPLOY** (separate workstream, per D3): package the hardened, renamed `gov-P6-good` build as a signed/notarized multi-platform release — Apple Developer ID + Authenticode cert provisioning, release CI (checksums, SBOM, provenance), fresh-machine QA smoke matrix. The Phase-R appId (R.7) and signing-identifier alignment feed directly into it.
- **Katmai AIMS integration** (already partly Done — WBS LG-6.1..6.4): the `FINAL-hardening-completion-report.md` (P5.V) and the AEP evidence exports become the Lliam-GOV evidence in the Katmai ISO 42001 Audit NotebookLM and the AIMS asset inventory.

# Traceability — this plan ↔ Linear

| Plan phase | Linear issues | Status at plan time |
|-----------|---------------|---------------------|
| PRE | AI-522 (In Review), AI-326 (In Review) | land / note parallel |
| R (rename) | **AI-341** (revived to Backlog 2026-07-02) | rescoped in Linear to Electron + data migration + guard test |
| P1 | AI-516,517,518,519,520,479,480 | Backlog |
| P2 | AI-481,482,483,484,485,486,487 | Backlog |
| P3 | AI-488,489,490,491,492 | Backlog |
| P4 | AI-493,494,495,496,497,498 | Backlog |
| P5 | AI-499,500,501,502,503 | Backlog |
| P6 | AI-505,507,509 | Backlog |

**Done 2026-07-02:** AI-341 un-archived (Backlog) and rescoped in Linear to match Phase R (core + Electron IPC/appId/data-migration + guard test); working branch `rename/hermes-to-lliam`.

---

# Appendix A — Rename inventory (measured 2026-07-02)

> **Why this appendix exists:** so there is a *ground-truth* reference instead of an estimate, and so a non-developer can see the shape of the job. **This is not a hand-checklist to work through** — the sweep (`git mv` + search-replace) plus the guard test in Task R.0 are what guarantee completeness. This appendix's job is (1) to show the scale honestly, and (2) to list the files whose *name* contains `hermes`, because those are the ones a careless agent is most likely to miss (a missed filename breaks imports; a missed text reference usually breaks a test — both caught by the suite, but the named files deserve explicit eyes).

## Scale

*(Measured against canonical `main` HEAD `7a945c4`, 2026-07-02. The earlier draft's 3,948/2,865 figures were from the stale mirror and are superseded.)*

| Measure | Count | Note |
|---------|-------|------|
| Generated output (`graphify-out/`, `build/`, `dist/`, `*.egg-info/`) | excluded | regenerate, never rename |
| Historical `evidence/` audit logs | excluded | frozen; editing them is tampering |
| **Real rename surface (code, config, docs, tests, website, assets)** | **3,428** | what the guard test targets (canonical) |
| Files living under `hermes`-named *paths* (moved by the dir renames below) | **~820** | mostly members of `hermes_cli/`, `tests/hermes_cli/`, `ui-tui/packages/hermes-ink/`, `hermes-frames/` |

Regenerate the counts anytime with `bash scripts/rename/inventory.sh` (Task R.0). Note the canonical surface is **~20% larger** than the stale mirror and further along (Electron `productName`/`executableName` already `Lliam-GOV`; godmode already deny-listed) — so an agent must *verify current state before changing*, not assume the pre-rename values.

## Rename surface by area (canonical `main`, generated + evidence excluded)

| Area | Files | Kind |
|------|------:|------|
| `tests/` | 1222 | test references — the safety net itself; updated as code renames, caught if missed |
| `website/` | 683 | mostly visible text (some is upstream Hermes content — review, don't blind-replace) |
| `apps/` | 320 | Electron desktop + installer — IPC, assets, config hooks |
| `hermes_cli/` | 186 | **core CLI package** — the highest-value rename (`git mv` to `lliam_cli/`) |
| `plugins/` | 160 | plugin system |
| `skills/` + `optional-skills/` | 296 | skill definitions — **some describe upstream Hermes Agent; keep those (D4)** |
| `ui-tui/` | 104 | terminal UI (`@hermes/ink` workspace) |
| `agent/`, `tools/`, `gateway/`, `web/` | 287 | agent runtime + tool + gateway code |
| `scripts/`, `docs/`, `locales/`, `nix/`, `docker/`, `tui_gateway/`, `acp_adapter/`, `cron/` | ~115 | supporting + entry points + packaging |

## Files & directories whose NAME contains `hermes` (the `git mv` targets — most miss-prone)

**Directories (source only — `git mv` + fix imports/refs):**
- `hermes_cli/` → `lliam_cli/` **(core)**
- `ui-tui/packages/hermes-ink/` → `lliam-gov-ink/`
- `apps/desktop/public/hermes-frames/` → `lliam-frames/`
- `docker/s6-rc.d/main-hermes/` → `main-lliam/`
- `.github/actions/hermes-smoke-test/` → `lliam-smoke-test/`
- `plugins/hermes-achievements/` → `lliam-achievements/`
- `optional-skills/devops/hermes-s6-container-supervision/` → rename
- `tests/hermes_cli/`, `tests/hermes_state/` → track the module renames
- `skills/autonomous-ai-agents/hermes-agent/`, `skills/software-development/hermes-agent-skill-authoring/` → **REVIEW FIRST — these may be documentation *about* upstream Hermes Agent, which stays under D4. Rename only if they're Lliam's own, not upstream credit.**

**Root-level files:**
- `hermes` (bash shim) → `lliam-gov`
- `hermes_bootstrap.py`, `hermes_constants.py`, `hermes_logging.py`, `hermes_state.py`, `hermes_time.py` → `lliam_*.py`
- `setup-hermes.sh` → `setup-lliam.sh`
- `hermes-already-has-routines.md` → review (may be upstream doc)

**Desktop app files:**
- `apps/desktop/src/hermes.ts` → `lliam.ts`
- `apps/desktop/src/types/hermes.ts` → `types/lliam.ts`
- `apps/desktop/src/app/session/hooks/use-hermes-config.ts` → `use-lliam-config.ts`
- `apps/desktop/public/hermes.png`, `hermes-sprite.png`, `hermes-frames/hermes-frame-{0..7}.png` → `lliam*.png` (**and update every CSS/code reference to them**)
- `apps/bootstrap-installer/src-tauri/hermes-setup.manifest` → rename

**Docker / packaging / scripts:**
- `docker/hermes-exec-shim.sh`, `docker/s6-rc.d/**/main-hermes` refs
- `packaging/homebrew/hermes-agent.rb`, `nix/hermes-agent.nix`, `flake.nix`
- `scripts/hermes-gateway`, `agent/transports/hermes_tools_mcp_server.py`

**Generated copies — do NOT rename by hand (they regenerate):** `build/lib/hermes_*`, `*.egg-info/`, anything under `dist/`.

## The one judgment call an agent must not automate

`skills/`, `website/`, and a few root docs contain text that is *about* the upstream Hermes Agent project (its name, Nous Research credit). Under decision **D4** that content **stays** — it is license attribution, not Lliam's own identity. A blind global replace would erase required credit. The guard test's exclusions cover `NOTICE`/`ATTRIBUTION`/`LICENSE`/`docs/upstream`, but skill/website prose needs a human-or-careful-agent read: *"is this string Lliam naming itself, or Lliam crediting Hermes?"* Rename the former, keep the latter. When in doubt, keep it and flag it for Jerome — over-crediting the upstream is safe; erasing attribution is a license problem.
