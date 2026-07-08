# R.8e — Keep Register (guard-green justification)

| Field | Value |
|---|---|
| Task | R.8e-3c — token-level guard redesign + final residual sweep, drive guard GREEN |
| Branch | `rename/hermes-to-lliam` |
| Date | 2026-07-08 |
| Author | Lliam-GOV Program (R.8e-3c) |
| Guard | `tests/rename/test_no_hermes_identifiers.py` |
| Purpose | The assessor-facing record that **guard green == every surviving `hermes` token is a documented, justified keep** — not an un-renamed product identifier. |

## What "guard green" means

The Phase R rename target is: **zero Lliam-owned `hermes` product/command
identifiers remain** (attribution, generated output, and frozen audit logs
excluded per D4 and the exclusion globs). The guard
(`tests/rename/test_no_hermes_identifiers.py`) is the machine definition of
"complete." After the full literal sweep (R.8b–R.8e-3b), almost every file that
still contains the string `hermes` does so **only** on lines that are
legitimate keeps. A file-level guard could therefore never go green without
deleting real contracts, so R.8e-3c redesigned it to a **token/line-level
keep-pattern allowlist**:

> Scan every non-excluded file line by line. A line containing `hermes`
> (case-insensitive) PASSES iff **(a)** its path is under a `WHOLE_TREE_KEEPS`
> entry, or **(b)** the line matches one documented `KEEP_PATTERNS` regex.
> Any line matching neither FAILS the guard.

Each `KEEP_PATTERNS` entry in the guard carries a one-line rationale inline; this
register is the human-readable roll-up of the **categories** those patterns fall
into. The guard file is the authoritative, exhaustive pattern list.

The adjudication discipline (encoded in the guard's module docstring): for each
survivor ask *"is this the product's DISPLAY NAME / command (→ rename it, don't
allowlist) or opaque data / contract / detection / upstream (→ keep +
document)?"* Over-keeping is safe and documented here; a real product-name
rename is **never** allowlisted away.

## A. Whole-tree keeps (`WHOLE_TREE_KEEPS`)

Every `hermes` under these paths is a documented keep; the guard does not read
them line-by-line.

| Path (prefix or exact file) | Why kept |
|---|---|
| `lliam_cli/migrate_home.py`, `lliam_cli/env_compat.py` (+ pre-R.2 `hermes_cli/*` duals) | One-time migration + env-compat shim — MUST name the old home/env to migrate **from** it. |
| `apps/desktop/src/lib/migrate-storage-keys.ts` (+ `.test.ts`) | Desktop localStorage-key migration: every `hermes*` literal is a migrate-from source key. |
| `tests/rename/`, `scripts/rename/` | The rename infrastructure itself — it names `hermes` to describe what it scans for. |
| `docker/`, `Dockerfile`, `tests/docker/` | Container OS install identity: the `hermes` OS user/group, `/opt/hermes` tree, s6 supervision, and the tests asserting them — an inherited runtime contract, not the product display name. |
| `skills/autonomous-ai-agents/hermes-agent`, `skills/software-development/hermes-agent-skill-authoring` | Upstream (D4) skills — `name:` is a registry key; renaming orphans them. |
| Generated `website/**` skill-catalog mirrors of the two upstream skills (EN + zh-Hans) | Generated mirrors of the D4 upstream skills. |
| `hermes-already-has-routines.md` | Upstream marketing post authored in Lliam-GOV's own voice (D4). |
| `optional-skills/migration/openclaw-migration/scripts/openclaw_to_hermes.py` (+ `tests/skills/test_openclaw_migration.py`) | OpenClaw→Hermes migration tool: its rebrand-identity map and 50+ string-equality assertions are functionally coupled to the KEPT `.hermes` home. A separate D-level decision, not a mechanical rename, governs its target identity. |

## B. Line-level keep categories (`KEEP_PATTERNS`)

The token allowlist. Categories (see the guard file for the exhaustive regex list
and per-pattern rationale):

| Category | Examples | Why kept |
|---|---|---|
| Legacy home / paths (migrate-from) | `~/.hermes`, `.hermes`, `%LOCALAPPDATA%\hermes`, `hermes_state.db`, `.hermes_history`, `HERMES.md` | Literals the one-time migration reads to relocate old on-disk data. |
| `HERMES_*` env namespace | `HERMES_HOME`, `HERMES_CONFIG`, `HERMES_DESKTOP_*`, … | Preserved backward-compat env API (see §D). |
| Live contract literals | `hermes_home`/`hermes_root` kwargs & argparse dests, `hermes_pkce`, `hermes_version`, `X-Hermes-*` headers, `hermes.session.*` wire objects, `hermes:*` IPC channels, dashboard localStorage keys | Kwargs/JSON/wire/IPC/persisted-state contract keys — test-asserted; renaming breaks clients or strands persisted state. |
| Legacy service / process **detection** markers | `hermes-gateway`, `ai.hermes.gateway`, `s6-setuidgid hermes`, `main-hermes`, `hermes.exe`, `pkill -f hermes`, proctitle `hermes` | Strings that must keep matching the OLD binary/service so the product can detect, clean up, or refuse to self-terminate it. |
| Externally-registered ids | OAuth `hermes-cli`, wire tags `hermes-agent` (portal/exa/copilot/honcho), OpenRouter `X-Title`, Slack `/hermes`, bot handles, `hermes-<platform>` toolset preset keys | Registered with third parties / users; renaming addresses a different service or breaks existing configs. |
| 3rd-party wire attribution | `User-Agent: Hermes-Agent/…`, ACP registry name, NeMo telemetry event names | Values sent to external APIs/relays. |
| Container / OS install identity | `/opt/hermes`, `hermes` user/group, docker-compose image/container names, NixOS module user | Inherited runtime-account contract (also covered by the docker/** whole-tree keep). |
| Upstream (D4) | `nous_hermes`, `Hermes-4`/`Hermes 3`, `nousresearch/hermes-agent`, `hermes-agent.nousresearch.com`, `teknium`/`Nous Research` | Nous Research model families, repo, host, author attribution — license obligation. |
| Incident / proper nouns | `hermes-0day`, contributor emails/handles in the release attribution map | Historical proper nouns. |
| Arbitrary test-fixture DATA | tmp-dir prefixes, opaque session/task/host/peer ids, model-name detection fixtures, wake-word/mention inputs, negative `"hermes" not in` assertions | Opaque values a test constructs, asserts on, or asserts absent — not the product display name. |

## C. R.8e-3c final residual keeps (this session, 2026-07-08)

The token-level guard's last-tail sweep left 61 un-allowlisted lines.
**23 were real product/command-name misses and were RENAMED** (see §E);
**38 were legitimate keeps** and received the following new documented patterns
(all in the `R.8e-3c FINAL residual keeps` block of the guard):

- SKILL.md frontmatter `hermes:` metadata-key fixture.
- Honcho / OpenViking external-service host / peer / peer_id fixture values.
- NeMo-relay scope-handle fixture.
- Test narration describing the **kept container command/argv** `hermes` (`test_container_boot`).
- The `#38798` toolset-name corruption fixture (`hermes-cli` rewritten to `hermes`).
- Generated skill-catalog example `owner` field fixture.
- pytest tmp-dir path segments (`home/opt/adapters / "hermes"`) + `SUDO_USER` fixture.
- OpenClaw→Hermes migration posture reference (`migrate-hermes`).
- Log-channel namespace `logger="hermes.<x>"`.
- DingTalk registration `source` wire tag; package.json `name` fixture.
- `docker exec -u hermes` asserted OS user; kept `/hermes` Slack slash-command name asserted.
- Profile-alias collision input + legacy `hermes -p <profile>` `.bat` wrapper body.
- Search-tool `{"q"/"query": "hermes"}` query-argument fixtures.
- Sandbox-mirror classifier narration referencing the **kept `.hermes`/HERMES_HOME mirror marker** (`agent/file_safety.py` matches `home/.hermes`).
- Historical removed `HermesOverlay` class-name reference in a regression docstring.
- `Hermes-PKCE` (references the kept `hermes_pkce` OAuth credential contract).

## D. Env-fallback decision (kept for one release)

Per the R.1 note and the R.8 cleanup decision, the following back-compat shims
are **KEPT for one release** (recommended: safer for any operator scripts /
systemd units / desktop subprocesses still passing the old names), and are
documented here as the justification for their `hermes` survivors:

- **`getenv_compat()` `HERMES_*` read-fallback** (`lliam_cli/env_compat.py`):
  every `LLIAM_*` var falls back to reading its `HERMES_*` predecessor. The whole
  `HERMES_*` namespace remains a live, resolvable env API.
- **`--hermes-root` / `--hermes-home` CLI aliases** — hidden, deprecated aliases
  for `--lliam-root` / `--lliam-home`.
- **`LLIAM_DESKTOP_HERMES*`** desktop back-compat env prefix.

These are allowlisted (in `env_compat.py` via the whole-tree keep, and via
`KEEP_PATTERNS` for the CLI-alias literals) rather than removed. Removal is a
follow-up once one release has shipped.

## E. Real-miss renames applied in R.8e-3c (not keeps)

23 residual lines were genuine stale product/command prose (the tests import
`lliam_cli.*`; the sources already emit `Lliam-GOV`) and were renamed to
`lliam-gov` / `Lliam-GOV`:

- Test docstrings/comments naming the CLI command (`Bare hermes`, `the hermes
  parser`, `every hermes invocation`, `makes hermes unrunnable`, `hermes
  subprocess`, `hermes import`, `a running Hermes`, `hermes launches the REPL`).
- Agent-architecture prose (`hermes's outer loop`, `not hermes`, `the full hermes
  gateway`, `Hermes-specific tools`, `Hermes-internal markers`).
- Google-Chat `'Hermes is thinking…'` docstrings — the source already emits
  `'Lliam-GOV is thinking…'`, so these were stale narration.
- Stale `TestGetDefaultHermesHome` section comment (no such class exists).
- **Stale zh-Hans i18n cross-links** (`hermes-video`,
  `debugging-hermes-tui-commands`) — the English catalog already renamed these to
  `lliam-gov-video` / `debugging-lliam-gov-tui-commands`; the zh-Hans i18n mirror
  was not regenerated. Renamed to match. **Follow-up:** the zh-Hans skill catalog
  should be fully regenerated during the website/R.9 work; the linked target
  pages may need the same rename for link validity.

## F. Test-isolation fix (governance finding)

Diagnosing the floor before this sweep surfaced a **rename-induced test-isolation
defect**: `tests/conftest.py`'s autouse `_hermetic_environment` fixture redirects
`HERMES_HOME` to a per-test tempdir but never neutralized `LLIAM_HOME`. Post-rename
(D5) `LLIAM_HOME` is the PRIMARY home env and **wins over `HERMES_HOME`** in
`getenv_compat()`. So the documented safety practice of exporting a suite-wide
throwaway `LLIAM_HOME` (to keep gateway-spawning tests off the operator's real
home) had the side effect of making **every** test share one home — a single test
writing `active_profile` then poisoned all subsequent tests, cascading into
~1,100 spurious failures, and any gateway-spawning test could reach the operator
home.

**Fix:** `_hermetic_environment` now `delenv("LLIAM_HOME")` per test, so the
per-test `HERMES_HOME` (or a test's own `setenv`) governs and the home always
resolves to a tempdir, never `~/.lliam`. Proven: a poisoned shared
`LLIAM_HOME=/tmp/lliam-testhome` (containing `active_profile=excluded`) now
yields 647 passed / 0 failed across the previously-cascading files.

This is the same class of defect the resume prompt flagged for P2: **a test
spawning a networked gateway + browser OAuth against the operator home is a
least-privilege / egress failure the P2 controls should catch.** Logged here as a
governance finding for the P2 workstream.

## G. Guard case-sensitivity fix (R.8e-3d, 2026-07-08) — completeness-guarantee correction

**Defect:** the `HERMES_*` env-var keep pattern (`HERMES_[A-Z0-9_]*`) was compiled
with the guard's global `re.IGNORECASE`, so it also matched **lowercase**
`hermes_<word>` — silently allowing ~660 lowercase leftovers (`hermes_cli`,
`hermes_constants`, `hermes_logging`, generated-id prefixes, fixtures) to pass the
guard **by accident, not by adjudication**. "Guard green" therefore did not fully
guarantee completeness for lowercase textual refs. (The app itself was never
broken — the full suite passed throughout, so all executable code paths were
correctly renamed; this was an audit-trail gap.) Surfaced while reviewing PR #92.

**Fix:** the env pattern is now `(?-i:HERMES_[A-Z0-9_]*)` — UPPERCASE-only
(env vars are always ALL-CAPS), so it no longer masks lowercase `hermes_`. That
surfaced the ~660 masked lines, each then adjudicated:

- **Renamed** (safe, mostly comments/docstrings/strings; one real runtime fix — a
  `from hermes_cli.commands import …` subprocess string that would have thrown
  `ModuleNotFoundError`): all stale renamed-module textual refs
  `hermes_(cli|constants|logging|state|time|bootstrap)` → `lliam_*` (123 lines,
  54 files), applied only on offender lines so kept literals (`hermes_state.db`,
  `hermes_bootstrap_lib`) were never touched.
- **Kept + documented** (new scoped KEEP_PATTERNS blocks + the
  `apps/bootstrap-installer` whole-tree keep) — every survivor is now an explicit,
  scoped, documented family (NOT a `hermes_\w+` catch-all, which was the original
  bug):
  - Platform approval-button `action_id`/callback wire contracts (`hermes_action`,
    `hermes_approve*`, `hermes_deny`, `hermes_confirm_*`) — Slack/Feishu/Teams echo
    them back; renaming breaks live buttons.
  - i18n message keys (`hermes_cmd_not_found`) — localized VALUE already reads Lliam-GOV.
  - Profile-manifest schema field (`hermes_requires`); pip `hermes_agent.plugins`
    entry-point group; Honcho host keys (`hermes_<profile>`, `hermes_coder`).
  - Generated runtime-id prefixes `f"hermes_<uuid/id>"` (browser/matrix/dingtalk/
    singularity session·txn·user·instance ids, Telegram `hermes_<slug>_bot` username).
  - code-execution generated-stub module (`hermes_tools.py`, parent-writes/child-imports
    functional contract); user-provider import namespaces (`_hermes_user_provider`,
    `_hermes_user_cron`); concurrent-instance / old-binary detection identifiers.
  - Opaque temp-file/dir/socket/cache prefixes and test-fixture identifiers.
  - `apps/bootstrap-installer` (Rust src-tauri) — self-consistent Tauri IPC + CLI
    resolution identity the base rebrand deliberately left unchanged (D-level follow-up).

**Deferred (documented, not masked):** a handful of live internal identifiers that
are non-display and non-contract (`hermes_completion`, `run_hermes_oauth_login_pure`,
`_hermes_run_generation`, `find_hermes_node_executable`) are kept with an explicit
"dedicated test-gated rename pass may finish these" rationale — they carry zero
audit-facing product-name risk.

**Legacy entry-point keep:** `hermes_cli.main` (the module path baked into pre-rename
launchd/systemd plists, Windows scheduled tasks, running-process argv, and the electron
backend spawn/detection) is kept as a legacy-DETECTION marker — current invocations
already use `lliam_cli.main`. (My first bulk pass over-reached and renamed some of these
legacy-detection refs; that was reverted — the `.main` refs are legacy-detection keeps,
and one `.replace("hermes_cli.main", "lliam_cli.main")` test fixture the over-rename had
turned into a no-op was restored.)

### ⚑ FLAGGED DESKTOP FINDING (for R.5 / R.9)

Making the guard case-sensitive surfaced that the **electron desktop app never had its
backend Python-package references renamed** for `hermes_cli` → `lliam_cli`.
`apps/desktop/electron/main.cjs` and `desktop-uninstall.cjs` still contain
`import hermes_cli`, `path.join(root, 'hermes_cli', 'main.py'/'__init__.py')`,
`-m hermes_cli.uninstall`, and `hermes_cli`/`hermes_constants`/`hermes_logging` in
comments. The backend package is `lliam_cli` now, so these are **functional and likely
broken** — the desktop app may not resolve/spawn the renamed backend. Phase R's R.5
updated electron *identity* (appId/IPC/protocol) but not these backend-package refs.

**This is NOT fixed here** — migrating it is a functional desktop task that must be
verified with `npm run test:ui` + a real backend spawn, not a blind text rename inside a
guard-cleanup. The two files are `WHOLE_TREE_KEEPS` entries in the guard (documented, not
masked) so the finding is explicit and the guard can be green; R.9 (or the R.V desktop
proof) owns the fix.

Guard GREEN (case-sensitive); full suite == floor; ruff clean; 0 collection errors.
