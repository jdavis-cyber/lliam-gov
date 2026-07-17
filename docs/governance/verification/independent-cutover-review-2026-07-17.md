# Independent Pre-Cutover Review — Code Review + End-to-End Testing

| Field | Value |
|---|---|
| Scope | Independent code review + end-to-end verification ahead of production cutover |
| Baseline | `main` @ `317a95b` (the P5 "assessor-ready hardened baseline", 188/188 controls) |
| Environment | Fresh clone, Linux x86_64, Python 3.11.15, `uv`-locked env (`--extra all --extra dev`), Node 22 |
| Date | 2026-07-17 |
| Method | Re-executed the documented local gate battery + CI workflow checks; ran full isolated test suite; five targeted read-only code reviews (CI gates, governance runtime, config overlay, exposed surfaces, fork/rename hygiene) |
| **Verdict** | **NOT yet cutover-ready.** The base agent, the P0–P2 governance spine, and the network perimeter are solid. But the P4–P5 governance layer that is this fork's reason to exist is substantially **built-and-tested but not wired into production**, and several self-update paths still point at upstream. Prioritized blockers below. |

---

## 1. Verification executed (all green except where noted)

| Check | Command / scope | Result |
|---|---|---|
| Dependency install | `uv sync --locked --extra all --extra dev` (Py 3.11) | PASS |
| Ruff lint | `ruff check .` | PASS |
| `ty` typecheck | `ty check` | 10,338 diagnostics — all pre-existing baseline; CI's lint job gates only on *new* diagnostics vs base, and this branch introduces none |
| TypeScript typecheck | ui-tui, web, apps/bootstrap-installer, apps/desktop, apps/shared | PASS (5/5) |
| Desktop production build | `npm run --prefix apps/desktop build` (vite) | PASS |
| Governance gates — workflow set | prohibited-skills, baseline-drift (P0), deps-hash, audit-chain selftest + gate, SoD, supply-chain, SBOM/AI-BOM | PASS (8/8) |
| Governance gates — full battery | soa, ssp-reconciliation, regulatory-reconciliation, fairness, control-effectiveness, **go/no-go** | PASS (6/6); go/no-go = **GO** |
| Packaged-wheel i18n e2e | `pytest -m integration tests/test_wheel_locales_e2e.py` | PASS (2/2) |
| e2e adapters | `tests/e2e/` (discord adapter, platform commands, matrix bootstrap) | Covered by suite below |
| Full isolated test suite | `scripts/run_tests.sh` (per-file isolation, 8 workers), ~34,400 tests | 36,073 passed / 80 failed — see §3 |
| Gov egress enclave | `docker compose -f docker-compose.yml -f deploy/docker-compose.gov.override.yml config` | Merges cleanly; **one bypass** — see F-INFRA-1 |

---

## 2. Process findings (independent of code)

- **P1 — CI has been red since 2026-07-12; Phases 4 and 5 merged with no CI.** The repo is private and out of GitHub Actions minutes: every run since `d744ec5` fails at the `Detect affected areas` job in ~2s (no runner), which cascades every gate to `skipped`, and `All required checks pass` reports failure. So the "188/188, all gates green" claims in the P4/P5 verification reports rest entirely on **local** gate runs recorded by the author. This review is the first *independent* re-execution of that battery — and it does pass locally (§1). Cutover planning should not assume server-side CI is enforcing anything today.
- **P2 — `deps_hash_gate.sh` mutates the environment it runs in.** Its step 3 runs `uv sync --locked` against the *live* venv, which prunes `--extra dev`/`--extra all` packages (pytest, etc.) out from under any concurrently-running process. Running the gate mid-test-suite silently broke ~3,300 test subprocesses with `No module named pytest` on the first pass here. The gate should run against a throwaway/`--no-install-project` isolated env, never the working venv.
- **P3 — The unit suite reaches PyPI at test time.** During the run, `tools/lazy_deps` auto-installed `anthropic==0.87.0` into the venv (observed via `agent/anthropic_adapter._get_anthropic_sdk` → `lazy_deps.ensure`). Tests that assert Anthropic-wire behavior pass or fail depending on whether a prior test triggered that network install — nondeterministic, and a supply-chain exposure inside CI. Tests should stub `lazy_deps` (a `conftest` autouse guard) rather than let it hit the index.

---

## 3. Test-suite analysis — 80 failures, none attributable to the hardening

The 80 failures across 22 files reconcile to the "characterized noise floor" (~59–60/21) documented in the P5.V report, inflated by two **environment** factors specific to this run, not the code:

- **Running as root.** Permission-deny tests (e.g. `tests/tools/test_search_error_guard.py` "diagnostic leaked into files") cannot fail-closed because root bypasses filesystem permissions. CI runs as an unprivileged user.
- **CPU oversubscription.** `test_agent_identity.py` and `test_codex_ttfb_watchdog.py` hit the 300s per-file timeout under 8 workers on a 4-core box (also running the review agents). **Both pass in ~32s in isolation at HEAD** — confirmed — so these are false timeouts, not hangs.
- **Optional-dependency families.** `test_tts_mistral`, `test_video_generation_tool_surface_matrix`, `test_fal_plugin`, `test_managed_media_gateways`, `test_image_generation`, `test_transcription_*` fail because their optional backends (edge-tts, fal, mistral, elevenlabs) are lazy-install-only and absent; this is the documented live-credential/optional-dep floor.

I bisected the two tests that *looked* like real regressions against the last-green commit `d744ec5`:

- `test_auxiliary_transport_autodetect.py::…kimi_coding_wraps_anthropic` and the two `test_auxiliary_named_custom_providers` Anthropic-messages cases **fail only when the `anthropic` SDK is absent** and pass once it is present (they depend on the lazy-install in P3). They pass at both `d744ec5` and HEAD with the SDK installed. Not a regression — a test-isolation/dependency artifact.

**Conclusion:** no failure traces to the governance hardening. The suite is at its known floor. (Recommend fixing the harness so the floor is 0: run tests unprivileged, stub `lazy_deps`, and cap workers at core count.)

---

## 4. Code-review findings

Severity reflects impact **for a governance product headed to a federal/defense cutover**, where the P4–P5 controls are the deliverable, not a nice-to-have. Two independent reviewers (config-overlay and governance-runtime) converged on the same core conclusion — the continuous-monitoring / cATO layer does not run in production — which raises confidence in it.

### 4a. Cutover blockers (must-fix)

**B1 — The cATO loop, auto-suspend, and circuit-breaker never run.** `agent/cato_loop.run_cato_cycle` has zero callers anywhere (runtime, cron, CI, workflows), and it is the *only* caller of `killswitch.engage()`. So LG-GV-07 (cATO auto-suspend), the entire `incident_response.circuit_breaker` block (LG-IR-03), and every `cato.*` config key are dead — and there is no automatic or even CLI path to engage the kill-switch; it can only be tripped by hand-writing `$HERMES_HOME/killswitch.state`. The effectiveness check that would drive it (`current_effectiveness_failures`) also returns `[]` on any exception, i.e. fails **open** ("posture effective") if the CI-gate scripts aren't present in an installed deployment. *(config-overlay C4, gov-runtime F6)*

**B2 — The runtime monitors can never fire.** `runtime_monitors._check_egress`/`_check_drift` key on `provider.call`/`mcp.call`/`mcp.load`/`skill.load` events that **no production code ever emits** (repo-wide, only tests construct them). The `tool.dispatch` fallback is also dead: the gate emits `action="tool.web_fetch"` but the monitor's membership test looks for `"web_fetch"`, and it reads `outcome.host` which dispatch records never carry. LG-MO-02/03 are test-only. Likewise the **output monitor** (`output_monitor.scan_output`, LG-PF-08/09 PII/CUI egress block) is called only from tests — it cannot block anything in production. *(gov-runtime F11, F14)*

**B3 — The ISCM/SIEM stream writes to the wrong path, silently.** The overlay ships `monitoring.iscm_sink.path: "$HERMES_HOME/logs/iscm-events.log"`, but the config loader never expands `$HERMES_HOME` and `iscm_sink.build_sink` only does `expanduser()`. Every SIEM event is appended to a literal `./$HERMES_HOME/logs/iscm-events.log` under the process CWD — an agent-writable path outside the file-safety denylist — while the collector tailing the real home path sees nothing. Forward failures are logged at `debug`. *(gov-runtime F12, config-overlay M3)*

**B4 — The kill-switch does not stop what an incident responder thinks it stops.** It is wired at the credential-resolution seam, which the TUI re-hits per turn but the **gateway and cron resolve only once** at session/job start — so a long-lived gateway or in-flight cron job keeps calling inference and replying (e.g. out to Telegram/Discord) after engage; only *new* sessions and tool dispatch halt. `engage()` also calls `set_interrupt(True)` with no thread id, flagging the operator's own thread, not the agent execution threads, so in-flight tools run to completion. And the **MCP server bypasses it entirely**: `mcp_serve.messages_send` egresses to messaging platforms and `permissions_respond` approves pending exec/plugin requests with no kill-switch check and no ledger record. *(gov-runtime F1, F2, F3)*

**B5 — `lliam-gov update` can silently revert a host to upstream Hermes.** The Windows ZIP update path downloads `NousResearch/hermes-agent/.../main.zip` and copies it over the install; the pip/uv/pipx update path upgrades `hermes-agent` (the fork publishes as `lliam-gov-agent`); `install.ps1`'s clone fallback fetches the upstream ZIP; `docker-compose.windows.yml` pulls `nousresearch/hermes-agent:latest`; and several failure messages tell users to reinstall from `hermes-agent.nousresearch.com`. Any of these replaces the governance-hardened code with stock Hermes. *(rename C1, C2, H1, H2, H3)*

**B6 — The overlay's whole posture hangs on one unchecked env var, with no startup guard.** `_gov_overlay_path` returns `None` — no log, no warning — if `HERMES_CONFIG`/`LLIAM_CONFIG` is unset, empty, or points at a missing file, and every governance module gates on `security.posture == strict`, which only the overlay sets. So a bad path yields a fully permissive runtime silently. The `.env.gov.example` ships `HERMES_CONFIG=<SET path/to/cli-config.gov.yaml>` — copied verbatim, the overlay never loads. The "LG-CH-03 startup drift check" that `baseline-critical-keys.yaml` claims would catch this **does not exist** — the baseline file is read only by the CI gate, never at runtime. Add a fail-closed startup assertion that the overlay loaded and posture is strict. *(config-overlay C1, C2)*

### 4b. High

- **H-1 — Env vars silently override posture-coerced security.** `HERMES_YOLO_MODE=1` disables the human-approval flow (and the PDP's delegated HITL tiers) under strict posture, checked by nothing; `LLIAM_ALLOW_PRIVATE_URLS` / `TIRITH_FAIL_OPEN` / a pre-set `TERMINAL_ENV=local` similarly re-open SSRF, disable Tirith, or force host shell execution ahead of the overlay. A strict host can be degraded to permissive without touching a version-controlled file. *(config-overlay C3, H1, H2)*
- **H-2 — The audit chain is tamper-*evident against accidents, not adversaries.*** `record_hash`/`prev_hash` are plain unkeyed SHA-256 over public content — anyone with file-write access can rewrite any record and recompute every downstream hash (~20 lines), and `verify_chain` reports PASS; suffix-truncation also passes (documented as LG-AU-08-R1). The production audit-chain cron reports **OK when the ledger has been deleted** (`if not exists: return 0`) — the most obvious tamper action pages no one. The "P1.4 HMAC keying" the docstring defers to was never built. *(ci-gates 7, 6; gov-runtime F8)*
- **H-3 — CI orchestrator and gates carry self-referential bypasses.** `all-checks-pass` treats `skipped`/`cancelled` needs as success, so a failed `detect` job green-lights the required check with zero gates run. The baseline-drift gate is switched off by the very key it guards (`posture != strict` → "non-gov profile, skip") and is pinned `--phase P0`, so P1/P2 critical keys (`audit.ledger_enabled`, `approvals.mode`, `provider_allowlist_enforce`, `egress.mode`) are never enforced. The path-freeze gate reads a head-editable, non-frozen manifest and passes when it's empty. Roughly half the gate scripts (go/no-go, SoA, SSP, regulatory, fairness, control-effectiveness, OSV-blocking) are wired into **no workflow** — their only teeth are pytest, in a lane skipped for `docs/`-only PRs, which is exactly where the governance registers live. *(ci-gates 1, 2, 4, 5, 9)*
- **H-4 — Attestation is a shared-secret checksum over a placeholder, skipped on the main path.** `model_manifest.yaml` ships `signature: REPLACE-WITH-PROVISIONED-SIGNATURE` and `${LLIAM_GOV_SIGNING_KEY}` is never expanded, so `verify_manifest` always fails — and the only way to make it pass is to paste the raw HMAC key into readable config, at which point anything that reads config can forge manifests. Runtime model attestation is skipped on the primary serving path (TUI/gateway/cron never pass `target_model`) while the paths that do pass it hard-fail under the placeholder signature — a cutover blocker either direction. `.env.gov.example` never even mentions `LLIAM_GOV_SIGNING_KEY`. *(gov-runtime F15, F16; config-overlay H3)*
- **H-5 — Home-directory split-brain.** The installer seeds `~/.hermes` and installs code at `~/.hermes/hermes-agent`, but runtime default moved to `~/.lliam` with a copy-everything (not move) first-run migration, and ~10 modules read a raw `HERMES_HOME` with a hardcoded `~/.hermes` fallback. A default post-migration host has some modules reading/writing the legacy `~/.hermes` copy while the rest use `~/.lliam` — a real data split. *(rename H-home-split)*
- **H-6 — Fail-closed startup enforcement runs only in the gateway.** Control-plane auth, provider allowlist, model integrity, governance-artifact checks, and audit-chain verification are wired at `gateway/run.py` startup only. The TUI, `run_agent.py`, cron scheduler, `batch_runner.py`, and `mcp_serve.py` verify none of it at process start — a CLI session runs on a broken audit chain or missing artifacts. *(config-overlay H4, gov-runtime F9)*

### 4c. Exposed-surface findings (perimeter is otherwise strong)

The dashboard/API perimeter reviewed as **unusually well-hardened**: every network route is auth-gated, the WebSocket DNS-rebind guard is correctly reimplemented, CORS is localhost-pinned with credentials off, the `--insecure` public-bind hole is closed, webhook adapters (WhatsApp, MS Graph, GitHub/GitLab/Svix, Chronos JWT) all verify signatures with constant-time compares and fail closed, and the MCP/ACP surfaces are stdio-only with no network bind. Residual items:

- **S-1 (Med; High if multi-user) — No authorization tiering behind the auth boundary.** Any authenticated dashboard session gets host RCE (`shell.exec`/`cli.exec` over the gated WS) and arbitrary filesystem read/write (`/api/fs/*` via `_fs_path`, which enforces no root confinement). Fine for a single-operator loopback install; for a multi-user OAuth-gated cutover, one valid/phished session = full host compromise. Needs network isolation + a sandboxed `terminal.backend` if exposed. *(exposed #1)*
- **S-2 (Med) — File-manager confinement is layout-dependent.** `/api/files*` only locks to a root when the install is at `/opt/data` or `HERMES_DASHBOARD_FILES_ROOT` is set; otherwise it's rooted at `$HOME` with full traversal-safe browse/read/write/delete. Set `HERMES_DASHBOARD_FILES_ROOT` in the cutover manifest. *(exposed #2)*
- **S-3 (Med in air-gapped) — `/api/ops/debug-share` egresses logs to an external paste service.** Any authenticated user can upload the diagnostic report + log tail off-box; redaction defaults on but is caller-overridable and regex-based. Remove or allowlist for the cutover build. *(exposed #3)*

### 4d. Infrastructure

- **F-INFRA-1 (High) — The egress enclave leaves the dashboard container unrestricted.** `deploy/docker-compose.gov.override.yml` reroutes only the `gateway` service through the squid allowlist; the `dashboard` service keeps `network_mode: host` on the same `hermes-agent` image with the same `~/.hermes` mount, so it has unrestricted internet egress outside the LG-NE-04/05 boundary. Either route `dashboard` through the proxy too or document why it's exempt.

### 4e. Lower-severity (fold into the same pass)

- ~30 overlay keys are unread mirrors of `policy/*.yaml` (values currently match, so no live divergence, but editing them changes nothing — an auditor reading the overlay as the config of record is reading decoys). `security.website_policy` (allowlist mode), `require_mfa`, `accounts` reconciliation, `model_hash_verify`, and `storage.encrypt_at_rest` claim enforcement that has no reader. *(config-overlay M1, M2, H5, M5)*
- The supply-chain gate misses the two-line form of the base64-exec attack it names, `from subprocess import run`, and several obfuscator codecs. The scheduled red-team job reports "green" when pytest *errors* (vs fails). The deps-hash "floor" passes on a single hashed entry. *(ci-gates 8, 13, 14)*
- Systematic attribution typo — "a fork of **Lliam-GOV** by Nous Research" (should be *Hermes*) — in `README.md:8`, `cli-config.gov.yaml`, and, notably, `lliam_cli/default_soul.py` (the persona injected into every session). Single find-replace. *(rename README/soul)*

**Secrets hygiene: clean.** No plausible real credentials in `.env*`, `evidence/`, `docs/governance/`, or fixtures — all placeholders/test tokens.

---

## 5. Recommended cutover gate

Treat **B1–B6 + F-INFRA-1** as blocking. They cluster into three fixes that unlock most of the list:

1. **Wire the P4–P5 layer or descope it honestly.** Schedule `run_cato_cycle` (and thus the kill-switch trigger + circuit breaker), emit the events the monitors consume (or repoint the monitors at `tool.dispatch` records that actually exist), fix the `$HERMES_HOME` expansion in the ISCM sink, and invoke `output_monitor` on the egress path. If any control can't be wired before cutover, strike its "Implemented" status and config key rather than ship it as paperware. *(B1, B2, B3)*
2. **Close the posture-integrity holes.** Add a fail-closed startup assertion that the overlay loaded and `posture == strict`, and make that gate refuse `HERMES_YOLO_MODE`/`LLIAM_ALLOW_PRIVATE_URLS`/`TIRITH_FAIL_OPEN`/`TERMINAL_ENV` re-opens under strict. Extend the fail-closed startup battery beyond the gateway to the TUI and MCP entrypoints. Provision a real signing key (and add it to `.env.gov.example`) or descope attestation. *(B4-MCP, B6, H-1, H-4, H-6)*
3. **Finish the rename's escape hatches.** Repoint every update/reinstall/compose path at `jdavis-cyber/lliam-gov` + `lliam-gov-agent`, ungate the Docker/docs-site publish workflows from the upstream repo, and resolve the `~/.hermes` vs `~/.lliam` split. *(B5, H-5)*

The base agent is functional, the P0–P2 governance spine and the ledger core are genuinely well-engineered and fail-closed, and the network perimeter is strong. The gap is specifically the continuous-monitoring / incident-response / attestation layer that distinguishes this fork — it demonstrably passes its tests but is not connected to any production execution path. Once B1–B6 are wired and re-verified (ideally with server-side CI restored so the gates actually block), this is a credible cutover candidate.

---

*Full per-area findings (CI gates, governance runtime, config overlay, exposed surfaces, rename hygiene) available from the review session; this document consolidates and de-duplicates them by severity and cutover impact.*
