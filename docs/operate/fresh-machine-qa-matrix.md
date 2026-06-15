# Fresh-machine QA matrix & smoke tests (AI-335)

Release qualification matrix proving Lliam-GOV works on clean machines with each
approved provider path. Pairs with the automated harness
`scripts/smoke-providers.py` and the release evidence package (AI-338).

## Lane status

| Lane | OS | Status | Blocker |
|---|---|---|---|
| **MAC-arm64** | macOS 14+ Apple Silicon | ✅ **proven** — clone→install→posture→provider→real prompt verified end-to-end (Gemini) | — |
| MAC-x64 | macOS 13+ Intel | ⏳ ready to run (same path) | needs an Intel host pass |
| WIN-x64 | Windows 11 x64 | ⛔ **blocked-on-posture-guard** | FIPS-on-Windows + POSIX posture-guard rewrite (parked, Jerome) |
| LINUX-x64 | Ubuntu 22.04+ x64 | ⏳ runtime works from source | signed artifacts pending packaging (AI-331) |

A **stable release requires** at least one clean macOS `/Applications` install
**and** one non-macOS install verified — the latter is currently gated, so a
stable cross-platform release is **blocked** until Windows/Linux lanes clear.

## Per-OS test sequence (each lane runs all rows)

| # | Step | Pass criteria | Automated by |
|---|---|---|---|
| 1 | Install | App/installer completes; no admin-only failure | manual |
| 2 | First launch | Window opens; first-run provider screen shows | manual |
| 3 | Backend bootstrap | Managed backend provisioned under Lliam home; marker written | `bootstrap-marker.test.cjs` (unit) + manual |
| 4 | Provider detection | Each installed CLI detected w/ path+version | `smoke-providers.py --real` |
| 5 | Provider login guidance | Exact install/login command shown for not-ready states | `smoke-providers.py` (mocked states) |
| 6 | Model selection | A model can be chosen for a ready provider | manual + smoke |
| 7 | One prompt execution | Prompt returns a result via the CLI | `smoke-providers.py --real --execute` |
| 8 | Update check | App reports current vs available; stale marker logged | manual + `bootstrap-marker` |
| 9 | Uninstall | App + `~/.lliam-gov` removable; provider logins survive | `desktop-uninstall.test.cjs` + manual |
| 10 | Log collection | `~/.lliam-gov/logs/` has desktop/agent/bootstrap logs | manual |

## Smoke harness — mocked vs real

`scripts/smoke-providers.py`:
- **mocked (default, CI-safe):** injects fake `which`/`run`/`auth_probe` so all
  three adapters report READY deterministically — validates the detect→auth→
  readiness→execute wiring with no real CLIs. Covered by
  `tests/providers/cli/test_smoke_providers.py`.
- **real (`--real`, `--execute`):** probes the CLIs actually installed and (with
  `--execute`) runs one prompt through the first ready provider — for manual
  release-candidate sign-off.

Both modes write an evidence artifact (see below). A captured mocked sample is at
`evidence/release/qa/smoke-mocked-sample.json`.

## Evidence capture (required fields)

Each QA run stores a JSON artifact under `evidence/release/qa/` carrying:
**app/desktop version, backend version, provider CLI versions, OS
system/release/machine, per-provider readiness, prompt-execution result, and
pass/fail notes.** The release evidence collector (`collect-release-evidence.py`)
references this path; until a real run lands it is reported **PENDING**.

## Release decision — blocker / severity criteria

| Severity | Definition | Release impact |
|---|---|---|
| **S1 blocker** | Install fails, app won't launch, bootstrap can't complete, or **no** provider can execute a prompt on a supported lane | **No release** |
| **S2 major** | One provider path broken but others work; update or uninstall fails | No release on affected lane; ship others only with sign-off |
| **S3 minor** | Cosmetic / degraded-state wording; recoverable with documented workaround | Ship with known-issue note |
| **S4 trivial** | Logging/telemetry nit | Ship |

Release sign-off requires: MAC-arm64 all-rows pass + one non-macOS lane all-rows
pass + zero open S1/S2 on shipped lanes + the AI-338 evidence manifest attached.

## Decision-gated

- **WIN-x64** lane is blocked on the parked posture-guard / FIPS-on-Windows work (Jerome).
- **Signed-artifact** rows (install of a notarized/Authenticode build) need certs (AI-331) + CI (AI-332, Actions offline).
- A **real** `--execute` smoke against a packaged build feeds the AI-338 QA evidence; until then the QA item stays PENDING.
