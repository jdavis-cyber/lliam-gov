# Lliam-GOV — Dependency-Pinning Evidence Pack (LG-SS-01 / LG-SS-07)

| Field | Value |
|---|---|
| Document | Dependency-Pinning Evidence Pack |
| Owner | Lliam-GOV Program |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Controls | LG-SS-01 (pin + hash-verify), LG-SS-07 (no runtime lazy installs) |
| Step | P0.6 |
| Date | 2026-06-30 |

This is the supply-chain evidence record for the software dependency layer. It is
**additive** — it documents and pins the EXISTING build artifacts; no package
name, version constraint, or build system is changed by this step.

---

## 1. Dependency pinning (LG-SS-01)

- **`pyproject.toml` `[project].dependencies`** — every PyPI dependency carries an
  upper bound: exact pins (`name==X.Y.Z`) or bounded ranges (`name>=floor,<next_major`).
  Examples: `openai==2.24.0`, `pydantic==2.13.4`, `requests==2.33.0`,
  `urllib3>=2.7.0,<3`, `fastapi>=0.104.0,<1`.
- **`uv.lock`** — the fully resolved lockfile, committed, containing **1798
  `sha256` hashes** (sdist + wheel `hash = "sha256:…"` entries) — the
  cryptographic pin for every resolved artifact.
- **Lazy-install specs** — even the optional-backend specs in
  `tools/lazy_deps.py` `LAZY_DEPS` are version-pinned (`name==X.Y.Z`), so any
  *permitted* install (low-side) is also pinned.

Both `pyproject.toml` and `uv.lock` are git-tracked and committed on
`harden/phase-0-baseline`.

## 2. Hash-verified install path (LG-SS-01)

The governed install path must verify hashes against the committed lock:

```
uv sync --locked            # uv: install exactly the locked, hashed resolution
# or, pip equivalent:
uv export --format requirements-txt --no-emit-project > requirements.lock
pip install --require-hashes -r requirements.lock
```

Overlay key (`cli-config.gov.yaml`): `security.require_hashed_install: true`.
The startup/CI assertion that enforces this is added in P0.7 (gov-baseline CI
gate) — this step pins the value and documents the path.

## 3. CI enforcement (existing)

`.github/workflows/supply-chain-audit.yml` → **"Check PyPI dependency upper
bounds"** fails the build on any PyPI dep without a `<next_major` ceiling
(`::error::PyPI dependencies without upper bounds detected`). P0.7 marks this a
required check on the gov baseline branch.

## 4. Runtime lazy-install kill switch (LG-SS-07)

`cli-config.gov.yaml` pins `security.allow_lazy_installs: false` (set in P0.1).
`tools/lazy_deps._allow_lazy_installs()` reads this via the overlay-aware
`load_config()`; when false, `tools/lazy_deps.ensure(<feature>)` raises
`FeatureUnavailable("lazy installs disabled (security.allow_lazy_installs=false)")`
**before** any pip call — so the agent cannot self-install a backend at runtime
in a CUI/air-gapped profile. The env seal `HERMES_DISABLE_LAZY_INSTALLS=1`
(`.env.gov.example`) is a defense-in-depth second lever.

## 5. Change control

Any dependency pin bump (pyproject edit + `uv.lock` regeneration) requires an
entry in [`change-record.md`](change-record.md) (LG-SS-01) and, for the gov
baseline, CODEOWNERS review.

## Capability impact
Low. No runtime agent capability is removed; pre-provisioned backends work
normally. A new optional backend simply cannot be self-installed mid-session —
it must be added to the pinned lock and pre-provisioned (air-gap posture).
