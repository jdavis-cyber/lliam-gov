# Contributing to Lliam-GOV

Lliam-GOV is a **governed, controlled fork** maintained as evidence inside an ISO/IEC 42001-aligned AI Management System. It is **not** an open-contribution project in the usual sense: changes are made internally or **by prior arrangement**, and every change must pass the governed review and local-green gate before it reaches `main`.

If you are an authorized contributor, this is the workflow.

> Looking for the upstream Hermes contribution guide (skills/tools taxonomy, plugin model, etc.)? It is preserved for reference at [`docs/upstream/CONTRIBUTING.hermes.md`](docs/upstream/CONTRIBUTING.hermes.md). It describes the upstream project, not Lliam-GOV's process.

## Ground rules

- **Contributions are by arrangement.** Open an issue (or a Linear item, internally) and agree the approach before writing code. Unsolicited public PRs may be closed without review.
- **Governance core is protected.** Changes to the audit log, encryption-at-rest, egress allow-list, or capability/self-modification gates require explicit maintainer sign-off and added tests.
- **Security issues do not go through PRs or public issues** — see [`SECURITY.md`](SECURITY.md).

## Verified dev setup

Requirements: **Python 3.12**, [`uv`](https://docs.astral.sh/uv/), and Git. (Node.js 20+ only if you touch the desktop app or TUI.) There are no git submodules.

```bash
gh repo clone jdavis-cyber/lliam-gov && cd lliam-gov
uv sync                      # creates the venv and installs dependencies
uv run lliam-gov --help      # sanity check — should print usage and exit 0
uv run lliam-gov version     # prints "Lliam-GOV vX.Y.Z"
```

> For the full governed profile on a personal Mac (encryption-at-rest, egress allow-list, capability + self-modification gates, fail-closed posture check), run `bash scripts/install-governed-macbook.sh`. **Demo/eval only — never on a CUI-in-scope device.**

## Tests and the local gate

GitHub Actions is currently offline, so **local-green is the merge gate.**

```bash
# scoped, per-file isolated test run for the files you changed:
bash scripts/run_tests.sh tests/path/to/affected_test.py

# the documented local merge gate (fast, scoped release invariants):
bash scripts/local-gate.sh
```

Run the scoped tests for the area you touched and the local gate before requesting a merge. The full suite is large and has known pre-existing/environmental failures tracked separately — do not treat a fully-green full run as the bar; treat **scoped-green + local-gate-green** as the bar.

## Pull request expectations

- One logical change per PR; describe what and why.
- Include tests for behavior changes, especially anything touching governance controls.
- Keep upstream Hermes attribution (`NOTICE`, `LICENSE`) intact.
- Note any change that affects the install/run flow so it can be re-verified.

Thank you for helping keep Lliam-GOV powerful, personal, and governed.
