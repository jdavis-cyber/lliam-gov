## What does this PR do?

<!-- Describe the change clearly. What problem does it solve, and why is this approach right? -->

## Related issue

<!-- Link the issue (GitHub or Linear) this addresses. Contributions are by arrangement — agree the approach first. -->

Fixes #

## Type of change

- [ ] 🐛 Bug fix
- [ ] ✨ New feature
- [ ] 🔒 Security fix
- [ ] 📝 Documentation
- [ ] ✅ Tests
- [ ] ♻️ Refactor (no behavior change)

## Governance impact

- [ ] This PR does **not** touch the governance core (audit log, encryption-at-rest, egress allow-list, capability/self-modification gates).
- [ ] This PR **does** touch the governance core — maintainer sign-off and added tests are included.

## Verification

- [ ] `uv run lliam-gov --help` exits 0 and `uv run lliam-gov version` is correct.
- [ ] Scoped tests for the affected files pass (`bash scripts/run_tests.sh <path>`).
- [ ] `bash scripts/local-gate.sh` passes (local-green merge gate while CI is offline).
- [ ] Upstream attribution (`NOTICE`, `LICENSE`) left intact.

## Notes

<!-- Anything reviewers should know, especially impact on the install/run flow. -->
