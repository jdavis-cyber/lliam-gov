# Repository maintenance and governed deployment

Ordinary development of this personal repository validates code and security
mechanisms. Historical example roles, signatures and review dates are not
recurring administrative obligations for maintaining the repository. A passing
build is not deployment authorization, certification or permission to process CUI.

## What CI checks

PRs, main pushes and manual Governance Gates runs retain baseline-drift,
prohibited-skill, dependency integrity, audit-chain, supply-chain artifact,
SBOM/AI-BOM and PR path-freeze checks. The full test, build, lint and vulnerability
workflows remain enabled. Failures are not ignored or converted to success.

The separation-of-duties job runs the existing policy regression suite. A
controlled test clock exercises valid, expired, malformed and non-waivable
cases. The shipped role examples are tested on their review dates and the next
day, including the command's success/failure exit status. Their dates and
principals are unchanged; they have not been renewed or approved by CI.

The daily GitHub reference-profile self-test schedule has been removed. It had
no production audit ledger and repeatedly failed on the same expired examples.
This does not change a deployed host's audit schedule: `audit_chain_cron.sh`,
its alert behavior and the real ledger checks are unchanged.

## Deliberate real-date assessment

The checker still uses today's date outside tests:

```sh
python ci/governance-ci-gates/sod_check.py \
  --roles docs/governance/roles.yaml \
  --overlay cli-config.gov.yaml
```

After October 11, 2026, the current example records produce two blocking
conflicts and exit 1. That remains the intended result. No date override or
bypass option is added. This checks configured role consistency, not actual
human independence or complete deployment readiness.

## Retained application boundaries

Runtime authorization, policy-review and authorization-record expiry,
egress/provider rules, human approval, kill-switch and audit behavior are
unchanged. The strict overlay and its referenced policy/authorization records
remain intact because the runtime consumes them. Changing that deployment
model requires a separate decision; this repository maintenance change does
not grant or extend a deployed authorization.

Earlier hardening reports record the behavior and schedules at the time of
those reports. This document describes the current maintenance scope.
