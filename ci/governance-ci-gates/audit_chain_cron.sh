#!/usr/bin/env bash
# audit_chain_cron.sh — host detective control for the governance audit chain
# (LG-AU-08 scheduled verification, spec §10).
#
# This is the PRODUCTION cron unit — distinct from the CI `audit-chain` job,
# which self-tests the verifier against a throwaway ledger. This script runs
# the same audit_chain_gate.py against the REAL host ledger and pages on any
# break (exit 1) or verifier error (exit 2). The CI schedule does NOT verify a
# production ledger; this does.
#
# Install (host with the in-scope agent), e.g. crontab:
#   17 7 * * *  HERMES_HOME=/opt/lliam HERMES_CONFIG=/opt/lliam/cli-config.gov.yaml \
#     /opt/lliam/repo/ci/governance-ci-gates/audit_chain_cron.sh >> /var/log/lliam-audit-chain.log 2>&1
# or a systemd timer / launchd plist calling this script with the same env.
#
# REQUIRED env (fail-closed if unset — an unpinned home/overlay would verify the
# wrong or no ledger and report a false OK):
#   HERMES_HOME    — the agent home whose logs/agent-audit.log is the ledger
#   HERMES_CONFIG  — the gov overlay (so resolve_ledger_path + strict posture resolve)
# OPTIONAL:
#   LLIAM_AUDIT_ALERT_CMD — command to run on a break/error (page/email/webhook);
#                           receives the gate output on stdin.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [[ -z "${HERMES_HOME:-}" || -z "${HERMES_CONFIG:-}" ]]; then
  echo "::error::audit_chain_cron: HERMES_HOME and HERMES_CONFIG must be set (fail-closed)" >&2
  exit 2
fi

PY="${LLIAM_PYTHON:-python3}"
out="$("$PY" "${REPO_ROOT}/ci/governance-ci-gates/audit_chain_gate.py" --require-strict 2>&1)"
rc=$?
echo "$out"

if [[ $rc -ne 0 ]]; then
  echo "::error::audit_chain_cron: verification FAILED (exit $rc) — tamper or verifier error" >&2
  if [[ -n "${LLIAM_AUDIT_ALERT_CMD:-}" ]]; then
    printf '%s\n' "$out" | ${LLIAM_AUDIT_ALERT_CMD} || true
  fi
fi
exit $rc
