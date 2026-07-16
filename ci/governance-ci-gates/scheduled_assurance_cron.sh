#!/usr/bin/env bash
# scheduled_assurance_cron.sh — recurring cATO assurance jobs (LG-MO-07/08/09,
# P5.2). Runs the scheduled red-team eval + the control-effectiveness verifier
# + governance metrics against the REAL host install, and pages on any break.
#
# Distinct from the CI pre-merge run: this is the post-deployment RECURRING
# control-evidence stream (LG-GV-07 cATO input). Install on the in-scope host:
#   23 7 * * *  HERMES_HOME=/opt/lliam HERMES_CONFIG=/opt/lliam/cli-config.gov.yaml \
#     /opt/lliam/repo/ci/governance-ci-gates/scheduled_assurance_cron.sh \
#     >> /var/log/lliam-assurance.log 2>&1
# or a systemd timer / launchd plist with the same env.
#
# REQUIRED env (fail-closed if unset):
#   HERMES_HOME    — the agent home whose logs/agent-audit.log is the ledger
#   HERMES_CONFIG  — the gov overlay (so posture + ledger path resolve)
# OPTIONAL:
#   LLIAM_ASSURANCE_ALERT_CMD — command run on a break (receives output on stdin)
#   ASSURANCE_STAMP           — UTC stamp for the red-team report filename
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATES="$REPO_ROOT/ci/governance-ci-gates"
PY="$REPO_ROOT/.venv/bin/python"
[[ -x "$PY" ]] || PY="python3"

if [[ -z "${HERMES_HOME:-}" || -z "${HERMES_CONFIG:-}" ]]; then
  echo "::error::scheduled_assurance_cron: HERMES_HOME and HERMES_CONFIG must be set (fail-closed)" >&2
  exit 2
fi

REPORT_DIR="${HERMES_HOME}/logs/assurance"
STAMP="${ASSURANCE_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
rc=0
out="$(
  set +e
  echo "== control-effectiveness (LG-MO-08) =="
  "$PY" "$GATES/control_effectiveness.py" --repo-root "$REPO_ROOT"; ce=$?
  echo "== scheduled red-team (LG-MO-07) =="
  "$PY" "$GATES/scheduled_redteam.py" --repo-root "$REPO_ROOT" \
    --report-dir "$REPORT_DIR" --stamp "$STAMP"; rt=$?
  echo "== governance metrics (LG-MO-09) =="
  "$PY" "$GATES/governance_metrics.py" \
    --ledger "$HERMES_HOME/logs/agent-audit.log" || true
  exit $(( ce != 0 || rt != 0 ))
)" || rc=$?

echo "$out"
if [[ $rc -ne 0 ]]; then
  if [[ -n "${LLIAM_ASSURANCE_ALERT_CMD:-}" ]]; then
    printf '%s\n' "$out" | ${LLIAM_ASSURANCE_ALERT_CMD} || true
  fi
  echo "::error::scheduled_assurance_cron: an assurance job failed (see above)" >&2
  exit 1
fi
echo "[assurance] OK — control-effectiveness + red-team green; metrics recorded."
