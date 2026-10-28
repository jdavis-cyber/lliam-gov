#!/usr/bin/env bash
# scheduled_assurance_cron.sh — recurring cATO assurance jobs (LG-MO-07/08/09,
# LG-GV-07, P5.2 / JER-76). Runs scheduled_assurance.py against the REAL host
# install: control-effectiveness, the scheduled red-team eval, governance
# metrics, then the cATO cycle (posture break → kill-switch auto-suspend),
# notification + redelivery, and the freshness heartbeat under
# $HERMES_HOME/logs/assurance/. Pages on any break.
#
# Distinct from the CI pre-merge run: this is the post-deployment RECURRING
# control-evidence stream (LG-GV-07 cATO input). Install the schedule with
#   lliam-gov assurance install          # launchd (macOS) / systemd user timer (Linux)
# or by hand, e.g. crontab:
#   23 7 * * *  HERMES_HOME=/opt/lliam HERMES_CONFIG=/opt/lliam/cli-config.gov.yaml \
#     /opt/lliam/repo/ci/governance-ci-gates/scheduled_assurance_cron.sh \
#     >> /var/log/lliam-assurance.log 2>&1
#
# REQUIRED env (fail-closed if unset):
#   HERMES_HOME    — the agent home whose logs/agent-audit.log is the ledger
#   HERMES_CONFIG  — the gov overlay (so posture + ledger path resolve)
# OPTIONAL:
#   LLIAM_PYTHON              — interpreter (default: repo .venv, then python3)
#   LLIAM_ASSURANCE_ALERT_CMD — command run on a break (receives output on stdin)
#   ASSURANCE_STAMP           — UTC stamp for the red-team report filename
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATES="$REPO_ROOT/ci/governance-ci-gates"
PY="${LLIAM_PYTHON:-$REPO_ROOT/.venv/bin/python}"
[[ -x "$PY" ]] || PY="python3"

if [[ -z "${HERMES_HOME:-}" || -z "${HERMES_CONFIG:-}" ]]; then
  echo "::error::scheduled_assurance_cron: HERMES_HOME and HERMES_CONFIG must be set (fail-closed)" >&2
  exit 2
fi

STAMP="${ASSURANCE_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"
# `if` keeps a nonzero job exit from tripping `set -e` before we print + page.
if out="$("$PY" "$GATES/scheduled_assurance.py" --repo-root "$REPO_ROOT" \
    --stamp "$STAMP" 2>&1)"; then
  rc=0
else
  rc=$?
fi

echo "$out"
if [[ $rc -ne 0 ]]; then
  if [[ -n "${LLIAM_ASSURANCE_ALERT_CMD:-}" ]]; then
    printf '%s\n' "$out" | ${LLIAM_ASSURANCE_ALERT_CMD} || true
  fi
  echo "::error::scheduled_assurance_cron: an assurance job failed (exit $rc, see above)" >&2
  exit "$rc"
fi
