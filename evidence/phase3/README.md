# Phase 3 Smoke Harness Operator Notes

AI-241 adds the Phase 3 smoke harness only. Do not commit runtime evidence
artifacts from this PR. The 24-hour run and committed evidence files belong to
AI-217 / PR B.

## What The Harness Exercises

`scripts/phase3_smoke.py` emits one controlled set of runtime events every
cadence:

- `gateway_auth`
- `tool_call_start`
- `tool_call_end`
- `session_open`
- `session_close`

On shutdown it emits `phase3_smoke_end`. The final event is part of the same
hash-chained JSONL audit log and its raw emission record includes the
pre-final last hash for operator correlation. The audit JSONL itself stores
only `params_hash`, so the readable pre-final hash anchor lives in the
harness emissions log outside the audit chain.

The harness sets `LLIAM_GOV_ENCRYPT_STATE=1` before running and writes a
synthetic state file through `lliam_gov.security.state_codec` each cadence.

## Short Local Verification

From the repo root:

```bash
LLIAM_GOV_ALLOW_NON_FIPS=1 \
python scripts/phase3_smoke.py \
  --duration-seconds 600 \
  --cadence-seconds 60 \
  --heartbeat-seconds 60
```

For a faster compressed smoke during development:

```bash
LLIAM_GOV_ALLOW_NON_FIPS=1 \
python scripts/phase3_smoke.py \
  --max-iterations 2 \
  --cadence-seconds 5 \
  --heartbeat-seconds 1
```

The default production cadence is 5 minutes. The required heartbeat interval is
1 minute. The PID file default is:

```text
~/.lliam-gov/phase3_smoke.pid
```

## Monitor

Default runtime files are written under:

```text
~/.lliam-gov/phase3_smoke/
```

Key files:

- `phase3-smoke-heartbeat.json` - overwritten every heartbeat interval.
- `phase3-smoke-manifest.json` - run configuration, sleep gaps, final hash.
- `phase3-smoke-emissions.jsonl` - raw harness emissions outside the audit chain.
- `phase3-smoke-state.bin` - synthetic state file routed through encryption.

Check heartbeat:

```bash
cat ~/.lliam-gov/phase3_smoke/phase3-smoke-heartbeat.json
```

Follow harness emissions:

```bash
tail -f ~/.lliam-gov/phase3_smoke/phase3-smoke-emissions.jsonl
```

## Stop

Use SIGTERM so the harness can append `phase3_smoke_end` and remove the PID
file:

```bash
kill -TERM "$(cat ~/.lliam-gov/phase3_smoke.pid)"
```

Avoid force-kill unless the process is already dead or unresponsive.

## Verify JSONL

The harness prints the audit path and final last hash on exit. Verify with:

```bash
lliam-gov audit verify-jsonl \
  --input <audit-jsonl-path> \
  --expected-last-hash <last-hash>
```

## PR B Evidence Artifacts

After the Friday 2026-06-05 24-hour run, AI-217 / PR B should commit the six
evidence artifacts under `evidence/phase3/`:

- `smoke-manifest-2026-MM-DD.md`
- `audit-chain-2026-MM-DD.jsonl`
- `aep-export-2026-MM-DD.json`
- `aep-verification-2026-MM-DD.log`
- `jsonl-verification-2026-MM-DD.log`
- `noise-floor-phase3-exit-2026-MM-DD.md`
