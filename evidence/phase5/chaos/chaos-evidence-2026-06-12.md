# Phase 5 chaos / fail-closed evidence (AI-229, WBS LG-5.5)

Generated: 20260616T090718Z  |  all failed closed: True

## audit_log_unavailable — PASS (failed closed)
    read-only-home dispatch -> {"error": "Audit logging failed closed: cannot prepare audit directory /tmp/lliam-chaos-wxa2q_ro/audit: [Errno 13] Permission denied: '/tmp/lliam-chaos-wxa2q_ro

## keyring_unavailable — PASS (failed closed)
    keychain probe failed closed -> Keychain/key-manager probe failed: keyring locked (chaos injection); protected operations must refuse (fail-closed).

## egress_misconfigured — PASS (failed closed)
    empty-allowlist egress denied -> egress denied: model-provider.example:443 is not on the Lliam-GOV allowlist (LLIAM_GOV_EGRESS_ALLOWLIST or /tmp/lliam-chaos-92ehvj36/egress-

## selfmod_rejected_no_leak — PASS (failed closed)
    rejected proposal b5bb0f70e0dc: pending=0, in_rejected=True
