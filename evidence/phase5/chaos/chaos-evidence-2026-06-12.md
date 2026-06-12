# Phase 5 chaos / fail-closed evidence (AI-229, WBS LG-5.5)

Generated: 20260612T085002Z  |  all failed closed: True

## audit_log_unavailable — PASS (failed closed)
    read-only-home dispatch -> {"error": "Audit logging failed closed: cannot prepare audit directory /var/folders/t3/_6xw7th15cqf0kfpv5cswn640000gn/T/lliam-chaos-e_irq4j2/audit: [Errno 13] P

## keyring_unavailable — PASS (failed closed)
    keychain probe failed closed -> Keychain/key-manager probe failed: keyring locked (chaos injection); protected operations must refuse (fail-closed).

## egress_misconfigured — PASS (failed closed)
    empty-allowlist egress denied -> egress denied: model-provider.example:443 is not on the Lliam-GOV allowlist (LLIAM_GOV_EGRESS_ALLOWLIST or /var/folders/t3/_6xw7th15cqf0kfpv

## selfmod_rejected_no_leak — PASS (failed closed)
    rejected proposal 729846c9689e: pending=0, in_rejected=True
