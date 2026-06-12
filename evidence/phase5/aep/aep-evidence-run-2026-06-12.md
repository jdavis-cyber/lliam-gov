# AEP evidence exports (AI-225, WBS LG-5.1) — representative governed session
# Generated: 2026-06-12. Chain produced by exercising real control paths under a
# governed profile (egress+capability+selfmod enforcement, capabilities granted to
# the workspace baseline): session open/close, tool dispatch start/end, CUI custody
# (cui_access + cui_delete), capability denial, egress denial, self-mod approve+reject.

## 1. Chain verification (pre-export)
Verified 12 audit records from /var/folders/t3/_6xw7th15cqf0kfpv5cswn640000gn/T/tmp.yC1tA6WeMp/audit/tool-calls-2026-06.jsonl; last_hash=sha256:ea4db26f9d66e34577167fb92cc78da66496b0f0f5ef44abd5c106e710e69b4e

## 2. AEP export
Exported 12 audit records to evidence/phase5/aep/aep-representative-2026-06-12.json

## 3. AEP re-import verification
Verified 12 audit records from evidence/phase5/aep/aep-representative-2026-06-12.json

## 4. Sanitization check — no raw params, secrets, or CUI payloads in export
PASS - raw 'params' objects absent
PASS - controlled-content payload absent
PASS - params_hash present
PASS - denial + success + custody event types present
record_count: 12

## 5. Event-type inventory in source chain
  cui_access: 1
  cui_delete: 1
  egress_denied: 1
  selfmod_approved: 1
  selfmod_proposed: 2
  selfmod_rejected: 1
  session_close: 1
  session_open: 1
  tool_call_blocked: 1
  tool_call_end: 1
  tool_call_start: 1

## Control coverage of this evidence sample
- CMMC L2 / SP 800-171: 3.1.2 (tool_call_blocked capability), 3.1.20/3.13.1 (egress_denied),
  3.3.x (hash-chained audit + verify), 3.8.x (cui_access/cui_delete custody)
- ISO 42001: A.6.2.4 (selfmod_approved/rejected human oversight), A.6.2.6 (operation evidence)
- ISO 27001: A.8.11 (params_hash masking — no raw payloads), A.8.15/A.8.16 (audit trail + monitoring)
