# Model Card — bedrock/anthropic.claude-3-5-sonnet  [LG-MP-05]

| Field | Value |
|---|---|
| Model id | `bedrock/anthropic.claude-3-5-sonnet` |
| Provider | bedrock (AWS GovCloud endpoint) |
| Architecture | Claude 3.5 Sonnet |
| Serialization | n/a (managed provider endpoint) |
| Context window | 200,000 tokens |
| Data residency | US (AWS GovCloud) |
| no-train | required by contract (verify per ATO/BAA) |
| CUI-eligible | yes (GovCloud host only) |

## Acceptable contexts
Coding, analysis, and CUI-marked work routed to the authorized AWS GovCloud
Bedrock endpoint (`bedrock-runtime.us-gov-west-1.amazonaws.com`). Commercial
Bedrock hosts are NOT authorized for CUI (enforced by the provider allowlist).

## Limits & cautions
- Route only to a FedRAMP High / IL4-IL5 GovCloud region; the provider
  allowlist rejects commercial hosts for CUI.
- Bind the provider-side guardrail (`bind.guardrail_identifier`) for
  Bedrock-routed CUI sessions (LG-MP-08).
- High-impact autonomous actions still require HITL + attestation.

## Provenance
Authorized under `AWS-GOVCLOUD-ATO-<id>` / `BAA-<id>`. Posture re-validated on
the 90-day cadence (LG-MP-08).
