# Model Card — lmstudio/llama-3.1-8b-instruct  [LG-MP-05]

| Field | Value |
|---|---|
| Model id | `lmstudio/llama-3.1-8b-instruct` |
| Provider | lmstudio (local enclave) |
| Architecture | Llama 3.1, 8B parameters, decoder-only transformer |
| Serialization | safetensors (LG-MP-07 safe format) |
| Context window | 128,000 tokens |
| Data residency | local (on-prem enclave; no external egress) |
| no-train | yes (no data leaves the host) |
| CUI-eligible | yes |

## Acceptable contexts
Coding assistance, document/data analysis, and CUI-marked work within the
operator enclave. This is the preferred high-sensitivity path (LG-MP-04).

## Limits & cautions
- Local inference only; do not point the `lmstudio` provider at a non-loopback
  host (the provider allowlist enforces `127.0.0.1`/`localhost`).
- Not authorized for autonomous high-impact actions without HITL approval
  (the tool-risk PDP + attestation gate apply).
- Model weights must be loaded in a safe format (safetensors/gguf); legacy
  code-executing formats are refused at load (LG-MP-07).

## Provenance
Enrolled under `ENCLAVE-LOCAL-001`. Version drift re-triggers the model-card
and hash checks (LG-MP-08).
