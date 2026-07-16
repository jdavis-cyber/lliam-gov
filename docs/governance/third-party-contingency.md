# Third-Party Contingency & Fallback Responsibilities — Lliam-GOV

| Field | Value |
|---|---|
| Document | Third-party contingency / fallback + shared incident-response responsibilities (LG-TP-06) |
| Owner | ISSO; AI Risk Owner (provider vetting) |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Version | 1.0 · 2026-07-16 |
| Review-by | At provider change and at each management review (LG-GV-08) |

> **Purpose.** Documents what happens when a third-party dependency (an inference provider or an MCP server) degrades, fails, or is contained during an incident — and the shared incident-response responsibilities between Lliam-GOV and each third party. The controlling rule: **degrade to an approved on-prem/local fallback, never to an arbitrary cloud provider.**

## 1. Contingency rule (deny-fallback)

When a provider is unavailable or contained, routing must **fall back only within the approved allowlist**, preferring local/on-prem inference — a failover can never silently reach a non-allowlisted or non-US endpoint. This is enforced, not just documented: the provider allowlist is applied on **all five routing paths** (primary/fallback/MoA/auxiliary/delegation) by `lliam_cli/provider_allowlist.py` (LG-MP-01/02), and `security.local_provider_preference` clamps high-sensitivity work to local providers (LG-MP-04). A failover that would reach an off-allowlist endpoint fails closed rather than degrading residency.

## 2. Fallback order

| Priority | Target | Condition |
|---|---|---|
| 1 | Local inference (`lmstudio` / `ollama` / `vllm`, loopback) | Always eligible; preferred for high-sensitivity CUI |
| 2 | Approved in-boundary cloud (`bedrock` GovCloud) | When local capacity is insufficient and the task is allowlist-eligible |
| — | **Any non-allowlisted / non-US provider** | **Never** — fail closed instead (reportable-spillage boundary) |

If no allowlisted provider is available, the agent **degrades to halt** (kill-switch) rather than routing off-boundary — availability is subordinate to residency for CUI.

## 3. Shared incident-response responsibilities

| Responsibility | Lliam-GOV (in-boundary) | Third party (provider / MCP) |
|---|---|---|
| Detect an incident on the agent side | **R** (monitors, ledger, effectiveness verifier) | I |
| Contain the agent (kill-switch, allowlist drop, provider cutoff) | **R** (`agent/killswitch.py`, allowlist) | — |
| Provider-side outage / breach notification | C (acts on notice) | **R** (per vetting agreement, `supplier-vetting-register.md`) |
| Rotate credentials shared with the provider | **R** (`secrets_cli`) | C |
| Preserve forensics for the agent's actions | **R** (LG-IR-04) | — |
| DFARS/DIBNet reporting for a CUI incident | **R** (IR plan §8) | I (may supply artifacts) |

Provider/MCP contingency and breach-notification terms are recorded as allowlist-entry evidence in `docs/governance/supplier-vetting-register.md` (LG-TP-03) and bound in the shared-responsibility matrix (`docs/governance/shared-responsibility-matrix.yaml`, LG-TP-04). A provider that fails to meet its contingency/notification obligation is dropped from the allowlist at the next vetting review (or immediately on an incident).

## 4. MCP-server contingency

A vetted MCP server that becomes unavailable or drifts (schema/permission change detected by LG-MO-03) is **quarantined** — dropped from `policy/mcp-allowlist.yaml` — rather than trusted degraded. The agent continues with its remaining allowlisted tools (capability-preserving); no unvetted substitute is auto-loaded.

---

*Built on Hermes Agent (Nous Research, MIT). Governance overlay is additive and capability-preserving.*
