# AI-Agent Disclosure & Privacy Notice — Lliam-GOV

| Field | Value |
|---|---|
| Document | AI-Agent Disclosure & Privacy Notice (LG-PF-04) |
| Owner | CAIO (`governance.role_bindings.caio`) |
| Version | 1.0 · 2026-07-16 |

> This notice is the disclosure text of record for operator and messaging surfaces. It is referenced from `docs/governance/privacy-policy.md` and the QMS provenance control (LG-QT-07).

## Disclosure

**You are interacting with an AI agent.** Lliam-GOV is an autonomous AI software agent (a non-person entity), not a human. Its outputs are machine-generated and may contain errors; artifacts it produces carry a synthetic-content provenance stamp (LG-QT-07) and must not be represented as human work product.

## What it records

Every consequential agent action is recorded to a tamper-evident audit ledger with the responsible principal (LG-AU-01/04). Content is redacted before persistence — secrets and PII are masked in the record (LG-AU-05).

## How your information is handled

- PII is redacted from AI-provider context by default and excluded from the agent's persistent memory (`docs/governance/privacy-policy.md`).
- Inference routes only to approved, vetted providers with no-train terms; nothing you provide is used to train models.
- Data the agent touches expires on a retention schedule and is securely purged.

## Human oversight and recourse

High-impact actions require approval by an authenticated human. If you are affected by an action or output of this agent and want human review, use the **appeal / human-handoff channel**: contact the operator of record (the HITL Approver in `docs/governance/roles-raci.md`), citing the session/correlation id shown on the surface you used. An in-flight action can be halted immediately by the kill-switch owner (LG-RM-09). Appeals are recorded and reviewed at management review (LG-HO-09, LG-GV-08).

---

*Built on Hermes Agent (Nous Research, MIT). Governance overlay is additive and capability-preserving.*
