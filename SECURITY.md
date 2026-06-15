# Security Policy

Lliam-GOV is a governance-grade personal AI agent. Security and auditability are core product properties, not add-ons. This document describes how to report a vulnerability, which versions are supported, the trust model, and what is in and out of scope.

> **Maintainer note (please confirm before publishing):** the reporting contact below is a **placeholder**. Set it to your real security inbox (e.g. a dedicated `security@…` address or GitHub private vulnerability reporting) before this repo is shared more widely.

## Supported versions

Lliam-GOV is maintained as a single, actively-developed line. Security fixes target the latest `main` and the most recent tagged release.

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| Latest tagged release | ✅ |
| Older tags / pre-fork upstream | ❌ |

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Report privately via **GitHub Private Vulnerability Reporting** (Security → *Report a vulnerability*) on this repository, or by email to **`security@PLACEHOLDER.example`** *(maintainer to replace with the real contact)*.

A useful report includes:

- A concise description and your severity assessment.
- The affected component, identified by file path and line range (e.g. `path/to/file.py:120-145`).
- Environment details: output of `lliam-gov version`, commit SHA, OS, and Python version.
- A reproduction against the latest `main`.
- Which trust boundary (below) is crossed.

Lliam-GOV does not currently operate a paid bug-bounty program. Good-faith reports are welcome and appreciated.

## Trust model

Lliam-GOV is a single-operator personal agent with a documented governance overlay. Its posture is layered, and the layers are not equally load-bearing.

**The primary security boundary against an adversarial model is the operating system.** No in-process component is containment by itself — not the approval/capability gate, not output redaction, not any pattern scanner, not a tool allow-list. Any in-process check operates on attacker-influenceable input and should be treated as defense-in-depth, not a boundary. For untrusted input surfaces or shared/production use, run Lliam-GOV under OS-level isolation (container or sandbox), not the default local backend.

**Governance overlay (Lliam-GOV additions).** On top of the agent runtime, Lliam-GOV adds controls that make agent behavior accountable and tamper-evident:

- **Encryption at rest** for the agent workspace (FIPS-validated path for production).
- **Append-only, hash-chained audit log** — a tamper-evident record of agent actions.
- **Egress allow-list** — deny-all by default, TLS enforced; the agent reaches only explicitly approved destinations.
- **Capability & self-modification gates** — dynamic capability expansion and agent self-modification require human approval.
- **Narrowed messaging surface** — integration channels restricted to a vetted set.
- **CUI marking & audit instrumentation** for controlled-information workflows.
- **Credential scoping** — provider credentials are stripped from lower-trust in-process components by default; this reduces casual exfiltration but is not containment.

These controls are accident-prevention and evidence-generation layered on top of the OS boundary — they raise the floor and produce an audit trail; they do not replace OS-level isolation.

## Scope

**In scope**
- Escape from a declared OS-level isolation posture.
- Unauthorized access to an external surface (gateway/HTTP/IPC adapter) by a caller outside the configured allow-list.
- Credential exfiltration via a mechanism that should have prevented it (env-scrubbing bug, adapter logging, transport flush).
- Defeat or silent bypass of a governance control that is documented as enforced (audit-log tampering that evades the hash chain, egress reaching a non-allow-listed destination, a self-modification path that skips the approval gate).

**Out of scope** (welcome as regular issues/PRs, but not via the private channel)
- Bypasses of in-process heuristics that this policy does not treat as boundaries (approval-gate regex gaps, redaction bypasses).
- Prompt injection on its own, without a chained concrete impact above.
- Consequences of an operator-chosen break-glass setting (e.g. the demo/eval profile that waives the FIPS hard-gate when no CUI is in scope, disabled approvals, local backend in production).
- Public exposure of the gateway/API without the documented external controls.

## Disclosure

- **Coordinated disclosure window:** 90 days from report, or until a fix ships, whichever is first.
- **Channel:** the private report thread or email correspondence.
- **Credit:** reporters are credited in release notes unless anonymity is requested.

## Governance posture

Lliam-GOV is operated as governed evidence inside an ISO/IEC 42001-aligned AI Management System, with hardening toward CMMC Level 2 / ISO 27001 controls. Security reports that demonstrate a gap between documented governance behavior and actual behavior are especially valuable and squarely in scope.
