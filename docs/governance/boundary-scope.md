# Authorized Boundary, Scope & System Inventory — Lliam-GOV

| Field | Value |
|---|---|
| Document | Authorized Boundary / Scope Statement + Asset & CUI Maps + Host Inventory |
| Controls | LG-IN-01 (boundary/scope), LG-IN-04 (asset classification), LG-IN-05 (CUI location map), LG-IN-06 (execution-surface host inventory) |
| Owner | ISSO (`governance.role_bindings.isso`) |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Version | 1.0 |
| Date | 2026-07-16 |
| Review-by | At each re-authorization and on any boundary change |

> **Purpose.** The authorized boundary and scope statement for the Lliam-GOV deployment, with the asset-classification register, the CUI storage/processing location map, and the execution-surface host inventory. Companion to `docs/governance/SSP.md` (LG-IN-07) and `docs/governance/intended-use.md` (LG-GV-02). Machine-readable component inventories are generated per build: AI-BOM + SBOM with baseline reconciliation (LG-IN-02/03, P3.4 — `ci/governance-ci-gates/generate_bom.py`).

## 1. Authorized boundary (LG-IN-01)

The authorization boundary is **the agent itself** — the Lliam-GOV multi-provider local-CLI inference agent — not a hosting platform. Host OS, network fabric, and physical facility are **inherited** from the underlying boundary (SSP §2).

**In-boundary (governed) components:**

| Component | Realization | Governing policy |
|---|---|---|
| Tool execution (file/shell/web/search) | PDP-mediated at dispatch; shell sandboxed (`terminal.backend: docker`) | `policy/tool-risk-policy.yaml` |
| MCP client | Deny-by-default allowlist, TLS required | `policy/mcp-allowlist.yaml` |
| Skills/plugins (incl. `optional-skills/`) | Signed/attested; offensive set denied | `policy/skills-allowlist.yaml`, `docs/governance/waiver-register.yaml` |
| Persistent memory | Partitioned, TTL-bounded, staged writes | `cli-config.gov.yaml` `memory.governance` |
| Inference routing (all 5 paths) | Approved-provider allowlist, fail-closed | `policy/provider-allowlist.yaml` |
| Audit ledger | Hash-chained, verify-on-startup | `cli-config.gov.yaml` `audit:` block |
| ACP adapter + desktop app | Authenticated control plane | `cli-config.gov.yaml` `security.require_operator_auth` |

**Out of boundary / excluded:** `computer_use` and `browser` toolsets (disabled in the CUI baseline, deviation-eligible); `godmode`/`obliteratus` (excluded, never waivable — SoA); non-allowlisted providers and MCP servers (denied fail-closed).

**Boundary enforcement at startup:** the go/no-go gate (`LG-GV-06`), provider-allowlist gate, model-integrity gate, control-plane auth gate, and audit-chain verify all run on the gateway startup path (`lliam_cli/security_audit_startup.py`) and fail closed under strict posture.

## 2. Asset classification (LG-IN-04)

| Asset | Location | Sensitivity | Tag / control |
|---|---|---|---|
| Workspace (write-confined) | `HERMES_WRITE_SAFE_ROOT` | CUI-bearing when mission data present | Safe-root allowlist + sensitive-path denylist (`agent/file_safety.py`) |
| Persistent memory store | `$HERMES_HOME/` memory partitions | CUI-eligible; PII excluded from persistence | `memory.governance` (partition/TTL/PII-exclude, LG-MC-02/05) |
| Audit ledger | `$HERMES_HOME/logs/agent-audit.log` | Security-relevant; redaction-on-write | Write-denied to the agent; hash-chained (LG-AU-01/07) |
| Secrets / credentials | OS keychain + managed secret sources; residual `.env` write-denied | Highest | Scoped per profile (`agent/secret_scope.py`, LG-IA-03) |
| Tool-result spill / caches | `$HERMES_HOME/` result storage | CUI-eligible, transient | Retention TTL + masking (`security.data_protection.result_retention_ttl_seconds`, LG-DP-11) |
| Config baseline | `cli-config.gov.yaml` (version-controlled) | Integrity-critical | Drift gate + path-freeze manifest (LG-CH-03) |
| Model artifacts | Local inference hosts + signed manifest | Integrity-critical | `model_manifest.yaml` + safe-serialization guard (LG-MP-06/07) |

## 3. CUI storage & processing location map (LG-IN-05)

> Eval-deployment note: **no CUI is in scope** for the current authorization (`LG-ATO-2026-001`); the map records where CUI *would* reside so the floor is enforced regardless.

| Location class | Concrete location | Handling controls |
|---|---|---|
| At rest — workspace | Safe-root subtree only | Write confinement (LG-AZ-04), markings preserved (LG-DP-02), at-rest encryption (`security.data_protection.at_rest_encryption`, LG-DP-07) |
| At rest — memory/spill | `$HERMES_HOME` partitions | PII excluded, TTL purge, secure delete (LG-MC-05/06, LG-DP-11) |
| In transit — provider context | Allowlisted in-boundary providers only | TLS verified (LG-DP-06), PII/CUI redaction to providers (LG-DP-03/04), taint gate (LG-DP-10) |
| In transit — MCP/web | Allowlisted destinations only | Deny-by-default egress (`security.egress.mode: allowlist`, LG-NE-01), SSRF/metadata floor (LG-NE-02) |
| In use — reasoning traces | Model context | Think-scrubbing before egress (`agent/think_scrubber.py`, LG-DP-09) |
| Audit record | Ledger | Redaction-on-write, unconditional (LG-AU-05) |

## 4. Execution-surface host inventory (LG-IN-06)

| Host | Role | Enrollment / constraint |
|---|---|---|
| `lliam-gov-eval-mac01` (operator workstation, macOS/arm64) | Sole execution surface: agent runtime + sandboxed docker backend | Single-operator eval host; FDE on; computer-use NOT enrolled (toolset disabled) |
| Local inference servers (`lmstudio`, `ollama`, `vllm` on loopback) | In-boundary local model serving | Allowlisted slugs in `policy/provider-allowlist.yaml`; loopback-only base URLs |
| `bedrock` (AWS GovCloud endpoint) | Approved cloud inference | Allowlisted with GovCloud host pin; commercial-host substitution denied (P3.1) |
| Sandbox containers | Shell/code execution (`terminal.backend: docker`) | Ephemeral; egress via the gov compose override (`deploy/docker-compose.gov.override.yml`) |

**Constraint of record:** `computer_use` requires an enrolled host + JIT grant + deviation entry; no host is currently enrolled — the enrollment list is intentionally empty (deny state, LG-IA-09/LG-AZ-11).

---

*Built on Hermes Agent (Nous Research, MIT). Governance overlay is additive and capability-preserving.*
