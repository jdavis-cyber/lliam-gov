# Supplier / Provider / MCP / Skill Vetting Register  [LG-TP-03 · ACTIVE @ P3.3]

| Field | Value |
|---|---|
| Document | Supplier Vetting Register |
| Owner | Lliam-GOV Program (ISSO) |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Review cadence | 90 days |
| Last validated | 2026-07-16 |
| Next due | 2026-10-14 |

The single register of every third-party component in the Lliam-GOV supply
chain — inference providers, MCP servers, and skills/plugins — with its vetting
status, the policy that enforces it, and the SDL review record (LG-SC-09). New
components enter the baseline ONLY after an SDL review (provenance + AST +
security-guidance patterns) is recorded here.

## 1. Inference providers (LG-MP-01 · `policy/provider-allowlist.yaml`)

| id | class | jurisdiction | residency | no-train | CUI | agreement | status |
|---|---|---|---|---|---|---|---|
| lmstudio | local | on-prem enclave | local | yes | yes | ENCLAVE-LOCAL-001 | approved |
| ollama | local | on-prem enclave | local | yes | yes | ENCLAVE-LOCAL-002 | approved |
| vllm | local | on-prem enclave | local | yes | yes | ENCLAVE-LOCAL-003 | approved |
| bedrock | gov-cloud | US (AWS GovCloud) | us | yes | yes | AWS-GOVCLOUD-ATO-\<id\> | approved (GovCloud host only) |

## 2. Models (LG-MP-05 · `docs/governance/model-cards/model-cards.yaml`)

| model id | card | serialization | CUI | status |
|---|---|---|---|---|
| lmstudio/llama-3.1-8b-instruct | ✓ | safetensors | yes | carded |
| bedrock/anthropic.claude-3-5-sonnet | ✓ | managed | yes | carded |

## 3. MCP servers (LG-SC-07 · `policy/mcp-allowlist.yaml`)

| name | transport | scope | write | TLS | SDL record | status |
|---|---|---|---|---|---|---|
| gov-filesystem | stdio | read_file/list_directory/search_files | deny | n/a (local) | SDL-MCP-0001 | approved |
| gov-ticketing | streamable_http | read_ticket/create_ticket | create_ticket (HITL) | required + CA verify | SDL-MCP-0002 | approved |

Any live `mcp_servers.<name>` not listed here is rejected at load
(deny-by-default). Shell-egress/persistence IOC command shapes are blocked
unconditionally (LG-SC-04).

## 4. Skills / plugins (LG-SC-03/09 · `policy/skills-allowlist.yaml`)

| skill | source | provenance | AST audit | status |
|---|---|---|---|---|
| pdf | builtin | clean | pass | approved |
| xlsx | builtin | clean | pass | approved |
| docx | builtin | clean | pass | approved |
| godmode / obliteratus / web-pentest / sherlock / oss-forensics | builtin (offensive) | — | — | **denied** (LG-SC-01) |

Third-party skills without a clean provenance record are refused execution
under `security.require_signed_skills` (LG-SC-03).

## 5. SDL review procedure (LG-SC-09)

Before any provider / MCP server / skill enters the baseline:
1. **Provenance** — record origin (vendor, repo, version, hash).
2. **AST audit** — `tools/skills_ast_audit.ast_scan_path` for skills; schema +
   scope review for MCP.
3. **Security guidance** — check against the IOC/shell-egress shapes and the
   least-privilege scope rules.
4. **OSV** — dependency vulnerability scan (P3.4).
5. **Record** — add a row above with the `record_ref`; stamp `reviewed`,
   `reviewer`, `review_date`.

Re-validation runs on the 90-day cadence (LG-MP-08 / LG-SC posture) and on any
version drift (which re-triggers provenance + hash + card checks).
