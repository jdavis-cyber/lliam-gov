# P3 — Capability-Preservation Verification Report

| Field | Value |
|---|---|
| Phase | Phase 3 — Supply Chain & Provider Governance |
| Gate | AI-492 (P3.V) |
| Branch | `harden/phase-3-supply-chain` |
| Date | 2026-07-16 |
| Result | **PASS** — no mission capability regressed |

## Purpose
Prove empirically that the Phase 3 supply-chain layer (provider allowlist, model
integrity/attestation, MCP & skill vetting, supply-chain CI gates + BOM)
hardened the agent **without cutting off authorized routes**. Per-emphasis
(Plan §6): every in-boundary provider must route on all five paths; approved
attested skills and allowlisted least-privilege MCP servers must still load;
only non-allowlisted providers, unvetted skills, and unsafe-serialization loads
may newly block.

## Phase 3 slices verified
| Step | Issue | Controls | New blocks introduced |
|---|---|---|---|
| P3.1 | AI-488 | LG-MP-01/02/03/04/08, GV-09 | non-allowlisted provider/base_url (all 5 paths) |
| P3.2 | AI-489 | LG-MP-05/06/07/08 | uncarded model / tampered manifest / unsafe-serialization load |
| P3.3 | AI-490 | LG-SC-03/04/05/07/08/09, TP-03 | non-allowlisted / write-broad MCP; unvetted skill |
| P3.4 | AI-491 | LG-SS-02..06, IN-02/03 | build with .pth/base64-exec/install-hook; OSV ≥ high |

## Findings
- **In-boundary routing intact:** `lmstudio`, `ollama`, `vllm` (local) and
  `bedrock` (GovCloud) route on primary / fallback / MoA / auxiliary /
  delegation — the multi-provider hot path is preserved (16-item corpus).
- **Approved suppliers still load:** an allowlisted least-privilege MCP server
  and a carded model both pass; a vetted builtin skill with clean provenance
  passes.
- **Acceptance boundary exact:** only non-allowlisted provider/base_url,
  unvetted skill, and unsafe-serialization loads newly block; safe formats
  (safetensors/gguf) and allowlisted routes are untouched.
- **Full-suite at the noise floor:** 60/21, zero new failures vs the
  characterized floor — additive hardening degraded no existing behavior.
- **Additive + path-frozen:** path-freeze gate green vs `gov-P2-good`
  (29 guarded paths, none renamed).
- **Enforcement seams are fail-closed startup gates** (provider allowlist,
  model integrity) — the hot resolution path was not modified, so throughput is
  unaffected on approved routes.

## Conclusion
Phase 3 is hardened **and** still fully capable. CUI inference stays available
through every authorized in-boundary provider on all routing paths, approved
skills and MCP servers still function, and the supply-chain gates + BOM produce
assessor evidence without blocking legitimate work. The only capabilities newly
gated are the three the plan authorizes. **No mission capability regressed.**
Save point `gov-P3-good` tagged on the Phase 3 close-out merge.
