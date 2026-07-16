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
only non-allowlisted providers, unattested models, and unapproved/drifted MCP
servers may newly block in live routing.

## Phase 3 slices verified
| Step | Issue | Controls | New blocks introduced |
|---|---|---|---|
| P3.1 | AI-488 | LG-MP-01/02/03/04/08, GV-09 | non-allowlisted provider/base_url (all 5 paths) |
| P3.2 | AI-489 | LG-MP-05/06/07/08 | uncarded / unsigned / manifest-mismatched model |
| P3.3 | AI-490 | LG-SC-03/04/05/07/08/09, TP-03 | unlisted or identity/scope/TLS-drifted MCP |
| P3.4 | AI-491 | LG-SS-02..06, IN-02/03 | build with .pth/base64-exec/install-hook; OSV ≥ high |

## Findings
- **In-boundary routing intact:** `lmstudio`, `ollama`, `vllm` (local) and
  `bedrock` (GovCloud) route on primary / fallback / MoA / auxiliary /
  delegation — the multi-provider hot path is preserved (16-item corpus).
- **Approved suppliers still load:** an allowlisted least-privilege MCP server
  and a carded model both pass; a vetted builtin skill with clean provenance
  passes.
- **Acceptance boundary:** non-allowlisted resolved provider/base URLs,
  unattested explicit runtime models, and unapproved/drifted MCP servers block;
  low-side behavior and approved routes are untouched.
- **Full-suite below the characterized noise floor:** the review run recorded
  36,352 passing tests and 32 failures across 14 files. Three stale mock
  expectations caused by the new routing-context argument were updated and the
  affected files then passed 148/148, leaving only unrelated baseline failures.
- **Additive + path-frozen:** path-freeze gate green vs `gov-P2-good`
  (29 guarded paths, none renamed).
- **Enforcement is layered:** fail-closed startup inventory plus checks on the
  final resolved runtime provider/model and live MCP object. Approved low-side
  behavior remains a no-op.

## Conclusion
Phase 3 is hardened **and** still capable. CUI inference stays available
through every authorized in-boundary provider on all routing paths, approved
skills and MCP servers still function, and the supply-chain gates + BOM produce
assessor evidence. **No tested mission capability regressed.**
Save point `gov-P3-good` is eligible only after the close-out merge and
post-merge verification; it is not present on this review branch.
