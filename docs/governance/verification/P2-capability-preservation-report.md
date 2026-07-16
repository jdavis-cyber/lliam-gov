# P2 — Capability-Preservation Verification Report

| Field | Value |
|---|---|
| Phase | Phase 2 — Authorization, Oversight & Egress |
| Gate | AI-487 (P2.V) |
| Branch | `harden/phase-2-authz-egress` |
| Date | 2026-07-15 |
| Result | **PASS** — no mission capability regressed |

## Purpose
Prove empirically that the Phase 2 graduated-enforcement layer (tool-risk PDP,
HITL gates, injection defense, data-protection/DLP, egress boundary, memory
governance) hardened the agent **without crippling it** — the phase's central
capability-preservation constraint. Per-emphasis (Plan §6): low/medium actions
stay allow/log (no approval fatigue); high-risk completes with an approver;
allowlisted egress succeeds; the only new blocks are CUI-tainted egress to
non-allowlisted sinks, hardline/sudo-stdin, and missing-approver high-risk.

## Phase 2 slices verified
| Step | Issue | Controls | New blocks introduced |
|---|---|---|---|
| P2.1 | AI-481 | LG-AZ-01/06/07/10/12, RM-08 | high-risk→HITL, deny-tier only |
| P2.2 | AI-482 | LG-HO-01..10 | non-interactive high-risk (fail-closed), sudo-stdin |
| P2.3 | AI-483 | LG-PI-04/06/09 | injected-content-triggered egress/exec → HITL |
| P2.4 | AI-484 | LG-DP-01..11 | CUI-tainted egress to non-allowlisted sink |
| P2.5 | AI-485 | LG-NE-01..06 | non-allowlisted / SSRF / metadata egress |
| P2.6 | AI-486 | LG-MC-02/04/05/06/07 | critical memory write → HITL |

## Findings
- **Graduated ladder holds:** allow / detect_log tiers proceed unprompted;
  only the High tier pauses for a human; only categorically-unsafe classes are
  hard-denied. Confirmed across the composed surfaces (105 Phase-2 unit tests +
  the 8-item capability corpus).
- **No approval fatigue:** file reads, in-safe-root writes, and non-destructive
  shell are never gated under the strict overlay.
- **Capability corpus green (§6):** safe-root coding, CUI-marked analysis with
  markings preserved, allowlisted provider inference, allowlisted web/MCP
  egress, and approver-gated high-risk all pass.
- **Acceptance boundary exact:** only the three authorized new-block classes
  appeared; nothing else broke.
- **Full-suite at the noise floor:** 60/21, zero new failures vs the
  characterized floor — additive hardening did not degrade any existing
  behavior.
- **Additive + path-frozen:** path-freeze gate green vs `gov-P1-good`
  (29 guarded paths, none renamed).

## Conclusion
Phase 2 is hardened **and** still fully capable. The agent remains a useful
coding / analysis / ops assistant; graduated enforcement gates only high-impact,
irreversible, or CUI-exfiltrating actions, and hard-denies only the categorically
unsafe. **No mission capability regressed.** Save point `gov-P2-good` tagged on
the Phase 2 close-out merge.
