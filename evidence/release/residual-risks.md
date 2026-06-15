# Residual risks & accepted limitations (AI-338)

Risks knowingly carried into the deployable release, with owner and the gating
work needed to retire each. Pairs with the threat model
(`docs/governance/provider-boundary-threat-model.md`).

| ID | Residual risk / limitation | Current mitigation | Retire when… | Owner |
|---|---|---|---|---|
| RR-1 | **CLI-backed inference** relies on third-party CLIs whose integrity Lliam-GOV cannot attest | env allowlist, explicit/temp cwd, output cap, timeout/cancel, redacted audit (AI-334) | provider CLI pinning/signature verification feasible | Jerome / providers |
| RR-2 | **Update / bootstrap trust** — installer fetched from GitHub raw at a pinned SHA with no signature check | immutable SHA URL + installed-agent fallback (AI-330) | backend-distribution-source decided + installer signing | **Jerome** |
| RR-3 | **No code signing/notarization** — users bypass Gatekeeper/SmartScreen | hardened-runtime + entitlements + notarize hook already configured | Apple Developer ID + Windows Authenticode certs obtained | **Jerome (procurement)** |
| RR-4 | **No CI provenance/checksums** for artifacts | release-readiness gate + local build | GitHub Actions restored (AI-332) | **Jerome / infra** |
| RR-5 | **Local logs** under `~/.lliam-gov/logs` may persist diagnostic text | runtime doesn't log prompts/output; failures redacted + truncated (AI-334) | log-retention/rotation policy documented | Jerome |
| RR-6 | **External provider availability** — outage/limits degrade the app | readiness probes + actionable errors; multi-provider choice | n/a (inherent to CLI-backed model) — accepted | accepted |
| RR-7 | **Windows posture not enforced** — FIPS-on-Windows + POSIX posture-guard rewrite parked | macOS posture proven; Windows marked pending in docs | parked posture-guard work unparked | **Jerome (parked)** |
| RR-8 | **Crash-dump leakage** (T8) | output cap bounds captured bytes; no tokens read into memory | OS crash-dump policy + symbol stripping in packaging (AI-331) | Jerome |

## Accepted-limitations summary

For the **T0 personal-demo** tier (see `deployment-tiers.md`), RR-2/RR-3/RR-4/RR-7
are **accepted** for now (single trusted operator, source/local build). They
become **must-fix** before the **T1 enterprise** tier, and all of the above plus
Katmai controls gate the **T2** tier.

No High/Critical dependency advisories are carried (see
`docs/governance/dependency-audit-policy.md` exceptions register — currently
empty).
