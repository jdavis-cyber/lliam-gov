# Lliam-GOV — Governed Production Profile (LG-4.7 / AI-224)

**Review cadence:** each phase gate, and whenever a control-surface env var is added.
**Applies to:** the Katmai production host (MacBook). Development hosts use dev parity (everything below off) and MUST NOT carry production data.

The production profile is the set of environment defaults under which every
Phase 3/4 control is active. `lliam_gov.security.runtime_guard.production_posture_check()`
validates the posture at startup and fails closed on the first violation.

## Required environment

| Variable | Production value | Control |
|---|---|---|
| `HERMES_HOME` | explicit path, dir mode `0700`, owned by the operator | workspace guard (LG-4.4) |
| `LLIAM_GOV_PROFILE` | `production` | root refusal + principal binding (LG-4.1) |
| `LLIAM_GOV_ENCRYPT_STATE` | `1` | encryption at rest, encrypted backups (LG-3.7/3.9, SP 800-171 3.8.9, 3.13.16) |
| `LLIAM_GOV_EGRESS_ENFORCE` | `1` | egress allowlist + TLS posture (LG-4.3, 3.1.20/3.13.1/3.13.8) |
| `LLIAM_GOV_CAPABILITY_ENFORCE` | `1` | capability-tagged dispatch (LG-4.2, 3.1.2) |
| `LLIAM_GOV_SELFMOD_GATE` | `1` | human-approval gate for self-modification (LG-4.5, ISO 42001 A.6.2.4) |
| `LLIAM_GOV_ALLOW_NON_FIPS` | **MUST NOT BE SET** | FIPS hard gate (LG-3.1, 3.13.11 — POA&M AI-282) |

## Optional narrowing

| Variable | Effect |
|---|---|
| `LLIAM_GOV_CAPABILITIES` | Replace the conservative `GOVERNED_BASELINE` (fs_read, fs_write, messaging, memory_write) with an explicit grant list. Grants only — `unclassified` is never grantable. |
| `LLIAM_GOV_PRIVILEGED_USERS` | Narrow (never widen) the audit/key/approval CLI ACL beyond home-ownership. |
| `LLIAM_GOV_EGRESS_ALLOWLIST` | Inline allowlist override; otherwise `<home>/egress-allowlist.txt`. |

## Startup order (what fails closed, in order)

1. Principal binding — refuses root (`ProductionRootRefused`).
2. FIPS probe — refuses non-FIPS OpenSSL (`FipsNotAvailable`).
3. Encrypt-state check — refuses plaintext persisted state.
4. Workspace check — refuses non-0700 / foreign-owned home.
5. Umask — tightened to at least `0077` (never loosened).
6. Keychain probe — refuses if key material is unreachable.
7. Sync-path warning — warns (does not refuse) under iCloud/Dropbox/OneDrive/Google Drive.

A template env file lives at `docs/operate/production.env.example`.
