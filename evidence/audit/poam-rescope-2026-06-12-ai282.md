# POA&M Re-scope — SP 800-171 3.13.11 FIPS-Validated Cryptography — 2026-06-12 (AI-282)

Re-scopes the single open POA&M carried across Phases 3–5. Status in the
control matrix remains `not_implemented` (no aspirational flip); what changes
is the POA&M framing: from "blocked on FIPS infrastructure, provision at the
Katmai MacBook install" to "conditional on a Katmai deployment decision."

## Corrected facts

1. **Device ownership.** The Phase 6 install target (AI-234) is the owner's
   personally-owned MacBook, NOT a Katmai-issued device. Earlier issue text
   assumed the install would occur "inside Katmai's CMMC L2 boundary" — that
   assumption was wrong. A personally-owned device sits outside any CMMC
   boundary, and CUI must not be processed on it regardless of crypto module.

2. **Control trigger.** 3.13.11 reads: "Employ FIPS-validated cryptography
   **when used to protect the confidentiality of CUI**" (800-171 r2; r3
   03.13.11 is the SC-13 analogue). The trigger is CUI presence. No CUI is
   processed on the current deployment: CUI handling in Lliam-GOV is
   audit-only custody (AI-223, deliberately no gating), and the system has
   no CUI data flows in scope.

## Posture (unchanged, already enforced)

`lliam_gov/security/runtime_guard.py::fips_check` fails closed: under the
production profile, a non-FIPS OpenSSL backend refuses to start
(`FipsNotAvailable`), with `LLIAM_GOV_ALLOW_NON_FIPS=1` as the explicit,
logged dev-host opt-out. The control is enforced **as a refusal** today:
the system cannot silently claim a CUI-protective posture it does not have.
Evidence: evidence/audit/fips-mode-startup-check.txt.

## Re-scoped condition

The affirmative control (a CMVP-certificated module in the crypto path) is
required **only if** Katmai approves a CUI-in-scope deployment on a
Katmai-managed device. That decision belongs to Katmai, after they demo the
software and audit the security package and agent documentation. Until that
decision, this POA&M is conditional — not blocked, not deferred-by-neglect.

## Provisioning path (if Katmai approves)

The operator does not author or "provide" a crypto module; FIPS validation
attaches to specific binary modules with CMVP certificates, satisfied by
running on one:

- **FIPS-enabled container base** (Ubuntu Pro FIPS or RHEL UBI in FIPS
  mode), where the system OpenSSL is the validated module and `cryptography`
  is built against it — the practical route on macOS hosts.
- **OpenSSL 3.x FIPS provider build**: compile `cryptography` against an
  OpenSSL 3.x with the CMVP-certificated FIPS provider enabled.
- Note: Apple CoreCrypto is itself FIPS-validated, but the pyca/cryptography
  wheels bundle their own OpenSSL and never touch CoreCrypto, so macOS
  validation does not transfer — `fips_check` can never pass on stock
  wheels regardless of device ownership.

## Acceptance (when the condition fires)

Unchanged from AI-282: crypto path uses a FIPS 140-2/140-3 validated module
(certificate referenced), evidence captured, 3.13.11 matrix row flipped.
