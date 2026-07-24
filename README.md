<p align="center">
  <img src="assets/lliam-gov-icon.png" alt="Lliam-GOV" width="160">
</p>

<h1 align="center">Lliam-GOV</h1>

<p align="center">
  <strong>How much security-as-code can an AI agent carry and still remain capable?</strong>
</p>

<p align="center">
  An open, self-assessed security-engineering case study built on
  <a href="https://github.com/NousResearch/hermes-agent">Hermes Agent</a> by Nous Research.
</p>

---

## The question

Capable AI agents are useful because they can reason across documents, write and
run code, call tools, access model providers, and coordinate multi-step work. Those
same capabilities complicate adoption in regulated environments.

Lliam-GOV is a working research vehicle for a practical question:

> How far can policy-as-code, runtime security controls, automated evidence, and
> fail-closed defaults constrain a frontier-model-capable knowledge-work agent
> without removing the capabilities that make it useful?

The project treats governance as an engineering discipline. Controls live beside
the code. CI tests them. Verification reports record what passed, what regressed,
and what remains a deployment decision.

## What this is

Lliam-GOV is a governance-hardened fork of the MIT-licensed Hermes Agent. It
retains a broad agent capability baseline—including terminal and desktop
interfaces, model-provider choice, tool use, coding, document analysis,
delegation, skills, and integrations—while adding a strict governance profile
and an evidence trail around privileged behavior.

It is also a hands-on governance laboratory maintained by
[Jerome Davis](https://secondorderstrategy.com/work/lliam-gov): a way to translate
control objectives into configuration, runtime enforcement, CI gates, and explicit
residual-risk decisions. The intended audience is anyone exploring responsible
agent adoption in regulated, federal, or defense-industrial-base environments.

## How the case study works

Each hardening phase follows the same testable loop:

1. Record the inherited capability baseline.
2. Add a control at the closest enforceable layer.
3. Test the control and its failure mode.
4. Re-run a representative capability-preservation corpus.
5. Record evidence, exceptions, and residual risk in version control.

This makes the experiment falsifiable: a control that exists only in prose does
not count as implemented, and a control that destroys the useful capability
baseline is treated as a regression to resolve or document.

## Current status

The repository's internal baseline contains **188 project-defined controls across
21 domains**. At the `gov-P5-good` tag, the project records all 188 as implemented
and has completed the hardening work through Phase 5. This is project-authored,
self-assessed evidence—not an independent assessment of operational effectiveness.

| Workstream | Repository status | Evidence |
|---|---|---|
| Product identity migration | Complete | [`R-rename-report.md`](docs/governance/verification/R-rename-report.md) |
| Phase 0 — baseline governance overlay | Implemented and tested | [`P0-capability-preservation-report.md`](docs/governance/verification/P0-capability-preservation-report.md) |
| Phase 1 — identity, audit, and principal isolation | Implemented and tested | [`P1-capability-preservation-report.md`](docs/governance/verification/P1-capability-preservation-report.md) |
| Phase 2 — authorization, egress, and data protection | Implemented and tested | [`P2-capability-preservation-report.md`](docs/governance/verification/P2-capability-preservation-report.md) |
| Phase 3 — provider and supply-chain governance | Implemented and tested | [`P3-capability-preservation-report.md`](docs/governance/verification/P3-capability-preservation-report.md) |
| Phase 4 — management-system evidence | Implemented and tested | [`P4-capability-preservation-report.md`](docs/governance/verification/P4-capability-preservation-report.md) |
| Phase 5 — monitoring and continuous-authorization signals | Implemented and tested | [`P5.V-report.md`](docs/governance/verification/P5.V-report.md) |
| Phase 6 — promotion and deployment cutover | Not complete | Deployment-specific work remains |

The consolidated project result is in the
[`FINAL hardening completion report`](docs/governance/verification/FINAL-hardening-completion-report.md).

## Security and governance as code

The implementation spans several layers:

- **Policy and configuration:** strict posture defaults, tool-risk policy,
  input-trust policy, approved-provider rules, skills allowlisting, and
  environment-specific profiles.
- **Runtime enforcement:** graduated human approval, policy-decision points,
  principal and capability scoping, egress and data-loss gates, audit-integrity
  controls, prompt-injection defenses, kill-switch behavior, and monitoring.
- **Isolation:** container-backed terminal execution, safe-root file boundaries,
  dropped capabilities, and deployment guidance for whole-process containment.
- **Supply chain:** reviewed dependency pins and hashes, critical-pattern scans,
  skill and MCP vetting, plus SBOM and AI-BOM artifacts.
- **Evidence:** control catalog, Statement of Applicability, system security plan,
  AI impact assessment, risk and deviation records, capability-preservation
  reports, and governance CI gates.

Start with:

- [`cli-config.gov.yaml`](cli-config.gov.yaml) — strict research profile
- [`policy/`](policy/) — machine-readable policies
- [`ci/governance-ci-gates/`](ci/governance-ci-gates/) — executable control tests
- [`docs/governance/`](docs/governance/) — governance and assurance artifacts
- [`SECURITY.md`](SECURITY.md) — threat model, limitations, and reporting process

## Capability preservation

The phase reports exercise representative daily knowledge-work capabilities while
the controls are active, including:

- approved-provider inference;
- multi-file coding and test execution in a sandbox;
- analysis of a CUI-marked test document with markings preserved;
- permitted low-risk tools and bounded network behavior; and
- agent workflows exercised after each hardening phase.

These are scoped project tests, not a comparative model-performance benchmark.
They support the conclusion that useful capability survived the tested controls;
they do not prove “frontier-level performance” or universal task coverage.

## The security boundary

Lliam-GOV deliberately makes a distinction that agent-security projects often
blur:

> **OS-level isolation is the security boundary for an adversarial model or
> untrusted input.**

Approvals, redaction, scanners, prompt-injection defenses, and allowlists inside
the agent process are valuable policy and defense-in-depth mechanisms. They are
not containment against code running in the same process. Shared or untrusted
deployments should wrap the whole process in an appropriate OS/container boundary,
not isolate only the terminal tool. See [`SECURITY.md`](SECURITY.md) for the full
trust model and supported posture.

## What this does not claim

Lliam-GOV is a research and engineering case study, not a compliance product.
It has not been independently assessed, accredited, authorized, or certified.
Installing it does not confer:

- an Authorization to Operate (ATO) or continuous ATO;
- authorization to process Controlled Unclassified Information;
- CMMC, FedRAMP, ISO/IEC 27001, or ISO/IEC 42001 status; or
- approval or endorsement by the U.S. Department of Defense, Department of War,
  or any customer.

Framework mappings are informative engineering artifacts. Actual suitability
depends on the complete system boundary, organization, data, infrastructure,
contracts, configuration, and operating evidence. Remaining deployment POA&Ms,
including FIPS and egress-enclave decisions, must be resolved by each adopter.

## Install and run

The installer builds Lliam-GOV locally and can include the desktop app:

**macOS / Linux / WSL2**

```bash
curl -fsSL https://raw.githubusercontent.com/jdavis-cyber/lliam-gov/main/scripts/install.sh | bash -s -- --include-desktop
```

**Windows (PowerShell)**

```powershell
iex "& { $(irm https://raw.githubusercontent.com/jdavis-cyber/lliam-gov/main/scripts/install.ps1) } -IncludeDesktop"
```

Omit `--include-desktop` / `-IncludeDesktop` for a CLI-only install. Reload the
shell after installation, then use:

| Command | What it does |
|---|---|
| `lliam-gov` | Terminal chat |
| `lliam-gov desktop` | Desktop app |
| `lliam-gov setup` | Connect a model provider |
| `lliam-gov update` | Update to the latest version |

The standard install does not, by itself, establish a regulated deployment
boundary. Review the strict profile, intended-use constraints, `SECURITY.md`, and
deployment-specific open items before using sensitive data.

## Lineage and license

Lliam-GOV is derived from
[Hermes Agent](https://github.com/NousResearch/hermes-agent), created by Nous
Research and distributed under the MIT License. The governance overlay, evidence
set, and Lliam-GOV product identity are maintained by Jerome Davis.

The original copyright and permission notice are retained in [`LICENSE`](LICENSE):

```text
Copyright (c) 2025 Nous Research
Copyright (c) 2026 Jerome Davis — Lliam-GOV fork
```

Security vulnerabilities should be reported privately through
[GitHub Security Advisories](https://github.com/jdavis-cyber/lliam-gov/security/advisories/new).
