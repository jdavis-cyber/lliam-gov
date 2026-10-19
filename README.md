# Lliam-GOV

**Put agents to work. Keep the organization in control.**

Agents can help with research, document analysis, coding and tool-driven work. Bringing them into an organization also means deciding what they may access, where people need to review changes and how to investigate behavior when something goes wrong.

Lliam-GOV explores that adoption problem through working code. It combines the capabilities of [Hermes Agent](https://github.com/NousResearch/hermes-agent) with configurable policies, review mechanisms and operational evidence. The goal is informed delegation: useful work within boundaries that a team can inspect and evaluate.

[Explore the agent](website/docs/developer-guide/architecture.md) · [Follow a control](policy/tool-risk-policy.yaml) · [Review the security model](SECURITY.md)

## Useful work, with decisions around it

**Set boundaries for the task.** Tool-risk policies, provider configuration and egress checks give operators places to define permitted behavior. The strict reference profile shows how those choices can be assembled for evaluation.

**Keep people involved in change.** Optional staged memory and skill writes can be reviewed before application. Review commands expose pending changes, skill diffs, approval and rejection, giving people a way to assess what the agent proposes to retain or reuse.

**Make behavior inspectable.** Structured audit events, redaction, integrity checks and configurable runtime monitoring provide material for investigating instrumented activity. That can help a team ask what happened, which policy applied and what needs closer review.

These mechanisms support a practical adoption process: choose a bounded workflow, evaluate its controls and use the evidence to decide what to delegate next.

## Potential uses

A program team could evaluate an agent that prepares a research brief from approved material. An analyst could use it to compare documents; an engineering team could explore coding assistance within a controlled workspace.

For each workflow, the team would define access, review points and the evidence it needs to inspect the result.

## How the engineering supports that control

The code includes a tool-policy decision layer, network-egress checks, staged-write review handlers and a structured audit ledger. Runtime monitors can consume recorded events to flag patterns such as repeated tool calls, policy violations or changes in observed provider/tool metadata.

The repository's hardening reports describe the project's control work and scoped capability checks. They provide an engineering record to examine, rather than a blanket guarantee that every tool, interface and deployment path behaves identically.

[Hermes Agent](https://github.com/NousResearch/hermes-agent) supplies the agent platform, interfaces, provider support and much of the tool ecosystem. Lliam-GOV's contribution is the security and governance overlay, its configuration and the associated evaluation record.

## Explore or evaluate

- **Start without installing:** compare the [tool policy](policy/tool-risk-policy.yaml), [decision layer](tools/tool_policy.py) and [regression tests](tests/tools/test_tool_policy_pdp.py).
- **Inspect the mechanisms:** [tool-risk policy](policy/tool-risk-policy.yaml), [staged-write review](lliam_cli/write_approval_commands.py), [audit ledger](agent/governance_audit.py) and [runtime monitors](agent/runtime_monitors.py).
- **Plan a bounded trial:** review the [strict profile](cli-config.gov.yaml), [network-isolation guidance](docs/security/network-egress-isolation.md) and [installation guide](website/docs/getting-started/installation.md). Windows users can use the [PowerShell installer](scripts/install.ps1). Use synthetic data and test the review and event-capture paths needed for your workflow.
- **Assess the evidence:** consult the [hardening reports](docs/governance/verification/) and [consolidated engineering record](docs/governance/verification/FINAL-hardening-completion-report.md) before drawing deployment conclusions.

## Evaluation boundaries

Lliam-GOV is a reference implementation and engineering evaluation project. Each deployment requires validation of its selected tools, policies and integrations.

**Whole-process OS or container isolation remains the containment boundary.** In-process checks do not contain arbitrary code with the agent's privileges. Review coverage and event capture depend on configuration and execution paths. The project provides no certification, deployment authorization or permission to process CUI. See [SECURITY.md](SECURITY.md).

Maintained by [Jerome Davis / Second Order Strategy](https://secondorderstrategy.com). [Contribute](CONTRIBUTING.md) · [Report a security issue](SECURITY.md) · [MIT license](LICENSE), retaining Nous Research and Jerome Davis attribution.
