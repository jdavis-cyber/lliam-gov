# Lliam-GOV

**A personal AI agent with governance built in.**

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License: MIT"></a>
  <a href="ATTRIBUTION.md"><img src="https://img.shields.io/badge/Built%20on-Hermes%20Agent-blueviolet?style=for-the-badge" alt="Built on Hermes Agent"></a>
  <a href="docs/governance/control-matrix.md"><img src="https://img.shields.io/badge/Governance-ISO%2042001%20%2F%20NIST%20AI%20RMF-0A66C2?style=for-the-badge" alt="Governance"></a>
</p>

Lliam-GOV is an agentic LLM assistant for environments where **autonomy has to stay accountable**. It pairs a capable open-source agent runtime with a governance overlay that puts policy controls, approval gates, and auditability at the core — not bolted on afterward. Every privileged action is mediated, logged to an append-only audit trail, and constrained by an explicit egress and capability policy.

It is built for operators who need an AI number-two they can actually answer for: encryption at rest, a human-approval gate over the agent's own self-modification, a narrowed messaging surface, and a documented control set that maps to ISO/IEC 42001 and the NIST AI RMF.

> **Built on Hermes Agent.** Lliam-GOV is derived from [Hermes Agent](https://github.com/NousResearch/hermes-agent) by Nous Research (MIT-licensed). The agent runtime, conversation loop, tool system, and gateway are upstream work; Lliam-GOV's contribution is the governance overlay and the evidence set around it. See [ATTRIBUTION.md](ATTRIBUTION.md) for the full lineage and credit.

---

## What makes it governed

The governance overlay lives in [`lliam_gov/`](lliam_gov/) and is wired into the runtime's privileged paths. Each control below maps to actual instrumentation, not aspiration:

| Control | What it does | Where |
| --- | --- | --- |
| **Encryption at rest** | Agent state and sensitive files are encrypted with managed keys before they touch disk. | `lliam_gov/security/encrypted_file.py`, `key_manager.py`, `state_codec.py` |
| **Append-only audit log** | Privileged actions, session open/close, and gateway traffic are written to a hash-chained, tamper-evident audit trail. | `lliam_gov/security/audit_logger.py`, `session_audit.py`, `gateway_audit.py` |
| **Egress allowlist + TLS** | Outbound network access is denied by default and constrained to an explicit allowlist with TLS enforcement. | `lliam_gov/security/egress.py` |
| **Human-approval gate on self-modification** | The agent cannot silently rewrite its own skills/config — dynamic self-modification is gated behind explicit approval. | `lliam_gov/security/selfmod_gate.py` |
| **Capability & principal isolation** | Privileged operations are checked against a principal's granted capabilities; isolation is enforced at runtime. | `lliam_gov/security/capabilities.py`, `principal.py`, `privileged_access.py`, `runtime_guard.py` |
| **CUI marking & handling** | Controlled-information marking and audit instrumentation (the demo boundary is fail-closed: **no CUI in scope**). | `lliam_gov/security/cui.py` |
| **Audit evidence export** | Governance evidence can be exported as an auditor-ready package (AEP). | `lliam_gov/security/aep_export.py` |

The full control set, with crosswalks to ISO/IEC 42001 and the NIST AI RMF, is documented in [`docs/governance/control-matrix.md`](docs/governance/control-matrix.md). Supporting evidence lives under [`evidence/`](evidence/).

Under the governance layer sits a full-featured agent: a terminal UI, a messaging gateway (narrowed to Slack, email, and Telegram), provider-agnostic model support, a skill system, scheduled automations, and subagent delegation — all inherited from the Hermes Agent runtime.

---

## Quickstart

Lliam-GOV is distributed as source. Clone the repo and run the setup script, which provisions `uv`, a virtualenv, and the agent dependencies:

```bash
git clone https://github.com/jdavis-cyber/lliam-gov.git
cd lliam-gov
./setup-hermes.sh     # installs uv, creates .venv, installs .[all], links the CLI
./hermes              # auto-detects the venv — no need to `source` first
```

Manual path (equivalent):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
uv venv .venv --python 3.11
source .venv/bin/activate
uv pip install -e ".[all,dev]"
scripts/run_tests.sh
```

Then configure a model provider and start a conversation:

```bash
hermes              # interactive CLI
hermes model        # choose your LLM provider and model
hermes tools        # configure which tools are enabled
hermes gateway      # start the messaging gateway (Slack, email, Telegram)
hermes setup        # full first-run setup wizard
hermes doctor       # diagnose issues
```

> **Note on the CLI name.** The runtime command, on-disk home (`~/.hermes/`), and internal module names are inherited from the upstream Hermes Agent and are intentionally left unchanged so the agent stays drop-in compatible with upstream and so existing installs and audit evidence keep working. Lliam-GOV is the product identity; `hermes` is the underlying runtime it ships on.

Use any model you want — OpenAI, Anthropic, OpenRouter, or your own endpoint. Switch with `hermes model`; no code changes.

---

## Architecture

```
lliam-gov/
├── lliam_gov/            # ← Governance overlay (Lliam-GOV's contribution)
│   └── security/         #   encryption, audit, egress, CUI, self-mod gate, isolation
├── agent/                # Agent runtime — conversation loop, providers, tools (upstream Hermes)
├── hermes_cli/           # CLI entry points (upstream Hermes)
├── gateway/              # Messaging gateway, narrowed to Slack / email / Telegram
├── tools/ · toolsets.py  # Tool implementations and toolset system
├── docs/
│   ├── governance/       # Control matrix, AIMS documented information, threat models
│   └── upstream/         # Preserved upstream Hermes docs & release notes (attribution)
└── evidence/             # Governance evidence artifacts
```

The runtime is the upstream Hermes Agent. Lliam-GOV adds the `lliam_gov/` package and wires its controls into the runtime's privileged paths (e.g. the audit hooks in `agent/conversation_loop.py`). Governance is enforced at the boundary, so the agent's day-to-day capabilities are unchanged while every privileged action remains accountable.

**Scope boundary:** Lliam-GOV's reference deployment is a single-operator evaluation environment. The demo boundary is fail-closed and carries **no CUI**. See [`docs/governance/`](docs/governance/) for the documented scope and control posture.

---

## Acknowledgements / Upstream

Lliam-GOV is built on **[Hermes Agent](https://github.com/NousResearch/hermes-agent)** by **Nous Research**, used under the MIT License. The upstream copyright and license are retained in full in [LICENSE](LICENSE), and the relationship — what is upstream and what is original to Lliam-GOV — is documented in [ATTRIBUTION.md](ATTRIBUTION.md) and [NOTICE](NOTICE). Upstream documentation and release notes are preserved under [`docs/upstream/`](docs/upstream/).

Lliam-GOV does not claim authorship of the upstream Hermes Agent codebase. Nous Research is credited as the upstream author; it does not endorse Lliam-GOV.

---

## License

MIT — see [LICENSE](LICENSE).

- Upstream Hermes Agent: Copyright © 2025 Nous Research
- Lliam-GOV governance overlay and documentation: Copyright © 2025 Jerome Davis

Both notices are retained; neither replaces the other. See [ATTRIBUTION.md](ATTRIBUTION.md).
