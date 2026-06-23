# Attribution

Lliam-GOV is built on — and derived from — **[Hermes Agent](https://github.com/NousResearch/hermes-agent)** by **Nous Research**, released under the MIT License.

This file makes the lineage explicit so that credit to the upstream authors is clear and is never erased by the rebrand to Lliam-GOV.

## Upstream

| | |
| --- | --- |
| **Project** | Hermes Agent |
| **Author** | Nous Research |
| **Source** | https://github.com/NousResearch/hermes-agent |
| **License** | MIT — Copyright © 2025 Nous Research |

The upstream MIT license text is retained verbatim in [LICENSE](LICENSE) at the repository root, as the MIT License requires. It is not modified, relicensed, or removed.

### What is upstream Hermes Agent work

The substantive runtime is upstream. This includes, but is not limited to:

- the agent runtime and conversation loop (`agent/`),
- the CLI and entry points (`hermes_cli/`, `cli.py`, `run_agent.py`),
- provider adapters and transports (`agent/transports/`, `providers/`),
- the tool system and toolsets (`tools/`, `toolsets.py`),
- the messaging gateway scaffolding (`gateway/`, `tui_gateway/`),
- the skill and plugin frameworks (`skills/`, `plugins/`),
- the dashboard / TUI (`ui-tui/`, `web/`), and
- the on-disk layout (`~/.hermes/`), environment variables (`HERMES_*`), and internal module names (`hermes_*`), which are intentionally left unchanged to preserve drop-in compatibility with upstream.

Upstream documentation and release notes are preserved under [`docs/upstream/`](docs/upstream/).

## Lliam-GOV's contribution

Original to Lliam-GOV, maintained by **Jerome Davis**:

- the governance overlay in [`lliam_gov/`](lliam_gov/) — encryption at rest, append-only hash-chained audit logging, egress allowlisting with TLS enforcement, capability/principal isolation, CUI marking, a human-approval gate over agent self-modification, and auditor-evidence export;
- the wiring of those controls into the runtime's privileged paths;
- the governance documentation under [`docs/governance/`](docs/governance/), including the control matrix and ISO/IEC 42001 / NIST AI RMF crosswalks; and
- the evidence set under [`evidence/`](evidence/).

These contributions are: Copyright © 2025 Jerome Davis, released under the same MIT License.

## Copyright

```
Copyright (c) 2025 Nous Research      — upstream Hermes Agent
Copyright (c) 2025 Jerome Davis       — Lliam-GOV governance overlay and documentation
```

Both notices stand together. Neither replaces the other. See [NOTICE](NOTICE) for the narrative summary.

## No endorsement

Nous Research is credited as the upstream author. Nous Research does not sponsor, endorse, or support Lliam-GOV, and Lliam-GOV is not an official Nous Research product.
