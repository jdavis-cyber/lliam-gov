# claude-bridge — governed capabilities design note

Status: PROPOSAL (for review before building). Date: 2026-06-17.
Scope: how to give the Claude-via-`claude -p` bridge real tools/skills without
regressing the working pure-chat path.

## 0. Governing principle

**Whoever executes a tool governs it.** Lliam's egress firewall (`egress.py`) and
audit chain wrap *Hermes' own process*. A `claude -p` subprocess runs outside
them. So there are two distinct governance domains, and the design treats them
separately:

- **Claude-native tools** (Read/Grep/Bash/Edit/WebFetch…) execute in the `claude`
  subprocess → governed by **Claude Code's** model: `--permission-mode`,
  `--allowedTools`/`--disallowedTools`, `--settings` hooks, and the `--add-dir`
  filesystem sandbox. NOT by Lliam's overlay.
- **Lliam-MCP tools** (`hermes mcp serve`) execute **inside Lliam** → governed by
  the **full overlay** (egress, audit, privileged gates). Surface today is the
  10-tool messaging/channel set (conversations_list, messages_read,
  messages_send, channels_list, permissions_respond, events_poll, …).

## 1. Non-breaking guarantee

- Default behavior is UNCHANGED: `CLAUDE_BRIDGE_TOOLS=off` ⇒ today's pure
  responder (`--max-turns 1 --allowedTools ""`). This is the floor and the
  fallback.
- Capability is a single env var read by the bridge at call time:
  `CLAUDE_BRIDGE_TOOLS = off | read | agent | mcp | mcp+read`
  (set in `~/.lliam-gov/.bridge_env`, reloaded per request — no rebuild).
- Any tier failure (claude error, MCP down) falls back to returning the error
  string exactly as today; the working chat never hard-breaks.
- Fully reversible: flip the var back to `off`.

## 2. The sandbox boundary (shared by all Claude-native tiers)

- A dedicated governed workspace: `~/.lliam-gov/workspace/` (created empty).
- `claude` runs with `cwd=~/.lliam-gov/workspace` and `--add-dir` limited to it
  (plus, optionally and read-only, the project the user names per session).
- Hard exclusions (never in `--add-dir`): `~/.hermes` (the EA), `~/.lliam-gov`
  internals (token, auth.json, audit chain, egress allowlist), `~/.ssh`, `~/.aws`.
- `--settings` JSON pins: permission rules, and a `Deny` rule on reads/writes of
  credential paths even if a dir is added.

## 3. Tiers

### Tier 0 — off (current)
`--max-turns 1 --allowedTools ""`. Pure text. No tools. Governance: N/A.

### Tier 1 — read-only investigation + governed research  (`read`)
- Enable: `--allowedTools Read Grep Glob WebSearch` (NO Bash/Edit/Write).
- `--permission-mode default`, `--max-turns 8` (lets it chain reads/searches).
- Governance: Claude sandbox; cannot mutate anything; cannot leave `--add-dir`.
- Risk: very low.

#### Research / web — how it's governed
Two web tools, two egress profiles:
- **WebSearch = first-party, trusted.** Anthropic runs the search server-side;
  results return through `api.anthropic.com` (already in Lliam's egress allowlist).
  No new local egress. → ENABLED in `read`. This is the primary research tool.
- **WebFetch = arbitrary URL fetch = bounded by allowlist.** This makes an
  outbound request Lliam's `egress.py` can't see, so we govern it at the Claude
  layer: a `--settings` permissions file with `WebFetch(domain:…)` ALLOW entries
  and a default DENY — the same deny-by-default-add-what-you-need philosophy as
  `egress-allowlist.txt`, one layer up. Seed list lives in
  `~/.lliam-gov/.bridge_websearch_allowlist` (e.g. docs sites, the repos in scope);
  empty ⇒ WebFetch denied, WebSearch still works. → OFF until a domain is added.

Net: research works out of the box via WebSearch; fetching specific pages is
opt-in per-domain and auditable.

### Tier 2 — sandboxed agentic  (`agent`)
- Enable: `Read Grep Glob Bash Edit Write` inside the workspace only.
- `--permission-mode acceptEdits` (or `dontAsk`) within `--add-dir`; never
  `bypassPermissions` globally.
- Optionally run each session in a throwaway git worktree for clean rollback.
- Governance: Claude sandbox + permission mode; filesystem-contained. Shell/network
  side effects are Claude-governed, NOT Lliam-governed — acceptable only because
  cwd is an isolated workspace.
- Risk: medium (Bash inside a sandbox). Mitigation: workspace-only `--add-dir`,
  `--settings` deny rules, no access to home/creds.

### Tier 3 — Lliam-governed MCP tools  (`mcp`)
- Run `hermes mcp serve` (stdio) under `HERMES_HOME=~/.lliam-gov`.
- `claude -p --mcp-config <lliam-mcp>.json --strict-mcp-config --allowedTools "mcp__hermes__*"`.
- Claude calls Lliam's messaging/channel tools; they EXECUTE IN LLIAM → full
  egress + audit + privileged gates apply. THE truly-Lliam-governed path.
- Limitation: only the 10-tool messaging surface exists today. Extending to the
  general toolset (bash/file/web/skills) means widening `mcp_serve.py` — a
  separate, larger effort tracked as a follow-up.
- Risk: low on governance (Lliam gates it); adds an MCP server process to manage
  (the launcher starts/stops it alongside the bridge).

### Tier 4 — skills  (additive to any tier)
- Lliam skills live in `~/.lliam-gov/skills` (and `~/.hermes/skills`). Expose to
  Claude via a skills dir / `--add-dir` so Claude's skill resolver picks them up.
- Governance follows whichever tier executes the skill's tools.

## 4. Multi-turn / agent-ownership note

Tiers 1–3 require `--max-turns > 1` so Claude can call a tool, read the result,
and continue. That means **Claude Code runs the agentic loop**, and Hermes'/Lliam's
OWN tool loop is bypassed for these turns — Hermes sees a single final assistant
message. Consequence: governance for native tools is Claude's, not Lliam's
(hence Tier 3 for Lliam-governed execution). This is inherent to "Claude is the
engine" and is the reason the tiers are explicit about which domain governs.

## 5. Recommended rollout

`read` → verify the tool path end-to-end and the sandbox holds → `mcp` for the
Lliam-governed surface → `agent` only if the user wants Claude doing real file
work in the workspace. Each step is a var flip with the responder as the floor.

## 6. Open decisions for the user

1. Workspace location: `~/.lliam-gov/workspace` ok, or a project path?
2. RESOLVED — Research: WebSearch ON (first-party/trusted channel); WebFetch
   per-domain allowlist via `--settings` (deny-by-default). Confirm seed domains.
3. Tier 3: acceptable that today it's only messaging tools, with general-toolset
   MCP as a later effort?
4. Should the launcher auto-start `hermes mcp serve` when `CLAUDE_BRIDGE_TOOLS`
   includes `mcp`?
