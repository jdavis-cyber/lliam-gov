# Fresh-machine setup — clone to running (macOS)

Get Lliam-GOV running on a brand-new Mac from a `git clone`, with your choice of
**Claude Code, Codex, or Gemini** as the inference provider. Switch providers any
time — Lliam-GOV uses the provider's own CLI for auth and inference, so it never
stores API keys (AI-334).

> Verified end-to-end from a fresh clone: clone → install → posture OK →
> provider selection → real prompt executed and returned a result.

## Prerequisites (one-time, if not already present)

- **git**, **curl** (preinstalled on macOS).
- **Node.js** (for the provider CLIs): `brew install node` (or from nodejs.org).
- `uv` is installed automatically by the installer if missing.

## 1. Clone

```bash
git clone https://github.com/jdavis-cyber/lliam-gov.git
cd lliam-gov
```

## 2. Install (governed demo/eval profile)

```bash
bash scripts/install-governed-macbook.sh
```

This installs `uv` if needed, syncs dependencies, creates the private governed
workspace `~/.lliam-gov` (mode 0700), writes `governed-demo.env`, runs a
fail-closed posture check, and creates a double-clickable launcher.

## 3. Choose a provider

```bash
source ~/.lliam-gov/governed-demo.env
bash scripts/show-providers.sh
```

This shows each provider's status (`Ready` / `Needs sign-in` / `Not installed`)
and the exact command to make any one ready. Install + log in to whichever you
want (no API keys — the CLI owns login):

| Provider | Install | Log in |
| --- | --- | --- |
| Claude Code | `npm install -g @anthropic-ai/claude-code` | `claude setup-token` |
| Codex | `npm install -g @openai/codex` | `codex login` |
| Gemini | `npm install -g @google/gemini-cli` | `gemini` (browser sign-in) |

Re-run `bash scripts/show-providers.sh` until your chosen provider shows
`✓ Ready`.

## 4. Run

```bash
uv run lliam-gov            # or double-click ~/.lliam-gov/start-lliam-gov.command
```

## Switching providers (Katmai policy changes)

Install/log in to a different provider CLI (step 3) and re-run
`show-providers.sh`. Any provider shown as `Ready` is selectable — no
reinstall, no API-key juggling.

## Notes

- The demo profile waives the FIPS hard-gate for personal/no-CUI use
  (POA&M AI-282). Do **not** use this profile on a Katmai-managed / CUI device.
- The posture check fails closed: if `~/.lliam-gov` isn't `0700`, install stops
  with an exact `chmod` fix.
- Windows is not yet covered by a seamless installer — see the deployability
  notes; the POSIX posture guard needs a Windows path (parked pending decision).
