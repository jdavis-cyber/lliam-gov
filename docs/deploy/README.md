# Lliam-GOV — deployment, provider setup & troubleshooting (AI-336)

Install Lliam-GOV and run it with a CLI-backed LLM provider (Claude Code, Codex,
or Gemini / Antigravity). Lliam-GOV uses each provider's **own CLI** for
authentication and inference, so **Lliam-GOV never asks for or stores an API
key** — the CLI owns its credentials (see [Security notes](#security-notes)).

> **Platform status (June 2026).** The **macOS** path is complete and verified
> end-to-end. **Windows** sections are marked **⏳ pending Phase-3 posture guard**
> (the FIPS-on-Windows / cross-platform posture-guard work is parked).
> **Linux** runtime is supported from source; signed Linux *artifacts* are
> pending packaging (AI-331).

## Contents
1. [Install — macOS](#install--macos)
2. [Install — Windows ⏳](#install--windows-)
3. [Install — Linux](#install--linux)
4. [Provider setup (Claude Code / Codex / Gemini)](#provider-setup)
5. [Do I need an API key?](#do-i-need-an-api-key)
6. [Update](#update)
7. [Uninstall](#uninstall)
8. [Troubleshooting](#troubleshooting)
9. [Security notes](#security-notes)

---

## Install — macOS

### A. From a packaged app (end-user)
1. **Download** `Lliam-GOV-<version>-arm64.dmg` (Apple Silicon) or `-x64.dmg`
   (Intel) from the release source.
2. **Verify** the download against its published `SHA256SUMS`:
   ```bash
   shasum -a 256 ~/Downloads/Lliam-GOV-*.dmg
   # compare to the matching line in SHA256SUMS
   ```
   > Code-signing/notarization verification (Gatekeeper "Developer ID") is
   > **pending signing certs** (AI-331). Until then macOS may warn on first open;
   > right-click → Open.
3. **First launch.** Drag `Lliam-GOV.app` to `/Applications`, open it. On first
   run it provisions a managed backend under `~/.lliam-gov/lliam-gov`
   (location-independent — moving the app does not move the backend; see
   `docs/operate/managed-backend-bootstrap.md`). A progress screen shows the
   bootstrap stages.
4. **Pick a provider** on the first-run provider screen, or later via
   **Settings → Providers**.

### B. From source (developer / eval)
See [`docs/operate/fresh-machine-setup.md`](../operate/fresh-machine-setup.md) —
verified clone → install → posture OK → provider selection → real prompt.
Quick form:
```bash
git clone https://github.com/jdavis-cyber/lliam-gov.git && cd lliam-gov
bash scripts/install-governed-macbook.sh
source ~/.lliam-gov/governed-demo.env
bash scripts/show-providers.sh
```

---

## Install — Windows ⏳

> **Pending Phase-3 posture guard (parked).** The Windows posture guard
> (`workspace_check` / `umask_check` / `keychain_check` cross-platform rewrite)
> and FIPS-on-Windows posture are Jerome's parked decisions. Windows packaging
> (NSIS/MSI + Authenticode signing) is also pending signing certs (AI-331).
> The steps below are the **intended** flow and will be finalized when that work
> is unparked.

1. Download `Lliam-GOV-<version>-x64.exe` (NSIS) and verify against `SHA256SUMS`
   (`Get-FileHash`).
2. Run the installer; first launch bootstraps the managed backend under
   `%LOCALAPPDATA%\lliam-gov\lliam-gov`.
3. Provider setup is identical (the CLIs are cross-platform npm packages).

Until the posture guard lands, run on Windows **from source under WSL** or use
the macOS/Linux path.

---

## Install — Linux

Runtime is supported from source today; signed AppImage/deb/rpm artifacts are
pending packaging (AI-331).

```bash
git clone https://github.com/jdavis-cyber/lliam-gov.git && cd lliam-gov
bash scripts/install.sh        # managed backend under ~/.lliam-gov/lliam-gov
```
Provider setup below is identical.

---

## Provider setup

Lliam-GOV supports three provider CLI families. Install the CLI, log in **once**
through that CLI, then select it in Lliam-GOV. The app probes each provider and
shows one of: *not installed*, *installed but not authenticated*, *ready*,
*degraded*, *unavailable* — with the exact command to fix the current state.

All three CLIs are Node packages, so install **Node.js** first
(`brew install node`, nodejs.org, or your package manager).

| Provider | Install | Log in | Verify |
|---|---|---|---|
| **Claude Code CLI** (Anthropic) | `npm install -g @anthropic-ai/claude-code` | `claude setup-token` | `claude --version` |
| **Codex CLI** (OpenAI) | `npm install -g @openai/codex` | `codex login` | `codex --version` |
| **Gemini / Antigravity CLI** (Google) | `npm install -g @google/gemini-cli` | `gemini` → complete the browser sign-in on first run | `gemini --version` |

After logging in, open **Settings → Providers** in Lliam-GOV (or the first-run
screen), pick the provider, choose a model, and use **Test this provider** to run
a one-shot prompt and confirm it works end-to-end.

> These are the same commands Lliam-GOV displays in each provider card, sourced
> from the adapters in `providers/cli/` — they stay in sync with the app.

---

## Do I need an API key?

**No** — not for Lliam-GOV. When you use a CLI-backed provider, the provider's
CLI holds your credentials and performs inference. Lliam-GOV only checks
*whether* a provider is logged in (a yes/no signal); it never reads, stores, or
transmits your token.

However: **your provider account still applies.** You need an account with the
vendor, and the vendor's **rate limits, quotas, and plan tiers** govern usage.
A "rate limited" error comes from the provider, not Lliam-GOV (see
[Troubleshooting](#troubleshooting)).

---

## Update

- **App:** install the newer signed artifact over the old one (in-app update /
  channels are scaffolded in AI-333; trusted update source is **pending**
  Jerome's distribution-source decision + signing certs).
- **Managed backend:** the in-app update path / `lliam-gov update` moves the
  managed checkout to the new pinned ref. A backend pinned to an older commit
  than the app still runs and logs *"update available"* (see
  `docs/operate/managed-backend-bootstrap.md`).
- **Providers:** `npm update -g @anthropic-ai/claude-code @openai/codex @google/gemini-cli`.

---

## Uninstall

1. Quit Lliam-GOV.
2. Remove the app bundle (`/Applications/Lliam-GOV.app`, or the Windows/Linux
   equivalent).
3. Remove user data: `rm -rf ~/.lliam-gov` (macOS/Linux) or
   `%LOCALAPPDATA%\lliam-gov` (Windows). This deletes the managed backend, logs,
   and the bootstrap marker.
4. Provider CLIs are independent — uninstall separately if desired
   (`npm uninstall -g …`). Your provider login lives in the CLI's own store and
   is untouched by removing Lliam-GOV.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Provider card says **not installed** | CLI missing from PATH | Run the provider's install command above; reopen Lliam-GOV. |
| Provider card says **not authenticated** / prompt fails with auth error | Provider login missing or **expired** | Re-run the login command (`claude setup-token` / `codex login` / `gemini`). |
| Prompt fails with **rate limit / 429 / quota** | The *provider* throttled you (not Lliam-GOV) | Wait and retry, or upgrade your provider plan. Errors are marked retryable. |
| First launch stuck on **bootstrap** / "backend offline" | Bootstrap stage failed, or marker present without a venv | See the bootstrap run log under `~/.lliam-gov/logs/bootstrap-*.log`; re-launch to retry/repair. If persistent, [reset](#reset--reinstall). |
| **Update blocked** / won't apply | Unverified/untrusted update source (verification pending), or app in use | Quit the app and reinstall the verified artifact manually; confirm `SHA256SUMS`. |
| **Port conflict** (gateway won't bind) | Another process holds the desktop gateway port | Close the other process, or set a different port and relaunch. Check `~/.lliam-gov/logs/desktop.log`. |
| Output looks **truncated** mid-run | Provider exceeded the output-size cap (`OUTPUT_LIMIT`) | Expected safety limit; shorten the task or raise `max_output_bytes` for that call. |
| Need the **logs** | — | App + bootstrap logs: `~/.lliam-gov/logs/` (`desktop.log`, `agent.log`, `bootstrap-*.log`). Provider stderr is returned in the result, **not** merged into app logs. |
| **Reset / reinstall** | Corrupt or stuck install | Quit, `rm -rf ~/.lliam-gov` (or `%LOCALAPPDATA%\lliam-gov`), relaunch — first run re-bootstraps cleanly. Provider logins survive (they live in the CLIs). |

<a name="reset--reinstall"></a>

---

## Security notes

- **Credential ownership.** Each provider CLI owns its own auth store
  (under your home / OS keychain). Lliam-GOV never reads or stores provider
  tokens — only a boolean "logged in?" signal.
- **What leaves your machine.** When you run a prompt, Lliam-GOV sends the
  **prompt text and selected model name to the chosen provider's CLI only**;
  that CLI talks to its vendor endpoint using its own credentials. No API keys
  are added to the provider's environment; environment isolation drops any
  globally-exported `*_API_KEY` / `*_TOKEN` / `*_SECRET` before the CLI starts.
- **How logs are stored.** App logs live under `~/.lliam-gov/logs/`. The runtime
  does not log prompts or provider output; failure records are redacted and
  truncated. Full detail: `docs/governance/provider-boundary-threat-model.md`
  (threat model + per-provider data-flow).

---

*App onboarding/help linkage: the first-run provider screen and Settings →
Providers should link to this page and to the threat-model doc. (Wiring tracked
with the onboarding surfaces.)*
