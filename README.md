<p align="center">
  <img src="assets/lliam-gov-icon.png" alt="LLIAM-GOV" width="160">
</p>

<h1 align="center">LLIAM-GOV</h1>

<p align="center">
  A fork of <a href="https://github.com/NousResearch/hermes-agent">Hermes Agent</a> by Nous Research —
  rebranded and being hardened for governance and security in federal and defense environments.
  <br><b>Work in progress.</b>
</p>

---

## Install

Installs LLIAM-GOV — the `hermes` command-line agent and (with `--include-desktop`) the desktop app, built from source on your machine. The installer provisions everything it needs (Python 3.11, Node.js, uv) automatically.

**macOS / Linux / WSL2:**

```bash
curl -fsSL https://raw.githubusercontent.com/jdavis-cyber/lliam-gov/main/scripts/install.sh | bash -s -- --include-desktop
```

**Windows (PowerShell):**

```powershell
iex "& { $(irm https://raw.githubusercontent.com/jdavis-cyber/lliam-gov/main/scripts/install.ps1) } -IncludeDesktop"
```

Omit `--include-desktop` / `-IncludeDesktop` for a CLI-only install (no desktop GUI build).

After it finishes, reload your shell:

```bash
source ~/.zshrc   # or ~/.bashrc
```

## Launch

| Command | What it does |
|---|---|
| `hermes` | Terminal chat (TUI) |
| `hermes desktop` | Open the LLIAM-GOV desktop app |
| `hermes setup` | Connect a model provider |
| `hermes update` | Update to the latest version |

> Optional: `ripgrep` and `ffmpeg` enable faster search and voice messages. Install them with your package manager (e.g. `brew install ripgrep ffmpeg`).

## License

Distributed under the **MIT License**, building on software originally created by Nous Research. The original copyright and permission notice are retained in [`LICENSE`](LICENSE), as required by its terms:

```
Copyright (c) 2025 Nous Research
Copyright (c) 2026 Jerome Davis — LLIAM-GOV fork
```
