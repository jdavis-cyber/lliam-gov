---
sidebar_position: 3
title: "Nix desktop setup"
---

# Nix desktop setup

The flake packages Lliam-GOV for a single desktop user. Nix packaging is maintained on a best-effort basis. With flakes enabled, run the following from a checkout of this repository.

```bash
nix run .#desktop
```

To install the desktop launcher in your user profile, run

```bash
nix profile install .#desktop
```

The desktop package starts Electron with the bundled Lliam-GOV CLI. To run the interactive CLI directly, use

```bash
nix run .#default
```

For declarative NixOS installations, add the flake's desktop package to the user's package list and rebuild that configuration.
