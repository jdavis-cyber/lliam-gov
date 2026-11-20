---
sidebar_position: 3
title: "使用 Nix 运行桌面应用"
---

# 使用 Nix 运行桌面应用

本仓库的 flake 为单个桌面用户打包 Lliam-GOV。Nix 软件包由社区尽力维护。 启用 flakes 后，在本仓库的检出目录中运行以下命令。

```bash
nix run .#desktop
```

要在用户配置中安装桌面启动器，请运行

```bash
nix profile install .#desktop
```

桌面软件包会启动 Electron，并使用随附的 Lliam-GOV CLI。要直接运行交互式 CLI，请使用

```bash
nix run .#default
```

在声明式 NixOS 安装中，将 flake 的桌面软件包添加到用户的软件包列表并重新构建配置。
