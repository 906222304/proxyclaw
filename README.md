<div align="center">

<img src="assets/proxyclaw.png" width="112" alt="ProxyClaw 图标" />

# ProxyClaw

**只让指定的程序（连同它的子进程）走 SOCKS5 代理，其余流量照常直连，不用开全局 TUN。**

[![Build](https://img.shields.io/github/actions/workflow/status/906222304/proxyclaw/release.yml?branch=main&style=flat-square&label=build)](https://github.com/906222304/proxyclaw/actions/workflows/release.yml)
[![License](https://img.shields.io/github/license/906222304/proxyclaw?style=flat-square)](LICENSE)

**简体中文** · [English](README.en.md)

<img src="docs/images/network-dark.png" alt="ProxyClaw 网络活动" width="88%" />

</div>

## 特性

- **进程级代理**：基于 WinDivert，只转发命中规则的进程，不改系统路由。
- **进程树**：规则命中后，子进程自动跟随，适合 Chromium / Electron 等多进程应用。
- **规则**：按进程名、路径、命令行关键词匹配，可限定 TCP / UDP、网段和端口；网络活动里能看到每条连接命中的规则与原因。
- **代理组与测速**：多个 SOCKS5 后端，分阶段测速，失败时指出卡在哪一步。
- **DNS 代理（可选）**、**UDP 转发**、托盘常驻、开机静默启动、深浅色主题。

## 快速开始

需要 Windows 10 2004+ / 11（x64）、管理员权限、WebView2 Runtime。

1. 从 [Releases](https://github.com/906222304/proxyclaw/releases) 下载 zip，完整解压（要开机自启请放在 `C:\Program Files\ProxyClaw`）。
2. 运行 `proxyclaw.exe` 并同意 UAC。
3. 在“代理”页把 `default` 组指向你的 SOCKS5（如 `127.0.0.1:7890`），到“规则”页添加规则并打开开关。

配置在同目录的 `proxyclaw.json`，日志在 `proxyclaw.log`。目前只接管 IPv4，IPv6 直连。问题排查见 [TROUBLESHOOTING](docs/TROUBLESHOOTING.md)。

## 构建

需要 Visual Studio 2026 / 2022、CMake 3.20+、Python 3.12+、Node.js 22。

```powershell
python scripts/prepare_release_deps.py
cmake --preset windows-vs2026
cd frontend; npm ci; npm run build; cd ..
cmake --build --preset windows-vs2026
ctest --preset windows-vs2026
```

`python scripts/verify.py` 一次跑完全部测试。架构见 [ARCHITECTURE](docs/ARCHITECTURE.md)。

## 致谢

基于 [Clew v0.10.0](https://github.com/ymonster/clew-proxy/tree/v0.10.0)（[@ymonster](https://github.com/ymonster)）开发；转发依赖 [WinDivert](https://github.com/basil00/Divert)。其它依赖见 [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES.md)。

## License

[MIT](LICENSE)，保留 Clew 原作者版权。WinDivert 使用 LGPL v3，见 `WinDivert-2.2.2-A/LICENSE`。
