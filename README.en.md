<div align="center">

<img src="assets/proxyclaw.png" width="112" alt="ProxyClaw icon" />

# ProxyClaw

**Send only the programs you choose (and their child processes) through a SOCKS5 proxy. Everything else stays direct, no system-wide TUN.**

[![Build](https://img.shields.io/github/actions/workflow/status/906222304/proxyclaw/release.yml?branch=main&style=flat-square&label=build)](https://github.com/906222304/proxyclaw/actions/workflows/release.yml)
[![License](https://img.shields.io/github/license/906222304/proxyclaw?style=flat-square)](LICENSE)

[简体中文](README.md) · **English**

<img src="docs/images/network-dark.png" alt="ProxyClaw network activity" width="88%" />

</div>

## Features

- **Per-process proxying**: built on WinDivert; only processes matched by a rule are forwarded, system routes are untouched.
- **Process trees**: once a rule matches, child processes follow, which suits multi-process apps like Chromium / Electron.
- **Rules**: match by process name, path or command-line keywords, limited to TCP / UDP, CIDRs and ports; network activity shows the rule and reason behind every connection.
- **Proxy groups and speed test**: multiple SOCKS5 back ends, staged speed test that shows which step failed.
- **Optional DNS proxy**, **UDP forwarding**, tray mode, silent autostart, light and dark themes.

## Quick start

Requires Windows 10 2004+ / 11 (x64), administrator rights and the WebView2 Runtime.

1. Download the zip from [Releases](https://github.com/906222304/proxyclaw/releases) and extract it fully (for autostart, put it in `C:\Program Files\ProxyClaw`).
2. Run `proxyclaw.exe` and accept the UAC prompt.
3. On the Proxies page point the `default` group at your SOCKS5 (e.g. `127.0.0.1:7890`), then add a rule on the Rules page and switch it on.

Config lives in `proxyclaw.json` next to the exe, logs in `proxyclaw.log`. Only IPv4 is proxied; IPv6 from proxied processes is blocked by default so apps fall back to IPv4 through the proxy (Settings → Network → IPv6 can switch it to direct). See [TROUBLESHOOTING](docs/TROUBLESHOOTING.en.md).

## Build

Requires Visual Studio 2026 / 2022, CMake 3.20+, Python 3.12+, Node.js 22.

```powershell
python scripts/prepare_release_deps.py
cmake --preset windows-vs2026
cd frontend; npm ci; npm run build; cd ..
cmake --build --preset windows-vs2026
ctest --preset windows-vs2026
```

`python scripts/verify.py` runs every test in one go. Architecture: [ARCHITECTURE](docs/ARCHITECTURE.md).

## Credits

Based on [Clew v0.10.0](https://github.com/ymonster/clew-proxy/tree/v0.10.0) by [@ymonster](https://github.com/ymonster); forwarding relies on [WinDivert](https://github.com/basil00/Divert). Other dependencies: [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES.md).

## License

[MIT](LICENSE). WinDivert is LGPL v3, see `WinDivert-2.2.2-A/LICENSE`.
