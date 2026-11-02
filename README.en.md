<div align="center">

<img src="assets/proxyclaw.png" width="128" alt="ProxyClaw icon" />

# ProxyClaw

**Windows process-level proxy and traffic routing**

Send only the apps you choose (and their whole child-process tree) through a SOCKS5 proxy. Everything else stays direct, no global TUN required.

[![Release](https://img.shields.io/github/v/release/906222304/proxyclaw?style=flat-square&logo=github)](https://github.com/906222304/proxyclaw/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/906222304/proxyclaw/total?style=flat-square&logo=windows)](https://github.com/906222304/proxyclaw/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/906222304/proxyclaw/release.yml?branch=main&style=flat-square&label=build)](https://github.com/906222304/proxyclaw/actions/workflows/release.yml)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6?style=flat-square&logo=windows)](#requirements)
[![License](https://img.shields.io/github/license/906222304/proxyclaw?style=flat-square)](LICENSE)
[![Stars](https://img.shields.io/github/stars/906222304/proxyclaw?style=flat-square&logo=github)](https://github.com/906222304/proxyclaw/stargazers)

[简体中文](README.md) · **English**

[Download](https://github.com/906222304/proxyclaw/releases/latest) ·
[Quick start](#quick-start) ·
[Troubleshooting](docs/TROUBLESHOOTING.en.md) ·
[Architecture](docs/ARCHITECTURE.md) ·
[Release guide](docs/RELEASE.md)

<img src="docs/images/main_ui.png" alt="ProxyClaw main UI" width="90%" />

</div>

---

## Table of contents

- [Why ProxyClaw](#why-proxyclaw)
- [Features](#features)
- [Is this tool for me](#is-this-tool-for-me)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Technical choices](#technical-choices)
- [Building from source](#building-from-source)
- [Testing](#testing)
- [Contributing](#contributing)
- [Contributors](#contributors)
- [Acknowledgements](#acknowledgements)
- [License](#license)

## Why ProxyClaw

Long ago, while using Antigravity, I hit a wall: with a Clash backend, TUN mode off meant I couldn't even refresh the model list, and turning TUN on broke other apps. I didn't want to hijack all traffic just for one app, so I built a tool that lets specific processes use the proxy on their own. It has evolved into what it is today.

ProxyClaw is based on [Clew v0.10.0](https://github.com/ymonster/clew-proxy/tree/v0.10.0), keeping the original copyright and [MIT license](LICENSE). On top of it, this project adds:

- 🇨🇳 Full Simplified Chinese UI with Windows CJK font support
- 🪟 Keeps running in the tray after the window is closed, by default
- 🛡️ Safer DNS lifecycle handling (system DNS is restored even after a crash)
- 🔁 TCP fallback when a DNS query over UDP times out or is truncated
- 🖥️ PerMonitorV2 HiDPI support and a built-in log viewer

## Features

| | Feature | Details |
| --- | --- | --- |
| 🌳 | **Process-tree proxying** | Once a rule matches, every child process, including ones spawned later, is proxied too. No more digging through Chromium / Electron children to find the one that does the networking. |
| 🔎 | **Command-line matching** | When one `python.exe` runs several scripts, proxy only the one running `crawler.py`. |
| 🔀 | **Multiple SOCKS5 backends** | Several proxy groups, with different rules routed to different groups and built-in latency tests. |
| 📡 | **TCP + UDP** | UDP via per-app-port SOCKS5 UDP ASSOCIATE ([RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html)). |
| 🧭 | **Built-in DNS forwarder** | System DNS points at the built-in forwarder and queries go upstream through SOCKS5, with TCP fallback; restored on exit or after a force-kill. |
| ⚡ | **Snappy UI** | State pushes use WebView2 in-process IPC and DELETE requests hit cpp-httplib's fast path, so hack / unhack no longer stalls. |
| 🚀 | **Silent autostart** | Launches elevated through Task Scheduler at logon with no UAC prompt, optionally straight to the tray. |
| 📜 | **Log viewer** | Search, filter warnings / errors, copy, and reveal the log file from inside the app. |

<details>
<summary><b>Command-line matching example: fixing ccusage pricing fetches</b></summary>

[ccusage](https://github.com/ryoppippi/ccusage) fails with `Failed to fetch model pricing from LiteLLM` when it can't reach LiteLLM. On Node 24+ you can set `NODE_USE_ENV_PROXY=1`; or add this rule on ProxyClaw's Rules page:

| Field | Value |
| --- | --- |
| Name | `ccusage` |
| Process name | `node.exe` |
| Cmdline pattern | `ccusage` |

</details>

<details>
<summary><b>How the UI stalls were fixed</b></summary>

In v0.8.1 and earlier, hack / unhack could occasionally stall for seconds. Two unrelated root causes were fixed separately:

- **State push moved to WebView2 in-process IPC**: the old HTTP/SSE stream permanently held one of the browser's six HTTP/1.1 connections per host, and decoding the chunked stream ran on the V8 main thread. `PostWebMessageAsJson` takes both costs away.
- **DELETE requests send an explicit `body: ''`**: cpp-httplib treats every DELETE as possibly having a body and, without `Content-Length`, waits the full 5 s `read_timeout`. An empty body makes the browser send `Content-Length: 0`, putting cpp-httplib on its fast path.

</details>

## Is this tool for me

**✅ Good fit**

- You want a specific app to use a proxy, but it does more than HTTP (arbitrary TCP / UDP), and you don't know or care which child process does the networking.
- You already run a proxy client such as Clash and want only a few apps to go through it, without global TUN.
- You care about MIT licensing, e.g. integrating into internal tooling or a commercial product without AGPL obligations.

**❌ Not a fit**

- You need macOS / Linux → try [ProxyBridge](https://github.com/InterceptSuite/ProxyBridge)
- You prefer an NDIS driver approach or a Windows service deployment → try [ProxiFyre](https://github.com/wiresock/proxifyre)
- You need a full proxy core with subscriptions, protocols and node selection → try [sing-box](https://sing-box.sagernet.org/) / [mihomo](https://wiki.metacubex.one/); ProxyClaw can sit in front of them

See the [related projects review](docs/RELATED_PROJECTS_REVIEW.md) (Chinese) for a deeper comparison.

## Quick start

### Requirements

- Windows 10 version 2004 or newer / Windows 11 (x64)
- Administrator privileges (required by the WinDivert driver and system DNS configuration)
- WebView2 Runtime (bundled with Windows 11; download from [Microsoft](https://developer.microsoft.com/microsoft-edge/webview2/) on Windows 10)
- Release packages statically link the MSVC runtime; your own builds with default settings may need the [VC++ Redistributable](https://aka.ms/vs/17/release/vc_redist.x64.exe)

### Three steps

1. Download `proxyclaw-vX.Y.Z-windows-x64.zip` (with its `.sha256` checksum) from [Releases](https://github.com/906222304/proxyclaw/releases/latest) and **extract the whole archive**.
2. Double-click `proxyclaw.exe` and accept the UAC prompt.
3. On the Proxies tab, point the `default` group at your SOCKS5 (e.g. Clash at `127.0.0.1:7890`), then add a rule on the Rules tab and switch it on.

> [!TIP]
> On first launch, a sibling legacy `clew.json` is imported into `proxyclaw.json` without modifying the original. An existing new config takes precedence, and explicitly named custom configs are not imported. Logs go to `proxyclaw.log`.

## Usage

### 1. Configure a proxy backend

Proxies tab:

- A `default` group already exists; change its host / port to point at your SOCKS5.
- The refresh icon runs a latency test.

<img src="docs/images/proxy_group.png" alt="Proxy group" width="80%" />

### 2. Add an auto rule

Rules tab → `Add Rule`. **New rules default to OFF; flip the toggle to activate.**

| Field | Meaning |
| --- | --- |
| Name | Rule name |
| Process name | Glob wildcards such as `curl*` or `python.exe`, or pick a specific exe path |
| Cmdline pattern | Command-line keywords, space-separated, case-insensitive, order-independent |
| Hack tree | Child processes are proxied too |
| Protocol | TCP / UDP / Both |
| Proxy group | Which proxy group to route through |

<img src="docs/images/rules.png" alt="Rules" width="80%" />

### 3. Process tree and network activity

- **Process tree**: hover a process to reveal a lightning icon; click it to proxy that PID and any future children. Handy for ad-hoc debugging. A manual hack always proxies both TCP and UDP; use an auto rule's Protocol field for one or the other.

  <img src="docs/images/process_hover.png" alt="Process tree hover" width="60%" />

- **All Processes**: click `All Processes` (or deselect every process) to see live network activity across the system.
- **Process header**: once a process is selected, a detail bar appears:
  - the explorer icon left of the name reveals the executable's folder;
  - hovering the path shows two copy buttons: working directory on the left, full command line including the image path (`all`) on the right;
  - the `+` icon creates a new rule using this process as a template.

  <img src="docs/images/network_process_hover_to_copy.png" alt="Network activity process header" width="80%" />

### 4. DNS proxy (off by default)

Some apps (Spotify, certain geo-sensitive services) are picky about DNS. With Settings → DNS Proxy on:

- System DNS is set to `127.0.0.2` (the built-in forwarder), and queries go upstream through SOCKS5 (default `8.8.8.8`).
- SOCKS5 UDP is tried first. If a query gets no valid reply within 1.5 s, or the reply is truncated (TC), it is retried over TCP through the same proxy (3 s shared budget for the TCP stage, then `SERVFAIL`).
- Query IDs are remapped and restored on reply so identical IDs from different processes never cross; a valid late UDP reply also ends the retry, and each query is answered once.
- System DNS is restored on disable / exit; after a force-kill, the next launch detects the leftover state and restores it.

TCP framing and SOCKS5 reply parsing follow [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html) and [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html). The local listener is UDP only; replies respect the client's EDNS UDP size and are truncated with TC when larger.

### 5. Background mode and tray

- New configs keep ProxyClaw running after the main window closes. Click the tray icon to reopen it; right-click → Exit ProxyClaw to quit.
- The toggle under Settings → General applies immediately. An existing config with `ui.close_to_tray: false` keeps that choice.
- If the tray is temporarily unavailable, the taskbar entry stays; after repeated tray registration failures, the window reappears so the app is never stranded in the background.

### 6. Autostart at logon (off by default)

ProxyClaw needs administrator rights, and the registry `Run` key would prompt UAC at every login. Instead it uses a Task Scheduler task with "Run with highest privileges":

- Settings → "Start ProxyClaw at logon" creates `ProxyClawAutoStart` (`schtasks /Create /SC ONLOGON /RL HIGHEST`).
- "Start minimized to tray" appends `--minimized`, so only the tray icon appears.
- Turning it off deletes the task (`schtasks /Delete /F`); manual removal in Task Scheduler is detected live.

> [!NOTE]
> The task stores the absolute path of `proxyclaw.exe`. If you move the executable, toggle the setting again.

### 7. Runtime logs

Settings → Runtime logs → View logs lets you search recent records, filter warnings / errors, copy the displayed text, or reveal the log file. Auto-refresh runs only while the viewer is open and the app is visible. Snapshots hold at most the latest 1,000 lines or 256 KiB; the full log stays beside the executable.

Having trouble? Start with the [troubleshooting guide](docs/TROUBLESHOOTING.en.md).

## Technical choices

### Third-party libraries

| Layer | Dependency | Purpose |
| --- | --- | --- |
| Backend | [WinDivert](https://github.com/basil00/Divert) | WFP-based user-mode packet capture / forwarding, dynamically linked and shipped with releases (LGPL v3) |
| Backend | [quill](https://github.com/odygrd/quill) | Async structured logging |
| Backend | [nlohmann/json](https://github.com/nlohmann/json) | JSON parsing and serialization |
| Backend | [cpp-httplib](https://github.com/yhirose/cpp-httplib) | Embedded HTTP server |
| Backend | [asio](https://think-async.com/Asio/) | Asynchronous I/O |
| Backend | [WebView2](https://developer.microsoft.com/microsoft-edge/webview2/) | Embedded Edge for the UI |
| Frontend | [Vue 3](https://vuejs.org/) + TypeScript + [Vite](https://vitejs.dev/) | App framework and build |
| Frontend | [reka-ui](https://reka-ui.com/) + [Tailwind CSS](https://tailwindcss.com/) | Components (shadcn-vue style) and styling |
| Frontend | [AG Grid Community](https://www.ag-grid.com/) | Network activity table |
| Frontend | [Monaco Editor](https://microsoft.github.io/monaco-editor/) | JSON editor in Settings (lazy-loaded) |
| Frontend | [Lucide](https://lucide.dev/) | Icons |

Full license information: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

<details>
<summary><b>Why WinDivert</b></summary>

- Mature WFP callout driver with solid Windows 10/11 support.
- LGPL v3 permits dynamic linking of the `.dll`, so the main project stays MIT.
- Free: the WinDivert author already paid for kernel-driver signing, so the released `.sys` is signed.

</details>

<details>
<summary><b>Why not DLL injection (for now)</b></summary>

1. Hooking `GetAddrInfoW` worked, but many modern processes ship their own async DNS resolvers, so `getaddrinfo` / `GetAddrInfoW` / `connect` / `WSAConnect` / `ConnectEx` and friends would all need hooking.
2. `PsSetCreateProcessNotifyRoutineEx` would give more accurate process creation / exit events and cleaner interception.
3. In the real world that also means dealing with AV / EDR and SignPath-style signing, which takes a long time and may cost money.
4. Conclusion: WinDivert is enough for now. With real demand, DLL injection can be explored on a branch.

</details>

<details>
<summary><b>Why not a self-built WFP kernel driver</b></summary>

It's technically cleaner (`FWPM_LAYER_ALE_CONNECT_REDIRECT_V4` rewrites the socket destination with zero packet manipulation), but Windows 10+ requires Microsoft-signed kernel drivers via Partner Center, which needs an EV code-signing certificate (~300–600 USD / year) and attestation. SignPath-style OSS signing only covers user-mode Authenticode. Not worth it for a personal open-source project right now.

</details>

<details>
<summary><b>Process-tree update strategy (<code>PROXYCLAW_PROJECTION_COALESCE</code>)</b></summary>

By default every ETW process event triggers an immediate refresh and push, with no coalescing timer. Even with 1000+ live processes the strand stays under 1% utilisation. Only sudden bursts of +1000 ETW events can briefly saturate it, and common flows like inspecting one process stay snappy. For extreme workloads, `cmake -DPROXYCLAW_PROJECTION_COALESCE=ON` enables a 100 ms coalescing window (trade-off: tree updates lag up to 100 ms).

</details>

## Building from source

### Toolchain

- Visual Studio 2022 or 2026 (C++23)
- CMake 3.20+, vcpkg
- Node.js 20+
- WebView2 SDK

### Steps

```bash
# Configure
cmake --preset windows-vcpkg

# Backend (~30 translation units; CMakeLists enables /MP for parallel builds)
cmake --build build --config Release

# Frontend
cd frontend
npm install
npm run build
cd ..

# Run
./build/Release/proxyclaw.exe
```

To reuse CI's pinned dependencies and build a package identical to a release, see the [build and release guide](docs/RELEASE.md). Pushing a `v*` tag builds the full Windows x64 package and publishes a Release; `main` and PR builds upload artifacts only.

<details>
<summary><b>clangd / LSP setup (optional)</b></summary>

The repo ships a `.clangd` file and a `windows-vcpkg-clangd` preset. You don't need them to build and run a release.

CMake's Visual Studio generator doesn't emit `compile_commands.json`, so clangd can't find the vcpkg / WebView2 / asio headers. To enable clangd navigation and completion (requires Ninja on PATH):

```bash
cmake --preset windows-vcpkg-clangd
```

This writes `compile_commands.json` into `build-clangd/` (gitignored). Re-run after changing `vcpkg.json`, adding source files, or adding include directories.

</details>

## Testing

None of these regression tests start the proxy or change system DNS. Background: [optimization review](docs/OPTIMIZATION_REVIEW.md) (Chinese).

<details>
<summary><b>UI loading and background refresh</b></summary>

The advanced JSON editor loads on demand; periodic refresh waits for the previous request and cancels stale ones when hidden or switching processes; the process tree resyncs when the window is restored.

```powershell
node --test tests/async_poller_test.mjs
python tests/run_projection_tests.py --cxx path/to/zig.exe --asio-include path/to/asio/include
```

</details>

<details>
<summary><b>HiDPI windows</b></summary>

The window uses PerMonitorV2 DPI awareness, and WebView2 follows monitor and text scaling. Process icons are cached as 64×64 PNGs. The test creates short-lived hidden windows to check the DPI manifest, work area, minimum size, 100/125/150/200% scale events and icon loading (scale events are simulated; real multi-monitor drags still need a manual check).

```powershell
python tests/run_window_dpi_tests.py --cxx path/to/zig.exe
```

</details>

<details>
<summary><b>Unicode paths, background defaults and legacy config import</b></summary>

Touches only test files under `build`. File pickers and Explorer calls are stubbed, so no real windows open.

```powershell
python tests/run_ui_config_tests.py --cxx cl --json-include C:/vcpkg/installed/x64-windows/include
# Zig (point at the directory containing nlohmann/json.hpp)
python tests/run_ui_config_tests.py --cxx path/to/zig.exe --json-include build/test-deps

# Build tests/test_ui_config_and_paths.cpp on its own
zig c++ -std=c++23 -Isrc -Ibuild/test-deps tests/test_ui_config_and_paths.cpp src/common/api_exception.cpp -lshell32 -lws2_32 -o build/test_ui_config_and_paths.exe
./build/test_ui_config_and_paths.exe
```

</details>

<details>
<summary><b>DNS lifecycle and packet parsing</b></summary>

Compiles the DNS manager directly with stubbed network and Windows APIs to simulate start, restart, backup and restore failures, and checks DNS packets, compression pointers and EDNS size parsing. No admin rights, WinDivert driver or vcpkg needed.

```powershell
python tests/run_dns_tests.py --cxx cl          # VS developer prompt
python tests/run_dns_tests.py --cxx clang++
python tests/run_dns_tests.py --cxx path/to/zig.exe
```

</details>

<details>
<summary><b>DNS over a real network</b></summary>

Compiles the production DNS forwarder and SOCKS5 UDP session against a local mock proxy to verify UDP timeouts, fragmented TCP reads, every SOCKS5 reply type, failures and timeouts, concurrent ID collisions, late replies and shutdown cleanup. Loopback only.

```powershell
python tests/run_dns_network_tests.py --cxx cl --asio-include path/to/asio/include
python tests/run_dns_network_tests.py --cxx path/to/zig.exe --asio-include path/to/asio/include
```

</details>

## Contributing

Issues and PRs are welcome!

- Before filing an issue, check the [troubleshooting guide](docs/TROUBLESHOOTING.en.md) and include the relevant part of `proxyclaw.log`.
- Project structure, architecture and API schema: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- Planned improvements: [related projects review](docs/RELATED_PROJECTS_REVIEW.md) (Chinese).

## Contributors

Thanks to everyone who contributes code, docs and feedback to ProxyClaw!

<a href="https://github.com/906222304/proxyclaw/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=906222304/proxyclaw" alt="Contributors" />
</a>

## Acknowledgements

- [Clew](https://github.com/ymonster/clew-proxy) by [@ymonster](https://github.com/ymonster): ProxyClaw's direct upstream and the source of its process-tree proxying, SYN parking and other core features.
- [WinDivert](https://github.com/basil00/Divert): makes user-mode, per-process forwarding possible.
- Every open-source project listed under [Technical choices](#technical-choices).

## Star History

<a href="https://star-history.com/#906222304/proxyclaw&Date">
  <img src="https://api.star-history.com/svg?repos=906222304/proxyclaw&type=Date" alt="Star History Chart" width="600" />
</a>

## License

- ProxyClaw: [MIT](LICENSE)
- Dynamically linked [WinDivert](https://github.com/basil00/Divert): LGPL v3 (original license kept at `WinDivert-2.2.2-A/LICENSE`)
- Other third-party licenses: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
