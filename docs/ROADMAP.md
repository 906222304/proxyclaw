# ProxyClaw 路线图

> **English summary.** v0.14–v0.18 are complete (**v0.18.0**, 2026-11-26): explainable per-connection decisions, split CI with `/W4` & ESLint, `(pid, psn)` rule matching, child-process-tree exceptions, engine status view with versioned config import/export, editable app presets with Store package identity matching, IPv6 TCP/UDP proxy, driverless Hook mode with TCP/UDP proxy, 64/32-bit (WOW64) injection (`proxyclaw_hook64.dll` + `proxyclaw_hook32.dll`), skip/failure observability, SOCKS5 username/password authentication (RFC 1929), performance baseline & comparison tooling (`stress_backend.py` + `compare_stress.py`), explicit resource caps across TCP/UDP/IPv6/Hook/DNS (`/api/stats.limits`), a shared `(pid, psn)` process info cache with live PSN verification, and one-click sanitized diagnostic ZIP export (`GET /api/diagnostics/export`). **v0.19** delivers an adapter-free DNS architecture across both WinDivert and Hook modes — always-on per-process UDP/TCP:53 rewriting with a shared TTL-cached SOCKS5 resolver (UDP + TCP fallback), Hook-mode real-IP resolution (`getaddrinfo` / `GetAddrInfoW` / `GetAddrInfoExW`), and opt-in WinDivert transparent `Dnscache` interception (default off, built-in LAN + user `dns.bypass_suffixes` direct bypass, automatic proxy-down fail-open, replacing `SetInterfaceDnsSettings` adapter mutation while keeping legacy `dns_state.json` startup recovery) — alongside engineering debt & doc cleanup (out-of-tree `version.ts`, `pyproject.toml`, `vcpkg.json` manifest for header-only C++ deps, WebView2 screenshot CI flake stabilization, and `ARCHITECTURE.md` / `TROUBLESHOOTING.md` sync). Not planned: installer or Windows Service split (stay portable zip), custom WFP driver (Draft PR #15 closed; WinDivert default + Hook driverless is the two-track model), default DLL injection, Fake-IP (`198.18.0.0/15` + `ATYP=3`) synthetic pools (real-IP resolution chosen for app/UDP/CIDR compatibility), WinDivert `RecvEx`/`SendEx` batching (skipped after v0.18 baseline), full TUN backend, built-in multi-protocol nodes, HTTP upstream (rejected with 400), hot-switching interception mode without restart, and a dedicated self-hosted nightly soak runner.

当前版本 **v0.18.0**（2026-11-26），v0.14–v0.18 路线图已全部完成（v0.18 补齐性能基准与前后对比工具、全链路显式资源上限与溢出计数、共享 `(pid, psn)` 进程信息缓存以及一键脱敏诊断包导出；`RecvEx`/`SendEx` 批处理经 Windows 实测基线确认内核到收包耗时仅 ~120 µs、瓶颈不在 WinDivert 工作线程，按计划跳过）。本文只列尚未完成的工作；已完成项见 [CHANGELOG](../CHANGELOG.md)。

**原则**：先有唯一的事实来源（CONNECT 时记录的决定），界面、统计和 IPv6 标注都从它读取；性能改动必须先有能测出判定延迟与漏代理的基准；保持绿色便携包形态，把精力集中在核心代理能力；不修改 Windows 网卡 DNS，避免崩溃残留或代理断线拖垮整机网络。

## v0.19：不改网卡的新一代 DNS 体系与工程债收口

**目标**：在不修改 Windows 网卡 DNS 的前提下解决 WinDivert 与 Hook 双模式的 DNS 污染、内网/国内误走代理及代理断线全机断网问题，并一次性收口历史工程维护与文档债。顺序：`#1` 公共解析引擎与按进程 53 端口 → `#2` Hook 按进程真实 IP 解析 → `#3` WinDivert 免改网卡系统 DNS 防污染 → `#4` 工程维护 → `#5` CI 稳定性与文档同步。

| # | 项目 | 内容 |
| --- | --- | --- |
| 1 | 公共 DNS 解析引擎与按进程 53 端口重写 | 抽出带 TTL 缓存、SOCKS5 UDP + 自动 TCP 回落、内置内网后缀（单标签、`.local` / `.lan` / `.home.arpa` / `.internal` / `.localdomain` / `in-addr.arpa` / `ip6.arpa`）+ 用户自定义直连后缀（`dns.bypass_suffixes`）的公共 DNS 核心。**WinDivert 与 Hook 双模式始终生效**：对所有被代理进程（即使规则仅勾 `tcp`）在 `default_exclude_cidrs` 之前截获其直发的 UDP:53 / TCP:53（含路由器内网 DNS，排除回环），按该进程所属代理组转发至 `dns.upstream_host:53`；上游代理不可用时返回失败防泄漏（ProxyClaw 退出即恢复直连）；`ipv6.mode == "block"` 时对非直连后缀的被代理进程 `AAAA` 查询直接返回空应答以加速 IPv4 回落。 |
| 2 | Hook 模式按进程真实 IP 解析 | 在 `proxyclaw_hook64.dll` / `proxyclaw_hook32.dll` 拦截 `getaddrinfo` / `GetAddrInfoW` / `GetAddrInfoExW`，经命名管道由宿主通过该进程所属代理组查询真实 IP（复用 #1 的 TTL 缓存与直连后缀，不改系统网卡 DNS）；命中直连后缀走原系统解析，上游代理不可用时防泄漏返回失败，宿主离线或管道不可用时 fail-open 走原解析；补齐 `tests/e2e_hook_mode.py` 端到端验证。 |
| 3 | WinDivert 免改网卡系统 DNS 防污染与 UI / 诊断集成 | 用 WinDivert 网络层对 `svchost (Dnscache)` UDP:53 的透明拦截替代 `SetInterfaceDnsSettings` 改网卡转发器（开关**默认关闭**，开启即生效，完全不改网卡配置、强退零残留；启动保留对历史 `dns_state.json` 的一次性崩溃恢复清理，旧配置 `dns.mode = "forwarder"` 平滑迁移）。命中内置或自定义直连后缀直接放行本地原 DNS，其余走默认代理组；**上游代理不可达时自动无缝退回本地原 DNS**，绝不导致整机断网。前端「设置 → 网络 → DNS」新增自定义直连后缀编辑、运行/回落状态展示与 `/api/stats.dns` 计数（缓存命中 / 代理转发 / 直连放行 / 断线回落），同步纳入诊断包导出。 |
| 4 | 工程维护收尾 | 版本文件（`frontend/src/version.ts` 等）移出源码树改为构建目录生成；Python 测试与构建脚本统一 `pyproject.toml` 管理；C++ 第三方头库（`quill`、`nlohmann-json`、`cpp-httplib`、`asio`）迁移至 `vcpkg.json` manifest（WinDivert / WebView2 / Detours 仍由 `scripts/prepare_release_deps.py` 拉取并校验 SHA256）。 |
| 5 | CI 稳定性与文档同步 | 排查并修复 `tests/ui_webview2_screenshots.py` 偶发的 `process-count` / `#root` 超时抖动；同步更新 `docs/ARCHITECTURE.md` 与 `docs/TROUBLESHOOTING.md`（含英文版），补齐 v0.17–v0.19 架构与排障说明。 |

**验收**

- 全程不修改 Windows 网卡 DNS 设置；强杀 ProxyClaw 后系统网络零残留，历史升级残留的 `dns_state.json` 启动时仍自动恢复。
- WinDivert 与 Hook 模式下，自发 53 端口的被代理应用（含指向 `192.168.x.x:53` 路由器 DNS）默认按所属代理组防污染；Hook 模式下 `git` / `curl` / Python 等走系统解析的应用按进程返回真实 IP 且不打扰未代理进程。
- WinDivert 开启「系统 DNS 防污染」后，内网及自定义直连后缀走原本地 DNS，上游代理断开时整机自动回落本地 DNS 不断网；被代理进程自身 DNS 在代理断开时不向运营商泄漏查询域名。
- `frontend/` 本地校验不再依赖源码树内写入 `version.ts`，C++ 第三方头库与 Python 脚本依赖声明单一清晰，WebView2 截图测试稳定通过且架构/排障文档与代码一致。

## 暂不计划

以下方向经确认暂不立项，避免分散维护精力：

- **安装包与服务化拆分**：保持绿色便携压缩包形态，不做 Program Files 安装包，也不拆分为「普通权限 UI + Windows 后台服务」。
- **自研 WFP 驱动**：需要微软签名与 EV 证书；已采用「WinDivert（默认）+ v0.17 Hook 模式（官方无驱动替代）」双路线，设计草案 PR #15 已关闭。
- **Fake-IP（`198.18.0.0/15`）+ `ATYP=3` 虚拟地址池**：跨进程传递 IP、应用缓存、UDP/QUIC 及基于 IP/CIDR 的规则排除兼容坑较多；v0.19 采用真实 IP 代理查询 + TTL 缓存路线，优先稳定与一致性。
- **WinDivert `RecvEx` / `SendEx` 批处理**：v0.18 实测基线表明内核到 `WinDivertRecv` 开销仅 ~120 µs（占比 <2%），无缓冲池耗尽，当前无需引入批处理复杂度。
- **其他非核心能力**：默认 DLL 注入、完整 TUN 后端、内置多协议代理节点、HTTP 代理上游（继续在保存时返回 400 拒绝）、运行时免重启热切换拦截模式、自托管 runner 夜间浸泡测试。自动切换上游只影响新连接，已建立的 TLS / SSE / WebSocket 不能透明迁移。
