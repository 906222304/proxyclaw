# ProxyClaw 路线图

> **English summary.** v0.14–v0.18 are complete (**v0.18.0**, 2026-11-26): explainable per-connection decisions, split CI with `/W4` & ESLint, `(pid, psn)` rule matching, child-process-tree exceptions, engine status view with versioned config import/export, editable app presets with Store package identity matching, IPv6 TCP/UDP proxy, driverless Hook mode with TCP/UDP proxy, 64/32-bit (WOW64) injection (`proxyclaw_hook64.dll` + `proxyclaw_hook32.dll`), skip/failure observability, SOCKS5 username/password authentication (RFC 1929), performance baseline & comparison tooling (`stress_backend.py` + `compare_stress.py`), explicit resource caps across TCP/UDP/IPv6/Hook/DNS (`/api/stats.limits`), a shared `(pid, psn)` process info cache with live PSN verification, and one-click sanitized diagnostic ZIP export (`GET /api/diagnostics/export`). Conditional `RecvEx`/`SendEx` batching was evaluated against the Windows CI baseline (~120 µs kernel-to-recv overhead, zero pool exhaustion) and intentionally skipped. Remaining low-priority maintenance: vcpkg manifest, `pyproject.toml` for Python test scripts, and out-of-tree generated `version.ts`. Not planned: installer or Windows Service split (stay portable zip), custom WFP driver (Draft PR #15 closed; WinDivert default + Hook driverless is the two-track model), default DLL injection, full TUN backend, built-in multi-protocol nodes, HTTP upstream (rejected with 400), hot-switching interception mode without restart, and a dedicated self-hosted nightly soak runner.

当前版本 **v0.18.0**（2026-11-26），v0.14–v0.18 路线图已全部完成（v0.18 补齐性能基准与前后对比工具、全链路显式资源上限与溢出计数、共享 `(pid, psn)` 进程信息缓存以及一键脱敏诊断包导出；`RecvEx`/`SendEx` 批处理经 Windows 实测基线确认内核到收包耗时仅 ~120 µs、瓶颈不在 WinDivert 工作线程，按计划跳过）。本文只列尚未完成的工作；已完成项见 [CHANGELOG](../CHANGELOG.md)。

**原则**：先有唯一的事实来源（CONNECT 时记录的决定），界面、统计和 IPv6 标注都从它读取；性能改动必须先有能测出判定延迟与漏代理的基准；保持绿色便携包形态，把精力集中在核心代理能力。

## 下一阶段规划

v0.18 收口后，先通过真机日常使用与一键诊断包收集真实场景反馈，再决定下一里程碑重点。

## 低优先级工程维护

穿插推进，不单独占里程碑：

- 依赖单一来源：C++ 第三方库迁移到 vcpkg manifest（WinDivert / WebView2 / Detours 仍由脚本拉取并校验 SHA256）。
- Python 测试脚本统一 `pyproject.toml` 管理。
- 版本文件（`frontend/src/version.ts` 等）不再在 CMake 配置阶段写入源码树。

## 暂不计划

以下方向经确认暂不立项，避免分散维护精力：

- **安装包与服务化拆分**：保持绿色便携压缩包形态，不做 Program Files 安装包，也不拆分为「普通权限 UI + Windows 后台服务」。
- **自研 WFP 驱动**：需要微软签名与 EV 证书；已采用「WinDivert（默认）+ v0.17 Hook 模式（官方无驱动替代）」双路线，设计草案 PR #15 已关闭。
- **WinDivert `RecvEx` / `SendEx` 批处理**：v0.18 实测基线表明内核到 `WinDivertRecv` 开销仅 ~120 µs（占比 <2%），无缓冲池耗尽，当前无需引入批处理复杂度。
- **其他非核心能力**：默认 DLL 注入、完整 TUN 后端、内置多协议代理节点、HTTP 代理上游（继续在保存时返回 400 拒绝）、运行时免重启热切换拦截模式、自托管 runner 夜间浸泡测试。自动切换上游只影响新连接，已建立的 TLS / SSE / WebSocket 不能透明迁移。
