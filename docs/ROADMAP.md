# ProxyClaw 路线图

> **English summary.** v0.14 and v0.15 shipped in **v0.16.0** (2026-11-25): explainable per-connection decisions, split CI with `/W4` & ESLint, `(pid, psn)` rule matching, child-process-tree exceptions, engine status view with versioned config import/export, editable app presets with Store package identity matching, IPv6 TCP/UDP proxy, and optional Hook interception. **v0.17** matures the driverless Hook mode and upstream auth: Hook UDP proxy (SOCKS5 UDP ASSOCIATE), 32-bit (WOW64) injection (`proxyclaw_hook32.dll`), Hook skip/failure observability in the UI, and SOCKS5 username/password authentication (RFC 1929). **v0.18** focuses on measured performance, bounds, and diagnostics: a performance baseline (CONNECT-to-decision p99, missed proxies, RSS vs process count), resource caps with overflow counters, a PSN-verified process info cache, and one-click diagnostic bundle export for real-machine troubleshooting (RecvEx/SendEx batching only if the baseline proves NETWORK threads are the bottleneck). Low-priority maintenance: vcpkg manifest, `pyproject` for Python test scripts, and out-of-tree generated `version.ts`. Not planned: installer or Windows Service split (stay portable zip), custom WFP driver (Draft PR #15 closed; WinDivert default + Hook driverless is the two-track model), default DLL injection, full TUN backend, built-in multi-protocol nodes, HTTP upstream (rejected with 400), hot-switching interception mode without restart, and a dedicated self-hosted nightly soak runner.

当前版本 **v0.16.0**（2026-11-25），v0.14（第 1–9、11–12 项；第 10 项已放弃）与 v0.15（第 1–5 项：子进程树例外、引擎状态与配置导入/导出、可编辑应用预设与 Store 包身份匹配、`(pid, psn)` 规则匹配状态、IPv6 TCP/UDP 代理，以及可选 Hook 注入模式）已全部完成。本文只列尚未完成的工作；已完成项见 [CHANGELOG](../CHANGELOG.md)。

**原则**：先有唯一的事实来源（CONNECT 时记录的决定），界面、统计和 IPv6 标注都从它读取；性能改动必须先有能测出判定延迟与漏代理的基准；保持绿色便携包形态，把精力集中在核心代理能力。

## v0.17：补齐无驱动 Hook 模式与上游认证

**目标**：建立「WinDivert（默认）+ Hook（官方无驱动替代）」双路线，让因安全软件冲突改用 Hook 模式的用户也能覆盖常见 UDP 与 32 位应用、看得清跳过原因，并支持带账密认证的 SOCKS5 上游。

| # | 项目 | 内容 |
| --- | --- | --- |
| 1 | Hook 模式 UDP 代理 | 拦截 `sendto` / `WSASendTo` / `recvfrom` / `WSARecvFrom` 与已连接 UDP，复用现有 SOCKS5 UDP ASSOCIATE 通道，覆盖 HTTP/3（QUIC）、语音通话与自定义 UDP 工具。 |
| 2 | 32 位（WOW64）进程注入 | 新增 `proxyclaw_hook32.dll` 的 x86 构建与便携包打包，双架构注入器按目标进程位数自动注入 64/32 位 DLL，不再跳过 32 位桌面应用与旧组件。 |
| 3 | Hook 注入与跳过可观测性 | 在进程树与网络活动（及决定原因）中明确标注未能注入的具体原因（AppContainer / 沙盒、仅允许微软签名模块、注入失败等），替代静默直连，便于排障。 |
| 4 | SOCKS5 用户名 / 密码认证 | 实现 RFC 1929（方法 `0x02`），代理组支持可选用户名与密码，覆盖 TCP 中继、UDP 关联、连通性测速与 DNS 转发；凭据不写入运行日志。 |

**验收**

- Hook 模式下 64 位与 32 位进程的 TCP 及 UDP 流量（回环 SOCKS5 UDP e2e）均能按规则走代理，子进程例外与网段过滤行为与 WinDivert 一致。
- 不可注入的受保护/沙盒进程在界面有明确的跳过原因标注。
- 配置用户名/密码的 SOCKS5 代理组可正常通过回环认证代理完成 TCP/UDP 转发与测速，且日志不出现明文密码。

## v0.18：性能基准、资源上限与真机诊断

**目标**：用数据证明性能改动的收益，用容量上限保护极端并发下的内存与端口安全，并通过一键诊断导出配合真机日常长运行排查问题。顺序：基准 → 资源上限 → 进程信息缓存 → 诊断导出（批处理仅视基准而定）。

| # | 项目 | 内容 |
| --- | --- | --- |
| 1 | 性能基准 | 在现有压测工具（`tests/stress_backend.py` + `tests/stress_etw.py`，CI 以 `--ci` 跑有界冒烟并上传 `stress-summary`）基础上，补充判定延迟（CONNECT → 发布的 p99）、漏代理计数（`late_rejected_proxied`、看门狗放行）以及 RSS 随进程数的变化，支持改动前后对比。 |
| 2 | 资源上限 | 活动 / 待建会话、重试、队列、UDP 端口等设明确容量上限与溢出计数，防止异常并发撑爆内存或耗尽端口；IO 线程数按基准实测决定。 |
| 3 | 进程信息缓存 | 减少重复查询进程路径、命令行与 Store 包身份，保留 `(pid, psn)` 校验与退出清理，不为命中缓存跳过 PID 复用防护。 |
| 4 | 诊断包一键导出 | 在「设置 → 诊断」提供一键导出诊断快照（运行日志 + `/api/stats` 引擎统计 + 脱敏配置），配合真机日常使用排查长运行异常（不建自托管 runner 跑夜间浸泡测试）。 |
| 5 | RecvEx / SendEx 批处理（视基准而定） | 仅当基准证明 NETWORK 工作线程确实是瓶颈时才立项（现有逐包循环无分配，strand 更可能是瓶颈）；必须保护 SYN parking、重传、校验和、关闭顺序与缓冲区生命周期。 |

**验收**

- 有可重复执行的基准脚本与基线数据；每项性能改动附前后对比，且不引入首包泄漏。
- 压力下会话 / 队列 / 端口资源有明确上界，超限时有计数与日志可查。
- 一键导出的诊断包包含完整日志与引擎统计，且自动剔除代理密码等敏感字段。

## 低优先级工程维护

穿插推进，不单独占里程碑：

- 依赖单一来源：C++ 第三方库迁移到 vcpkg manifest（WinDivert / WebView2 / Detours 仍由脚本拉取并校验 SHA256）。
- Python 测试脚本统一 `pyproject.toml` 管理。
- 版本文件（`frontend/src/version.ts` 等）不再在 CMake 配置阶段写入源码树。

## 暂不计划

以下方向经确认暂不立项，避免分散维护精力：

- **安装包与服务化拆分**：保持绿色便携压缩包形态，不做 Program Files 安装包，也不拆分为「普通权限 UI + Windows 后台服务」。
- **自研 WFP 驱动**：需要微软签名与 EV 证书；已采用「WinDivert（默认）+ v0.17 Hook 模式（官方无驱动替代）」双路线，设计草案 PR #15 已关闭。
- **其他非核心能力**：默认 DLL 注入、完整 TUN 后端、内置多协议代理节点、HTTP 代理上游（继续在保存时返回 400 拒绝）、运行时免重启热切换拦截模式、自托管 runner 夜间浸泡测试。自动切换上游只影响新连接，已建立的 TLS / SSE / WebSocket 不能透明迁移。
