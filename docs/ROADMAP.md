# ProxyClaw 路线图

> **English summary.** v0.14 makes capability boundaries visible and decisions explainable: IPv6 traffic labelled as not taken over, DNS TCP-only mode with asynchronous enable, per-connection rule-hit explanation, a capped icon cache, and every unit test in CTest. v0.15 widens coverage: end-to-end IPv6 proxying (TCP + UDP), editable app presets, child-process-tree exceptions, and an engine status view with config import / export. Later: a performance baseline first (the stress harness exists and CI publishes a smoke baseline), then WinDivert RecvEx/SendEx batching, resource limits, long-session soak tests and a service mode. Not planned: a custom WFP driver, DLL injection by default, a TUN back end, built-in proxy protocols.

当前版本 v0.13.0（2026-11-07）。本文替代此前的各份调研 / 复核文档，只列尚未完成的工作；已完成的见 [CHANGELOG](../CHANGELOG.md)。

## v0.14：能力边界清楚，决定可解释

**目标**：用户不用读日志就能知道某条连接为什么走代理或直连，以及哪些流量 ProxyClaw 目前不接管。

| 项目 | 内容 |
| --- | --- |
| IPv6 状态呈现 | 网络层目前只处理 IPv4 包，IPv6 一律放行直连。在网络活动与规则页明确标出“IPv6 未接管”，避免用户以为已代理。 |
| DNS 仅 TCP 模式 | 启动不再强制 UDP ASSOCIATE 成功：探测上游 TCP 可用后允许以 TCP-only 方式启用（运行时已有 TCP 回退）；保留系统 DNS 备份与恢复。 |
| DNS 异步启用 | 启用 DNS 的接口立即返回“启动中”，界面显示进度与失败原因，不再同步等待最长 10 秒。 |
| 规则命中解释 | 每条连接记录实际动作、命中的规则（或手动 hack）、代理组、判定步骤与配置版本；界面展示“为什么”，并提示多条规则冲突。改规则后旧连接仍显示原决定。 |
| 图标缓存上限 | 按完整路径为键（避免同名不同路径复用错误图标）；失败查找带重试期限，不再每次重新枚举进程；缓存设容量上限。 |
| 测试归位 | `test_components.cpp`、`test_window_dpi.cpp`、`test_icon_resolution.cpp` 注册进 CTest，删除 Zig 专用的 `run_window_dpi_tests.py`。 |

**验收**

- 发出 IPv6 连接的进程在界面上显示为“IPv6 未接管 / 直连”，e2e 覆盖。
- 仅支持 TCP 的 SOCKS5 上游可以启用 DNS 代理；启用、关闭、强杀后重启均能恢复系统 DNS（loopback harness 用例）。
- 启用 DNS 的 API 在 200 ms 内返回，状态随后经推送更新。
- 任意一条连接都能在界面看到命中规则与原因；规则冲突有提示。
- 图标缓存在 1 万个不同路径下内存有上界；同名不同路径的程序图标正确。
- CTest 覆盖全部 C++ 单元测试，CI 绿。

## v0.15：覆盖更多真实场景

**目标**：双栈网络、常见应用和复杂进程树开箱即用，少写规则。

| 项目 | 内容 |
| --- | --- |
| IPv6 端到端代理（TCP + UDP） | 统一地址类型、tracker / socket 键、规则与 CIDR 匹配、IPv6 报文重写与校验和、SOCKS5 CONNECT / UDP 帧中的 IPv6 地址、接口与作用域、活动列表。 |
| 应用预设 | 基于现有规则系统的可编辑预设（常见 AI 客户端、IDE、浏览器等），支持路径 / Store 包身份匹配；可从网络活动一键生成规则。 |
| 子进程树例外 | 为进程树规则配置子树直连例外（如 Electron 根进程下的 ssh / scp、局域网服务、代理客户端自身）；不默认放行所有 SSH，也不因同名 node / python 就代理全部实例。 |
| 引擎状态与配置迁移 | 界面显示引擎运行、WinDivert 驱动加载失败、DNS 恢复等状态；配置导入 / 导出，沿用带版本号的配置迁移。 |

**验收**

- 双栈环境下 IPv6 TCP 与 UDP 经 SOCKS5 出口，出口地址与 IPv4 一致（e2e 用回环 IPv6 代理验证）；IPv6 规则排除网段生效。
- 选择预设后无需手写规则即可代理对应应用；Store 应用升级后路径变化仍能命中。
- 设置例外后，例外子树的连接直连，其余子进程仍走代理（e2e）。
- 驱动加载失败时界面给出明确提示；导出的配置在新目录导入后行为一致。

## 之后：先有基准，再谈性能与部署

**目标**：用数据证明性能改动的收益，并让长期运行更稳。

| 项目 | 内容 |
| --- | --- |
| 性能基准 | 记录空闲、单独 TCP / UDP、健康 / 故障上游、窗口显示 / 隐藏、进程风暴、大流量下的 CPU、RSS、句柄、p95 / p99 延迟与丢包，重点测“非目标应用”经过用户态的成本。压测工具已在仓库中（`tests/stress_backend.py` + `tests/stress_etw.py`），CI 每次以 `--ci` 跑有界冒烟并上传 `stress-summary`（请求数、错误、p50/p95/p99、proxyclaw 内存与句柄）作为粗略基线；还缺固定硬件上的完整场景与前后对比。 |
| RecvEx / SendEx 批处理 | NETWORK 层仍逐包 `WinDivertRecv/Send`，按基准评估批量收发；必须保护 SYN parking、重传、校验和、关闭顺序和缓冲区生命周期。 |
| 资源上限 | 活动 / 待建会话、重试、队列等设容量上限与溢出计数；IO 线程数按测量决定。 |
| 进程信息缓存 | 减少重复解析进程信息，保留 PSN 身份校验，不为命中缓存跳过 PID 重用与退出清理。 |
| 长时间稳定性 | 数小时真实会话（长连接 / SSE / WebSocket）浸泡测试，并持续观察本机回环相关蓝屏是否复现。 |
| 服务化 | 普通权限 UI + 提权后端服务、带 ACL 的命名管道 IPC；作为独立工作包，不与转发修复混在一起。 |
| 工程整理 | 依赖单一来源（vcpkg manifest，WinDivert / WebView2 仍脚本拉取）；Python 测试脚本统一 `pyproject` 管理。 |

**验收**

- 有可重复执行的基准脚本与基线数据；每项性能改动附前后对比，且不引入首包泄漏。
- 资源在压力下有上界，超限有计数与日志。
- 服务模式下 UI 无需管理员权限，其他本机用户无法调用管理接口。

## 暂不计划

自研 WFP 驱动（需微软签名与 EV 证书）、默认 DLL 注入、完整 TUN 后端、内置多种节点协议。自动切换上游只影响新连接，已建立的 TLS / SSE / WebSocket 不能透明迁移。只有现有路径确实无法解决问题时才重新立项。
