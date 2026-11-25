# ProxyClaw 路线图

> **English summary.** v0.14 makes every decision explainable from one source of truth: CTest coverage, per-connection decision records captured at CONNECT time, connection JSON built off the strand (activity poll merged in), a hit-rule column with reasons and conflict hints, blocking IPv6 for proxied processes so they fall back to IPv4, DNS TCP-only startup and asynchronous enable, an icon cache keyed by full path with backoff and a cap, `psn` in the pushed process tree, a split CI with `/W4` and ESLint, and a docs sweep (process-tree keyboard / ARIA was dropped). v0.15: an engine state view with config import / export, editable presets; child-process-tree exceptions, rule match state keyed by `(pid, psn)`, end-to-end IPv6 TCP/UDP, and optional hook interception are already shipped. Later: a performance baseline first (decision latency, missed proxies, RSS vs process count), then resource caps, RecvEx/SendEx batching only if the baseline shows a need, a process info cache, nightly soak tests, service mode (with a Program Files installer and WebView2 profile protection as an interim step) and build tidy-up. Not planned: a custom WFP driver, DLL injection by default, a TUN back end, built-in proxy protocols; the `http` upstream type is dropped and SOCKS5 username / password stays unsupported (rejected with 400) until implemented.

当前版本 v0.15.2（2026-11-24），新增可选的 Hook 注入拦截方式（无驱动，仅 TCP）；v0.14 计划已全部完成（第 1–9、11–12 项；第 10 项进程树键盘与 ARIA 已放弃并关闭 PR #14），并已完成 v0.15 第 1 项（子进程树例外）、第 4 项（规则匹配状态按 `(pid, psn)` 键控）与第 5 项（IPv6 TCP / UDP 代理 `ipv6.mode = proxy`，支持 IPv6 规则网段与出口不通时回落 IPv4）。本文只列尚未完成的工作；已完成的见 [CHANGELOG](../CHANGELOG.md)。

**原则**：先有唯一的事实来源（CONNECT 时记录的决定），界面、统计和 IPv6 标注都从它读取；性能改动必须先有能测出策略延迟与漏代理的基准。

## v0.15：覆盖更多真实场景

**目标**：双栈网络、常见应用和复杂进程树开箱即用，少写规则。按下表顺序推进。

| # | 项目 | 内容 |
| --- | --- | --- |
| 2 | 引擎状态与配置导入 / 导出 | 界面显示引擎运行、WinDivert 驱动加载失败、DNS 恢复等状态及决定记录计数；配置导入经 `config_store`，沿用带版本号的配置迁移。 |
| 3 | 可编辑应用预设 | 基于现有规则系统的预设（常见 AI 客户端、IDE、浏览器等），支持路径 / Store 包身份匹配；可从网络活动的决定记录一键生成规则。 |

**验收**

- 设置例外后，例外子树的连接直连，其余子进程仍走代理（e2e）。
- 驱动加载失败时界面给出明确提示；导出的配置在新目录导入后行为一致。
- 选择预设后无需手写规则即可代理对应应用；Store 应用升级后路径变化仍能命中。
- PID 复用后新进程不继承旧进程的匹配状态。
- 双栈环境下 IPv6 TCP 与 UDP 经 SOCKS5 出口，出口地址与 IPv4 一致（e2e 用回环 IPv6 代理验证）；IPv6 规则排除网段生效。

## 之后：先有基准，再谈性能与部署

**目标**：用数据证明性能改动的收益，并让长期运行更稳。顺序：基准 → 资源上限 → 批处理（视基准而定）→ 进程信息缓存 → 浸泡测试 → 服务化。

| 项目 | 内容 |
| --- | --- |
| 性能基准 | 在现有压测工具（`tests/stress_backend.py` + `tests/stress_etw.py`，CI 以 `--ci` 跑有界冒烟并上传 `stress-summary`）基础上，补充判定延迟（CONNECT → 发布的 p99）、漏代理（`late_rejected_proxied`、看门狗放行）以及 RSS 随进程数的变化；固定硬件上的完整场景与前后对比。 |
| 资源上限 | 活动 / 待建会话、重试、队列、UDP 端口等设容量上限与溢出计数；IO 线程数按测量决定。 |
| RecvEx / SendEx 批处理 | 仅当基准显示 NETWORK 工作线程是瓶颈时才做（现有逐包循环无分配，strand 更可能是瓶颈）；必须保护 SYN parking、重传、校验和、关闭顺序和缓冲区生命周期。 |
| 进程信息缓存 | 减少重复解析进程信息，保留 PSN 身份校验，不为命中缓存跳过 PID 重用与退出清理。 |
| 夜间浸泡测试 | 数小时真实会话（长连接 / SSE / WebSocket），在自托管 runner 上每晚运行而非每个 PR；持续观察本机回环相关蓝屏是否复现。 |
| 服务化 | 普通权限 UI + 提权后端服务、带 ACL 的命名管道 IPC，作为独立工作包。过渡方案：安装到 Program Files 的安装包，以及 WebView2 用户数据目录（profile）防篡改保护。 |
| 工程整理 | 依赖单一来源（vcpkg manifest，WinDivert / WebView2 仍脚本拉取）；Python 测试脚本统一 `pyproject` 管理；版本文件不再在配置时写入源码树。 |

**验收**

- 有可重复执行的基准脚本与基线数据；每项性能改动附前后对比，且不引入首包泄漏。
- 资源在压力下有上界，超限有计数与日志。
- 服务模式下 UI 无需管理员权限，其他本机用户无法调用管理接口。

## 暂不计划

自研 WFP 驱动（需微软签名与 EV 证书）、默认 DLL 注入、完整 TUN 后端、内置多种节点协议。自动切换上游只影响新连接，已建立的 TLS / SSE / WebSocket 不能透明迁移。只有现有路径确实无法解决问题时才重新立项。

**上游类型决定**：不支持 HTTP 代理上游，`http` 类型从配置与界面中移除（v0.13.1 起保存时即返回 400）。SOCKS5 用户名 / 密码认证目前未实现，带用户名或密码的代理组同样返回 400；如需支持，再单独实现 RFC 1929（方法 0x02）。
