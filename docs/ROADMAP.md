# ProxyClaw 路线图

> **English summary.** v0.14 makes every decision explainable from one source of truth: all C++ unit tests in CTest first, then a per-connection decision record captured at CONNECT time, connection JSON built off the strand (activity poll merged in), a hit-rule column with the reason and conflict hints, blocking IPv6 for proxied processes so they fall back to IPv4, DNS TCP-only startup and asynchronous enable, an icon cache keyed by full path with backoff and a cap, `psn` in the pushed process tree, keyboard / ARIA for the process tree, a split CI with /W4 and ESLint, and a docs sweep. v0.15: child-process-tree exceptions, an engine state view with config import / export, editable presets, rule match state keyed by (pid, psn), and end-to-end IPv6 last (may slip). Later: a performance baseline first (decision latency, missed proxies, RSS vs process count), then resource caps, RecvEx/SendEx batching only if the baseline shows a need, a process info cache, nightly soak tests, service mode (with a Program Files installer and WebView2 profile protection as an interim step) and build tidy-up. Not planned: a custom WFP driver, DLL injection by default, a TUN back end, built-in proxy protocols; the `http` upstream type is dropped and SOCKS5 username / password stays unsupported (rejected with 400) until implemented.

当前版本 v0.14.0（2026-11-09），已完成 v0.14 第 1–4 项（测试归位、每连接决定记录、连接 JSON 移出 strand、命中规则列），其余各项在后续 v0.14.x 发布。本文只列尚未完成的工作；已完成的见 [CHANGELOG](../CHANGELOG.md)。v0.13.1 已完成：代理组快照替换、窗口位置经配置存储保存、自启动仅限管理员专属目录、开发钩子需 `--dev-hooks`、IPv6 移出判定路径（`ipv6_unmanaged` 计数）、进程排除改为运行时 (pid, psn) 状态、孤儿进程按 (pid, psn) 跟踪并限时限量、TCP :53 使用配置的 DNS 上游、代理组输入校验、WinDivert 关闭顺序、控制台模式不再一小时后退出。

**原则**：先有唯一的事实来源（CONNECT 时记录的决定），界面、统计和 IPv6 标注都从它读取；性能改动必须先有能测出策略延迟与漏代理的基准。

## v0.14：决定可解释，边界可见

**目标**：用户不用读日志就能知道某条连接为什么走代理或直连，以及哪些流量 ProxyClaw 目前不接管。按下表顺序推进。

| # | 项目 | 内容 |
| --- | --- | --- |
| 5 | IPv6 阻断回落 | 被代理进程的 IPv6 TCP 连接由 SYN 闸门回 RST、IPv6 UDP 丢弃，应用回落 IPv4 并经过代理；局域网 IPv6（链路本地、ULA、组播）与规则排除端口不阻断；设置 `ipv6.mode` = `block`（默认）/ `direct`，运行时生效；决定记录原因 `ipv6_blocked`，`/api/stats` 计数。 |
| 6 | DNS 仅 TCP 启动 | 启动不再强制 UDP ASSOCIATE 成功：探测上游 TCP 可用后允许以 TCP-only 方式启用（运行时已有 TCP 回退）；保留系统 DNS 备份与恢复。 |
| 7 | DNS 异步启用 | 启用 DNS 的接口立即返回“启动中”，界面显示进度与失败原因，不再同步等待最长 10 秒，也不再在配置观察者中阻塞 API 线程。 |
| 8 | 图标缓存 | 按完整路径为键（服务端由 pid 解析路径，去掉客户端 `path` 参数）；失败查找带重试退避，不再每次重新枚举进程；缓存设容量上限；工作线程初始化 COM；前端负结果短期过期并回收 object URL。 |
| 9 | 推送进程树带 `psn` | 界面按 (pid, psn) 缓存进程详情，PID 复用后不再显示上一个进程的路径 / 命令行。 |
| 10 | 进程树键盘与 ARIA | `role="tree"/"treeitem"`、`aria-expanded`、`aria-selected`、方向键与 roving tabindex。 |
| 11 | CI 拆分 + /W4 + ESLint | 构建 / 单元测试 → e2e → 发布（仅标签）；项目源文件 `/W4`；ESLint 与 `tsc --noEmit` 独立步骤。偶发失败的 e2e 不再阻塞发布产物。 |
| 12 | 文档清理 | 修正过时的注释与文档（批处理 RecvEx/SendEx、“Stage 4”、`config_sse_bridge` 命名、ARCHITECTURE 中的排除与 TCP:53 说明、README 的 IPv6 代理地址说法）。 |

**验收**

- CTest 覆盖全部 C++ 单元测试，CI 绿。
- 每条连接的结论与记录的决定一致（不是重新计算）；任意一条连接都能在界面看到命中规则与原因；规则冲突有提示。
- 带 UI 等效轮询的压测冒烟中 `late_rejected_proxied` 不上升。
- 被代理进程连接全局 IPv6 地址时被拒绝（RST，Windows 重试后约 2 秒内失败），UDP 数据报被丢弃；规则排除端口的连接不受影响（e2e 用文档网段 2001:db8::/64 + 静态邻居覆盖）。
- 仅支持 TCP 的 SOCKS5 上游可以启用 DNS 代理；启用、关闭、强杀后重启均能恢复系统 DNS（loopback harness 用例）。
- 启用 DNS 的 API 在 200 ms 内返回，状态随后经推送更新。
- 图标缓存在 1 万个不同路径下内存有上界；同名不同路径的程序图标正确。
- 进程树可只用键盘浏览与选择。

## v0.15：覆盖更多真实场景

**目标**：双栈网络、常见应用和复杂进程树开箱即用，少写规则。按下表顺序推进。

| # | 项目 | 内容 |
| --- | --- | --- |
| 1 | 子进程树例外 | 为进程树规则配置子树直连例外（如 Electron 根进程下的 ssh / scp、局域网服务、代理客户端自身）；建立在 v0.13.1 的 (pid, psn) 排除状态与 v0.14 的决定原因之上。不默认放行所有 SSH，也不因同名 node / python 就代理全部实例。 |
| 2 | 引擎状态与配置导入 / 导出 | 界面显示引擎运行、WinDivert 驱动加载失败、DNS 恢复等状态及决定记录计数；配置导入经 `config_store`，沿用带版本号的配置迁移。 |
| 3 | 可编辑应用预设 | 基于现有规则系统的预设（常见 AI 客户端、IDE、浏览器等），支持路径 / Store 包身份匹配；可从网络活动的决定记录一键生成规则。 |
| 4 | 规则匹配状态按 (pid, psn) | `matched_pids` 改为 (pid, psn)，在进程启动 / 退出时刷新，而不只在规则变更时刷新；修正进程树继承的已知残留问题。 |
| 5 | IPv6 端到端代理（TCP + UDP） | TCP 已在 v0.14.x 以 `ipv6.mode = proxy` 提供（[::1] 接收器 + SOCKS5 ATYP 4）；剩余 UDP。放在最后，允许顺延到 v0.16：统一地址类型、tracker / socket 键、规则与 CIDR 匹配、IPv6 报文重写与校验和、SOCKS5 CONNECT / UDP 帧中的 IPv6 地址（ATYP 4）、接口与作用域、活动列表；按地址族用配置开关逐步开启。 |

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
