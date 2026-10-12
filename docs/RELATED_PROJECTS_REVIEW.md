# 同类项目调研与优化方向（2026-10-09）

## 结论和检查范围

ProxyClaw 最值得继续强化的定位是：已有本地代理客户端之上的 Windows 进程树流量入口，提供可靠转发、明确的分流结果和可定位的故障信息。

本次对照四个指定项目，并补充 WinDivert、NDIS/Netfilter、DLL 注入和 TUN 路线的项目。外部能力依据官方仓库、发布说明和文档；本地依据当前工作区，而不是仅依据远端 HEAD。检查时 HEAD 为 `6632a40`，存在尚未提交的连接稳定性和日志界面等改动。本文只新增调研记录，不修改这些实现。

本次进行静态检查，没有运行真实流量、数小时稳定性或吞吐基准。下文明确区分已确认的实现事实、据此推断的风险和建议的验收条件。没有证据把新增发现归因为此前 GPT 卡死的实际原因。

## 四个指定项目分别值得借鉴什么

| 项目 | 路线与已核实能力 | 对 ProxyClaw 的意义 |
| --- | --- | --- |
| [ProxyBridge](https://github.com/InterceptSuite/ProxyBridge) | Windows 使用 WinDivert；规则支持代理、直连、阻止，TCP/UDP、HTTP/SOCKS5、多代理及 IPv6；跨平台分别实现 | 借鉴规则动作、能力显示、配置档案和 IPv6 设计；不能据宣传推断更快或更稳定 |
| [ProxiFyre](https://github.com/wiresock/proxifyre) | NDISAPI / Windows Packet Filter；SOCKS5 TCP/UDP、IPv4/IPv6、GUI、服务；可选 TLS 传输 | 借鉴校验、服务状态、分阶段诊断和进程归属缓存；不必因此替换现有 WinDivert 路线 |
| [Clew](https://github.com/ymonster/clew-proxy) | 本项目直接上游；进程树、命令行匹配、多组 SOCKS5、DNS forwarder；v0.10.0 加入 SYN parking 和 PSN 校验 | 持续跟踪上游差异，保留现有对短命进程及 PID 重用的处理；这些不是本项目尚缺的新功能 |
| [codex-app-proxy](https://github.com/leisair/codex-app-proxy) | 便携启动器，查找 Store 应用并传入 Chromium 代理和禁用 QUIC 参数，启动后退出 | 借鉴初次配置、已有实例检测和最小诊断；启动参数覆盖范围应按应用实测，不能视为整个进程树网络拦截 |

资料状态需要分开看：ProxiFyre 当前 README 已有 GUI 和 Windows 服务，不能继续称它为纯 CLI 工具。2026-10-06 发布的 [v2.6.2](https://github.com/wiresock/proxifyre/releases/tag/v2.6.2) 专门减少连接更新时重复查询进程信息，并增加 IPv4/IPv6 归属及并发测试。

ProxyBridge 当前 README 宣称 Windows/macOS/Linux 支持，但 [v4.0.0 发布说明](https://github.com/InterceptSuite/ProxyBridge/releases/tag/v4.0.0) 把该版 Linux 列为尚在开发。应区分当前源码能力和指定发行包，不能据 README 推断全部平台的发布成熟度。该版的 IPv6、多代理、Profiles 和域名转发值得研究。

普通 HTTP CONNECT 承载 TCP；UDP 需要 SOCKS5 UDP ASSOCIATE 或另外的明确机制。ProxyBridge 的 Windows [规则代码](https://github.com/InterceptSuite/ProxyBridge/blob/master/Windows/src/pb_rules.c) 也区分 HTTP 与 SOCKS5 的 UDP 能力。不要在本项目增加 HTTP 类型后仍统一显示“TCP + UDP 可用”。

## 其他相关项目

| 项目 | 类别 | 可借鉴内容和适用边界 |
| --- | --- | --- |
| [OpenProxifier](https://github.com/4111y80y/OpenProxifier) | WinDivert + DLL 注入双模式 | 代理/直连/阻止、SOCKS5 认证、启动前测试、内置测试应用；其功能列表不构成本次实测的稳定性保证 |
| [wfp-divert](https://github.com/okatodev/wfp-divert) | 精简 WinDivert TCP/UDP 重定向 | Reflection、按应用/IP/CIDR 分流、UDP 回收；适合阅读小型实现。名字含 WFP，但它仍使用 WinDivert，不是独立自研 WFP 驱动 |
| [proxinject](https://github.com/PragmaTwice/proxinject) | DLL 注入 / API hook | 按 PID、名称、路径启动或附加，以及子进程控制。可参考命令行体验；注入兼容性须另外验证 |
| [proxychains-windows](https://github.com/shunf4/proxychains-windows) | MinHook + DLL 注入 | Fake IP、远端域名解析、子进程与命名管道；作者也记录终端及 hook 边界。适合研究 DNS 归属，不能直接解决所有自带 resolver 的应用 |
| [Netch](https://github.com/netchx/netch) | Netfilter 进程模式 + TUN 等模式 | 模式划分和能力边界；README 声明部分特性未必在 v1 实现。适合作为架构参考，不能按功能列表假定可直接接入 |
| [tun2socks](https://github.com/xjasonlyu/tun2socks) | TUN + gVisor 网络栈 | IPv6、用户态网络栈和跨平台转发。它本身不等价于当前基于进程树的规则层 |
| [sing-box](https://sing-box.sagernet.org/configuration/route/rule/) / [mihomo](https://wiki.metacubex.one/en/config/rules/) | 完整代理核心与规则系统 | 进程/路径规则、DNS 策略、TUN、规则动作；更适合作为现有上游及设计参照。当前定位下，订阅、节点协议和测速选节点可继续交给上游 |

[sing-box 的 Windows TUN 文档](https://sing-box.sagernet.org/configuration/inbound/tun/) 说明 strict_route 还要处理多网卡 DNS 泄漏及兼容性。它表明“能按进程分流”和“完全没有系统层面的影响”是不同问题。

## 已有成果：不要重复列为待开发

根据工作区源码及 `OPTIMIZATION_REVIEW.md`、`CONNECTION_STABILITY_REVIEW.md`：

- 已有进程树跟踪、命令行/路径匹配、多代理组、SYN parking、PSN 验证和自身流量绕过。
- 已有中文界面、后台与托盘行为、高清屏适配、Monaco 按需加载及防重叠周期刷新。
- 当前工作区已有 TCP 握手总期限、半关闭、完整读取不同 SOCKS5 回复、Windows 保活、UDP 控制断线与会话回收修复。
- 已有 DNS 查询的 UDP 超时/截断后 TCP 回退，以及日志查看界面。

已有隔离测试记录不能替代真实长时间应用观测；这里没有重新运行或重新确认那些测试结果。

## 第一阶段：补齐实际行为和诊断

### 1. 规则执行与界面结果统一（优先）

**已确认事实：** `frontend/src/components/RuleEditorDialog.vue` 提供 `include_ports`；`src/services/connection_service.cpp` 使用完整 `TrafficFilterEngine::should_proxy()` 推算显示状态。但 TCP 的 `src/core/windivert_socket.hpp` 当前只调用目的 IP 排除逻辑；UDP 的 `src/udp/windivert_network_udp.hpp` 通过 `IpExcludePolicy` 也只评估 CIDR 排除。`src/rules/traffic_filter.hpp` 明确写明 include/port 尚未接入转发。

**影响：** 某些设置会改变界面的判断，却没有对应的实际转发行为；已有连接的显示还可能跟随新规则推算，偏离建连时的决定。应先统一现有语义，再增加新规则类型。

**建议：** TCP/UDP 使用同一不可变目的地址/端口策略；为连接保存实际动作、命中规则、代理组、配置版本和原因，界面读取实际决定。未支持的字段先明确拒绝或隐藏。随后再增加 `PROXY / DIRECT / BLOCK`、优先级和子进程例外，且明确多个规则与继承规则的竞争次序。

**验收：** 仅允许端口 443 的规则对 80/443 的真实出口符合配置；全局/规则排除和 TCP/UDP 结果一致；改规则后旧连接仍显示原决定，新连接显示新决定。

### 2. UDP 每包目的地址与返回来源（优先复现）

**已确认事实：** `UdpSessionTable` 以 `uint16_t app_port` 为键，每次覆盖一个目的地址。网络层先更新表，再将包反射到本地 relay；relay 收包后再查该表。下行虽然解码了 SOCKS5 帧的地址/端口，调用 `inject_reply()` 时只使用负载和表中最后的目的地址。

**风险推断：** 同一 UDP socket 快速向 A、B 两个目标发送时，表可能已被 B 覆盖，而 relay 尚在读取 A 的数据；迟到的 A 回复可能被注入为 B 的来源。UDP 收包循环还直接等待 `get_or_create()`，一个最长 10 秒的慢握手会暂停该循环接收其他端口的数据；这是协程队头阻塞，不是 IO 工作线程被同步锁住。

**建议：** 把每包原始目的地址/端口及本地地址、接口、socket 生命周期标识一起带到 relay 队列；不能只把表改成五元组而仍在反射后丢失目的端口。会话归属与单包目的地分开，下行使用已验证的 SOCKS5 返回来源；一个应用 socket 可继续独占一个 ASSOCIATE，无需每个远端都建新会话。按 socket 并发建连、单次共享 pending 结果，增加全局/单 socket 有界队列、容量和失败退避，避免无限协程。

**验收：** 单 socket 交错访问两个回环 UDP echo 目标、回复乱序、同端口重用、不同本地地址、切换组及关闭重建；验证负载和来源均正确。让一个组握手停顿，另一个已有健康会话仍及时收到数据。

ProxyBridge 的 [连接表](https://github.com/InterceptSuite/ProxyBridge/blob/master/Windows/src/pb_conntrack.c) 和 [UDP relay](https://github.com/InterceptSuite/ProxyBridge/blob/master/Windows/src/pb_relay.c) 可用于比较，但其按端口及共享上游反查方式也有需要验证的边界。不要直接照搬另一项目就宣称这些问题已解决。

### 3. 测速升级为真实分阶段健康检测（优先）

**已确认事实：** `src/services/group_service.cpp::test_group()` 单独使用同步 socket，仅处理 IPv4 字面代理地址；默认目标端口为 80，去掉 URL scheme 后发送明文 HEAD。它用单次 `recv()` 读握手，固定读 10 字节 CONNECT 回复，收到任何回复就返回 `latency_ms`。因此它没有复用刚修复的分段/IPv6/域名回复读取，也没有进行 HTTPS TLS 验证或 HTTP 状态校验。

**建议：** 共用 SOCKS5 协议读取与统一期限；先提供代理端口、握手、目标 CONNECT、HTTPS/TLS、HTTP 状态、UDP echo/DNS 的独立结果。标准 URL parser 保留 scheme、host、port；HTTPS 使用系统证书验证，不能“去掉 https”后测端口 80。状态显示“可连接/目标可达/认证受限/UDP 不可用”等实际含义，403 说明收到了 HTTP 响应，不能当作登录成功。

**验收：** 分段、域名/IPv6 BND 回复、坏协议、HTTPS、目标拒绝、证书错误及只开放 HTTP 端口均能正确区分；测速总期限覆盖解析和 connect，取消后不占用处理线程。

### 4. 管理 API 的调用边界（优先）

**已确认事实：** API 监听 127.0.0.1；`src/transport/middleware.cpp` 设置通配 CORS 并开放 OPTIONS，`route_registry.cpp` 直接执行 handler，未见生效的会话 token 或 Origin/Host 校验。接口包含配置、规则、开机任务、日志读取及 shell 操作，程序通常以管理员运行。部分头文件提到 auth，但当前分发实现没有该检查。

**建议：** 去掉通配 CORS；校验 Host/Origin，为读写管理接口加入随机会话凭证并由宿主向可信前端交付。凭证不要泄漏到日志或公开静态文件；WebView2 消息也校验来源。若要隔离本机低权限进程，评估带用户/权限 ACL 的命名管道或宿主 IPC，CORS 不能承担本机进程身份验证。

**验收：** 未授权请求不能读日志或改配置，正常前端继续工作，外部 Origin 和无凭证请求被拒绝。浏览器是否能访问 localhost 还取决于其本地网络访问限制；本次没有验证可利用链，不将其描述为已成功利用的漏洞。

## 第二阶段：补齐能力边界与易用性

### IPv6：端到端实现，先准确呈现状态

TCP/UDP 网络层只获取 IPv4 IP header，没有 IPv4 header 就直接放行。SOCKS5 TCP 正确消费 IPv6 BND 回复仅表示握手解析完整，应用 IPv6 目的地址、IPv6 Reflection、CIDR 和 UDP 编解码仍需实现。

先在界面明确 IPv6 尚未接管；再统一地址类型、tracker/socket 键、规则与报文重写、SOCKS5 CONNECT/UDP 帧、接口/作用域、校验和及活动列表。完整支持前不要提供会误伤非目标应用的全局禁用 IPv6。双栈目标、AAAA 优先、仅 IPv6、同数字端口跨地址族和退出清理是验收重点。

### DNS：启动模式和系统作用范围

当前本地监听 UDP，运行时有 TCP 回退；但启动仍先要求 UDP ASSOCIATE 成功，不支持 UDP 的上游无法利用该回退启用 DNS。可增加经探测的 TCP-only 上游模式、异步启用状态和本地 TCP DNS；后续再评估 DoH/DoT、TTL 缓存和同请求合并。

设置系统网卡 DNS 会影响其他应用的系统解析。先说明作用范围、上游组和恢复状态，再研究按应用 DNS 方案。Windows DNS Client、应用自己的 DoH 和自带 resolver 使归属复杂；“代理 svchost.exe 的 DNS”不能直接等价于“只代理某个目标应用 DNS”。域名嗅探/IP 反查受共享 CDN、缓存、加密 DNS 和同 IP 多域名限制，不能承诺准确还原原始主机名。

### 应用预设与进程树例外

沿用现有规则系统提供可编辑的应用配置预设、路径/包身份选择、从活动创建规则、命中解释与冲突提示。为 Electron 根进程下的 ssh/scp、局域网服务及代理客户端提供用户可配置的子树直连例外；不要默认放行所有 SSH，也不要因同名 node/python 就代理全部实例。Store 应用版本路径变化需要身份/模式匹配和回归验证。

codex-app-proxy 的已有实例检查及一次性向导值得借鉴，但轻量启动器应独立作为可选能力；Chromium 参数不能作为整个进程树的透明代理保证，环境变量也不是所有程序都读取。

## 第三阶段：基准后再做性能与部署

1. **WinDivert 批处理。** `windivert_network.hpp` 注释写有 batch I/O，但实际循环仍使用逐包 `WinDivertRecv/Send`。按 [WinDivert 官方说明](https://reqrypt.org/windivert-doc.html#divert_recv_ex) 评估 RecvEx/SendEx；测低速延迟与高包率吞吐，并保护 SYN parking、重传、校验和、关闭顺序和包缓冲区生命周期。
2. **测量非目标应用的成本。** 当前抓取所有非回环出站 TCP/UDP，未命中的包也经过用户态。记录单独开 TCP/UDP、健康/故障上游、隐藏/显示窗口、突发进程和大流量下的 CPU、RSS、句柄、p95/p99 延迟与包丢失。不要只比较 UI bundle 大小或项目语言就下性能结论；动态收窄过滤器需另证不会漏首包。
3. **限制资源。** 已有 UDP 超时回收，下一步是活动/待建会话、重试、队列与图标缓存的容量限制。CPU 核数不直接等于最优 IO 线程数。
4. **进程缓存。** 借鉴 ProxiFyre 2.6.2 的减少重复解析思想，保留本项目 PSN 身份验证；不能为了命中缓存而跳过 PID 重用和退出清理。
5. **部署。** 先提供明确的引擎运行/驱动失败/DNS 恢复状态、完整退出、配置导入导出和带版本迁移。服务化、普通权限 UI + 提权后端、IPC ACL 作为后续较大工作包，不和转发修复混在一起。

## 推荐开发顺序与暂缓方向

| 顺序 | 工作包 | 完成标准 |
| --- | --- | --- |
| 1 | 现有规则执行、实际决定显示、管理 API 校验 | UI 与真实出口一致，管理请求明确授权 |
| 2 | UDP 多目标及队头阻塞专项复现/修复 | 多目标乱序、重用和一个慢组不影响健康组 |
| 3 | 共用协议组件、异步分阶段健康检查 | 测试链路与生产协议一致，HTTPS 和 UDP 能力有独立结果 |
| 4 | IPv6 能力呈现/实现、DNS TCP-only/异步启动 | 双栈覆盖可验证；启用/退出/异常恢复可验证 |
| 5 | 应用预设、子树例外、规则解释 | 常用场景少配置，异常流量能解释 |
| 6 | 批量抓发、资源上限、服务化 | 先有基准，再用数据证明收益和回归边界 |

暂缓自研 WFP 驱动、默认 DLL 注入、完整 TUN 后端和内置多种节点协议。它们会扩大驱动、兼容性或运维范围，应以现有路径确有无法解决的问题作为立项依据。自动切换上游只影响新连接；已建立 TLS/SSE/WebSocket 不能透明迁移或重放，必须保留应用可见的断线/重连语义。

借鉴设计和直接复用代码应分别评估。各仓库许可证不同，尤其 ProxiFyre 为 AGPL-3.0、Netch 为 GPL-3.0；MIT/Apache 项目也需要保留对应版权与通知。本文没有引入第三方代码。
