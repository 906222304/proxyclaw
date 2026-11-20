# WFP 驱动参考项目对比

> 调研日期 2026-11-19。star、提交日期以当天为准。设计见 [wfp-driver.md](wfp-driver.md)。

## 结论

**没有一个能直接拿来用。** 主流 VPN 的「按应用分流」驱动（Mullvad、Windscribe、Proton、PIA）只改**源地址**，把连接换到另一块网卡，从不把目的地址改到本地代理。开源代码里真正做「重定向到本地 relay + 取回原始目的地址」的只有三个：ProxyBridge Driver 分支（原型）、tunless（从未运行）、ebpf-for-windows netebpfext（生产级，但是通用 eBPF 框架）。

推荐组合：
- **整体结构**照 ProxyBridge Driver 和 tunless（与 ProxyClaw 一一对应）；
- **API 用法的正确性**以微软文档为准，对照 netebpfext 核查（样例代码有笔误，见下）；
- **健壮性**借鉴 Windscribe 的注释和写法（GPL-2，只借鉴思路）；
- **进程跟踪、子进程继承、新进程首连 pend、IOCTL 状态机、卸载自救**借鉴 Mullvad 的思路（MPL-2.0，clean-room 重写）；
- **签名流程**参考 Proton 的 README。

## 总表

| 项目 | 做什么 | 层 | 取原始目的地址 | UDP | 成熟度 | 许可 | 对我们的价值 |
|---|---|---|---|---|---|---|---|
| [ProxyBridge `Driver` 分支](https://github.com/InterceptSuite/ProxyBridge/tree/Driver) | 按镜像名重定向到本地 relay | CONNECT_REDIRECT v4/v6 + AUTH_CONNECT（观察） | context `{origDst,pid}` | 内核流表 + IOCTL 查询（有缺陷） | 原型，未发版，只有自签名；2026-09 起无更新 | MIT | 结构最像；缺陷要避开 |
| [bojieli/tunless](https://github.com/bojieli/tunless) | 全部 TCP 重定向到 loopback | CONNECT_REDIRECT v4/v6 | context + records | 不做（直连） | **从未编译、加载过** | MIT | 防环和共存写得最完整，代码短 |
| [ebpf-for-windows netebpfext](https://github.com/microsoft/ebpf-for-windows) + [GuestProxyAgent](https://github.com/Azure/GuestProxyAgent) | eBPF 程序决定重定向 | AUTH_CONNECT + CONNECT_REDIRECT | context | 未读 | 生产级，微软维护 | MIT | 核对正确性；读取端参考 |
| [Mullvad win-split-tunnel](https://github.com/mullvad/win-split-tunnel) | 把进程移出 VPN 隧道 | BIND/CONNECT_REDIRECT + AUTH_* | 不需要 | 改源地址 | 2021 年起生产使用，近一年仍有蓝屏 | GPL-3+ 或 MPL-2.0 | 进程跟踪和生命周期设计最好 |
| [Windscribe](https://github.com/Windscribe/Desktop-App) | 分流 | BIND/CONNECT_REDIRECT | 不需要 | 改源地址 | 生产 | GPL-2.0 | 防蓝屏、防无限重定向 |
| [ProtonVPN](https://github.com/ProtonVPN/win-app) | 分流 + DNS 阻断 | BIND/CONNECT_REDIRECT + IPPACKET | 不需要 | 改源地址 | 生产，x64/arm64 | GPL-3.0 | attestation 签名步骤 |
| [微软 WFPSampler / ddproxy](https://github.com/microsoft/Windows-driver-samples/tree/main/network/trans) | 官方代理场景 / UDP 改写 | CONNECT_REDIRECT / DATAGRAM_DATA | context + records | ddproxy 重注入 | 2010–2014 年的样例 | MS-PL | API 顺序的权威来源 |
| [Netch](https://github.com/netchx/netch) | 按进程代理 | 闭源 NetFilter SDK | 按源端口查表 | SOCKS5 UDP | 2022 年后停更 | GPL-3.0（驱动为商业闭源） | 只参考用户态功能 |
| [ProxiFyre](https://github.com/wiresock/proxifyre) | 按应用 SOCKS5 | NDIS（非 WFP） | — | 支持 | 活跃 | AGPL-3.0 | 竞品对照 |

## 逐项要点

### ProxyBridge Driver 分支（主要结构参考）
- 约 750 行。动态会话，sublayer 权重 0x8000；重定向过滤器无条件、动作为 `CALLOUT_UNKNOWN`；按 `ALE_APP_ID` 镜像路径后缀匹配进程，不按 PID；同步 classify，不 pend；`localRedirectTargetPID` 设为自身 PID。
- 缺陷（`ProxyBridgeDrv.c` 行号，见调研原文）：
  - **B1** 环回分支在 acquire 之后没调用 Apply 就返回，留下 BLOCK（:171-181）；
  - **B2** `RegisterWfp` 失败时不回滚（:430-464），可能留下指向已卸载代码的过滤器；
  - **B3** DIRECT 判定没有直连路径：TCP 会走第一个代理，UDP 被丢弃（#229）；
  - **B4** IPv6 UDP 不可用；
  - **B5** 没有 `IRP_MJ_CLEANUP`，崩溃后流量继续导向已死的 relay；
  - **B6** 只配了 HTTP 代理时 UDP 进黑洞；
  - UDP 流表按端口为键、后写覆盖、永不淘汰；没有 `previousVersion` / BY_OTHER 处理；relay 没调用 `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS`。
- 项目状态：维护者 2026-08-30 表示签名方案没解决、Windows 开发暂停；相关 issue 已于 2026-10-22 以 not_planned 关闭。
- **取**：整体分层、context 结构、relay 读取方式。**不取**：按镜像名匹配、UDP 流表、生命周期处理。

### tunless
- 只有 TCP。classify：先 `FwpsQueryConnectionRedirectState0` 跳过自己改过的连接，再遍历 `previousVersion`，**别人改过就不叠加**；context 里放原始目的地址、PID 和 AppId；设置 redirect handle 和 target PID。用户态 Go 调用 `SIO_QUERY_*_RECORDS/CONTEXT`，出站时 `SIO_SET_*_RECORDS`。动态会话随进程退出自动清理。
- README 自述「从未编译、加载、跑过 Driver Verifier，也未签名」，只能当设计稿看。

### Mullvad win-split-tunnel
- 思路上最值得借鉴：
  - 进程表（AVL）+ `PsSetCreateProcessNotifyRoutineEx` + 父进程已分流则子进程继承；
  - 未知 PID 的连接在重定向层 `FwpsPendClassify0`，进程登记后 `FwpsCompleteClassify0(NULL)` 重新授权；
  - 启动握手：先缓存进程事件，用户态做快照，再开始分发，重复项做校验；
  - WFP 事务配合自写 undo 日志；用哑过滤器强制 ALE 重新授权；
  - 严格的 IOCTL 状态机；卸载失败时故意蓝屏（`KeBugCheckEx`），而不是带着残留回调卸载。
- 读代码时发现的问题 **[未验证]**：pend 超时只在有进程事件时才扫描；一个失败分支可能遗留未完成的分类；一处写进程设置时没加锁；父链没有防环（PR #56）。
- 已知蓝屏：#11487（锁泄漏，修复 2026-11-13 合入但未发版）、#8860（开机循环，维护者说只是缓解）。没发现与 ESET 有关的蓝屏报告。
- 只改源地址，不使用任何代理式重定向 API。

### Windscribe（健壮性检查清单）
- 校验 provider context 的类型和大小（任何人都能把过滤器指向你的 callout GUID）；
- 在 acquire **之前**跳过 `IS_REAUTHORIZE`，否则会在 `NETIO!FeApplyModifiedLayerData` 蓝屏；
- 所有跳过判断都放在 acquire 之前，acquire 成功后只 Apply 一次；
- 同一 filterId 改过超过 3 次就 BLOCK；
- 用 EV 证书签名，二进制随安装包分发。

### 微软官方（文档 + 样例）
- 完整的 inline 和 pend 流程、四种 redirect state 的处理、`localRedirectHandle`/`TargetPID` 必填、context 归 WFP 所有、acceptor 地址规则：见 wfp-driver.md §5。
- 文档和样例里的问题，**不要照抄**：
  - 多 callout 示例写成了 `rights &= WRITE`（应为 `|=`）；
  - `previousVersion` 解引用前没判空；
  - 内联路径传了 `REAUTHORIZE_IF_MODIFIED_BY_OTHERS`（文档要求为 0）；
  - WFPSampler 不处理注销时返回的 `STATUS_DEVICE_BUSY`；
  - README 提到的代理服务 `WFPSamplerProxyService` 在仓库里不存在。
- callout 注销后，`CALLOUT_UNKNOWN/TERMINATING` 过滤器按 BLOCK 处理；用 `PERMIT_IF_CALLOUT_UNREGISTERED` 或动态会话避免断网。
- 签名：attestation 被定为「仅用于测试」（2026-03-23），生产路径为 HLK/WHCP；HVCI 兼容是硬性要求。
- 官方原话：更推荐在 STREAM 层做检查；如果一定要代理，就用 connect-redirect，并让代理调用 redirect records IOCTL，这样多个代理才能共存。

### 不建议投入时间
mullvad/wfp-rs（不支持 callout 和重定向层）、wintun（是 TUN 网卡，不是 callout）、mihomo/sing-box（只在用户态查进程）、Nova（专有许可）、abyss-rs（仓库里没有驱动源码）、PIA 驱动（停在 2020 年，只有 IPv4）、个人实验项目（leaf、JammVpn）。

## 共同空白
- **UDP 目的地址重定向**：没有经过运行验证的开源 WFP 实现。
- **签名**：能正常分发的项目都靠 EV 证书 + Partner Center，没有捷径。
- **与安全软件共存**：没有任何项目公开说明与 ESET 一类产品共存的实测结果。
