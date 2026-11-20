# ProxyClaw WFP 驱动设计草案（Draft）

> 状态：草案，未立项。日期 2026-11-20。参考项目评估见 [wfp-references.md](wfp-references.md)。
> 标记：**[官方]** 微软文档明确；**[参考]** 参考项目的做法；**[待验证]** 需在 VM/WinDbg 上实测。
> ROADMAP「暂不计划」里有自研 WFP 驱动这一项，本文用来评估是否重新立项，不是立项决定。

## 1. 为什么考虑换

现在的拦截靠 WinDivert 分两层：SOCKET 层能拿到 PID 但不能改包，NETWORK 层能改包但拿不到 PID，两层只能靠本地端口对上（见 ARCHITECTURE「WinDivert dual-layer」「TCP SYN parking」「PortTracker」）。由此带来：

- SYN 停放、四态 CAS、内核时间戳 TTL、phantom CONNECT、ISN 重传例外、`late_rejected` 等一整套补偿逻辑；
- IPv6 要单独的 SYN 门和 `[::1]` 反射表；
- 每个被代理的包都要在用户态改写后经 `WinDivertSend` 重新注入，热路径开销大；而且重新注入正是 2026-11-18 蓝屏（0xD1，NETIO.SYS，栈上有 ESET `epfwwfp.sys`）被怀疑的触发点 **[待验证]**。

WFP 的 `ALE_CONNECT_REDIRECT_V4/V6` 层**在建连时同时拿到 PID 和原始目的地址**，可以直接把连接改到本地 relay。relay 在 accept 到的 socket 上用 `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` 取回原始目的地址 **[官方]**。之后包不再经过用户态，上面这些补偿逻辑大部分可以删掉。

## 2. 目标与非目标

目标：
- 按进程（含子进程树）把 TCP 透明重定向到 ProxyClaw 本地 relay，IPv4/IPv6 都支持；
- 进程刚启动就发出的连接也不漏（替代 SYN 停放）；
- 驱动或 ProxyClaw 崩溃时流量直连（fail-open），不断网；
- 与其他 WFP 产品（杀软、VPN）按微软的约定共存；
- 保留 WinDivert 后端作为回退，可在设置里切换。

非目标（第一阶段）：
- UDP 走 WFP（见 §7，先留在 WinDivert）；
- 在内核里实现规则引擎（规则匹配仍在用户态）；
- 32 位、Windows Server 支持。

## 3. 总体结构

```
用户态 ProxyClaw                               内核 proxyclaw.sys（KMDF，非 PnP）
┌────────────────────────┐   IOCTL             ┌─────────────────────────────────┐
│ rule_engine / 进程树    │ ── SET_TARGETS ───▶ │ 目标进程表（AVL，PID+创建时间）   │
│ (pid,psn) 判定          │ ── SET_POLICY ────▶ │ 目的地址直连表（CIDR/端口）       │
│                        │ ◀─ PEND_QUERY ───── │ 待定连接队列（FwpsPendClassify）  │
│ relay（acceptor v4/v6） │                     │ CONNECT_REDIRECT_V4/V6 callout  │
│  accept → QUERY_CONTEXT │ ◀── 重定向后的 TCP ── │  → 127.0.0.1/::1 或本机地址:port │
│  出站 → SIO_SET_RECORDS │                     │ 进程创建通知（子进程继承）         │
└────────────────────────┘                     └─────────────────────────────────┘
```

代码组织：新增 `driver/`（WDK 工程）和 `src/capture/` 抽象层：`capture_backend` 接口，下面有 `windivert_backend`（现有代码迁入）和 `wfp_backend`。relay、规则、DNS、UI 不变。

## 4. 进程判定

**分工：规则匹配仍在用户态，驱动只认 PID 集合。** 理由：规则支持进程名通配、路径、命令行、手动劫持和排除，搬进内核风险大；而用户态已经有完整的 (pid, psn) 进程树（#13）。

- `IOCTL_SET_TARGETS`：用户态全量或增量下发 `{pid, create_time, group_id, policy_id, inherit}`。驱动按 PID 建 AVL 表，用创建时间防 PID 复用（内核用 `PsGetProcessCreateTimeQuadPart`；psn 在内核里没有公开 API，所以不用 psn 做键）。
- **子进程继承在内核完成** [参考 Mullvad]：驱动注册 `PsSetCreateProcessNotifyRoutineEx`。父进程在表里且 `inherit=1`，子进程**在创建回调里同步**加进表，然后通知用户态。这样 `git`、`curl` 这类刚启动就连网的子进程不再依赖 ETW 的 1–2 s 延迟。沿父链查找时要防环（Mullvad PR #56 的教训）。
- **待定进程**：新进程不在表里、但可能命中名称类规则（父进程不在表里）时，驱动不知道它该不该代理。做法 [参考 Mullvad，pend 机制为官方 API]：
  1. 创建回调把它标成 `undecided`，经 inverted-call IOCTL（`PEND_QUERY`）通知用户态；
  2. 它的首个 connect 在 `CONNECT_REDIRECT` 层 `FwpsPendClassify0`；
  3. 用户态判定后 `IOCTL_RESOLVE {pid, verdict}`，驱动 `FwpsCompleteClassify0(handle, 0, NULL)` 触发重新授权，再按结果处理；
  4. **20 ms 超时放行**（与现在 `watchdog_ms` 一致），用内核定时器（`KeSetTimer` + DPC）驱动，不像 Mullvad 那样只在进程事件时顺带扫描。
  只对「存在名称类规则」的情况启用；没有规则可能命中时，创建回调直接标 `direct`。
- 进程退出：创建通知的退出分支删表项，同时 fail 掉该 PID 所有挂起的分类。

## 5. 重定向（TCP，IPv4/IPv6）

classify 顺序严格按官方流程 [官方，Using Bind or Connect Redirection]，并加上 Windscribe 踩过的坑 [参考]：

1. 没有 `FWPS_RIGHT_ACTION_WRITE` → 直接返回，不改 action；
2. 设置了 `FWP_CONDITION_FLAG_IS_REAUTHORIZE`，且 `previousVersion` 显示是自己改的 → 放行。**所有跳过判断都必须放在 acquire 之前**；acquire 成功后必须且只能 Apply 一次，否则可能在 `NETIO!FeApplyModifiedLayerData` 蓝屏 [参考 Windscribe 注释]；
3. 读 `FWPS_METADATA_FIELD_PROCESS_ID`，查表：不在表里 / `direct` → 放行；`undecided` → pend（§4）；
4. `FwpsQueryConnectionRedirectState0`：
   - `REDIRECTED_BY_SELF` / `PREVIOUSLY_REDIRECTED_BY_SELF` → 放行（后者官方禁止再重定向）；
   - `REDIRECTED_BY_OTHER` → 默认**不叠加**，记计数 `redirected_by_other`（§9）；
5. 目的地址直连判定（本地/私网、规则里的 CIDR 排除、端口不匹配）→ 放行。直连判定下放到内核，避免直连流量绕 relay；ProxyBridge 正是因为没下放，才出现「DIRECT 走代理/UDP 丢包」（#229）；
6. `FwpsAcquireClassifyHandle0` → `FwpsAcquireWritableLayerDataPointer0`（注意：这一步会把 action 置成 BLOCK、清掉 WRITE）；
7. 分配 context（`ExAllocatePool2(POOL_FLAG_NON_PAGED)`，内容为 `{orig_dst sockaddr_storage, pid, create_time, group_id, policy_id, decision_ts}`），写入 `localRedirectContext/Size`；Apply 成功后归 WFP 释放 [官方]；
8. 改写 `remoteAddressAndPort`：本地地址为通配时改成环回，否则改成**源 socket 的本地地址**加 relay 端口 [官方示例代码]。**所以 acceptor 必须监听 `0.0.0.0` / `::`**，不能只听 127.0.0.1；
9. `localRedirectTargetPID = ProxyClaw PID`，`localRedirectHandle = g_redirect`（启动时 `FwpsRedirectHandleCreate0` 创建一次）；
10. `actionType = PERMIT`，`rights |= WRITE`（软放行，后面的产品仍可决策）；
11. `FwpsApplyModifiedLayerData0(handle, req, 0)`：内联路径 flags 必须为 0 [官方]，**不要照抄**样例里的 `REAUTHORIZE_IF_MODIFIED_BY_OTHERS`；
12. `FwpsReleaseClassifyHandle0`。

**环回**：被代理进程访问 127.x/::1 时，在**第 3 步之前**直接放行。ProxyBridge 在 acquire 之后才判断、又不 Apply，就会留下 BLOCK（它的 B1 缺陷）。

**relay 侧**：
- accept 后 `SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS`（8 KB 缓冲）和 `..._CONTEXT`；`FWP_E_NOT_FOUND` 视为不是我们重定向的连接，直接关闭；
- 连上游 SOCKS5 的出站 socket **在 bind 之前** `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` [官方，HLK `ConnectionProxying-NoDeadlocks`]。即使上游代理在本机，也能防环、让其他产品看出这是被代理的连接；
- 自身 PID 在驱动里也直接放行，双保险（对应现在的「Never proxy self」）。

拿到 context 之后，现有的 `relay_through_proxy`、`DecisionRecord`、IPv6 egress 回退都能沿用。`PortTracker`、`syn_parker`、`ipv6_flow_table` 在 WFP 后端下不再需要。

## 6. WFP 对象与生命周期

- **动态会话**（`FWPM_SESSION_FLAG_DYNAMIC`），由 ProxyClaw 进程持有 engine 句柄：进程退出，过滤器自动删除；
- 自建 provider 和 sublayer（HLK `FwpmSublayers-UseOwnOrBuiltIn`）。sublayer 权重取中等值 **[待定]**，不抢 `0xFFFF`；
- 过滤器动作为 `FWP_ACTION_CALLOUT_UNKNOWN`，并加 `FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED`：驱动没加载或已注销时按放行处理，否则会被当作 BLOCK [官方]；
- 不用 BOOTTIME / PERSISTENT 过滤器；
- 驱动处理 `IRP_MJ_CLEANUP`：控制句柄一关（含崩溃）就清空目标表、fail 掉所有挂起分类、停止重定向。ProxyBridge 缺了这一步，崩溃后流量会被导向已经不存在的 relay（它的 B5 缺陷）；
- 设备 SDDL 为 `SDDL_DEVOBJ_SYS_ALL_ADM_ALL`，独占打开；所有 IOCTL 缓冲用溢出安全的校验 [参考 Mullvad]；
- **卸载顺序** [官方 + inspect 样例]：置卸载标志（classify 直接放行）→ 关闭会话 → 完成全部挂起分类 → 停定时器、排空 DPC → `FwpsFlowRemoveContext0`（如有）→ 注销 callout（`STATUS_DEVICE_BUSY` 时重试）→ `FwpsRedirectHandleDestroy0` → 删除设备；
- 注册失败路径要逐步回滚（注销已注册的 callout、关 engine）。ProxyBridge 没有回滚，可能留下指向已卸载代码的过滤器（它的 B2 缺陷）；
- 服务启动方式：SCM `SERVICE_KERNEL_DRIVER` + 按需启动，由 ProxyClaw 安装和启停（与现在 WinDivert 的方式一致）。

## 7. UDP

开源参考里**没有一个**在内核里把 UDP 目的地址重定向到本地 SOCKS5 relay 并经过运行验证。官方虽然说 UDP 可以重定向，但限制很多 [官方]：

- 每个新的远端地址/端口组合单独走一次 connect-redirect；
- redirect records 只放在首包的 `WSARecvMsg` 控制消息里，控制消息常量名在文档里有两种写法，以 `ws2ipdef.h` 为准 **[待验证]**；
- 回包源地址能否还原成原目的地址，文档没写 **[待验证]**，这是透明 UDP 的关键。

所以分两步：
1. **第一阶段**：UDP 继续用现有的 WinDivert 路径（`udp_port_tracker`），配置项 `capture.udp_backend = windivert`；
2. **第二阶段**：在 VM 上做 PoC，比较 (a) ALE connect-redirect + `WSARecvMsg` 和 (b) ddproxy 式的 `DATAGRAM_DATA` 克隆、改写、重注入 [官方样例]。选定后再迁。注意 (b) 也是包注入，蓝屏风险的性质与现在类似。

DNS 不受影响：DNS 转发器本身就是用户态的。

## 8. IPv6

- 同一个 callout 注册 V4 和 V6 两层，context 里放 `sockaddr_storage`；
- relay 的 `[::1]` acceptor 已有（#2）；按 §5 第 8 步，还需要再听 `::`；
- `ipv6.mode=block`：WFP 后端在 `ALE_AUTH_CONNECT_V6` 硬阻断，比现在发 RST 更干净；
- `ipv6.mode=proxy`：直接重定向；IPv6 egress 回退（#7）照旧由用户态改判为 block。

## 9. 与 ESET 等其他 WFP 产品共存

- 按官方约定：遇到 `REDIRECTED_BY_OTHER` 或 `previousVersion->localRedirectHandle != NULL`（别家已经把连接导到它的本地代理）时**不再重定向** [官方]。代价是：ESET 如果在 connect-redirect 层做 HTTPS 扫描代理，被代理的应用会走 ESET 的代理出去，而不是我们的 **[待验证 ESET 是否这样做]**；
- 可选的「强制模式」：拦截对方代理发出的出站连接（官方建议的做法），但出站进程变成 ESET 服务，需要靠 redirect records 还原原始应用 **[待验证 records 是否带得出原 app]**。第一阶段不做，只统计 `redirected_by_other` 并在 UI 里提示；
- 用 `previousVersion` 计数做熔断：同一 filterId 改过超过 3 次就放弃 [参考 Windscribe/WFPSampler]；
- 只用软放行，不清 WRITE，不 Veto；
- 上线前在装了 ESET 的 VM 上用 `netsh wfp show state` 看它的 sublayer 权重和 callout 层。这也顺带回答一个问题：去掉包重注入后，0xD1 蓝屏是否消失。

## 10. 签名与分发（成本最大的一项）

- Win10 1607 起，新内核驱动必须由微软在 Partner Center 签名；开通账号需要 **EV 代码签名证书** [官方]（年费几百美元，官方不公布价格，**[待确认]**）；
- **微软 2026-03-23 的文档把 attestation 签名定为「仅用于测试」**：不能经 Windows Update 推给零售用户，Windows Server 2016+ 不加载。官方推荐的生产路径是 **HLK 测试 + WHCP 签名** [官方]。attestation 签名的驱动在 Win10/11 桌面上技术上仍能加载，但有政策风险；
- 驱动必须兼容 HVCI（Win11 新装机默认开启）：只用 NX 池、没有 W+X 节、节按 0x1000 对齐 [官方]；
- 开发期用 test-signing（`bcdedit /set testsigning on`，要关 Secure Boot）。**GitHub 托管 runner 不能重启，也不能开 test-signing**，驱动的 e2e 需要自建 Windows VM runner；
- 许可证：驱动代码自写，MIT。参考 ProxyBridge、tunless、netebpfext（均为 MIT）的片段可以带署名复用；Mullvad 只借鉴思路（若复制则文件须保持 MPL-2.0）；Windscribe、Proton、PIA（GPL）只看不抄。

**结论**：签名是一个「花钱 + 走流程 + 每次重新构建都要重签」的长期成本。没有 EV 证书之前，WFP 后端只能作为开发者选项（test-signing）存在。

## 11. 测试

- 单元测试：classify 决策函数（权限、reauth、redirect state、环回、直连表）抽成纯 C，用现有 zig 和 CTest 在用户态跑；
- Driver Verifier（标准设置 + IRQL 检查 + 池跟踪）+ HLK `WindowsFilteringPlatform_Tests`；
- e2e：现有 `tests/e2e_rule_policy.py` 加一个后端参数，在自建 VM 上跑；新增用例：子进程立即连网（30/30）、ProxyClaw 被 kill 后直连恢复、驱动卸载后连接不受影响、`::`/本机地址绑定的客户端、与 ESET 共存；
- 压测：300 连接突发，对比 WinDivert 后端的决策延迟和 CPU。

## 12. 分阶段计划

| 阶段 | 内容 | 退出条件 |
|---|---|---|
| P0 | `capture_backend` 抽象，现有 WinDivert 代码迁入，行为不变 | CI 全绿 |
| P1 | 驱动骨架：动态会话、TCP v4/v6 重定向、`SET_TARGETS`、`IRP_MJ_CLEANUP`、relay 取 context 并设置 records；test-signing | VM e2e TCP 全过，Verifier 无报错 |
| P2 | 内核子进程继承 + undecided pend + 20 ms 定时器；直连表下放 | 新进程首连 30/30，kill/卸载用例通过 |
| P3 | 共存：BY_OTHER 统计、熔断；ESET VM 验证 | 装 ESET 的 VM 上 24 h 无蓝屏 |
| P4 | UDP PoC（两种方案）并选型 | 回包源地址正确，多目的地址正确 |
| P5 | 签名：EV 证书 + attestation（或 HLK/WHCP），设置里加后端切换，默认仍为 WinDivert | 用户自愿切换，可随时回退 |

## 13. 开放问题

1. 是否愿意承担 EV 证书和 Partner Center 的流程成本？不愿意的话，到 P3 为止只是技术储备。
2. `localRedirectTargetPID` 是否强制要求 accept 方的 PID 一致（关系到将来是否改成服务模式）**[待验证]**。
3. connect 层改写后，绑定具体本地地址的客户端在 IPv6 下的行为 **[待验证]**。
4. 0xD1 蓝屏是否确实由 WinDivert 重注入与 ESET 冲突导致：可以先用 44443 验证包（不重注入直连 SYN）做低成本确认，结果直接影响换方案的紧迫性。
