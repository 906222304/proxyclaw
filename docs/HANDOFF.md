# 交接文档

更新于 2026-11-27。记录项目当前状态、进行中的工作和接手要点。

## 项目概况

- ProxyClaw：Windows 进程级 SOCKS5 代理。后端 C++23，前端 React 19 + WebView2。
- 默认分支 `main`，最新发布 **v0.18.1**（2026-11-27）。
- 近期已发布版本：
  - **v0.15.0**（2026-11-22）：可选 Hook 注入拦截模式（#16）、DNS 仅 TCP 启动（#10）与后台异步启用（#11）、全路径图标缓存与退避（#12）、进程树 `psn`（#13）。
  - **v0.15.1**（2026-11-23）：修复连接列表重复行 key 重影，移除规则编辑器禁用开关（#17）。
  - **v0.15.2**（2026-11-24）：修复 Hook 模式 `/api/tcp` 展示、移除控制管道无超时 `FlushFileBuffers`、绑定非回环网卡 IP 直连放行、子进程/巡检代次竞态与 `child_failed` 回退、Hook 与 WinDivert 解耦（#18）。
  - **v0.16.0**（2026-11-25）：CI 拆分与 `/W4` + ESLint（#19）、文档与旧注释清理（#20）、规则匹配状态按 `(pid, psn)` 键控与进程树快捷建规（#21）、子进程树例外（#22）、引擎状态面板与配置导入/导出（#23）、可编辑应用预设与 Store 包身份匹配及网络活动一键建规（#24），v0.14 与 v0.15 路线图全部收口。
  - **v0.17.0**（2026-11-26）：SOCKS5 RFC 1929 用户名/密码认证（#26）、Hook 注入与跳过原因可观测性（#27）、32 位 WOW64 进程注入与跨架构子进程注入及双架构打包（#28）、Hook 模式 UDP 代理（#29），v0.17 路线图全部收口。
  - **v0.18.0**（2026-11-26）：性能基准与对比工具（#30）、TCP/UDP/IPv6/Hook/DNS 全链路显式资源上限与 `/api/stats.limits`（#31）、共享 `(pid, psn)` 进程信息缓存与单句柄 PSN 校验（#32）、一键脱敏诊断包 ZIP 导出（#33），v0.18 路线图全部收口（`RecvEx`/`SendEx` 批处理经基线验证跳过）。
  - **v0.18.1**（2026-11-27）：修复中文/非 ASCII 安装路径下前端静态文件挂载 404 问题，统一宽字符路径解析、`cpp-httplib` UTF-8 挂载、宽字符 CLI 参数解析与 manifest UTF-8 代码页（#35）。
- 贡献者只能是 906222304，提交邮箱 `58179067+906222304@users.noreply.github.com`。
- 流程：功能在分支上做 → 开 draft PR → CI 全绿 → **用户明确同意后**才合并、打 tag、发布。

## 进行中的 PR

当前无阻塞中的功能 Draft PR。

已关闭放弃：
- PR #14（`feat/tree-a11y`，进程树键盘 / ARIA 收益不大，已从路线图移除）。
- PR #15（`docs/wfp-driver-design`，已确定采用「WinDivert 默认 + Hook 无驱动替代」双路线，自研 WFP 驱动留在暂不计划）。

## Hook 模式（v0.15.0 起，v0.17.0 补齐 UDP / 32 位 / 可观测性）

### 配置

- `interception.mode`：`windivert`（默认）或 `hook`，**重启后生效**。
- `/api/stats.interception` 返回当前实际在跑的模式、`active` 状态与 hook 计数（含 `wow64_enabled`、`live_injected`、`skip_reasons` 与 `udp_*` 计数）。前端「设置 → 网络 → 拦截方式」与「引擎状态」卡片会显示这些值。

### 结构

- `src/hook/hook_protocol.hpp`：命名管道 `\\.\pipe\proxyclaw-hook-v1` 的协议，请求 40 字节，应答 16 字节（含 `connect` / `child` / `child_failed` / `udp_send` / `udp_close`）。
- `src/hook/hook_pipe_server.hpp`：管道服务端，用 `GetNamedPipeClientProcessId` 确认调用方 PID；写回响应后使用带超时、可被 `stop_event_` 取消的重叠读等待客户端关闭（不调用同步 `FlushFileBuffers`）。
- `src/hook/hook_mode.{hpp,cpp}` + `src/hook/hook_inject_tracker.hpp` + `src/hook/hook_status.hpp`：
  - 在 strand 上做判定，复用规则、进程树、网段和端口过滤、IPv6 模式。
  - 每秒巡检一次，按巡检代次（generation）跟踪已注入与被跳过的 `(pid, psn)` 状态（`injected` / `pending` / `wow64` / `restricted` / `signed_only` / `open_failed` / `failed`），并在进程树 `hook_status`、`/api/stats` `skip_reasons` 与 `/api/tcp` / `/api/udp` `hook_skip_*` 中展示；导入表注入失败时通过 `child_failed` 清除标记并立刻唤醒巡检回退。
- `src/hook/hook_injector.hpp` + `src/hook/pe32_export.hpp`：用 `CreateRemoteThread` + `LoadLibraryW` 注入；针对 32 位（WOW64）进程解析目标进程 PE32 `kernel32.dll` 导出表以注入 `proxyclaw_hook32.dll`（缺少 32 位 DLL 时优雅降级为跳过）。跳过以下进程：
  - AppContainer 或低完整性（`restricted`）
  - 只允许加载微软签名模块的进程（`signed_only`）
- `src/hook/hook_flow_table.hpp` + `hook_acceptor.hpp` + `hook_udp_table.hpp` + `hook_udp_relay.hpp`：TCP 本地回环中继（IPv4/IPv6 各一个）通过 `relay_through_proxy` 走 SOCKS5；UDP 为每个 `(family, app_port, dst, dst_port)` 流绑定独立回环中继端口并复用 `Socks5UdpManager`（支持 RFC 1929 认证），不改写 UDP 载荷字节。`/api/tcp` 与 `/api/udp` 均通过 `DecisionLog` 还原真实目标地址与 `PROXIED` 状态。
- `src/hook_dll/`：双架构产出 `proxyclaw_hook64.dll`（x64）与 `proxyclaw_hook32.dll`（Win32），导出 `DetourFinishHelperProcess @1`。
  - 用 Detours hook：`connect`、`WSAConnect`、`sendto`、`WSASendTo`、`WSASendMsg`、`recvfrom`、`WSARecvFrom`、`WSAGetOverlappedResult`、`GetQueuedCompletionStatus(Ex)`、ConnectEx / WSASendMsg / WSARecvMsg 扩展函数体（经 `WSAIoctl` 找到后原地 detour，注入前已缓存的指针也会生效）、`getpeername`、`closesocket`、`CreateProcessInternalW`。
  - 同架构子进程通过 `DetourUpdateProcessWithDll` 注入，跨架构子进程（`x64 <-> WOW64`）通过 `DetourProcessViaHelperW` 交由匹配位数的 `rundll32.exe` 助手完成导入表注入。
  - 显式绑定非回环网卡 IP 的 socket 直接放行直连；ProxyClaw 不在、超时或出错时一律直连（fail-open）。
- Detours 固定在提交 `1dbd4ea2`（MIT），由 `scripts/prepare_release_deps.py` 下载并校验 SHA256。CMake 通过 `PROXYCLAW_DETOURS_DIR` 指定路径，x64 与 Win32（`-DPROXYCLAW_HOOK32_ONLY=ON`）均启用 `/W4` 构建。

### 覆盖范围

- 覆盖：64 位与 32 位（WOW64）进程的 TCP 与 UDP（IPv4 与 IPv6）。
- 不覆盖：
  - AppContainer / 沙盒进程和只允许加载微软签名模块的进程（界面明确标示跳过原因）、显式绑定非回环网卡 IP 的 socket
  - 直接走 syscall 的程序
  - 注入完成前已经建立的连接

### 测试

- 单测：`hook_flow_table_tests`（含 `inject_tracker`、`pe32_export`、`udp_relay_index`）、`hook_pipe_server_tests`、`decision_log_tests`、`connection_rows_tests`、`proxy_probe_tests`、`latency_histogram_tests`、`resource_caps_tests`、`process_info_cache_tests`、`diagnostics_tests`、`components_tests`（含 RFC 1929 认证）。
- 端到端：`tests/e2e_hook_mode.py`（配合 32 位 `hook32_probe.exe`），在 CI 的 elevated runner 上跑，覆盖 64/32 位 TCP、跨架构 `x64 -> WOW64` 子进程注入、无连接多目标 UDP、已连接 UDP、IOCP Proactor UDP、排除端口直连、`/api/tcp` 与 `/api/udp` 真实目标还原及 `hook_status` / `skip_reasons` 校验。

### 风险与待办

- 尚未在装有 ESET 等安全软件的真机上验证，注入可能被拦截或报毒。
- 设计参考了 ProxyLane（MIT），已写入 `THIRD_PARTY_NOTICES.md`，没有复制它的代码。
- 运行中免重启热切换已移入暂不计划。

## 其他未决事项

- **0xD1 蓝屏**：用户机器上 `NETIO.SYS` 出现 0xD1，栈上有 ESET 的 `epfwwfp.sys`，没有 WinDivert 帧。初步判断是 ESET 与 WinDivert 的 WFP 冲突，Hook 模式不加载驱动，作为官方无驱动替代路线已在 v0.17 补齐。
- **ROADMAP 下一阶段**：v0.14–v0.18 路线图已全部收口，见 `docs/ROADMAP.md`（仅余低优先级工程维护项，待真机使用反馈后再规划下一里程碑），继续保持绿色便携包形态。
- **已知 CI 抖动**：WebView2 截图步骤偶发 `process-count` / `#root` 超时，处理方法是重跑失败的 `e2e` job。

## 硬性规则

- 不要把 WinDivert 句柄关联到任何 IOCP。WinDivert 2.2.2 的同步调用使用栈上的 OVERLAPPED，这曾导致退出时崩溃（见 PR #4）。
- `/api` 的中间件已经设置了 `no-store`，handler 里不要再写 `Cache-Control`。
- README 中文版和英文版保持同步、保持简短。

## 构建与验证

- 完整构建和所有测试都在 `.github/workflows/release.yml` 里。push / PR 触发构建和测试；推送 `v*` tag 会发布 Release。
- 依赖用 `python scripts/prepare_release_deps.py` 准备。
- 打包用 `scripts/package_local.py`，产物必须同时包含 `proxyclaw_hook64.dll` 与 `proxyclaw_hook32.dll`。
