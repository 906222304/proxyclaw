# 交接文档

更新于 2026-11-25。记录项目当前状态、进行中的工作和接手要点。

## 项目概况

- ProxyClaw：Windows 进程级 SOCKS5 代理。后端 C++23，前端 React 19 + WebView2。
- 默认分支 `main`，最新发布 **v0.16.0**（2026-11-25）。
- 近期已发布版本：
  - **v0.15.0**（2026-11-22）：可选 Hook 注入拦截模式（#16）、DNS 仅 TCP 启动（#10）与后台异步启用（#11）、全路径图标缓存与退避（#12）、进程树 `psn`（#13）。
  - **v0.15.1**（2026-11-23）：修复连接列表重复行 key 重影，移除规则编辑器禁用开关（#17）。
  - **v0.15.2**（2026-11-24）：修复 Hook 模式 `/api/tcp` 展示、移除控制管道无超时 `FlushFileBuffers`、绑定非回环网卡 IP 直连放行、子进程/巡检代次竞态与 `child_failed` 回退、Hook 与 WinDivert 解耦（#18）。
  - **v0.16.0**（2026-11-25）：CI 拆分与 `/W4` + ESLint（#19）、文档与旧注释清理（#20）、规则匹配状态按 `(pid, psn)` 键控与进程树快捷建规（#21）、子进程树例外（#22）、引擎状态面板与配置导入/导出（#23）、可编辑应用预设与 Store 包身份匹配及网络活动一键建规（#24），v0.14 与 v0.15 路线图全部收口。
- 贡献者只能是 906222304，提交邮箱 `58179067+906222304@users.noreply.github.com`。
- 流程：功能在分支上做 → 开 draft PR → CI 全绿 → **用户明确同意后**才合并、打 tag、发布。

## 进行中的 PR

| PR | 分支 | 状态 | 说明 |
|----|------|------|------|
| #15 | `docs/wfp-driver-design` | draft，仅文档 | WFP 驱动设计草案。不代表决定要做；EV 证书和签名成本待定 |

已关闭放弃：PR #14（`feat/tree-a11y`，进程树键盘 / ARIA 收益不大，已从路线图移除）。

## Hook 模式（v0.15.0 起，v0.15.2 修复加固）

### 配置

- `interception.mode`：`windivert`（默认）或 `hook`，**重启后生效**。
- `/api/stats.interception` 返回当前实际在跑的模式、`active` 状态与 hook 计数。前端「设置 → 网络 → 拦截方式」会显示这个值。

### 结构

- `src/hook/hook_protocol.hpp`：命名管道 `\\.\pipe\proxyclaw-hook-v1` 的协议，请求 40 字节，应答 16 字节（含 `connect` / `child` / `child_failed`）。
- `src/hook/hook_pipe_server.hpp`：管道服务端，用 `GetNamedPipeClientProcessId` 确认调用方 PID；写回响应后使用带超时、可被 `stop_event_` 取消的重叠读等待客户端关闭（不调用同步 `FlushFileBuffers`）。
- `src/hook/hook_mode.{hpp,cpp}` + `src/hook/hook_inject_tracker.hpp`：
  - 在 strand 上做判定，复用规则、进程树、网段和端口过滤、IPv6 模式。
  - 每秒巡检一次，按巡检代次（generation）跟踪已注入的 `(pid, psn)`，避免并发清理误删 `decide_child` 刚登记的子进程；导入表注入失败时通过 `child_failed` 清除标记，交由 1 s 巡检回退。
- `src/hook/hook_injector.hpp`：用 `CreateRemoteThread` + `LoadLibraryW` 注入。跳过以下进程：
  - WOW64（32 位）
  - AppContainer 或低完整性
  - 只允许加载微软签名模块的进程
- `src/hook/hook_flow_table.hpp` + `hook_acceptor.hpp`：本地中继（IPv4 和 IPv6 各一个），通过 `relay_through_proxy` 走 SOCKS5。`/api/tcp` 通过 `DecisionLog::find_tcp_v4_proxied` 还原真实目标地址与 `PROXIED` 状态。
- `src/hook_dll/`：产出 `proxyclaw_hook64.dll`。
  - 用 Detours hook 这些调用：`connect`、`WSAConnect`、ConnectEx 函数体（经 `WSAIoctl` 找到后原地 detour，注入前已缓存的指针也会生效）、`getpeername`、`closesocket`、`CreateProcessInternalW`。
  - 显式绑定非回环网卡 IP 的 socket 直接放行直连；ProxyClaw 不在、超时或出错时一律直连（fail-open）。
- Detours 固定在提交 `1dbd4ea2`（MIT），由 `scripts/prepare_release_deps.py` 下载并校验 SHA256。CMake 通过 `PROXYCLAW_DETOURS_DIR` 指定路径，只在 x64 MSVC 下构建。

### 覆盖范围

- 覆盖：TCP（IPv4 与 IPv6）。
- 不覆盖：
  - UDP（直连）
  - 上面列出的会被跳过的进程、显式绑定非回环网卡 IP 的 socket
  - 直接走 syscall 的程序
  - 注入完成前已经建立的连接

### 测试

- 单测：`hook_flow_table_tests`（含 `inject_tracker`）、`hook_pipe_server_tests`、`decision_log_tests`、`connection_rows_tests`。
- 端到端：`tests/e2e_hook_mode.py`，在 CI 的 elevated runner 上跑，11 项全部通过（含 `/api/tcp` 真实目标与 `PROXIED` 校验、非回环绑定 socket 直连、`ipv6.proxy_available` 校验）。

### 风险与待办

- 尚未在装有 ESET 等安全软件的真机上验证，注入可能被拦截或报毒。
- 设计参考了 ProxyLane（MIT），已写入 `THIRD_PARTY_NOTICES.md`，没有复制它的代码。
- 可能的后续：UDP 支持、32 位注入（`proxyclaw_hook32.dll`）、运行中切换模式而不用重启。

## 其他未决事项

- **0xD1 蓝屏**：用户机器上 `NETIO.SYS` 出现 0xD1，栈上有 ESET 的 `epfwwfp.sys`，没有 WinDivert 帧。初步判断是 ESET 与 WinDivert 的 WFP 冲突，Hook 模式不加载驱动，可作为这类机器的绕行方案。
- **WFP 驱动方向**：Draft PR #15 仅为设计草案，尚未立项。
- **ROADMAP 剩余项**：v0.15 全部五项（#1–#5）已完成；下一阶段见 `docs/ROADMAP.md`「之后：先有基准，再谈性能与部署」。
- **已知 CI 抖动**：WebView2 截图步骤偶发 `#root` 超时，处理方法是重跑失败的 `e2e` job。

## 硬性规则

- 不要把 WinDivert 句柄关联到任何 IOCP。WinDivert 2.2.2 的同步调用使用栈上的 OVERLAPPED，这曾导致退出时崩溃（见 PR #4）。
- `/api` 的中间件已经设置了 `no-store`，handler 里不要再写 `Cache-Control`。
- README 中文版和英文版保持同步、保持简短。

## 构建与验证

- 完整构建和所有测试都在 `.github/workflows/release.yml` 里。push / PR 触发构建和测试；推送 `v*` tag 会发布 Release。
- 依赖用 `python scripts/prepare_release_deps.py` 准备。
- 打包用 `scripts/package_local.py`，产物必须包含 `proxyclaw_hook64.dll`。
