# 交接文档

更新于 2026-11-22。记录项目当前状态、进行中的工作和接手要点。

## 项目概况

- ProxyClaw：Windows 进程级 SOCKS5 代理。后端 C++23，前端 React 19 + WebView2。
- 默认分支 `main`，最新发布 **v0.14.2**（2026-11-18）。
- `main` 上已合入、尚未发布的改动（CHANGELOG「Unreleased」）：
  - DNS 仅 TCP 启动（#10）
  - DNS 异步启用（#11）
  - 图标缓存（#12）
  - 进程树 psn（#13）
- 贡献者只能是 906222304，提交邮箱 `58179067+906222304@users.noreply.github.com`。
- 流程：功能在分支上做 → 开 draft PR → CI 全绿 → **用户明确同意后**才合并、打 tag、发布。

## 进行中的 PR

| PR | 分支 | 状态 | 说明 |
|----|------|------|------|
| #16 | `feat/hook-mode` | draft，CI 绿（run 44923588852） | Hook 注入拦截方式，可在设置中与 WinDivert 切换 |
| #15 | `docs/wfp-driver-design` | draft，仅文档 | WFP 驱动设计草案。不代表决定要做；EV 证书和签名成本待定 |
| #14 | `feat/tree-a11y` | draft | 进程树键盘操作与 ARIA，待用户决定是否合并 |

## Hook 模式（PR #16）

### 配置

- `interception.mode`：`windivert`（默认）或 `hook`，**重启后生效**。
- `/api/stats.interception` 返回当前实际在跑的模式和 hook 计数。前端「设置 → 网络 → 拦截方式」会显示这个值。

### 结构

- `src/hook/hook_protocol.hpp`：命名管道 `\\.\pipe\proxyclaw-hook-v1` 的协议，请求 40 字节，应答 16 字节。
- `src/hook/hook_pipe_server.hpp`：管道服务端，用 `GetNamedPipeClientProcessId` 确认调用方 PID。
- `src/hook/hook_mode.{hpp,cpp}`：
  - 在 strand 上做判定，复用规则、进程树、网段和端口过滤、IPv6 模式。
  - 每秒巡检一次，注入匹配的进程。
- `src/hook/hook_injector.hpp`：用 `CreateRemoteThread` + `LoadLibraryW` 注入。跳过以下进程：
  - WOW64（32 位）
  - AppContainer 或低完整性
  - 只允许加载微软签名模块的进程
- `src/hook/hook_flow_table.hpp` + `hook_acceptor.hpp`：本地中继（IPv4 和 IPv6 各一个），通过 `relay_through_proxy` 走 SOCKS5。
- `src/hook_dll/`：产出 `proxyclaw_hook64.dll`。
  - 用 Detours hook 这些调用：`connect`、`WSAConnect`、`WSAIoctl`（ConnectEx）、`getpeername`、`closesocket`、`CreateProcessInternalW`。
  - ProxyClaw 不在、超时或出错时，连接一律直连（fail-open）。
- Detours 固定在提交 `1dbd4ea2`（MIT），由 `scripts/prepare_release_deps.py` 下载并校验 SHA256。CMake 通过 `PROXYCLAW_DETOURS_DIR` 指定路径，只在 x64 MSVC 下构建。

### 覆盖范围

- 覆盖：TCP。
- 不覆盖：
  - UDP（直连）
  - 上面列出的会被跳过的进程
  - 直接走 syscall 的程序
  - 注入完成前已经建立的连接

### 测试

- 单测：`hook_flow_table_tests`。
- 端到端：`tests/e2e_hook_mode.py`，在 CI 的 elevated runner 上跑，8 项全部通过。验证了：
  - 运行中进程被注入
  - `connect` 和 `ConnectEx` 走代理，`getpeername` 返回原地址
  - 排除的端口直连
  - 子进程第一个连接就走代理
  - 不匹配规则的进程直连
  - stats 计数正确

### 风险与待办

- 尚未在用户的真机上验证，尤其是装了 ESET 等安全软件的机器。注入可能被拦截或报毒。
- 设计参考了 ProxyLane（MIT），已写入 `THIRD_PARTY_NOTICES.md`，没有复制它的代码。
- 可能的后续：UDP 支持、32 位注入（`proxyclaw_hook32.dll`）、运行中切换模式而不用重启。

## 其他未决事项

- **0xD1 蓝屏**：用户机器上 `NETIO.SYS` 出现 0xD1，栈上有 ESET 的 `epfwwfp.sys`，没有 WinDivert 帧。初步判断是 ESET 与 WinDivert 的 WFP 冲突，不是 v0.14.2 的回归。
  - 已建议用户关闭或更新 ESET 防火墙后复测。
  - Hook 模式不加载驱动，可以作为这类机器的绕行方案。
- **WFP 驱动方向**：用户尚未选择。
- **ROADMAP 剩余项**：#11 CI 拆分、W4、ESLint；#12 文档。
- **已知 CI 抖动**：截图步骤 `#root` 超时，处理方法是重跑失败的 job。

## 硬性规则

- 不要把 WinDivert 句柄关联到任何 IOCP。WinDivert 2.2.2 的同步调用使用栈上的 OVERLAPPED，这曾导致退出时崩溃（见 PR #4）。
- `/api` 的中间件已经设置了 `no-store`，handler 里不要再写 `Cache-Control`。
- README 中文版和英文版保持同步、保持简短。

## 构建与验证

- 完整构建和所有测试都在 `.github/workflows/release.yml` 里。push 触发构建和测试；推送 `v*` tag 会发布 Release。
- 依赖用 `python scripts/prepare_release_deps.py` 准备。
- 打包用 `scripts/package_local.py`，产物必须包含 `proxyclaw_hook64.dll`。
