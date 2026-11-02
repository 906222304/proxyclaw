<div align="center">

<img src="assets/proxyclaw.png" width="128" alt="ProxyClaw 图标" />

# ProxyClaw

**代理爪 · Windows 进程级代理与分流**

只让你指定的程序（连同它的整棵子进程树）走 SOCKS5 代理，其余流量保持直连，不用开全局 TUN。

[![Release](https://img.shields.io/github/v/release/906222304/proxyclaw?style=flat-square&logo=github)](https://github.com/906222304/proxyclaw/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/906222304/proxyclaw/total?style=flat-square&logo=windows)](https://github.com/906222304/proxyclaw/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/906222304/proxyclaw/release.yml?branch=main&style=flat-square&label=build)](https://github.com/906222304/proxyclaw/actions/workflows/release.yml)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6?style=flat-square&logo=windows)](#系统要求)
[![License](https://img.shields.io/github/license/906222304/proxyclaw?style=flat-square)](LICENSE)
[![Stars](https://img.shields.io/github/stars/906222304/proxyclaw?style=flat-square&logo=github)](https://github.com/906222304/proxyclaw/stargazers)

**简体中文** · [English](README.en.md)

[下载](https://github.com/906222304/proxyclaw/releases/latest) ·
[快速开始](#快速开始) ·
[常见问题](docs/TROUBLESHOOTING.md) ·
[架构文档](docs/ARCHITECTURE.md) ·
[发布说明](docs/RELEASE.md)

<img src="docs/images/main_ui.png" alt="ProxyClaw 界面预览" width="90%" />

</div>

---

## 目录

- [为什么做 ProxyClaw](#为什么做-proxyclaw)
- [特性](#特性)
- [这个工具适不适合我](#这个工具适不适合我)
- [快速开始](#快速开始)
- [使用指南](#使用指南)
- [技术选择](#技术选择)
- [从源码构建](#从源码构建)
- [测试](#测试)
- [贡献](#贡献)
- [贡献者](#贡献者)
- [致谢](#致谢)
- [License](#license)

## 为什么做 ProxyClaw

很早前用 Antigravity 时发现：后端 Clash 不开 TUN mode 甚至无法刷新模型列表，开了又影响其它应用。我不想为了一个软件全局劫持流量，就做了个工具让特定进程独立走代理，一直演进到现在这个版本。

ProxyClaw 基于 [Clew v0.10.0](https://github.com/ymonster/clew-proxy/tree/v0.10.0) 开发，保留原作者版权及 [MIT 许可证](LICENSE)，在此基础上加入：

- 🇨🇳 完整简体中文界面，适配 Windows 中文字体
- 🪟 默认关闭窗口后保持后台运行（托盘常驻）
- 🛡️ 更稳妥的 DNS 生命周期处理（异常退出后自动恢复系统 DNS）
- 🔁 DNS UDP 超时 / 截断后自动改走 TCP 回退
- 🖥️ PerMonitorV2 高清屏适配与内置日志查看器

## 特性

| | 特性 | 说明 |
| --- | --- | --- |
| 🌳 | **进程树代理** | 规则命中后，所有子进程（包括之后动态派生的）自动跟着走代理。Chromium / Electron 应用派生很多子进程，不必再研究究竟是哪个子进程在联网。 |
| 🔎 | **命令行级匹配** | 同一个 `python.exe` 跑不同脚本时，可以只代理跑 `crawler.py` 的那个进程。 |
| 🔀 | **多 SOCKS5 后端** | 多个代理组，不同规则路由到不同组，支持延迟测试。 |
| 📡 | **TCP + UDP** | UDP 采用 per-app-port SOCKS5 UDP ASSOCIATE（[RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html)）。 |
| 🧭 | **内置 DNS forwarder** | 系统 DNS 指向内置 forwarder，查询经 SOCKS5 到上游；UDP 超时后 TCP 回退；退出或被强杀后自动还原。 |
| ⚡ | **UI 即时响应** | 状态推送改走 WebView2 进程内 IPC，DELETE 请求走 cpp-httplib 快路，hack / unhack 不再卡顿。 |
| 🚀 | **开机静默启动** | 通过任务计划程序以最高权限启动，登录后无 UAC 弹窗，可直接隐藏到托盘。 |
| 📜 | **日志查看器** | 应用内搜索、筛选警告 / 错误、复制、定位日志文件。 |

<details>
<summary><b>命令行匹配示例：修复 ccusage 无法获取模型价格</b></summary>

[ccusage](https://github.com/ryoppippi/ccusage) 运行时会报 `Failed to fetch model pricing from LiteLLM`。Node 24 以上可以用 `NODE_USE_ENV_PROXY=1` 让 HTTP 代理环境变量生效；也可以在 ProxyClaw 的“规则”页面新增规则：

| 字段 | 值 |
| --- | --- |
| 规则名称 | `ccusage` |
| 进程名称 | `node.exe` |
| 命令行匹配 | `ccusage` |

</details>

<details>
<summary><b>UI 卡顿是怎么修好的</b></summary>

v0.8.1 及之前 hack / unhack 等操作偶尔会卡几秒，分别修了两个互不相关的成因：

- **状态推送改走 WebView2 进程内 IPC**：原先用 HTTP/SSE 推送，SSE 长连接会占住 HTTP/1.1 同源 6 连接里的一个槽位，chunked 字节流的解码也常驻 V8 主线程；换成 `PostWebMessageAsJson` 后推送不再走浏览器网络栈。
- **DELETE 请求显式带 `body: ''`**：cpp-httplib 把所有 DELETE 当作“可能有 body”，没看到 `Content-Length` 时会 peek 等满 5 秒 `read_timeout`。前端显式带空 body，让浏览器写出 `Content-Length: 0`，cpp-httplib 走快路立即处理。

</details>

## 这个工具适不适合我

**✅ 适合**

- 想让某个应用走代理，但它不只有 HTTP，还有任意 TCP / UDP，而且你不知道（也不想知道）是哪个子进程在联网。
- 已经有 Clash 这类代理客户端在跑，只想让几个特定应用走它，不想开全局 TUN。
- 在意 MIT 许可证，要集成进内部工具链或商业产品而不沾 AGPL 传染风险。

**❌ 不适合**

- 需要 macOS / Linux → 看 [ProxyBridge](https://github.com/InterceptSuite/ProxyBridge)
- 偏好 NDIS 驱动路线或 Windows 服务化部署 → 看 [ProxiFyre](https://github.com/wiresock/proxifyre)
- 需要订阅、节点协议、测速选节点等完整代理核心 → 看 [sing-box](https://sing-box.sagernet.org/) / [mihomo](https://wiki.metacubex.one/)，ProxyClaw 可以接在它们后面

更多同类项目对比见 [同类项目调研](docs/RELATED_PROJECTS_REVIEW.md)。

## 快速开始

### 系统要求

- Windows 10 版本 2004 或更新 / Windows 11（x64）
- 管理员权限（WinDivert 驱动和系统 DNS 配置都需要）
- WebView2 Runtime（Windows 11 自带；Windows 10 从 [微软](https://developer.microsoft.com/microsoft-edge/webview2/) 下载）
- Release 包已静态链接 MSVC 运行时；自行用默认配置构建时可能需要 [VC++ 运行库](https://aka.ms/vs/17/release/vc_redist.x64.exe)

### 三步上手

1. 从 [Releases](https://github.com/906222304/proxyclaw/releases/latest) 下载 `proxyclaw-vX.Y.Z-windows-x64.zip`（附带 `.sha256` 校验文件），**完整解压**。
2. 双击 `proxyclaw.exe`，同意 UAC 提权。
3. 在“代理”页把 `default` 组指向你的 SOCKS5（如 Clash 的 `127.0.0.1:7890`），再到“规则”页添加规则并打开开关。

> [!TIP]
> 首次运行会把同目录的旧 `clew.json` 导入为 `proxyclaw.json`，原文件保持不变；已有新配置时优先使用新配置，显式指定其他名称的配置文件不会自动导入。日志写入 `proxyclaw.log`。

## 使用指南

### 1. 配置代理后端

“代理”标签页：

- 默认已有一个 `default` 组，修改 host / port 指向你的 SOCKS5。
- 点击刷新图标进行延迟测试。

<img src="docs/images/proxy_group.png" alt="代理组" width="80%" />

### 2. 添加自动规则

“规则”标签页，点击“添加规则”。**新建规则默认停用，需要手动打开开关才会生效。**

| 字段 | 说明 |
| --- | --- |
| 规则名称 | 规则名 |
| 进程名称 | 通配符，例如 `curl*`、`python.exe`；也可以选择具体的 exe 路径 |
| 命令行匹配 | 命令行关键词，多个用空格分隔，大小写不敏感、顺序无关 |
| 代理整个进程树 | 始终开启，子进程跟着走代理 |
| 协议 | 仅 TCP / 仅 UDP / TCP + UDP |
| 代理组 | 走哪个代理组 |

<img src="docs/images/rules.png" alt="规则" width="80%" />

### 3. 进程树与网络活动

- **进程树**：hover 某个进程，右侧出现小闪电图标，点击即可代理当前 PID（含它之后派生的子进程），适合临时调试。手动 hack 固定同时代理 TCP + UDP；只想代理单一协议请用自动规则的“协议”字段。

  <img src="docs/images/process_hover.png" alt="进程树 hover" width="60%" />

- **全部进程**：点击左侧“全部进程”（或不选中任何进程）查看所有进程的实时网络活动。
- **进程信息条**：选中进程后顶部出现详情：
  - 名称左侧的资源管理器图标可定位 exe 所在目录；
  - 路径栏 hover 出现两个复制按钮，左侧复制工作目录，右侧“全部”复制含 image path 的完整命令行；
  - 右侧 `+` 以当前进程为蓝本新建规则。

  <img src="docs/images/network_process_hover_to_copy.png" alt="网络活动进程信息条" width="80%" />

### 4. DNS 代理（默认关闭）

部分应用（Spotify、某些海外服务）对 DNS 解析的地域敏感。打开“设置 → DNS 代理”后：

- 系统 DNS 自动配置为 `127.0.0.2`（内置 forwarder），查询经 SOCKS5 到上游（默认 `8.8.8.8`）。
- 优先使用 SOCKS5 UDP；单条请求 1.5 秒内无有效回复、或回复带 TC 截断标志时，通过同一代理改用 TCP 重试（TCP 阶段共享 3 秒超时，失败返回 `SERVFAIL`）。
- 请求编号重新分配并在回复时还原，避免不同进程的同编号请求串线；迟到的有效 UDP 回复也能结束重试，每条请求只返回一次。
- 关闭或退出时自动还原系统 DNS；进程被强杀，下次启动会检测残留并恢复。

TCP 封装与 SOCKS5 回复读取分别遵循 [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html) 与 [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html)。本地接口仍只监听 UDP，返回报文遵循客户端的 EDNS UDP 容量，超出时返回 TC 截断回复。

### 5. 后台运行与托盘

- 新配置默认开启“关闭窗口后保持后台运行”：关闭主窗口后代理继续工作，点击托盘图标重新打开；右键托盘选择“退出 ProxyClaw”才会结束程序。
- “设置 → 通用设置”中的开关保存后立即生效；已有配置明确设置 `ui.close_to_tray: false` 时仍遵循该设置。
- 托盘暂时不可用时保留任务栏入口；托盘多次注册失败时重新显示窗口，避免后台程序无法操作。

### 6. 开机自动启动（默认关闭）

ProxyClaw 需要管理员权限。若走注册表 `Run` 键，每次登录都会弹 UAC，所以改用任务计划程序 +“以最高权限运行”，登录后静默启动：

- 打开“设置 → 登录 Windows 后自动启动”会注册 `ProxyClawAutoStart` 任务（`schtasks /Create /SC ONLOGON /RL HIGHEST`）。
- 同时勾选“启动时隐藏到托盘”会附加 `--minimized`，只显示托盘图标。
- 关闭开关即删除任务（`schtasks /Delete /F`）；在任务计划程序里手动删除也会被实时检测到。

> [!NOTE]
> 任务记录的是 `proxyclaw.exe` 的绝对路径。移动程序后请重新打开一次此开关。

### 7. 运行日志

“设置 → 运行日志 → 查看日志”可搜索最近记录、筛选警告和错误、复制当前内容或打开日志文件位置。自动刷新只在日志窗口打开且应用可见时运行，最多读取最近 1000 行或 256 KiB，完整日志保存在程序同目录。

遇到问题请先看 [常见问题排查](docs/TROUBLESHOOTING.md)。

## 技术选择

### 第三方库

| 层 | 依赖 | 用途 |
| --- | --- | --- |
| 后端 | [WinDivert](https://github.com/basil00/Divert) | 基于 WFP 的用户态抓包 / 转发，动态链接随包分发（LGPL v3） |
| 后端 | [quill](https://github.com/odygrd/quill) | 异步结构化日志 |
| 后端 | [nlohmann/json](https://github.com/nlohmann/json) | JSON 解析与序列化 |
| 后端 | [cpp-httplib](https://github.com/yhirose/cpp-httplib) | 内置 HTTP 服务端 |
| 后端 | [asio](https://think-async.com/Asio/) | 异步 IO |
| 后端 | [WebView2](https://developer.microsoft.com/microsoft-edge/webview2/) | 嵌入 Edge 渲染前端 |
| 前端 | [Vue 3](https://vuejs.org/) + TypeScript + [Vite](https://vitejs.dev/) | 应用框架与构建 |
| 前端 | [reka-ui](https://reka-ui.com/) + [Tailwind CSS](https://tailwindcss.com/) | 组件（shadcn-vue 风格）与样式 |
| 前端 | [AG Grid Community](https://www.ag-grid.com/) | 网络活动表格 |
| 前端 | [Monaco Editor](https://microsoft.github.io/monaco-editor/) | 设置页 JSON 编辑器（按需加载） |
| 前端 | [Lucide](https://lucide.dev/) | 图标 |

完整许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

<details>
<summary><b>为什么用 WinDivert</b></summary>

- 成熟的 WFP callout driver，Win10/11 稳定支持。
- LGPL v3 允许动态链接 `.dll`，主项目可以保持 MIT。
- 免费：WinDivert 作者已经承担了内核驱动签名费用，发布的就是签好的 `.sys`。

</details>

<details>
<summary><b>为什么现在不用 DLL 注入</b></summary>

1. 注入 `GetAddrInfoW` 效果不错，但很多进程自带异步 DNS resolver 无法覆盖，需要同时注入 `getaddrinfo` / `GetAddrInfoW` / `connect` / `WSAConnect` / `ConnectEx` 等调用，工程量较大。
2. 结合 `PsSetCreateProcessNotifyRoutineEx` 能更准确地发现进程创建与销毁，拦截更精确。
3. 但实际环境要应对安全软件 / EDR、SignPath 类签名服务等，周期长，甚至需要付费。
4. 结论：WinDivert 目前够用；有需求时可单开分支尝试 DLL 注入。

</details>

<details>
<summary><b>为什么不做自研 WFP 内核驱动</b></summary>

技术上更完善（`FWPM_LAYER_ALE_CONNECT_REDIRECT_V4` 直接改写 socket 目标，零包操作），但 Windows 10+ 要求内核驱动由 Microsoft 签名，走 Partner Center 需要 EV 代码签名证书（约 300–600 美元 / 年）和 attestation 流程。SignPath 类开源签名服务只覆盖用户态 Authenticode，不签内核驱动，对个人开源项目成本过高。

</details>

<details>
<summary><b>进程树更新策略（<code>PROXYCLAW_PROJECTION_COALESCE</code>）</b></summary>

默认每个 ETW 进程事件直接刷新前端、即时推送，不做定时合并。即使 1000+ 进程在跑，strand 利用率也不到 1%。只有瞬间 +1000 进程的 ETW 风暴才可能让 strand 短时间被序列化占住，常用的“查看某个进程”操作不受影响。遇到极端负载时可用 `cmake -DPROXYCLAW_PROJECTION_COALESCE=ON` 启用 100ms 合并窗口（代价：树更新最多滞后 100ms）。

</details>

## 从源码构建

### 工具链

- Visual Studio 2022 或 2026（C++23）
- CMake 3.20+
- Python 3.12+（拉取固定版本依赖）
- Node.js 20+

### 步骤

```powershell
# 拉取并校验固定版本依赖（与 CI 一致：quill、nlohmann/json、cpp-httplib、asio、WinDivert、WebView2 SDK）
python scripts/prepare_release_deps.py

# 配置（VS 2026 用 windows-vs2026）
cmake --preset windows

# 前端
cd frontend
npm ci
npm test
npm run build
cd ..

# 后端（约 30 个编译单元，已开启 /MP 并行编译）与单元测试
cmake --build --preset windows
ctest --preset windows

# 运行
./build/Release/proxyclaw.exe
```

一键验证（前端测试与构建、后端构建、ctest、分层检查、e2e）：`python scripts/verify.py`，不在管理员终端时加 `--no-e2e`。

想复用 CI 的固定依赖、本机打出与 Release 一致的完整包，见 [自动构建和发布说明](docs/RELEASE.md)。推送 `v*` 标签会自动构建 Windows x64 完整包并发布 Release；`main` 和 PR 构建只上传测试产物。

<details>
<summary><b>clangd / LSP 配置（可选）</b></summary>

仓库带有 `.clangd` 和 `windows-clangd` preset，只编译运行 release 时用不到。

CMake 的 Visual Studio 生成器不输出 `compile_commands.json`，clangd 找不到依赖 / WebView2 / asio 头文件。需要 clangd 跳转 / 补全时（本机需有 Ninja）：

```bash
cmake --preset windows-clangd
```

会在 `build-clangd/`（已 gitignore）生成 `compile_commands.json`。依赖版本变化、新增源文件或 include 目录后重跑一次。

</details>

## 测试

`ctest --preset windows` 会运行全部原生单元测试（管理 API 鉴权、DNS 报文与生命周期、配置与中文路径、日志读取、进程树推送、TCP 重定向），CI 每次提交都会跑。下面列出各测试的背景和单独运行方式，它们都不需要启动代理，也不会修改系统 DNS。优化背景见 [项目优化检查](docs/OPTIMIZATION_REVIEW.md)。

<details>
<summary><b>界面加载与后台刷新</b></summary>

设置页高级 JSON 编辑器按需加载；周期刷新等待上次请求结束，隐藏或切换进程时取消旧请求，窗口恢复后主动同步进程树。

```powershell
cd frontend; npm test; cd ..
python tests/run_projection_tests.py --cxx path/to/zig.exe --asio-include path/to/asio/include
```

</details>

<details>
<summary><b>高清屏窗口</b></summary>

窗口使用 PerMonitorV2 DPI 适配，WebView2 跟随屏幕与系统文字缩放；切换屏幕时调整窗口、最小尺寸及图标，已保存的窗口位置保持物理像素格式兼容。进程图标提取为 64×64 PNG 缓存。

测试只创建短暂隐藏的窗口，验证 DPI 声明、工作区、最小尺寸、100%/125%/150%/200% 缩放事件与图标加载（缩放事件为模拟消息，多屏实际拖动仍需人工验证）。

```powershell
python tests/run_window_dpi_tests.py --cxx path/to/zig.exe
```

</details>

<details>
<summary><b>中文路径、后台默认值与旧配置导入</b></summary>

只操作 `build` 内的测试文件。文件选择器和 Explorer 调用由替代接口模拟，不会打开真实窗口。

```powershell
python tests/run_ui_config_tests.py --cxx cl --json-include C:/vcpkg/installed/x64-windows/include
# Zig 示例（指定包含 nlohmann/json.hpp 的目录）
python tests/run_ui_config_tests.py --cxx path/to/zig.exe --json-include build/test-deps

# 单独编译 tests/test_ui_config_and_paths.cpp
zig c++ -std=c++23 -Isrc -Ibuild/test-deps tests/test_ui_config_and_paths.cpp src/common/api_exception.cpp -lshell32 -lws2_32 -o build/test_ui_config_and_paths.exe
./build/test_ui_config_and_paths.exe
```

</details>

<details>
<summary><b>DNS 生命周期与报文解析</b></summary>

直接编译 DNS 管理器，用替代的网络和 Windows 接口模拟启动、重启、备份及恢复失败，并检查 DNS 报文、压缩指针与 EDNS 大小解析。不需要管理员权限、WinDivert 驱动或 vcpkg。

```powershell
python tests/run_dns_tests.py --cxx cl          # VS 开发者终端
python tests/run_dns_tests.py --cxx clang++
python tests/run_dns_tests.py --cxx path/to/zig.exe
```

</details>

<details>
<summary><b>DNS 真实网络</b></summary>

编译生产 DNS 转发器与 SOCKS5 UDP 会话，以本机模拟代理验证 UDP 超时、TCP 分段读取、各类 SOCKS5 回复、失败与超时、并发编号冲突、迟到回复及停止清理。仅使用回环地址。

```powershell
python tests/run_dns_network_tests.py --cxx cl --asio-include path/to/asio/include
python tests/run_dns_network_tests.py --cxx path/to/zig.exe --asio-include path/to/asio/include
```

</details>

## 贡献

欢迎 Issue 和 PR！

- 提交问题前请先查看 [常见问题排查](docs/TROUBLESHOOTING.md)，并附上 `proxyclaw.log` 的相关片段。
- 项目结构、架构与 API schema 见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。
- 后续优化方向见 [同类项目调研与优化方向](docs/RELATED_PROJECTS_REVIEW.md)。

## 贡献者

感谢每一位为 ProxyClaw 贡献代码、文档和反馈的人！

<a href="https://github.com/906222304/proxyclaw/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=906222304/proxyclaw" alt="Contributors" />
</a>

## 致谢

- [Clew](https://github.com/ymonster/clew-proxy) by [@ymonster](https://github.com/ymonster)：ProxyClaw 的直接上游，进程树代理、SYN parking 等核心能力来自这里。
- [WinDivert](https://github.com/basil00/Divert)：让用户态进程级转发成为可能。
- 以及 [技术选择](#技术选择) 中列出的所有开源项目。

## Star History

<a href="https://star-history.com/#906222304/proxyclaw&Date">
  <img src="https://api.star-history.com/svg?repos=906222304/proxyclaw&type=Date" alt="Star History Chart" width="600" />
</a>

## License

- ProxyClaw：[MIT](LICENSE)
- 动态链接的 [WinDivert](https://github.com/basil00/Divert)：LGPL v3（原许可证保留于 `WinDivert-2.2.2-A/LICENSE`）
- 其它第三方依赖许可：见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
