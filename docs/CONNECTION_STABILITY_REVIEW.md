# 长连接稳定性检查（2026-10-09）

检查对象：`proxyclaw-v0.10.0-hidpi-preview-windows-x64`。
旧包可执行文件 SHA256：`cbb838c0482671aa879e3c88ce11b2a549d4bed56ec51bf7d6bee78bffcd87b0`。
当时 DNS 代理关闭，代理上游为本机 `127.0.0.1:7890`（`verge-mihomo`）。

## 证据和限制

- 日志中的 UDP 会话总数从 144 增长到 157。旧代码没有调用会话清理，失效会话的接收协程也可能一直保留。
- 旧版 TCP 握手成功日志只覆盖建连，转发错误被吞掉，因此“握手失败为 0”不能证明长连接正常。
- 隔离测试编译旧提交 `6632a40` 的实际源码，复现了 TCP 半关闭截断响应、IPv6 SOCKS5 回复污染数据、UDP 控制连接丢失后接收挂住三个缺陷。
- 绕过 ProxyClaw 的转发，直接访问上游 SOCKS 端口：Windows curl 4 次有 2 次 TLS 失败；Python/OpenSSL 8 次有 1 次 TLS 握手超过 10 秒。其余请求收到公开首页的 HTTP 403，证明当次 TLS/HTTP 可达，不代表登录或应用接口正常。两种客户端的统计不能合并当成上游故障率。
- 这些证据说明转发实现和上游连接都需要关注，尚不能确定哪项造成了用户这次 GPT 卡死。没有清理登录缓存、改变系统 DNS 或替换正在运行的程序。

## 本次修复

1. TCP 解析、连接和 SOCKS5 握手使用 10 秒总期限；拒绝和协议错误立即退出。正确消费 IPv4、IPv6、域名回复，校验版本、保留字段和地址类型。
2. TCP 半关闭保留另一方向的响应。真正的传输错误关闭两侧，唤醒等待；记录端口、方向、连接持续时间、收发字节数和结束原因。
3. TCP 使用 Windows 保活，空闲 60 秒开始探测，探测间隔 10 秒。没有设置应用数据空闲断线期限。保活检测的是相邻 TCP 对端；本机 Mihomo 活着、远端节点不通时，不能代替端到端检测。
4. UDP 建连/握手异步化，同样有 10 秒总期限，不再占用网络线程或长时间持有管理锁。DNS 启动保留同步接口，在独立 IO 上运行这套有期限的异步握手。
5. 每 30 秒清理失效或 120 秒无收发的 UDP 会话。UDP 路由表执行原有过期清理，收到回复也更新活跃时间；下次应用发送时重新建立会话。
6. UDP 控制连接丢失会同时关闭数据套接字；替换旧会话先关闭它。收发错误终止会话，避免错误重试空转。会话操作和关闭使用同一 strand，配置使用加锁的独立快照。

已建立的 TLS 流不能在不通知应用的情况下跨节点恢复或重放。上游掉线后仍需应用重连，本次修复不保证 GPT 自动恢复，也不修改 Mihomo 的节点、超时或路由设置。

## 验证

`tests/run_proxy_health_tests.py` 编译生产转发代码，在本机假 SOCKS 服务器上注入故障；不使用 WinDivert 驱动或真实账户。

- 12 项 TCP：半关闭、IPv4/IPv6/域名回复、分段回复、健康空闲、复位、握手停顿、短拒绝回复、错误协议字段。
- 11 项 UDP/保活：控制断开取消接收、重建后回复正常、握手不阻塞单个 IO 工作线程及状态查询、停止取消握手、IPv4/IPv6/通配地址/域名各 96 次建立与回收、路由清理、对象释放、Windows 保活选项。
- 原有 22 项 DNS 真实网络回归：UDP 响应验证、TCP 回退、超时、晚到响应、并发上限、停止时取消。

运行方法（已有本地工具链）：

```powershell
python tests/run_proxy_health_tests.py
python tests/run_proxy_health_tests.py --baseline
python tests/run_dns_network_tests.py --cxx build/test-toolchain/ziglang/zig.exe --asio-include build/network-test-deps/asio-asio-1-30-2/asio/include
```

`--baseline` 默认读取旧提交 `6632a40` 的头文件，专门复现上述三个缺陷；也可用 `--baseline-ref` 指定另一个旧提交。

这是加速的故障/回收回归，尚未做数小时的实际 GPT 会话观测。独立的 stability-preview 包保留当前配置和 DNS 关闭状态；切换前从托盘退出旧代理，不能并行运行。复现时保留发生时间和对应 `proxyclaw.log`，重点检查 `[RELAY] End`、`Transport lost`、`Establish failed`、`TCP control connection lost`，并结合 Mihomo 同时段的日志判断。

后续日志界面可从“设置 → 运行日志 → 查看日志”打开，支持最近记录的搜索、警告/错误筛选、复制和打开文件位置；关闭窗口或隐藏应用会停止读取。日志文件读取使用固定路径，限制末尾 256 KiB 和 1000 行，处理中文路径及日志轮转，读取接口不在信息级别反复记录自身请求。通过 `tests/run_log_tail_tests.py` 和 `tests/run_ui_optimization_tests.py --logs` 检查实际文件服务及构建后的界面行为。
