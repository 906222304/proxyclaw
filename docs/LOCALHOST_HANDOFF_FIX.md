# 本机 TCP 回环兼容修复

## 已观察到的问题

2026-11-01 的完整内核转储中，ProxyClaw 线程正在关闭 TCP 端点；
`UniKNetWFPW864` 的 ALE 分类请求释放路径同步注入传输数据，经
`IppLoopbackEnqueue` 进入 `TcpMatchReceive` 并等待 TCP 锁，最终触发 0x133。
小型转储只显示网络栈的一部分，不能据此把全部责任归到 WinDivert 本身。

旧版将应用网卡地址同时用作本机监听连接的源地址和目的地址。这是 Windows
意义上的回环，但不是标准 127.0.0.1 元组。修复将监听端的两个地址均改为
127.0.0.1，监听器也只绑定到 127.0.0.1；回包恢复应用地址、原远端和原网卡。
这是避开已观察路径的应用兼容修复，没有修改或停用第三方网络安全驱动。

## 连接关闭

协程完成时，最后的 FIN 可能仍在 WinDivert 队列里。立即清除端口映射会让
应用永远收不到这个 FIN。现在将映射保留为最长 120 秒的 draining 状态；
新 relay 不再接受该状态，但 FIN、ACK 和重传仍能恢复原元组。新连接的
决策会替换旧映射，旧映射也不会替新 SYN 作决定。固定表的大小没有增加。

## 完整 GUI 包

`proxyclaw.exe` 还需要同目录的 `frontend/dist`。CMake 现在支持
`PROXYCLAW_FRONTEND_DIST`，并把已构建页面复制到可执行文件旁。
`scripts/package_local.py` 生成不涉及发布、推送或打标签的本地完整包，打包前
校验 index.html 引用的资源及运行库。

## 验证方法与边界

- `tests/run_tcp_redirect_tests.py`：真实 WinDivert 解析/校验和，验证地址恢复、
  网卡、关闭尾包、过期映射与端口复用，不打开驱动。
- `tests/run_tcp_handoff_live.py`：管理员下限定端口的并发关闭、重置及 HTTPS。
  运行前必须退出其他 ProxyClaw 实例并卸载其 WinDivert 驱动。
- 短期集成验证不能证明长期不再蓝屏；仍需正常使用观察及检查新转储。

本次前端未修改，离线构建可复用相同代码基线的已有 frontend/dist。
