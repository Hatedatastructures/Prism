# Preview 顶层模块索引

本索引覆盖 `Preview/` 中 13 个非构建 owner。`Preview/CMake/` 是构建资料，不属于运行时模块；协议叶目录单列于[协议索引](../protocols/README.md)。

| 模块 | 责任摘要 | 说明 |
| --- | --- | --- |
| Account | 账户身份、凭据索引、认证与账户/stream lease | [Account](account.md) |
| Application | 配置读取、进程服务、启动事务、回滚与停机 | [Application](application.md) |
| Boundary | TCP/UDP/QUIC 入口、包分类、CID 分发与入口 drain | [Boundary](boundary.md) |
| Composition | 启动冷路径的协议/provider 准备、冻结、绑定与能力校验 | [Composition](composition.md) |
| Contract | 跨 owner 的 typed 请求、服务和生命周期契约 | [Contract](contract.md) |
| Foundation | 中立错误、标识、内存、executor、诊断与基础设施 | [Foundation](foundation.md) |
| Lifecycle | task registry、取消、drain barrier 和生命周期交接 | [Lifecycle](lifecycle.md) |
| Net | 拨号、DNS、数据报 egress、relay 等通用网络服务 | [Net](net.md) |
| Operations | 管理 API、命令、事件、运行状态和管理资源 | [Operations](operations.md) |
| Resource | 进程/worker/session 共享资源的具体 Preview owner | [Resource](resource.md) |
| Runtime | worker、TCP listener、session 调度、识别和数据面生命周期 | [Runtime](runtime.md) |
| Statistics | 流量与运行指标的观察、聚合和发布 | [Statistics](statistics.md) |
| Transport | typed I/O 前门、传输装饰层、操作预约和 activity drain | [Transport](transport.md) |

页面只描述当前源码能证明的责任、调用路径、依赖和测试映射。它们不把测试存在、配置可表达或模块名称出现表述成运行验收通过。

当前 TCP acceptor 的实现仍在 `Runtime/Listener.hpp` 和 `PreviewRuntime` target，虽模块目标将 TCP socket 归于 Boundary；详见 [Boundary](boundary.md) 与 [Runtime](runtime.md)。模块责任和当前源码归属分别说明，不把预期边界说成已完成迁移。

Foundation 中有独立维护指南的 Diagnose 子模块见 [Foundation / Diagnose](foundation-diagnose.md)。`Preview/CMake/` 的 CMake 与构建登记由[构建与分层验收](../build-and-validation.md)说明。
