# Preview 源码入口

`Preview/` 是当前 Preview 生产实现。程序 target 为 `PrismPreview`，测试根目录为 `tests/Preview/`。本页只导航源码，不记录随工作树变化的测试计数、二进制 hash 或验收状态。

## 生产 owner

| 目录 | 说明 |
| --- | --- |
| `Account/` | 身份、凭据和 lease。 |
| `Application/` | 配置、进程级服务、启动事务与停机。 |
| `Boundary/` | TCP/UDP/QUIC ingress 和 socket 生命周期。 |
| `Composition/` | 配置到 typed provider/protocol binding 的冷路径装配。 |
| `Contract/` | 跨模块 typed 请求、服务与数据面契约。 |
| `Foundation/` | 错误、标识、内存、executor 和诊断基础设施。 |
| `Lifecycle/` | task、取消、drain 与生命周期交接。 |
| `Net/` | DNS、dial、egress 和 relay 服务。 |
| `Operations/` | 管理控制面与命令/事件 owner。 |
| `Protocols/` | 每个协议的 wire、auth、session 与关闭行为。 |
| `Resource/` | 进程、worker 与运行阶段共享资源。 |
| `Runtime/` | worker、listener、session 调度和通用数据面。 |
| `Statistics/` | 运行统计与观察数据。 |
| `Transport/` | typed I/O 前门、传输装饰和 activity drain。 |
| `CMake/` | Preview target、依赖边与构建辅助；不是运行时模块。 |

## 实际入口

- 进程入口：[`Application/Main/PreviewMain.hpp`](Application/Main/PreviewMain.hpp)。
- 启动事务：[`Application/Startup/Start.hpp`](Application/Startup/Start.hpp)。
- 配置模型：[`Application/Configuration/PreviewConfiguration.hpp`](Application/Configuration/PreviewConfiguration.hpp)。
- TCP session：[`Runtime/Session.hpp`](Runtime/Session.hpp)。
- UDP/QUIC ingress：[`Boundary/`](Boundary/) 与对应协议 owner。

## 手册

- [Preview 架构](../docs/ARCHITECTURE.md)。
- [模块索引](../docs/preview/modules/README.md)与[协议目录](../docs/preview/protocols/README.md)。
- [请求路径](../docs/preview/request-paths.md)、[配置与装配](../docs/preview/configuration.md)、[所有权与生命周期](../docs/preview/ownership-and-lifecycle.md)。
- [构建与分层验收](../docs/preview/build-and-validation.md)。

旧版 `include/prism/`、`src/prism/` 和历史证据按各自版本阅读；它们不作为当前 Preview API 或验收结果。
