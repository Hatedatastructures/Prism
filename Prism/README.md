# Prism 源码入口

`Prism/` 是当前唯一生产实现。程序 target 和输出名称为 `Prism`，测试根目录为 `tests/Prism/`。默认配置文件为 `PrismConfiguration.json`。本页只导航源码，不记录随工作树变化的测试计数、二进制 hash 或验收状态。

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
| `CMake/` | Prism target、依赖边与构建辅助；不是运行时模块。 |

## 实际入口

- 进程入口：[`Application/Main/PrismMain.hpp`](Application/Main/PrismMain.hpp)。
- 启动事务：[`Application/Startup/Start.hpp`](Application/Startup/Start.hpp)。
- 配置模型：[`Application/Configuration/PrismConfiguration.hpp`](Application/Configuration/PrismConfiguration.hpp)。
- TCP session：[`Runtime/Session.hpp`](Runtime/Session.hpp)。
- UDP/QUIC ingress：[`Boundary/`](Boundary/) 与对应协议 owner。

## 手册

- [Prism 架构](../docs/ARCHITECTURE.md)。
- [开发入口与模块边界](../docs/prism/README.md)。
- [配置说明](../docs/tutorial/configuration.md)、[构建与测试](../docs/TESTING.md)、[所有权与生命周期](../docs/prism/ownership-and-lifecycle.md)。

本仓库的旧版生产 API 已退役；新增实现和验收说明都以当前 `Prism/`、`tests/Prism/` 与 [项目文档](../docs/index.md) 为准。
