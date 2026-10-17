# Prism Preview 架构

本文描述当前 `Preview/` 主线。旧版 `include/prism/`、`src/prism/` 的实现只见[legacy Prism 架构参考](legacy/prism-architecture.md)。本文解释模块责任和调用路径，不是构建、CTest、真实请求、互操作或性能通过报告。

## 模块边界

| 模块 | 拥有的责任 | 不承担的责任 |
| --- | --- | --- |
| `Protocols/<Name>/` | 本协议 wire、认证、连接/stream/datagram 状态机，以及协议级行为 | Application 启停、跨协议 registry、通用 socket/CID 分发 |
| `Composition/` | 启动冷路径的类型化协议/provider 准备、冻结、绑定、能力检查和依赖注入 | 协议帧循环、认证业务、协议连接关闭 |
| `Boundary/` | TCP/UDP socket、packet 分类、QUIC CID 和入口 drain/close | 具体协议凭据与业务状态机 |
| `Runtime/` | worker、listener、session 调度、识别与通用数据面生命周期 | 具体协议 wire/auth 和 Composition 注册细节 |
| `Application/` | 已编译配置、进程级服务、启动/回滚/停机事务 | 协议 admission handler 或协议 stream/datagram lambda |
| `Account/` | typed identity、credential lookup、认证与账户/stream lease | 协议 wire 解析和全局 socket 生命周期 |
| `Lifecycle/` | task 注册、取消和 drain 生命周期契约 | 具体协议认证和应用装配 |
| `Contract/`、`Foundation/` | 中立 typed 契约、错误、标识、内存、executor 和基础设施 | 具体协议分发或应用配置解释 |
| `Net/`、`Transport/` | 通用拨号、relay、DNS、typed I/O 与传输活动契约 | 按协议名称做热路径分派 |
| `Operations/`、`Statistics/` | 管理控制面、运行观察与统计事件 | 协议数据面所有权 |
| `Resource/` | Preview 进程、worker 与运行阶段的共享资源 owner | 代替实际 session/protocol 最终关闭者 |

顶层 owner 页面及其正式入口见[模块索引](preview/modules/README.md)，23 个协议/辅助目录见[协议索引](preview/protocols/README.md)。源码 include 方向和 CMake target 方向都必须符合模块责任；仅更改 target 名称不能形成真实边界。

**当前源码与目标 owner 表存在一个明确落差：**TCP acceptor 的实际实现仍位于 `Preview/Runtime/Listener.hpp` 并属于 `PreviewRuntime` target，虽然模块责任表把 TCP socket 归给 Boundary。文档按目标规则说明职责，同时按当前源码标明具体入口；不把这项差异描述成已经迁移。

## 启动事务

真实进程入口是 `Preview/Application/Main/PreviewMain.hpp`；启动编排由 `Preview/Application/Startup/Start.hpp` 承担。

```text
PreviewMain
  -> Application::Run / Application::Start
     -> Configuration generation、schema/reference/capability/service validation
     -> process services 与协议 resources Prepare
     -> typed provider/catalog Bind 与 TCP profile/resolver 编译
     -> Boundary listener start
     -> Operations start
     -> readiness publish
     -> StartupTransaction commit
```

generation、provider、listener 或 Operations 任一启动阶段失败时，由启动事务回滚尚未提交的资源。就绪发布成功后才提交 runtime owner。完整阶段和错误边界见[启动、请求和关闭路径](preview/request-paths.md)。

## 请求路径与冷/热边界

TCP 从 `Preview/Runtime/Listener.hpp` 接入 Runtime session，经过识别和已编译 profile/provider binding 进入具体协议 owner；UDP packet 由 Boundary listener 分类并交给 typed dispatcher；QUIC 的 admission/CID 入口归 Boundary，协议 engine 与应用 session 归相应协议 owner。更多细节见[请求路径说明](preview/request-paths.md)。

协议名称、配置引用与 capability 在启动冷路径校验和编译。热路径消费冻结的 typed binding 和协议状态，不按字符串重新查找、不走空 factory 表。配置字段存在不等于启动已接线；启动已接线也不等于经过真实运行验收。

## 所有权与验收

Preview 以具体 owner、typed lease、executor、close receipt 和 drain 状态表达生命周期，不直接套用旧版四层资源容器。传输 buffer 借用范围、取消、写半关闭、最终关闭者和真实 drain 见[所有权与生命周期](preview/ownership-and-lifecycle.md)。

源码结构、构建、focused tests、全量 tests、真实请求、互操作和性能必须分层报告。当前版本的验收状态不由本架构页推断；记录格式和运行入口见[构建与分层验收](preview/build-and-validation.md)。
