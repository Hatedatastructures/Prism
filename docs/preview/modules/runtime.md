# Preview Runtime

`Preview/Runtime/` 管理 worker、TCP listener、session admission、协议识别和通用数据面编排。它消费启动阶段已经编译的服务与 typed provider，不拥有具体协议 wire/auth 实现。

## 当前职责与 TCP 源码归属

[`TcpListener`](../../../Preview/Runtime/Listener.hpp) 目前直接持有 TCP acceptor、接入控制、连接 admission 和 listener drain；[`WorkerGroup`](../../../Preview/Runtime/WorkerGroup.hpp)、[`Worker`](../../../Preview/Runtime/Worker.hpp) 与 [`Process`](../../../Preview/Runtime/Process.hpp) 管理 worker 调度和进程关系。该 acceptor 实际登记在 `PreviewRuntime` target。

这与仓库模块所有权表中“Boundary 拥有 TCP socket”的目标分工存在源码/target 落差。本文记录当前实现，不把 socket 描述成已迁入 Boundary。UDP/QUIC 包入口当前位于 [`Preview Boundary`](boundary.md)。Runtime 不负责 QUIC CID、UDP socket、具体协议认证或 frame 状态机。

## 当前调用与数据流

`Application::Startup::BoundaryPhase::Start` 先发布初始 generation service snapshot，构造 `TcpListener`，启动已配置数量的 worker，再开始 TCP accept。listener 对连接进行 admission/worker 选择，向 worker mailbox 投递拥有连接和 admission receipt 的闭包；被拒绝或停机时由接入 owner 收束拒绝路径。

worker tracked task 建立 `Runtime::Session`，session 接管其 generation use lease、registry token 和 deferred-cleanup owner。`Session::Run` 切回入站 transport executor，保存 inbound Activity，并按 session services 运行识别/认证 admission 与 typed protocol factory；随后将已接受的数据面交给 stream relay、datagram session 或 mux root 路径。具体协议行为见[协议目录](../protocols/README.md)。

运行结束时 `Session` 通过 close policy 请求 exactly-once 传输关闭，禁用后续取消，再等待 control delivery、`ActiveTransports::Finalize` 与 child task registry drain；只有这些步骤成功才发布 `IsDrained()`。`ListenerSessionRunner` 观察 session 终态并向 listener drain owner 报告；任务逻辑结束或 listener `Stop()` 本身不等于 session 已排空。

取消是 `SessionControl` 对已拥有任务的请求；它本身不关闭 carrier。通用双向 stream half-close 由 [`StreamRelay`](../../../Preview/Contract/Services/Stream.hpp) 保留，最终的传输关闭和 `Activity()->Drain()` 仍由传输/session owner 完成。Runtime 负责编排等待顺序和传播 typed `Fault::Failure`，不把单个关闭命令被接受当成底层已退休。

## 配置、include 与 CMake

Runtime 使用 `Runtime.WorkerCount`、TCP listener endpoint 和 generation 内的 profile/provider snapshot。协议选择、凭据和 capability 在配置与 Composition 冷路径准备；热路径用已绑定 typed services，不应根据协议名临时装配实现。

[`Preview/CMakeLists.txt`](../../../Preview/CMakeLists.txt) 将 listener/session/worker、session registry、recognition 与 middleware headers 登记在 `PreviewRuntime` `INTERFACE` target。生产 target 直接依赖 `PreviewFoundation`，并通过受检的 `LinkPreviewTargets` 依赖 `PreviewIngressContract`、`PreviewStatistics`、`PreviewNet`、`PreviewTransport`、`PreviewLifecycle`、`PreviewAccount`、`PreviewResource`。正常生产 target 图没有 Runtime→Composition 边；源码和 target 依赖可在同一 CMake 文件核对。

关键源码还包括 [`SessionAdmission.hpp`](../../../Preview/Runtime/SessionAdmission.hpp)、[`ListenerSessionRunner.hpp`](../../../Preview/Runtime/ListenerSessionRunner.hpp)、[`ListenerConnectionDrain.hpp`](../../../Preview/Runtime/ListenerConnectionDrain.hpp)、[`SessionControl.hpp`](../../../Preview/Runtime/SessionControl.hpp)、[`SessionServices.hpp`](../../../Preview/Runtime/SessionServices.hpp) 和 [`ActiveTransports.hpp`](../../../Preview/Runtime/ActiveTransports.hpp)。

Runtime 配置结构可从 [PreviewConfiguration.hpp](../../../Preview/Application/Configuration/PreviewConfiguration.hpp) 核对；listener 和 protocol 字段的允许组合由 Application Configuration validation 决定。

## 测试位置与证据边界

[`tests/Preview/Runtime/CMakeLists.txt`](../../../tests/Preview/Runtime/CMakeLists.txt) 登记 listener admission/lifecycle、session orchestration、session registry、control/delivery 生命周期、worker group、middleware 和 runtime snapshot 等场景；`tests/Preview/Lifecycle/` 覆盖 task registry 与 drain 基础。

这些路径只表示源码和 CMake 测试映射，不登记测试结果，也不声称 TCP 请求或 runtime shutdown 通过；通过结论只能来自与当次源码、配置和 binary hash 绑定的验收报告。启动/请求/停机总路径见[请求路径](../request-paths.md)。
