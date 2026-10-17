# Application 模块

## 职责与边界

Application 读取 Preview 配置、构造进程和 worker 服务、准备并绑定 provider、启动 Boundary 与管理端点，最后发布就绪状态。它还拥有启动回滚、信号、generation 发布和进程级停机编排。

Application 不实现协议 wire/auth、协议帧循环或具体 socket/session 的最终关闭细节；关闭请求由 Application 编排，真实协议、传输、listener 与 worker owner 各自报告取消和排空结果。

## 关键源码

- [PreviewMain.hpp](../../../Preview/Application/Main/PreviewMain.hpp)：可执行入口。
- [Application.hpp](../../../Preview/Application/Application.hpp)、[Definition.hpp](../../../Preview/Application/Definition.hpp)、[RuntimeState.hpp](../../../Preview/Application/RuntimeState.hpp)：公开生命周期、启动选项和进程运行状态。
- [Startup/Start.hpp](../../../Preview/Application/Startup/Start.hpp)、[Startup/GenerationPhase.hpp](../../../Preview/Application/Startup/GenerationPhase.hpp)、[Startup/StartupTransaction.hpp](../../../Preview/Application/Startup/StartupTransaction.hpp)：配置 generation、分阶段启动和失败回滚。
- [Assembly/ProviderAssembly.hpp](../../../Preview/Application/Assembly/ProviderAssembly.hpp)、[Assembly/AccountAssembly.hpp](../../../Preview/Application/Assembly/AccountAssembly.hpp)：向 Composition 交付配置化协议和账户服务。
- [Startup/BoundaryPhase.hpp](../../../Preview/Application/Startup/BoundaryPhase.hpp)、[Startup/OperationsPhase.hpp](../../../Preview/Application/Startup/OperationsPhase.hpp)、[Shutdown.hpp](../../../Preview/Application/Shutdown.hpp)：发布入口、启动管理服务和协调停机。
- [PreviewConfiguration.hpp](../../../Preview/Application/Configuration/PreviewConfiguration.hpp)：Preview 自有配置模型；它与旧版配置结构分离。

## include 与 CMake 依赖

- [Preview/Application/CMakeLists.txt](../../../Preview/Application/CMakeLists.txt) 定义 `PreviewApplication` 静态库；`Startup/Start.hpp` 被作为 CXX source 编译。`PrismPreview` 将 [Main/PreviewMain.hpp](../../../Preview/Application/Main/PreviewMain.hpp) 作为 CXX source 编译并链接 `PreviewApplication`。
- `PreviewApplication` 的 CMake 依赖包括 `PreviewFoundation`、`PreviewLifecycle`、`PreviewRuntime`、`PreviewAccount`、`PreviewResource`、`PreviewConfiguration`、`PreviewOperations`、`PreviewComposition` 和 `PreviewBoundary`；其实现还链接 TLS/crypto 与 diagnose backend。
- 配置样例来自 `Preview/Application/Configuration/PreviewConfiguration.json`，CMake 将其复制到可执行文件目录。运行时仍以传给 `Application::Options` 的路径和 secret resolver 为准。

## 当前启动与运行流

1. `Application::Start` 调用 `GenerationPhase::Build` 读取、校验配置并准备 generation 与账户目录。
2. 创建 `RuntimeState` 并绑定账户准入 authority；`StartupTransaction` 接管尚未发布的资源。
3. `StartupRuntime` 依次建立进程服务、准备 protocol providers、准备启用的 datagram 服务、绑定 providers、启动 Boundary，再启动 Operations。
4. 成功后 `PublishPhase` 产生 `Readiness`，事务提交到 `State_`；启动失败返回带分类、配置路径和说明的 `StartupError`，未发布就绪状态。
5. `Run` 驱动应用控制 `io_context`。幂等 `Stop` 提交 shutdown 请求；shutdown coordinator 停止准入、按阶段排空实际 owner、记录首个 typed 失败并回收资源。

## 配置、binding 与执行器

- 配置由 `PreviewConfiguration` 和 Contract 中的 typed `ProtocolConfiguration`/`ProtocolBindingConfiguration` 表示。Generation 准备完成后由 Application Assembly 调用 Composition，不在每个 packet/frame 上按字符串查 provider。
- Application 拥有控制 `io_context` 和 generation publication；worker 使用各自执行上下文。Operations Controller 有独立管理 executor/thread，管理 handler 将状态查询和命令投递回 Application 控制 executor。
- 启动边界通过 `std::expected<Readiness, StartupError>` 返回错误；运行期关闭将 `Preview::Fault::Failure` 汇总为停机结果。`Stop` 请求不等同于资源已排空，最终状态需由 shutdown 的 owner 回执决定。
- Application 的回滚 owner 关闭未发布对象；运行期各 protocol binding、carrier、session、listener 与 worker owner 仍负责其真实取消、半关闭和最终 close。

## 配置支持、生产接线与运行证据

- **模型与配置支持：** [Configuration/PreviewConfiguration.hpp](../../../Preview/Application/Configuration/PreviewConfiguration.hpp) 与 [Contract/Ingress/ProtocolConfiguration.hpp](../../../Preview/Contract/Ingress/ProtocolConfiguration.hpp) 描述 Preview 配置值；模型字段存在不单独证明服务已接线。
- **生产接线：** 当前生产入口为 `PrismPreview` → `Application::Run/Start` → generation、provider、boundary、operations 启动阶段。CMake 的可执行目标与源代码路径可在上述链接中核对。
- **运行证据边界：** 本页只列源码接线与测试映射，不登记 build、CTest、运行或互操作结果；通过结论只能来自绑定当次源码、配置和 binary hash 的验收报告。本页不声称通过。

## 测试位置

- [tests/Preview/Application](../../../tests/Preview/Application/)：启动、Assembly、配置化入口和请求路径场景。
- [tests/Preview/Application/Configuration](../../../tests/Preview/Application/Configuration/)：解析、秘密解析及 generation 准备。
- [tests/Preview/Operations](../../../tests/Preview/Operations/)：Application 与管理端点的交互场景。
- 注册入口为 [tests/Preview/CMakeLists.txt](../../../tests/Preview/CMakeLists.txt)；页面只映射测试源码与 target 位置。
