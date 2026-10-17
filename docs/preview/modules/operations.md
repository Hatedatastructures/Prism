# Operations 模块

## 职责与边界

Operations 提供独立的 HTTP 管理 listener、请求路由、认证/请求边界、查询与命令 DTO，以及可选的构建后静态资源清单。Application 将管理 handler 接回控制 executor；查询结果和命令结果以拥有型值返回。

Operations 不拥有代理数据面、协议 session 或 worker 资源，也不直接代替这些真实 owner 关闭 I/O。它接收命令并将其派发给 Application/对应领域 owner。

## 关键源码

- [Controller.hpp](../../../Preview/Operations/Controller.hpp)、[HttpServer.hpp](../../../Preview/Operations/HttpServer.hpp)、[HttpConnection.hpp](../../../Preview/Operations/HttpConnection.hpp)：管理 listener、HTTP server 与连接生命周期。
- [Router.hpp](../../../Preview/Operations/Router.hpp)、[Models.hpp](../../../Preview/Operations/Models.hpp)、[Routes](../../../Preview/Operations/Routes/)：请求路由及 typed 查询/命令值。
- [Application/Startup/OperationsPhase.hpp](../../../Preview/Application/Startup/OperationsPhase.hpp)、[Application/OperationsStartup.hpp](../../../Preview/Application/OperationsStartup.hpp)：启动 controller、命令 bootstrap 与 executor 转发 handler。
- [Application/OperationsDrain.hpp](../../../Preview/Application/OperationsDrain.hpp)、[Application/OperationsEventProducer.hpp](../../../Preview/Application/OperationsEventProducer.hpp)：命令排空与管理事件记录。
- [Operations/Web/Loader.hpp](../../../Preview/Operations/Web/Loader.hpp)、[Operations/Web/Catalog.hpp](../../../Preview/Operations/Web/Catalog.hpp)：可选静态资源 catalog 的冷加载与只读查询。

## include 与 CMake 依赖

- [Preview/CMakeLists.txt](../../../Preview/CMakeLists.txt) 将 `Operations/` 下的 HTTP、Router、模型和 route 头登记到 `PreviewOperations` INTERFACE target。
- `PreviewOperations` 当前依赖 `PreviewFoundation`、`PreviewStatistics` 与 `OpenSSL::Crypto`；Windows 下额外链接 `ws2_32` 与 `mswsock`。
- Application CMake 将 `PreviewOperations` 作为 `PreviewApplication` 的依赖。`tests/Preview/Operations/CMakeLists.txt` 是管理 API 的模块测试 owner，跨 Application 的真实路径另由 Application tests 登记。

## 当前请求与命令流

1. `Startup/OperationsPhase::Start` 在配置启用管理 endpoint 时建立 bootstrap command credential、typed `RouterHandlers` 和 `Controller::Options`；可选加载 `catalog.json`，并使用配置中的读取和排空期限。
2. `Controller::Start` 在管理专属 `io_context` 上启动 HTTP server，并运行独立管理线程。HTTP 路由把输入解码成 `Query` 或 `Command`。
3. `MakeOperationsHandlers` 捕获 Application 控制 executor 与弱 RuntimeState；管理线程上的查询/命令通过 `co_spawn` 投递到控制 executor，不在管理线程直接读取运行态。
4. 管理命令交给实际业务 owner；统计与事件查询读取 Runtime 提供的拥有型快照值。静态 Web catalog 只由 HTTP 资源查找使用，不把请求路径转成任意文件路径。
5. 配置 reload route 将 `ValidateOnly`/发布模式、`BaseGeneration` 与候选 JSON 解码为 typed 命令，再交给 [Application/OperationsReload.hpp](../../../Preview/Application/OperationsReload.hpp)。它检查当前 generation 和 `HotReload.Enabled`，构造并验证候选 generation；含 restart-required 字段时返回重启要求。ValidateOnly 只验证并回收候选，发布模式则准备运行中 worker 并由 Application 的 publication transaction 发布新 generation。仅修改磁盘配置文件不会自动触发这条命令路径。

## 所有权、错误与关闭

- Controller 拥有 HTTP server、管理 `io_context`、work guard 和管理线程。`Start` 返回真实绑定 endpoint 或错误；启动异常不会伪装成成功。
- HTTP request deadline、最大操作数与 shutdown deadline 由 Options/配置约束。typed route/command 结果携带领域错误；RuntimeState 不可用时 handler 返回 Unavailable。
- `Drain` 关闭管理 listener 准入，并按同一绝对 deadline 等待连接/响应退出；调用 Application 的关闭路径在管理 io 自然返回后 `Join` 线程。Drain 失败保留失败与剩余连接数。
- controller 的 close/drain 管理管理 HTTP owner；它不做代理流的半关闭。代理 stream/datagram/mux 的取消与最终 close 归各协议和 Boundary owner。

## 配置支持、生产接线与运行证据

- **模型与配置支持：** `PreviewConfiguration` 中的 Operations 配置提供是否启用、endpoint/超时和可选 Web 资源目录；`Application::Options` 也允许嵌入式调用者提供资源目录。
- **生产接线：** Application 在 Boundary 启动之后通过 `OperationsPhase` 建立 Controller；handler 明确转发到控制 executor。
- **运行证据边界：** 本页只列源码接线与测试映射，不登记 build、CTest、运行或互操作结果；通过结论只能来自绑定当次源码、配置和 binary hash 的验收报告。本页不声称通过。

## 测试位置

- [tests/Preview/Operations](../../../tests/Preview/Operations/)：HTTP、命令发布、drain 与 Web resources 场景。
- [tests/Preview/Application](../../../tests/Preview/Application/)：Application 与 Operations 联合的请求路径场景，例如该目录 CMake 登记的 Operations 测试。
- 根登记见 [tests/Preview/CMakeLists.txt](../../../tests/Preview/CMakeLists.txt)。
