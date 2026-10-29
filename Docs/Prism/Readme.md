# Prism 开发入口

`Include/Prism/` 保存当前生产公共头文件，`Src/Prism/` 保存 `.cpp` 与私有头文件；CMake 可执行 target 为 `Prism`，功能测试位于 `Test/Prism/`。

如果你刚开始看代码，先确认自己要改的是用户配置、协议行为、网络入口还是生命周期，再按下面的路径定位。公共接口通常在 `Include/Prism/`，具体执行逻辑通常在对应的 `Src/Prism/` 模块；测试应优先找同模块和同场景的用例。

## 入口

- 进程入口：`Src/Prism/Application/Main/PrismMain.cpp`
- 公开启动声明：`Include/Prism/Application/Definition.hpp` 中的 `Application::Start()`
- 启动实现：`Src/Prism/Application/Startup/Start.cpp`
- 启动回滚事务私有实现：`Src/Prism/Application/Startup/Detail/Transaction.hpp`
- 配置类型与解析：`Include/Prism/Application/Configuration/` 与 `Src/Prism/Application/Configuration/`
- 应用装配：`Include/Prism/Application/Assembly/` 与 `Src/Prism/Application/Assembly/`
- TCP session 调度：`Include/Prism/Runtime/` 与 `Src/Prism/Runtime/`
- UDP/QUIC ingress：`Include/Prism/Boundary/` 与 `Src/Prism/Boundary/`
- 协议 wire、认证与会话：`Include/Prism/Protocols/` 与 `Src/Prism/Protocols/`

## 模块边界

`Protocols/` 拥有协议行为；`Composition/` 拥有配置到类型化 binding 的冷路径装配；`Boundary/` 拥有数据报和 QUIC 入口；`Runtime/` 拥有 worker、listener、session 调度；`Application/` 拥有进程服务与启动停机。

TCP acceptor 当前仍位于 Runtime。目标职责和当前实现差异应如实记录，不能通过文档或 CMake target 名称掩盖。

## 按修改目标找代码

| 你要修改的内容 | 建议从哪里开始 | 接着检查 |
| --- | --- | --- |
| JSON 字段、配置加载或配置报错 | `Application/Configuration/` | `Test/Prism/Application/Configuration/` 和配置相关 CMake target |
| 程序启动、失败回滚或正常停机 | `Application/Startup/`、`Application/Shutdown/` | `Application::Start()` 调用路径及对应 Application 测试 |
| SOCKS5、VLESS 等协议报文或认证 | `Protocols/<协议名>/` | 同协议的 codec/session 测试和其对外 binding |
| TCP listener、worker 或 session 调度 | `Runtime/` | Runtime/Application 的请求路径测试 |
| UDP 或 QUIC 入口和准入 | `Boundary/` | 对应 Boundary 和协议集成测试 |
| DNS、上游拨号或通用转发 | `Net/` | Net 契约测试及调用该能力的协议场景 |
| HTTP 管理 API | `Operations/` | Operations router 和 API 行为测试；Web 界面另看 `Web/` |

第一次改一个模块时，同时查看该模块的 `CMakeLists.txt`：target 清单表达模块的编译边界。只找到头文件并不一定代表它已被目标编译或导出。

## 继续阅读

- [架构与责任边界](../Architecture.md)
- [构建与测试](../Testing.md)
- [所有权与异步生命周期](Ownership.md)
- [配置](../Tutorial/Configuration.md)

面向使用者的协议入口、binding 和互操作范围见[协议支持说明](../Tutorial/Protocols.md)。协议 wire 与内部状态机的实现细节仍以 `Include/Prism/Protocols/`、`Src/Prism/Protocols/` 和对应的 `Test/Prism/Protocols/` 用例为准。
