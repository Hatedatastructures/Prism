# Prism 开发入口

`Include/Prism/` 保存当前生产公共头文件，`Src/Prism/` 保存 `.cpp` 与私有头文件；CMake 可执行 target 为 `Prism`，功能测试位于 `tests/Prism/`。

## 入口

- 进程入口：`Src/Prism/Application/Main/PrismMain.cpp`
- 公开启动声明：`Include/Prism/Application/Definition.hpp` 中的 `Application::Start()`
- 启动实现：`Src/Prism/Application/Startup/Start.cpp`
- 启动回滚事务私有实现：`Src/Prism/Application/Startup/StartupTransaction.hpp`
- 配置类型与解析：`Include/Prism/Application/Configuration/` 与 `Src/Prism/Application/Configuration/`
- 应用装配：`Include/Prism/Application/Assembly/` 与 `Src/Prism/Application/Assembly/`
- TCP session 调度：`Include/Prism/Runtime/` 与 `Src/Prism/Runtime/`
- UDP/QUIC ingress：`Include/Prism/Boundary/` 与 `Src/Prism/Boundary/`
- 协议 wire、认证与会话：`Include/Prism/Protocols/` 与 `Src/Prism/Protocols/`

## 模块边界

`Protocols/` 拥有协议行为；`Composition/` 拥有配置到类型化 binding 的冷路径装配；`Boundary/` 拥有数据报和 QUIC 入口；`Runtime/` 拥有 worker、listener、session 调度；`Application/` 拥有进程服务与启动停机。

TCP acceptor 当前仍位于 Runtime。目标职责和当前实现差异应如实记录，不能通过文档或 CMake target 名称掩盖。

## 继续阅读

- [架构与责任边界](../ARCHITECTURE.md)
- [构建与测试](../TESTING.md)
- [所有权与异步生命周期](ownership-and-lifecycle.md)
- [配置](../tutorial/configuration.md)

本项目不维护逐协议专题页。具体 wire 与行为以 `Include/Prism/Protocols/`、`Src/Prism/Protocols/` 和对应的 `tests/Prism/Protocols/` 用例为准。
