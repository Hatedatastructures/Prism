# Prism 开发入口

`Prism/` 是当前生产实现，CMake 可执行 target 为 `Prism`；功能测试位于 `tests/Prism/`。生产头文件按真实 owner 拆分，生产 `.cpp` 不重新引入。

## 入口

- 进程入口：`Prism/Application/Main/PrismMain.hpp`
- 启动事务：`Prism/Application/Startup/Start.hpp`
- 配置类型与解析：`Prism/Application/Configuration/`
- 应用装配：`Prism/Application/Assembly/`
- TCP session 调度：`Prism/Runtime/`
- UDP/QUIC ingress：`Prism/Boundary/`
- 协议 wire、认证与会话：`Prism/Protocols/`

## 模块边界

`Protocols/` 拥有协议行为；`Composition/` 拥有配置到类型化 binding 的冷路径装配；`Boundary/` 拥有数据报和 QUIC 入口；`Runtime/` 拥有 worker、listener、session 调度；`Application/` 拥有进程服务与启动停机。

TCP acceptor 当前仍位于 Runtime。目标职责和当前实现差异应如实记录，不能通过文档或 CMake target 名称掩盖。

## 继续阅读

- [架构与责任边界](../ARCHITECTURE.md)
- [构建与测试](../TESTING.md)
- [所有权与异步生命周期](ownership-and-lifecycle.md)
- [配置](../tutorial/configuration.md)

本项目不维护逐协议专题页。具体 wire 与行为以 `Prism/Protocols/` 源码和对应的 `tests/Prism/Protocols/` 用例为准。
