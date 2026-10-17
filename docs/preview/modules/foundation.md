# Preview Foundation 模块

Foundation 是 Preview 的值类型与底层设施层。稳定的错误、内存、身份、executor、generation 和通用文本/密码工具由这里提供。

## 职责与边界

该模块拥有错误值与分类、Expected/Status 基础类型、异常基类、标识符、内存池和拥有型字节、executor/关闭存储原语、generation lifetime，以及无协议语义的文本、HTTP framing、密码学、限速和 traffic observation 工具。

Foundation 不拥有具体协议状态机、配置解析、监听与 DNS 拨号、Runtime worker/session 调度，也不决定何时关闭上层协议连接。取消域的实际树与通知由 Lifecycle 管理；Foundation 只提供部分值类型和执行器基础设施。

## 当前源码

- 聚合入口与字节/解析工具：[Foundation.hpp](../../../Preview/Foundation/Foundation.hpp)、[ByteSpan.hpp](../../../Preview/Foundation/ByteSpan.hpp)、[FlatBuffer.hpp](../../../Preview/Foundation/FlatBuffer.hpp)、[Parser.hpp](../../../Preview/Foundation/Parser.hpp)。
- 业务失败与注册/值错误：[Fault/Code.hpp](../../../Preview/Foundation/Fault/Code.hpp)、[Fault/Failure.hpp](../../../Preview/Foundation/Fault/Failure.hpp)、[Fault/FailureState.hpp](../../../Preview/Foundation/Fault/FailureState.hpp)、[Error/Expected.hpp](../../../Preview/Foundation/Error/Expected.hpp)、[Exception/Deviant.hpp](../../../Preview/Foundation/Exception/Deviant.hpp)。
- ID、generation、executor 与内存：[Identifier/Id.hpp](../../../Preview/Foundation/Identifier/Id.hpp)、[Generation/Lifetime.hpp](../../../Preview/Foundation/Generation/Lifetime.hpp)、[Executor/ExecutorReclaimer.hpp](../../../Preview/Foundation/Executor/ExecutorReclaimer.hpp)、[Executor/ClosingStorage.hpp](../../../Preview/Foundation/Executor/ClosingStorage.hpp)、[Memory/Container.hpp](../../../Preview/Foundation/Memory/Container.hpp)、[Memory/BytePool.hpp](../../../Preview/Foundation/Memory/BytePool.hpp)、[Memory/OwnedBytes.hpp](../../../Preview/Foundation/Memory/OwnedBytes.hpp)。
- 通用能力：[Utility/Crypto](../../../Preview/Foundation/Utility/Crypto)、[Utility/Text](../../../Preview/Foundation/Utility/Text)、[Utility/Http](../../../Preview/Foundation/Utility/Http)、[Utility/Rate/TokenBucket.hpp](../../../Preview/Foundation/Utility/Rate/TokenBucket.hpp)、[Utility/TrafficSink.hpp](../../../Preview/Foundation/Utility/TrafficSink.hpp)。
- Diagnose 的 facade/context 也列入 Foundation；其后台实现和应用 owner 见[专页](foundation-diagnose.md)。

## Include 与 CMake 依赖

Preview/CMakeLists.txt 中的 PreviewFoundation 是 INTERFACE target，声明上述生产头；其外部依赖为 OpenSSL::Crypto、Blake3C 与 BoostSystemHeaderOnly。Account、Lifecycle、Transport、Net、协议、Application 等 target 通过明确 target edge 使用它。路径和依赖以当前 CMake 登记为准，不以旧版 include/prism 镜像关系推断。

Public 头的 include 方向应保持在通用基础能力；协议 wire、Application 和 Composition 实现不属于 Foundation 的依赖。PreviewDiagnoseBackend 是单独的生产 target，依赖 PreviewFoundation；它不等同于 Foundation 的 public Diagnose facade。

## 错误、所有权与执行语义

Fault::Failure 是可复制的失败值，保存 Fault::Code 与原生 std::error_code；它不持有 I/O，也不触发取消、半关闭或最终关闭。运行时 I/O/协议失败通过 typed 结果传播；Exception::Deviant 及 Network/Protocol/Security 子类适用于需要异常边界的路径，不能据此替代热路径结果。

Memory 类型封装 PMR/byte-pool 等存储。借用视图不能跨越其 owner 的生命周期；generation pin/use lease 仅表达代际存活和使用预约，不替代具体资源关闭回执。executor/reclaimer 与 closing storage 是供实际 owner 装配的工具，不会自行接管协议资源。

## 配置、绑定与测试

Foundation 不提供用户配置项。Application/Configuration 和 Composition 可将解析后的值转为这些底层 ID、错误、内存与 executor 类型。

测试源码归属见 [tests/Preview/Foundation](../../../tests/Preview/Foundation/CMakeLists.txt)、[Fault](../../../tests/Preview/Foundation/Fault/CMakeLists.txt)、[Memory](../../../tests/Preview/Foundation/Memory/CMakeLists.txt)、[Utility/Crypto](../../../tests/Preview/Foundation/Utility/Crypto/CMakeLists.txt)、[Utility/Rate](../../../tests/Preview/Foundation/Utility/Rate/CMakeLists.txt) 与 [Utility/Diagnose](../../../tests/Preview/Foundation/Utility/Diagnose/CMakeLists.txt)。

本页只列当前源码接线与测试映射，不登记执行结果。任何通过结论均须来自绑定当次源码、配置与 binary hash 的报告。
