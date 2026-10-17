# Preview Contract 模块

本页描述当前 Preview/Contract 的跨模块契约。该目录并非单个 CMake target；生产构建把不同责任拆到多个 interface target。

## 职责与边界

Contract 定义协议识别与请求元数据、接入/认证端口、流/数据报/mux 根数据面、QUIC 与原始数据报接入、退役回执，以及网络服务端口。它提供编译期可见的所有权和关闭语义，让协议 owner、Runtime 与 Boundary 交接值和接口。

Contract 不实现协议 wire、认证算法、监听器、DNS/socket engine，也不解析用户 JSON。配置读写和校验属于 Application/Configuration；冻结后的绑定属于 Composition；通用 socket 接入属于 Boundary。

## 当前源码

- 协议类别与配置值：[Protocol.hpp](../../../Preview/Contract/Ingress/Protocol.hpp)、[ProtocolConfiguration.hpp](../../../Preview/Contract/Ingress/ProtocolConfiguration.hpp)、[RequestMetadata.hpp](../../../Preview/Contract/Ingress/RequestMetadata.hpp)。
- 握手结果与准入：[DataPlane.hpp](../../../Preview/Contract/Ingress/DataPlane.hpp)、[InboundAdmission.hpp](../../../Preview/Contract/Ingress/InboundAdmission.hpp)、[AdmissionRetirement.hpp](../../../Preview/Contract/Ingress/AdmissionRetirement.hpp)。
- 流、datagram、mux 与 QUIC owner：[StreamFactory.hpp](../../../Preview/Contract/Ingress/StreamFactory.hpp)、[DatagramSession.hpp](../../../Preview/Contract/Ingress/DatagramSession.hpp)、[MuxSession.hpp](../../../Preview/Contract/Ingress/MuxSession.hpp)、[QuicConnection.hpp](../../../Preview/Contract/Ingress/QuicConnection.hpp)、[StreamCatalog.hpp](../../../Preview/Contract/Ingress/StreamCatalog.hpp)。
- 服务端口：[Stream.hpp](../../../Preview/Contract/Services/Stream.hpp)、[Datagram.hpp](../../../Preview/Contract/Services/Datagram.hpp)、[Authentication.hpp](../../../Preview/Contract/Services/Authentication.hpp)、[Quic.hpp](../../../Preview/Contract/Services/Quic.hpp)。
- I/O 活动与关闭回执：[CarrierActivity.hpp](../../../Preview/Contract/Io/CarrierActivity.hpp)、[CarrierCloseReceipt.hpp](../../../Preview/Contract/Io/CarrierCloseReceipt.hpp)。

## Include 与 CMake 依赖

生产 target 在 [Preview/CMakeLists.txt](../../../Preview/CMakeLists.txt) 中分层登记：

- PreviewIngressModel 拥有 protocol/configuration/request metadata/provider failure 值，依赖 Foundation 与 Lifecycle。
- PreviewDatagramContract 拥有 raw ingress、datagram service 与 egress 接口，依赖 Foundation。
- PreviewStreamContract 拥有 stream service 接口，依赖 NetworkModel、Foundation、Account、Transport 与 IngressModel。
- PreviewIngressContract 拥有 typed data plane、inbound admission、session/factory、QUIC 和 authentication 接口；依赖 Foundation、Account、Lifecycle、Transport、Net、IngressModel、DatagramContract 与 StreamContract。

这些 target 关系与头文件 include 一起界定依赖；不要把 Preview/Contract 当成可绕过实际 target 的单一模块边。

## 当前调用与数据流

Application 读取并校验配置，Composition 把类型化配置和协议/carrier owner 编译、绑定并冻结。Boundary 或 Runtime 将接入交给协议工厂；工厂准备 InboundAdmission，完成协议握手后产出 ProtocolDataPlane。其 Root 是 StreamDataPlane、DatagramDataPlane 或 MuxRootDataPlane 的 variant，Runtime 消费这个明确形状，而不是靠布尔标志或 RTTI 猜测。stream 的上游拨号与 relay 通过 StreamServices/StreamRelay 端口交给 Net 实现。

## 配置、所有权与错误

Contract 中的 ProtocolConfiguration、carrier configuration 和 typed option 是配置模型，不等同于已装配或已运行的服务。实际解析/验证见 Preview/Application/Configuration，类型化绑定见 Preview/Composition。

ProtocolDataPlane 以 move-only 方式移交握手结果、根数据面、目标、身份与账户租约。流根传输由 relay 持有至双向转发退出并最终关闭；datagram session owner 负责运行、取消、drain 与最终关闭，Transport 句柄只保活控制载体；mux session owner 负责子流取消、根 drain 与关闭。契约把半关闭留给各自的 stream/transport owner。操作失败使用 Fault::Failure/std::expected 保留领域码与 native cause；异常转换只在明确边界处理。

## 测试位置与证据

合同本身的 CMake 入口是 [tests/Preview/Contract/CMakeLists.txt](../../../tests/Preview/Contract/CMakeLists.txt)，当前登记 [Task9ContractTest.cpp](../../../tests/Preview/Contract/Task9ContractTest.cpp)。协议公共地址/读取行为另在 [tests/Preview/Protocols/Common](../../../tests/Preview/Protocols/Common/CMakeLists.txt)。

本页只列当前源码接线与测试映射，不登记执行结果。任何通过结论均须来自绑定当次源码、配置与 binary hash 的报告。
