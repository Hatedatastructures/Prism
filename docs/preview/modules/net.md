# Preview Net 模块

Net 拥有 Preview 的通用网络目标、DNS、TCP 拨号、stream relay 与数据报 egress/relay 实现；上层协议通过 typed target 和服务接口消费它们。

## 职责与边界

模块包含 host/domain/target 值、DNS 配置与 resolver（上游、缓存、合并、UDP/TCP/TLS/DoH 传输实现）、连接竞速拨号、worker dial service、stream egress/relay、UDP relay 与 endpoint retirement。

Net 不拥有业务协议认证或 wire codec，不负责应用启动/配置语法，也不接管 Boundary listener、QUIC CID 分发或协议专属的 session 最终关闭策略。

## 当前源码

- 网络目标与主机模型：[Target.hpp](../../../Preview/Net/Target.hpp)、[Host.hpp](../../../Preview/Net/Host.hpp)、[DomainName.hpp](../../../Preview/Net/DomainName.hpp)。
- DNS API 与实现：[Dns/Config.hpp](../../../Preview/Net/Dns/Config.hpp)、[Dns/Resolver.hpp](../../../Preview/Net/Dns/Resolver.hpp)、[Dns/Upstream.hpp](../../../Preview/Net/Dns/Upstream.hpp)、[Dns/Cache.hpp](../../../Preview/Net/Dns/Cache.hpp)、[Dns/Detail/QueryExecutor.hpp](../../../Preview/Net/Dns/Detail/QueryExecutor.hpp)、[Dns/Detail/Exchange.hpp](../../../Preview/Net/Dns/Detail/Exchange.hpp)、[Dns/Detail/UdpTransport.hpp](../../../Preview/Net/Dns/Detail/UdpTransport.hpp)、[Dns/Detail/TcpTransport.hpp](../../../Preview/Net/Dns/Detail/TcpTransport.hpp)、[Dns/Detail/TlsTransport.hpp](../../../Preview/Net/Dns/Detail/TlsTransport.hpp)。
- 拨号与服务：[Dialer/Dialer.hpp](../../../Preview/Net/Dialer/Dialer.hpp)、[Services/WorkerDialService.hpp](../../../Preview/Net/Services/WorkerDialService.hpp)、[Services/StreamEgress.hpp](../../../Preview/Net/Services/StreamEgress.hpp)、[Services/StreamRelay.hpp](../../../Preview/Net/Services/StreamRelay.hpp)。
- 数据转发与退休：[Relay/Relay.hpp](../../../Preview/Net/Relay/Relay.hpp)、[Relay/Pump.hpp](../../../Preview/Net/Relay/Pump.hpp)、[UdpRelay.hpp](../../../Preview/Net/UdpRelay.hpp)、[Udp/EndpointRetirement.hpp](../../../Preview/Net/Udp/EndpointRetirement.hpp)。

## Include 与 CMake 依赖

Preview/CMakeLists.txt 将纯网络目标值放进 PreviewNetworkModel，其依赖是 Foundation；实现 target PreviewNet 声明 DNS、dialer、relay 和 egress 头，依赖 Transport、Foundation、DatagramContract、NetworkModel、StreamContract，并显式链接 OpenSSL::SSL 以支持 DNS TLS/DoH。Contract 的服务接口与 Net 实现仍分别由各自 target 拥有。

## 当前调用与配置绑定

Application 的 [DnsAssembly.hpp](../../../Preview/Application/Assembly/DnsAssembly.hpp) 将配置模型映射为 Network::Dns::Config。ReloadGenerationPreparation.hpp 为 worker 创建 WorkerDialService；[WorkerSessionServices.hpp](../../../Preview/Application/WorkerSessionServices.hpp) 将按值 Target 请求转交给它。WorkerDialService 先检查 shutdown 状态，再调用 Dialer；Dialer 使用配置的 Resolver 得到候选并建立可靠传输。其注释明确域名不会回退到系统解析器。

流转发侧由 [StreamRelayService](../../../Preview/Net/Services/StreamRelay.hpp) 实现 Contract 的 StreamRelay。它构造 traffic observation 后调用 Net Relay；Relay 在双向 pump 中执行传输和关闭。

## 所有权、错误与关闭

拨号返回 expected<SharedTransmission, Fault::Failure>，失败保留领域分类/native cause。WorkerDialService::Shutdown 在 admission 已关且 Connect 已排空后，等待 Resolver 维护协程真正结束。

StreamRelay 按值接管两端传输、请求元数据和 stream 租约。Relay 完成双向转发后归还租约；写方向完成时按 stream 合同半关闭，取消/失败会关闭两端并等待 Activity drain。最终连接关闭由 Net Relay owner 执行。UDP endpoint 生命周期由关联的 retirement owner 管理。

## 测试位置与证据

当前登记在 [tests/Preview/Net/CMakeLists.txt](../../../tests/Preview/Net/CMakeLists.txt)，包括 DNS config/format/answer/cache/coalescer/rules/upstream/transport/resolver、dial resolution、dialer 与 UDP relay 场景。

本页只列当前源码接线与测试映射，不登记执行结果。任何通过结论均须来自绑定当次源码、配置与 binary hash 的报告。
