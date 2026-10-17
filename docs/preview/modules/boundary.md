# Preview Boundary

Boundary 是 UDP/QUIC 数据报入口、分类、CID 分发和入口关闭边界。它接收网络包并把包交给当代已编译的 typed ingress；协议凭据、wire 状态机和连接会话仍归各自协议 owner。

## 责任与当前实现边界

- [`DatagramListener`](../../../Preview/Boundary/Datagram/DatagramListener.hpp) 持有 UDP socket、接收缓冲、peer endpoint 和 packet pump。它把收到的字节复制进 `BoundaryPacket`，交给 [`DatagramClassifier`](../../../Preview/Boundary/Datagram/DatagramClassifier.hpp) 分类，再调用入口 handler。
- [`BoundaryDispatcher`](../../../Preview/Boundary/Contract/BoundaryDispatcher.hpp) 使用每包的 `DatagramIngressSelection`，校验 generation/use state，分发已有 raw association、QUIC admission、QUIC gateway 和普通 UDP fallback。
- [`QuicConnectionRegistry`](../../../Preview/Boundary/Quic/QuicConnectionRegistry.hpp) 以 listener executor 串行管理 CID、peer 与协议连接 lease；[`QuicConnectionRegistryCloseOwner`](../../../Preview/Boundary/Quic/QuicConnectionRegistryCloseOwner.hpp) 持有请求关闭时尚未退休的连接 owner。
- [`QuicPacketGateway`](../../../Preview/Boundary/Quic/QuicPacketGateway.hpp) 维护入口 readiness、连接 admission budget 和包统计。生产接线中的 CID/peer 连接表由 `QuicConnectionRegistry` 管理；两者职责不可合并描述。
- Boundary 不实现 Hysteria2、TUIC 或其它代理协议的凭据校验、帧解释和 TCP/UDP 转发业务。相应协议页见[协议目录](../protocols/README.md)。

**当前 TCP 入口的源码归属与模块目标不一致：**真实 TCP acceptor 位于 [`Runtime/Listener.hpp`](../../../Preview/Runtime/Listener.hpp)，并登记在 `PreviewRuntime` target；当前 `PreviewBoundary` target 包含 UDP/QUIC 入口头。仓库模块责任表把 TCP socket 列为 Boundary 责任，但本页按当前实际源码记录，不能把 TCP acceptor 说成已经迁入 Boundary。

## 当前调用与数据流

启动时 [`Startup/QuicServices.hpp`](../../../Preview/Application/Startup/QuicServices.hpp) 在已有 UDP listener 时创建进程级 CID registry；[`Startup/DatagramServices.hpp`](../../../Preview/Application/Startup/DatagramServices.hpp) 装配 admission budget、packet gateway、datagram listener 和 dispatcher。`BoundaryPhase::Start` 发布初始 generation 的 datagram selection，之后启动 TCP listener 和配置的 UDP ingress。

UDP pump 对每个数据报构造含 payload、peer、分类和 sequence 的 `BoundaryPacket`。handler 读取当时 active generation 的 selection 后调用 dispatcher。dispatcher 先检查 selection 与其 generation owner/use state 是否匹配；QUIC-like 未知 CID 包先尝试现有 raw association，再交 QUIC admission callback；普通 UDP 与未被 QUIC owner 接管的包可以回落到普通 datagram handler。没有配置 gateway 时，QUIC-like 包仍有普通 UDP fallback，避免把加密协议偶然匹配 QUIC 首字节的包静默丢弃。

QUIC admission 按 CID 和 peer 路由现有连接，未知连接使用该包的 typed generation selection 取得工厂并创建协议 lease。注册表只请求协议 lease 关闭；共享 UDP socket 的最终关闭仍由 `DatagramListener` 负责。

## 配置、依赖与关闭

`PreviewConfiguration` 支持 UDP 与 QUIC listener 列表，各最多一个；若两者同时配置，校验要求地址和端口相同。Hysteria2/TUIC 才能使用 QUIC protocol options，相关字段和限制见[QUIC](../protocols/quic.md)、[Hysteria2](../protocols/hysteria2.md) 与 [TUIC](../protocols/tuic.md)。配置模型本身不代表 listener 或协议已经启动。

`PreviewBoundary` 是 `INTERFACE` target，当前源清单在 [`Preview/CMakeLists.txt`](../../../Preview/CMakeLists.txt)，包含 Datagram、QUIC gateway/registry 和 dispatcher headers；它显式依赖 `PreviewFoundation`、`PreviewNet`、`PreviewProtocolQuic`、`PreviewProtocolQuicNative`，并通过后续 `LinkPreviewTargets` 接入 datagram/ingress contracts。`PreviewApplication` 创建并装配这些对象；协议行为不因此转移到 Boundary。

应用停机时先封止 QUIC admission、请求关闭 active provider，再停止 TCP listener；随后停止 UDP listener、标记 gateway draining，并等待 UDP receive loop 退出。之后 registry 请求 QUIC protocol leases 关闭，gateway 进入 closed；registry/owner 关闭失败会保留 typed failure，不能当作成功 drain。`DatagramListener::Stop` 是同步取消/关闭请求，`Drain` 才等待 pump 完成。详细顺序见 [`Shutdown/DrainStages.hpp`](../../../Preview/Application/Shutdown/DrainStages.hpp) 和[所有权与生命周期](../ownership-and-lifecycle.md)。

配置校验的具体位置是 [SchemaValidation.hpp](../../../Preview/Application/Configuration/Validation/SchemaValidation.hpp) 与 [ConfigurationValidation.hpp](../../../Preview/Application/Configuration/Validation/ConfigurationValidation.hpp)：前者检查 listener 数量和 UDP/QUIC endpoint 共址，后者限制 QUIC protocol options 只出现在 Hysteria2/TUIC 配置中。

## 测试位置与证据边界

当前相关测试源码及 CMake owner 位于 [`tests/Preview/Boundary/`](../../../tests/Preview/Boundary/CMakeLists.txt)：`DatagramBoundaryTest`、`DatagramBoundaryServiceTest`、`BoundaryDispatcherTest`、`QuicConnectionRegistryTest`、`QuicPacketGatewayLifecycleTest`，并将 typed owner 和 generation binding 场景加入 registry target。它们标明覆盖入口，不证明测试当前通过。

这些路径标明测试源码与 CMake 的归属，但不登记结果。本页只列源码接线与测试映射，不声称通过；任何通过结论只能来自与当次源码、配置和 binary hash 绑定的验收报告。
