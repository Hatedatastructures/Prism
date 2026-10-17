# Preview Transport 模块

Transport 为 Preview 提供通用异步载体合同、I/O completion 与常用传输装饰器。协议使用这些能力，但传输层不实现协议认证或应用请求语义。

## 职责与边界

Transmission 是统一字节载体前门，暴露 partial/exact read/write、write half-close、cancel、close、executor、activity 与层级访问。其余 owner 包括 completion/control 跟踪、Reliable/Unreliable、Native TLS、Encrypted、Padding、Preview replay、Connector 和 MemoryStream。

Transport 不解析业务协议 frame，不选择协议绑定，也不拥有上层 datagram/mux session 的完整生命周期。装饰器不得替调用方掩盖实际 close/drain owner。

## 当前源码

- 公共 I/O 前门：[Transmission.hpp](../../../Preview/Transport/Transmission.hpp)、[Writer.hpp](../../../Preview/Transport/Writer.hpp)、[WriteDriver.hpp](../../../Preview/Transport/WriteDriver.hpp)。
- 操作与 completion owner：[Detail/IoCompletion.hpp](../../../Preview/Transport/Detail/IoCompletion.hpp)、[Detail/IoActivity.hpp](../../../Preview/Transport/Detail/IoActivity.hpp)、[Detail/TrackedCompletion.hpp](../../../Preview/Transport/Detail/TrackedCompletion.hpp)、[Detail/TransmissionControl.hpp](../../../Preview/Transport/Detail/TransmissionControl.hpp)。
- 载体与装饰器：[Reliable.hpp](../../../Preview/Transport/Reliable.hpp)、[Unreliable.hpp](../../../Preview/Transport/Unreliable.hpp)、[Encrypted.hpp](../../../Preview/Transport/Encrypted.hpp)、[NativeTls.hpp](../../../Preview/Transport/NativeTls.hpp)、[Pad.hpp](../../../Preview/Transport/Pad.hpp)、[Preview.hpp](../../../Preview/Transport/Preview.hpp)、[Connector.hpp](../../../Preview/Transport/Connector.hpp)、[MemoryStream.hpp](../../../Preview/Transport/MemoryStream.hpp)。

## Include 与 CMake 依赖

Preview/CMakeLists.txt 中 PreviewTransport 是 interface target，依赖 PreviewFoundation、PreviewLifecycle 与 PreviewIoContracts。Windows 下另链接 ws2_32、mswsock、crypt32。TLS engine 由 Transport 的 Encrypted/NativeTls owner 提供；协议 target 通过明确依赖消费。

## 当前调用与 I/O 流

Transport 实现派生 StartRead/StartWrite/StartWriteShutdown 和 OnClose/OnCancel；上层调用者使用统一 Transmission 前门。每个 I/O 经过 activity reservation 和一次 completion 交付；executor 从载体 owner 固定。上层协议可以再包装 Transmission，但其 executor、Activity 和底层关闭回执仍需沿 owner 链保留。

借用 buffer 要保持有效至对应 completion。ReadSome/WriteSome 保留部分 I/O 语义，ReadExact/WriteExact 执行完整 I/O。WriteShutdown 是写方向半关闭，反向读仍可继续。Cancel 请求取消；Close 封止新操作并提交真实关闭命令，其成功只表示命令已被接管。实际活动退出须由 Activity/close receipt 的 drain 证明。

## 配置、错误与生命周期

Transport 没有单独的用户配置 parser。构造选项和 TLS context 由 Application/Composition 在冷路径提供；例如 Native TLS 协议 facade 通过 Transport 的 TLS engine 执行握手。

I/O 结果使用 IoResult/Fault::Failure 保留错误值与 native cause。运行在载体 executor 的 owner 串行调用底层操作；谁最终关闭装饰链由 OwnsClose 与外部回执决定，不能把命令接收当成 drain 完成。

## 测试位置与证据

测试归属在 [tests/Preview/Transport/CMakeLists.txt](../../../tests/Preview/Transport/CMakeLists.txt)，覆盖 Transmission、transport decorators、TLS、padding、reliable/unreliable、carrier activity、ownership 等源码场景。

本页只列当前源码接线与测试映射，不登记执行结果。任何通过结论均须来自绑定当次源码、配置与 binary hash 的报告。
