# Preview 启动、请求和关闭路径

本文描述当前生产路径的 owner 顺序，不声称任何测试、互操作或性能场景已经通过。

## 进程启动

`Preview/Application/Main/PreviewMain.hpp` 持有 `main()`。它解析可执行文件路径：若提供第一个位置参数，则该参数是配置文件路径；否则读取可执行文件同目录的 `PreviewConfiguration.json`。入口构造 `Application::Options`，提供配置路径、secret resolver 和 Operations 资源目录，再调用 `Application::Run()`。

启动事务由 `Preview/Application/Startup/Start.hpp` 编排：

```text
PreviewMain
  -> Application::Run / Application::Start
     -> GenerationPhase::Build
        -> 读取、解析、schema/reference/capability/service 校验
        -> 构造不可变 ConfigurationGeneration 与账户 catalog
     -> StartupTransaction 开始接管未发布资源
     -> ProcessServices::Build
     -> ProtocolServices::Prepare
     -> DatagramServices::Build（配置有 UDP/QUIC 共享 ingress 时）
     -> ProtocolServices::Bind
        -> provider/catalog prepare、freeze、bind
        -> QUIC/数据报服务、TCP protocol profile/resolver
     -> BoundaryPhase::Start
     -> OperationsPhase::Start
     -> PublishPhase::Publish
     -> StartupTransaction::Commit
```

任一阶段失败时返回带路径和原因的启动错误，未提交资源由 `StartupTransaction` 回滚。就绪状态在入口启动后发布；发布异常仍由事务回滚。`Application` 是进程级启动、回滚和停机 owner；协议认证和会话关闭行为仍归具体协议。

## TCP 请求

TCP accept 由 `Preview/Runtime/Listener.hpp` 管理。已接受连接进入 Runtime session 编排：会话固定相应 generation/service snapshot，识别过程只在入口处消费预读数据，随后使用已编译的 profile、resolver 和 provider binding 进入具体协议 session。出站连接和通用 relay 使用 `Preview/Net/` 服务。协议 wire、认证、stream 状态和协议级关闭由 `Preview/Protocols/<Name>/` 持有。

配置名称和 capability 在启动冷路径校验、准备、冻结和绑定。热路径消费 typed binding，不应逐 packet/frame 按字符串查找或重新遍历空 factory registry。

## UDP 与 QUIC 请求

配置的 UDP/QUIC ingress 共用 Boundary 的 UDP socket。`DatagramListener` 接收 packet、分类并将 owner-held `BoundaryPacket` 交给 `BoundaryDispatcher`；Boundary 负责入口和 packet 分发，不实现具体代理协议的凭据或 wire 业务。`QuicPacketGateway` 管理入口 readiness、按 CID 分发 handler 的 packet 表和 admission budget；`QuicConnectionRegistry` 管理 protocol lease、peer、CID alias 以及真实关闭回执。两者是不同 owner。实际 QUIC engine 和代理会话行为归相应 `Protocols/Quic` 与具体协议模块。

启动校验要求恰好一个 TCP listener，UDP 与 QUIC 各至多一个；同时配置 UDP 和 QUIC 时，两者必须共用地址和端口。具体协议是否使用 raw UDP、QUIC 或 TCP binding，须同时核对配置能力、启动装配和该协议 owner。

## 停机边界

`Application` 安排停机并管理总预算，入口 owner 停止接纳新请求；Runtime、Boundary、Composition provider 和具体协议按各自合同取消、关闭并等待真实活动结束。传输层的 `Cancel`、`WriteShutdown`、`Close` 与 `Activity()->Drain()` 含义不同，详见[所有权与生命周期](ownership-and-lifecycle.md)。单个关闭命令被接受，不等于异步 I/O、协议 session 或进程已经退出。
