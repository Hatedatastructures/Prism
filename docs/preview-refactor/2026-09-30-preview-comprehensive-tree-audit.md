# Preview 下一代实现全面树型静态审查

> 文档状态说明（2026-10-05）：本文保留原版本的分析、计划或验收快照，文中的“当前”、完成标记、路径和测试数字均属于原记录时点。今天的 Preview 入口、已执行范围与剩余责任见[开发入口](../../Preview/README.md)和[当前执行状态](2026-10-03-preview-no-compat-status.md)。本轮不改写原始历史结果；旧任务提示词需先核对现行 AGENTS.md、无兼容层计划和真实源码，不能直接替代当前任务卡。

> 审查时间：2026-09-30 00:23:53 +08:00  
> 审查对象：当前工作树 `Preview/`、`tests/Preview/`、Preview CMake 与真实启动链  
> 审查方式：源码、include、CMake target、调用点、测试源码和文件规模静态核对；未构建、未运行测试、未启动服务。  
> 结论性质：源码事实、可由源码推出的风险、以及未由运行时复现的待验证项分开记录。

## 结论摘要

你的判断是对的，但问题不只是“文件长”。Preview 当前同时存在四类问题：

1. **协议行为的 owner 没有收拢。** 协议 wire/codec 通常在 `Protocols/<Name>/`，但认证后的 session、UDP/XUDP、QUIC admission、HTTP/3 业务、relay 和 close 行为又散在 `Composition/`、`Application/`、`Ingress/`、`Runtime/`。新增协议必须修改多处中央分支。
2. **模块边界主要停留在名字和 CMake target。** `Runtime/Front` 直接 include `Composition` 和 `Protocols/Quic`，`Composition` 又反过来承担协议运行态；根 CMake 的 target 图不能完整解释源码 include 图。
3. **生产路径和实验/兼容路径并存。** Application 实际使用 `Ingress::UdpListener`、`Ingress::QuicGateway`、`QuicCidRegistry`；Runtime/Front 仍公开另一套 UDP/QUIC front，但没有接入 Application。Foundation 仍导出另一套旧 `Coroutine::TaskRegistry`。
4. **部分具体 bug 已经超过维护性问题。** 当前静态代码中可以确认 QUIC 未知短头会进入新 server factory、QUIC 原生层忽略配置的 stream/datagram 上限并长期保留关闭流、Hysteria2 认证租约在真实 HTTP/3 路径被丢弃、TUIC datagram 回包丢失客户端 association id、Application 某个启动失败分支不回滚，以及多个数据面 map 无上限。

当前 `Preview/` 共 **440 个文件、124,096 行**，68 个文件超过 500 行、10 个超过 1,000 行；`tests/Preview/` 共 **416 个文件、326 个 C++ 测试源**，87 个 C++ 源超过 500 行、19 个超过 1,000 行。行数不是单独的坏代码证明，但和状态机、所有权、协议策略、构建归属混在一起时，已经是实质性风险。

## 严重问题总表

| 编号 | 级别 | 当前状态 | 问题 |
|---|---|---|---|
| QUIC-01 | P2 | Application 真实 UDP/QUIC 路径可达 | 未知 QUIC short header 没有 CID bytes，仍可进入 `QuicCidRegistry` 的新 server factory，随机 QUIC-like 包可消耗连接对象和 handshake 资源 |
| QUIC-02 | P2 | Native QUIC 实际路径可达 | `MaxStreams`/`MaxDatagrams` 配置没有被 NativeConnection 使用，stream state 在关闭后不从 `Streams_` 删除；长期连接可积累资源 |
| QUIC-03 | P2 | TUIC 实际路径可达 | Native 层同时把 stream 放入待接收队列并调用 callback；TUIC callback 消费后队列仍保留 provider，连接生命周期内持续积累 |
| HY2-01 | P2 | Hysteria2 HTTP/3 实际路径可达 | `/auth` 的 `AuthenticationResult.Lease` 被丢弃，认证租约只活到回调结束，连接/账户 quota 不覆盖后续 stream/datagram |
| TUIC-01 | P2 | TUIC datagram provider 实际路径可达 | `Dgram::AsyncReceiveFrom()` 解析 `AssocId/PktId` 却不保存；发送始终使用默认 `AssocId_=0`，多 association 客户端回包错误 |
| CID-01 | P2 | Registry 失败路径可达 | `QuicCidRegistry` move 了 map key 后又使用被 move 的 `Key` 查找失败项，拒绝首包时可能不删除 entry/server |
| APP-01 | P2 | 配置/profile 错误时可达 | `Application::Start()` 在 `MakeTcpProfile()` 失败时直接返回，没有 `RunStartupRollback()`，已创建的 Runtime/Diagnose 状态留在对象内 |
| MEM-01 | P2 | VLESS XUDP 实际路径可达 | `VlessXudp::Run()` 的 `Sessions` 按客户端 session id 无上限，远端可用大量 id 使内存持续增长 |
| MEM-02 | P2 | AnyTLS 实际路径可达 | AnyTLS `State::Streams` 没有最大流数、重复 SYN 检查和完成流回收约束，长连接可积累 stream state |
| TYPE-01 | P2/P3 | 公开辅助 API；当前仓库无生产调用点 | `ToTypedResult()` 从 nested DataPlane 移动租约后留下 engaged 的 moved-from optional，随后 `Context::SetDataPlane()` 可能得到空租约 |
| PIPE-01 | P2 | 公开 API 可达 | `Pipeline::Add(nullptr)` 接受空 middleware，`Run()` 无条件调用 `mw->Handle()` |
| JSON-01 | P2/P3 | Settings 辅助路径；不在当前 Glaze 启动主路径 | 自维护 JSON parser 的数字 grammar、控制字符、surrogate、重复 key 和 double 精度语义不严格 |
| ARCH-01 | P2 | 结构性 | `Runtime/Front` 反向 include `Composition`/`Protocols`，且不是 Application 的真实 front；存在第二套入口和隐藏依赖 |
| ARCH-02 | P2 | 结构性 | Application 近 5,000 行，集中配置、识别、协议 handler、UDP、QUIC、Operations、线程和 shutdown |
| ARCH-03 | P2 | 结构性 | `Composition` 已成为协议运行态聚合层，不再只是配置期装配层 |
| ARCH-04 | P2 | 结构性 | Protocol catalog、recognition matrix、builtin registry、Application switch 各自维护协议事实 |
| ARCH-05 | P2 | 结构性 | `SessionOptions`/`SessionServices`/`Middleware::Context`/`ProtocolDataPlane` 四层并存，legacy 字段和 canonical 字段可漂移 |
| ARCH-06 | P2/P3 | 结构性 | QUIC、UDP、AnyTLS、XUDP、HTTP/3 等协议行为跨四到五个目录，协议特殊性没有通过窄 typed provider 收口 |
| DEAD-01 | P3 | 当前仓库无生产 caller | `Composition/Api`、部分 Route/Outbound/Reload API、旧 Coroutine TaskRegistry、Runtime Front 等是公开但未接入或仅测试使用的平行实现 |
| TEST-01 | P3 | 测试维护风险 | 87 个 Preview C++ 测试源超过 500 行，19 个超过 1,000 行；大量文件同时承担 fixture、协议、生命周期和 E2E |

---

# 一、审查口径和真实启动链

## 1.1 当前真实 Application 路径

当前独立入口是：

```text
Preview/Application/Main/PreviewMain.cpp
  -> Preview::Application::Application::Run()
  -> Application::Start()
     -> ConfigurationParser::PrepareFile()
     -> Builtin registry / snapshot freeze
     -> ConfigurationValidator / GenerationBuilder
     -> account directories / authenticator
     -> RuntimeState / Diagnose / DNS / worker group
     -> optional Ingress::UdpListener + UdpDemux + IngressDispatcher
     -> optional QuicCidRegistry + Native QUIC Server factory
     -> TCP Runtime::TcpListener
     -> Runtime::Session
        -> Recognition::Pipeline
        -> Composition protocol acceptor
        -> ProtocolDataPlane
        -> mux / UDP service / dial / relay
     -> optional Operations::HttpServer
```

证据：[`PreviewMain.cpp`](../../Preview/Application/Main/PreviewMain.cpp#L17-L66)、[`Application.cpp`](../../Preview/Application/Application.cpp#L4120-L4851)。

这个链条已经说明一个根本问题：`Application` 不是纯 composition root。它包含了协议 credentials、Hysteria2 relay、TUIC dial/resolve/datagram service、TCP candidate factory、carrier registry、QUIC server factory、Operations query/command handler 和 shutdown 协程。

## 1.2 不是所有看起来属于 Runtime 的入口都在真实路径

`Runtime/Front/UdpFront.hpp` 和 `Runtime/Front/QuicFront.hpp` 的文件说明已经承认真实 UDP pump 在 `Ingress/UdpListener`，而当前 Application 也确实没有构造这两个 Front。Runtime Front 主要由集成/合同测试触碰。

这不是“小的重复类”问题，而是两个不同系统同时被公开成正式 API：

- 真实启动：`Ingress::UdpListener` -> `IngressDispatcher` -> `QuicGateway`/`QuicCidRegistry`/协议 gateway。
- 实验/合同入口：`Runtime::Front::UdpFront`/`QuicFront` -> typed registration/association。

两套 API 的 readiness、CID 路由、关闭、协议绑定语义没有证明等价。以后任何测试通过 Front 都不能自动证明 Application 的真实入口通过。

---

# 二、按顶层目录树审查

## 2.1 `Preview/CMakeLists.txt` 与 `Preview/CMake/`

### 规模和现状

- [`Preview/CMakeLists.txt`](../../Preview/CMakeLists.txt) 当前 899 行。
- [`Preview/CMake/PreviewBoundary.cmake`](../../Preview/CMake/PreviewBoundary.cmake) 当前 660 行。
- 根 CMake 同时登记 20 多个 protocol target、全部 header source、target 依赖、边界检查、standalone closure 和 fault injection。
- 大多数协议 target 是 `INTERFACE`，大量协议状态机定义在 header；只有少数非模板实现获得静态库 owner。

### CMAKE-01：target 图和源码 include 图仍然不一致

`PreviewRuntime` 的允许链接集合只包含 Foundation/Transport/Net/Lifecycle/Account/Resource/Scheduler，但 `Runtime/Front/UdpFront.hpp` include 了 `Composition/Adapters/DataPlane.hpp` 和 `Composition/Recognition/ProtocolMatrix.hpp`，`Runtime/Front/QuicFront.hpp` 还 include 了 `Protocols/Quic/*`。

证据：[`UdpFront.hpp`](../../Preview/Runtime/Front/UdpFront.hpp#L23-L28)、[`QuicFront.hpp`](../../Preview/Runtime/Front/QuicFront.hpp#L23-L28)、[`Preview/CMakeLists.txt`](../../Preview/CMakeLists.txt#L248-L306)。

当前这些 header 不一定被 `PreviewRuntime` 的编译单元直接实例化，因此问题可能在某些 target/测试才显现。但从模块合同看，源码跨层依赖已经存在，CMake 不能解释它。边界检查只验证 target properties，不验证每条 `#include <Preview/...>` 的模块边。

### CMAKE-02：依赖 helper 仍有两套写法

部分依赖经过 `LinkPreviewTargets()`，部分直接使用 `target_link_libraries()`。这造成：

- `AssertPreviewDependency()` 的“调用时检查”不能覆盖直接链接。
- `_GetPreviewAllowedInternalLinks()` 又维护一套允许表。
- 实际图、局部 API 规则和注释存在重复来源。

当前最终 `AssertPreviewTargetGraph()` 能发现部分非法最终边，但这是事后全图检查，不是防止错误声明的单一入口。建议删掉直接 `target_link_libraries(PreviewComposition ...)` 等旁路，并增加源码 include graph 检查。

### CMAKE-03：header-only target 被当成模块隔离

模板/纯 inline codec 使用 `INTERFACE` 合理；但 `Protocols/Mux/Session.hpp`、`Protocols/Xhttp/Conn.hpp`、`Protocols/Trusttunnel/Http2.hpp` 等包含大量状态机、异步循环和实际 owner。仅登记 header 并不会形成真实编译边界，也不会降低耦合或编译影响面。

### CMAKE-04：模块 ownership 仍集中在根 manifest

新协议仍然需要修改根 CMake 的 source list、target declaration、allowed edge、Composition link 和 Application include。目标结构应该是每个真实模块拥有自己的 `CMakeLists`，根目录只组合，不是把 899 行继续扩大。

---

## 2.2 `Preview/Account/`

### 当前优点

`Credential`、`SecureBytes`、`AccountRecord`、`AccountRuntime`、`AccountDirectory`、`AccountLease` 已经有较清楚的值对象/运行态分层，账户租约是正确方向。当前生产 TCP 协议多数通过 `DirectoryAuthenticator` 取得 typed `AccountLease`。

### ACCOUNT-01：账户认证 owner 仍被协议入口复制

Application 为每个静态 protocol 创建 directory/authenticator 数组，并在各个 `ServerConfig`、QUIC factory、Session service 中再次传递。一个“账户目录”概念被拆成：

- Application 的 `Accounts` 主目录。
- 每协议 `ProtocolAccounts[8]`。
- QUIC credential 单独构造的单账户目录。
- 协议 Conn 内部自己的 `AuthLease_`。

证据：[`Application.cpp`](../../Preview/Application/Application.cpp#L1040-L1121)、[`Application.cpp`](../../Preview/Application/Application.cpp#L1161-L1241)、[`Application.cpp`](../../Preview/Application/Application.cpp#L4224-L4260)。

这会导致协议新增多账户/协议专属 credential 时必须回到 Application 加分支。建议 Account 只暴露 immutable account snapshot + typed credential matcher + lease service，协议 provider 通过单一 typed contract 获取结果。

### ACCOUNT-02：`Foundation::Authenticator` 还把旧 Check API 放在基础公共边界

[`Foundation/Authenticator.hpp`](../../Preview/Foundation/Authenticator.hpp#L38-L72) 保留 `LegacyAuthLease`，`Authenticate()` 默认实现调用旧 `Check()` 且不能产生 lease（L155-L185）。这使“认证成功但没有 quota lease”成为合法默认状态；对于所有需要连接配额的协议，必须在协议边界重复检查 lease，否则会出现 HY2-01 类问题。

建议把旧 codec adapter 放到明确的 compatibility target，基础 runtime `Authenticator` 只保留 typed `Authenticate()` 或把“无 lease 的静态认证”单独建为显式类型。

---

## 2.3 `Preview/Application/`

### APP-02：Application 是 god object

[`Application.cpp`](../../Preview/Application/Application.cpp) 4,925 行，当前至少同时包含：

- 日志级别/render mode 解析。
- 协议 credential 解析、UUID/PSK 解析。
- TCP candidate factory。
- HTTP/SOCKS5/VLESS/Trojan/VMess/SS2022/AnyTLS/TrustTunnel handler 装配。
- Hysteria2 stream/datagram relay。
- TUIC dial/resolve/datagram service。
- Native TLS context。
- UDP listener、SS2022 gateway、QUIC CID registry。
- Worker、TCP listener、Operations server。
- Operations query/command 逻辑。
- shutdown deadline、rollback、Diagnose flush、signal。

证据：[`Application.cpp`](../../Preview/Application/Application.cpp#L132-L301)、[`Application.cpp`](../../Preview/Application/Application.cpp#L1244-L1827)、[`Application.cpp`](../../Preview/Application/Application.cpp#L3141-L4100)、[`Application.cpp`](../../Preview/Application/Application.cpp#L4120-L4851)。

这不是简单按 4,925 行切成多个 include 片段就能解决。应形成真实 owner：

```text
Application
  -> ConfigurationGenerationOwner
  -> TcpIngressAssembly
  -> UdpIngressAssembly
  -> QuicProtocolBindingOwner
  -> OperationsAssembly
  -> ShutdownCoordinator
```

Application 只按顺序调用这些 owner 的 prepare/bind/start/drain/rollback，不持有协议 relay lambda。

### APP-01：profile 构建失败没有启动回滚

在 `Start()` 已经创建 `RuntimeState`、安装 Diagnose、创建 DNS/UDP/Native TLS/Services 后，`MakeTcpProfile()` 失败分支直接返回：

```cpp
const auto Profile = MakeTcpProfile(...);
if (!Profile)
{
    LastError_ = Profile.error();
    return std::unexpected(*LastError_);
}
```

证据：[`Application.cpp`](../../Preview/Application/Application.cpp#L4683-L4693)。

同一文件其它晚期失败路径普遍调用 `RunStartupRollback(Runtime)`，该处却没有。结果：

- `State_` 仍然存在，Phase 仍是 `Created`。
- Diagnose runtime 和 flush timer 仍挂在 RuntimeState 中。
- `Start()` 后续调用会进入“cannot restart after stop”类失败，而不是干净的未启动状态。
- 只有析构时才可能继续清理，启动失败的 rollback contract 不一致。

整改：引入 `StartupTransaction`，所有已发布资源由 transaction 逆序回滚；禁止在 `Start()` 内出现未走统一失败出口的 `return`。

### APP-03：Application 的静态协议枚举数组是扩展瓶颈

`StaticProtocol`、`std::array<bool, 8>`、`std::array<Authenticator, 8>`、`ProtocolCredentialKey()`、`ParseStaticProtocol()`、`RegisterTcpCandidate()`、`MakeRuntimeAcceptors()`、`MakeAccountCredential()` 分散维护同一组协议事实。

证据：[`Application.cpp`](../../Preview/Application/Application.cpp#L416-L574)、[`Application.cpp`](../../Preview/Application/Application.cpp#L2260-L2542)。

新增协议不是注册一个 provider，而是修改多处 switch、数组大小、credential parser、validator 和 target link。

### APP-04：QUIC readiness 名称与实际含义不一致

Application 在 UDP listener 启动成功后直接调用：

- `QuicGateway->MarkSocketReady()`。
- `MarkReceiveLoopReady()`。
- 如果配置了 protocol，直接 `MarkHandshakeReady()` 和 `MarkProtocolReady()`。

证据：[`Application.cpp`](../../Preview/Application/Application.cpp#L4744-L4760)。

这只证明 QUIC factory 已配置，不证明任何 Native QUIC 连接已经完成 handshake 或上层 protocol binding。Operations 的 `QuicHandshakeReady`/`QuicProtocolReady` 因此是“服务能力已装配”，但字段命名像真实连接状态。应改成 `QuicAdmissionConfigured` / `QuicProviderReady`，连接级 handshake 放 NativeConnection health。

### APP-05：Application 里的协议 relay 不属于 Application

`RelayHysteria2Stream()`、`RelayHysteria2Datagrams()`、TUIC `RunTuic*()` 都是协议业务和数据面状态机，而不是进程启动职责。它们应成为 `Protocols/Hysteria2/Service`、`Protocols/Tuic/Service` 的 typed callback implementation，Composition 只注入 `Dial/Resolve/Metrics`。

---

## 2.4 `Preview/Application/Configuration/`

### CONFIG-01：ConfigurationValidator 仍是协议知识聚合器

[`ConfigurationValidator.hpp`](../../Preview/Application/Configuration/ConfigurationValidator.hpp) 当前 1,938 行，既校验通用 worker/listener/secret，又校验：

- Hysteria2/TUIC 单 QUIC provider 限制。
- ALPN `h3`。
- QUIC UUID、limits、credential secret。
- carrier ambiguity、SNI/ALPN overlap。
- protocol binding、mux、recognition、capabilities、builtin snapshot。

证据：[`ConfigurationValidator.hpp`](../../Preview/Application/Configuration/ConfigurationValidator.hpp#L64-L317)、[`ConfigurationValidator.hpp`](../../Preview/Application/Configuration/ConfigurationValidator.hpp#L1215-L1398)。

建议拆成 `ListenerValidator`、`ProtocolValidator`、`CarrierValidator`、`RecognitionValidator`、`CapabilityValidator`，但共享 `ValidationContext` 必须只包含真实共同数据，不能把所有字段塞进万能 context。

### CONFIG-02：配置 parser/generation/reload 是三套阶段，Application 没有真正使用 reload

当前有 `ConfigurationParser -> PreparedConfiguration -> GenerationBuilder -> ConfigurationGeneration -> ConfigurationStore -> ReloadCoordinator` 的设计，但真实 `Application::Start()` 直接建立 generation 并运行；`ReloadCoordinator`/`ConfigurationStore` 在 Preview 生产调用点中没有接入。

证据：[`ReloadCoordinator.hpp`](../../Preview/Application/Configuration/ReloadCoordinator.hpp#L35-L114)、[`Application.cpp`](../../Preview/Application/Application.cpp#L4140-L4200)。

结果是：文档/API 暗示支持 generation reload，实际 Application 没有把新 generation 绑定到 worker、listener、protocol bindings 或 session drain。要么接入完整 reload transaction，要么把这些接口隔离为实验配置模块。

### CONFIG-03：公开 Parse API 与生产 Prepare API 的 secret 暴露语义不一致

`ConfigurationParser::Parse()` 返回的 `PreviewConfiguration` 会保留 inline `Secrets`；`PrepareFile()` 会转入 `SecretResolutionTransaction` 并在 `PreparedConfiguration` 构造中清理原 map。两条 API 对明文 secret 生命周期不同。

证据：[`ConfigurationParser.cpp`](../../Preview/Application/Configuration/ConfigurationParser.cpp#L20-L74)、[`ConfigurationParser.cpp`](../../Preview/Application/Configuration/ConfigurationParser.cpp#L93-L129)、[`PreparedConfiguration.cpp`](../../Preview/Application/Configuration/PreparedConfiguration.cpp#L198-L204)。

这不是立即泄漏，但 API 使用者很容易误把 `Parse()` 的结果当成安全 generation。建议 Parse 只返回不含 secrets 的 typed model，secret resolution 只在 Prepare 阶段发生。

---

## 2.5 `Preview/Composition/`

### COM-01：Composition 责任过宽

`Composition/` 当前约 51 个文件、13,258 行，包含：

- protocol adapters。
- recognition candidate registry/factory/profile builder。
- TLS carrier。
- QUIC Hysteria2/TUIC factory。
- AnyTLS service/wire。
- VLESS XUDP。
- UDP service factories。
- mux service/H2 server/SingMux。
- builtin registry/capability。
- Operations API。
- 自维护 Settings JSON loader。

这已经不是 composition，而是第二个 Runtime + protocol service 聚合层。

### COM-02：协议运行态错误地放在 Composition

当前主要错位：

| 文件 | 实际承担的协议行为 | 建议 owner |
|---|---|---|
| `Composition/AnytlsService.hpp` | AnyTLS frame、stream table、dial、relay、close | `Protocols/Anytls/Service` |
| `Composition/VlessXudp.hpp` | XUDP frame、session map、UDP socket、relay | `Protocols/Vless/Xudp` |
| `Composition/UdpService.hpp` | SOCKS5/Trojan/VLESS/VMess UDP session 和动态 cast | 各协议 packet service；Composition 只选 provider |
| `Composition/Quic/Hysteria2Factory.hpp` | Hysteria2 raw stream、HTTP/3 auth、datagram handler、relay | Hysteria2 protocol service + typed binding |
| `Composition/Quic/TuicFactory.hpp` | TUIC callback、lease/relay/metrics glue | TUIC protocol binding；保留注入接口 |
| `Composition/H2MuxServer.hpp` | H2Mux stream accept/relay bridge | Mux protocol service |

Composition 应只负责：配置名到 typed descriptor、能力校验、prepare、freeze、bind/start/rollback。

### COM-03：UdpService 是协议 switch + RTTI 聚合器

`UdpServiceFactory` 对每个协议返回 lambda，内部用 `dynamic_pointer_cast<Socks5::Conn> / Vless::Conn / Trojan::Dgram / Vmess::Dgram` 选择正确 packet semantics。

证据：[`UdpService.hpp`](../../Preview/Composition/UdpService.hpp#L68-L209)。

问题：

- 运行时 Context 仍然只提供 `Inbound` + `detected`，协议类型和传输动态类型必须同时匹配。
- 每个协议重复 resolver、timeout、统计、socket、close 逻辑。
- 新协议需要修改 central factory 和 Application switch。
- `MakeSs2022()` 明确返回 `NotSupported`，而 SS2022 UDP 另走 `Ingress::Ss2022Gateway`，同一“UDP capability”有两条完全不同的模型。

建议协议返回 typed `DatagramService`/`PacketProvider`，Composition 只注册 provider，不做动态 cast。

### COM-04：AnyTLS 没有流上限和重复 stream 保护

`AnytlsService::State` 只有 `unordered_map<uint32_t, StreamState> Streams`；`HandlePush()` 首次收到数据时可创建 stream 并启动两条 detached relay，未检查：

- `Streams_.size()` 上限。
- 同一 stream id 的重复 `Syn`。
- 已关闭 stream id 的复用。
- stream 结束后的 map erase。

证据：[`AnytlsService.hpp`](../../Preview/Composition/AnytlsService.hpp#L96-L121)、[`AnytlsService.hpp`](../../Preview/Composition/AnytlsService.hpp#L791-L891)。

这是 MEM-02。认证后长连接上，远端可以反复创建 id，导致 map、channel、detached relay 状态累积；应使用 bounded stream registry + exactly-once close/erase。

### COM-05：VLESS XUDP session map 无上限且响应是串行的

`VlessXudp::Run()` 在每个新 `SessionId` 上执行 `Sessions[Frame->SessionId]`，没有最大 flow 数、idle reap、重复 flow 状态或 per-flow budget。

证据：[`VlessXudp.hpp`](../../Preview/Composition/VlessXudp.hpp#L411-L439)。

同一循环中每个请求发送后立即等待一个上游响应，再处理下一帧（L506-L540），这不是并行 UDP flow；一个静默/慢目标会阻塞同一 XUDP 根连接的后续 session。若协议要求多 flow 并行，应按 flow 启动有界 child operation；若只支持串行，应在配置和协议合同中明确拒绝多 flow。

### COM-06：TypedResult 仍有租约移动错误

`ToTypedResult()` 在 `Result.DataPlane.AccountLease` 存在时把 lease 移到 `Typed.AccountLease`，但没有 reset nested optional：

```cpp
Typed.AccountLease = std::move(*Typed.Data.Data.AccountLease);
```

证据：[`TypedResult.hpp`](../../Preview/Composition/Adapters/TypedResult.hpp#L191-L209)。

之后如果把 `Typed.Data.Data` 再交给 `Context::SetDataPlane()`，`optional` 仍 engaged，但内部 lease 已 moved-from。当前仓库 `AcceptTyped()` 无生产 caller，因此这是公开 helper 的 P2/P3，不应写成当前线上路径已触发；应修复或删除这条未接入双轨。

### COM-07：三个协议元数据表不是一个可验证的 manifest

当前至少有：

- `Composition/Protocol/ProtocolCatalog.hpp`：协议 descriptor、TCP/UDP/QUIC 属性。
- `Composition/Recognition/ProtocolMatrix.hpp`：recognition、UDP association、QUIC ALPN。
- `Composition/Builtin/ProtocolBuiltins.hpp`：builtin capability/metadata callback。
- `Application.cpp`：`StaticProtocol`、switch、factory。

它们回答的问题不同，却使用相似的 protocol name/Supports 字段。新增协议时不能从一份 manifest 推导所有 binding，容易出现“catalog 宣称支持、实际 factory 缺失”的漂移。应拆成明确的 `ProtocolManifest`、`CarrierBinding`、`ExecutableProvider`，并在 freeze 阶段检查三者闭合。

### COM-08：旧 Settings parser 是重复正确性负担

`Composition/Settings/Json.hpp` 明确标注“生产用 glaze”，但仍作为公共 target source 和测试 API 存在。当前缺陷：

- `ParseNumber()` 接受 `1+2`、`1e`、`--1` 等 token，再用不带 `idx` 的 `stod`，没有验证完整消费。
- `ParseString()` 不拒绝裸控制字符 0x00-0x1f。
- `\uXXXX` 把 surrogate 当普通 BMP 码点编码，不合并 pair，也不拒绝孤立 surrogate。
- `obj.emplace()` 对重复 key 静默保留首值。
- 所有数字存 `double`，Loader 再转 `uint64_t`，超过 2^53 的整数会变值。

证据：[`Json.hpp`](../../Preview/Composition/Settings/Json.hpp#L87-L175)、[`Json.hpp`](../../Preview/Composition/Settings/Json.hpp#L177-L207)、[`Json.hpp`](../../Preview/Composition/Settings/Json.hpp#L253-L303)、[`Loader.hpp`](../../Preview/Composition/Settings/Loader.hpp#L98-L121)。

这些主要是辅助 API 缺陷，不是当前 `Application::Start()` 的 Glaze parser 主路径；应删除或严格标记 compatibility-only，不要让它看起来是 Preview 的第二个生产配置 parser。

### COM-09：Builtin registry 不是协议插件工厂

`ProtocolBuiltins` 只提供 descriptor/capability/metadata callback，不会自动生成 protocol codec、认证、Session、UDP 或 QUIC server。Application 仍手工调用 candidate registry、UDP factory 和 protocol switch。

证据：[`ProtocolBuiltins.hpp`](../../Preview/Composition/Builtin/ProtocolBuiltins.hpp#L1-L20)、[`Application.cpp`](../../Preview/Application/Application.cpp#L4164-L4185)。

命名为 Builtin/Registry 很容易使调用者以为“注册一个协议即可运行”。应明确区分 `MetadataRegistry` 与 `ProtocolProviderRegistry`。

---

## 2.6 `Preview/Foundation/`

### FOUNDATION-01：Foundation 仍包含多个不应向底层暴露的上层依赖

- `Foundation/Authenticator.hpp` include `Account/Directory.hpp`，实际 Foundation contract 依赖 Account domain。
- `Foundation/SessionBase.hpp` include `Transport/Stream.hpp`，基础抽象向上依赖 Transport。
- `Foundation/Utility/Diagnose/FieldCodec.hpp` include `Statistics/Redaction.hpp`，diagnose field encoding 依赖 statistics redaction。
- `Foundation.hpp` 聚合导出 `Utility/Coroutine/Registry.hpp`，但生产使用的是 `Lifecycle/TaskRegistry.hpp`。

这破坏了“Foundation 是最底层稳定值类型/错误/原语”的预期边界。

### FOUNDATION-02：两套 TaskRegistry 并存

[`Foundation/Utility/Coroutine/Registry.hpp`](../../Preview/Foundation/Utility/Coroutine/Registry.hpp#L145-L350) 是旧的 `io_context + TaskRegistry* owner` 实现；实际 Application/Session/Worker 使用 [`Lifecycle/TaskRegistry.hpp`](../../Preview/Lifecycle/TaskRegistry.hpp#L49-L710)。旧 registry 主要出现在测试和聚合头。

它们有不同的：

- executor owner。
- cancel/drain 语义。
- task id/label 语义。
- 析构和 owner 指针生命周期。

必须选一个 canonical registry；旧版本迁移完成后从 Foundation 聚合头和生产 target 中删除，而不是长期保留同名 public concept。

### FOUNDATION-03：SessionBase 是未完成迁移的适配层

[`SessionBase.hpp`](../../Preview/Foundation/SessionBase.hpp#L1-L67) 仍被 `Protocols/Mux/StreamState.hpp` 使用，注释已经说明将来 `StreamHandle` 直连 `Transmission` 后删除。当前不能标成 dead code，但应明确 migration owner 和删除条件，否则每个新协议都会继续依赖旧抽象。

### FOUNDATION-04：错误类型过多且转换边界不清

Preview 同时有 `Preview::Error`、`Preview::Fault::Code`、`std::error_code`、`boost::system::error_code`、异常层次。转换在每个协议/transport 中重复出现。建议为 parse、auth、dial、relay、close 分别定义稳定边界，禁止业务层在四种错误类型之间到处手工映射。

---

## 2.7 `Preview/Ingress/`

### INGRESS-01：QuicCidRegistry 可能由无 CID 的未知 short header 创建 server

`UdpDemux::ClassifyShortHeader()` 对 fixed-bit 命中的未知 short header 返回 `Kind::Quic`、`Route::UnknownCid`，但 `ConnectionIdBytes` 为空，仅留下一个 hash `ConnectionId`。

证据：[`UdpDemux.hpp`](../../Preview/Ingress/UdpDemux.hpp#L193-L223)。

`QuicCidRegistry::Handle()` 对空 `ConnectionIdBytes` 只尝试按 peer 查找；找不到后仍调用 `Options_.Factory(Packet.Classification.ConnectionIdBytes, Packet.Peer)`，即以空 CID 创建新 Native server。

证据：[`QuicCidRegistry.hpp`](../../Preview/Ingress/QuicCidRegistry.hpp#L65-L127)。

Application 的 `IngressDispatcher` 会在 SS2022 未认证抢占时把包交给这个 registry，因此该路径是真实可达的。证据：[`Application.cpp`](../../Preview/Application/Application.cpp#L4425-L4439)。

风险：攻击者可发送大量命中 fixed bit 的随机 short header，使每个新 peer/包触发 QUIC server 初始化尝试；`MaxConnections` 只限制 registry entry 数，不解决错误 admission 和昂贵初始化。整改：没有可提取的 long-header destination CID 时必须 fail closed，不能调用新连接 factory；short header 只能路由到已经登记且 peer/CID 匹配的连接。

### INGRESS-02：Registry move 后的失败清理不可靠

代码先 `Entries_.emplace(std::move(Key), ...)`，后面拒绝首包时又 `Entries_.find(Key)`。

证据：[`QuicCidRegistry.hpp`](../../Preview/Ingress/QuicCidRegistry.hpp#L117-L147)。

`Key` 在 move 后处于 valid-but-unspecified 状态，不能作为原 map key 使用。即便首包 `DispatchAndPrune()` 返回 false，后续清理可能找不到 entry，server 保留在 map 中。应在 emplace 前保存 immutable key，或者直接用 iterator/Server pointer 做 cleanup。

### INGRESS-03：Ingress 命名下仍有协议特定 SS2022 行为

`Ingress/Ss2022Gateway.hpp` 包含 SS2022 wire parser、PSK trial、peer replay window、DNS resolve、UDP egress、response encryption 和 peer table。

证据：[`Ss2022Gateway.hpp`](../../Preview/Ingress/Ss2022Gateway.hpp#L41-L112)、[`Ss2022Gateway.hpp`](../../Preview/Ingress/Ss2022Gateway.hpp#L212-L323)。

Ingress 应拥有 socket、packet、peer association 生命周期；SS2022 authentication/packet wire/relay 应由 `Protocols/Shadowsocks2022` 提供 typed provider。否则下一个协议会继续往 Ingress 添加 keys、parser、replay 状态。

### INGRESS-04：IngressDispatcher 的 `bool` handler 合同过于含糊

`QuicAdmission` 返回 `true` 表示已消费，`QuicGateway::Handle` 返回 `true` 表示 packet accepted，`DatagramHandler` 无返回值。一个 packet 可能被异步接收后实际认证失败，但入口已经当成 consumed；诊断和重试没有统一结果类型。

建议用 `IngressDecision {Consumed, Rejected, RetryOrdinary, BoundedFailure}`，并把异步 admission 的“已排队”与“已认证”分开。

### INGRESS-05：UdpListener 使用 detached receive loop，但 shutdown 依赖 channel

`UdpListener::Start()` 以 `Net::detached` 启动 `ReceiveLoop`；`Drain()` 等待 `Completion`。

证据：[`UdpListener.hpp`](../../Preview/Ingress/UdpListener.hpp#L118-L160)、[`UdpListener.hpp`](../../Preview/Ingress/UdpListener.hpp#L181-L194)。

这种方式可以工作，但所有异常只能被 `ReceiveLoop` 自己吞掉；handler 发生异常时只增加 `PacketsRejected`，不会把 packet pump failure 传到 Application 的 lifecycle registry。建议把 receive loop 注册进 owner 的 TaskRegistry，并以 typed completion 返回终态。

---

## 2.8 `Preview/Lifecycle/`

### LIFECYCLE-01：TaskRegistry 很完整，但文件仍是一个生命周期超级对象

[`TaskRegistry.hpp`](../../Preview/Lifecycle/TaskRegistry.hpp) 710 行同时包含 global task id reservation、child domain、barrier、active map、cancel、quarantine、failure callback、spawn 和 teardown。

不要为了行数机械切割；应按真实编译/owner 切成：

- `TaskRegistry` public API。
- `TaskRegistryState`/ID reservation。
- `TaskSubmission`。
- `TaskDrain/Quarantine`。

最重要的是保持一个 owner 推进 `Active -> Completed/Quarantined`，不要把状态机拆成多个可互相修改的 helper。

### LIFECYCLE-02：Worker Stop 与 TaskRegistry Drain 语义不统一

`WorkerResources::Stop()` 只调用 `Tasks.Cancel()`，随后 `Work.reset()` 和 `IoContext.stop()`；Application 的 SessionRegistry 会 drain SessionControl，但 Worker task registry 本身没有在 worker stop 前等待 `Tasks.Drain()`。

证据：[`WorkerResources.hpp`](../../Preview/Resource/WorkerResources.hpp#L152-L161)、[`Application.cpp`](../../Preview/Application/Application.cpp#L3401-L3430)。

TaskRegistry 的 destructor 会尝试 quarantine，但这意味着停机可能在任务 completion 没有实际执行的情况下收口。若这是设计好的隔离策略，应把 `Quarantined` 作为应用 shutdown evidence；若要求优雅停机，应先 cancel -> drain -> stop io。

### LIFECYCLE-03：大量 detached 路径绕过统一 registry

当前 detached 路径包括 UDP receive、Operations accept、QUIC Native pump/send、H2/HTTP3 session、XHTTP、TrustTunnel、Mux、AnyTLS、DNS maintenance 等。示例：[`Native.cpp`](../../Preview/Protocols/Quic/Native.cpp#L863-L870)、[`AnytlsService.hpp`](../../Preview/Composition/AnytlsService.hpp#L837-L881)、[`UdpListener.hpp`](../../Preview/Ingress/UdpListener.hpp#L159-L160)。

不是每个短-lived callback 都必须进 TaskRegistry，但每个长期循环必须有：创建者、取消源、最终 close、drain evidence 和 executor。当前这些规则分散在类注释，缺少全树 owner table。

---

## 2.9 `Preview/Net/`

### NET-01：DNS 已经拆文件，但 Resolver/Upstream 仍聚合策略

`Net/Dns/` 22 个文件约 5,672 行，已有 Cache/Coalescer/Rules/Transport/DoH/ConnPool，但 `Upstream.hpp` 676 行、`Resolver.hpp` 591 行仍同时处理 upstream selection、retry/fallback、connection pool、cache/coalescing、错误映射。

建议使每层只有一个可观察契约：

- Rules：输入 host -> action。
- Cache：answer/negative/expiry。
- Coalescer：同 key single-flight 和 waiter cancellation。
- Transport：单次 wire exchange。
- Upstream：attempt policy。
- Resolver：组合并返回值结果。

本次未运行 DNS 并发测试，不对这些实现宣称线程安全。

### NET-02：Route/Outbound 与真实拨号入口不是同一条路径

`Net/Route/Route.hpp` 和 `Net/Outbound/Outbound.hpp` 在当前 Preview production caller 中没有明显调用点；真实 Application 直接构造 `Dialer` 或 worker `WorkerDialService`。这会产生“支持路由”的 API 表象，但路由配置在 Application validator 中反而被拒绝为未接线。

证据：[`Application.cpp`](../../Preview/Application/Application.cpp#L985-L991)、[`WorkerDialService.hpp`](../../Preview/Net/Services/WorkerDialService.hpp#L41-L117)。

应决定：接入 route snapshot，或把 Route/Outbound 降为实验 target；不要让配置、API 和真实数据面三套语义并存。

### NET-03：拨号超时/地址策略被复制

Application 有 `DialTarget()`、`DialTargetWithResolver()`、`ResolveUdpTarget()`；WorkerDialService 又有 worker-local resolver/dial；UDP service 各自再做 `ResolveTarget`。同一“拨号目标”在 TCP、UDP、QUIC raw stream、TUIC datagram、Hysteria datagram 有不同错误映射和 IPv6 策略。

应提供 typed `DialRequest/ResolveRequest` 和一个 worker-owned service，协议只调用它，不自行打开 socket。

---

## 2.10 `Preview/Operations/`

### OPS-01：HttpServer 仍然把四种职责放进一个 1,877 行编译单元

[`HttpServer.cpp`](../../Preview/Operations/HttpServer.cpp) 同时负责：

- loopback socket accept。
- connection strand。
- read deadline。
- HTTP parser。
- route/query/command dispatch。
- response serialization。
- active connection registry。
- drain timer。

建议拆为 `HttpConnection`、`HttpRequestParser`、`OperationsHttpCodec`、`HttpServer`；Application 只提供 Router。

### OPS-02：Route/Router/HttpServer 的层次是合理方向，但 API 仍有异步时序陷阱

`Router::SetQueryHandler()`/`SetCommandHandler()` 只是 `post`，没有完成通知；调用方刚设置 handler 就立即 `QueryAsync()` 时，实际顺序依赖同一 strand 排队。当前 Application 构造时直接传 handler，所以未形成现行故障，但公开 API 应返回 awaitable/expected 或写明“下一次 strand turn 生效”。

### OPS-03：管理面授权依赖 loopback 位置，不是应用级认证

Application 只允许 Operations endpoint 为 loopback，HTTP server 本身没有 auth。当前安全边界依赖 bind address；若未来把 server 复用到非 loopback 或做端口转发，所有 command/query 会直接暴露。应让 Operations transport policy 显式声明 `LoopbackOnly`/auth，而不是只在 Application parser 拦一次。

---

## 2.11 `Preview/Performance/`

当前只有两个生产目录 benchmark 源，边界清楚；但它们不代表性能验收。所有性能结论必须绑定：当前源码版本、配置、编译产物、payload、连接数、线程数、分配计数和延迟统计。

当前未运行 benchmark，不报告 Preview 性能通过。

---

# 三、`Preview/Protocols/` 协议树审查

## 3.1 总体问题：协议目录有 wire，但没有完整协议 owner

`Protocols/` 当前 166 个文件、约 52,952 行。多数协议只拥有 codec/Conn，而以下行为在别处：

- 认证结果到 AccountLease：Composition adapters。
- protocol accept：Composition/Recognition。
- UDP session：Composition/UdpService 或 Ingress。
- QUIC admission：Composition/Quic + Application + Ingress。
- carrier candidate：Composition/Recognition + Runtime/Recognition。
- stream relay：Application/Composition。

这使“协议目录”只拥有 wire，而不是协议生命周期。应按协议竖切：wire、auth、session、stream/datagram provider、close；公共层只拥有纯 transport contract。

## 3.2 `Protocols/Common/`

`Address.hpp`、`Framing.hpp`、`Read.hpp`、`Mux.hpp` 是合理的共享纯工具，但 `Common` 容易成为所有协议依赖的垃圾抽屉。只有跨多个协议且没有协议语义的地址/读写原语才能放这里；协议-specific frame header、mux marker、carrier magic 应回到协议目录。

## 3.3 `Protocols/Anytls/`

`Anytls/Codec.hpp`、`Conn.hpp`、`Types.hpp` 本身规模适中，但真实服务在 `Composition/AnytlsService.hpp`。这导致 `Anytls::Conn` 和 Composition service 之间存在两套 AnyTLS 会话概念。应确定 `Conn` 是唯一 wire/stream owner，service 只做 adapter，或把真实 command/session 状态完全收回 `Protocols/Anytls`。

## 3.4 `Protocols/Ech/`

ECH keygen/scan 是相对独立 helper，但 public 聚合头没有说明它是否是 carrier admission 的一部分。应明确 cold-path helper、密钥生命周期和失败语义，不要让 ECH helper 变成 runtime protocol registry 的隐式依赖。

## 3.5 `Protocols/Gun/`

`Gun/Grpc.hpp` 868 行同时处理 gRPC framing、HTTP/2 endpoint、header/message/status 语义；`Conn.hpp` 又持有另一套 Transmission wrapper。Gun 是 carrier/HTTP2 adapter，不应和通用 HTTP/2 protocol 共享不透明的“简化”状态。当前 `Composition/Recognition/TlsCandidateFactory.hpp` 还负责 Gun candidate 构造，协议 wire/auth/handler 仍跨层。

## 3.6 `Protocols/Http1/`

这是当前相对改善最大的协议叶：

- `Parser.hpp` 负责 request target/headers。
- `HeaderFields.cpp` 负责头元数据。
- `ForwardRequest.cpp` 负责重写。
- `ForwardRequestTransport.cpp` 负责 body framing/upgrade gate。

当前已经修复/覆盖了旧报告中的关键问题：

- `Proxy-Authorization`、`Proxy-Connection`、`Keep-Alive`、`TE` 不再发往源站。
- absolute-form 会用 authority 生成 Host。
- `Connection` 声明的 hop-by-hop 扩展字段会被过滤。

证据：[`ForwardRequest.cpp`](../../Preview/Protocols/Http1/ForwardRequest.cpp#L58-L173)。

仍需重点测试：

- 同名重复 Host/Connection header。
- `Transfer-Encoding` 与 `Content-Length` 冲突。
- chunk trailer/extension。
- 101 upgrade response 与首个响应 body 的边界。
- HEAD/CONNECT/普通 forward 的组合路径。

不要把 9 月 27 日旧 HTTP-01/02/03 直接作为当前缺陷；应补组合测试确认当前修复没有回归。

## 3.7 `Protocols/Http2/`

`Impl.hpp` 947 行，将 frame dispatch、HPACK、stream/window、settings、writer 和 session lifecycle 聚合在一起；同时 `Http2/Codec.hpp`、`Http2/Frame.hpp`、`Http2/Session.hpp` 又维护多个层级。

问题不是自包含实现本身，而是：

- TrustTunnel、Gun、XHTTP、H2Mux 各自以不同方式消费它。
- `Http3` 又有 QPACK/Huffman 复用，协议层级边界不清。
- 一个 H2 session 变更会重新编译多个 carrier/Composition 头。

应明确 `Http2Core`（frame/codec/state）和 carrier-specific session adapter（Gun/TrustTunnel/XHTTP/H2Mux）。

## 3.8 `Protocols/Http3/`

HTTP/3 NativeClient/NativeServer/Session、QPACK、Huffman、Auth 混在同一 protocol 目录，但 Hysteria2 HTTP/3 authentication 在 `Http3/Auth.hpp` + Composition factory，TUIC 使用 Native QUIC provider，不走同一 session。

主要问题：

- `NativeClient.hpp` 766 行、`Session.hpp` 722 行，provider lifecycle、nghttp3 callback、request/auth/session state 混在一起。
- Hysteria2-specific auth headers 与通用 HTTP/3 session 没有清楚隔离。
- NativeServer callback 和 Composition `OnStream`/`OnDatagram` 的双路消费容易重复或遗漏。

建议拆 `Http3Core`、`Http3ProviderAdapter`、`Hysteria2Http3Auth`，并由 Hysteria2 provider 唯一拥有 stream admission。

## 3.9 `Protocols/Hysteria2/`

### HY2-02：底层旧 Hysteria2 Conn/Dgram 与 Native HTTP/3 生产路径是两套语义

`Hysteria2/Conn.hpp` 自己描述认证/目标/UDP frame 是“简化”，`Hysteria2/Dgram.hpp` 也同时支持自定义 wire 与 `StandardWire_`。真实 QUIC path 使用 `Hysteria2Factory -> NativeServerSession -> Hysteria2::AcceptPacket(provider, Config)`，而 TCP candidate 仍使用 Hysteria2 protocol types/codec。

证据：[`Hysteria2.hpp`](../../Preview/Protocols/Hysteria2/Hysteria2.hpp#L159-L175)、[`Hysteria2Factory.hpp`](../../Preview/Composition/Quic/Hysteria2Factory.hpp#L634-L676)。

必须把“测试简化 wire”和“外部互操作 wire”分成明确 targets/namespace，不能依靠 bool `StandardWire_` 在同一个 Dgram 上切换两套协议。

### HY2-01：认证租约被丢弃

`AuthenticateHysteria2Request()` 调 `Authenticator->Authenticate()`，只读取 `Accepted`，没有保存 `Result.Lease`。

证据：[`Hysteria2Factory.hpp`](../../Preview/Composition/Quic/Hysteria2Factory.hpp#L415-L441)。

这直接违反 [`Foundation/Authenticator.hpp`](../../Preview/Foundation/Authenticator.hpp#L125-L137) 对 runtime lease 的合同。真实 H3 auth 成功后，lease 在临时 `AuthenticationResult` 生命周期结束时释放；后续 Hysteria2 stream/datagram 可以无限持续而不计入账户连接配额。应让 H3 session owner 持有 connection lease，stream relay 只在该 lease 存活时创建。

## 3.10 `Protocols/Tuic/`

TUIC `ConnectionAdmission` 是当前较好的协议 owner 候选：它拥有认证、connection lease、pending/active stream、datagram lifecycle，并且不 include Application/Ingress/Composition。

但仍有三个问题：

1. `Dgram` 忽略 incoming `AssocId/PktId`，见 TUIC-01。
2. `ConnectionAdmission::Create()` 自定义 deleter 用 `dispatch` 把析构投递到 strand；executor 停止后 callback 可能永不执行，且自定义 deleter 没有 catch，理论上 dispatch 异常会在 shared_ptr 析构路径 terminate。证据：[`Admission.cpp`](../../Preview/Protocols/Tuic/Admission.cpp#L45-L63)。
3. `AdmissionServices` 有五个 `std::function`，包括 relay、dial、resolve、datagram exchange、report；这是有领域语义的 provider，但需要明确 cancellation/owner，不应继续往一个 service bag 加字段。

## 3.11 `Protocols/Mux/`

`Mux/Session.hpp` 1,307 行，确实把 frame loop、stream table、incoming queue、write queue、budget、flow control、cancel、teardown 全部放在一个 template class 中。

优点：

- `MaxStreamRxBytes`、`MaxSessionRxBytes`、`MaxPendingWriteBytes` 已有明确预算。
- writer 单 owner，避免帧交错。
- teardown 会清空 stream table/incoming queue。

问题：

- smux/yamux/h2mux 的差异被大量 `if constexpr`、concept detection 和策略静态 API 隐藏，真实状态机仍难读。
- `Session` include `Foundation/SessionBase.hpp`，迁移层尚未消失。
- `Close/Cancel/FrameLoop/WriteLoop` 同时由 Control、detached、StreamHandle 触发，生命周期证据依赖多个 channel。
- 流 ID 单调递增且不复用是安全的，但长连接大量短流会在 `uint32` 耗尽前持续增加，应该把耗尽/连接轮换作为可观察策略。

建议按 `MuxSessionCore`、`MuxWriter`、`MuxFlowControl`、`MuxStreamRegistry` 拆真实编译/owner；不按 600 行机械切片。

## 3.12 `Protocols/Quic/`

### QUIC-02：配置 limits 完全没有进入 NativeConnection

`ServerOptions` 暴露 `MaxStreams`、`MaxDatagrams`：[`Native.hpp`](../../Preview/Protocols/Quic/Native.hpp#L66-L99)。NativeConnection 构造接收并存入 `MaxStreams_`/`MaxDatagrams_`，但全文件只有构造和成员声明，没有任何消费点。

证据：[`Native.cpp`](../../Preview/Protocols/Quic/Native.cpp#L288-L316)；grep 当前只命中这两处。

初始化硬编码：

```cpp
Params.initial_max_streams_bidi = 1024;
Params.initial_max_streams_uni = 1024;
Params.max_datagram_frame_size = 1400;
```

证据：[`Native.cpp`](../../Preview/Protocols/Quic/Native.cpp#L1395-L1448)。

因此配置文件的 `MaxStreams`/`MaxDatagrams` 校验和 readiness 看似有效，实际没有限制 Native QUIC。应在 transport params、stream admission、datagram provider/inbox 三层明确区分协议 advertised limit 和本地 active resource limit。

### QUIC-03：Stream state 永不删除

`MakeStream()` 将每个 stream 放入 `Streams_`；`OnStreamClose()` 只设置 `PeerFin` 和 notify，没有 `Streams_.erase()`。

证据：[`Native.cpp`](../../Preview/Protocols/Quic/Native.cpp#L1913-L1953)、[`Native.cpp`](../../Preview/Protocols/Quic/Native.cpp#L2002-L2010)。

客户端可在一个 QUIC 连接上反复打开/关闭 stream，老的 `StreamState`、received queue、provider 和 weak owner 记录会一直留到连接关闭。即使 QUIC transport 的 simultaneous max 是 1024，也没有 lifetime max；这是长期连接内存增长。

### QUIC-04：callback 路径与 queue 路径双重保存 provider

`MakeStream(Incoming=true)` 总是将 provider 放进 `IncomingStreams_`/`IncomingUnidirectionalStreams_`，随后又调用 `OnStream_`/`OnUnidirectional_` callback。

证据：[`Native.cpp`](../../Preview/Protocols/Quic/Native.cpp#L1921-L1950)。

Hysteria2 NativeServerSession 会调用 `Accept*Stream()` 消费 queue；TUIC factory 则通过 callback 直接把 provider 交给 `ConnectionAdmission`，没有消费 Native queue。TUIC 连接上 queue 会保存每个 stream provider，和 QUIC-03 叠加。

应选一种模式：`Pull`（queue + Accept）或 `Push`（callback），不能默认两边都持有。

### QUIC-05：GatewayCommon 的 authenticated 字段语义错误

`RegisterTypedConnection()` 在连接/ALPN/source 检查后立即写 `State->authenticated = true`，但 Hysteria2/TUIC 的真正认证发生在更晚的 HTTP/3 `/auth` 或 exporter/uni stream 阶段。

证据：[`GatewayCommon.hpp`](../../Preview/Protocols/Quic/GatewayCommon.hpp#L141-L163)。

当前字段生产无读取点，因此不是已证明的认证绕过；但名字和注释会诱导未来代码在协议认证前放行。应拆成 `TransportBound`、`TlsHandshakeComplete`、`ProtocolAuthenticated`，或删除兼容字段。

### QUIC-06：Native QUIC 文件不是单一状态机，而是多个 owner 拼接

`Native.cpp` 2,784 行同时承担：ngtcp2 callbacks、TLS callbacks、socket token、receive/send/pump loop、stream provider、datagram inbox、CID/peer path、handshake readiness、close and callbacks。它应按真实编译单元拆成：

- `NativeConnectionCore`：ngtcp2 state and executor.
- `NativeTlsCallbacks`。
- `NativePacketPump`。
- `NativeStream` / `NativeDatagram`。
- `NativeServer/Client` facade。

不能只把 callback 函数移动到 `Detail/*.inc`，那会制造假边界。

## 3.13 `Protocols/Reality/Restls/Shadowtls/Ws/Xhttp/`

这些是 carrier/stealth 协议，当前主要问题是 owner 分散：

- wire/crypto 在 `Protocols/<Name>`。
- candidate registration 在 `Composition/Recognition/TlsCandidateFactory.hpp`。
- configured carrier builder 在 `Composition/Recognition/*Carrier.hpp`。
- carrier commit/route 在 `Runtime/Recognition`。
- Application 负责把配置转换成 password/dial/TLS context。

其中 `Xhttp/Conn.hpp` 2,108 行、`Ws/Conn.hpp` 972 行、`Shadowtls/Codec.hpp` 721 行，都是完整异步连接状态机，不应被当作普通 codec header。

XHTTP/AnyTLS/TrustTunnel 的 `WireWriter` 都各自实现队列、completion、close、pending write；这说明缺少通用的、有领域语义的 `SerializedWriter` contract。不要做万能 writer service；应抽取明确的“单 executor、FIFO、bounded pending bytes、exactly-once completion”基础组件。

## 3.14 `Protocols/Shadowsocks2022/`

SS2022 codec/Conn/Dgram 已有较完整 wire，但 UDP 真正 listener/gateway 在 `Ingress/Ss2022Gateway.hpp`，TCP candidate 在 `Composition/Recognition/CandidateFactory.hpp`，Application 还另外构造 PSK/account directory。

SS2022 的 `Dgram`/Ingress 两条 UDP 模型没有统一 typed packet contract；一个是 `Transmission` decorator，一个是 peer-keyed shared UDP gateway。应明确“独立 UDP protocol ingress”和“已认证 stream 上的 datagram carrier”是两种不同 capability，不要都叫 UDP service。

## 3.15 `Protocols/Socks5/`

`Codec.hpp` 981 行、`Conn.hpp` 850 行，分别混合地址/认证/请求和 connection/UDP association 生命周期；`UdpAssoc.hpp` 又承担 UDP socket、动态 peer、resolver、idle timer、TCP watch、metrics。

Composition `Socks5` adapter、`Socks5Factory`、Application protocol arrays 再次包装这些状态。建议：

- `Socks5Wire`：greeting/auth/request/reply。
- `Socks5Connection`：TCP handshake/half-close。
- `Socks5UdpAssociation`：UDP session owner。
- adapter：只转成 Runtime typed result。

当前没有发现 SOCKS5 认证绕过，但组合测试应覆盖 deferred reply、UDP control close、client endpoint change。

## 3.16 `Protocols/Vless/Trojan/Vmess/`

三个协议都有相似的 `Conn -> AcceptResult -> DataPlane` 流程，但每个 adapter 仍重复：

- credential/UUID/password 配置。
- AccountId/Identity/Lease 提取。
- TCP/UDP/mux 分支。
- `MaterializeTypedDataPlane()`。

这类重复应收敛到有语义的 `ProtocolAuthenticationResult`，而不是让 `AcceptResult` 同时保存旧字段、typed DataPlane、IsDgram、AccountLease 和 PostDial。

VLESS/Vmess/Trojan 的多账户支持当前主要依赖 `AuthenticatorOwner`，但 Application 仍把 first account 的 UUID/password 放进 Config。配置语义是“目录可多账户”，协议 config 却保留“单 first credential”，应统一。

## 3.17 `Protocols/Trusttunnel/`

`Trusttunnel/Http2.hpp` 1,016 行，标准 HTTP/2 CONNECT、Basic auth、DATA stream 和 close 都在一个文件；`Composition/Recognition/TrusttunnelCandidate.hpp` 和 `Composition/Adapters/Trusttunnel.hpp` 又分别做 carrier/adaptor。

`TrustTunnel` 是“协议承载 + 认证 + data plane”组合，不适合被 ProtocolCatalog 直接当普通 TCP protocol 或被 `UdpService` 当普通 UDP capability。建议明确 `Carrier -> InnerProtocol` 两阶段 typed result。

## 3.18 `Protocols/Native/`

Native protocol 叶较小，但 `NativeTls` 实际在 Transport，Native carrier 注册在 Application/Composition，名字容易与 `Protocols/Quic/Native` 混淆。建议命名区分 `PlainTcp`、`NativeTlsCarrier`、`NativeQuic`。

---

# 四、`Runtime/` 审查

## 4.1 `Runtime/Session.hpp` 是第二个 god object

当前 1,499 行，承担：

- raw ingress TLS probe/upgrade。
- Recognition profile/legacy dual path。
- carrier commit。
- ProtocolAccept。
- Context/DataPlane materialization。
- generic auth。
- mux/pad。
- datagram service。
- dial/outbound decorator。
- PostDial response。
- relay。
- logging/audit/close。

证据：[`Session.hpp`](../../Preview/Runtime/Session.hpp#L338-L411)、[`Session.hpp`](../../Preview/Runtime/Session.hpp#L704-L1059)、[`Session.hpp`](../../Preview/Runtime/Session.hpp#L1082-L1214)。

建议让 Session 只做生命周期和阶段编排，建立以下 typed boundaries：

```text
IngressTransport -> RecognitionResult
RecognitionResult -> ProtocolSession
ProtocolSession -> ProtocolDataPlane
ProtocolDataPlane -> StreamPlan/DatagramPlan/MuxPlan
Plan -> Dial/Relay owner
```

## 4.2 SessionOptions/SessionServices/Context 有四份事实

`SessionOptions` 同时支持 `Services` 和 legacy 字段；`SessionServices` 再保存 `ResolveCandidate`/`Resolver`、`AcceptProtocol`、`UdpService`、`Mux`、`Dial`；`Context` 同时保存 `DataPlane` 与 `Target/AccountId/identity/AccountLease/ProtocolAuthenticated/Inbound`。

证据：[`Session.hpp`](../../Preview/Runtime/Session.hpp#L66-L109)、[`SessionServices.hpp`](../../Preview/Runtime/SessionServices.hpp#L53-L103)、[`Context.hpp`](../../Preview/Runtime/Middleware/Context.hpp#L47-L112)。

`SetDataPlane()`/`SynchronizeDataPlane()` 是双向同步机制，允许 canonical variant 和兼容字段分别被修改。长期结果是：

- 认证状态可以在两个位置不一致。
- target/identity/lease 可能有两个 owner。
- Inbound 既是 Context 字段又是 DataPlane transport。
- `Resolver` 和 `ResolveCandidate` 同义并存。

整改顺序：先锁定一个 `SessionPlan`，再删除 legacy fields，最后才拆 Session 文件。

## 4.3 Middleware 不是所有 gateway 的统一抽象

现有 Middleware 以 `SharedTransmission` 为核心，适合 Auth/Dial/Mux/Pad/Relay。QUIC gateway 需要 CID、ALPN、connection、stream provider、datagram provider、TLS exporter、peer/drain 生命周期，不能直接塞进现有 `Middleware::Context`。

正确做法是两类 typed pipeline：

- `StreamPipeline`：可靠字节流阶段。
- `CarrierAdmission`：TCP carrier/QUIC connection/CID 阶段。

不要为了统一接口制造一个包含 socket、CID、target、lease、provider、datagram callback 的万能 context。

## 4.4 Runtime Front 应该二选一

如果 Runtime Front 是未来正式 API，就要由 Application 使用它并删除 Ingress 重复入口；如果 Ingress 是正式入口，就把 Runtime Front 降为合同测试/experimental target，并从 PreviewRuntime public source 和 production include graph 移除。

---

# 五、未接线、重复和疑似无用代码

下面不是“代码一定应该删除”，而是当前仓库内没有真实 production caller，必须定性：接入、实验隔离或退役。

| 模块 | 当前调用情况 | 判断 |
|---|---|---|
| `Runtime/Front/UdpFront.hpp` | Application 不构造；主要是 Front 合同/集成测试 | 与 Ingress 二选一 |
| `Runtime/Front/QuicFront.hpp` | Application 不构造；Health 明确返回 Unsupported | 实验/contract-only |
| `Foundation/Utility/Coroutine/Registry.hpp` | 生产调用集中在 Lifecycle registry；主要测试/聚合头 | 迁移后删除 |
| `Composition/Api/ApiManager.hpp` | 生产无 Application caller，Statistics benchmark 使用 StatisticsApi | 接线或隔离 |
| `Composition/Api/OperationsApi.hpp` | 生产 Operations server 直接使用 Router/Models | 不是当前正式入口 |
| `Net/Route/Route.hpp`/`Net/Outbound/Outbound.hpp` | 生产 Application 直接 Dialer/WorkerDialService | 接入 route snapshot 或实验隔离 |
| `Configuration/ReloadCoordinator.hpp` | 无真实 Application reload caller | 不要宣传已支持热 reload |
| `Runtime/Middleware/Builtin/Throttle.hpp` 的 Throttle/Ban | Session production pipeline 未实例化；主要 RateLimit tests | dormant；生产接入前要修并发/增长 |
| `Composition/Builtin` 的多个 wrapper | metadata callback 有调用；不是 protocol handler registry | 改名/缩小 API |
| `GatewayCommon::GuessProtocol()` | 设计为始终 Unknown，主要测试 | 删除看似 detector 的兼容 API |
| `AcceptTyped()/ToTypedResult()` | 全树无 production caller | 修正租约语义或退役 |

### DORMANT-01：BanMiddleware 激活前有明显风险

[`Throttle.hpp`](../../Preview/Runtime/Middleware/Builtin/Throttle.hpp#L101-L198)：

- `NowFn_` 可为空，`RecordFailure()`/`IsBanned()` 直接调用。
- `Failures_`/`Banned_` 普通 unordered_map，无并发保护。
- 过期 banned entry 只在查询时返回 false，不 erase。
- attacker 可持续制造新 key，状态无上限。
- `MaxFailures_ == 0` 时第一次失败立即封禁所有 key。

当前未接入 production pipeline，因此这是激活前 P2/P3，不应写成现行请求路径 race。

---

# 六、测试树审查

## 6.1 测试规模和文件耦合

当前 `tests/Preview/`：416 文件、326 C++ 源，87 个超过 500 行，19 个超过 1,000 行。最大文件包括：

| 文件 | 行数 | 混合职责 |
|---|---:|---|
| `core/Configuration/ConfigurationTest.cpp` | 2,385 | JSON、typed decode、validator、secret、generation |
| `core/Application/ApplicationTest.cpp` | 1,888 | startup、failure、listener、UDP/QUIC、shutdown |
| `protocols/stealth/anytls/AnytlsSessionDeep.cpp` | 1,834 | auth、frame、mux、relay、close |
| `core/transport/TransportDecoratorCoverage.cpp` | 1,811 | encryption、padding、EOF、half-close、decorator |
| `core/recognition/MixedTrialModeTest.cpp` | 1,575 | candidate budget、race、cancel、commit |
| `core/recognition/ConfiguredModeTest.cpp` | 1,505 | route、profile、configured candidate |
| `protocols/stealth/misc/StealthVmessErrorCoverage.cpp` | 1,448 | 多 protocol error matrix |
| `core/fuzz/DgramErrorCoverage.cpp` | 1,388 | generated cases + error coverage |
| `core/recognition/TlsReassemblyTest.cpp` | 1,366 | TLS record、ClientHello、fragment/error |
| `protocols/http/Http11ConnectTest.cpp` | 1,365 | HTTP parser、forward、CONNECT、response |
| `core/runtime/MuxServiceTest.cpp` | 1,210 | mode、stream、task、shutdown |
| `protocols/tuic/TuicAdmissionTest.cpp` | 1,171 | auth、pending、stream、datagram、close |

测试大文件的问题不是“每个 TEST 必须独立一个文件”，而是 fixture、wire vector、生命周期和真实 E2E 共用同一个 target；一个 include 改动会重编译大量无关场景，失败定位和评审成本高。

建议按行为拆：

- codec grammar/vector。
- auth/lease。
- session normal/half-close。
- cancel/drain/owner destruction。
- Application assembly。
- real interop。

## 6.2 测试路径和真实路径不是同一合同

- Runtime Front 集成测试验证 `UdpFront/QuicFront`，Application 测试验证 `Ingress/UdpListener/QuicGateway`；二者通过不等价。
- protocol factory tests 不等价于真实 listener + recognition + auth + lease + relay + shutdown。
- 当前没有覆盖 QUIC unknown short header 不创建 server 的负向测试。
- 当前没有覆盖 Native QUIC stream close 后 `Streams_` 回收、MaxStreams/MaxDatagrams 配置真正生效的测试。
- 当前没有覆盖 Hysteria2 auth lease 在 `/auth` 后保持到连接关闭的测试。
- 当前没有覆盖 TUIC non-zero association id round-trip 的测试。
- 当前没有覆盖 `Application::Start()` profile build error 后 State/Diagnose/资源完全回滚的测试。
- 当前没有覆盖 VLESS XUDP/AnyTLS 的 flow/stream count 上限和 idle reap。
- 当前没有把当前 HTTP forward fix 作为完整 handler -> upstream 组合测试固定下来，只测 helper 会再次留下回归空间。

## 6.3 没有运行测试

本次按要求没有构建和运行测试，因此不能报告以下内容：

- 当前源码能否编译。
- CTest 是否通过。
- QUIC/HTTP3/TUIC/Hysteria2 外部互操作。
- 并发、取消、executor stop、Windows 行为。
- 任何性能结论。

本报告中的“可达”指源码调用链可到达，不等于本次已运行复现。

---

# 七、已复核但当前不应误报的旧问题

## 7.1 HTTP forward 旧问题当前已有修复

旧审查中 HTTP-01/02/03 的问题是：认证后的 `Proxy-Authorization` 泄露、absolute-form Host 与拨号 authority 不一致、hop-by-hop header 泄露。当前 `ForwardRequest.cpp` 已显式处理：

- `IsAlwaysHopByHop()` 过滤 `proxy-authorization`、`proxy-connection`、`keep-alive`、`te`。
- `Connection` token 指定的字段过滤。
- absolute-form 重新生成 authority Host。
- forward body 由 `ForwardRequestTransport` 定界。

证据：[`ForwardRequest.cpp`](../../Preview/Protocols/Http1/ForwardRequest.cpp#L58-L173)、[`Conn.hpp`](../../Preview/Protocols/Http1/Conn.hpp#L203-L238)。

仍需测试组合路径，但不能把它们继续写成当前已确认的 HTTP 漏洞。

## 7.2 SessionRegistry CAS 移动问题当前已修正

当前 `Register()` 使用 `Record{Info, Entry}` 拷贝 `Info`，不是旧报告中的 `std::move(Info)` 后 CAS 重试；因此不应继续报告“CAS 失败会把 SessionInfo 移空”。仍需保留 low-memory compaction 的测试，但旧具体缺陷不再成立。

## 7.3 QuicAdmissionContext 旧 god-context 已不在当前文件树

当前 `Ingress/` 已没有旧 `QuicAdmissionContext.hpp`；QUIC binding 主要由 `QuicCidRegistry`、Native Server options 和 Composition factories 组成。跨层协议状态仍存在，但不能引用已删除的旧 context 作为当前文件问题。

---

# 八、建议的重构目标

## 8.1 先锁定四条硬边界

```text
Protocols/<Name>
  wire / codec / auth / protocol session / stream & datagram owner / close

Composition
  manifest / config compile / capability check / typed prepare-bind-start / rollback

Ingress
  socket / packet classify / CID map / ingress drain / close

Runtime
  worker / listener / session lifecycle / cancellation / generic stream plan

Application
  only generation -> assembly -> publish -> rollback -> drain -> join
```

允许协议特殊，但特殊性必须通过 typed provider 表达，而不是把协议 fields 塞进 Ingress 或 Application 的万能 context。

## 8.2 分阶段迁移顺序

### 阶段 0：基线和证据

- 保存当前 dirty state、当前大文件清单、CMake target closure。
- 给每个 public type 建 `owner -> caller -> executor -> close -> tests` 表。
- 重新验证所有旧报告，尤其是已经变化的 Application/HTTP/QUIC 文件。

### 阶段 1：先修当前 P1/P2

优先处理：

1. unknown QUIC short header fail-closed。
2. QuicCidRegistry key cleanup。
3. Native QUIC limits 真正接入，stream close erase，callback/queue 二选一。
4. Hysteria2 auth lease owner。
5. TUIC association id/packet id round-trip。
6. Application profile failure rollback。
7. VLESS XUDP/AnyTLS bounded state。
8. Pipeline null contract。
9. TypedResult lease moved-from bug。

每项先加 focused negative/regression test，再改结构。

### 阶段 2：按协议竖切 QUIC/UDP/AnyTLS

- Hysteria2：`Protocols/Hysteria2/Service` 拥有 auth lease、HTTP/3 stream/datagram session；Composition 只注入 dial/resolve/metrics。
- TUIC：保留 `ConnectionAdmission` 作为协议 owner；Composition 只提供 factory binding。
- SS2022：把 PSK/replay/packet wire 放回协议 provider，Ingress 只提供 peer/socket。
- VLESS：把 XUDP flow map、limits、relay 放回 VLESS service。
- AnyTLS：把 command/stream map/lifecycle 放回 Anytls service，并定义 max stream/close。

### 阶段 3：收敛 Runtime data contract

- 生成不可变 `SessionPlan`：profile、provider、timeouts、dial service。
- 每会话 `SessionContext` 只保存 input、target、lease、control、transport、traffic handle。
- 删除 `SessionOptions`/`SessionServices` 的 legacy alias/raw pointer 双轨。
- `ProtocolDataPlane` 成为唯一 target/account/auth/lease/transport 来源。

### 阶段 4：清理入口和 build graph

- 决定 Runtime Front 与 Ingress 的唯一正式入口。
- 每个模块拥有自己的 CMake source/target declaration。
- boundary checker 增加 source include edge 检查。
- 非模板状态机建立真实 `.cpp` owner。
- 旧 Coroutine Registry、Route/Outbound 未接线 API、未使用 ApiManager 分别定性。

### 阶段 5：Application/Operations 瘦身

- Application 保留顺序、发布、逆序 rollback、drain、join。
- Operations 拆 `HttpConnection`/parser/router/server。
- 配置 reload 要么完整接线，要么从正式 API 移出。

### 阶段 6：测试和验收

分开报告：

1. 源码边界检查。
2. 构建。
3. focused unit/contract tests。
4. 全量 CTest。
5. 真实 Application request path。
6. 外部互操作。
7. stress/perf。
8. shutdown/resource cleanup。

每条证据绑定当前源码、配置、二进制和 dirty state。

---

# 九、最终判断

Preview 当前不是“把几个超长文件拆小”就能解决的项目。最核心的设计错误是：

> 协议模块拥有了 wire，却没有拥有完整的协议生命周期；Composition/Application/Ingress/Runtime 通过回调、字符串、dynamic cast 和兼容字段把缺失的生命周期拼回来。

这会造成三个后果：

1. **正确性风险：** lease、close、half-close、CID、datagram association、stream state 在不同 owner 之间转移，最容易出现 HY2-01、TUIC-01、QUIC-02 这类问题。
2. **扩展风险：** 新协议必须修改 central enum、validator、candidate registry、Application switch、UDP factory、QUIC context/factory、CMake target 和测试矩阵。
3. **验证风险：** contract test、factory test、Runtime Front test、Application integration test 各自通过，却不能证明真实请求路径一致。

建议先处理上面的 P1/P2，并以 QUIC/TUIC/Hysteria2 这一条真实复杂竖切作为边界重构样板；随后再迁移 UDP/XUDP/AnyTLS，最后处理 Session、Application、Operations 和 CMake。不要先做全树机械改名或纯行数拆分。

