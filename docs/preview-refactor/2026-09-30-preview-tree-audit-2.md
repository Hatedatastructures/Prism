# Preview 树型全面问题清单（下一代实现结构审查）

> 文档状态说明（2026-10-05）：本文保留原版本的分析、计划或验收快照，文中的“当前”、完成标记、路径和测试数字均属于原记录时点。今天的 Preview 入口、已执行范围与剩余责任见[开发入口](../../Preview/README.md)和[当前执行状态](2026-10-03-preview-no-compat-status.md)。本轮不改写原始历史结果；旧任务提示词需先核对现行 AGENTS.md、无兼容层计划和真实源码，不能直接替代当前任务卡。
<!-- pathcheck:historical=本文含 2026-10-05「本轮不改写原始历史结果」声明；文中行号按当日源码求值，已随文件拆分漂移（例：Encrypted.hpp 现 130 行） -->

> 审查时间：2026-09-30
> 源码版本：commit `3c5b678f`（`wip(preview): snapshot current changes and architecture review`）+ 工作树 202 个脏文件（`git status --porcelain` 计数），其中 `Preview/Application/TuicAdmission.hpp` 处于删除状态、`Preview/{Application,Composition,Protocols,Runtime}/…` 多数模块有未提交改动。
> 审查方式：只读静态分析。12 个并行分片审查 + 主 agent 的全树度量（include 图、编译闭包、函数长度、规范扫描）+ 关键结论逐条回读源码复核。
> **未做**：未配置/构建、未运行任何测试或二进制、未做外部互操作与性能测量。因此本报告不声称 Preview 能编译、测试通过、行为正确或性能达标。
> "可达"指从 `Preview/Application/Main/PreviewMain.cpp → Application::Start()` 的真实调用链在源码上可到达，不等于已运行复现。

## 0. 分级与类别

| 级别 | 含义 |
| --- | --- |
| P1 | 现行可达的安全/数据正确性缺陷（未认证转发、越界、认证绕过、活锁、ODR） |
| P2 | 真实路径上的正确性、资源或可用性缺陷（配额失效、无上限、回滚缺失、静默丢弃） |
| P3 | 结构问题（owner 错位、耦合、双轨、重复、未接线） |
| P4 | 规范与可维护性（长度上限、命名、注释、默认参数、编译耦合） |

类别：**A** = 缺陷（行为错误）、**B** = 结构/耦合、**C** = 死代码/重复/规范。

---

## 1. 全树度量基线

### 1.1 规模

`Preview/` 共 **442 个文件**，其中 **436 个 C++ 源（412 `.hpp` + 24 `.cpp`）、121,186 行**；另有 `CMakeLists.txt` 919 行、`CMake/PreviewBoundary.cmake` 666 行、`Preview/Application/CMakeLists.txt` 90 行、配置 JSON、2 个 README。

| 模块 | 行数 | 文件 | 模块 | 行数 | 文件 |
| --- | ---: | ---: | --- | ---: | ---: |
| `Protocols/` | 52,407 | 168 | `Account/` | 1,889 | 9 |
| `Runtime/` | 13,545 | 39 | `Lifecycle/` | 1,629 | 6 |
| `Composition/` | 13,226 | 51 | `Scheduler/` | 1,429 | 5 |
| `Foundation/` | 10,833 | 64 | `Statistics/` | 975 | 10 |
| `Application/` | 9,706 | 27 | `Resource/` | 515 | 6 |
| `Net/` | 5,672 | 22 | `Performance/` | 239 | 2 |
| `Transport/` | 4,081 | 12 | `Ingress/` | 2,123 | 8 |
| `Operations/` | 2,917 | 8 | | | |

`.hpp : .cpp = 412 : 24`。协议状态机、Composition 服务、Runtime 会话、Lifecycle registry 几乎全部是 header-only inline：`PreviewRuntime` 的唯一编译单元是 `Mailbox.cpp`（P4 编译耦合，见 §6.4）。

### 1.2 超长文件分布（按真实行数 `wc -l`）

- **≥500 行：64 个文件**（Protocols 37、Composition 9、Runtime 8、Net 3、Application 2、Transport/Scheduler/Operations/Lifecycle/Foundation 各 1）
- **≥800 行：22 个**；**≥1000 行：10 个**
- 前 20 个文件占全树 **23%**（29,026/121,186 行），前 64 个文件占 **46%**（56,579 行）

≥1000 行的 10 个文件：

```
4925 Preview/Application/Application.cpp                 1499 Preview/Runtime/Session.hpp
2784 Preview/Protocols/Quic/Native.cpp                   1307 Preview/Protocols/Mux/Session.hpp
2108 Preview/Protocols/Xhttp/Conn.hpp                    1281 Preview/Runtime/Recognition/Profile.hpp
1938 Preview/Application/Configuration/ConfigurationValidator.hpp
1020 Preview/Runtime/Recognition/ConfiguredMode.hpp      1016 Preview/Protocols/Trusttunnel/Http2.hpp
1877 Preview/Operations/HttpServer.cpp                    868–986 段：Composition/AnytlsService.hpp(986)、
                                                            Protocols/Socks5/Codec.hpp(981)、Ws/Conn.hpp(972)、
                                                            Shadowsocks2022/Conn.hpp(957)、Http2/Impl.hpp(947)、
                                                            Composition/Recognition/CandidateFactory.hpp(941)、
                                                            Protocols/Vmess/Conn.hpp(908)、Gun/Grpc.hpp(868)、
                                                            Http1/ForwardRequestTransport.cpp(861)
```

500–800 行区间另有 44 个文件（`Socks5/Conn.hpp 850`、`Reality/Codec.hpp 837`、`TlsCandidateFactory.hpp 800`、`Settings/Loader.hpp 766`、`Vmess/Auth.hpp 746`、`Runtime/Listener.hpp 742`、`Tuic/Conn.hpp 742`、`Shadowtls/Codec.hpp 721`、`MixedTrialMode.hpp 716`、`TaskRegistry.hpp 710`、`SessionRegistry.hpp 695`、`Recognition/Tls.hpp 689`、`Dns/Upstream.hpp 676`、`MuxService.hpp 658`、`Vmess/ChunkCodec.hpp 657`、`Reality/Carrier.hpp 656`、`Vless/Codec.hpp 655`、`Hysteria2Factory.hpp 647`、`Unreliable.hpp 635`、`Hysteria2/Conn.hpp 635`、`Shadowtls/Conn.hpp 634`、`SS2022/RequestCodec.hpp 634`、`Http3/Session.hpp 632`、`Trojan/Codec.hpp 619`、`UdpService.hpp 618`、`SS2022/ResponseCodec.hpp 599`、`Resolver.hpp 591`、`SessionControl.hpp 590`、`Http3/NativeClient.hpp 589`、`Dns/Format.hpp 589`、`ForwardResponseFraming.cpp 575`、`Hysteria2/Dgram.hpp 573`、`Restls/Conn.hpp 564`、`Http2/Codec.hpp 564`、`Trojan/Conn.hpp 557`、`ContextDecoder.hpp 553`、`VlessXudp.hpp 544`、`Restls/Codec.hpp 539`、`Hysteria2/Codec.hpp 524`、`Yamux/Codec.hpp 521`、`Tuic/Admission.cpp 520`、`SS2022/ChunkCodec.hpp 518`、`Vmess/RequestCodec.hpp 514`、`FairScheduler.hpp 507`、`H2MuxServer.hpp 502`）。

行数不是坏代码的单独证明；这里的实质问题是这些文件同时承载状态机、所有权、协议策略与构建归属（§4 各节的逐文件证据）。

### 1.3 超过 120 行上限的函数（AGENTS.md Rule 3）

工具口径（brace 深度 + 签名识别，偏保守）确认的硬超限：

| 行数 | 函数 | 位置 |
| ---: | --- | --- |
| 874 | `Session::RunCore()` | `Preview/Runtime/Session.hpp:341-1214` |
| 731 | `Application::Start()` | `Preview/Application/Application.cpp:4121-4851` |
| 572 | `ConfigurationValidator::Validate()` | `Preview/Application/Configuration/ConfigurationValidator.hpp:65-636` |
| 239 | `MakeTcpCandidateRegistry()` | `Preview/Application/Application.cpp:2546-2784` |
| 144 | `ParseClientHello()` | `Preview/Protocols/Reality/Carrier.hpp:172-315` |
| 139 | `AcceptPreparedReality()` | `Preview/Composition/Recognition/RealityPrepared.hpp:43-181` |
| 136 | `MakeRuntimeAcceptors()` | `Preview/Application/Application.cpp:2407-2542` |
| 135 | `ParseRequest()` | `Preview/Operations/HttpServer.cpp:1580-1714` |

分片审查补充（多行签名、协程体）：`ValidateCarrier` 373 行（`ConfigurationValidator.hpp:1490-1863`）、`MixedTrialMode::Recognize` ~203（`Runtime/Recognition/MixedTrialMode.hpp:98-301`）、`RecognizeLegacy` ~164（`Recognition.hpp:136-300`）、`RedactSensitiveText` 122（`Statistics/Redaction.hpp:96-217`）、`ConfiguredMode::Recognize` ~141（`ConfiguredMode.hpp:632-773`）、`HttpHandler::Accept` 126（`CandidateFactory.hpp:520-643`）、`VlessXudp::Run` 132（`VlessXudp.hpp:411-542`）、`AcceptLoop` 132（`Listener.hpp:576-705`）、`Listener` 会话注册段 130、`RelayDirection` 101（`Middleware/Builtin/Relay.hpp:133-233`）、`Ss2022 ResponseCodec` UDP 解析 146（`ResponseCodec.hpp:452-597`）、`Ws` 帧读取 162（`Ws/Conn.hpp:467-628`）、`Xhttp` 握手等待 155（`Xhttp/Conn.hpp:955-1109`）、`Mux/Session` 帧循环 147（`Mux/Session.hpp:956-1102`）、`Http3/Session` 161、`Http2` HPACK 解码 140、`Shadowtls/Server` relay 151、`Restls async_read_some` 147、`Yamux/Codec` 239、`Shadowtls/Codec` 221、`Socks5` 消息解析器 204（`Codec.hpp:685-888`）、`Dns/Cache` 310、`TokenBucket` 216、`GatewayCommon` 309、`Transmission/Reliable` 类级 345/362。另有 32 个 80-119 行的函数贴近上限。

超 10 行 lambda（Rule 13）抽样：`Application.cpp:236-301`（66）、`Session.hpp:509-618` `WriteRecognition`（110）、`AnytlsService.hpp:705-775`（71）、`TlsCandidateFactory.hpp:183-233`（59）、`UdpService.hpp:70-115`（46）、`ProtocolAdapter.hpp:67-115`（48）、`Hysteria2Factory.hpp:464-495`（32）、`Admission.cpp:85-99/120-138/144-165`、`Route.hpp:92-104`、`ContextState.hpp:370-382`。

### 1.4 模块级 include 边（只统计跨模块，已排除自环）

```
56 Composition -> Protocols     41 Composition -> Runtime     22 Application -> Composition
41 Runtime -> Foundation        26 Runtime -> Transport        18 Transport -> Foundation
11 Composition -> Transport      9 Application -> Foundation    6 Runtime -> Net
 6 Composition -> Net            6 Foundation -> Statistics     5 Runtime -> Account
 5 Protocols -> Account          5 Application -> Protocols     5 Application -> Ingress
 4 Runtime -> Composition         4 Composition -> Account      3 Protocols -> Composition
 3 Runtime -> Protocols           3 Application -> Statistics   2 Ingress -> Protocols
 2 Lifecycle -> Resource          2 Resource -> Net             1 Protocols -> Runtime
 1 Foundation -> Transport        1 Foundation -> Account       1 Transport -> Statistics
 1 Composition -> Operations      1 Ingress -> Net              1 Statistics -> Foundation
```

其中 **18 条是 AGENTS.md 明确禁止的方向**（逐文件行号见 §3.2）。

### 1.5 编译闭包：哪些 Preview 文件根本没进 PrismPreview

以 22 个生产 `.cpp`（`Performance/*` 2 个 bench 除外）为根，沿 include 图做传递闭包：**360 / 436 个文件在闭包内，76 个不在**。不在闭包内的文件（部分明显是"另一套实现"）：

```
按模块：Protocols 21 / Foundation 20 / Composition 8 / Scheduler 5 / Runtime 5 / Resource 3
        Operations 3 / Net 3 / Transport 2 / Statistics 2 / Performance 2 / Lifecycle 1 / Ingress 1
代表项：Runtime/Front/{UdpFront,QuicFront}.hpp        Runtime/Middleware/Builtin/Throttle.hpp
        Runtime/Recognition/ProbeDefense.hpp          Runtime/Statistics.hpp
        Scheduler/{FairScheduler,PriorityScheduler,Types,Detail/FixedTable}.hpp
        Net/{Route/Route,Outbound/Outbound,UdpRelay}.hpp  Transport/{MemoryStream,Algorithm}.hpp
        Ingress/UdpAssociation.hpp                    Resource/{Session,Stream}Resources.hpp
        Composition/Api/*（4 个）                      Composition/Adapters/{Hysteria2,Tuic}.hpp
        Composition/Recognition/AnytlsCarrier.hpp      Protocols/Ech/*（4 个）
        Protocols/Http2/Stream.hpp                     Protocols/Quic/GatewayCommon.hpp
        Protocols/Http3/NativeClient.hpp               Protocols/Native/{Conn,Types,Native}.hpp
        Protocols/{Restls,Shadowtls,Trusttunnel,Tuic}/*Carrier|*Conn|*Dgram|聚合头
        Foundation/Utility/{Coroutine/Registry,Account/Authenticator,Rate/TokenBucket,
                            Diagnose/Observability,Crypto/{X25519,Blake3,Block,Sha224}}.hpp
        Foundation/Exception/*（4 个）                 Foundation/CodecTraits.hpp
```

### 1.6 include 扇入热点（改一行触发重编译的范围）

```
133 Preview/Transport/Transmission.hpp        85 Preview/Transport/MemoryStream.hpp（仅测试）
120 Preview/Foundation/Error.hpp              83 Preview/Foundation/Fault/Code.hpp
 51 Preview/Foundation/Memory/Container.hpp    45 Preview/Foundation/Fault/Handling.hpp
 45 Preview/Runtime/Middleware/Context.hpp     40 Preview/Foundation/Authenticator.hpp
 36 Preview/Net/Dialer/Dialer.hpp              35 Preview/Foundation/ByteSpan.hpp
 34 Preview/Transport/Reliable.hpp             27 Preview/Runtime/Session.hpp
 23 Preview/Protocols/Socks5/Socks5.hpp        21 Preview/Foundation/Utility/Diagnose/Facade.hpp
```

### 1.7 规范扫描

- **注释语言**：全树注释行约 17,000 行，非中文行极少（`Foundation` 1/3258、`Application` 3/219、`Protocols` 3/8687）。**总体合规**；但分片复核在 `MixedTrialMode.hpp:2-4`、`ConfiguredMode.hpp:45-67/327-331`、`Profile.hpp:1276-1277`、`Recognition.hpp:63-66`、`AnytlsService.hpp:3-5`、`UdpService.hpp:3`、`MuxService.hpp:3`、`Http3/{Auth,Session,Server,NativeServer,NativeClient}.hpp`、`Hysteria2/Http3Auth.{hpp,cpp}:3`、`Native.cpp:885-887/1564-1568`、`Ingress/UdpDemux.hpp:249-251` 仍有英文注释与英文 `@brief`。
- **磁盘上有 22 个空 `Detail/` 目录**（`Application/`、`Application/Configuration/`、`Composition/`、`Composition/Recognition/`、`Composition/Settings/`、`Lifecycle/`、`Operations/`、`Runtime/`、`Runtime/Recognition/`、`Protocols/{Gun,Http2,Hysteria2,Mux,Quic,Shadowsocks2022,Shadowtls,Socks5,Trusttunnel,Tuic,Vmess,Ws,Xhttp}/Detail`）。**更正（§10.2）**：git 不跟踪空目录，`git ls-files Preview` 里只有 14 个 `Detail/` **文件**（`Foundation/Utility/Diagnose/Detail/*`、`Net/Dns/Detail/*`、`Protocols/Http3/Detail/Varint.hpp`），因此这 22 个空目录是**本地工作树残留，不是仓库缺陷**，不计入问题清单；真正的 AGENTS.md 风险点是已跟踪的 `Detail/` 是否被用来拼装假边界 —— 抽查结果是：`Diagnose/Detail/*` 是普通内部实现头（有独立 include guard 与类型定义，非 `.inc` 文本片段），合规。
- **协程纯度**：全树 `std::mutex`/`lock_guard`/`scoped_lock`/`unique_lock`/`this_thread::sleep_for`/`getaddrinfo`/`condition_variable` **0 命中**；`std::function` 声明集中在 §3.5 列出的 service bag 文件。
- **RTTI**：`dynamic_cast`/`dynamic_pointer_cast` 20 处，热路径集中在 `Composition/UdpService.hpp`（4）、`Transport/Transmission.hpp`（3）、`Protocols/{Vmess,Shadowsocks2022}/Dgram.hpp`（各 2）、`Application.cpp`、`Session.hpp`、`Adapters/{Trusttunnel,TypedResult,DataPlane}.hpp`、`Composition/{AnytlsService,H2MuxServer}.hpp`、`Runtime/Contract/Handler.hpp`。
- **忙等自旋**：`while(...load())` 6 处 —— `Application.cpp:4106`、`Ingress/UdpListener.hpp:286`、`Lifecycle/DrainBarrier.hpp:196`、`Net/Dns/Detail/Maintenance.hpp:32`、`Net/Dns/Upstream.hpp:615`、`Operations/HttpServer.cpp:1474`（多数是 futex/条件等待而非纯自旋，但 `Account/Directory.hpp:197` 是真无界自旋，见 §4.2）。
- **`catch (...)`**：158 处；确认的空体吞异常点：`Transport/Encrypted.hpp:388-395`、`SinkSet.hpp:69-75/258-261`、`Listener.hpp:348-350`、`Native.cpp:2088-2101`、`Application.cpp` 多处 `catch(...) {}`。
- **命名残留**：`SessionOptions` 的 `timeout/identity/peer/routes` 等小写字段（`Session.hpp:80,98-106`、`Context.hpp:66-110`、`Relay.hpp:84-85`、`Handler.hpp:33-53`、`GatewayCommon.hpp:77`、`Hysteria2/Tuic Types.hpp:64-66/102-104`、`MuxService.hpp:574`、`SessionRegistry.hpp:39-40`）与 PascalCase 新字段并存，同一结构体内新旧混用，违反"同一文件内禁止新旧混用"。
- **`namespace Detail` vs `namespace detail`**：`CandidateFactory.hpp:95`（小写）对 `Hysteria2Factory.hpp:93`、`RestlsCarrier.hpp:41`（大写）—— 同目录同层两种写法。

---

## 2. 结论摘要（你的判断是对的，但根因不止"文件长"）

1. **协议模块只拥有 wire，不拥有协议生命周期。** 每个协议的"网关/service/relay/admission/CID/datagram/auth"实际散在 `Composition/`、`Application/`、`Ingress/`、`Runtime/` 四处（§3.1 有竖切对照表）。所以新增一个协议要动 10-12 个中央点，而这些点各自维护一份"能力事实"，漂移已经发生（§4.4/§4.5）。
2. **模块边界是纸面的。** 根因是 `ConfigurePreviewTarget()` 给每个 Preview target 加了 `INTERFACE ${CMAKE_SOURCE_DIR}` 全局 include 目录（`Preview/CMakeLists.txt:4-10`）——任何头都能 include 任何头，`PreviewBoundary.cmake` 只校验声明的 link 边，因此 18 条禁止方向的 include 全部编译通过。更糟的是允许表本身已被写死让步：`PreviewIngress` 的白名单显式包含 `PreviewProtocolQuic/QuicNative/Shadowsocks2022`，注释写"C04/P1 过渡"（`PreviewBoundary.cmake:242-249`）。
3. **存在两套并行系统且都对外宣称为正式实现**：入口两套（`Ingress::UdpListener/QuicGateway/QuicCidRegistry` vs `Runtime::Front::{UdpFront,QuicFront}`）、任务注册表两套（`Lifecycle::TaskRegistry` vs `Foundation::Utility::Coroutine::Registry`）、认证器三套（`Account::DirectoryAuthenticator` 同名两类、`Foundation::Authenticator`、`Foundation::Utility::Account::*`）、carrier 两套（`Composition/Carrier/FacadeCarrier` 与 `Recognition/*Carrier`/`Server`）、UDP 三套（`Ingress::Ss2022Gateway`、`Ingress::UdpAssociation`、`Composition::UdpService`）、配置解析两套（glaze 主路径 vs `Composition/Settings/Json+Loader`）、HTTP/3 两套（nghttp3 vs 自研 QPACK）、Hysteria2 wire 三套。**436 个文件里 76 个不在生产编译闭包内，16 个 0 扇入**（§5）。
4. **P1 级缺陷确实存在，但只有 3 条经得起逐行复核**：未认证的 Hysteria2 QUIC DATAGRAM 开放转发（§2.1，端到端复核）；VMess 握手零重放防护（窗口内抓到的包可直接当已认证隧道用）；识别 grace 超时后 detached 操作无 join 保证（结构性 UAF）。另有 3 条属"潜伏型"：`DirectoryAuthenticator` ODR（两个定义尚未进同一 TU）、`IngressDispatcher` 二次 `std::move`（当前回落谓词与准入谓词重合所以不可见）、`Account::TryAcquire` 忙等（发布顺序造成的短窗口热自旋）。我第一轮把 6 条判得过重，降级理由逐条见 §10.1。
5. **"用中间件实现协议特殊性"这个方向部分可行、部分被现有抽象堵死**：现有 `Middleware::Pipeline` 以 `SharedTransmission` 为中心，只有 Session 里 2 个真实装配点；QUIC/datagram/CID/exporter/lease 语义无法表达，因此协议特殊性被迫走回调 + `dynamic_pointer_cast` + 兼容字段。§3.4 给出可落地的抽象边界。

### 2.1 已复核的 P1（我逐行验证过调用链）

**Hysteria2 DATAGRAM 面完全绕过 `/auth`，构成未认证 UDP 开放转发（SSRF/滥用中继）**

| 步骤 | 证据 | 事实 |
| --- | --- | --- |
| 1 | `Preview/Protocols/Quic/Native.cpp:2093-2102` | `OnEstablished_`（TLS/QUIC 握手完成）之后立刻 `OnDatagram_(DatagramProvider())`，无任何协议认证前置 |
| 2 | `Preview/Composition/Quic/Hysteria2Factory.hpp:632-641` | `Options.OnDatagram = Detail::MakeDatagramHandler(Config, OnDatagram, Peer)` —— 参数里没有 `AuthOwner`/`Http3AuthSession`；同文件的 `Http3AuthSession` 只被 stream 路径持有 |
| 3 | `Preview/Composition/Quic/Hysteria2Factory.hpp:477-482` | 对照：stream 路径确实有 `if (!AuthSession->Authenticated()) co_return ...;` 门禁 —— datagram 路径没有对应物 |
| 4 | `Preview/Protocols/Hysteria2/Hysteria2.hpp:244-254` | `AcceptPacket(Provider, Config)` 直接 `(void)Config;`，注释写"服务端配置（QUIC 会话已完成认证时不再重复使用）"—— 把"已认证"当成外部假设，没有校验 |
| 5 | `Preview/Application/Application.cpp:1365-1451` | `RelayHysteria2Datagrams()` 从数据报解析 `Target.Host/Port` 后 `Udp::socket Egress(...)` 直拨任意目标；`while(true)` 无数据报数上限、`async_receive_from` 无 deadline |
| 6 | `Preview/Application/Application.cpp:1385-1390` | 计量归属使用工厂级 `Context->AccountId`，不是认证后的账户，配额与审计双重失真 |

影响：任何能完成 QUIC/TLS 握手的对端（握手只需要合法 SNI/ALPN 与证书可达，不需要凭据）即可让服务端向任意 `host:port` 发 UDP，且可长期占用一条协程 + 一个 socket + 64KB 缓冲。stream 侧已修复（`Http3AuthSession` 持租约，HY2-01 已闭环），datagram 侧是唯一没有门禁的面。
整改方向：datagram handler 与 raw stream 一样由协议 owner 在认证后安装（把 `AuthOwner` 传入 `MakeDatagramHandler`，未认证时丢弃/拒绝），`AcceptPacket` 的 `(void)Config` 改为真实校验，relay 循环加数据报上限与空闲超时，计量取认证账户租约。
证据缺口：需真实 hysteria2 客户端确认 DATAGRAM 在 `/auth` 之前是否被客户端实际使用；建议以 focused 负向测试固定"未认证 DATAGRAM 不产生出站"。

---

## 3. 结构诊断

### 3.1 协议生命周期 owner 分裂总表

你举的"网关不在协议模块内"是对的，下面是竖切对照。`Protocols/<X>` 有 wire，`X 的运行态` 在别处：

| 协议 | wire/codec 在 | 真实运行态在 | 认证/租约在 | 入口/网关在 | 结果 |
| --- | --- | --- | --- | --- | --- |
| Hysteria2 | `Protocols/Hysteria2/{Codec,Conn,Dgram,Http3Auth}` | `Composition/Quic/Hysteria2Factory.hpp`（raw stream 帧、0x401 地址帧、HTTP/3 auth、datagram）+ `Application.cpp:1268-1464`（stream/datagram relay） | `Composition` 的 `Http3AuthSession`；`AcceptPacket` 丢弃 Config | `Ingress/{QuicCidRegistry,UdpDemux}` + `Application.cpp:4404-4490` | 三套 wire、两个 owner、datagram 面无门禁 |
| TUIC | `Protocols/Tuic/{Codec,Conn,Dgram,Admission}` | `Composition/Quic/TuicFactory.hpp`（callback/lease/relay/dial/resolve/report 装配）+ `Application.cpp:1530-1718` | `Protocols/Tuic/Admission.cpp`（协议 owner，全树最好的一个） | 同上 | 唯一契约较好但 relay/dial 仍在 Application；`AdmissionServices` 5 个 `std::function` |
| SS2022 | `Protocols/Shadowsocks2022/*` | `Ingress/Ss2022Gateway.hpp`（wire parser、PSK 试解、peer replay window、DNS、UDP 出口、响应加密、peer 表）+ `Composition/Recognition/CandidateFactory.hpp` | `Ingress` 内自己做 | `Ingress/Ss2022Gateway` | 协议凭据/重放/包语义全在 Ingress；UDP 有两套模型 |
| AnyTLS | `Protocols/Anytls/{Codec,Conn}` | `Composition/AnytlsService.hpp`（986 行：frame、stream 表、dial、relay、close） | adapter `Composition/Adapters/Anytls.hpp:49-51`（无 lease） | `Runtime/Session` | 两套 AnyTLS 会话概念；`Adapters/Anytls.hpp` 不设认证门禁 |
| VLESS XUDP | `Protocols/Vless/{Codec,Conn,UdpTunnel}` | `Composition/VlessXudp.hpp`（frame、session map、socket、relay） | adapter | `Runtime/Session` 的 mux 回调 | XUDP flow 表无上限、每帧重开 socket |
| HTTP/1 入站代理 | `Protocols/Http1/*` | `Composition/Recognition/CandidateFactory.hpp:508-652`（`HttpHandler`：Basic 认证、CONNECT/forward 分流、HEAD/Upgrade 装饰、PostDial） | `CandidateFactory` | — | 完整业务 handler 住在识别工厂里 |
| Reality 握手 | `Protocols/Reality/{Codec,Carrier,Response}` | `Composition/Recognition/RealityPrepared.hpp:41-181`（X25519 ECDH、SessionId 解密、shortID 校验、ServerHello/Finished 验证、应用密钥派生、record 接管） | `RealityPrepared` | `Application/RealityCarrierRegistration.hpp` | 协议 crypto 状态机的编排外置；`Reality/Carrier.hpp:9` 反向 include Composition |
| mux（smux/yamux/h2mux/singmux） | `Protocols/Mux/*` | `Composition/{MuxService,H2MuxServer,SingMux}.hpp` + `Application.cpp:4595-4682` | — | — | 模式解析三轨（enum/字符串/bool），H2 模式不吃 `MaxStreams` |
| UDP（SOCKS5/Trojan/VLESS/VMess） | 各 `Protocols/<X>/Dgram.hpp` | `Composition/UdpService.hpp:68-209` 用 4 处 `dynamic_pointer_cast` 选语义 | adapter | `Ingress/UdpListener` | 新协议必须改中央 factory；SS2022 返回 NotSupported 另走一条模型 |
| carrier（Reality/Restls/Shadowtls/Ws/Xhttp/Gun/TrustTunnel） | `Protocols/<X>/*` | candidate 构造 `Composition/Recognition/TlsCandidateFactory.hpp`、配置 carrier `Composition/Recognition/*Carrier.hpp`、facade `Composition/Carrier/FacadeCarrier.hpp`、提交/路由 `Runtime/Recognition/*`、配置转换 `Application.cpp:2544-2784` | 各处 | — | 一个协议跨 5 个目录，且 `Protocols→Composition` 反向 include |

### 3.2 依赖方向违规（逐文件行号，全部实际读到）

| 违规 include | 位置 | 声明的边界 |
| --- | --- | --- |
| `Protocols/Reality/Carrier.hpp:9` → `Composition/Carrier/FacadeCarrier.hpp` | 同名问题 `Restls/Carrier.hpp:9`、`Shadowtls/Carrier.hpp:10` | `PreviewProtocol{Reality,Restls,Shadowtls}` 允许集合只有 `PreviewProtocolsCommon`（`PreviewBoundary.cmake:343-352`） |
| `Runtime/Front/QuicFront.hpp:23-24,27` → `Composition/Adapters/DataPlane.hpp`、`Composition/Recognition/ProtocolMatrix.hpp`、`Protocols/Quic/{Datagram,GatewayCommon,Stream}Adapter.hpp`；`UdpFront.hpp:25-26` 同 | 类继承 `Protocols::GatewayCommon`（`QuicFront.hpp:95`） | `PreviewRuntime` 允许集合不含 Composition/Protocols（`PreviewBoundary.cmake:251-259`） |
| `Ingress/QuicCidRegistry.hpp:8` → `Protocols/Quic/Native.hpp`；`Ingress/Ss2022Gateway.hpp:10` → `Protocols/Shadowsocks2022/ResponseCodec.hpp` | — | 白名单已放宽并注释"过渡"（`PreviewBoundary.cmake:242-249`） |
| `Foundation/Authenticator.hpp:19` → `Account/Directory.hpp` | Foundation 允许内部依赖 = **0**（`PreviewBoundary.cmake:223-224`） | 底层契约依赖账户域 |
| `Foundation/SessionBase.hpp:26` → `Transport/Stream.hpp` | 同上 | 基础抽象向上依赖 |
| `Foundation/Utility/Diagnose/{FieldCodec.hpp:8, Detail/AsyncSubmission.hpp:11, Detail/BackendBridge.hpp:13, Detail/ContextDecoder.hpp:10-11, Detail/AsyncBackendState.hpp:11}` → `Statistics/{Redaction,Trace}.hpp`；`ContextState.hpp:409` 调 Statistics 函数 | `PreviewDiagnoseBackend` 只允许 `PreviewFoundation`（`PreviewBoundary.cmake:355-356`）；`PreviewStatistics → PreviewFoundation`（`Preview/CMakeLists.txt:159`） | 模块级环：Foundation ↔ Statistics |
| `Transport/Encrypted.hpp:390` → `Statistics/Redaction.hpp` | `PreviewTransport` 只允许 `PreviewFoundation` | Transport 依赖 Statistics |
| `Protocols/Mux/Session.hpp:45` → `Runtime/SessionControl.hpp` | `PreviewProtocolMux` 只允许 `PreviewProtocolsCommon` | 协议层依赖 Runtime 会话控制 |
| `Composition/Adapters/Common.hpp:26,287`、`ProtocolAdapter.hpp:32` 把实现写进 `namespace Preview::Runtime::{,Detail}` | 目录与命名空间不一致 | 边界伪造（读者按命名空间找模块会找错） |
| `Application.cpp:2179,2193,2195` 借用他模块私有 detail：`Recognition::detail::WithRouteServerNames`、`Settings::detail::NormalizeScheme` | — | Application 直接调用他模块 detail 命名空间 |
| `Composition/Protocol/ProtocolCatalog.hpp:11` → `Composition/Recognition/ProtocolMatrix.hpp`，被 Runtime Front 与 Application 同时消费 | — | 元数据契约没有中立 owner |

**根因**（可一行修）：`Preview/CMakeLists.txt:4-10` 的 `ConfigurePreviewTarget()` 给每个 target 加 `target_include_directories(${Target} INTERFACE ${CMAKE_SOURCE_DIR})`，头文件包含与声明依赖完全解耦；`AssertPreviewTargetIncludes()`（`Preview/CMakeLists.txt:864-866`）只校验 include 目录属性，不校验每条 `#include` 的模块边。另 `logs/issues.md` P-8 已登记"CMake allowlist 未覆盖实际链接边"，本报告的 §3.2 是其源码级证据集。

### 3.3 双轨 / 平行实现总清单（活 = 生产路径实际使用）

| 概念 | 轨道 A（活） | 轨道 B（状态） |
| --- | --- | --- |
| TCP/UDP 入口 | `Ingress::UdpListener` + `IngressDispatcher` + `QuicCidRegistry` | `Runtime::Front::{UdpFront,QuicFront}` —— **不被生产构造**，仅 `tests/Preview/integration/Task9FrontIntegration.cpp` |
| QUIC 连接表 | `QuicCidRegistry::Entries_` | `QuicGateway::{Connections_,LegacyConnections_}` 双 map（`:246,300`），真实路径无人 `RegisterConnection`；`UdpDemux::{RegisteredCids_,LegacyCids_}` 同样双表（`:94,128`） |
| 任务注册表 | `Lifecycle::TaskRegistry` | `Foundation::Utility::Coroutine::Registry`（368 行，仅测试） |
| 账户认证器 | `Account::Authenticator.hpp:50-109` 的 `Preview::Account::DirectoryAuthenticator` | `Foundation/Utility/Account/Authenticator.hpp:51-138` 的**同名同类**（不同定义，`Check` 签名一致）→ ODR；`Foundation::Authenticator` + `LegacyAuthLease` 第三轨 |
| 配置解析 | glaze（`Application/Configuration/ConfigurationParser.*`） | `Composition/Settings/{Json,Loader}.hpp`（自研 parser；`LoadConfig/ParseJson` 仅测试，但 `Settings::RecognitionConfig` 类型是生产依赖） |
| 协议 accept 装配 | `Composition/Adapters/ProtocolAdapter.hpp:86-113`（`MakeProtocolAccept`） | `Adapters/TypedResult.hpp:182-213`（`ToTypedResult`）+ `AcceptTyped`（**全仓 0 caller**）；两者逐字段对应 |
| 识别 | `Runtime/Recognition/ConfiguredMode`（默认） | `MixedTrialMode`（配置可达）、`DeterministicMode`（内部转调 MixedTrial）、`Recognition.hpp:134-300` `RecognizeLegacy` + `Route/SchemeExecutor/Probe 自由函数/ProbeDefense`（**生产无装配点**） |
| HTTP/3 | nghttp3（`Http3/{Session,NativeServer}`） | 自研 `Http3/{Decoder,Encoder,Qpack,StaticTable,DynamicTable,Huffman}` —— **T 位与 RFC 9204 相反**，仅测试/fuzz + Hysteria2 legacy `MakeAuthRequest` |
| Hysteria2 wire | `Composition/Quic/Hysteria2Factory` 的 0x401 风格帧 | `Protocols/Hysteria2/Codec.hpp` 简化帧 + `Dgram.hpp` 的 `StandardWire_` bool 参考帧 |
| carrier | `Composition/Recognition/{Shadowtls,Restls}Carrier.hpp`、`MakeShadowtlsServerAccept`（生产） | `Composition/Carrier/FacadeCarrier.hpp` 491 行第二套 carrier 契约（含自建 `CarrierError`），仅测试；`MakeShadowtlsCarrier` 0 caller |
| 启动引导 | `Application.cpp:2036-2256` 自建 recognition config | `Composition/Recognition/SettingsBuilder.hpp:150-195,216-372`（`InstallProfile/BuildSessionOptions/MakeSessionFactory/MakeTcpListener/StartTcpListener`）仅 `ProfileBootstrapTest`；`ProfileBuilder.hpp:130-135` **0 caller** |
| 流量统计 | `Statistics::EventRing/TrafficDelta` | `Runtime/Statistics.hpp`（`TrafficCounter` 仅测试、`IdentityTraffic/PerWorkerTraffic` 仅未接线的 `Api/StatisticsApi`），且每新增 identity 整表 COW |
| 限流 | `Account/Rate.hpp`（生产只构造 `UnlimitedRatePolicy`） | `Foundation/Utility/Rate/TokenBucket.hpp`（216 行，生产 0 使用） |
| 脱敏 | `Statistics/Redaction.hpp` 单一算法 | 被 Diagnose bridge、AsyncSubmission、ContextDecoder/ContextState/FieldCodec、`Transport/Encrypted.hpp:390`、`Middleware/Builtin/Relay.hpp:50`、`Operations/Redaction.hpp:19`、`Statistics/EventRing.hpp:94` 多层重复调用，"哪层可信"无合同 |
| 路由/出站 | `Application.cpp` 直连 `Dialer`/`WorkerDialService`；`Routes` 配置在 `Application.cpp:985-991` 明确拒绝 | `Net/Route/Route.hpp`、`Net/Outbound/Outbound.hpp`（生产 0 caller） |
| 热重载 | 无（`Application.cpp:4173,4193` 硬编码 `GenerationId{1}`） | `Configuration/{ConfigurationStore,ReloadCoordinator}.hpp` 仅测试；`HotReload` 字段生产 0 消费者 |
| API 面 | `Operations::{Router,HttpServer}`（生产） | `Composition/Api/{ApiManager,OperationsApi,StatisticsApi}.hpp` 仅测试/bench；`Api.hpp` 聚合头 0 include |
| 资源模型 | `Resource/{Process,Worker}Resources`、`ExecutorReclaimer` | `Resource/{Session,Stream}Resources.hpp` + `Resource.hpp` 聚合头 —— 0 扇入（AGENTS.md 的 L3/L4 层实际未落地） |
| 调度 | `Listener`+`Mailbox`+`AffinityBalancer` | `Scheduler/{Fair,Priority}Scheduler,Types,Detail/FixedTable` 全不在生产闭包 |

### 3.4 "协议特殊性走中间件"这条路的可行性判断

现状：`Middleware::Pipeline` 在生产只有两个装配点（`Session.hpp:1117-1120` 装饰、`1137-1139` dial），`Auth`（`Session.hpp:1095`）与 `Relay`（`1204`）是直接调 `Handle()` 而非入管线；`Throttle/Pad/Mux` 中间件里 `Throttle` 生产 0 装配点。同时 `Application.cpp:275-277/1349-1351`、`AnytlsService.hpp:761`、`Quic/Hysteria2Factory.hpp:388`、`Quic/TuicFactory.hpp:285` 各自临时拼 `Middleware::Context` + Relay —— 同一个"数据面"有两套写法。

为什么现在不能用它承载协议特殊性：
1. `Middleware::Context`（`Context.hpp:51-112`）是 24 字段万能袋：四份身份（`AccountId`/`identity`/`DisplayIdentity`/`RawIdentity`）、两份 sink、两份 dial；`SetDataPlane()` 单向拷贝、`SynchronizeDataPlane()` 只同步 Transport，认证结果不回写 DataPlane（`Context.hpp:136-139` 移走租约后不 `reset()`，留下 engaged-but-moved 的 `optional`）。
2. 接口没有所有权合同：`Pipeline.hpp:40-59` 只有 `Name/Handle`，没有取消、半关闭、最终关闭者、executor 约束；`Relay.hpp:94-103` 关两端但不 `Cancel`，`176-179` 半关闭后无人负责最终 close。
3. 抽象只覆盖"可靠字节流"。QUIC 需要 CID/ALPN/connection/stream provider/datagram provider/TLS exporter/peer-drain 生命周期，塞不进 `SharedTransmission` 型管线。

可行的切法（不新增万能层）：
- **`StreamPipeline`**（现有 Middleware 的收窄版）：只处理可靠流阶段，接口写死 owner/cancel/half-close/final-close/executor；`ProtocolDataPlane` 成为 target/identity/lease/transport 的唯一来源，删掉 `Context` 的兼容字段与双向同步。
- **`DatagramService` / `PacketProvider`**（typed，协议各自实现）：替换 `UdpService.hpp` 的 4 处 `dynamic_pointer_cast`，Composition 只做注册与选择，不做语义分派。
- **`ConnectionAdmission`**（以 `Protocols/Tuic/Admission` 为样板）：QUIC 的 connection/stream/datagram/lease 生命周期归协议 owner；`Composition` 只提供 typed prepare/bind/rollback 槽位；CID/包分类留在 `Ingress`。
- **`CarrierAdmission`**：carrier 是"承载 + 内层协议"两阶段 typed result，而不是被 `ProtocolCatalog` 当普通 TCP 协议、被 `UdpService` 当普通 UDP capability。
- 一个共享的 `SerializedWriter` 契约（单 executor、FIFO、有界 pending bytes、exactly-once completion）：目前 XHTTP/AnyTLS/TrustTunnel/Ws/Mux/Http3/Reality 各自实现 pending write + offset + half-close，命名 `PendingWire_/PendingOffset_/PendingReadPayload_/PendingWrites_/PendingBytes_/PendingOutput_/PendingHeaders_` 7 种变体分散在 10+ 文件（`Http3/Session.hpp` 24 处、`Shadowtls/Conn.hpp` 22、`Ws/Conn.hpp` 16、`Gun/Conn.hpp` 16、`Restls/Conn.hpp` 14、`Trusttunnel/Conn.hpp` 12、`Mux/Session.hpp` 12）。

### 3.5 service bag（`std::function` 聚集点，按文件）

```
12 Preview/Composition/Quic/Hysteria2Factory.hpp     9 Preview/Protocols/Quic/Native.hpp
 7 Preview/Runtime/SessionControl.hpp                6 Preview/Protocols/Tuic/Admission.hpp
 6 Preview/Operations/Router.hpp                     5 Preview/Runtime/SessionServices.hpp
 5 Preview/Protocols/Xhttp/Conn.hpp                  5 Preview/Ingress/QuicGateway.hpp
 5 Preview/Composition/MuxService.hpp                4 Preview/Runtime/SessionRegistry.hpp
 4 Preview/Lifecycle/TaskRegistry.hpp                3 Preview/Runtime/Recognition/{Profile,ConfiguredMode}.hpp
 3 Preview/Runtime/Contract/DataPlane.hpp            3 Preview/Protocols/Vless/UdpTunnel.hpp
 3 Preview/Protocols/{Trusttunnel/Http2,Http3/NativeServer,Http2/Session}.hpp
 3 Preview/Composition/Quic/TuicFactory.hpp
```
`Native.hpp` 的 `NativeConnection` 构造函数实测 19 参含 12 个默认值（`Native.cpp:285-299`），直接违反"默认参数不超过 2/复杂边界 3"。

### 3.6 P1/P2 汇总表（本报告新确认，含复核状态）

| # | 级别 | 问题 | 位置 | 复核 |
| --- | --- | --- | --- | --- |
| 1 | P1 | Hysteria2 QUIC DATAGRAM 面无 `/auth` 门禁 → 未认证 UDP 开放转发/SSRF | `Quic/Native.cpp:2093-2102`、`Composition/Quic/Hysteria2Factory.hpp:632-641`、`Protocols/Hysteria2/Hysteria2.hpp:244-254`、`Application.cpp:1365-1451` | **逐行复核** |
| 2 | P2 | UDP 回落合同被二次 `std::move` 破坏：QUIC 分类包交给 datagram handler 时 payload 已空。**当前潜伏** —— 唯一消费者是 `Ss2022Gateway`，其回落谓词与准入谓词（`HasAuthenticatedClientWire`）相同，因此结果不变、暂无用户可见丢包；接入第二个 datagram 消费者或两个谓词分叉即成静默丢包 | `IngressDispatcher.hpp:45-72`、`QuicGateway.hpp:164-212`（生产无 `RegisterConnection` ⇒ `Handle` 恒 false）、`Ss2022Gateway.hpp:83-105,116-127`、`Application.cpp:4405-4439` | **逐行复核；由 P1 降级**（见 §10.1） |
| 3 | P2 | `QuicCidRegistry` 用被 move 的 key 再 `find` 做失败清理，被拒 server 残留 | `QuicCidRegistry.hpp:127`（`emplace(std::move(Key))`）与 `:137`（`Entries_.find(Key)`）；成功路径用 `It`（`:134`），仅失败清理失效 | **逐行复核** |
| 4 | P2 | VMess legacy AEAD 块 nonce = 16-bit 计数 + 固定 10B 种子，65536 块后回绕重用 (key,nonce)；实现没有块计数上限、不强制轮换、也不拒绝该模式。**注：该计数方案继承自上游 VMess aes-128-gcm 语义，且重用发生在该连接自身密钥与该客户端主动选择的模式内** ⇒ 影响是该会话对被动观察者的机密性退化，不是认证绕过 | `Vmess/ChunkCodec.hpp:53-62,250-273,353,460-465,560` | **逐行复核；由 P1 降级**（见 §10.1） |
| 5 | P2 | VMess `Option` 位由远端提供且不校验合法位，双向 wire 语义（含条目 4 的弱模式）由客户端选择；`GlobalPadding/ConnectionReuse` 被静默忽略 | `RequestCodec.hpp:194,474`、`Vmess/Conn.hpp:533-537`、`ChunkCodec.hpp:332,407,451,539` | **逐行复核；由 P1 降级**（本身是策略缺失，与条目 4 合并处置） |
| 6 | P1 | VMess 握手零重放防护：只有 ±120s 时间窗，全仓无 AuthID/nonce 去重缓存（`Fault::Code::ReplayDetected` 无使用者）。**前提**：攻击者需在窗口内捕获到一个有效握手包；由于 request key/nonce 也在该包内，重放方可把会话当作已认证隧道继续使用（加密 body、解密响应）。上游 Xray/sing-box 实现有 seen-cache，此处缺失 | `Vmess/Auth.hpp:690-714`、`Types.hpp:30` | **逐行复核**（维持 P1，前提是抓包能力） |
| 7 | P2 | Reality carrier 只校验 version 字节 + ShortId，SessionId 内 7 字节时间/随机字段从不比较 ⇒ 无重放窗口。**注：单靠重放 ClientHello 无法完成 TLS 1.3 握手（缺客户端握手密钥），因此不构成直接会话获得**；实际风险是与上游（校验 ±checkTime）规范偏差 + 无界握手资源消耗/反射 | `Protocols/Reality/Carrier.hpp:552-573` | **逐行复核；由 P1 降级**（见 §10.1） |
| 8 | P1 | `Preview::Account::DirectoryAuthenticator` 在两个头文件里定义两个不同类（同命名空间、同名、`Check` 签名一致）⇒ ODR 地雷。**当前潜伏**：`Foundation/Authenticator.hpp:19-20` 已同时引入两套 *Directory*，只差两个 *Authenticator* 定义进同一 TU 即编译失败/链接期任选其一 | `Account/Authenticator.hpp:50-109`、`Foundation/Utility/Account/Authenticator.hpp:51-138` | **逐行复核**（潜伏型，标注见 §10.1） |
| 9 | P2 | 账户目录 `TryAcquire` 读侧两条 `continue` 既不改变可推进状态也无重试上限/无 yield；而 `Upsert` 是**先发布记录、后 `PublishPolicy`**，因此并发认证在该窗口内会热自旋整条握手线程（可观测为 CPU 满载）；只有当某条路径发布了记录却不发布策略时，窗口才变永久活锁 | `Account/Directory.hpp:197-216`、`:70-111`（发布顺序）、`Runtime.hpp:240-248,285-296`（`while (Current->Generation() < Generation)` 同样无上限） | **逐行复核；由 P1 降级**（"必然活锁"证据不足） |
| 10 | P3 | `Fault::CachedMessage` 标 `noexcept` 却在静态初始化里构造 N 个 `std::string`（OOM ⇒ `std::terminate`）；同文件注释宣称"后续零分配"而 `message()` 按值返回 | `Foundation/Fault/Compatible.hpp:30-53,80-83` | **逐行复核；由 P1 降级**（触发需内存耗尽，属契约矛盾而非现行缺陷） |
| 11 | P3 | `Fault::Handling` 用硬编码枚举序号做跨层错误映射，无枚举名、无 `static_assert`。逐项核对 `Error.hpp:26-68` 后**当前映射是一致的**，仅 `KdfError(16)`/`CryptoError(19)` 被降级为 `GenericError`；缺陷是脆弱性而非现行为错 | `Foundation/Fault/Handling.hpp:103-127`、`Error.hpp:26-68` | **逐行复核；由 P1 降级** |
| 12 | P2 | MixedTrial 与 Configured 对 "route 适用但无候选" 语义相反：前者继续试探全部结构候选，后者判 `NoMatch` | `MixedTrialMode.hpp:184-197`（只在 `Route.Candidate` 存在时收窄）vs `ConfiguredMode.hpp:718-723`（`!Route.Candidate` 即 `NoMatch`）、`ConfiguredMode.hpp:427-428` 注释承诺 | **逐行复核** |
| 13 | P1 | grace 超时后 detached 操作无 join 保证：识别协程可越过 `Session` 栈上 `ProbeBuffer` 的生命周期恢复 | `ConfiguredMode.hpp:214-216`（`co_spawn(..., Net::detached)`）、`:236-244`（仅 `ControlGracePeriod` 后即 `co_return`）、`MixedTrialMode.hpp:130-135`（`Buffer.Ensure(*Inbound,…)` 以裸引用跨 await）、`Session.hpp:833-835`（`Probe` 为栈对象）| **结构复核**（内层操作是否合作取消 → 待运行验证） |
| 14 | P2 | Hysteria2/TUIC datagram 循环无上限无 deadline，每包 close/open socket，每会话 64KB 常驻 | `Application.cpp:1385-1451`、`1597-1609` | 分片复核 |
| 15 | P2 | TCP 会话数据面实际全部运行在 listener 的 `Runtime->Io`，worker 线程只做登记与 dial | `Listener.hpp:347,648-651`、`Transport/Reliable.hpp:139-142`、`Session.hpp:342-348`、`Application.cpp:4716-4721` | **逐行复核** |
| 16 | P2 | 生产没有连接上限：`Listener::Options::MaxConnections{0}`（0=无限），Application 未从配置传入 | `Listener.hpp:116,718-728`、`Application.cpp:4713-4721` | **逐行复核** |
| 17 | P2 | 启动失败分支不回滚且不 `State_.reset()` ⇒ `Run()` 继续 `Io.run()` 永久挂起（不返回 1） | `Application.cpp:4688-4693` + `4852-4876` | **逐行复核** |
| 18 | P2 | `Services->Mux` lambda 捕获自身所属的 `SessionServices` shared_ptr ⇒ 引用环，整条 services 图永不释放 | `Application.cpp:4635-4682` | **逐行复核** |
| 19 | P2 | `SessionServices::Traffic` 全仓无生产赋值点 ⇒ 账户/用户流量统计恒不生效 | `Runtime/SessionServices.hpp:73`、`Application.cpp:272,4557,4579`、`Relay.hpp:391-394` | **逐行复核** |
| 20 | P2 | Native QUIC `MaxStreams/MaxDatagrams` 无消费点，硬编码 1024/1400；`Streams_` 关闭后不 erase；callback+queue 双路保存 provider | `Quic/Native.cpp:292-293,310-311,1401-1403,1446-1448,1919,1924-1945,2002-2011` | 分片复核 |
| 21 | P2 | AnyTLS 流表无上限、慢上游直接杀连接、半关闭不发 FIN、detached relay 不受 `Control` 取消 | `Composition/AnytlsService.hpp:80,119,321-429,875-882,935-951` | 分片复核 |
| 22 | P2 | VLESS XUDP：单帧错误 `co_return` 杀整根连接、每帧重开 socket、`Sessions` 无上限、串行 send→单 reply | `Composition/VlessXudp.hpp:411-542` | 分片复核 |
| 23 | P2 | mux：H2 模式不吃 `MaxStreams`、正常退出无 drain、异常路径 `UnregisterRoot` 缺失；H2MuxServer 接收无预算 | `Composition/MuxService.hpp:476,544-553,589-648`、`H2MuxServer.hpp:55,212-220,260,482-491` | 分片复核 |
| 24 | P2 | HTTP/2 core：`OnData` 同步自动 `WINDOW_UPDATE`（无背压）、无并发流上限、不宣告/不 enforce `MAX_CONCURRENT_STREAMS`、HPACK 动态表固定 4096、`CONTINUATION` 聚合无上限、RESET 指向已关闭流即断整条连接 | `Protocols/Http2/Impl.hpp:538-542,624,651-659,728-733,765-795`、`Http2/Codec.hpp:490,530-541` | 分片复核 |
| 25 | P2 | XHTTP StreamOne 预绑定写缓冲与 `PacketBodies` 无上限、无 accept/match deadline | `Protocols/Xhttp/Conn.hpp:318-324,1108,1136,1339` | 分片复核 |
| 26 | P2 | Ws 读协程内直接回 Pong，与并发写共用底层 `async_write_some` ⇒ WS 帧字节可交错损坏。**已补证据**：`Transport/Reliable.hpp:272-295` 直委托 socket `async_write_some`，无 strand/无写队列/无写标志位，`Ws/Conn.hpp:302,391,533` 两处协程可并发进入同一条写链 | `Protocols/Ws/Conn.hpp:302-308,532-539`、`Preview/Transport/Reliable.hpp:272-295` | **逐行复核（原判"待验证"已闭环）** |
| 27 | P2 | SS2022 Ingress 每包三轮全 PSK 试解 + 逐字节转 vector + 每包新建出口 socket、在途无上限、`Close()` 不取消在途 | `Ingress/Ss2022Gateway.hpp:83-152,212-290,107-112` | 分片复核 |
| 28 | P2 | `EventRing` 不是环：满 1024 后只 `++Dropped` 永不淘汰，`TerminalReserved_` 只增 ⇒ 运维事件流最终永久静默 | `Statistics/EventRing.hpp:76-100,177` | 分片复核 |
| 29 | P2 | DNS：flight/cache/每查询 detached 子任务三处无上限；事务 ID 用时间戳^计数器可预测；`Dialer` 多地址重试复用已失败 socket | `Net/Dns/{Coalescer.hpp:199-214,Cache.hpp:101-109,Upstream.hpp:151-156,573-608}`、`Net/Dialer/Dialer.hpp:124-144` | 分片复核 |
| 30 | P2 | `Account::Rate` 在生产不可用：所有调用点传空 `RateRequest`（`Now=0` ⇒ 直接判失败），且只构造 `UnlimitedRatePolicy` | `Account/Rate.hpp:116`、7 个协议 `Conn` + `Middleware/Builtin/Auth.hpp:97`、`Application.cpp:1084,1218` | 分片复核 |
| 31 | P2 | AnyTLS / TrustTunnel adapter 不置 `AccountId`/`AccountLeaseRequired` ⇒ 配额、限速、撤销对其失效 | `Composition/Adapters/{Anytls.hpp:49-52,Trusttunnel.hpp:46-48}` | 分片复核 |
| 32 | P2 | `EnforceProtocolAuthentication` 只在 6 个 adapter 调用，`ProtocolAdapter`（自称唯一适配点）与 `CandidateFactory` 不设门禁 ⇒ 忘调即绕过账户校验 | `Adapters/{Vless,Trojan,Vmess,Ss2022,Socks5}.hpp` vs `ProtocolAdapter.hpp:78-115`、`CandidateFactory.hpp:584-623` | 分片复核 |
| 33 | P2 | 多账户只取 `Accounts[0]` 的凭据参与 wire/识别；每协议各建一份目录 ⇒ 同一账户多套 `AccountRuntimeState`，配额按协议重复计 | `Application.cpp:1839-1848`、`1040-1101`、`563-574` | 分片复核 |
| 34 | P2 | Operations 无应用级鉴权（仅 `is_loopback()`），却能 Revoke/Drain；`DrainCommand` 读 `Value.Worker` 只回显，实际置全局停机 | `Application.cpp:3045-3051,4000-4025`、`HttpServer.cpp:1525-1529`、`Router.hpp:43-47` | 分片复核 |
| 35 | P2 | `SessionRegistry::Shutdown` 无重试上限/超时，Control 置 Blocked 而 Active 不归零则 `while(true)` 空转；`Put/Remove` 旁路 token 合同 | `Runtime/SessionRegistry.hpp:260-287,430-475` | 分片复核 |
| 36 | P2 | Diagnose：`BeginShutdown` 后 `Accepting=false`，终态事件（Services/Dns 析构）既不落盘也不计 `Dropped`；`Logger_` 非原子 `shared_ptr` 与 `Pool_` 保护不对称 | `Application/DiagnoseRuntime.hpp:151-155`、`Diagnose/Detail/{BackendLifecycle.hpp:180-185,AsyncBackendState.hpp:161,AsyncSubmission.hpp:144-177}` | 分片复核 |
| 37 | P2 | FrameArena 绑定 `thread_local` 无锁池，但 `SharedSessionResource` 以 shared_ptr 跨线程持有 ⇒ 在线程 A 分配、线程 B 释放即 UB/堆损坏 | `Foundation/Memory/{Pointer.hpp:76,254,Pool.hpp:73-86}`、消费点 `Anytls/Conn.hpp:46`、`Http3/{Auth,Session,NativeClient}`、`Hysteria2/Http3Auth.cpp:42,200` | 分片复核 |
| 38 | P2 | 密钥材料不清零、X25519 生成失败静默返回全零私钥（无错误通道）；全仓 `OPENSSL_cleanse/memset_s/explicit_bzero` 命中 0 | `Foundation/Utility/Crypto/{X25519.hpp:109-120,Hkdf.hpp:212-247,Aead.hpp:252}` | 分片复核 |
| 39 | P2 | 配置：`Priority` 静默截断 65535 导致 validator 与运行时歧义判据不一致；`IsValidUuidText` 不校验连字符结构；`Quic.MaxStreams/MaxDatagrams` 无上界；`ValidateCarrier` 的 `std::visit` 链无兜底分支 | `Configuration/ConfigurationValidator.hpp:1189-1197,677-709,303-308,1501-1862`、`Application.cpp:1965` | 分片复核 |
| 40 | P2 | 内联凭据 `Accounts[].Credential` 全程不零化（与 `Secrets` 的 SecureBytes 语义不一致），`glz::generic` 预检复制出第二份明文 | `Configuration/{PreviewConfiguration.hpp:197-198,PreviewConfigurationSchema.hpp:53-57,ConfigurationGeneration.hpp:97}`、`Application.cpp:563-572` | 分片复核 |
| 41 | P2 | TUIC datagram 解析 `AssocId/PktId` 后丢弃、发送恒用 0；TUIC/HY2 分片只校验不重组（`FragTotal>1` 时每片当独立数据报投递） | `Protocols/Tuic/{Dgram.hpp:104,193-209,398,Conn.hpp:382-384,537-544}` | 分片复核 |
| 42 | P2 | Hysteria2 手写 QPACK 的静态索引 T 位与 RFC 9204 相反（`11xxxxxx` 当静态索引、拒绝 `10xxxxxx`），真实客户端字段行必判 `BadMessage` | `Protocols/Http3/{Decoder.hpp:263-296,Encoder.hpp:147,162}` | 分片复核 |
| 43 | P2 | 热路径 64KB 栈/数组值初始化反复 memset（`QueueFlush` 最坏一次 8MB），与"零分配"目标相反 | `Quic/Native.cpp:1109,1227,1323,1641,1776`、`Http3/Session.hpp:301`、`Hysteria2/{Conn.hpp:306,Dgram.hpp:163}`、`Tuic/Dgram.hpp:153` | 分片复核 |
| 44 | P2 | SS2022 `ReadChunk` 每块从单调 arena 取缓冲且永不归还 ⇒ 长连接内存随累计流量线性膨胀 | `Shadowsocks2022/Conn.hpp:690-691`、`Memory/Pointer.hpp:225-245` | 分片复核 |

---

## 4. 按目录树的逐模块问题

### 4.0 `Preview/CMakeLists.txt`(919) + `CMake/PreviewBoundary.cmake`(666) + `Application/CMakeLists.txt`(90)

- **[P3] 边界检查与源码 include 图解耦**：`ConfigurePreviewTarget()` 的 `INTERFACE ${CMAKE_SOURCE_DIR}`（`CMakeLists.txt:4-10`）使任何头可包含任何头；`AssertPreviewTargetSources/Includes`（`:847-866`）只校验 target 属性，不校验模块边。§3.2 的 18 条违规 include 全部静默通过。`logs/issues.md` P-8 已登记"allowlist 未覆盖实际链接边"，本节是源码级证据。
- **[P3] 允许表已把违规固化为白名单**：`PreviewBoundary.cmake:242-249` 给 `PreviewIngress` 放行 `PreviewProtocolQuic/QuicNative/Shadowsocks2022`，注释"C04/P1 过渡"；而 `PreviewFoundation` 允许集合为空（`:223-224`）却被源码 include `Account/Directory.hpp`、`Transport/Stream.hpp`、`Statistics/*`（§3.2）—— 声明与实际互相矛盾，两个方向都不可信。
- **[P3] 41 个 target 集中在根 manifest**：新增协议需改 target 声明、`target_sources`、允许表、`LinkPreviewTargets(PreviewComposition …)`（`:876-894`）与 Application include 五处。
- **[P3] header-only 被当成模块隔离**：`PreviewRuntime` 是 INTERFACE 且唯一编译单元是 `Mailbox.cpp`；`Protocols/Mux/Session.hpp`(1307)、`Xhttp/Conn.hpp`(2108)、`Quic/Native.cpp` 的门面段（`:2450-2784` 约 330 行纯转发）等状态机没有真实编译边界。
- **[P4] 5 个磁盘文件不在 `Preview/CMakeLists.txt` 登记**：`Application/{Application.cpp,DiagnoseRuntime.hpp}`、`Application/Main/PreviewMain.cpp`（由 `Application/CMakeLists.txt` 承担，但该文件只登记 `Application.hpp DiagnoseRuntime.hpp`，两个被包含的公共头 `RealityCarrierRegistration.hpp`/`TrustTunnelCredentials.hpp` 反而在父级登记）、`Performance/{Scheduler,Statistics}Benchmark.cpp`（由 `tests/Preview/perf/CMakeLists.txt:21-31` 编译）。
- **[P4] `Preview/Performance/` 里放 `main()` 基准源**，却由测试 CMake 编译 —— 目录归属与构建归属不一致。
- **[P3] `PreviewFoundation` INTERFACE 直接 link `OpenSSL::Crypto`/`Blake3C`**（`:89-93`），使 `Role.hpp`/`ByteSpan.hpp` 这类纯值类型头也拖入 BoringSSL+BLAKE3。
- **[P4] 边界 fault 注入开关**（`:896-915`）本身合理，但它证明"负向边"只能靠人工注入验证，不能靠 include 图验证。

### 4.1 `Preview/Account/`（9 文件 / 1,889 行）

- **[P2] 账户目录读侧忙等窗口**（§3.6 条目 9）：`Directory.hpp:197-216` 两条 `continue` 既不推进状态也无重试上限/无 yield，而 `:70-111` 是"先 CAS 发布记录、后 `PublishPolicy`"，两者之间并发认证会热自旋整条握手线程；`Runtime.hpp:285-296` 的 `while (Current->Generation() < Generation)` 同样无上限。整改：有限重试 + 退避 + 明确失败码，并把发布顺序改为"策略先于记录"。
- **[P1 潜伏] `DirectoryAuthenticator` 一名两制**（§3.6 条目 8）：两个 `class DirectoryAuthenticator final` 同在 `namespace Preview::Account`，一个不继承、一个继承 `Preview::Authenticator`，`Check(std::string_view,std::string_view) const -> Preview::AuthResult` 签名一致而语义不同（`Account/Authenticator.hpp:172` 返回空、`Foundation/Utility/Account/Authenticator.hpp:122` 做真实查找）。今天没有 TU 同时包含两者，所以不报错；`Foundation/Authenticator.hpp:19-20` 已经把两套 *Directory* 引进同一文件，只差类名相撞。来源见 `Foundation/Utility/Account/README.md`（自称"account 模块已实现，T5 阶段"）—— 那是**早期阶段的实现被留在树里未改名未删除**。
- **[P2] 认证成功但没有租约是合法默认**：`Foundation/Authenticator.hpp:162` 注释自认默认实现不能产生 `AccountLease`，`:181-185` 直接 `Accepted=true` 无 Lease；`:214` 把 `TryAcquire` 返回的租约丢弃；`LegacyAuthLease::operator AccountLease&&`（`:63-67`）先 `Legacy_.reset()` 再移动恒空的 `Typed_` ⇒ "认证成功、配额已释放、无人持有"。生产调用点 `Composition/Recognition/CandidateFactory.hpp:345,371` 只取 `Check(...).Ok` 布尔。这正是 §6 里 HY2-01/AnyTLS/TrustTunnel 配额失效的共同根因。
- **[P2] 限速策略在生产不可用**：`Rate.hpp:116` 对 `Now==0` 直接 `return false`，而 7 个协议 `Conn` + `Middleware/Builtin/Auth.hpp:97` 全部传 `.Rate = {}`；Application 只构造 `UnlimitedRatePolicy`（`Application.cpp:1084,1218`）。⇒ `Rate.hpp` 384 行分片限速等于零验证，任何非 Unlimited 策略会让所有认证被判 RateLimited。
- **[P2] 凭据→身份/明文键**：`Foundation/Utility/Account/Directory.hpp:241-255,292-300` 用明文 `std::string` 作 CowMap 键、非常量时间比较、不清零；`Utility/Account/Authenticator.hpp:82,107` 一次认证 `Find` 两次（TOCTOU + 双查），`:114` 把凭据本身当 `Identity`，`:110` 把配额超限伪报为 `Disabled`；对照新实现 `Account/Credential.hpp:185-203` 已是常量时间。
- **[P3] `SecureBytes` 只做到析构清零**（`SecureBytes.hpp:83` 普通 `std::vector<std::byte>`，无 mlock/专用分配器），且入参是 `std::string_view`（`:23-29`）—— 调用方原串不被擦除；`Application.cpp:1070-1072` 又把明文复制进 `Effective.Credential`。
- **[P3] `Resource/SessionResources.hpp`、`StreamResources.hpp`、`Resource.hpp`、`Account.hpp` 聚合头在生产闭包外**（AGENTS.md 的 L3/L4 所有权层实际未落地）。
- **正面**：`Credential`/`Record`/`Runtime`/`Lease` 的值对象分层与常量时间比较方向正确；`Runtime.hpp` 的配额/撤销语义是清晰的。

### 4.2 `Preview/Application/`（27 文件 / 9,706 行，其中 `Application.cpp` 4,925 行）

- **[P2] `Application::Start()` 731 行、12 类职责**（`:4121-4851`）：日志级别/render mode 解析、凭据与 UUID/PSK 解析、TCP candidate registry（`:2546-2784`）、8 协议 acceptor（`:2407-2542`）、识别 config（`:2036-2160`）、Hysteria2 stream/datagram relay（`:1268-1464`）、TUIC dial/resolve/datagram/report（`:1530-1718`）、QUIC server factory（`:1742-1827`）、carrier 装配（`:2544-2784`）、UDP/SS2022/QUIC 网关构造（`:4404-4490`）、UDP service + mux 分发（`:4595-4682`）、Operations query/command handler（`:3801-4044`）、shutdown/rollback（`:3385-3542`）。**协议业务 lambda 与数据面状态机直接在 Application**，与 AGENTS.md 的 Application 职责表冲突。
- **[P2] 启动事务不闭合**：`MakeTcpProfile` 失败是唯一未 `RunStartupRollback` / 未 `State_.reset()` 的晚期分支（`:4688-4693`，对照 `:4374,4494,4532,4563,4584,4741,4750,4776,4805,4847` 全部 reset）；`Run()` 的 `if (!State_ || Phase==Ready)`（`:4854`）在失败后既不重试 Start 也不返回，落到 `State_->Io.run()`（`:4876`）⇒ **静默永久挂起**。整改：`StartupTransaction` + 统一失败出口。
- **[P2] 引用环**：`Services->Mux = [Service, Services = Runtime->Services, Resolver]`（`:4635-4682`）把持有自己的 `shared_ptr<SessionServices>` 存进自己的成员 ⇒ `SessionServices` 及 Profile/Dns/MuxService 永不释放；`MakeMuxStreamHandler(Services, ...)` 再把环传播到每连接副本。
- **[P2] 每连接复制整个 `SessionServices`**（`:3110` `make_shared<SessionServices>(*Services)`）：6 个 `std::function` + 十余 `shared_ptr` 在 accept 路径深拷贝。
- **[P2] 多账户语义漂移**：`FirstAccount`（`:1839-1848`）供 12 处 wire 凭据（`:2292-2521`）；QUIC 凭据按 `SecretRef` 名匹配、首个命中即 `break`（`:1129-1131,1191-1197`）；凭据 map 键三套拼写（`:546-556` "Shadowsocks2022" / `:1916-1931` "ss2022" / `:1151-1155` 小写 builtin 名）。
- **[P3] 协议事实 12 处重复**：枚举 `:416-426`；switch `:438,549,607,1921,2273,2433`；`array<…,8>` `:856,1833,1834,2406,2408,4224,4225`；内建名字符串 `:456,876,893,1471,1675,4525,4548`。新增一个 TCP 协议约需改 10-12 处，漏一处即静默 `nullopt`/未初始化数组项。`RegisterTcpCandidate`（`:2273-2394`）与 `MakeRuntimeAcceptors`（`:2433-2539`）是同一 `ServerConfig` 构造的两份全量拷贝。
- **[P3] 跨层 include 与借用 detail**：`:46-49` 直接 include `Protocols/{Socks5/Conn,Vless/Conn,Ws/Ws}`、`Transport/Encrypted`；`CMakeLists.txt:10-35` 未声明 Protocols/Net/Transport/Statistics 依赖；`:2179,2193,2195` 调 `Recognition::detail::WithRouteServerNames`、`Settings::detail::NormalizeScheme`。
- **[P3] QUIC readiness 名不符实**（`:4753-4759`）：仅凭 `QuicAdmissionConfigured` 就 `MarkHandshakeReady/MarkProtocolReady`；`UdpEndpoint` 可只来自 `Listeners.Udp`（`:4281-4302`）⇒ 无 QUIC 也标 SocketReady，健康值出现 `QuicSocketReady=true, QuicReady=false` 自相矛盾（`:4796-4800`，`:3786-3790` 原样透传 Operations）。
- **[P3] 死代码**：`DialTarget()`（`:656-681`）定义后无任何调用（`4507` 用的是 `DialTargetWithResolver`）；进程级 `TaskRegistry` 有 Create/Cancel/Drain/reset（`:3147,3511-3517,3393`）但**从未 Register** ⇒ 停机白耗一个 deadline 段；`Preview/Application/Detail/` 空目录。
- **[P3] `MakeTcpRecognitionConfig` 静默丢候选**：`:2109-2112` 遇 `Carrier == nullptr` 直接 `continue` 且不返回错误（`:2160`），所有失败塌成 `MissingResolver`（`:2162-2258`）⇒ 配置写错时错误信息不指位。
- **[P4] 硬编码容量**：`{4096, 65536, {}}`（`:4408-4409`）、`MaxStreams=256`（`:4632`）、`MaxCryptoTrials=16`（`:2060`）、Process 容量 64（`:3151`）、65535（`:1378,1597`）；每 QUIC 连接全量复制工厂选项（`:1784,1803`）；`shared_ptr<weak_ptr<QuicCidRegistry>>` 环解 hack 在 factory 之后才写入（`:1725,4541-4542,4593`）。
- **[P4] 热路径 RTTI**：`:242-243` 每个 mux 流 `dynamic_cast<SingMux::ServerStream*>`；`:1968-1977` `AppendRecognitionCandidate` 10 参；`:60-83` 未 include `<algorithm>` 却使用 `std::find_if/min/max`（`:1952,1965,2128`）；`:2958-2960` 英文注释；`:1013-1037` 弱凭据是 4 个字面量黑名单且只在 TCP 环回外生效；`:4076-4086` `signal_set` 未重投 ⇒ 第二次 SIGINT 无处理，且全目录无强制退出路径；`:4142` `std::move(Options_.SecretResolver)` 使二次 `Start()` 静默失去环境变量解析。

### 4.3 `Preview/Application/Configuration/`（23 文件；`ConfigurationValidator.hpp` 1,938 行 header-only）

- **[P3] validator 仍是协议知识聚合器**（CONFIG-01 仍成立）：`Validate()` 572 行（`:64-636`）、`ValidateCarrier()` 373 行（`:1490-1863`）；QUIC 单 provider（`:255-269`）、ALPN `h3`（`:291-296`）、TUIC UUID（`:284-290`）、carrier 类型匹配（`:1506-1515,1694-1699`）、AnyTLS/TrustTunnel 栈规则（`:398-404,1359-1362,1494-1499`）、mux 白名单（`:418-433,662-665`）、builtin 快照/canonical 名（`:1320-1357`）应分别下沉 `Protocols/<Name>`、`Composition/Builtin`、`Composition/Carrier`。
- **[P3] 同一字段三处描述**：根键集合 `PreviewConfigurationJson.hpp:352-371`（19 键）vs `PreviewConfigurationSchema.hpp:20-23`（14 必填）vs validator 里的字符串路径（`:75,79,92,100,113,119,144,531-565`）；mux/枚举白名单三份且口径不同（`:662-665` vs `Composition/MuxService.hpp:70-72`）；log level/RenderMode 两份（`PublicSettingsValidator.cpp:31-51` vs `Diagnose/Detail/AsyncBackendState.hpp:57-58`）。
- **[P2] secret 生命周期不对称**：`ConfigurationParser.cpp:61-73` 的 `Parse()` 返回含明文的 `PreviewConfiguration`，而安全副本在 `PreparedConfiguration.cpp:180` 析构时被销毁 —— 拿到的是明文、丢掉的是安全副本；`PreviewConfigurationSchema.hpp:53-57` 的 `glz::generic` 预检把含 `Secrets` 的整树深拷进 Document，函数返回即按普通 `std::string` 析构，未走 wiper；内联 `Accounts[].Credential`（`PreviewConfiguration.hpp:197-198`）由 `ConfigurationGeneration.hpp:97` 的 const 成员持有到进程结束。
- **[P2] `Priority` 静默截断**：`ClampCandidatePriority`（`:1189-1197`）把 >65535 折叠为 65535，而 binding 歧义判定用原始 int32 比较（`:1378`），`Application.cpp:1965` 是第三份同规则拷贝 ⇒ 65535 与 70000 运行时同优先级，validator 判"不歧义"而放行真实歧义。
- **[P2] `Routes` 与 `Statistics.Enabled` 校验-运行脱节**：`Routes` 是 schema 必填根字段并整套校验（`:507-519`），运行时却一律拒绝（`Application.cpp:985-991`）；`Statistics.Enabled`（`PreviewConfiguration.hpp:236`、json:83）全仓零消费者。
- **[P2] 热重载完全未接线**（CONFIG-02 加重）：`ConfigurationStore`/`ReloadCoordinator` 仅测试引用，`HotReload` 生产零引用，`Application.cpp:4173,4193` 硬编码 `GenerationId{1}`；`ReloadCoordinator.hpp:81-112` 还是"先 ack 后 publish、publish 失败无回滚"。
- **[P3] 地址/DNS/路径只判非空**：`:1899-1908`（Address）、`:521-529`（Dns.Servers）、`:160-166,1523-1533`（证书路径）；`PublicSettingsValidator.cpp:56-60` 对 `Logging.Directory` 只判非空，而 `SinkSet.hpp:115-127` 直接 `create_directories(Directory)` 并拼接 `FileName` ⇒ 相对/穿越路径在运行时才暴露。
- **[P3] `IsValidUuidText` 不校验连字符结构**（`:677-709`，任意位置跳 `-`、32 nibble 即通过）；`Quic.MaxStreams/MaxDatagrams` 只校验 >0（`:303-308,834-858`）。
- **[P3] 错误聚合缺失**：全链"首个失败即返回"，`ConfigurationError` 无 json pointer/行列，`PreviewConfigurationSchema.hpp:46` 的 parse 错误 Path 留空。
- **[P4] 死别名与占位**：`ConfigurationError.hpp:24-25` `InvalidPort/InvalidTimeout` 是 `InvalidValue` 同值别名且 0 引用；`:34-37` 四个错误码仅可经测试专用路径产生；`:48`/`ConfigurationParser.hpp:86`/`GenerationBuilder.hpp:30` 三重 `using` 别名；`ConfigurationStore::Pin()` 是 `Current()` 的同义空壳；`MapSecretRefResolver`/`MakeChainedSecretResolver`（`SecretRefResolver.hpp:69-85`、`PreparedConfiguration.cpp:228-261`）全仓 0 调用；`Preview/Application/Configuration/Detail/` 空目录。
- **[P4] `ResolvedSecrets::Lookup` 每次查找构造临时 key**（`ResolvedSecrets.hpp:41` `Values_.find(std::string(Reference))`，`PreparedConfiguration.cpp:167` 同型），被 `Application.cpp:591,1062,1135,1181,2617,2661` 调用；`Add` 用 `try_emplace` 静默丢弃同名第二值。
- **[P4] `ValidateServerNameList` 5 个位置参数含默认值**（`:801-806`），违反默认参数上限；`:434` 的 `if (ProtocolIndex)` 是恒真重复判空。
- **[P4] `PreviewConfiguration.json`** 含内联凭据（:58）、空 `SecretRef`（:57）、空 `NativeTls` 路径（:30-31）、硬编码公共 DNS（:63）、相对日志目录（:69-70）、`Operations.Endpoint` 明文管理面（:88，仅靠 `PublicSettingsValidator.cpp:128-133` 字符串白名单保证环回）—— 与 `logs/issues.md` 已登记的 configuration.json 硬编码凭据同级。

### 4.4 `Preview/Composition/`（51 文件 / 13,226 行）

**它已不是 composition，而是第二个 Runtime + 协议 service 聚合层。**

- **[P3] owner 错位（A 类，逐文件）**：

| 文件 | 行数 | 实际承担 | 应属 |
| --- | ---: | --- | --- |
| `AnytlsService.hpp` | 986 | AnyTLS frame、stream 表、dial、relay、close、StreamTransport | `Protocols/Anytls/Service` |
| `Recognition/CandidateFactory.hpp` | 941 | 完整 HTTP 入站代理 `HttpHandler`（`:508-652`）、5 个 `PrepareXxx` 认证（`:329-468`）、Basic 认证两套（`:98-124,686`） | `Protocols/Http1` + 协议 owner |
| `Recognition/TlsCandidateFactory.hpp` | 800 | 8 carrier 的 candidate 构造、ClientHello 特征、SNI 归一化 | `Protocols/<carrier>` + `Ingress` 分类 |
| `MuxService.hpp` | 658 | smux/yamux/h2mux/singmux 会话编排、模式解析三轨 | `Protocols/Mux/Service` |
| `Quic/Hysteria2Factory.hpp` | 647 | HY2 raw stream 帧、HTTP/3 auth、datagram、relay | `Protocols/Hysteria2/Service` |
| `UdpService.hpp` | 618 | 4 协议 UDP session 语义 + 4 处 `dynamic_pointer_cast` | 各协议 `DatagramService` |
| `VlessXudp.hpp` | 544 | XUDP frame、flow map、socket、relay | `Protocols/Vless/Xudp` |
| `H2MuxServer.hpp` | 502 | H2Mux stream accept/relay bridge | `Protocols/Mux/H2Mux` |
| `Carrier/FacadeCarrier.hpp` | 491 | 第二套 carrier 契约 + 自建 `CarrierError`（与 `Preview::Error` 重复） | 中立契约模块（且当前 0 生产调用） |
| `Quic/TuicFactory.hpp` | 346 | TUIC push callback、lease/relay/dial/resolve/report 装配 | `Protocols/Tuic`（已有 `Admission`） |
| `Recognition/RealityPrepared.hpp` | 183 | Reality TLS1.3 握手编排：X25519 ECDH、SessionId 解密、ShortId、ServerHello/Finished 验证、密钥派生 | `Protocols/Reality` |
| `Settings/Loader.hpp` + `Json.hpp` | 766+436 | 自研 JSON parser（legacy）| 应删或显式 compatibility target |

- **[P2] 资源与正确性**：AnyTLS（`AnytlsService.hpp:119,885-889,935-951`：emplace 无容量检查、`try_send` 失败即整连接 `Close`、慢上游被当协议错误而非背压；`StreamTransport` 未覆写 `Shutdown/NextLayer` ⇒ 半关闭 FIN 丢失，客户端只能等 30s 超时；`:875-882` detached relay 不受 `Control`）；XUDP（`VlessXudp.hpp:421,434-438,481-496,507-528,516`）；mux（`MuxService.hpp:476,544-553,589-648`、`H2MuxServer.hpp:55,212-220,482-491`）；UdpService（`:58` 硬编码 60s 与配置 `IdleTimeoutMs` 脱钩、`:456-457` 不过滤回包源、`:212-220` SS2022 返回 NotSupported 而实际另有 Ingress 模型）。
- **[P2] 热路径重复解析**：`TlsCandidateFactory.hpp:689-700,457-474` 每个候选每轮全量 `ParseClientHello`（Prepare 再解一次），`:377,384` 每连接对每个 SNI 模式 `Normalize` 分配 `std::string` ⇒ O(候选数×轮数) 解析；`CandidateFactory.hpp:881-887` 把 AnyTLS `VerifyAuth` 放进 `Inspect`，非 winner 候选也付密码哈希成本。
- **[P2] 类型擦除无标签**：`TlsCandidateFactory.hpp:48,243,248` `static_pointer_cast<const ClientHelloFeatures>`、`LayeredCandidateFactory.hpp:176-181`、`TrusttunnelCandidate.hpp:38-40`（入参直接忽略）—— 注册错类型即静默错误转型。
- **[P3] 四张协议元数据表漂移（具体不一致项）**：`ProtocolCatalog.hpp:204` xhttp `SupportsUdp=true` vs `ProtocolMatrix.hpp:153-161` 无 xhttp；`:175` trusttunnel 同样；`:152,158` hysteria2/tuic `SupportsUdp=false` 却在 `ProtocolMatrix.hpp:159-160` 登记为 UDP association；`ProtocolBuiltins.hpp:132,140` 宣称 socks5/ss2022 提供 Multiplex，而两个 adapter 无 mux 分支；`:148-150` 宣称 TrustTunnel 提供 Datagram，adapter 无该路径；`Loader.hpp:154-156` 收 `shadowsocks` 别名却缺 `anytls`/`trusttunnel`；`ProtocolMatrix.hpp:144-161` 只有 `ss2022`（`SupportsUdp("shadowsocks")=false`）。另 `ProtocolCatalog::Supports` 对未知 Scope `default: return true`（`:90-100`），而 `OperationScope` 含 DnsResolve/RouteLookup/Dial 三个未覆盖值 ⇒ 虚假能力声明，且 `Supports()` 生产 0 调用者。
- **[P3] 双轨装配**：`MakeProtocolAccept`（`ProtocolAdapter.hpp:86-113`）与 `ToTypedResult`（`TypedResult.hpp:182-213`）逐字段对应，后者 `AcceptTyped` 全仓 0 caller，且 `TypedResult.hpp:208` 未 `reset()` 嵌套 optional（同一 bug 模式在**生产路径** `Context.hpp:136-139` 也有一份）；`SettingsBuilder.hpp:150-195,216-372` 与 `ProfileBuilder.hpp:130-135` 是 test-only 启动引导（Application 在 `:2162-2256` 重新实现同一循环）；7 个 `MakeXxxCandidate` 别名（`CandidateFactory.hpp:899-939`）、`MuxService::Stop/IsStopping`+COW 注册表（`:230-254,103-111,343-397`）无生产 caller；`Adapters/{Hysteria2,Tuic}.hpp` 整文件 0 引用。
- **[P3] `Builtin` 不是插件工厂**：`ProtocolBuiltins.hpp:189-192` 的 Callback 恒返回 `NotFound`，`Snapshot::Invoke`（`Snapshot.hpp:131-159`）无生产调用者、`Find` 线性扫描；`:236-276` 六个注册入口中 4 个是同一函数别名且 0 调用者；`Capability.hpp:35-39` 五个别名无使用者。命名暗示"注册即可运行"，实际生产只做字符串比对（`Application.cpp:789-810`）。
- **[P3] `FacadeCarrier` 三宗**：491 行不在生产路径；`Accept`（`:356`）无条件新建 `HandshakeState`，忽略 `Request.State`（`:276`）⇒ 外部无法传共享状态做取消/跨候选追踪；被 `Protocols/{Reality,Restls,Shadowtls}/Carrier.hpp:9,9,10` 反向 include，形成 `Composition ↔ Protocols` 环。
- **[P4] host:port 解析 5 份实现且语义不同**：`RestlsCarrier.hpp:64-107`（缺省端口 443）、`ShadowtlsCarrier.hpp:66-99`（缺端口即拒）、`Hysteria2Factory.hpp:179-200`、`AnytlsService.hpp:437-505`、`VlessXudp.hpp:96-151`。
- **[P4] 规模/规范**：>120 行函数 `RealityPrepared.hpp:43-181`(139)、`CandidateFactory.hpp:520-643`(126)、`VlessXudp.hpp:411-542`(132)；>10 行 lambda `AnytlsService.hpp:705-775`(71)、`TlsCandidateFactory.hpp:183-233`(59)、`UdpService.hpp:70-115`(46)；默认参数超限 `TlsCandidateFactory.hpp:176-180`；`namespace detail`(小写) 与 `Detail` 混用；英文注释 `AnytlsService.hpp:3-5`、`AnytlsWire.hpp:3`、`UdpService.hpp:3`、`MuxService.hpp:3`、`Hysteria2Factory.hpp:47,114,356-358`、`ShadowtlsCarrier.hpp:145-147`；`Adapters/Ss2022.hpp` 使用 `Runtime::Detail::*` 却未 include `Common.hpp`（靠 `ProtocolAdapter.hpp` 的 include 顺序存活，单独 include 即编译失败），`Vless.hpp:12,15` 重复 include 同一头。

### 4.5 `Preview/Foundation/`（64 文件 / 10,833 行；Diagnose 子树 19 文件 ≈4,600 行）

- **[P3] 底层反向依赖上层（三向）**（结构性，见 §3.2；不是行为缺陷）：`Authenticator.hpp:19-20` 同时 include `Account/Directory.hpp` 与 `Foundation/Utility/Account/Directory.hpp`（两套账户模型进同一 TU，26 个生产文件被动继承）；`SessionBase.hpp:26` → `Transport/Stream.hpp`（`:12-15` 自陈 DEPRECATED，仍被 `Protocols/Mux/StreamState.hpp` 使用）；Diagnose 5 处 → `Statistics/{Redaction,Trace}`。后果：Foundation 不能独立编译/复用/测试，且形成 `Foundation ↔ Statistics` 模块级环。
- **[P3] `CachedMessage` noexcept + 构造 `std::array<std::string,N>`**（`Fault/Compatible.hpp:30-53`，§3.6 条目 10）：静态初始化时 OOM 即 `std::terminate`；同文件 `:31-32` 的"后续零分配"与 `message()` 按值返回矛盾（`Protocols/Http2/Impl.hpp:74-81` 另有一处 preface 首字节不符即整体跳过校验的兼容分支，记在 §4.10）。
- **[P3] 错误码按硬编码序号跨层映射**（`Fault/Handling.hpp:103-127`，注释自认"固定枚举序号"）：`case 0..18` 无枚举名、无 `static_assert`。逐项核对 `Error.hpp:26-68` 后**当前映射成立**，只有 `KdfError(16)`/`CryptoError(19)` 细节降级为 `GenericError`；缺陷是"以后改枚举顺序不会被编译期拦住"。
- **[P2] 五套错误体系并存且实测使用量同级**：`Preview::Error` 389 处、`Fault::Code` 433 处、`std::error_code` 387、`boost::system::error_code` 412、`ProtocolEc` 21、`Preview::Foundation::Error`（仅 Builtin）。三种 `AuthFailure`/`AcquireFailure`/`AuthReason` 枚举逐字重复，靠三份 1:1 转换函数维持（`Foundation/Authenticator.hpp:249-268`、`Account/Authenticator.hpp:88-107,217-236`）。
- **[P2] `Fault::Handling` 在数据路径做字符串比较**：`:91,103` 用 `category().name()=="Preview::fault"` 判定，调用点含每读一次即转换（`Protocols/Common/Read.hpp:59,110`、`ProbeBuffer.hpp:134,202`、`Relay.hpp:403`、`Restls/Conn.hpp:464`、`Shadowtls/Conn.hpp:569`）；同文件 `:185` 已示范正确写法 `&category()==&Category()`。
- **[P2] `Memory/Pointer.hpp:76` + `Pool.hpp:73-86`**：`thread_local UnsynchronizedPool` 永不释放，`SharedSessionResource` 以 shared_ptr 跨协程/线程持有 ⇒ 跨线程释放 UB；`PooledObject`（`Pool.hpp:135` 默认 `PoolType::Local`）new/delete 各取当时线程的池。
- **[P2] Crypto 包装的安全前提未落地**：`X25519.hpp:109-120` `RAND_bytes` 失败静默返回全零私钥；`Hkdf.hpp:212-247` 派生密钥落普通 `std::vector` 且从不 wipe，全仓无 `OPENSSL_cleanse/memset_s/explicit_bzero`；`Aead.hpp:268-307` 构造失败 `return;` 后 `Ctx_` 保持 nullptr 且不报错、密钥长度不自校验；`Base64.hpp:77-89` 静默丢弃空白并同时接受两套字母表（凭据可被规范化差异绕过，Http1/Trusttunnel/SS2022 用它解凭据）。协议绕过包装直用底层：`Reality/Codec.hpp:201` 调 `::X25519`（跳过 `X25519.hpp:159-173` 的低阶点全零检查）、`:152` 自建 `GenerateKeypair`；`Reality/Response.hpp:79` 自建 `HmacSha512`；`Trojan/Codec.hpp:56` 自建 28 字节 Sha224；`Restls/Codec.hpp:87-110,151-183` 直调 `blake3_hasher_*`（跳过 32 字节密钥校验）。
- **[P3] 零生产使用的 Foundation 资产（约 2,300 行）**：`Exception/*` 586 行（`Exception::` 在生产 0 次）、`Parser.hpp` 318 + `FlatBuffer.hpp` 245（Mux 三个 Codec 只靠其传递 include，实际无 `Parser<` 使用）、`CodecTraits.hpp` 135（全仓仅 CMake 提及）、`Crypto/{X25519,Blake3,Block,Sha224}` 593、`Rate/TokenBucket.hpp` 251（唯一使用者 Throttle 中间件，生产 0 装配点）、`Memory/Pool.hpp` 的 `PooledObject/EnablePooling/MonotonicBuffer/HotPool` + `Memory::{Map,UnorderedMap,List,Allocator}`（**Preview 从不调 `EnablePooling` ⇒ AGENTS.md 的 PMR 热路径零分配承诺在本实现未落地**，`CurrentResource()` 实为 new_delete）、`CowMap.hpp` 135、`Coroutine/Registry.hpp` 368（与 `Lifecycle::TaskRegistry` 同名类同 `SpawnTracked` 语义不同）、`ByteSpan` 的 `As<>` 家族（生产 0，tests 47）、`Identifier/{Identifier,Types}` 三重 3 行转发头、`Executor/{Affinity,Types}`、`Cancellation/{Mode,Types}`、`Memory/{Types,Domain}`（`Affinity/Mode/Domain` 三个枚举只在 Builtin 存值与参与哈希，无任何行为执行点）。
- **[P3] `Foundation.hpp` 聚合头约定失效**：生产 0 include（仅 1 个测试），却仍导出无用户的 `Coroutine/Registry.hpp:35`；同时未导出 15 个真实在用的顶层头（`Authenticator/ByteSpan/Error/CodecTraits/FlatBuffer/Parser/Role/SessionBase/CowMap/Utility/*`），违反 AGENTS.md"新增子头文件需同步更新聚合头"。
- **[P3] `Block.hpp:87-97,138-148`**：`Output` 仅 16 字节却把 `EVP_*Final_ex` 写入 `data()+OutLen` 且不校验 `OutLen/FinalLen` ⇒ 潜在 one-past-end 越界；当前 0 生产调用，属"带缺陷的死代码"。
- **[P3] `CowMap.hpp:99-113`** 无界 CAS 重试（每次整表复制，无退避无上限）、`:77` 自认 UpdateFn 可被多次执行（非幂等重放）、`:86-91` `Remove` 的 `Removed` 在重试下可被覆盖。
- **[P4] `TokenBucket.hpp:23-25` 用 `#error` 硬性要求 x86_64 + `__int128`**，`:28,30` GNU/Clang 属性、`:67` `volatile` 与 `__sync_*` 混用 —— 架构假设写进 Foundation 头；`Error.hpp:155-209` 约 55 行是 gtest 断言用 `operator==` 重载（`:156` 注释自述）—— 测试工装进生产头；`Fault/Code.hpp`、`Memory/{Pool,Container}`、`Exception/Deviant` 标注"镜像自 `include/prism/…`，锁定"，Crypto 各头标注"已分叉" —— 与旧版双份维护是既定状态。
- **Diagnose 子树专项**：
  - **[P2] 停机后日志静默丢失**：`DiagnoseRuntime.hpp:151-155` + `BackendLifecycle.hpp:180-185` 在 `BeginShutdown` 即 `Accepting=false`，其后 Services/DnsResolver 析构等终态事件全部返回 `Stopped`，既不落盘也不计入 `Dropped[]`，与 `Application.cpp:3373` 注释"worker 停止后仍可记录最终事件"矛盾。
  - **[P2] 提交/卸载残留竞态**：`Facade.hpp:189-206,115,131-136` 的 `ActiveCalls.fetch_add(acq_rel)` 与 `Submit` 置空分属不同原子变量，acquire/release 不禁止 store-buffer 重排 ⇒ 理论上提交方可带旧 `Submit` 进回调而卸载方已见 0 放行 owner 销毁（x86 TSO 下不可观测，ARM 构建即现行缺陷）。
  - **[P2] `Logger_` 非原子 shared_ptr**（`AsyncBackendState.hpp:161`）被 `AsyncSubmission.hpp:144,177` 读、`BackendLifecycle.hpp:185` reset，而 `Pool_` 用 `atomic<shared_ptr>` —— 保护不对称，唯一防线是类注释。
  - **[P2] 每条日志全量脱敏且多层重复**：`BackendBridge.hpp:62` 无条件 `RedactSensitiveText` → `AsyncSubmission.hpp:86` EmergencyWriter 再脱敏整个 payload → `ContextDecoder.hpp:287`+`ContextState.hpp:409`+`FieldCodec.hpp:158` 同一字段最多被同算法扫 3 次；facade 之外 `Transport/Encrypted.hpp:390`、`Relay.hpp:50`、`Operations/Redaction.hpp:19`、`EventRing.hpp:94` 各自预脱敏。算法单一（无漂移），但"哪层可信"无合同，漏一层即泄漏。`Statistics/Redaction.hpp:96-217` 本身 122 行超限，`:21-36` 每个候选 token 构造小写 `std::string` 做 21 次比较。
  - **[P3] 过度分层**：Facade→SubmissionSlot→DiagnoseRuntime→BackendLifecycle→BackendBridge→AsyncSubmission→SinkSet 七层，`BackendBridge` 整类只有 1 个静态方法且唯一调用点在 `BackendLifecycle.hpp:117-121`；`Facade.hpp:145-149 IsEnabled` 纯转发；级别阈值每条日志检查 3 次；`SubmissionRequest/Record` 双结构仅搬字段。
  - **[P3] `Observability.hpp`(377 行) 生产未接线**（仅 `tests/Preview/core/diagnose/ObservabilityTest.cpp:17` + CMake 源列表），`HdrHistogram/EwmaMeter/SampleTracer` 宣传的速率统计与采样环无生产消费点；`EmergencyWriter/FallbackWritten`（`AsyncSubmission.hpp:52-104`、`SubmissionReceipt.hpp:20-24,50-53`）同为死双轨（README:410 自认）。
  - **[P3] 停机 barrier 与 flush 饥饿**：`SinkSet.hpp:214-262` 每次 Drain 新建 barrier logger+promise+future；`AsyncSubmission.hpp:206-209` 的 `Flush` 在 `EnqueueGate_` 忙时静默跳过 ⇒ 高频日志下 250ms 定时 flush（`Application.cpp:3356-3367`）可被持续跳空，warn 以下日志滞留到 pool 析构。
  - **[P3] 热路径线性查表**：`ContextDecoder.hpp:56-84` 扩展模式每条日志遍历 19 个 Descriptor，`:219-240` `FindBinding` 线性；`FieldCatalog::Find`（`:106-116`）线性扫描，而 `FieldId` 是 0..18 稠密枚举，可直接 constexpr 反查表。
  - **[P4] 每条日志 ≥4 次堆分配**（`Facade.hpp:210`、`BackendBridge.hpp:62`、`AsyncSubmission.hpp:170`、`ContextDecoder.hpp:44/127`）；Diagnose 目录 0 个 `.cpp`，`SinkSet.hpp:9-16` 把 spdlog 重 include 传给 17 个 `Facade.hpp` 引用者与 11 个 `ContextState.hpp` 引用者；`FieldKey.hpp:140-142` 4 个默认模板参数；`Observability.hpp:53,182,285` 用前置返回类型违反尾随返回规范；`PrefixCache.hpp:88-98` 依赖"20 位十进制上限"这一脆弱假设（建议 `static_assert`）。

### 4.6 `Preview/Ingress/`（8 文件 / 2,123 行）

- **[P2 潜伏] 回落合同被 move 破坏**（§3.6 条目 2）。`IngressDispatcher.hpp:60-64` 的注释明确说明回落是为了"避免 SS2022 密文首字节偶然命中 QUIC fixed bit 造成随机丢包"，但 `:52` 已把 `Packet` 移入 `QuicGateway::Handle`（`:164` 按值取参，且生产无 `RegisterConnection` ⇒ `:198-201` 恒 `return false`），`:70` 交出的是空 payload。**为什么不是现行丢包**：`Application.cpp:4415-4424` 注册的 datagram 消费者只有 `Ss2022Gateway`，其 `Handle` 对 Quic/UnknownCid 包要求的准入谓词与 `CanAcceptUnclaimedQuic`（`:83-94`）完全相同（`HasAuthenticatedClientWire`），因此 admission 已拒绝的包，回落拿着完整 payload 也一样会被拒 ⇒ 结果等价。风险在于：任何第二个 UDP 协议、或两个谓词分叉（例如未来 SS2022 允许未认证首包做探测），这条回落就变成静默丢包。整改：`Dispatch` 收 `const UdpPacket&` 或先决定路由再转移所有权；typed `IngressDecision`。
- **[P2] `QuicCidRegistry` move-key 清理失效**（`QuicCidRegistry.hpp:127,137`）：`emplace(std::move(Key))` 后在拒绝路径用 `Entries_.find(Key)`；`Key` 是 CID 容器，move 后为空 ⇒ find 必失败，被拒 server 与 entry 残留，`Server->Close()`/`EraseServerEntries` 被跳过（成功路径用 `It`，不受影响）。
- **[P2] QUIC admission 无容量上限**：`QuicCidRegistry.hpp:60,94,127` 三处 emplace 无 size 检查；`QuicGateway` 的 `MaxConnections` 只约束生产从不登记的那张表，且 `Application.cpp:4406-4410` 硬编码 4096/65536 而非取配置。`Native.cpp:1415-1460` 对未知 CID 直接分配 ngtcp2 conn + `SSL_new`，无 Retry/stateless 验证（`:1569-1572` 还刻意保留 `ERR_RETRY` 包）。
- **[P2] 分流键用 peer 而非 CID**：`QuicCidRegistry.hpp:71-81` + `Register:55-56`（同 peer 的第二条 server 被拒）⇒ CID 轮换/迁移退化；`UdpDemux::RegisterQuicCid` 生产 0 调用（仅测试），两张 CID 表恒空。
- **[P2] `UdpDemux` 热路径线性/碰撞**：`:307-325` 对全部登记 CID `std::equal` 无早退、`:327-340` 最多 20 次 FNV 查表、`:280-293,304` 64 位哈希可跨连接误投。
- **[P2] `QuicGateway` 单连接失败毒化整网关**：`:203-206,292-296` 超 `MaxPacketsPerConnection` 或一次 handler false/异常即 `MarkBoundedFailure()` 永久置 `Readiness::Failed`，而 `Handle` 不看该标志继续收包；`:181-189` 使短头 legacy 命中路径与 `Connections_` 互斥（`UdpDemux.hpp:211-218` 返回 `RegisteredCid` 时永远查不到 handler）。
- **[P2] `Ss2022Gateway` 是协议实现不是入口**（INGRESS-03 仍成立）：`:126-152` wire/PSK 试解（admission、Handle、Process 各对全部 key 试解一轮）、`:159-187` peer replay window、`:189-210` DNS、`:263-290` 每包新建出口 socket、`:298-322` 响应加密、`:325-381` peer 表；`:129-134,219-224` 逐字节转 vector；`:97-103` co_spawn detached 在途无上限；`Close()`(`:107-112`) 只清 peer 表不取消在途。
- **[P2] `UdpListener` pump 脱离 lifecycle**：`:159` `Net::detached`，`:262-280,330-337` 异常只 `++PacketsRejected`；`:191,341` 容量 1 的 channel 使二次 Drain 无超时即挂；`:259,267,302` 非原子 `LastError` 被 pump 写、`:233` Health 读。
- **[P3] 三套并存的 QUIC 连接表**：`QuicGateway.hpp:299-300`、`UdpDemux.hpp:356-357`、`QuicCidRegistry.hpp:334`，前两套生产 0 调用；`QuicCidRegistry::Register`（`:44-63`）也无 caller，其 3 个 O(N) 前置检查纯属负担。
- **[P3] `IngressDispatcher`/`QuicGateway`/`Ss2022Gateway` 三种 bool/void 合同**（INGRESS-04 仍成立），"已排队"与"已认证"不可区分；`UdpAssociation.hpp` 仅测试引用却登记为生产源（`Preview/CMakeLists.txt:233`）且表无上限（`:197-207`）。
- **[P3] `UdpDemux.hpp:4-6` 自述"不解析应用协议"与 `:226-278` 的 QUIC 长头解析矛盾**（注释与实现漂移）。

### 4.7 `Preview/Lifecycle/` + `Resource/` + `Scheduler/` + `Statistics/`

- **[P2] Worker 停机不 Drain**（LIFECYCLE-02）：`Resource/WorkerResources.hpp:152-161` `Cancel()→Work.reset()→IoContext.stop()`、`Runtime/Worker.hpp:150,162-170`，在途会话协程帧与其 socket 被直接抛弃，registry 只能在析构时 quarantine（`TaskRegistry.hpp:456-478`）；进程级 Tasks 反而有 Drain（`Application.cpp:3409-3417`）—— 两个层级语义不一致。
- **[P2] `TaskRegistry` 每次 spawn 复制全局集合**：`TaskRegistry.hpp:135-180`（COW `std::set<uint64_t>` + CAS 重试）、`:515` 每任务 `CreateChild` → `CancellationDomain.hpp:56-72` 复制 children 向量 ⇒ 控制路径 O(N) 分配与跨线程争用，任务数无上限。
- **[P2] `EventRing` 不是环**（§3.6 条目 28）；`SparseCounters.hpp`（146 行无锁 map，`MaxEntries==0` 即无限，`:73`）与 `TrafficDelta.hpp`（`:60-66,108-116` 无上限线性 `find_if`；`:69-89` Flush 后不清空且永久拒刷）只被未接线的 `Api/StatisticsApi` 与基准消费 ⇒ **生产实际上没有可用计数器**。
- **[P3] LIFECYCLE-01 仍成立**：`TaskRegistry.hpp` 710 行，`SpawnTracked`（`:492-635`）≈140 行、内层 lambda `:559-629` 70 行；`:124` 的 `Stats.Active` 用 Barrier 计数而非 `Active.size()`（观测与真实集合可能背离）。
- **[P3] 四层资源模型只落地两层**：`SessionResources.hpp`/`StreamResources.hpp`/`Resource.hpp` 全仓（含测试）0 引用；`ExecutorReclaimer.hpp:115-128` 的 `Pending/QuarantinedCount/ActionFailures` 无生产读取者且每次 Post 两次堆分配（`:60-90`）。
- **[P3] `FailureBoundary.hpp:44-57`** `catch(...)` 吞全部异常仅计 `Failed`；`CancellationDomain.hpp:144-151` 在 strand 上 emit 而 `TaskRegistry.hpp:620` 在另一 Executor 上 await（跨 executor 使用 `cancellation_slot`）。
- **[P3] Scheduler 整模块未接线**：`FairScheduler`/`PriorityScheduler`/`Types`/`Detail/FixedTable` 只被 `Preview/Performance/SchedulerBenchmark.cpp` 使用（`tests/Preview/perf/CMakeLists.txt:21-25`）；而 `WorkerResources.hpp:169` 把一个 strand 成员命名为 `Scheduler` —— 名称撞车且无实现对应。
- **[P4] `Statistics/{Counters,Events}.hpp`** 分别是 4 行/3 行占位头；`Statistics.hpp`(13) 与 `Runtime/Statistics.hpp`(402) 双轨（后者 COW、每新增 identity 复制整表，生产 0 使用）。

### 4.8 `Preview/Net/`（22 文件 / 5,672 行）与 `Transport/`（12 文件 / 4,081 行）

- **[P2] DNS 三处无上限 + 事务 ID 可预测**（§3.6 条目 29）；`Resolver.hpp:99-104,586` 全进程单 strand 串行（吞吐瓶颈）；`Doh.hpp:141-146` 只匹配两种 Content-Length 大小写（其余走 `:176-178` fail-closed），`:182-187` 丢弃 body 后多余字节破坏 keep-alive 复用语义。
- **[P2] `Dialer` 多地址重试复用已失败 socket**（`Dialer.hpp:124-144`，仅 `:142` 移动）⇒ 首地址失败后其余地址基本不可用；`:115-118` 直接用 `Tcp::resolver` 绕开 DNS 模块；`:108,121,145` 把所有错误压成 `connection_refused`/`no_such_file_or_directory`；无 Happy Eyeballs。
- **[P3] 拨号/解析 8 处重复实现**（NET-03 加强）：`Application.cpp:656,691,745`、`Services/WorkerDialService.hpp:51-117`、`Composition/UdpService.hpp:545`、`VlessXudp.hpp:382`、`Transport/Unreliable.hpp:557-592`、`Dialer.hpp:114-123`、`Resolver.hpp:500-540`。
- **[P3] NET-02 仍成立**：`Net/Route/Route.hpp`、`Net/Outbound/Outbound.hpp` 生产 0 caller（只有注释引用 `Middleware/Builtin/Dial.hpp:5`）；存在两个 `Target`（`Net/Target.hpp:24`、`Outbound.hpp:32`）；`Route.hpp:65,79` 每次 `find` 构造 `std::string`，与自身 `:7` 的"无临时分配"注释矛盾。
- **[P3] `UdpRelay.hpp:198`** "单活跃会话简化"：新来源即删除本侧旧的未配对条目，peer 表无容量上限（`:83-137`）。
- **[P3] Transport 的重复是超时/取消/半关/错误映射，而不是 writer 队列**（更正我最初的猜测）：`Unreliable.hpp:324-337,401-404`；`Reliable.hpp:174-183` 与 `211-262`（awaitable 与 completion 两套 race）；`Encrypted.hpp:352-377`；`Transmission.hpp:316-336` 默认转发；`Encrypted::Close`（`:170-179`）直取叶子且无 close_notify 主动半关；`Unreliable::Shutdown`（`:391-393`）**空实现**；`Unreliable.hpp:262-294` 非对端数据报无限静默丢弃且无超时；`:557-592` 在读路径新建 `udp::resolver` 并 `Socket_.open` 改族。
- **[P3] 脱敏错位**：唯一算法在 `Statistics/Redaction.hpp:96`，却被 Foundation/Diagnose 5 处、`Transport/Encrypted.hpp:14,390`、`Runtime/Middleware/Relay.hpp:34`、`Operations/Redaction.hpp:9` 反向依赖；`Account/SecureBytes.hpp:67` 的 `"[redacted]"` 是第三套语义。
- **[P4] `Transport/MemoryStream.hpp`** 85 个测试 include、生产 0 —— 测试夹具驻留生产模块与生产 target；`Transport/Algorithm.hpp` 同样仅测试。

### 4.9 `Preview/Operations/`（8 文件 / 2,917 行）

- **[P3] `HttpServer.cpp` 1,877 行 ≥6 种职责**：accept 循环（`:1470-1575`）、HTTP parser（`:1579-1714`，136 行）、dispatch（`:1085-1150`）、响应序列化（`:402-670`）、连接表（`:1426-1467`）、drain（`:1804-1865`）；三套关闭路径 + 两个 strand + 两个 flag 使最终关闭者不可判定（`:1151-1260`）。
- **[P2] 管理面与数据面同线程**：`Router.hpp:326-339` 同步执行 handler，`Application.cpp:4404-4450` 同一个 `Runtime->Io` ⇒ 一个大分页快照阻塞全部数据面；`HttpServer.cpp:1438` 连接数无上限、`:1345` + `HttpServer.hpp:27` 每连接预留 16KB。
- **[P3] `Router::SetQueryHandler/SetCommandHandler` 只 post 无完成通知**（`:302-316`）；鉴权只有 `is_loopback()`（`HttpServer.cpp:1525-1529`），`RouterOptions` 无 token 字段（`:43-47`）却能承载 Revoke/Drain。
- **[P4] `Commands.hpp`(3 行)、`Queries.hpp`(3 行)、`Operations.hpp`(10 行)** 是占位/转发头；`Redaction.hpp` 与 `Statistics/Redaction.hpp` 概念重复。

### 4.10 `Preview/Protocols/`（168 文件 / 52,407 行）

（协议间共性问题：`Adapters/`→协议→`Composition` 三处重复装配见 §4.4；owner 分裂见 §3.1；此处记协议内部缺陷。）

- **Quic / Http3 / Hysteria2 / TUIC**（竖切最重）
  - **[P1]** datagram 无门禁（§2.1）；**[P2]** 配置上限零消费、`Streams_` 不 erase、callback+queue 双路（§3.6 条目 20）；**[P2]** per-stream 接收队列无字节预算（`Native.cpp:169,1993`，只受静态 64KB/流、1MB/连接流控限制 `:1397-1400`）；**[P2]** `GatewayCommon.hpp:159-162` 登记即 `authenticated=true`（QUIC-05 仍成立，当前无生产读取点）；**[P2]** `NativeServer.hpp:57,248-252` H3 事件通道（容量 256）`try_send` 失败即 `co_return`，ReadLoop/AcceptLoop 退出但不关连接也不报错 ⇒ 半开流；**[P2]** `Native.cpp:709-716` `NativeDatagram::Receive` 缓冲不足时丢弃剩余字节（合同写在 `DatagramAdapter.hpp:46`"由实现定义"）。
  - **[P3]** `Native.cpp` 2,784 行多 owner 拼接（socket token 全局表 `:70-157`、TLS/回调、pump、provider、CID 判定 `:1580-1637`、门面 `:2450-2784` 约 330 行纯转发）；构造函数 19 参含 12 默认（`:285-299`）。
  - **[P2]** HY2 `Conn.hpp:518-533` 认证帧载荷截断 512B + `Codec.hpp:250-257` `Consumed = Data.size()` 整块吞为一条 payload ⇒ TCP 首包 >512B 或多帧合并时数据错位；`Dgram.hpp:561` `SessionId_` 恒 0（注释"测试简化：固定 0"）、`:402` 用 `static_cast<uint16_t>(PacketId_)` 写 wire 而 `:414` 32 位自增 ⇒ 65536 包回绕。
  - **[P2]** TUIC `Admission.cpp:56-62` 自定义 deleter 用 `dispatch` 投递析构（executor 停止则永不执行；deleter 无 catch，dispatch 抛出即在 shared_ptr 析构路径 terminate）、`:78` 析构 `assert(running_in_this_thread)` 在停止路径不成立；`:132` `MaxPendingBidiStreams=0` 默认全拒而认证成功后绕过上限（`:127-131`）；`:500` `AccountLease_.Release()` 早于仍在退栈的子协程持有的 StreamLease（父子合同待验证）。
  - **[P3]** HY2 wire 三套 owner 分裂（`Codec.hpp:4-6` 简化、`Dgram.hpp:63,107,179,563` 的 `StandardWire_` bool、`Hysteria2Factory.hpp:118-228` 的 0x401 风格帧，且地址族恒 `Domain` `:210`）；手写 QPACK 与 nghttp3 两套并存（`DynamicTable.hpp:21-42` 是空壳）；`Huffman.cpp:137-150,213-230` 每符号最多 30×256 次比较，而生产 HPACK 路径确实命中它（`Http2/Codec.hpp:225`）。
  - **[P4]** `GatewayCommon.hpp:52,59-64` `GuessProtocol` 恒返回 Unknown；`Codec`/`Parser` 的 `Buf_` 永不清理（`Hysteria2/Codec.hpp:418-491`、`Tuic/Codec.hpp:418-491`）；`Dgram.hpp:518-558` 未用的 `ReadExact/ReadAddressBody`；`Native.cpp:2332-2341` `RecvRetry` 未注册、`:1191-1195` 重复 `co_return Offset`、`Huffman.cpp:169-172` 不可达分支；4 处 `(void)Config`；`StreamAdapter.hpp:9-12` 注释仍指向旧树路径、`Tuic/Dgram.hpp:6-7` 头注释写 "AssocID 4B LE" 而实现是 2B BE。
- **代理协议叶（VLESS/VMess/Trojan/SOCKS5/SS2022/AnyTLS/Native/Common/ECH）**
  - **[P1]** VMess 握手零重放防护（§3.6 条目 6）；nonce 计数回绕与 Option 位不校验降为 **P2**（条目 4、5：属上游协议继承的 legacy AEAD 语义 + 实现缺少计数上限/轮换，不是新引入的密码学错误）。
  - **[P2]** VMess `RequestCodec.hpp:410-477`：`Put` 每次重做 4 组 KDF+GCM，配合 `Conn.hpp:578-640` 的**逐字节**喂入与 `Adapters/Vmess.hpp:53-68` 的逐账户重试 ⇒ O(账户数×字节数) CPU 放大，认证后 body 可达 65535B；同类：`SS2022/RequestCodec.hpp:496-532` 每字节重算 SessionKey(BLAKE3)+2 次 OpenRaw。
  - **[P2]** VMess 的 UUID 显式检查是死代码：`RequestCodec.hpp:467` `Msg_.uuid = Uuid_`（存的是期望值而非收到值），于是 `Conn.hpp:614-619` 的 `ConstantTimeEqual` 恒真。
  - **[P2]** SS2022 `Conn.hpp:690-691` 每块从单调 arena 取缓冲（`Pointer.hpp:225-245` ≤8KB 永不归还）⇒ 长连接内存随累计流量线性膨胀；VMess 用成员缓冲复用（`Vmess/Conn.hpp:763`）作为对照。
  - **[P2]** AnyTLS：`Protocols/Anytls/Conn.hpp:7` 自述"测试库简化透传"，真实 mux 帧在 `Composition/Anytls{Wire,Service}`，认证帧第三次出现在 `CandidateFactory.hpp:436-465`；`Anytls.hpp:51-55` `ServerConfig` 只有单 Password 无 Authenticator，`Application.cpp:2519-2533` 只取 first account ⇒ 多账户静默失效；`Conn.hpp:122-131` 认证前先按 `PadLen(≤65535)` 分配并吞 padding，未认证流量可迫使分配且无握手超时。
  - **[P2]** SOCKS5 `UdpAssoc.hpp:111` `bind(127.0.0.1:0)` 并把该 BND 应答给客户端 ⇒ 远程 SOCKS 客户端按 BND 发 UDP 永不可达（生产路径由 `Application.cpp:4602` 注入）；`UdpAssoc.hpp:266-288` 与 `Vless/UdpTunnel.hpp:180-214` Egress 未 `connect`，任意源命中临时端口即封帧回客户端并计入统计（目标侧 spoofing）。
  - **[P2]** `Vless/Codec.hpp:586-599` `Parser::Put` 失败路径 `Buf_` 只增不清，调用方须自行止损；其余 `Vless/Codec.hpp:299-395`、`SS2022/RequestCodec.hpp:241-320,519-562`、`Trojan/Codec.hpp:329-419` 边界校验经核**未见可崩溃级越界**（不夸大）。
  - **[P3]** UDP 数据面四套重复实现（`Vless/UdpTunnel.hpp:103-233`、`Socks5/UdpAssoc.hpp:203-290`、`UdpService.hpp:395-543`、`Net/UdpRelay.hpp:83-137`）；`Conn→AcceptResult→DataPlane` 四份拷贝（4 个 adapter + `CandidateFactory` 第 5 份）；`SendBytes` 同款 11 个协议文件、`ReadExact/RecvExactStatus` 家族 20+ 文件；`VLESS mux` 命令解析出假目标 `v1.mux.cool:0` 且 `Vless.hpp:190,223` 固定 `EnableMux=true` 无开关（若上层忘记 mux 分支即 dial 假域名端口 0）；`Trojan/Trojan.hpp:222-236` `AcceptPacket` 不校验命令类型（CONNECT 也被包成 Dgram）；`Vmess/Dgram.hpp:189,207`、`SS2022/Dgram.hpp:129,197` 每包 `dynamic_cast` 且模板参数 `Memory` 实际未使用；SS2022 `Types.hpp:23-31` 声明 Aes256Gcm/ChaCha20Poly1305 但 codec 硬编码 AES-128（`ChunkCodec.hpp:84,217`、`ResponseCodec.hpp:34`）= 假能力声明。
  - **[P3] 双轨开关清单**（"测试库简化 vs 真实 wire"同文件并存）：`Vless/Dgram.hpp:377 StandardWire_`（生产恒 true，legacy 仅测试）、`Vmess/ChunkCodec.hpp:332 UseAuthenticatedLength`、`SS2022/Conn.hpp:642-654 DerivePsk`（"测试库约定 SHA256[:16]"，生产走 `UsePsk=true`）、`Anytls/Conn.hpp:7`、`Socks5/UdpAssoc.hpp:9` 自述 Dgram 是"编解码测试模型"、`Socks5/{Dgram.hpp, Socks5.hpp:104-163 AcceptPacket/ConnectPacket}` 生产 0 调用、`Hysteria2/Dgram.hpp:63,107,179` `StandardWire_`。
  - **[P3] 无握手 deadline + 逐字节读**：`Vmess/Conn.hpp:578-640`、`SS2022/Conn.hpp:777-790`、`Vless/Conn.hpp:277-293`、`Trojan/Conn.hpp:331-347`、`Socks5/Conn.hpp:666-687`、`Anytls/Conn.hpp:122-131`、`Native/Conn.hpp:45-65`（服务端 TLS 无超时，客户端 Connect 有 30s：`:102-112`）—— 慢速攻击者可使连接常驻。
  - **[P4] Common/ECH/Native 死码**：`Common/{Form,Mux}.hpp` 全仓 0 include、`Common/Read.hpp:5-6` 声称"被 Trojan 和 VLESS relay 共同使用"实际生产 0、`Common/Framing.hpp` 仅 1 个测试；`Ech/{Scan,Keygen}.hpp`、`Native/*` 仅测试/interop；`Vmess/ChunkCodec.hpp:568-655` 的 `ChunkStream`（90 行）全仓 0 使用；`Socks5/Conn.hpp:634` private `ReadRequest` 无调用、`Codec.hpp:537` `ParseUserpassReply` 生产 0。
- **carrier 与 HTTP（Reality/Restls/Shadowtls/Ws/Xhttp/Gun/Http1/Http2/TrustTunnel/Mux）**
  - **[P2]** Reality SessionId 的 7 字节时间/随机字段从不参与比较 ⇒ 重放防护缺失、与上游（校验 ±checkTime）规范偏差；但仅重放 ClientHello 无法完成 TLS 1.3 握手（缺客户端握手密钥），故不是直接的会话获得路径（§3.6 条目 7）。
  - **[P2]** Http2 core 五项（§3.6 条目 24）；`Impl.hpp:74-81` preface 首字节不符即整体跳过校验（"兼容旧自回环"）；`Stream.hpp` 0 扇入死码；`H2Session::SendPing/SendGoaway/ConsumeData` 0 消费；`NextServerId_`(:384)、`StreamState.RxPending`(:364) 未用。
  - **[P2]** XHTTP StreamOne（§3.6 条目 25）+ `Conn.hpp:1041` `Path.rfind(Base,0)==0` 前缀过宽（`/mypathX` 命中 `/mypath`，split 路径有 `ParseSplitPath` 校验而 stream-one 没有）；无 boundary/multipart 解析，mode 靠大小写敏感字符串三层白名单；driver 循环内部 4 份拷贝（`:1069-1107,1434-1469,1735-1764,1954-1992`）。
  - **[P2]** Ws 无写串行器（§3.6 条目 26）—— 其余 carrier 都有 `WireWriter`，唯独 Ws 没有；已补证据：`Transport/Reliable.hpp:272-295` 直委托 socket 且无 strand/无写队列，两条协程可并发进入同一写链 ⇒ 部分写时帧字节交错。
  - **[P2]** Http1 `Parser.hpp:442-448` `ParseStatusCode` 的 `Code=Code*10+d` 对 >10 位数字有符号溢出 UB；除此之外 HTTP1 走私防线是全树最强的一组（`HeaderFields.cpp:275,318,339-400`：CL+TE 冲突、重复 Host、重复 CL、obs-fold、chunk extension/trailer、1xx/101、HEAD 全部显式拒绝或处理）—— 7.1 各项复核未见回归。
  - **[P2]** Gun `Grpc.hpp:758-764` TunEnvelope 内容嗅探（首条消息恰好 `0x0A`+varint+长度吻合即永久切换 protobuf 包裹模式）；`RxQueue_.push_back` 因 H2 自动 WINDOW_UPDATE 而实际无界；`:595-602` `Ready_` 等待无 timer。
  - **[P3]** `WireWriter/Transport/driver` 四套复制：`Xhttp/Conn.hpp:71-209` vs `Trusttunnel/Http2.hpp:55-173`（逐行近似）、`Xhttp:217-578` vs `Trusttunnel:175-500`、`Xhttp:586-838` vs `Gun/Grpc.hpp:573-866`、`AnytlsService.hpp:321` 第五套。
  - **[P3]** Restls/Shadowtls 双服务端入口：`Protocols/{Restls,Shadowtls}/Carrier.hpp`（facade）与 `Server.hpp`（生产）同协议并存，`Restls/Carrier.hpp` 仅被测试与聚合头引用，生产走 `Composition/RestlsCarrier.hpp:143→Server.hpp`。
  - **[P3]** Mux：`Session.hpp` 1307 行未拆（`FrameLoop` 约 230 行 `:877-1105`）、`if constexpr` 20 处隐藏 smux/yamux/h2mux 差异、`h2mux` 隐式开流逻辑复制两份（`:997-1022` 与 `:1060-1072`）、`:45` 反向依赖 `Runtime/SessionControl.hpp`、`:44` 仍依赖 `Foundation/SessionBase.hpp`；预算 `MaxStreamRxBytes/MaxSessionRxBytes/MaxPendingWriteBytes` 经核**确在消费点生效**（`Session.hpp:623-631,1219-1224`、`StreamState.hpp:342`）—— 这一点好于旧报告；Smux/Yamux/H2Mux 各 25 行 Client/Server/Session 别名头共 18 个纯 boilerplate。
  - **[P3]** 新增一个 carrier 需触碰约 8-10 处：`Protocols/<P>`（wire+Carrier）、`FacadeCarrier.hpp:35-40` `CarrierKind`、`TlsCandidateFactory`（`Make<P>ServerAccept` `:58,140,236`）、`<P>Carrier.hpp`、`ProtocolMatrix.hpp:168-176`、`ProtocolBuiltins.hpp:72,150-165`、`ProtocolCatalog.hpp:202`、`PreviewConfiguration.hpp:80`、`PreviewConfigurationJson.hpp:101`、validator（`:672,1740`）、`Application.cpp:2706`。
- **待验证（协议层）**：真实 hysteria2/tuic 客户端与 `StandardWire`、`/auth` 字段（`hysteria-auth`、`:path /auth`、无 12B 签名、ATYP 数值 HY2=1/2/3 与 TUIC=0/1/2 不一致）的互操作对拍；`Account::StreamLease` 与连接租约的父子释放合同；`Trusttunnel/Codec.hpp:128-141 VerifyBasicAuth` 在空 user/pass 配置下是否放行（需查 Application 校验分支）；Ws 并发写交错是否由 `Transmission` 契约兜住。

### 4.11 `Preview/Runtime/`（39 文件 / 13,545 行）

- **[P2] `RunCore` 874 行**（`Session.hpp:341-1214`）承担 12 类阶段职责：`:704-811` raw probe/TLS upgrade、`:813-936` 识别 legacy（Routes/Scheme）与 canonical（Profile）双路径 + Acceptor 二选一、`:938-996` ProtocolAccept/Prepare、`:998-1059` DataPlane materialize/mux、`:1061-1080` datagram、`:1082-1115` generic auth、`:1117-1133` decoration、`:1136-1192` dial/outbound decorator、`:1194-1202` PostDial、`:1203-1213` relay、`:120-267,1370-1491` 日志/审计/关闭。
- **[P2] 会话不在 worker 上执行**（§3.6 条目 15）：`Listener.hpp:648-651` 用 `Transport::MakeReliable(std::move(Sock))`（socket 执行器 = acceptor 的 `Runtime->Io`，`Application.cpp:4716`），`Session.hpp:342-348` 首个 `co_await dispatch(Inbound->Executor())` 把会话迁回该 Io；`Workers->Dispatch(...)` 只决定 `StartSession` 的投递与 `Control` 绑定 ⇒ worker 线程对 TCP 会话仅"登记 + 提供 DialService"，数据面单点串行。
- **[P2] 四份事实**（4.2 仍成立）：`SessionOptions`（`:66-109`，Services + legacy 字段，生产只设 `Services/SourceIp`）、`SessionServices`（`:53-103`，`Resolver` 与 `ResolveCandidate` 同义双写，`Application.cpp:4695-4696`）、`Middleware::Context`（24 字段袋，`:51-112`，四份身份、两份 sink、两份 dial）、`ProtocolDataPlane`。`SetDataPlane`(`:127-144`) 单向拷贝 + `SynchronizeDataPlane`(`:149-163`) 只同步 Transport ⇒ 认证结果不回写 DataPlane、租约两处、`has_value()` 真而内容已 moved。
- **[P2] `Active` 传输发布有缺口**：15 处手工 `StoreInbound`（`Session.hpp:350,746,807,842,946,954,986,1011,1029,1042,1049,1066,1099,1123,1140`），`PadMiddleware`（`Pad.hpp:69`）替换 `Inbound` 后直到 `:1140` 才发布 ⇒ 取消窗口内关闭的是被替换前的传输。
- **[P2] 每连接复制 services、`Traffic` 恒空、无连接上限**（§3.6 条目 16/19）；`Mailbox.cpp:38-56` 无界 CAS 自旋、容量 64（`Worker.hpp:58`、`Listener.hpp:120`），`:692-694` Full → `Request->Reject()` 直接关 TCP（无 backpressure）。
- **[P2] `SessionRegistry`**：`:231,499-510` 每次注册/移除整表 COW 复制、`:359-407` 全表扫描、无 `MaxEntries`；`:79-80,539-551,634-644` 生产代码携带测试故障注入原子计数并主动 `throw std::bad_alloc`；`:260-287` `Put/Remove` 旁路 `ShuttingDown` 与 token 合同（生产 0 caller）；`:430-475` Shutdown 无重试上限/超时。7.2 的 CAS 移动问题确已修正（`Record{Info, Entry}` 拷贝 + tombstone + pending 计数）。
- **[P2] `SessionControl::Bind` 二次绑定静默丢弃**：`:141-160` CAS 失败仍 `return true`，且 `:119-139` `MakeBinding` 每次新建 TaskRegistry —— `Session.hpp:348` 的绑定必然失败并留下未使用对象。
- **[P2] `Middleware::Pipeline::Add(nullptr)` 无校验**（`Pipeline.hpp:78-82,93-95`，PIPE-01 仍成立）；`BanMiddleware` 激活即缺陷（`Throttle.hpp:149,177` 无条件调用可空 `NowFn_`；`:194-195` 无锁无上限；`:178-181` 过期不 erase；`:160` `MaxFailures_==0` 首失败即封）—— 仅 `tests/Preview/core/rate/RateLimitTest.cpp:271-327` 引用。
- **[P3] Runtime/Front 双入口**（4.4 仍成立）：生产 0 构造，只有 `tests/Preview/integration/Task9FrontIntegration.cpp:135-363` + `CMakeLists.txt:289-290`；`UdpFront.hpp:112-135` 是同步 Bind、无 pump，与 `Ingress/UdpListener` 不等价；`QuicFront.hpp:339-357` Health 恒 `UnsupportedService=true`；`:188` 写 `Authenticated`(`:443`) 后全文件无读取；`:387-392`/`:462-467` 裸 `unordered_map` + 非原子 `LastError_/Draining_/Closed_`，`OpenStream/OpenDatagram`（`:193-266`）不切换 executor。
- **[P3] `MuxMiddleware` 死分支 + 抽象泄漏**：`Session.hpp:1038-1059` 已 return，`:1118` 又挂同一回调，是否重复执行取决于被注入 lambda 自查 `IsMux()`（`Application.cpp:4643-4646`）—— 正确性外推到回调。
- **[P3] 用 OpenSSL 文本分类失败**：`Session.hpp:1258-1272` 对 `NativeError.message()` 做字符串匹配（应使用 `ERR_GET_REASON`）；`Listener.hpp:531-563` `RunSession` 为立即启动协程，`Control->Start` 返回 false 后 `Registration` 已在协程帧内又 `Reject()` 关同一传输（帧析构行为待验证）；`:347` detached accept loop 绕过 registry，析构 `:302-306` 不等待循环。
- **[P4] 死参数/死字段**：`Relay.hpp:310-312` 的 `Outbound_` 总被 `:355-358` 的 `ctx.Outbound` 覆盖，`Session.hpp:1204` 传字面量 `nullptr`；`Session.hpp:1083-1089` 仅打日志的 legacy 分支；`RunCore` 声明在 public（`:338`）而 `SessionLogState` 是私有嵌套类型（`:120`）；`Runtime/Recognition/Detail/`、`Runtime/Detail/` 空目录。

### 4.12 `Preview/Runtime/Recognition/`（15 文件 ≈6,430 行，占 Runtime 模块近半）

- **[P2]** MixedTrial 与 Configured 对"route 适用但无候选"语义相反：`MixedTrialMode.hpp:184-197` 只在 `Route.Candidate` 存在时收窄候选集，`Route.Applicable && !Route.Candidate` 时整块跳过、继续对全部结构候选做认证试探；`ConfiguredMode.hpp:718-723` 同情形直接 `NoMatch`（`:427-428` 注释亦承诺"未命中由 coordinator 映射 NoMatch"）。配置了 route 的 profile 在 MixedTrial 下不会 fail closed。
- **[P1]** grace 超时后 detached 操作无 join 保证（`ConfiguredMode.hpp:214-216,236-244` + `MixedTrialMode.hpp:130-135` 裸引用跨 await + `Session.hpp:833-835` 栈上 `ProbeBuffer`）—— 内层操作是否合作取消待运行验证。
- **[P2] 热路径成本**：`ProbeBuffer.hpp:43-48` 每连接无条件 reserve 64KB（`Session.hpp:835-837`）；`MixedTrialMode.hpp:162` 每轮 `Snapshot` + `ProbeBuffer.hpp:239-243` 的 `EnsureWritable` 整段复制，增长步长可为 +1（`:180-181,219-221`、`ConfiguredMode.hpp:750` `Buffer.Size()+1`）⇒ 字节粒度读 + O(n²) 拷贝；preread 全量 `assign` 仅为日志（`ConfiguredMode.hpp:826,902`、`MixedTrialMode.hpp:543,652`，消费方只用 size 与 front `Session.hpp:462,1444-1449`）；`Tls.hpp:608-626` 每 ClientHello 至少 3 个 vector 整份复制，`ConfiguredMode.hpp:454-466` 与各候选 `Inspect` 对同一快照重复 `ScanClientHello`。
- **[P2] 三套小写规范化 + 两套 SNI 通配语义**：`Route.hpp:261-280` vs `Profile.hpp:1040-1059` vs `SchemeExecutor.hpp:88-103`；通配匹配 `Route.hpp:245-253`（首点后缀查表）vs `Profile.hpp:520-532`（`ends_with` + 单标签前缀）；Route 无模式校验、Profile 拒绝非法模式（`:932-935`）；Route 重复项静默覆盖、Profile 报 `DuplicateRoute`（`:954-956`）。
- **[P2] `ProbeDefense`**：生产 0 装配点（仅 `CoreModulesCoverage.cpp:71,84`）；`:215,256,280-311` 每次查询先 `Expire()` 全表遍历，满容量逐条线性找最旧淘汰（最坏 O(n²)），默认 `MaxRecords=100000`；`:76` 阈值默认 2 易误杀真实失败客户端。
- **[P2] 静默失败**：`DeterministicMode.hpp:35-38`、`MixedTrialMode.hpp:105-110`、`ConfiguredMode.hpp:639-643` 在模式/参数不符时返回默认 `RecognizeResult`（无 Status），调用方无法区分"配置错误"与"无匹配"；`Recognition.hpp:272-277` `catch(...)` 吞异常后 `Status` 仍是 `Accepted`（`:197`）而 `success=false`，二者矛盾。
- **[P3] 三套 Mode 的私有骨架约 250 行近乎全文重复**（`ConfiguredMode.hpp:590-618,789-803,805-815,822-838,840-866,868-886,888-944,998-1015` vs `MixedTrialMode.hpp:56-84,317-331,631-641,648-664,666-692,529-585,694-711`）；`DeterministicMode.hpp:50` 内部就是 MixedTrial。
- **[P3] `Profile` 每访问线性扫描**：`CandidateHandle`（`:561-571`）、`FindCandidate`（`:1077-1268`）每连接 `shared_from_this`（`:1278`）、`Name/Scheme` 返回 `std::string` 拷贝（`:1095-1114`）；`MixedTrialMode.hpp:279-287` 每次比较 `max_element/count_if` 值拷贝 Handle；`SchemeExecutor.hpp:56-69` 每连接 `Normalize` 分配 `std::string` 再查 `unordered_map`，与 `CandidateRegistry.hpp:84-121,352` 的 carrier 注册职责重叠（提交边界两层并存）。
- **[P3] legacy 识别层是仅测试存活的平行实现**：`RecognizeLegacy`（`Recognition.hpp:134-300`）、`Route/SchemeExecutor` 生产无 setter（`Session.hpp:352-353` 读指针、`SessionServices.hpp:67-69`，全仓无赋值）、`Probe.hpp:113-154` 自由函数无 caller、`Recognition.hpp:360-363` `ProbeBytes`、`Protocol.hpp:64-70` 三个 Magic 常量死码；`Protocol.hpp:113-116` 注释声称存在 VLESS 魔数回落路径，实际 `Detect` 从未检查 `VlessMagic` —— 注释与实现不符。
- **[P4] 规范**：`ProbeDefense.hpp:97-99` 构造 4 个默认参数；`RecognizeResult` 小写字段 `detected/transport/preread/scheme/success`（`ConfiguredMode.hpp:334-338`）与 PascalCase 新字段（`:340-351`）同结构体共存；`ProbeRecord.timestamp/tier`、`ProbeResult.success`；英文注释若干（清单见 §1.7）；`ProbeDefense.hpp:170` 使用 `memcpy` 未见 `<cstring>`。

---

## 5. 死代码 / 用不上的代码（三层口径）

### 5.1 完全 0 扇入的文件（16 个，任何 TU 都不 include 它们）

| 文件 | 行数 | 定性 |
| --- | ---: | --- |
| `Composition/Adapters/Hysteria2.hpp` | 38 | `MakeHysteria2Datagram` 0 caller，Application 自建（`Application.cpp:1643`）→ 删 |
| `Composition/Adapters/Tuic.hpp` | 38 | `MakeTuicDatagram` 0 caller → 删 |
| `Composition/Api/Api.hpp` | 5 | 聚合头，0 include → 删 |
| `Composition/Builtin/Builtin.hpp` | 8 | 同上 |
| `Foundation/CodecTraits.hpp` | 135 | 契约 + 第 5 个错误枚举，无人实现 → 删 |
| `Lifecycle/Lifecycle.hpp` | 12 | 聚合头（仅 2 个 Diagnose detail 引用其它头）→ 与 §4.5 聚合头一并处理 |
| `Operations/{Commands,Queries}.hpp` | 3+3 | 占位头 → 删或补内容 |
| `Protocols/Common/{Form,Mux}.hpp` | 38+50 | 0 引用 → 删 |
| `Protocols/Http2/Stream.hpp` | 238 | 0 引用（`Http2/Impl.hpp` 自有流状态） → 删 |
| `Resource/{Resource,SessionResources,StreamResources}.hpp` | 8+57+60 | L3/L4 所有权层未落地 → 删或实现 |
| `Statistics/{Counters,Events}.hpp` | 4+3 | 占位 → 删 |

### 5.2 只被测试引用、不在生产编译闭包内（"看起来是正式 API，实际没接线"）

`Runtime/Front/{UdpFront,QuicFront}.hpp`（865 行）、`Runtime/Middleware/Builtin/Throttle.hpp`、`Runtime/Recognition/ProbeDefense.hpp`、`Runtime/Statistics.hpp`、`Ingress/UdpAssociation.hpp`、`Net/{Route/Route,Outbound/Outbound,UdpRelay}.hpp`、`Transport/{MemoryStream,Algorithm}.hpp`、`Scheduler/{FairScheduler,PriorityScheduler,Types,Detail/FixedTable}.hpp`、`Composition/Api/{ApiManager,OperationsApi,StatisticsApi}.hpp`、`Composition/Recognition/AnytlsCarrier.hpp`、`Composition/Carrier/FacadeCarrier.hpp`、`Composition/Settings/{Json,Loader}` 的 parser 半边、`Foundation/{Foundation,Exception/*,Utility/Coroutine/Registry,Utility/Account/*,Utility/Rate/TokenBucket,Utility/Diagnose/Observability,Utility/Crypto/{X25519,Blake3,Block,Sha224,Crypto}}.hpp`、`Protocols/Ech/*`、`Protocols/Native/*`、`Protocols/Http3/NativeClient.hpp`、`Protocols/{Restls,Shadowtls,Trusttunnel,Tuic}/*{聚合头,Carrier,Conn,Dgram}`、`Account/{Account,Record,Lease,Rate,Runtime,SecureBytes,Credential}`（多为被 0 扇入的聚合头牵入）。

**判定要求**：每一处必须选一种处置 —— 接入生产、降级为显式 experimental/compatibility target（独立 CMake target + 文档标注）、或删除。当前状态是"登记在 `Preview/CMakeLists.txt` 生产源列表里 + 命名空间与正式 API 相同"，这本身就是缺陷（读者与调用方无从判断哪条是活的）。

### 5.3 函数/成员级 0 caller（分片复核，逐项带行号）

`Application.cpp:656-681 DialTarget`；`Application.cpp:3147` 进程级 `TaskRegistry`（Create/Cancel/Drain/reset 齐全，**从无 Register**）；`Adapters/TypedResult.hpp:124-136 AcceptTyped` 与 `:182-213 ToTypedResult`；`Recognition/ShadowtlsCarrier.hpp:147-154 MakeShadowtlsCarrier`；`Recognition/ProfileBuilder.hpp:130-135 BuildProfile`；`Recognition/SettingsBuilder.hpp:150-195,216-372`（5 个引导函数）；`CandidateFactory.hpp:899-939` 的 7 个 `MakeXxxCandidate` 别名与 `:858-870` SS2022 别名；`MuxService.hpp:230-254,103-111,343-397`（Stop/IsStopping/COW 注册表）；`Builtin/Snapshot.hpp:131-159 Invoke`；`Builtin/ProtocolBuiltins.hpp:236-276` 的 4 个注册别名；`Builtin/Capability.hpp:35-39` 5 个别名；`Protocol/ProtocolCatalog.hpp:90-100 Supports`；`Ingress/QuicCidRegistry.hpp:44-63 Register`；`Ingress/QuicGateway.hpp:118-152 RegisterConnection/Unregister`；`Ingress/UdpDemux.hpp:94 RegisterQuicCid`；`Configuration/SecretRefResolver.hpp:69-85`（`MapSecretRefResolver`、`MakeChainedSecretResolver`）与 `ConfigurationStore.hpp:26-35 Pin`；`Runtime/Recognition/Probe.hpp:113-154 Probe()`；`Protocols/Quic/GatewayCommon.hpp:52,59-64 GuessProtocol/ProtocolGuess`；`Protocols/Quic/Native.cpp:2332-2341 RecvRetry`；`Protocols/Http2/Impl.hpp:384 NextServerId_`、`H2Session::{SendPing,SendGoaway,ConsumeData}`；`Protocols/Vmess/ChunkCodec.hpp:568-655 ChunkStream`；`Protocols/Socks5/Conn.hpp:634 ReadRequest`、`Codec.hpp:537 ParseUserpassReply`；`Protocols/Hysteria2/Dgram.hpp:518-558 ReadExact/ReadAddressBody`；`Composition/Recognition/LayeredCandidateFactory.hpp` 与 `TrusttunnelCandidate.hpp:38-40`（入参被忽略）；`SingMux.hpp:42-44,50`（Version/Padding/PacketAddr 解析后无读取）；`Foundation/ByteSpan` 的 `As<To>` 家族与 `AsStrView`；`Foundation/Memory/{Pool 的 PooledObject/EnablePooling/MonotonicBuffer/HotPool, Container 的 Map/UnorderedMap/List/Allocator}`；`Foundation/Identifier/{SnapshotId,Identifier,Types}`；`Foundation/{Executor/*,Cancellation/*,Memory/Domain}` 三个"只存值不生效"的枚举；`Foundation/Utility/Diagnose/{Observability 全部,EmergencyWriter,FallbackWritten}`；`Operations/{Commands,Queries}.hpp`；`Statistics/{Counters,Events}`；`Account/Authenticator.hpp` 的 `AuthenticatorCallback`（`:33-34` 0 使用）。

### 5.4 目录与构建级残留

`Foundation/Utility/Account/README.md` 自称"account 模块（已实现），T5 阶段已落地"，并用小写文件名（`cow_map.hpp`/`directory.hpp`/`authenticator.hpp`）把消费方写成 `core/middleware/builtin/auth.hpp`、`core/runtime/session.hpp`；`Foundation/Utility/Diagnose/README.md` 同类。**这解释而非开脱了 §4.1 的同名两套类**：`Foundation/Utility/Account/*` 是**早期阶段的实现**，后来在 `Preview/Account/` 重写过一份，旧的一份既没删除、也没改名、还留在 `Preview::Account` 命名空间与生产 target 源列表里。其余：`Error.hpp:155-209` 的 gtest 断言重载属测试工装进生产头。（原判"22 个空 `Detail/` 目录是仓库残留"已在 §1.7/§10.2 撤回 —— git 不跟踪空目录。）

---

## 6. 编译耦合与规模治理（"臃肿"的可量化部分）

- **[P3] 412 个头 vs 24 个 `.cpp`**：状态机、异步循环、所有权逻辑全部 inline 到消费者 TU。`PreviewRuntime` 的编译单元只有 `Mailbox.cpp`；Diagnose 目录 0 个 `.cpp`；`ConfigurationValidator.hpp`(1,938 行) 无 `.cpp` 且被 9 个 TU 包含（含 4,925 行的 `Application.cpp`）—— 改一个字段触发全树重编。
- **[P3] `PreviewFoundation` INTERFACE link `OpenSSL::Crypto` + `Blake3C`**（`CMakeLists.txt:89-93`），使纯值类型头也连带 BoringSSL/BLAKE3。
- **[P3] 聚合头约定已失效**：`Foundation.hpp`、`Account.hpp`、`Builtin.hpp`、`Api.hpp`、`Lifecycle.hpp`、`Resource.hpp`、`Scheduler.hpp`、`Statistics.hpp`、各协议 `Xxx.hpp` 的聚合头，生产 0 引用或只引用不完整（§4.5、§5.1），违反 AGENTS.md"新增子头文件需同步更新聚合头"。
- **[P2] 每条日志 ≥4 次堆分配**、热路径 64KB 值初始化反复 memset（§3.6 条目 43）、VMess/SS2022 逐字节重解析（§4.10）、`SessionServices` 每连接深拷贝（`Application.cpp:3110`）、每 QUIC 连接全量复制工厂选项（`:1784,1803`）—— 与"迁移前后比较分配/吞吐"的基线要求冲突（AGENTS.md Preview 验收条款）。

---

## 7. 验证缺口（六层证据不可互替）

本报告只完成第 1 层。按 AGENTS.md 的 Preview 验收口径，必须分别取证：

| 层 | 当前状态 | 缺口 |
| --- | --- | --- |
| 1 源码检查 | 已完成（本文） | 依赖方向需先决定 Front/Scheduler/Api/Route 的定性 |
| 2 构建 | **未做** | 全树是否可编译未知；`Ss2022.hpp` 缺 include（§4.4）、`ProbeDefense.hpp` 缺 `<cstring>` 等都可能只在特定 TU 顺序下成立 |
| 3 focused tests | 未运行 | 需新增负向用例（下表） |
| 4 全量 CTest | 未运行 | `tests/Preview/` 327 个 `.cpp` / 130,430 行，31 个 >500 行 |
| 5 真实请求 / 互操作 | 未运行 | HY2 `StandardWire`、`/auth` 字段、ATYP 数值差异（HY2 1/2/3 vs TUIC 0/1/2）、QPACK T 位均未经外部客户端对拍 |
| 6 性能 / 停机取证 | 未运行 | `Scheduler`/`Statistics` 基准不代表生产；§4.7 显示生产实际无计数器 |

必须新增的负向/回归测试（当前全树缺失，逐条对应 §3.6）：

1. 未认证 QUIC DATAGRAM 不产生任何出站（HY2）。
2. `IngressDispatcher`：QUIC 分类 + gateway 拒绝时，回落 handler 收到**原始完整 payload**。
3. `QuicCidRegistry`：16-20B DCID 首包被拒后 entry/server 计数归零。
4. Native QUIC：`MaxStreams/MaxDatagrams` 配置生效后 transport params 与 admission 同步；stream close 后 `Streams_` 尺寸回落；TUIC 路径 `IncomingStreams_` 不增长。
5. VMess：单连接 65536+ 块后 nonce 不重复（可用计数器注入）；`Option` 非法位被拒；重复 AuthID 被拒（重放缓存）。
6. Reality：同一 ClientHello 在时间窗外仍被拒（重放）。
7. `Account::Directory::TryAcquire`：代次不一致时有限重试并有错误码。
8. `Application::Start()`：profile 构造失败后 `State_` 为空、Diagnose 已 flush、`Run()` 返回 1。
9. `SessionServices`：Mux 回调不阻止 `SessionServices` 归零（weak 捕获）；`Traffic` 有生产实现并被 relay 计数。
10. 识别：MixedTrial 在 route 命中但候选为空时判 `NoMatch`；grace 超时后无 detached 协程访问 `ProbeBuffer`（ASan）。
11. AnyTLS/XUDP/mux/H2Mux/XHTTP：流/flow/pending bytes 上限生效、慢上游是背压不是断连、半关闭 FIN 到达、`Run` 返回后无存活 detached relay。
12. HTTP/2 core：并发流上限、`MAX_CONCURRENT_STREAMS` 宣告与 enforce、头块上限、RESET 指向已关闭流不断连、HPACK 动态表协商。
13. `Memory/Pointer` + `Pool`：跨线程释放 `SharedSessionResource` 的 ASan/TSan 用例。
14. `Fault`：`Error` 枚举插入后编译期一致性（`static_assert` 或按名 switch）。
15. 配置：`Priority` 越界被拒、UUID 结构校验、`Logging.Directory` 规范化、`glz::generic` 预检不复制 secret。
16. `Runtime/Front` 与 `Ingress` 若都保留，需要等价性测试；否则删除其一后由 Application 路径测试覆盖。

---

## 8. 建议的处理顺序（不含具体实现承诺）

**第一批（正确性）**：3 条链已闭合的 P1（§3.6 条目 1、6、13）先加负向测试再修；随后 4 条小改动高确定性的 P2（条目 17 启动失败挂起、18 `Services->Mux` 引用环、19 `Traffic` 接线或删除、16 连接上限）。潜伏型（条目 2、8、9）随相邻改动一起收口即可，不必单独动刀。

**第二批（资源与可用性）**：条目 14-44，重点是：`MaxConnections`/QUIC admission 上限接线、`Traffic` 接线、worker 执行域纠正（会话迁到 worker 执行器或按 worker 建 acceptor）、`EventRing` 真环形化、DNS/`Coalescer`/`Cache` 上限、`Ss2022Gateway` 单包一次试解 + 出口关联化、TaskRegistry 的 COW 复制、Drain 语义统一（worker→registry→io）。

**第三批（结构，按协议竖切，一次切一条）**：以 `Protocols/Tuic/Admission` 为样板（它是全树唯一同时拥有 auth/lease/pending/stream/datagram/close 的协议 owner），依次收拢 Hysteria2 → SS2022 → AnyTLS → VLESS XUDP → mux；每步把 `Composition/<X>Service|Factory` 变成 typed prepare/bind/rollback 槽位，并把 `Application` 的 relay lambda 移入协议目录。

**第四批（边界与清理）**：`ConfigurePreviewTarget` 去掉全局 `${CMAKE_SOURCE_DIR}`（改为按 target 暴露自身目录）→ 让 §3.2 的 18 条 include 变成编译错误；补 include-graph 边界检查（现有 `AssertPreviewTargetGraph` 只看 link）；给被放宽的 `PreviewIngress` 白名单设定删除条件；二选一决定 `Runtime/Front` 与 `Ingress`；把 `ProtocolMatrix/ProtocolCatalog/ProtocolBuiltins/StaticProtocol` 四表合成一份可校验的 manifest（freeze 期闭合）；按 §5 清单删除或定性；把 `Middleware::Context` 的 24 字段拆成 `AuthResult`/`StreamPlan`，删 legacy 别名与双向同步；每个真实模块拥有自己的 `CMakeLists`。

**不建议先做的事**：全树机械改名或按行数切片（会掩盖 owner 问题）；引入新的万能 context/service locator；把 QUIC/datagram 硬塞进现有 `SharedTransmission` 管线。

---

## 9. 与既有审查文档的差异（避免误读旧台账）

对 `docs/preview-refactor/2026-09-30-preview-comprehensive-tree-audit.md`、`2026-09-28-preview-module-refactor-analysis.md`、`logs/issues.md` 的复核结论：

| 旧条目 | 现判定 | 依据 |
| --- | --- | --- |
| HY2-01（认证租约丢弃） | **stream 面已修复，datagram 面更严重** | `Http3AuthSession` 已持租约；datagram 完全无门禁（§2.1） |
| QUIC-01（未知 short header 建 server） | **部分修复** | `QuicCidRegistry.hpp:71-81` 空 CID 已不再调 factory；但 `Handle` 无容量上限、无地址验证（§4.6） |
| QUIC-02/03/04/05/06、CID-01、TUIC-01 | 仍成立 | 行号见 §3.6 条目 20/41、§4.6 |
| APP-01（profile 失败不回滚） | **仍成立且后果更重** | 不是"状态残留"，而是 `Run()` 永久 `Io.run()`（§3.6 条目 17） |
| APP-02/03/04/05、ARCH-01/02/03/04/05 | 仍成立 | §4.2、§4.11 |
| COM-01/02/03/05/07/08/09、ACCOUNT-01/02、FOUNDATION-01/02/03/04 | 仍成立（部分比记录更严重） | §4.4、§4.1、§4.5 |
| COM-04 / MEM-02（AnyTLS 流无上限） | **部分成立** | `Fin` 已 `erase`（`AnytlsService.hpp:945-951`），但 emplace 仍无容量检查、重复 SYN 静默 |
| COM-06 / MEM-01 | 仍成立 | `TypedResult.hpp:208`；`VlessXudp.hpp:434-438`；另发现**生产同型 bug** `Context.hpp:136-139`（对应 `logs/issues.md` P-1/P-13） |
| PIPE-01、DORMANT-01、DEAD-01、INGRESS-02/03/04/05、LIFECYCLE-01/02/03、NET-01/02/03、OPS-01/02/03、CONFIG-01/02/03、TEST-01 | 仍成立 | §4.3、§4.4、§4.7、§4.8、§4.9、§4.11、§7 |
| 7.2 SessionRegistry CAS 移动 | **确已修正** | `Record{Info, Entry}` 拷贝 + tombstone + pending 计数 + 故障注入测试 |
| 7.1 HTTP 转发旧三项 | **已修复且未见回归** | `HeaderFields.cpp:275,318,339-400`、`ForwardRequest.cpp:58-173`；本报告新增 `ParseStatusCode` 溢出（§4.10） |
| `logs/issues.md` P-11（双阶段解析 SecretRef） | Prepared 路径**已修复** | `GenerationBuilder::Build(GenerationBuildOptions)`+`ReloadCoordinator` 仍保留双解析形态（未接线） |
| P-12（重复键/首错顺序） | 仍成立 | glaze 6.5.1 无 `error_on_duplicate_keys`（`build/_deps/glaze-src/include/glaze/core/opts.hpp:87,94` 仅两项 `error_on_*`），非可配置 |
| P-8（CMake allowlist 未覆盖实际链接边） | 仍成立，本报告给出根因 | §4.0（全局 include 目录使边界不可验证） |
| P-M11/P-M12（ProbeDefense 可注入时钟、COW 快照） | 已落地 | `ProbeDefense.hpp:97-106,282-284` |

**本报告新增（旧文档未覆盖，级别按 §10.1 复核后）**：Hysteria2 datagram 无门禁（P1）、VMess 零重放防护（P1）、识别 grace 无 join 保证（P1）、`DirectoryAuthenticator` ODR（P1 潜伏）、`IngressDispatcher` 二次 move（P2 潜伏）、`TryAcquire` 忙等窗口（P2）、VMess nonce 回绕与 Option 位（P2）、Reality 时间窗（P2）、MixedTrial/Configured route 语义相反（P2）、`QuicCidRegistry` move-key 清理失效（P2）、`CachedMessage noexcept` + 分配（P3）、`Fault::Handling` 按序号映射（P3）、worker 执行域错位（P2）、生产无连接上限（P2）、`Traffic` 未接线（P2）、`Services->Mux` 引用环（P2）、启动失败后永久挂起（P2）、FrameArena 跨线程释放（P2）、`Memory::EnablePooling` 从未调用（PMR 承诺未落地）、`EventRing` 不是环、HTTP/2 core 五项缺失、手写 QPACK T 位反向、§5 的 0 扇入/0 caller 完整清单、§1.5 的编译闭包指标（76 文件不在生产二进制内）。

**我更正的旧结论**：`Mux/Session` 的三项预算（`MaxStreamRxBytes/MaxSessionRxBytes/MaxPendingWriteBytes`）经核确在消费点生效（`Mux/Session.hpp:623-631,1219-1224`、`StreamState.hpp:342`），不应继续按"未强制执行"记载；Diagnose 的 `ContextDecoder` 不解析历史日志文件（只捕获/渲染字段），旧描述有误；旧报告中"Reality/Restls/Shadowtls 走 FacadeCarrier 生产路径"的说法需修正为"生产走 `MakeShadowtlsServerAccept`（`Application.cpp:2625`）等 CandidateFactory 路径，`FacadeCarrier` 仅测试使用"—— 反向依赖仍在，但受影响的是一条未接入轨道。

---

## 10. 自查与再评估（对自己这份报告的对抗性复核）

第二遍我不是重读代码片段，而是**专门去找自己结论的反例**。结果：6 条降级、1 条误报撤回、2 条原判"待验证"的证据补齐、并补了 6 个第一轮漏掉的分析维度。

### 10.1 降级清单与理由（这是我第一轮的不严谨处）

| 条目 | 原判 → 现判 | 我漏掉的反证 |
| --- | --- | --- |
| 2 `IngressDispatcher` 二次 move | P1 → **P2 潜伏** | 我只验证了"payload 被移空"，没验证"移空后结果是否不同"。回落消费者只有 `Ss2022Gateway`，而它的 `Handle`(`:116-127`) 与准入 `CanAcceptUnclaimedQuic`(`:83-94`) 用**同一个** `HasAuthenticatedClientWire` 谓词 ⇒ 当前每条分支结果等价。合同坏，丢包不坏。 |
| 4 VMess nonce 回绕 | P1 → **P2** | 我把协议继承的属性当成实现缺陷。`ChunkCodec.hpp:250-273` 的 16-bit 计数 + 10B 固定种子就是上游 VMess legacy AEAD 的既定语义；且重用范围是"该连接自己的 key + 该客户端主动选择的模式"，不是全局密钥，也不是认证绕过。真正的缺陷是没做块上限/轮换（可执行改进），以及条目 5 的模式不可控。 |
| 5 Option 位远端决定 | P1 → **P2** | 与条目 4 合并：它放大的是"服务端无法强制安全模式"，属于策略缺失。 |
| 7 Reality 时间窗 | P1 → **P2** | 我只看了 `Carrier.hpp:552-573` 缺时间比较，没推完握手剩余部分：TLS 1.3 的 `Finished` 需要客户端握手密钥，纯 ClientHello 重放无法建立可用会话。真实风险是规范偏差 + 无界握手消耗。 |
| 9 `TryAcquire` 无界自旋 | P1 → **P2** | "代次不收敛即永久活锁"缺发布顺序证据。读 `Directory.hpp:70-111` 后是：记录先 CAS 发布、`PublishPolicy` 后执行 ⇒ 存在**设计内的短窗口**让并发认证在两条 `continue` 上热自旋（可观测为握手线程 CPU 飙升），但不是必然永久活锁。降级为"无 yield/无上限的忙等窗口"。 |
| 10 `CachedMessage noexcept` + 分配 | P1 → **P3** | 触发需要静态初始化时内存耗尽；实质是 `noexcept` 契约与注释矛盾 + 按值返回，属可维护性。 |
| 11 `Fault::Handling` 序号映射 | P1 → **P3** | 我把"脆弱"写成了"错分类"。逐项核对 `Error.hpp:26-68` 后当前映射**是一致的**，只有 `KdfError(16)`/`CryptoError(19)` 细节降级为 `GenericError`。风险在于以后改枚举顺序不会有编译期阻拦。 |

维持 P1 的只有 3 条：**条目 1（HY2 datagram 无门禁）**、**条目 6（VMess 零重放）**、**条目 13（识别 grace 无 join）**；**条目 8（ODR）**维持 P1 但明确标"潜伏"。教训：P1 的门槛应当是"存在一条从远端输入到可观测错误后果的完整链"，我第一轮把"缺防护"与"链已闭合"混记了。

### 10.2 误报撤回

- **"22 个空 `Detail/` 目录是仓库残留"—— 撤回。** `git ls-files Preview` 只有 14 个 `Detail/` **文件**，git 不跟踪空目录，所以这 22 个目录是我这台机器的本地残留（磁盘 442 文件 vs git 413 文件），不构成项目缺陷。
- **`MuxService` 的 COW 注册表"是跨连接/跨线程竞争点"—— 修正为单线程内重入与 COW 成本。** 分片把它写成线程争用；实际执行域见 §10.4，会话都在主 `Io` 上，争用主要是同线程重复复制与异常路径未 `UnregisterRoot`，不是数据竞争。
- **"HTTP/3 两套实现并存意味着生产可能走错那一套"—— 收紧。** 生产 H3 走 nghttp3（`Http3/Session.hpp:59` 注释与 `Composition/Quic/*` 调用链），自研 QPACK/Huffman 只被测试、fuzz 与 Hysteria2 legacy `MakeAuthRequest` 使用；风险是"死轨道带错误语义却仍在生产 target 源列表"，不是现行互通故障。

### 10.3 补强（原判证据不足，现已闭环）

- 条目 26（Ws 并发写）：已确认 `Transport/Reliable.hpp:272-295` 直委托 socket `async_write_some`，无 strand、无写队列、无"写入中"标志 ⇒ 两条协程并发进入同一写链时部分写会交错。原"需要 Transmission 契约证据"的保留意见取消。
- 条目 1（HY2 datagram）：追加两处反证检查 —— `Hysteria2Factory.hpp:523-542` 的 `HandleHysteria2Datagram` 不引用任何 `AuthSession`，`Protocols/Hysteria2/Dgram.hpp` 全文没有 auth/cookie/握手校验 ⇒ 不存在"Dgram 内部自带认证"的可能。P1 稳固。

### 10.4 新增维度一：执行器与并发模型（第一轮完全没量化）

| 事实 | 证据 |
| --- | --- |
| 主线程单 `io_context` 承载：TCP accept、**全部会话数据面**、UDP pump、QUIC 收包、Operations server | `Application.cpp:4716`（`ListenerOptions.Executor = Runtime->Io`）、`:4876`（`State_->Io.run()`）、`:3538/3573/3643/3692/4108`（启动期 `run_one()` 泵）、`Reliable.hpp:139-142` + `Session.hpp:342-348`（会话迁回 socket 执行器） |
| worker 线程各跑自己的 `io_context`，实际只承担 mailbox 登记与 `DialService` | `Application.cpp:3161-3176`（每 worker 一个 `std::thread` 跑 `Worker::Run()`）、`Resource/WorkerResources.hpp:122-128,168-172`、`Listener.hpp:680-684`（`Workers->Dispatch`） |
| `Runtime.WorkerCount` 默认 2 ⇒ 4 个执行域，其中 2 个对入站流量近乎闲置 | `Configuration/PreviewConfiguration.json:4` |
| 进程级共享对象：`MuxService` 单实例、`QuicCidRegistry`、`AccountDirectory`（`atomic<shared_ptr<Records>>`）、Diagnose `Pool_`（`atomic<shared_ptr>`）与 `Logger_`（**非**原子） | `Application.cpp:4627`、`Directory.hpp:269`、`AsyncBackendState.hpp:161` |

结论：这解释了两件事 —— (a) 条目 16（无连接上限）和条目 14（无 deadline 的 relay 循环）在单线程 Io 上会直接放大为整机停顿；(b) 大量"是否有数据竞争"的疑问要按执行域逐点判，不能一律按多线程处理。我第一轮在这点上口径不统一，是本报告最需要读者警惕的地方。

### 10.5 新增维度二：默认配置的可达性（避免把"产品形态风险"说成"开箱即灾"）

`Configuration/PreviewConfiguration.json` 实际内容：TCP/UDP 均绑 `127.0.0.1:1080`，`Listeners.Quic: []`，`Carriers: []`，`Builtins: []`，只 1 个 `socks5` inbound + 1 个 binding，`NativeTls.Enabled=false`，`Operations.Endpoint=127.0.0.1:9090`，账户是内联 `Credential`（样例值，`Application.cpp:1013-1025` 的样例名单认识它并在环回时跳过弱凭据告警）。
⇒ 条目 1（HY2 datagram）、条目 41（TUIC assoc）、条目 20-24（QUIC/H3/H2 core）在**默认样例下不可达**，需要真实部署启用 QUIC/Hysteria2/TUIC 才成立；而产品用途正是对外监听，所以级别不降，但"暴露面"要这样标注。反之，条目 15/16/17/19（执行域、无上限、启动挂起、`Traffic` 空）与条目 2（合同）在默认样例下就已经生效。

### 10.6 新增维度三：内在复杂度 vs 偶然复杂度（回答"是不是本来就复杂"）

组合面确实大：`Protocols/` 有 22 个协议目录，而配置的静态协议枚举只有 8（`std::array<…,8>`）；再乘上传输 {TCP, UDP, QUIC}、mux {无, smux, yamux, h2mux, singmux}、识别 {Deterministic, Configured, MixedTrial}、carrier 7 种 —— 名义组合数千，真实需要支持的边只有几十条。**声明这几十条边是内在复杂度，无法消除**；但当前是用 **4 份互不相干的表**（`ProtocolCatalog` / `ProtocolMatrix` / `ProtocolBuiltins` / `Application` 的 switch）来声明，漂移因此不可避免。
可消除的偶然复杂度（均可由现有代码直接判定，不依赖运行）：18 条禁止方向的 include + 使边界不可验证的全局 include 目录；76 个不在生产闭包内的文件（含 16 个 0 扇入）；2 套入口、2 套 TaskRegistry、3 套 Authenticator/Directory、5 套错误体系、2 套 HTTP/3、3 套 Hysteria2 wire、7 种 pending-write 命名、8 处拨号/解析重复实现；`Middleware::Context` 24 字段与双向同步；731/874/572 行的三个函数。**我的判断：约六到七成"臃肿"属偶然复杂度**，消除手段是"单一 manifest + 竖切 owner + 真实编译边界"，不是把长文件切成短文件。

### 10.7 新增维度四：可观测性（这些缺陷能不能被自己发现）

现状基本不能：生产没有可用计数器（`SparseCounters`/`TrafficDelta`/`Scheduler`/`Runtime/Statistics` 全在闭包外，`Api/StatisticsApi` 只服务 bench），`SessionServices::Traffic` 恒空，`EventRing` 满 1024 后永久静默，`catch (...)` 158 处多数只计数或什么都不做，失败原因大量塌缩（`MissingResolver`、`GenericError`、`OperationAborted`）。⇒ §3.6 里的资源类 P2 大多**无法从生产指标看出**，只能靠新增负向测试与显式上限断言发现。这也意味着 §8 的第一批工作应当先补指标，再改结构。

### 10.8 新增维度五：测试有效性（绿灯覆盖的是不是活轨道）

`tests/Preview/` 327 个 `.cpp` / 130,430 行，规模与生产（436 文件 / 121,186 行）相当，但：`Transport/MemoryStream.hpp` 被 85 个测试包含而生产 0 引用 —— 大量测试跑在内存流夹具上；`Runtime/Front/*`（865 行）、`ProbeDefense`、`Throttle`、`Scheduler`、`Api/*`、`Route/Outbound`、`FacadeCarrier`、`SettingsBuilder/ProfileBuilder` 的绿灯对应的都是**未接线轨道**。因此"Preview 测试通过"与"真实请求路径正确"之间的距离，比测试数量给人的感觉要大得多（AGENTS.md 的分层验收条款正是为此写的）。

### 10.9 新增维度六：与旧树的关系（校准"下一代"的合理性）

Preview 与旧树**没有源码级耦合**（`grep include <prism|psm` 在 `Preview/` 下 0 命中），只有 16 个头声明"镜像自 include/prism/…，同步策略：锁定"或"已分叉"；旧树 `include/prism` 236 文件 27,585 行 + `src/prism` 126 文件 32,833 行仍在仓库里由另一套 target 构建。所以"170 个同名文件"只是命名巧合，**不构成双份维护缺陷**；但它确实解释了 Preview 为什么必须自带 HTTP/2、QPACK、QUIC 封装、DNS、日志后端等全部基础设施 —— 这是"下一代实现"的合理代价，不应被记作臃肿。我第一轮在 §4.5/§5 里对"Foundation 重复实现"的措辞偏严，按这一条重新校准。

### 10.10 本报告自身的可信度分层

| 层次 | 数量 | 置信 |
| --- | --- | --- |
| 我逐行复核并读过反例 | 条目 1、2、3、4、5、7、8、9、10、11、12、15、16、17、18、19、26 + §1/§3.2/§4.0 全部度量 | 高（可复查行号） |
| 分片报告 + 我抽查结构（未跑运行证据） | 条目 13、20、21、22、23、24、25、27-44 | 中高（"源码事实"，后果待验证） |
| 仅分片报告 | §4 各节的 P3/P4 细节 | 中（行号可查，判断未二验） |
| 明确待验证 | TLS/QUIC 互操作语义（`StandardWire`、`/auth` 字段、ATYP 数值）、`Account` 父子租约合同、WS 并发写的运行表现、`Validator` 的 `std::visit` 兜底、内层识别操作是否合作取消 | 低 —— 已在正文标注，不作结论使用 |

**修正后的最小行动集（取代 §8 第一批的口径）**：① 先给条目 1、6、13 加负向测试并修（三条闭合链）；② 修条目 17（启动失败挂起）、18（引用环）、19（`Traffic` 接线或删除）、16（连接上限）—— 都是小改动、高确定性；③ 把 §10.4 的执行域事实写进文档，再决定条目 15 是"设计如此（单线程数据面 + worker 只 dial）"还是"缺陷"，不要未经这个决定就重构；④ §5 的死轨道做定性标记（生产 / 实验 / 待删）而不是直接删；⑤ 其余 P2 按 §10.7 先补指标。

