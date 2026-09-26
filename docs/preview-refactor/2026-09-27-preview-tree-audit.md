# Preview 下一代模块全树静态审查

审查日期：2026-09-27
审查对象：Preview/ 当前工作树
审查方式：按顶层目录树静态检查目录、文件体量、CMake 目标依赖、关键调用路径和现有测试源码。

## 总体结论

Preview 不是单纯的“协议文件太长”。主要问题是模块边界在 CMake 名称上看似分层，源码 include 和实际职责却反复跨层：Runtime Front 直接依赖 Composition 与 QUIC Protocols；Ingress 的 admission context 同时承载 Hysteria2/TUIC 的认证、拨号、DNS、流与数据报回调；应用启动代码又负责 protocol registry、factory wiring 和逐协议分支。结果是改一个协议需要同步触碰配置校验、识别/候选构造、运行时入口、QUIC admission、Composition factory、Application 和集中式 CMake。

当前可复核的问题不止是代码体量：HTTP proxy 会把已验证的 Proxy-Authorization 凭据发给目标站点；absolute-form URI 的路由 authority 与转发 Host 可以不一致；Settings JSON parser 接受非法数字、未转义控制字符、重复 key，并损失大整数精度；若干 UDP/QUIC front 类不在 Application 的实际数据路径中，却作为 PreviewRuntime 公共内容保留。另有 Pipeline 空指针解引用、QUIC admission 的未知协议默认落到 Hysteria2、connection state 在协议认证前标记 authenticated 等问题。部分后者受到当前配置校验约束，报告会明确其实际可达条件，不把 API invariant 错误夸大为已证实的认证绕过。

### 问题优先级总表

P1 表示可导致敏感凭据泄漏或严重安全边界失效；P2 表示会造成错误路由、非法输入被接受或公开 API 崩溃；P3 表示当前数据路径未命中、被上层约束掩盖或显著增加扩展/维护成本。

| 编号 | 级别 | 子树 | 问题 | 当前状态 |
|---|---|---|---|---|
| HTTP-01 | P1 | Composition/Protocols/Http1 | Basic Proxy-Authorization 在 HTTP 转发请求中被原样发往源站 | 真实 HttpHandler 路径可达 |
| HTTP-02 | P2 | Composition/Protocols/Http1 | absolute-form URI authority 与 Host 可不一致，转发保留错误 Host | 真实普通 HTTP 转发路径可达 |
| HTTP-03 | P2 | Protocols/Http1 | Connection/Proxy-Connection 等 hop-by-hop 头随原始头块转发 | 未被剥离或重建 |
| JSON-01 | P2 | Composition/Settings | 数字扫描接受非法 token，stod 未验证完整消费 | 真实 Settings parser |
| JSON-02 | P2 | Composition/Settings | 原始控制字符通过字符串解析 | 真实 Settings parser |
| JSON-03 | P2 | Composition/Settings | surrogate pair/孤立 surrogate 被编码成非法 UTF-8 | 真实 Settings parser |
| JSON-04 | P2 | Composition/Settings | 重复对象 key 静默保留首值 | 真实 Settings parser |
| JSON-05 | P2 | Composition/Settings | double 到 uint64/int64 的设置转换丢失大整数精度 | TimeoutMs 等字段可达 |
| API-01 | P2 | Runtime/Middleware | Pipeline.Add 接受空指针，Run 直接解引用 | 公开 API 可达 |
| QUIC-01 | P3 | Ingress/Composition/Application | 未知 Protocol 被 Ready 当作 Hysteria2 | 当前合法配置校验会拦截 |
| QUIC-02 | P3 | Protocols/Quic/Runtime/Front | typed transport registration 把未认证连接标为 authenticated | 字段当前无读取点 |
| ARC-01 | P2 | Runtime/CMake/Composition | Runtime Front 反向 include Composition 和 Protocols/Quic | 目标链接图未声明 |
| ARC-02 | P2 | CMake | target dependency allowlist 可被直接 target_link_libraries 绕开 | 当前存在旁路 |
| ARC-03 | P2 | Ingress/Composition/Application | QUIC gateway、协议 admission、协议 handlers 分散四层 | 扩展需改多份中央逻辑 |
| ARC-04 | P2 | Application/Runtime/Protocols | Start、Session、Quic Native、XHTTP 等状态机聚在超长文件 | 结构与变更风险 |
| DEAD-01 | P3 | Runtime/Middleware | Throttle/Ban 有测试，但没有 production pipeline 接线 | 目前 dormant |
| DEAD-02 | P3 | Runtime/Front | UdpFront 明言生产 pump 在 Ingress；QuicFront 也未接到 Application | 并行/实验实现 |
| DEAD-03 | P3 | Foundation/Lifecycle | Coroutine::TaskRegistry 与 Lifecycle::TaskRegistry 重复，前者没有生产调用点 | 旧实现只留测试 |
| META-01 | P3 | Composition/Runtime/Front | ProtocolCatalog、ProtocolMatrix、Builtin 三处能力/入口语义不同且未统一命名 | 当前 Front 路径未接入 Application |
| META-02 | P3 | Composition/Builtin | 多个同义注册 wrapper 无调用点；builtin metadata 不是 handler factory | 静态扩展负担 |

## 逐项真实性核验

针对“报告里的问题是否真的在项目中”，逐条回看了报告引用的当前磁盘源文件和关键调用点。结论不是每一项都等于当前线上故障：

- 当前主路径上确认可达的缺陷：HTTP-01。Application 的 MakeRuntimeAcceptors 用 RequireAuth=true 构造 HTTP handler，MakeTcpProfile 将该 Accept 函数绑定到 candidate；成功认证后普通 HTTP 请求进入 ReleaseForward，原始 Proxy-Authorization 确实被带到源站。HTTP-02/03 同样存在于该生产转发代码路径。
- 当前代码实现确实存在、输入可以到达的解析/API 缺陷：JSON-01 至 JSON-05、API-01。Settings Loader 调用该 JSON parser；Pipeline 的公开 Add 和 Run 函数直接实现了空指针可解引用路径。
- 源码中确实存在，但不是当前合法配置下已证实的线上故障：QUIC-01。ConfigurationValidator 与 MakeQuicAdmissionContext 都把 protocol 限制在 Hysteria2/TUIC，所以正常 Application 配置会挡住未知协议；Ready() 自身仍把任意非 TUIC 字符串映射为 Hysteria2，这是防御性合同错误。
- 字段/类确实存在，但不能描述成当前已发生的安全绕过：QUIC-02 的 authenticated 字段在 typed connection 注册时置 true，但全树没有读取它的生产 gate；它目前是语义错误和未来误用风险。
- 代码确实存在，但没有当前生产调用点：DEAD-01 的 Throttle/Ban；DEAD-02 的 Runtime::Front 前端；DEAD-03 的 Foundation Coroutine::TaskRegistry；ProtocolBuiltins 中未使用的纯转调别名。报告把它们标成 dormant/legacy，不把它们说成现有生产请求路径已在运行。
- 架构判断不是运行时 bug：大文件、跨目录 ownership、CMake helper 旁路、协议元数据表语义未统一。它们基于当前真实目录/依赖/调用关系，但影响是维护和扩展风险；META-01 明确不把 SupportsUdp 两张表的不同语义说成已验证的当前请求失败。
- TUIC Application 测试没有 NativeTls 配置；它不能作为有效 TUIC 启动路径的正反证据。报告已将其限定为测试合同/fixture 缺口，而不是断言 TUIC 当前必然启动成功或失败。

本次是静态核验，没有构建或执行测试；所以“存在源码路径”不等于已经由运行时复现，“无调用点”也只表示当前仓库内搜索不到生产调用者，不代表外部 downstream 不会调用公开 API。

### 审查口径与限制

- 当前 HEAD 为 a9cd8fd8；工作树存在未提交修改，包含 Preview/Application/Application.cpp 和多份 Diagnose 实现/测试。本文按审查时磁盘内容记录，不把这些工作树内容等同于已提交版本。
- Preview/ 共 412 个文件，约 116,863 个物理行；其中 61 个文件超过 500 行，10 个超过 1,000 行。计数包含头文件、CMake、配置和说明，不代表纯 C++ LOC。
- tests/Preview/ 有 350 个文件，其中 281 个 C++ 测试源文件，73 个超过 500 行、17 个超过 1,000 行；其余是 CMake、脚本和数据。不等于 350 个已执行测试 target。
- Preview 下可见 7 个 .cpp 文件，其中 2 个为 Performance benchmark；其余生产源文件主要集中在 Application、Operations、Runtime Mailbox、QUIC Native。其余实现大量采用头文件和 INTERFACE target。
- 按用户要求，没有构建或运行测试。因此，协议线协议正确性、并发时序、跨平台行为及 E2E 稳定性未由本次审查验证。下文把静态可证缺陷、边界/维护问题和待验证风险分开表述。

## 按目录树检查

### Account

Account/ 共 9 个文件、约 1,888 行，职责规模相对集中。QUIC admission 会将账户凭据和 authenticator 通过 QuicAdmissionContext 带入协议 factory；这类协议与账户的绑定目前发生在 Ingress/Application/Composition，而不是 Account 自身。Account 本身没有在本轮静态抽查中形成独立的高置信逻辑缺陷。

### Application

Application/Application.cpp 有 4,618 行；Application::Start() 从约第 3,732 行延伸到第 4,545 行，单个启动流程约 800 行。文件还集中放置 RuntimeState、启动回滚、listener 启动、信号处理、操作 API 查询/命令、TCP candidate 构造、UDP service wiring、QUIC CID registry 和逐协议启动分支。[Application.cpp](../../Preview/Application/Application.cpp#L3732)

这使 Application 同时承担 composition root 和协议策略实现。MakeQuicAdmissionContext() 自己校验 protocol 类型并装配 Hysteria2/TUIC 回调；后续启动代码再按字符串 "tuic"/其他分支选择 factory。协议增加或数据面变化需要回到这个大文件修改多处代码，且启动顺序与协议逻辑在同一翻阅范围内。[Application.cpp](../../Preview/Application/Application.cpp#L1229) [Application.cpp](../../Preview/Application/Application.cpp#L4241)

Application/TuicAdmission.hpp 定义异步 TUIC stream admission/handler，却被登记在 PreviewConfiguration 的 target source 列表中。它包括协议流、认证和拨号相关行为，不是配置模型或解析代码；当前目录归属和构建 target 名称都把运行时协议行为放到了配置边界。[TuicAdmission.hpp](../../Preview/Application/TuicAdmission.hpp#L25) [Preview/CMakeLists.txt](../../Preview/CMakeLists.txt#L372)

Configuration/ConfigurationValidator.hpp 有 2,058 行，并且直接维护全部协议配置的语义规则。例如 Hysteria2/TUIC 的名单、单 QUIC protocol 限制、ALPN、UUID 和 credential 规则都在同一个 validator。该文件与 Application、Composition 的候选/启动工厂构成重复的协议清单；增加协议不是通过单一协议描述注册完成，而要修改多个 central switch/validator。[ConfigurationValidator.hpp](../../Preview/Application/Configuration/ConfigurationValidator.hpp#L252)

### CMake

Preview/CMakeLists.txt 有 792 行，集中列出 Preview 生产头、各协议 target、target 链接关系和边界断言。多数 Protocol、Runtime、Composition target 为 INTERFACE，主要提供 headers 与传递依赖；真正的编译所有权没有随目录模块化一起形成。对于模板/必须 header-only 的协议这是合理的，但目前 Application、Runtime、Composition、多个 protocol 之间仍靠大规模内联实现和中央 source list 维持，模块 target 名称容易给出比实际源码边界更强的隔离感。

源码 include 图与声明的 target 图不一致：Runtime/Front/UdpFront.hpp 和 QuicFront.hpp 直接 include Composition/Adapters、Composition/Recognition；QuicFront 还直接 include Protocols/Quic。然而 PreviewRuntime 的显式链接集合只列 Net、Transport、Foundation、Lifecycle、Account、Resource、Scheduler 等依赖，不包含 Composition 或 ProtocolQuic。这是 Runtime -> Composition/Protocols 的隐藏依赖；Composition 又链接 Runtime，形成源码层面的反向边/循环。当前边界断言检查 CMake target link/include-directory 属性，并不检查源文件的 #include 依赖，所以不会报告这类问题。[UdpFront.hpp](../../Preview/Runtime/Front/UdpFront.hpp#L25) [QuicFront.hpp](../../Preview/Runtime/Front/QuicFront.hpp#L23) [Preview/CMakeLists.txt](../../Preview/CMakeLists.txt#L294)

边界 helper 的规则与实际链接也有旁路。AssertPreviewDependency() 对 PreviewComposition 的允许集合不包含 PreviewOperations/PreviewStatistics，但 CMake 在 367 行直接 target_link_libraries(PreviewComposition ...)；PreviewConfiguration 的规则只允许 Foundation，实际又在 391 行直接链接 PreviewAccount。直接调用 target_link_libraries 不会执行 LinkPreviewTargets 内部的断言。因而这些边界检查并不是实际目标图的完整校验，规则、例外和实际依赖已发生漂移。[PreviewBoundary.cmake](../../Preview/CMake/PreviewBoundary.cmake#L131) [PreviewBoundary.cmake](../../Preview/CMake/PreviewBoundary.cmake#L144) [Preview/CMakeLists.txt](../../Preview/CMakeLists.txt#L367) [Preview/CMakeLists.txt](../../Preview/CMakeLists.txt#L391)

PreviewRuntime -> PreviewConfiguration 是显式 target edge，但 Runtime 源码目录当前没有直接 include Preview/Application/Configuration。需要确认这是实际依赖还是遗留 link；若只为让顶层 Application 编译通过，应由 PreviewApplication 显式持有，而不应扩大 Runtime 的传递依赖。相反，Runtime 实际 include 的 Composition/Protocol 依赖没有登记。

PreviewComposition 还把 PreviewOperations 静态库作为传递依赖，这意味着只需要 protocol composition 的消费者也获得 Operations HTTP server 闭包。控制面 API 与数据面候选装配最好分成不同 target，避免 target 名称和消费成本不一致。

### Composition

Composition/ 约 12,561 行，49 个文件；7 个文件超过 500 行，其中 Recognition/CandidateFactory.hpp 946 行、TlsCandidateFactory.hpp 800 行、AnytlsService.hpp 848 行、MuxService.hpp 658 行、Settings/Loader.hpp 766 行。Composition 同时包含协议适配器、识别候选构造、QUIC protocol factories、mux service、AnyTLS service、设置加载和 Operations API，已是另一个很宽的聚合层。

CandidateFactory/TlsCandidateFactory 与 Runtime Recognition 的 Profile、ConfiguredMode、MixedTrialMode 分别保存和转换候选/协议选择信息。新增协议需要跨这些层维护同一份能力与名字，属于重复协议知识，而不是仅靠增加一个协议目录即可扩展。[CandidateFactory.hpp](../../Preview/Composition/Recognition/CandidateFactory.hpp#L646) [TlsCandidateFactory.hpp](../../Preview/Composition/Recognition/TlsCandidateFactory.hpp#L714) [Profile.hpp](../../Preview/Runtime/Recognition/Profile.hpp#L1) [ConfiguredMode.hpp](../../Preview/Runtime/Recognition/ConfiguredMode.hpp#L1)

Hysteria2/TUIC factory 放在 Composition 中本身可以成立，因为它们装配 QUIC、认证、Runtime dial 和协议 handler；问题是协议 admission 又分散在 Application/TuicAdmission.hpp、Ingress/QuicAdmissionContext.hpp 和 Application.cpp。建议把协议自身的认证状态机/stream-datagram handler 收回对应 Protocol service/API，把 Composition 限定为依赖注入和注册，把共享 QUIC socket/CID 入口留给 Ingress。

HTTP-01：Application 的 MakeRuntimeAcceptors() 明确以 RequireAuth=true 和协议 Authenticator 构造实际 HTTP handler；MakeTcpProfile() 再把这个 Accept callback 覆盖到识别 candidate 上。Handler 先读取并验证 Request.authorization；普通非 CONNECT 请求随后调用 ReleaseForward。BuildForwardRequest 将请求行改成 origin-form 后直接追加 Raw.substr(Request.LineEnd)，所以成功验证的 Proxy-Authorization 不会被移除，会随普通 HTTP 请求发送给用户指定的源站。即便 RequireAuth=false，只要客户端附带此头，也仍会被照样转发。CONNECT 不走这个 ReleaseForward 分支。[Application.cpp](../../Preview/Application/Application.cpp#L2059) [Application.cpp](../../Preview/Application/Application.cpp#L2454) [CandidateFactory.hpp](../../Preview/Composition/Recognition/CandidateFactory.hpp#L562) [CandidateFactory.hpp](../../Preview/Composition/Recognition/CandidateFactory.hpp#L603) [Parser.hpp](../../Preview/Protocols/Http1/Parser.hpp#L465) [Parser.hpp](../../Preview/Protocols/Http1/Parser.hpp#L487)

HTTP-02：对 absolute-form 请求，ResolveTarget 从 Request.Target 的 URI authority 决定拨号 Host/Port；ParseRequest 虽然提取 Host，却没有检查它与 URI authority 是否相同；BuildForwardRequest 又保留原始 Host 头。于是客户端可以要求代理连接 URI 中的主机 A，同时把 Host: B 发给连接后的服务器，造成虚拟主机/缓存路由混淆。转发绝对 URI 时应从唯一 authority 重新生成 Host，或在输入不一致时拒绝。[Parser.hpp](../../Preview/Protocols/Http1/Parser.hpp#L393) [Parser.hpp](../../Preview/Protocols/Http1/Parser.hpp#L434) [Parser.hpp](../../Preview/Protocols/Http1/Parser.hpp#L487)

HTTP-03：普通 HTTP 转发是按字节保留完整原始头块，不解析/去除 Connection 声明的逐跳字段，也不去除 Proxy-Connection 等 proxy 侧控制头。除 Proxy-Authorization 外，源站还会收到只对当前代理连接有效的 header；Connection 声明的扩展 hop-by-hop 字段也会泄漏到下一跳。现有转发测试只覆盖无 proxy credential、无 Connection 头的普通请求，无法发现这类转发错误。[Parser.hpp](../../Preview/Protocols/Http1/Parser.hpp#L348) [Parser.hpp](../../Preview/Protocols/Http1/Parser.hpp#L487) [Http11ConnectTest.cpp](../../tests/Preview/protocols/http/Http11ConnectTest.cpp#L78)

builtin registry 有实际调用，用于配置 builtin/capability 校验，但它不是运行时 protocol handler 插件注册表：ProtocolBuiltins 文档明确把 I/O、认证和数据面留给 Composition adapter/Front；Application 仍直接调用 CandidateFactory、UdpServiceFactory 并按协议类型分支。向 registry 加一项不会自动生成协议解析、Session handler 或 ingress service。[ProtocolBuiltins.hpp](../../Preview/Composition/Builtin/ProtocolBuiltins.hpp#L2) [Application.cpp](../../Preview/Application/Application.cpp#L3776) [CandidateFactory.hpp](../../Preview/Composition/Recognition/CandidateFactory.hpp#L646)

ProtocolBuiltins 还公开 RegisterProtocolAndCarrierBuiltins、RegisterAllBuiltins、RegisterBuiltinDescriptors 等纯转调别名；Application 实际调用 RegisterAllBuiltins，而 RegisterProtocolAndCarrierBuiltins、RegisterBuiltinDescriptors 在仓库内没有调用点。别名数量增加 API 表面积，却不形成额外能力；同文件中仅用于测试的注册变体应与 production API 区分。[ProtocolBuiltins.hpp](../../Preview/Composition/Builtin/ProtocolBuiltins.hpp#L259) [ProtocolBuiltins.hpp](../../Preview/Composition/Builtin/ProtocolBuiltins.hpp#L267) [ProtocolBuiltins.hpp](../../Preview/Composition/Builtin/ProtocolBuiltins.hpp#L275) [Application.cpp](../../Preview/Application/Application.cpp#L3777)

Composition/Settings/Json.hpp 是一份自维护 JSON 解析器，同时配置文件的另一条主路径使用 Glaze。两个 parser 的严格性与数值/Unicode 语义并不一致；除非 Settings 有无法由现有 parser 表达的需求，否则这会产生长期的重复正确性负担。

#### HTTP/QUIC/UDP 协议代码的真实归属

HTTP 的 parser/ServerConn 在 Protocols/Http1；负责请求认证、AccountLease、CONNECT/普通转发分支和 PostDial response 的 HttpHandler 在 Composition/Recognition/CandidateFactory。CandidateFactory 因此同时是识别 candidate builder 和 HTTP 会话 handler 所有者。[Conn.hpp](../../Preview/Protocols/Http1/Conn.hpp#L107) [CandidateFactory.hpp](../../Preview/Composition/Recognition/CandidateFactory.hpp#L518)

QUIC Native transport 在 Protocols/Quic；Hysteria2/TUIC wire 类型和 codec 在各自 Protocols 目录；Hysteria2 HTTP/3、TUIC stream factory 在 Composition/Quic；TUIC admission handler 在 Application/TuicAdmission.hpp；共享 QUIC 上下文在 Ingress；CID registry 和每协议 factory 选择在 Application.cpp。共享 socket/CID 路由属于 Ingress，协议认证/状态机属于相应 Protocol service，Composition 负责装配，Application 只选择已注册 service 会更容易维护。目前两种协议实现横跨四五个目录，新增 admission/state field 会继续扩大 QuicAdmissionContext。[Native.hpp](../../Preview/Protocols/Quic/Native.hpp#L1) [Hysteria2Factory.hpp](../../Preview/Composition/Quic/Hysteria2Factory.hpp#L349) [TuicFactory.hpp](../../Preview/Composition/Quic/TuicFactory.hpp#L135) [TuicAdmission.hpp](../../Preview/Application/TuicAdmission.hpp#L25) [QuicAdmissionContext.hpp](../../Preview/Ingress/QuicAdmissionContext.hpp#L33) [Application.cpp](../../Preview/Application/Application.cpp#L4241)

SS2022 request/response/dgram codec 在 Protocols/Shadowsocks2022；Ingress/Ss2022Gateway 负责 UDP packet peer/session admission；Application 普通 UdpServiceFactory 则只装配 SOCKS5/VLESS/Trojan/VMess。SS2022 走 direct ingress gateway，不走同一 UdpService factory。这一差异可能是协议所需，但当前代码没有统一的 typed ingress contract 描述“UDP carrier association”和“protocol 在其他载体上承载 datagram”两类能力。[Ss2022Gateway.hpp](../../Preview/Ingress/Ss2022Gateway.hpp#L1) [RequestCodec.hpp](../../Preview/Protocols/Shadowsocks2022/RequestCodec.hpp#L1) [Application.cpp](../../Preview/Application/Application.cpp#L4272)

### Foundation

Foundation 有 65 个文件、约 10,698 行。Utility/Diagnose/Detail/ContextDecoder.hpp 有 567 行；Diagnose 目录当前有未提交修改，审查时没有将其变化判断为稳定架构结论。

Foundation/SessionBase.hpp 不是完全未使用代码：当前 Protocols/Mux/StreamState.hpp 的 StreamHandle 仍继承它，并由 Protocols/Mux/Stream.hpp 适配为 Transmission。但 SessionBase.hpp 自己留有“StreamHandle 直连 Transmission 后删除本文件”的迁移 TODO，说明目前仍存在额外抽象和适配层。应把它记为未完成迁移，不应误删或标成死代码。[SessionBase.hpp](../../Preview/Foundation/SessionBase.hpp#L14) [StreamState.hpp](../../Preview/Protocols/Mux/StreamState.hpp#L96)

Foundation/Utility/Coroutine/Registry.hpp 还公开了另一套 Preview::Coroutine::TaskRegistry，约 350 行、以 io_context 引用和裸 TaskRegistry* owner 实现 token 注销。全树 production 调用集中在 Preview::Lifecycle::TaskRegistry；Coroutine 版本只出现在 RegistryTest 和 OwnershipAudit 测试，Preview/CMakeLists 却把它登记为 PreviewFoundation 公共头。它不是当前运行时的实际 registry，而是两套接口/所有权语义并存的旧实现。OwnershipAudit 中的 TaskRegistryDanglingOwner 用例记录过析构后 completion 访问 Owner_ 的 UAF，并依靠 Detach 修复；现状不应写成仍可触发的 bug，但继续作为 Foundation 公共 API 会误导后续接入者。[Registry.hpp](../../Preview/Foundation/Utility/Coroutine/Registry.hpp#L61) [Registry.hpp](../../Preview/Foundation/Utility/Coroutine/Registry.hpp#L165) [TaskRegistry.hpp](../../Preview/Lifecycle/TaskRegistry.hpp#L49) [OwnershipAudit.cpp](../../tests/Preview/core/misc/OwnershipAudit.cpp#L222) [Preview/CMakeLists.txt](../../Preview/CMakeLists.txt#L43)

### Ingress

Ingress/QuicAdmissionContext.hpp 是当前最明显的多协议 god-context：一个 struct 同时保存通用 QUIC executor/limits、账户 credential/authenticator、DNS resolver、Runtime DialFn、metrics/trace、Hysteria2 stream/dgram callback、TUIC UUID/password/stream/dgram callback、owner close callback。Ingress 因而不再只负责 carrier admission，而知道两种应用协议的认证和业务数据面形状。[QuicAdmissionContext.hpp](../../Preview/Ingress/QuicAdmissionContext.hpp#L33)

PreviewIngress target 直接依赖 Quic Native、Hysteria2、TUIC、Shadowsocks2022；其中 QuicAdmissionContext include Hysteria2/TUIC，QuicCidRegistry include QUIC Native，Ss2022Gateway include SS2022 codec。Ingress 命名下同时承载通用 UDP demux、QUIC CID admission、protocol-specific wire recognition。建议抽出 carrier-level interface，并让协议模块提供明确的 typed admission handler；避免继续向 context 增加每个新协议的字段和 callback。

现有 Middleware 不能直接代替这类 gateway：Middleware::Handle() 处理 SharedTransmission 字节流和一个通用 Context；QUIC ingress 处理的是 CID/connection、ALPN、stream provider、datagram provider、TLS exporter 和连接 drain 生命周期。把它硬塞进现有 stream middleware 会扩张接口、让传输语义变得模糊。Middleware 适合 Auth/Dial/Mux/Pad/Relay 等可表示为 stream-stage 的逻辑；gateway 应走独立 typed carrier/protocol adapter。

### Lifecycle

Lifecycle/TaskRegistry.hpp 有 710 行，是 detached/worker task 的重要所有权边界。该文件和 SessionControl、Application rollback、Runtime stop 多处共同构成取消和 shutdown 生命周期；文件改动的风险面远大于单个协议。当前静态抽查没有确认具体生命周期 bug，但后续拆分 Runtime/App 时应以 TaskRegistry 的 stop/join/cancel 语义为不变量，不要把它拆成只有文件变短、所有权反而更分散的片段。

### Net

Net/Dns/ 有 22 个文件、约 5,672 行；Resolver 591 行、Upstream 676 行、Format 589 行。DNS parse/transport/upstream/fallback/cache/coalescing 已分了子文件，但主要协调器仍承载多个策略。该区域属于高风险共享服务，当前未执行并发和 DNS 行为测试，本文不对其缓存、single-flight 或线程安全作通过结论。

### Operations

Operations/HttpServer.cpp 有 1,627 行；同一 translation unit 既包含连接 close/read-deadline 管理，也包含 HTTP request parsing。Operations server 属于管理面，不应与各协议数据面混到 Application 启动流程；目前 Application.cpp 仍直接构造 Router、Query/Command handler 和 HttpServer。建议让 Application 只提供稳定的 operations interface，管理端点的组装从启动主体中拆出。[HttpServer.cpp](../../Preview/Operations/HttpServer.cpp#L1135) [HttpServer.cpp](../../Preview/Operations/HttpServer.cpp#L1364) [Application.cpp](../../Preview/Application/Application.cpp#L3650)

### Performance

Performance/ 只有两个 benchmark 源文件，总体边界清楚。本次没有运行 benchmark，不能从目录存在或历史数据推断当前性能。

### Protocols

Protocols/ 共 148 个文件、约 48,942 行；61 个大文件中有 36 个在该目录，超过 1,000 行的 protocol 文件有 4 个。协议树内部虽然多数协议有自己的目录，但实现粒度不一致：有的分 Codec/Conn，有的把 HTTP/2、HTTP/3 server/client/session 都放在相邻大文件，有的把一个连接的收发、并发写队列和生命周期放进一个 Conn.hpp。文件数增加并没有稳定地对应清晰所有权。

最大风险点包括 Protocols/Quic/Native.cpp 2,769 行，包含 QUIC stream/datagram、TLS callback、ngtcp2/nghttp3 回调桥接和 Native Gateway 实现；Protocols/Xhttp/Conn.hpp 2,108 行；Protocols/Mux/Session.hpp 1,307 行；Protocols/Trusttunnel/Http2.hpp 1,016 行。上述代码涉及底层 callback、多个异步循环或多流状态机，属于应优先拆出具名、真实编译边界的文件，不适合仅按行数切碎。

QUIC shared gateway 的协议判断目前放在 Protocols/Quic/GatewayCommon.hpp，包含 H3/TUIC 枚举分支和两个虚钩子；更上层又有 Ingress gateway、Composition factories、Application protocol-specific context。共享 QUIC 连接/stream adapter 可以留在 Quic/Ingress，但 Hysteria2/TUIC 的协议 handler 应由协议模块暴露 typed 接口，避免公共 GatewayCommon 继续列举应用协议。[GatewayCommon.hpp](../../Preview/Protocols/Quic/GatewayCommon.hpp#L312)

静态状态问题：RegisterTypedConnection() 在“typed QUIC connection 注册”成功时立即把 ConnectionState::authenticated 设为 true；但 Hysteria2 authenticator 在 HTTP /auth handler 执行，TUIC authenticator 在 exporter/token admission 执行。这个字段目前在全树没有读点，因而没有发现直接安全绕过；但它的值与注释“是否认证通过”不符，后续若作为 gate 使用会在协议认证前放行。应删除兼容字段，或把 transport admission 与 protocol authentication 分成不同状态。[GatewayCommon.hpp](../../Preview/Protocols/Quic/GatewayCommon.hpp#L77) [GatewayCommon.hpp](../../Preview/Protocols/Quic/GatewayCommon.hpp#L141) [QuicFront.hpp](../../Preview/Runtime/Front/QuicFront.hpp#L170)

GatewayCommon::GuessProtocol() 被明确实现为始终返回 Unknown，当前只由测试验证该行为，没有生产调用。它不是 protocol detector；保留的兼容 API 容易让调用方误以为 QUIC stream 首字节可用于协议路由。若设计要求绝不猜测，应把这个约束放在明确的绑定/dispatch API，不保留一个看似检测函数的空实现。[GatewayCommon.hpp](../../Preview/Protocols/Quic/GatewayCommon.hpp#L55)

### Resource

Resource/ 共 6 个文件、约 515 行，体量适中。当前没有对其所有权模型作并发或 detach 审计，因此不报告“资源安全已确认”。

### Runtime

Runtime/Session.hpp 有 1,255 行，承担 carrier probe/TLS upgrade、protocol recognition、认证、mux/pad、dial、protocol reply、relay 和多阶段日志/失败收尾。第 925 行之后的一个主要路径连续编排认证、装饰 pipeline、dial 和 relay，故 Session 不只是状态对象，而是多个子系统的控制器。它适合保留会话生命周期协调，但认证适配、carrier commit、拨号/relay policy 应有独立稳定接口。[Session.hpp](../../Preview/Runtime/Session.hpp#L625) [Session.hpp](../../Preview/Runtime/Session.hpp#L925) [Session.hpp](../../Preview/Runtime/Session.hpp#L995)

Recognition 跨 Runtime/Recognition/Profile.hpp 1,281 行、ConfiguredMode.hpp 1,020 行、MixedTrialMode.hpp 716 行、Tls.hpp 689 行以及 Composition CandidateFactory/TlsCandidateFactory。识别预算、候选优先级、carrier commit 和 inner protocol dispatch 分散在两层目录，修改识别行为必须同时理解多份 profile/candidate 表示。这是层间概念重复和阅读成本，不是文件名问题。

DEAD-02：UdpFront.hpp 文件头明说真实 production packet pump 在 Ingress/UdpListener；UdpFront 只保留 typed association/transport contract。QuicFront 在全树的内部调用点也只出现在自身和 Task9FrontIntegration 测试；Application 实际创建的是 Ingress::UdpListener、IngressDispatcher、Ingress::QuicGateway 和 QuicCidRegistry，没有构造 Runtime::Front::UdpFront/QuicFront。两种 Front 又被 PreviewRuntime 的 INTERFACE source 列表公开，并分别 include Composition/Protocol headers。因此目前存在“测试中的 Runtime Front”与“真正启动的 Ingress path”两套入口模型；Task9FrontIntegration 通过不等于 Application 的真实 UDP/QUIC path 等价通过。应明确它是实验 API/合同测试，或迁移实现并删除另一套入口。[UdpFront.hpp](../../Preview/Runtime/Front/UdpFront.hpp#L2) [QuicFront.hpp](../../Preview/Runtime/Front/QuicFront.hpp#L2) [UdpFront.hpp](../../Preview/Runtime/Front/UdpFront.hpp#L82) [Application.cpp](../../Preview/Application/Application.cpp#L4015) [Task9FrontIntegration.cpp](../../tests/Preview/integration/Task9FrontIntegration.cpp#L132) [Preview/CMakeLists.txt](../../Preview/CMakeLists.txt#L286)

ProtocolCatalog、ProtocolMatrix 和 ProtocolBuiltins 是三份 protocol capability/registration 表。它们可能本来就回答不同问题（协议能否承载数据报、能否作为 UDP association 注册、builtin 需要什么能力），但字段名和类型没有把这三种概念区分清楚：ProtocolCatalog 将 TrustTunnel 标为 SupportsUdp=true，却不列入 ProtocolMatrix::UdpAssociations；Hysteria2/TUIC 在 Catalog 中 SupportsUdp=false，却列入 UdpAssociations。ProtocolCatalog::Supports 没有 production 调用点，Front 的 SupportsUdp 读另一张 Matrix，而 Application 又独立构造四种 UDP service。当前不能把任何一张表当作整个 Preview 的唯一支持真值；这属于能力模型歧义/未接线，不是已证实的当前配置 bug。[ProtocolCatalog.hpp](../../Preview/Composition/Protocol/ProtocolCatalog.hpp#L81) [ProtocolCatalog.hpp](../../Preview/Composition/Protocol/ProtocolCatalog.hpp#L168) [ProtocolMatrix.hpp](../../Preview/Composition/Recognition/ProtocolMatrix.hpp#L153) [Application.cpp](../../Preview/Application/Application.cpp#L4272)

Runtime/Middleware/Pipeline.hpp 的 Add() 无条件保存 shared_ptr；Run() 无条件执行 mw->Handle()。公开 API 接受空 shared_ptr，因此 Pipeline.Add(nullptr) 后运行会空指针解引用。Add 应拒绝空项，或明确用类型/约束保证不可为空。[Pipeline.hpp](../../Preview/Runtime/Middleware/Pipeline.hpp#L78) [Pipeline.hpp](../../Preview/Runtime/Middleware/Pipeline.hpp#L90)

Runtime/Middleware/Builtin/Throttle.hpp 中 ThrottleMiddleware、BanMiddleware 目前没有被 Application/Session 的 production pipeline 实例化；Session 当前 pipeline 实例是 Auth、Mux、Pad、Dial、Relay。Throttle/Ban 的使用只出现在 RateLimit 测试源码。因此它们现状是 dormant/test-only plumbing，不能被理解为已接入 Preview 生产请求路径的限速/封禁能力。[Session.hpp](../../Preview/Runtime/Session.hpp#L958) [RateLimitTest.cpp](../../tests/Preview/core/rate/RateLimitTest.cpp#L119)

Dormant 的 BanMiddleware 若以后接入 production 仍有缺陷：RecordFailure() 与 IsBanned() 操作普通 unordered_map，没有同步；两个 map 不会清除过期 key，外部来源持续变化会使内存随 key 数增长；构造器也接受空 NowFn，但随后无检查地调用。它当前未接入数据面，因此这些是激活前风险，不是当前确认的线上 race。[Throttle.hpp](../../Preview/Runtime/Middleware/Builtin/Throttle.hpp#L110) [Throttle.hpp](../../Preview/Runtime/Middleware/Builtin/Throttle.hpp#L147)

QUIC admission guard 的协议字段是字符串。ReadyForTuic() 检查 Protocol == "tuic"，ReadyForHysteria2() 不检查协议名，Ready() 则把所有非 TUIC 字符串当作 Hysteria2。Application 随后同样把 tuic 以外都发给 Hysteria2 factory。ConfigurationValidator 和 MakeQuicAdmissionContext() 当前只允许 Hysteria2/TUIC，因此合法配置路径会挡住未知值；但 context 的自身契约并不封闭，直接调用者/未来新增协议容易静默误路由。应改为 enum/variant 并让未知值 fail-closed。[QuicAdmissionContext.hpp](../../Preview/Ingress/QuicAdmissionContext.hpp#L58) [QuicAdmissionContext.hpp](../../Preview/Ingress/QuicAdmissionContext.hpp#L76) [ConfigurationValidator.hpp](../../Preview/Application/Configuration/ConfigurationValidator.hpp#L259) [Application.cpp](../../Preview/Application/Application.cpp#L4250)

ConfigurationValidator 还明确拒绝在一个 QUIC listener 上同时启用 Hysteria2 和 TUIC，理由是不能通过 trial 两个 QUIC engines 决定 admission。这是当前产品能力限制而非隐藏 bug；若目标是同一 UDP/QUIC 入口支持多个协议，需要依赖 ALPN/CID/认证协议 discriminator 进行唯一选择，而不是继续 trial。

### Scheduler

Scheduler/ 共 5 个文件、约 1,429 行；FairScheduler.hpp 507 行。没有在本轮发现独立高置信缺陷。调度服务与 Runtime worker 的所有权/关闭顺序应和 Lifecycle TaskRegistry 一起审查。

### Statistics

Statistics/ 共 10 个文件、约 971 行，体量合理。Metrics sink 目前通过 QUIC admission context 和 Session Context 跨层传递，是更适合由 runtime service/typed context 提供的依赖，不应继续扩张 protocol context。

### Transport

Transport/ 共 12 个文件、约 4,082 行；Unreliable.hpp 635 行。Transport 的 Transmission/stream/datagram 能力是合理的复用边界。当前 Middleware 只接受 SharedTransmission，而 Datagram 和 QUIC connection 的生命周期另由 Ingress/Protocols 管理；若要通过中间件扩展，需要先定义不同 carrier stage 的类型合同，不能把可靠字节流和 QUIC stream/datagram 混成一个无差别 Context。

## 可静态确认的 parser 缺陷

Composition/Settings/Json.hpp 的 ParseNumber() 扫描时允许数字 token 内出现任意组合的 + - . e E，随后以没有 idx 参数的 std::stod() 解析，所以没有检查转换是否消费了整个 token。例如 1e、1+、01 会被 token 扫描吞入，stod 可以只转换前缀并返回成功；ParseJson() 最后的 trailing-content 检查无法发现已被扫描消费的非法后缀。[Json.hpp](../../Preview/Composition/Settings/Json.hpp#L178) [Json.hpp](../../Preview/Composition/Settings/Json.hpp#L201) [Json.hpp](../../Preview/Composition/Settings/Json.hpp#L372)

ParseString() 对非 escape 字符直接 append，没有拒绝 U+0000 到 U+001F 的原始控制字节；JSON 字符串内换行等控制字符应必须 escape。[Json.hpp](../../Preview/Composition/Settings/Json.hpp#L171)

\uXXXX 只把一个 16-bit code unit 编码成 UTF-8，没有合并 surrogate pair，也没有拒绝孤立 surrogate。BMP 外字符如 \uD83D\uDE00 会编码为两个非法 UTF-8 surrogate 序列，而不是对应的四字节 UTF-8 字符。源码注释也明确标出仅支持 BMP。[Json.hpp](../../Preview/Composition/Settings/Json.hpp#L121)

对象字段通过 obj.emplace() 插入；重复 key 被静默忽略，实际保留第一次出现的值，不报配置错误。多份 JSON parser 对重复 key 采取不同策略时会出现配置解释分歧，建议 Settings parser 明确拒绝重复键。[Json.hpp](../../Preview/Composition/Settings/Json.hpp#L286)

JSON-05：JsonValue 把每个数字都存为 double；Settings Loader 的 ReadUnsigned 再从 double 转成 uint64_t。虽然 TimeoutMs 接受至 int64 最大值，double 不能精确表示超过 2^53 的所有整数，合法输入如 9007199254740993 会先变成相邻可表示值，随后被当成合法整数写进配置，静默改变时长。当前 MaxConnections/port 等小范围字段不受同样精度影响，但 64-bit timeout/counter 参数不能继续走 double 中转。[Json.hpp](../../Preview/Composition/Settings/Json.hpp#L55) [Loader.hpp](../../Preview/Composition/Settings/Loader.hpp#L105) [Loader.hpp](../../Preview/Composition/Settings/Loader.hpp#L286)

现有 SettingsApiTest.cpp 覆盖基本值、嵌套结构和少量错误输入，但没有覆盖非法数字 token、裸控制字符、surrogate pair/孤立 surrogate 或重复 key。该结论来自测试源码检查；本次没有执行测试。[SettingsApiTest.cpp](../../tests/Preview/core/settings/SettingsApiTest.cpp#L22) [SettingsApiTest.cpp](../../tests/Preview/core/settings/SettingsApiTest.cpp#L60)

## 测试树本身的问题

tests/Preview 有 281 个 C++ 测试源文件，但 73 个超过 500 行、17 个超过 1,000 行。ConfigurationTest.cpp 2,293 行、AnytlsSessionDeep.cpp 1,834 行、TransportDecoratorCoverage.cpp 1,811 行和 ApplicationTest.cpp 1,810 行都把大量场景装进一个 translation unit。它们内部虽然可能有多个 TEST suite，但文件责任与构建 target 仍然绑在一起；单个改动要重新编译整个大文件，测试失败定位、review 和跨 agent/task 拆分都更费力。这里的问题不是每个 TEST 必须独立文件，而是当前单文件已经同时覆盖协议、配置、生命周期、fixture 和多个边界合同。

HTTP 转发的认证测试拆成两块：一组单测 CheckBasic 是否接受凭据；另一组单测 BuildForwardRequest 如何转发普通请求。没有测试把“成功认证的普通 HTTP request”送过 HttpHandler，并断言 Proxy-Authorization 不出现在上游字节中。正是这种只测 parser/helper、不测组合路径的缺口让 HTTP-01 没被现有测试发现。[Http11ConnectTest.cpp](../../tests/Preview/protocols/http/Http11ConnectTest.cpp#L264) [Http11ConnectTest.cpp](../../tests/Preview/protocols/http/Http11ConnectTest.cpp#L78)

ApplicationTest 中的 RejectsTuicProtocolUntilQuicFrontIsWired 仍以“TUIC 未支持”为合同，但配置没有 NativeTls 证书输入；当前 Application 的 TUIC admission context 和 ConfigureTuicServer 分支都存在。该测试未构造有效的 TUIC 启动配置，所以不能证明当前 TUIC 合法配置应被拒绝，也不能证明完整 TUIC 启动成功。测试名称/预期、必要 TLS 前置条件和当前启动实现应被整理成同一合同。[ApplicationTest.cpp](../../tests/Preview/core/Application/ApplicationTest.cpp#L932) [Application.cpp](../../Preview/Application/Application.cpp#L1239) [Application.cpp](../../Preview/Application/Application.cpp#L4250)

Task9FrontIntegration 的 Front 测试覆盖 Runtime::Front::UdpFront/QuicFront 的数据结构与单对象调用；Application 启动测试则通过 Ingress::UdpListener/QuicGateway。两组测试各自通过仍不能证明 front 合同与真实 Application ingress 等价。目前看不到把 Task9 Front 的注册、协议绑定、关闭传播和资源限制通过 Application 的真实配置路径跑通的测试。[Task9FrontIntegration.cpp](../../tests/Preview/integration/Task9FrontIntegration.cpp#L132) [ApplicationTest.cpp](../../tests/Preview/core/Application/ApplicationTest.cpp#L1035)

下表列出 tests/Preview 下所有超过 500 行的 C++ 源文件，便于按模块安排后续逐文件 review；行数不是缺陷判据，但大文件的跨场景耦合已是测试维护风险。

| 目录 | 测试源文件 | 行数 |
|---|---|---:|
| carrier | carrier/RealityCarrierTest.cpp | 642 |
| core/account | core/account/AccountNgxTest.cpp | 927 |
| core/account | core/account/AuthenticatorTest.cpp | 592 |
| core/Application | core/Application/ApplicationTest.cpp | 1,810 |
| core/Configuration | core/Configuration/ConfigurationTest.cpp | 2,293 |
| core/crypto | core/crypto/CryptoExceptionCoverage.cpp | 1,026 |
| core/fuzz | core/fuzz/DgramErrorCoverage.cpp | 1,388 |
| core/Lifecycle | core/Lifecycle/TaskLifecycle.cpp | 1,116 |
| core/net | core/net/DnsResolverNgxTest.cpp | 608 |
| core/net | core/net/DnsTransportTest.cpp | 573 |
| core/net | core/net/DnsUpstreamTest.cpp | 695 |
| core/net | core/net/UdpRelayTest.cpp | 599 |
| core/Operations | core/Operations/OperationsHttpTest.cpp | 645 |
| core/protocol | core/protocol/TestCommonCodecDeep.cpp | 696 |
| core/recognition | core/recognition/ConfiguredModeTest.cpp | 1,505 |
| core/recognition | core/recognition/MixedTrialModeTest.cpp | 1,575 |
| core/recognition | core/recognition/ProfileCompileTest.cpp | 762 |
| core/recognition | core/recognition/RecognitionCarrier.cpp | 1,058 |
| core/recognition | core/recognition/RecognitionTest.cpp | 995 |
| core/recognition | core/recognition/TlsReassemblyTest.cpp | 1,366 |
| core/recognition | core/recognition/TlsSignal.cpp | 650 |
| core/runtime | core/runtime/AdapterTest.cpp | 710 |
| core/runtime | core/runtime/H2MuxStreamLifetimeTest.cpp | 681 |
| core/runtime | core/runtime/ListenerE2ETest.cpp | 1,107 |
| core/runtime | core/runtime/MuxServiceTest.cpp | 1,210 |
| core/runtime | core/runtime/SessionLifecycleTest.cpp | 779 |
| core/runtime | core/runtime/SessionOrchestrationTest.cpp | 581 |
| core/runtime | core/runtime/SessionRecognitionModeTest.cpp | 887 |
| core/runtime | core/runtime/Socks5UdpE2ETest.cpp | 673 |
| core/runtime | core/runtime/TrojanE2ETest.cpp | 549 |
| core/runtime | core/runtime/UdpServiceTest.cpp | 877 |
| core/runtime | core/runtime/VlessE2ETest.cpp | 715 |
| core/runtime | core/runtime/VMessE2ETest.cpp | 550 |
| core/settings | core/settings/ProfileBootstrapTest.cpp | 516 |
| core/transport | core/transport/CoreTransmission.cpp | 779 |
| core/transport | core/transport/TransportDecoratorCoverage.cpp | 1,811 |
| core/transport | core/transport/TransportTest.cpp | 757 |
| integration | integration/InteropHysteria2.cpp | 581 |
| integration | integration/InteropTuic.cpp | 636 |
| perf | perf/RecognitionPerf.cpp | 628 |
| protocols/http | protocols/http/Http11ConnectTest.cpp | 544 |
| protocols/http2 | protocols/http2/H2CodecTest.cpp | 804 |
| protocols/http3 | protocols/http3/HttpQuicCoverage.cpp | 1,142 |
| protocols/http3 | protocols/http3/NativeQuicLoopback.cpp | 506 |
| protocols/hysteria2 | protocols/hysteria2/Hysteria2ClientServerPerf.cpp | 573 |
| protocols/hysteria2 | protocols/hysteria2/Hysteria2ConnErrorMatrix.cpp | 726 |
| protocols/hysteria2 | protocols/hysteria2/Hysteria2ConnSession.cpp | 1,027 |
| protocols/mux/core | protocols/mux/core/MuxSessionDeep2.cpp | 619 |
| protocols/mux/core | protocols/mux/core/MuxSessionTest.cpp | 675 |
| protocols/mux/core | protocols/mux/core/MuxWriteContract.cpp | 743 |
| protocols/mux/h2mux | protocols/mux/h2mux/H2muxCraftAsync.cpp | 620 |
| protocols/mux/h2mux | protocols/mux/h2mux/H2muxCraftDeep2.cpp | 543 |
| protocols/mux/smux | protocols/mux/smux/SmuxCraftDeep2.cpp | 850 |
| protocols/shadowsocks2022 | protocols/shadowsocks2022/Ss2022CodecDeep.cpp | 750 |
| protocols/socks5 | protocols/socks5/Socks5ConnSession.cpp | 642 |
| protocols/socks5 | protocols/socks5/Socks5DgramSession.cpp | 532 |
| protocols/stealth/anytls | protocols/stealth/anytls/AnytlsSessionDeep.cpp | 1,834 |
| protocols/stealth/executor | protocols/stealth/executor/StealthExecutorDeep3.cpp | 775 |
| protocols/stealth/misc | protocols/stealth/misc/StealthVmessErrorCoverage.cpp | 1,448 |
| protocols/stealth/native | protocols/stealth/native/NativeConnTest.cpp | 573 |
| protocols/stealth/nested | protocols/stealth/nested/StealthNestedPerf.cpp | 668 |
| protocols/stealth/nested | protocols/stealth/nested/StealthNestedPerf2.cpp | 721 |
| protocols/stealth/nested | protocols/stealth/nested/StealthNestedPerf3.cpp | 538 |
| protocols/stealth/reality | protocols/stealth/reality/RealityKeygenTest.cpp | 527 |
| protocols/stealth/shadowtls | protocols/stealth/shadowtls/ShadowtlsRelay.cpp | 710 |
| protocols/stealth/ws | protocols/stealth/ws/WsConnSession.cpp | 650 |
| protocols/stealth/xhttp | protocols/stealth/xhttp/XhttpErrorMatrix.cpp | 666 |
| protocols/stealth/xhttp | protocols/stealth/xhttp/XhttpNgxE2E.cpp | 744 |
| protocols/trojan | protocols/trojan/TrojanConnSession.cpp | 796 |
| protocols/tuic | protocols/tuic/TuicClientServerPerf.cpp | 619 |
| protocols/vless | protocols/vless/VlessConnSession.cpp | 1,075 |
| protocols/vless | protocols/vless/VlessStressTest.cpp | 501 |
| protocols/vmess | protocols/vmess/VmessConnSession.cpp | 899 |

## 大文件清单

以下按 Preview 顶层目录顺序列出全部超过 500 行的文件，行数按当前磁盘物理行统计。大文件不自动等于坏代码；应结合表中承担的职责判断，优先处理跨状态机/协议/所有权边界混合的文件，而不是机械按行数拆分。

| 目录 | 文件 | 行数 |
|---|---|---:|
| Application | Application/Application.cpp | 4,618 |
| Application | Application/Configuration/ConfigurationValidator.hpp | 2,058 |
| Composition | Composition/AnytlsService.hpp | 848 |
| Composition | Composition/H2MuxServer.hpp | 502 |
| Composition | Composition/MuxService.hpp | 658 |
| Composition | Composition/Quic/Hysteria2Factory.hpp | 502 |
| Composition | Composition/Recognition/CandidateFactory.hpp | 946 |
| Composition | Composition/Recognition/TlsCandidateFactory.hpp | 800 |
| Composition | Composition/Settings/Loader.hpp | 766 |
| Foundation | Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp | 567 |
| Lifecycle | Lifecycle/TaskRegistry.hpp | 710 |
| Net | Net/Dns/Format.hpp | 589 |
| Net | Net/Dns/Resolver.hpp | 591 |
| Net | Net/Dns/Upstream.hpp | 676 |
| Operations | Operations/HttpServer.cpp | 1,627 |
| Protocols | Protocols/Gun/Grpc.hpp | 868 |
| Protocols | Protocols/Http1/Parser.hpp | 549 |
| Protocols | Protocols/Http2/Codec.hpp | 564 |
| Protocols | Protocols/Http2/Impl.hpp | 947 |
| Protocols | Protocols/Http3/NativeClient.hpp | 766 |
| Protocols | Protocols/Http3/NativeServer.hpp | 568 |
| Protocols | Protocols/Http3/Session.hpp | 722 |
| Protocols | Protocols/Hysteria2/Codec.hpp | 524 |
| Protocols | Protocols/Hysteria2/Conn.hpp | 635 |
| Protocols | Protocols/Hysteria2/Dgram.hpp | 573 |
| Protocols | Protocols/Mux/Session.hpp | 1,307 |
| Protocols | Protocols/Mux/Yamux/Codec.hpp | 521 |
| Protocols | Protocols/Quic/Native.cpp | 2,769 |
| Protocols | Protocols/Reality/Carrier.hpp | 656 |
| Protocols | Protocols/Reality/Codec.hpp | 837 |
| Protocols | Protocols/Restls/Codec.hpp | 539 |
| Protocols | Protocols/Restls/Conn.hpp | 564 |
| Protocols | Protocols/Shadowsocks2022/ChunkCodec.hpp | 518 |
| Protocols | Protocols/Shadowsocks2022/Conn.hpp | 957 |
| Protocols | Protocols/Shadowsocks2022/RequestCodec.hpp | 634 |
| Protocols | Protocols/Shadowsocks2022/ResponseCodec.hpp | 599 |
| Protocols | Protocols/Shadowtls/Codec.hpp | 721 |
| Protocols | Protocols/Shadowtls/Conn.hpp | 634 |
| Protocols | Protocols/Socks5/Codec.hpp | 981 |
| Protocols | Protocols/Socks5/Conn.hpp | 838 |
| Protocols | Protocols/Trojan/Codec.hpp | 619 |
| Protocols | Protocols/Trojan/Conn.hpp | 557 |
| Protocols | Protocols/Trusttunnel/Http2.hpp | 1,016 |
| Protocols | Protocols/Tuic/Conn.hpp | 718 |
| Protocols | Protocols/Vless/Codec.hpp | 655 |
| Protocols | Protocols/Vmess/Auth.hpp | 746 |
| Protocols | Protocols/Vmess/ChunkCodec.hpp | 657 |
| Protocols | Protocols/Vmess/Conn.hpp | 908 |
| Protocols | Protocols/Vmess/RequestCodec.hpp | 514 |
| Protocols | Protocols/Ws/Conn.hpp | 972 |
| Protocols | Protocols/Xhttp/Conn.hpp | 2,108 |
| Runtime | Runtime/Listener.hpp | 737 |
| Runtime | Runtime/Recognition/ConfiguredMode.hpp | 1,020 |
| Runtime | Runtime/Recognition/MixedTrialMode.hpp | 716 |
| Runtime | Runtime/Recognition/Profile.hpp | 1,281 |
| Runtime | Runtime/Recognition/Tls.hpp | 689 |
| Runtime | Runtime/Session.hpp | 1,255 |
| Runtime | Runtime/SessionControl.hpp | 590 |
| Scheduler | Scheduler/FairScheduler.hpp | 507 |
| Transport | Transport/Unreliable.hpp | 635 |
| Build | CMakeLists.txt | 792 |

## 后续审查/整改顺序建议

1. 先修复 Settings JSON 的语法与 Unicode 行为，并增加对应的 parser 测例；这些是可直接证实的错误接受/错误解码路径。
2. 统一 CMake target 图和源码 include 图。先解除 Runtime/Front -> Composition/Protocols 反向依赖，令每个模块对跨层接口有显式依赖，再让边界检查遍历实际 link 属性并检查 include 边。
3. 将 QUIC carrier admission 与 Hysteria2/TUIC protocol handler 分为 carrier-neutral 接口和协议自有 handler。不要把 QUIC Gateway 当作当前 SharedTransmission middleware 的一种普通实现。
4. 从 Application::Start 和 Session 编排里抽出具名 composition/service owner；只在形成真实编译单元或清晰所有权时拆 .cpp/.hpp，不使用 class/namespace 内部 include 片段拼接。
5. 决定 Throttle/Ban 是生产功能还是测试/示例代码。若是生产功能，接入实际 pipeline、定义 key/生命周期/线程模型并限制 state growth；若不是，标记实验用途并避免让它看起来像已工作的生产能力。
6. 对 QUIC、Mux、XHTTP 和 Recognition 做后续协议专项静态审查和真实异步回归。当前报告不宣称这些协议在所有合法组合、关闭/取消/半关闭情况下通过。
