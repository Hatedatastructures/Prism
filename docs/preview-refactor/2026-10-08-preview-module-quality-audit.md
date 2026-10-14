# Preview 模块与文件质量对比审查
<!-- pathcheck:historical=本文是 2026-10-08 的审计快照，行号按当日源码求值且当日未声明维护义务；已实测漂移（例：Preview/Transport/Encrypted.hpp 现 130 行、ProtocolAcceptors.hpp 现 371 行、所引 415 行已不存在） -->

审查日期：2026-10-08（延续 2026-10-07 的分析）。当前分支 codex/preview-refactor-20260928，HEAD 3c5b678f；对象为未提交工作树。正文和附录保留审查快照，随后发生的源码变更及当前状态见第 10 节。

本轮由单一审查者完成。生成本文和静态 JSON 审查产物，生产源码未修改。未构建、运行测试、启动 PrismPreview、执行互操作或性能实验。

## 1. 对比基准与证据范围

Diagnose 的进程级注册、Worker/Session 字段传播属于日志的正常作用范围。它的优点是 stable facade、类型化字段、值派生/入队前快照、backend owner 及最终关闭边界。其他模块按同样标准比较：谁维护不变量、谁拥有异步数据、谁最终关闭、调用者需要多少内部知识、失败是否准确报告。

本文没有把所有跨模块依赖判成耦合，也没有把所有可变状态判成错误。共享 I/O、QUIC 引擎、协议 root 状态及第三方 C ABI 均有必要职责。

全量自动扫描覆盖 641 个生产头文件；人工检查围绕真实启动/请求/关闭路径及高风险文件。目录矩阵的静态覆盖不等于每一行完成手工证明，也不意味着未列出缺陷的子模块已经通过动态验收。

| 项目 | 本轮证据 |
|---|---|
| 语法树 | 5094 个函数定义、460 个 lambda、5656 个函数声明器 |
| 解析 | 0 个未分类错误；133 个精确识别的空默认参数恢复 |
| 结构规则 | 头文件超过 600 行 0；函数体超过 120 行 11；lambda 跨度超过 10 行 67；参数超过 3 个 100 |
| 参数告警分类 | 40 个固定第三方回调签名位置；60 个其他位置，包含需按语义审查的 variadic/低层操作 |
| 静态结构门禁 | check_preview_contracts.ps1 exit 0：641 headers、1029 source consumers、0 production implementations |
| 风格检查 | exit 1，表示确有结构告警；不能报告为全门禁通过 |
| 构建/测试/请求/互操作/性能 | 本轮未执行 |

自动扫描文件：[最终静态快照](2026-10-08-preview-quality-static.json)；[首轮静态快照](2026-10-07-preview-quality-static.json)。JSON 包含每个生产头文件 SHA-256。

审查过程中发现其他工作更新了 Preview/Protocols/Anytls/Relay.hpp、Preview/Protocols/Anytls/State.hpp；没有回退这些修改。最终扫描重新记录了源码与 AST，因此函数定义数由 5093 更新为 5094。

## 2. 问题类型与优先级

确认缺陷：源码控制流/持有关系可直接确认。能力未接完整：接口已声明而生产执行缺失或范围不一致。设计耦合：依赖/权限/职责问题。合同风险或边界限制：需要针对触发条件做运行验证，不冒充已复现故障。

P1 是先处理的正确性、资源收口或命令范围问题；P2 是接口/能力/资源预算问题。这里的优先级是源码审查排序，不是已量测的线上故障严重度。共 50 项人工审查记录，类型不同，不能统称 50 个已经运行复现的 bug。

| 编号 | 优先级 | 类型 | 子模块 | 问题 | 主要文件 |
|---|---|---|---|---|---|
| Q01 | P1 | 确认缺陷 | Protocols/Trusttunnel | 客户端 Session 与 Transport 强引用环 | [Preview/Protocols/Trusttunnel/Http2Client.hpp:128](I:/code/Prism/Preview/Protocols/Trusttunnel/Http2Client.hpp:128) |
| Q02 | P1 | 确认缺陷 | Protocols/Trusttunnel | 写失败不完成其余排队请求 | [Preview/Protocols/Trusttunnel/Http2Wire.hpp:113](I:/code/Prism/Preview/Protocols/Trusttunnel/Http2Wire.hpp:113) |
| Q03 | P2 | 确认缺陷 | Protocols/Http2 | 普通未知帧被错误拒绝，测试固定错误预期 | [Preview/Protocols/Http2/Detail/FrameProcessor.hpp:114](I:/code/Prism/Preview/Protocols/Http2/Detail/FrameProcessor.hpp:114) |
| Q04 | P2 | 确认缺陷（潜在使用路径） | Protocols/Http2 | GOAWAY 错误码读取位置与位宽错误 | [Preview/Protocols/Http2/Detail/FrameProcessor.hpp:67](I:/code/Prism/Preview/Protocols/Http2/Detail/FrameProcessor.hpp:67) |
| Q05 | P1 | 确认资源边界缺口 | Protocols/Http2 | 超长帧声明先等收齐再拒绝 | [Preview/Protocols/Http2/Detail/ConnectionState.hpp:117](I:/code/Prism/Preview/Protocols/Http2/Detail/ConnectionState.hpp:117) |
| Q06 | P1 | 确认资源边界缺口 | Protocols/Http2 | CONTINUATION 头块累计没有总量上限 | [Preview/Protocols/Http2/Detail/FrameProcessor.hpp:229](I:/code/Prism/Preview/Protocols/Http2/Detail/FrameProcessor.hpp:229) |
| Q07 | P2 | 设计耦合 | Runtime/Middleware | 中间件获得过宽的可变状态权限 | [Preview/Runtime/Middleware/Context.hpp:43](I:/code/Prism/Preview/Runtime/Middleware/Context.hpp:43) |
| Q08 | P2 | 设计耦合/热路径成本 | Runtime/Session | 固定阶段使用每会话动态单项 Pipeline | [Preview/Runtime/Session/DataPlaneRelay.hpp:104](I:/code/Prism/Preview/Runtime/Session/DataPlaneRelay.hpp:104) |
| Q09 | P2 | 设计耦合 | Application/Composition | 不同协议装配入口尚未统一 | [Preview/Application/ProtocolAcceptors.hpp:415](I:/code/Prism/Preview/Application/ProtocolAcceptors.hpp:415) |
| Q10 | P2 | 设计耦合 | Application/ProtocolAcceptors | 从候选名字后缀恢复 mux 正式语义 | [Preview/Application/ProtocolAcceptors.hpp:43](I:/code/Prism/Preview/Application/ProtocolAcceptors.hpp:43) |
| Q11 | P2 | 公共合同风险 | Net/Dns | 查询与同步管理接口的执行器约束不统一 | [Preview/Net/Dns/Resolver.hpp:126](I:/code/Prism/Preview/Net/Dns/Resolver.hpp:126) |
| Q12 | P2 | 生命周期合同缺口 | Net/Dns | Resolver 缺少显式关闭与查询排空入口 | [Preview/Net/Dns/Resolver.hpp:104](I:/code/Prism/Preview/Net/Dns/Resolver.hpp:104) |
| Q13 | P2 | 能力未接完整 | Runtime/Statistics | 公开 Errors 指标没有生产更新入口 | [Preview/Runtime/Statistics.hpp:93](I:/code/Prism/Preview/Runtime/Statistics.hpp:93) |
| Q14 | P2 | 设计耦合 | Operations/HttpConnection | 拆出的模板 helper 直接依赖完整 server State 布局 | [Preview/Operations/HttpConnection.hpp:63](I:/code/Prism/Preview/Operations/HttpConnection.hpp:63) |
| Q15 | P2 | 确认规则缺口 | Foundation/Mux | 明确退役的 SessionBase 仍处于生产请求路径 | [Preview/Foundation/SessionBase.hpp:12](I:/code/Prism/Preview/Foundation/SessionBase.hpp:12) |
| Q16 | P2 | 确认分层缺口 | Foundation/Utility/Diagnose | 中立工具归属与源码依赖方向不一致 | [Preview/Foundation/Utility/Diagnose/FieldCodec.hpp:8](I:/code/Prism/Preview/Foundation/Utility/Diagnose/FieldCodec.hpp:8) |
| Q17 | P1 | 确认异常隔离缺口 | Runtime/Session | noexcept 日志辅助函数在 try 前分配 | [Preview/Runtime/Session/RecognitionLogging.hpp:94](I:/code/Prism/Preview/Runtime/Session/RecognitionLogging.hpp:94) |
| Q18 | P2 | 确认策略偏差 | Application/Shutdown | 日志最终 flush 失败改写应用退出结果 | [Preview/Application/Shutdown.hpp:217](I:/code/Prism/Preview/Application/Shutdown.hpp:217) |
| Q19 | P2 | 旧接口残留 | Foundation/Utility/Diagnose | 当前路径不产生的回执类别仍被公开保留 | [Preview/Foundation/Utility/Diagnose/SubmissionReceipt.hpp:15](I:/code/Prism/Preview/Foundation/Utility/Diagnose/SubmissionReceipt.hpp:15) |
| Q20 | P2 | 确认测试合同冲突 | tests/Preview/core/diagnose | 生命周期测试仍断言旧小写 JSON 身份键 | [tests/Preview/core/diagnose/ContextLifetimeTest.cpp:72](I:/code/Prism/tests/Preview/core/diagnose/ContextLifetimeTest.cpp:72) |
| Q21 | P2 | 资源保留风险 | Foundation/Utility/Diagnose | 长期文本反复 With 保留旧文本历史 | [Preview/Foundation/Utility/Diagnose/ContextState.hpp:116](I:/code/Prism/Preview/Foundation/Utility/Diagnose/ContextState.hpp:116) |
| Q22 | P2 | 执行模型限制 | Foundation/Utility/Diagnose | discard_new 不代表整条提交无锁等待 | [Preview/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp:149](I:/code/Prism/Preview/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp:149) |
| Q23 | P2 | 时间合同限制 | Foundation/Utility/Diagnose | 同步 drain Timeout 不约束阻塞入队，最终 join 无总时限 | [Preview/Foundation/Utility/Diagnose/Detail/SinkSet.hpp:207](I:/code/Prism/Preview/Foundation/Utility/Diagnose/Detail/SinkSet.hpp:207) |
| Q24 | P1 | 后续源码已改，待运行 | Protocols/Xhttp | StreamOne 强引用环（发现快照） | [Preview/Protocols/Xhttp/StreamClient.hpp:67](I:/code/Prism/Preview/Protocols/Xhttp/StreamClient.hpp:67) |
| Q25 | P1 | 确认缺陷 | Protocols/Xhttp | Split 客户端与服务端 State 自拥有 | [Preview/Protocols/Xhttp/SplitClient.hpp:94](I:/code/Prism/Preview/Protocols/Xhttp/SplitClient.hpp:94) |
| Q26 | P1 | 确认资源边界缺口 | Protocols/Xhttp/Split | 下载流建立前 PendingUpload 无累计字节上限 | [Preview/Protocols/Xhttp/SplitServer.hpp:86](I:/code/Prism/Preview/Protocols/Xhttp/SplitServer.hpp:86) |
| Q27 | P2 | 确认资源边界缺口 | Protocols/Gun | gRPC 单消息限制不约束待消费队列/累计响应 | [Preview/Protocols/Gun/GrpcStream.hpp:206](I:/code/Prism/Preview/Protocols/Gun/GrpcStream.hpp:206) |
| Q28 | P1 | 确认资源边界缺口 | Protocols/Http3 | 原生 nghttp3 头接收路径未应用独立 Decoder 的限制 | [Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:34](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:34) |
| Q29 | P2 | 异常边界风险 | Protocols/Http3 | 分配/用户操作异常未转换为 C 回调错误返回 | [Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:13](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:13) |
| Q30 | P2 | 错误合同信息丢失 | Protocols/Vless | UDP frame Reader 将 EOF/超时/I/O/长度错误合为 false | [Preview/Protocols/Vless/UdpTunnel.hpp:177](I:/code/Prism/Preview/Protocols/Vless/UdpTunnel.hpp:177) |
| Q31 | P2 | 确认功能限制 | Protocols/Common/DatagramRelay | UDP 转发绑定为一问一答的串行交换 | [Preview/Protocols/Common/DatagramRelay.hpp:125](I:/code/Prism/Preview/Protocols/Common/DatagramRelay.hpp:125) |
| Q32 | P2 | 来源隔离风险 | Protocols/Common/DatagramRelay | 私有 UDP socket 的回复未校验已发送目标 | [Preview/Protocols/Common/DatagramRelay.hpp:197](I:/code/Prism/Preview/Protocols/Common/DatagramRelay.hpp:197) |
| Q33 | P2 | 确认缺陷 | Protocols/Vless | UDP 隧道跨地址族目标切换失败 | [Preview/Protocols/Vless/UdpTunnel.hpp:209](I:/code/Prism/Preview/Protocols/Vless/UdpTunnel.hpp:209) |
| Q34 | P1 | 确认功能缺陷 | Statistics/Redaction | 引号值不处理转义，敏感值尾部可漏出 | [Preview/Statistics/Redaction.hpp:191](I:/code/Prism/Preview/Statistics/Redaction.hpp:191) |
| Q35 | P2 | 确认资源边界缺口 | Boundary/Quic | 连接表自身没有入站容量预算，CID lookup 可分配 | [Preview/Boundary/Quic/QuicConnectionRegistry.hpp:36](I:/code/Prism/Preview/Boundary/Quic/QuicConnectionRegistry.hpp:36) |
| Q36 | P2 | 确认资源边界缺口 | Protocols/Shadowsocks2022 | MaxPeers 不约束每包 Active 操作数 | [Preview/Protocols/Shadowsocks2022/Ss2022Gateway.hpp:125](I:/code/Prism/Preview/Protocols/Shadowsocks2022/Ss2022Gateway.hpp:125) |
| Q37 | P2 | 生命周期合同风险 | Protocols/Xhttp/StreamTransport | 关闭 active writer 后未提供显式排空确认 | [Preview/Protocols/Xhttp/StreamTransport.hpp:165](I:/code/Prism/Preview/Protocols/Xhttp/StreamTransport.hpp:165) |
| Q38 | P1 | 确认命令语义缺陷 | Application/Operations | Revoke 忽略 CloseSessions | [Preview/Operations/Routes/RouteDispatch.hpp:347](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:347) |
| Q39 | P1 | 确认命令语义缺陷 | Application/Operations | Cancel Stream/Task 被扩大为整个 Session | [Preview/Operations/Routes/RouteDispatch.hpp:361](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:361) |
| Q40 | P1 | 确认命令语义缺陷 | Application/Operations | Worker Drain 参数被忽略并触发全应用停机 | [Preview/Operations/Routes/RouteDispatch.hpp:317](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:317) |
| Q41 | P2 | 能力未接完整 | Application/Operations | 公开 Generation/Stream/Task 查询没有应用 handler | [Preview/Operations/Models.hpp:61](I:/code/Prism/Preview/Operations/Models.hpp:61) |
| Q42 | P2 | 能力未接完整 | Application/Operations | Reload route 存在但真实 handler 恒拒绝 | [Preview/Operations/Routes/RouteDispatch.hpp:331](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:331) |
| Q43 | P2 | 确认路由/实现不匹配 | Operations/Routes | Streams/Reset 产生的命令必然缺少 Session | [Preview/Operations/Routes/RouteDispatch.hpp:380](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:380) |
| Q44 | P2 | 公共身份合同缺口 | Operations/Models | Stream 查询/重置缺少父 session 身份 | [Preview/Operations/Models.hpp:88](I:/code/Prism/Preview/Operations/Models.hpp:88) |
| Q45 | P2 | 状态结果合同缺口 | Application/Operations | Drain 返回 Completed 发生在真实异步停机之前 | [Preview/Application/OperationsStartup.hpp:319](I:/code/Prism/Preview/Application/OperationsStartup.hpp:319) |
| Q46 | P2 | 能力限制 | Statistics/EventRing | EventRing 实际是填满后丢弃的有界保存容器 | [Preview/Statistics/EventRing.hpp:74](I:/code/Prism/Preview/Statistics/EventRing.hpp:74) |
| Q47 | P1 | 确认功能限制 | Protocols/Socks5/UdpAssoc | 生产 UDP association 固定绑定 loopback | [Preview/Protocols/Socks5/UdpAssoc.hpp:109](I:/code/Prism/Preview/Protocols/Socks5/UdpAssoc.hpp:109) |
| Q48 | P2 | 确认功能限制 | Protocols/Socks5/UdpAssoc | UDP egress 固定 IPv4，不能转发 IPv6 目标 | [Preview/Protocols/Socks5/UdpAssoc.hpp:122](I:/code/Prism/Preview/Protocols/Socks5/UdpAssoc.hpp:122) |
| Q49 | P1 | 确认协议合同缺口 | Protocols/Socks5/UdpAssoc | 没有校验 UDP 包是否来自该 TCP association 的客户端 | [Preview/Protocols/Socks5/UdpAssoc.hpp:303](I:/code/Prism/Preview/Protocols/Socks5/UdpAssoc.hpp:303) |
| Q50 | P1 | 确认异常隔离缺口 | Protocols/Xhttp | detached driver 异常后跳过通知/关闭并静默退出 | [Preview/Protocols/Xhttp/StreamClient.hpp:167](I:/code/Prism/Preview/Protocols/Xhttp/StreamClient.hpp:167) |

## 3. 逐项证据与触发条件

### Q01 客户端 Session 与 Transport 强引用环

**P1 / 确认缺陷 / Protocols/Trusttunnel**

Transport 的写/FIN 回调强持有 Session；Session 的头、数据、关闭回调强持有 Transport。客户端退出与 Close 未解除这些回调，引用计数无法自行回收。服务端 FinishDriver 已清理回调，客户端未采用相同收口。影响是客户端路径资源滞留；未做运行时内存测量。

文件：[Preview/Protocols/Trusttunnel/Http2Client.hpp:128](I:/code/Prism/Preview/Protocols/Trusttunnel/Http2Client.hpp:128)；[Preview/Protocols/Trusttunnel/Http2Stream.hpp:155](I:/code/Prism/Preview/Protocols/Trusttunnel/Http2Stream.hpp:155)。

### Q02 写失败不完成其余排队请求

**P1 / 确认缺陷 / Protocols/Trusttunnel**

循环只通知当前请求，随后 Closed=true 并 break；其余请求仍等待独立 completion。外部 Close 可以补救，但错误分支自身没有兑现唤醒全部等待者的合同。并发写中前一请求失败时后续写/FIN 可能挂起。

文件：[Preview/Protocols/Trusttunnel/Http2Wire.hpp:113](I:/code/Prism/Preview/Protocols/Trusttunnel/Http2Wire.hpp:113)；[Preview/Protocols/Trusttunnel/Http2Stream.hpp:378](I:/code/Prism/Preview/Protocols/Trusttunnel/Http2Stream.hpp:378)。

### Q03 普通未知帧被错误拒绝，测试固定错误预期

**P2 / 确认缺陷 / Protocols/Http2**

在没有未完成 HEADERS 的普通场景，未知类型进入 default 并报 ProtocolError，测试 UnknownFrameTypeRejected 也要求拒绝。RFC 9113 5.5 要求忽略未知/不支持帧；头块中的扩展帧是另一条例外规则。

文件：[Preview/Protocols/Http2/Detail/FrameProcessor.hpp:114](I:/code/Prism/Preview/Protocols/Http2/Detail/FrameProcessor.hpp:114)；[tests/Preview/protocols/http2/H2CodecTest.cpp:785](I:/code/Prism/tests/Preview/protocols/http2/H2CodecTest.cpp:785)。

### Q04 GOAWAY 错误码读取位置与位宽错误

**P2 / 确认缺陷（潜在使用路径） / Protocols/Http2**

OnGoaway 存在时从 Payload.last<4>() 用 DecodeU31 读 ErrorCode。错误码实际位于载荷第 4-7 字节且为 32 位；附加 debug data 会被误读为错误码。未发现当前 Preview 的 OnGoaway 赋值，故不能把影响扩大成所有 carrier 已触发。

文件：[Preview/Protocols/Http2/Detail/FrameProcessor.hpp:67](I:/code/Prism/Preview/Protocols/Http2/Detail/FrameProcessor.hpp:67)。

### Q05 超长帧声明先等收齐再拒绝

**P1 / 确认资源边界缺口 / Protocols/Http2**

完整帧检查在 LocalMaxFrameSize 验证之前，超过本地上限的长度声明仍使 RxBuffer 继续累计。应区分已可判定非法的头与尚未收齐的合法帧；运行暴露受上层读入大小与超时影响。

文件：[Preview/Protocols/Http2/Detail/ConnectionState.hpp:117](I:/code/Prism/Preview/Protocols/Http2/Detail/ConnectionState.hpp:117)。

### Q06 CONTINUATION 头块累计没有总量上限

**P1 / 确认资源边界缺口 / Protocols/Http2**

同一 stream 的 continuation 不断 append 到 PendingHeaders.Block，只在 END_HEADERS 后解码；单帧限制不约束总头块。恶意或异常 peer 可以持续增加内存，实际窗口受上层 timeout 影响。

文件：[Preview/Protocols/Http2/Detail/FrameProcessor.hpp:229](I:/code/Prism/Preview/Protocols/Http2/Detail/FrameProcessor.hpp:229)。

### Q07 中间件获得过宽的可变状态权限

**P2 / 设计耦合 / Runtime/Middleware**

每个 middleware 同时可修改目标、认证事实、账户租约、根传输、出站、PostDial 和服务。Handle 又单独接受 ctx.Inbound 的别名，职责所需权限没有由接口收窄。已唯一化 DataPlane 是改进，但没有消除阶段之间的写权限耦合。

文件：[Preview/Runtime/Middleware/Context.hpp:43](I:/code/Prism/Preview/Runtime/Middleware/Context.hpp:43)；[Preview/Runtime/Middleware/Pipeline.hpp:57](I:/code/Prism/Preview/Runtime/Middleware/Pipeline.hpp:57)。

### Q08 固定阶段使用每会话动态单项 Pipeline

**P2 / 设计耦合/热路径成本 / Runtime/Session**

生产 stream 路径创建只含一个 Pad 或 Dial 的 Pipeline，分配 shared middleware/vector，再按固定顺序处理 decorator、PostDial、ActiveTransports 和 Relay。泛化机制与生产用途之间存在成本与维护权衡，未做性能实测。

文件：[Preview/Runtime/Session/DataPlaneRelay.hpp:104](I:/code/Prism/Preview/Runtime/Session/DataPlaneRelay.hpp:104)。

### Q09 不同协议装配入口尚未统一

**P2 / 设计耦合 / Application/Composition**

S5/SS2022 等走 typed provider；VLESS/Trojan/VMess/AnyTLS/TrustTunnel 仍由 Application 的协议分支构造特定配置和 candidate。应用需了解 wire/mux/凭据形状，接口变更横跨 Application 与 Composition。冷路径具体类型依赖本身合理，问题是责任位置和装配模式不一致。

文件：[Preview/Application/ProtocolAcceptors.hpp:415](I:/code/Prism/Preview/Application/ProtocolAcceptors.hpp:415)；[Preview/Application/ProtocolProfile.hpp:84](I:/code/Prism/Preview/Application/ProtocolProfile.hpp:84)；[Preview/Composition/Provider/ProviderCatalog.hpp:298](I:/code/Prism/Preview/Composition/Provider/ProviderCatalog.hpp:298)。

### Q10 从候选名字后缀恢复 mux 正式语义

**P2 / 设计耦合 / Application/ProtocolAcceptors**

CandidateMuxMode 使用 Candidate.Name.ends_with("+" + BindingId) 匹配模式。命名规则承担正式 binding 关系，名字生成和解析需要同步维护，未使用已有 typed candidate 身份直接表达该关系。

文件：[Preview/Application/ProtocolAcceptors.hpp:43](I:/code/Prism/Preview/Application/ProtocolAcceptors.hpp:43)。

### Q11 查询与同步管理接口的执行器约束不统一

**P2 / 公共合同风险 / Net/Dns**

AsyncResolve 转入 Serial strand；HitCount/Size/Clear 直接触碰非原子 Hits 和非线程安全 Cache。公共接口未明确约束或提供同样调度，跨线程使用会产生风险。未确认当前真实调用链已发生竞争。

文件：[Preview/Net/Dns/Resolver.hpp:126](I:/code/Prism/Preview/Net/Dns/Resolver.hpp:126)；[Preview/Net/Dns/Resolver.hpp:248](I:/code/Prism/Preview/Net/Dns/Resolver.hpp:248)。

### Q12 Resolver 缺少显式关闭与查询排空入口

**P2 / 生命周期合同缺口 / Net/Dns**

构造启动 detached maintenance，析构取消 timer；查询协程仍使用 this/成员，公共 API 没有 Close/Drain 表达最终收口，调用者必须额外维持对象和 executor 生命周期。不能据此直接称当前 owner 路径 UAF。

文件：[Preview/Net/Dns/Resolver.hpp:104](I:/code/Prism/Preview/Net/Dns/Resolver.hpp:104)。

### Q13 公开 Errors 指标没有生产更新入口

**P2 / 能力未接完整 / Runtime/Statistics**

Value/StreamValue 读 Metric::Errors，但 Accumulate 只准备/更新 UpBytes、DownBytes、Events，TrafficEvent 无错误结果。Errors=0 不能被解释为真实无错误。

文件：[Preview/Runtime/Statistics.hpp:93](I:/code/Prism/Preview/Runtime/Statistics.hpp:93)；[Preview/Runtime/Statistics.hpp:157](I:/code/Prism/Preview/Runtime/Statistics.hpp:157)；[Preview/Foundation/Utility/TrafficSink.hpp:21](I:/code/Prism/Preview/Foundation/Utility/TrafficSink.hpp:21)。

### Q14 拆出的模板 helper 直接依赖完整 server State 布局

**P2 / 设计耦合 / Operations/HttpConnection**

duck type helper 直接访问 Acceptor、ActiveConnections、timer、计数和状态位；文件已拆但状态修改合同仍靠隐含字段约定。不是作用域 include/text 拼接；Router 的 typed/strand 边界相比更清楚。

文件：[Preview/Operations/HttpConnection.hpp:63](I:/code/Prism/Preview/Operations/HttpConnection.hpp:63)；[Preview/Operations/HttpServer.hpp:146](I:/code/Prism/Preview/Operations/HttpServer.hpp:146)。

### Q15 明确退役的 SessionBase 仍处于生产请求路径

**P2 / 确认规则缺口 / Foundation/Mux**

SessionBase 自称 DEPRECATED，StreamHandle 仍继承它，再由 StreamTransmission 转成唯一 Transmission。生产 Client/Server/RootSession 仍使用适配器，旧接口没有退役；同时 Foundation/SessionBase 引用上层 Transport/Stream。

文件：[Preview/Foundation/SessionBase.hpp:12](I:/code/Prism/Preview/Foundation/SessionBase.hpp:12)；[Preview/Protocols/Mux/StreamState.hpp:109](I:/code/Prism/Preview/Protocols/Mux/StreamState.hpp:109)；[Preview/Protocols/Mux/Stream.hpp:42](I:/code/Prism/Preview/Protocols/Mux/Stream.hpp:42)；[Preview/Protocols/Mux/RootSession.hpp:59](I:/code/Prism/Preview/Protocols/Mux/RootSession.hpp:59)。

### Q16 中立工具归属与源码依赖方向不一致

**P2 / 确认分层缺口 / Foundation/Utility/Diagnose**

Foundation 中 Diagnose 依赖 Statistics 的 TraceSelection/Redaction，而 target 图 Statistics 依赖 Foundation。是局部工具归属与门禁缺口，不据此否定日志 facade/owner 整体封装。

文件：[Preview/Foundation/Utility/Diagnose/FieldCodec.hpp:8](I:/code/Prism/Preview/Foundation/Utility/Diagnose/FieldCodec.hpp:8)；[Preview/Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp:10](I:/code/Prism/Preview/Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp:10)。

### Q17 noexcept 日志辅助函数在 try 前分配

**P1 / 确认异常隔离缺口 / Runtime/Session**

WriteRecognition noexcept 在 try 前调用 PascalCaseToken/构造字符串，分配异常会 terminate；部分 admission 日志准备也在保护区外。触发条件是诊断准备异常，未执行故障注入。

文件：[Preview/Runtime/Session/RecognitionLogging.hpp:94](I:/code/Prism/Preview/Runtime/Session/RecognitionLogging.hpp:94)；[Preview/Runtime/Session/RecognitionAdmission.hpp:76](I:/code/Prism/Preview/Runtime/Session/RecognitionAdmission.hpp:76)。

### Q18 日志最终 flush 失败改写应用退出结果

**P2 / 确认策略偏差 / Application/Shutdown**

FinalizeShutdown Failed 导致 MarkShutdownFailed 设置 ExitCode=1/Phase=Failed。日志初始化可以阻止启动，但运行后观察失败仍扩展到应用最终结果；不会回滚已完成网络请求。

文件：[Preview/Application/Shutdown.hpp:217](I:/code/Prism/Preview/Application/Shutdown.hpp:217)；[Preview/Foundation/Utility/Diagnose/Detail/BackendLifecycle.hpp:189](I:/code/Prism/Preview/Foundation/Utility/Diagnose/Detail/BackendLifecycle.hpp:189)。

### Q19 当前路径不产生的回执类别仍被公开保留

**P2 / 旧接口残留 / Foundation/Utility/Diagnose**

FallbackWritten 明确保留兼容旧回执并被 Accepted 接受；ContextCapacityExceeded 实际由 ContextError 返回。应同步消费者收敛结果合同；.legacy 文件归档是数据保存，不是应删除的接口。

文件：[Preview/Foundation/Utility/Diagnose/SubmissionReceipt.hpp:15](I:/code/Prism/Preview/Foundation/Utility/Diagnose/SubmissionReceipt.hpp:15)。

### Q20 生命周期测试仍断言旧小写 JSON 身份键

**P2 / 确认测试合同冲突 / tests/Preview/core/diagnose**

测试找 worker/session，而当前 renderer 输出 Worker/Session。静态可确认冲突，本次不报告实测失败数量。

文件：[tests/Preview/core/diagnose/ContextLifetimeTest.cpp:72](I:/code/Prism/tests/Preview/core/diagnose/ContextLifetimeTest.cpp:72)；[Preview/Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp:126](I:/code/Prism/Preview/Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp:126)。

### Q21 长期文本反复 With 保留旧文本历史

**P2 / 资源保留风险 / Foundation/Utility/Diagnose**

CloneAuxiliary 复制 OwnedText；替换字段时追加新 string，但不移除已无绑定引用的旧 string。反复更新同字段时 FieldCount 稳定而文本保存量可增长；未量测实际生产增长。

文件：[Preview/Foundation/Utility/Diagnose/ContextState.hpp:116](I:/code/Prism/Preview/Foundation/Utility/Diagnose/ContextState.hpp:116)；[Preview/Foundation/Utility/Diagnose/ContextState.hpp:254](I:/code/Prism/Preview/Foundation/Utility/Diagnose/ContextState.hpp:254)。

### Q22 discard_new 不代表整条提交无锁等待

**P2 / 执行模型限制 / Foundation/Utility/Diagnose**

生产者做格式化/捕获/脱敏/渲染；spdlog enqueue_if_have_room 和 queue_size 取 mutex，门闩拒绝分支也读 queue_size。应准确表述不等队列空位，不误称全路径 wait-free。日志的进程级作用范围不算此问题。

文件：[Preview/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp:149](I:/code/Prism/Preview/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp:149)；[build/_deps/spdlog-src/include/spdlog/details/mpmc_blocking_q.h:111](I:/code/Prism/build/_deps/spdlog-src/include/spdlog/details/mpmc_blocking_q.h:111)。

### Q23 同步 drain Timeout 不约束阻塞入队，最终 join 无总时限

**P2 / 时间合同限制 / Foundation/Utility/Diagnose**

barrier logger 使用 block policy，wait_until 发生在入队之后；FinalizeShutdown 还等待调用、queue worker 和 sink，未提供总时限。属明确控制路径边界，不能描述成协程操作或全程硬超时。

文件：[Preview/Foundation/Utility/Diagnose/Detail/SinkSet.hpp:207](I:/code/Prism/Preview/Foundation/Utility/Diagnose/Detail/SinkSet.hpp:207)；[Preview/Application/DiagnoseRuntime.hpp:162](I:/code/Prism/Preview/Application/DiagnoseRuntime.hpp:162)。

### Q24 StreamOne 强引用环：发现快照与后续解除

**P1 / 发现时确认；后续源码已改，待运行验证 / Protocols/Xhttp**

客户端 Session 回调持 Transport，Transport 写/FIN 回调持 Session；服务端 OnHeaders 更直接强捕获所属 Session。Close/driver 退出未清除这些闭环。是该子模块请求资源释放的实际所有权缺口。

文件：[Preview/Protocols/Xhttp/StreamClient.hpp:67](I:/code/Prism/Preview/Protocols/Xhttp/StreamClient.hpp:67)；[Preview/Protocols/Xhttp/StreamServer.hpp:103](I:/code/Prism/Preview/Protocols/Xhttp/StreamServer.hpp:103)；[Preview/Protocols/Xhttp/StreamTransport.hpp:165](I:/code/Prism/Preview/Protocols/Xhttp/StreamTransport.hpp:165)。

后续源码复查：StreamClient/StreamServer 已改成 WeakState 回调和具名 driver，当前源码已解除本项已识别的强引用环；尚未执行 weak-owner 释放与真实请求验证。本节旧行号/旧 hash 保留为发现快照，当前入口分别为 StreamClient.hpp:176、StreamServer.hpp:187。

### Q25 Split 客户端与服务端 State 自拥有

**P1 / 确认缺陷 / Protocols/Xhttp**

State 持 Session/Transport，其事件和写/关闭回调均强捕获 State；形成 State→Session→State 和 State→Transport→State。常规 Close 只关 Wire/Encrypted，未解除这些引用。

文件：[Preview/Protocols/Xhttp/SplitClient.hpp:94](I:/code/Prism/Preview/Protocols/Xhttp/SplitClient.hpp:94)；[Preview/Protocols/Xhttp/SplitClient.hpp:129](I:/code/Prism/Preview/Protocols/Xhttp/SplitClient.hpp:129)；[Preview/Protocols/Xhttp/SplitServer.hpp:127](I:/code/Prism/Preview/Protocols/Xhttp/SplitServer.hpp:127)；[Preview/Protocols/Xhttp/SplitServer.hpp:341](I:/code/Prism/Preview/Protocols/Xhttp/SplitServer.hpp:341)。

### Q26 下载流建立前 PendingUpload 无累计字节上限

**P1 / 确认资源边界缺口 / Protocols/Xhttp/Split**

Transport 尚未绑定时持续 emplace DATA 到 PendingUpload，绑定后才清空。当前未见 PendingUpload 的字节/条数预算，peer 延迟创建下载流可累积上传缓冲。实际可持续时间受外层关闭策略影响。

文件：[Preview/Protocols/Xhttp/SplitServer.hpp:86](I:/code/Prism/Preview/Protocols/Xhttp/SplitServer.hpp:86)；[Preview/Protocols/Xhttp/SplitServer.hpp:143](I:/code/Prism/Preview/Protocols/Xhttp/SplitServer.hpp:143)。

### Q27 gRPC 单消息限制不约束待消费队列/累计响应

**P2 / 确认资源边界缺口 / Protocols/Gun**

MessageDecoder 的 MaxMessageBytes 只约束单消息；server RxQueue 和 client Payload 的重复 append 没有总预算。慢读者或多消息响应可持续增加内存，需要独立队列/总响应预算。

文件：[Preview/Protocols/Gun/GrpcStream.hpp:206](I:/code/Prism/Preview/Protocols/Gun/GrpcStream.hpp:206)；[Preview/Protocols/Gun/GrpcStream.hpp:317](I:/code/Prism/Preview/Protocols/Gun/GrpcStream.hpp:317)；[Preview/Protocols/Gun/GrpcSession.hpp:210](I:/code/Prism/Preview/Protocols/Gun/GrpcSession.hpp:210)。

### Q28 原生 nghttp3 头接收路径未应用独立 Decoder 的限制

**P1 / 确认资源边界缺口 / Protocols/Http3**

独立 Decoder 限制 64 KiB 头块/128 字段/16 KiB 字段；原生 server/client callback 直接 assign/push_back，nghttp3 settings 使用 default，未设置相同项目级预算。不能用独立 Decoder 的边界测试替代原生回调路径验证。

文件：[Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:34](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:34)；[Preview/Protocols/Http3/Detail/SessionLifecycle.hpp:29](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionLifecycle.hpp:29)；[Preview/Protocols/Http3/NativeClient.hpp:465](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:465)；[Preview/Protocols/Http3/Decoder.hpp:27](I:/code/Prism/Preview/Protocols/Http3/Decoder.hpp:27)。

### Q29 分配/用户操作异常未转换为 C 回调错误返回

**P2 / 异常边界风险 / Protocols/Http3**

回调含 make_shared、map emplace、string assign、vector push_back，但未在边界 catch 并返回 NGHTTP3_ERR_CALLBACK_FAILURE。异常可以离开库所期望的 int-return 回调协议，调用方无法仅凭返回码判断失败；未注入异常。C ABI 参数数量本身不是此风险。

文件：[Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:13](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:13)；[Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:34](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:34)；[Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:91](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:91)；[Preview/Protocols/Http3/NativeClient.hpp:465](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:465)。

### Q30 UDP frame Reader 将 EOF/超时/I/O/长度错误合为 false

**P2 / 错误合同信息丢失 / Protocols/Vless**

ReadFrame/ReadExactWithTimeout 返回 bool，RunCore false 后统一 break 并 Success。无法区分正常 EOF、空闲过期、I/O 错误和无效长度；是否把 idle expiry 视为正常可按策略决定，但错误来源已丢失。

文件：[Preview/Protocols/Vless/UdpTunnel.hpp:177](I:/code/Prism/Preview/Protocols/Vless/UdpTunnel.hpp:177)；[Preview/Protocols/Vless/UdpTunnel.hpp:292](I:/code/Prism/Preview/Protocols/Vless/UdpTunnel.hpp:292)。

### Q31 UDP 转发绑定为一问一答的串行交换

**P2 / 确认功能限制 / Protocols/Common/DatagramRelay**

每个上传后立即等一个回包，再接收下一上传；无响应目标阻塞后续包，连续多个回包没有独立下行泵，不能由单次 echo 证明一般 UDP 转发语义。Common 覆盖 Trojan/VMess，VLESS 与 Hysteria2 也需同输入并行/无响应/多回复验证。 SOCKS5 UdpAssoc 也采用接收一包后等待一次上游应答的相同串行模型。

文件：[Preview/Protocols/Common/DatagramRelay.hpp:125](I:/code/Prism/Preview/Protocols/Common/DatagramRelay.hpp:125)；[Preview/Protocols/Common/DatagramRelay.hpp:181](I:/code/Prism/Preview/Protocols/Common/DatagramRelay.hpp:181)；[Preview/Protocols/Vless/UdpTunnel.hpp:183](I:/code/Prism/Preview/Protocols/Vless/UdpTunnel.hpp:183)；[Preview/Protocols/Hysteria2/DatagramSession.hpp:129](I:/code/Prism/Preview/Protocols/Hysteria2/DatagramSession.hpp:129)；[Preview/Protocols/Socks5/UdpAssoc.hpp:303](I:/code/Prism/Preview/Protocols/Socks5/UdpAssoc.hpp:303)。

### Q32 私有 UDP socket 的回复未校验已发送目标

**P2 / 来源隔离风险 / Protocols/Common/DatagramRelay**

async_receive_from 返回任意 Source 就被封装回 carrier，没有匹配当前 Target 或已授权目标集合。需要明确第三方来源可否注入/跨目标延迟包如何关联；未进行网络注入测试。

文件：[Preview/Protocols/Common/DatagramRelay.hpp:197](I:/code/Prism/Preview/Protocols/Common/DatagramRelay.hpp:197)；[Preview/Protocols/Vless/UdpTunnel.hpp:222](I:/code/Prism/Preview/Protocols/Vless/UdpTunnel.hpp:222)；[Preview/Protocols/Socks5/UdpAssoc.hpp:349](I:/code/Prism/Preview/Protocols/Socks5/UdpAssoc.hpp:349)。

### Q33 UDP 隧道跨地址族目标切换失败

**P2 / 确认缺陷 / Protocols/Vless**

Egress 只在未打开时按目标 family open；IPv4 socket 已打开后遇到 IPv6 目标仍直接 send_to，不切换 socket。Common DatagramRelay 已做 family 重开，两条协议路径行为不一致。

文件：[Preview/Protocols/Vless/UdpTunnel.hpp:209](I:/code/Prism/Preview/Protocols/Vless/UdpTunnel.hpp:209)。

### Q34 引号值不处理转义，敏感值尾部可漏出

**P1 / 确认功能缺陷 / Statistics/Redaction**

扫描敏感引号值时遇任意同类引号即结束，没有跳过反斜线转义。JSON 风格 token 值含 escaped quote 时，后半段重新按普通文本输出。Diagnose、EventRing 和 Operations 共享该工具，风险跨越多个观察入口。

文件：[Preview/Statistics/Redaction.hpp:191](I:/code/Prism/Preview/Statistics/Redaction.hpp:191)。

### Q35 连接表自身没有入站容量预算，CID lookup 可分配

**P2 / 确认资源边界缺口 / Boundary/Quic**

Options 无 MaxEntries/未认证 admission budget，new peer 可以走 Factory→emplace；MakeKey 每个包构造 string，20-byte CID 可超过常见 SSO。需要核对 factory/外围预算及热路径分配；不把模块本地缺口直接等同于已完成 DoS 实证。

文件：[Preview/Boundary/Quic/QuicConnectionRegistry.hpp:36](I:/code/Prism/Preview/Boundary/Quic/QuicConnectionRegistry.hpp:36)；[Preview/Boundary/Quic/QuicConnectionRegistry.hpp:53](I:/code/Prism/Preview/Boundary/Quic/QuicConnectionRegistry.hpp:53)；[Preview/Boundary/Quic/QuicConnectionRegistry.hpp:129](I:/code/Prism/Preview/Boundary/Quic/QuicConnectionRegistry.hpp:129)。

### Q36 MaxPeers 不约束每包 Active 操作数

**P2 / 确认资源边界缺口 / Protocols/Shadowsocks2022**

Peer 数有 1024 默认预算，但每个已认证 packet 可生成 Active operation 并做异步交换；当前未见独立的 global/per-peer pending operation 预算。慢目标下同一个合法 peer 的在途操作和缓冲仍可增长。

文件：[Preview/Protocols/Shadowsocks2022/Ss2022Gateway.hpp:125](I:/code/Prism/Preview/Protocols/Shadowsocks2022/Ss2022Gateway.hpp:125)；[Preview/Protocols/Shadowsocks2022/Ss2022Gateway.hpp:147](I:/code/Prism/Preview/Protocols/Shadowsocks2022/Ss2022Gateway.hpp:147)；[Preview/Protocols/Shadowsocks2022/GatewayState.hpp:97](I:/code/Prism/Preview/Protocols/Shadowsocks2022/GatewayState.hpp:97)。

### Q37 关闭 active writer 后未提供显式排空确认

**P2 / 生命周期合同风险 / Protocols/Xhttp/StreamTransport**

Close 处理排队请求但 active request 已从队列弹出并仍 await 下层写入；这些 adapter 只提供 Close，没有独立 tracked writer/drain 完成合同。活动请求的实际终止还依赖下层被其他 owner 取消。属于需要验证的收口风险，不在本轮宣称已发生 UAF。

文件：[Preview/Protocols/Xhttp/StreamTransport.hpp:165](I:/code/Prism/Preview/Protocols/Xhttp/StreamTransport.hpp:165)；[Preview/Protocols/Xhttp/StreamTransport.hpp:300](I:/code/Prism/Preview/Protocols/Xhttp/StreamTransport.hpp:300)；[Preview/Protocols/Trusttunnel/Http2Stream.hpp:155](I:/code/Prism/Preview/Protocols/Trusttunnel/Http2Stream.hpp:155)。

### Q38 Revoke 忽略 CloseSessions

**P1 / 确认命令语义缺陷 / Application/Operations**

HTTP route 接受 close_sessions（默认 true），执行只做 Accounts.Revoke，未按该参数取消已注册会话。账户模块 Revoke 只置 revoked 标志，无 I/O 对象，不能自动兑现关闭会话。返回 Completed 仍可能保留旧会话。

文件：[Preview/Operations/Routes/RouteDispatch.hpp:347](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:347)；[Preview/Application/OperationsStartup.hpp:320](I:/code/Prism/Preview/Application/OperationsStartup.hpp:320)；[Preview/Account/Runtime.hpp:251](I:/code/Prism/Preview/Account/Runtime.hpp:251)。

### Q39 Cancel Stream/Task 被扩大为整个 Session

**P1 / 确认命令语义缺陷 / Application/Operations**

route 接受 stream/task 并进入 typed Command，执行始终 Registry.Cancel(SessionId)，忽略 child 范围。仅想取消某 stream/task 的请求会取消整根 session，并在结果里回显被忽略的 ID。

文件：[Preview/Operations/Routes/RouteDispatch.hpp:361](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:361)；[Preview/Application/OperationsStartup.hpp:329](I:/code/Prism/Preview/Application/OperationsStartup.hpp:329)。

### Q40 Worker Drain 参数被忽略并触发全应用停机

**P1 / 确认命令语义缺陷 / Application/Operations**

route 接受 worker、stop_accepting、force，执行仅回显 Worker，然后 StopRequested=true / ScheduleShutdown。定向 worker drain 被扩大为进程停机；StopAccepting/Force 不参与执行。

文件：[Preview/Operations/Routes/RouteDispatch.hpp:317](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:317)；[Preview/Application/OperationsStartup.hpp:341](I:/code/Prism/Preview/Application/OperationsStartup.hpp:341)。

### Q41 公开 Generation/Stream/Task 查询没有应用 handler

**P2 / 能力未接完整 / Application/Operations**

模型和 Router 支持查询形状，但应用 visitor 仅处理 Health/Worker/Account/Session/Event，其余返回 InvalidOperationsQuery。不能把 typed route/parser 测试当作这些生产查询已完成。

文件：[Preview/Operations/Models.hpp:61](I:/code/Prism/Preview/Operations/Models.hpp:61)；[Preview/Application/OperationsStartup.hpp:274](I:/code/Prism/Preview/Application/OperationsStartup.hpp:274)。

### Q42 Reload route 存在但真实 handler 恒拒绝

**P2 / 能力未接完整 / Application/Operations**

current_generation/target_generation/validate_only 解析进入模型，执行无 Reload 分支，统一返回 reload_unavailable。这是明确未支持的能力，不是内存错误；应在对外能力说明中如实反映。

文件：[Preview/Operations/Routes/RouteDispatch.hpp:331](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:331)；[Preview/Application/OperationsStartup.hpp:349](I:/code/Prism/Preview/Application/OperationsStartup.hpp:349)。

### Q43 Streams/Reset 产生的命令必然缺少 Session

**P2 / 确认路由/实现不匹配 / Operations/Routes**

Streams/{id}/Reset 只填 StreamId，真实 Cancel handler 要求非零 SessionId，故这条生产 route 会进入 rejected。Task-only 形状也没有执行路径。

文件：[Preview/Operations/Routes/RouteDispatch.hpp:380](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:380)；[Preview/Application/OperationsStartup.hpp:334](I:/code/Prism/Preview/Application/OperationsStartup.hpp:334)。

### Q44 Stream 查询/重置缺少父 session 身份

**P2 / 公共身份合同缺口 / Operations/Models**

wire StreamId 只在 root 内唯一，Statistics.CounterKey 已有 ParentSession；StreamQuery 和 reset URL 却只传 StreamId，未来接线仍无法唯一定位不同 root 的同号流。当前查询/reset 尚未实现，属于先解决的模型缺口。

文件：[Preview/Operations/Models.hpp:88](I:/code/Prism/Preview/Operations/Models.hpp:88)；[Preview/Operations/Routes/RouteDispatch.hpp:380](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:380)；[Preview/Statistics/Types.hpp:44](I:/code/Prism/Preview/Statistics/Types.hpp:44)。

### Q45 Drain 返回 Completed 发生在真实异步停机之前

**P2 / 状态结果合同缺口 / Application/Operations**

执行分支初始创建 Completed，只 ScheduleShutdown 即返回。Router 不为 Completed 登记 pending OperationId；客户端不能通过该结果确认真实 drain 已完成，Accepted/Completed 的业务含义不一致。

文件：[Preview/Application/OperationsStartup.hpp:319](I:/code/Prism/Preview/Application/OperationsStartup.hpp:319)；[Preview/Application/OperationsStartup.hpp:341](I:/code/Prism/Preview/Application/OperationsStartup.hpp:341)；[Preview/Operations/Router.hpp:379](I:/code/Prism/Preview/Operations/Router.hpp:379)。

### Q46 EventRing 实际是填满后丢弃的有界保存容器

**P2 / 能力限制 / Statistics/EventRing**

Append 满后丢弃，Page/Read 不回收元素，只有 Clear 清空；没有覆盖旧条目或消费游标收缩。不能把它描述成持续保存近期事件的循环 ring。当前应用只追加少量生命周期事件，实际满后观察缺失未压测。

文件：[Preview/Statistics/EventRing.hpp:74](I:/code/Prism/Preview/Statistics/EventRing.hpp:74)；[Preview/Statistics/EventRing.hpp:162](I:/code/Prism/Preview/Statistics/EventRing.hpp:162)。

### Q47 生产 UDP association 固定绑定 loopback

**P1 / 确认功能限制 / Protocols/Socks5/UdpAssoc**

Ingress 固定 udp::v4 并 bind 127.0.0.1:0，BND 应答取该 local endpoint；没有外部 bind 地址选项。远程 SOCKS5 客户端不能使用这个 loopback UDP 入口，单机 focused echo 不覆盖该限制。

文件：[Preview/Protocols/Socks5/UdpAssoc.hpp:109](I:/code/Prism/Preview/Protocols/Socks5/UdpAssoc.hpp:109)；[Preview/Protocols/Socks5/Binding.hpp:129](I:/code/Prism/Preview/Protocols/Socks5/Binding.hpp:129)。

### Q48 UDP egress 固定 IPv4，不能转发 IPv6 目标

**P2 / 确认功能限制 / Protocols/Socks5/UdpAssoc**

Egress 固定 udp::v4，解析到 IPv6 endpoint 后直接 send_to，没有按目标族更换 socket。与 Common DatagramRelay 的 family 重开行为不一致。

文件：[Preview/Protocols/Socks5/UdpAssoc.hpp:122](I:/code/Prism/Preview/Protocols/Socks5/UdpAssoc.hpp:122)；[Preview/Protocols/Socks5/UdpAssoc.hpp:336](I:/code/Prism/Preview/Protocols/Socks5/UdpAssoc.hpp:336)。

### Q49 没有校验 UDP 包是否来自该 TCP association 的客户端

**P1 / 确认协议合同缺口 / Protocols/Socks5/UdpAssoc**

收到 ClientEp 只用于发送回包，未与 TCP 控制客户端或配置的 expected source IP 比较；RFC 1928 7 要求获取并验证来源 IP。当前 loopback binding 限制了公网暴露，风险主要取决于可达性，未进行第三方来源注入测试。

文件：[Preview/Protocols/Socks5/UdpAssoc.hpp:303](I:/code/Prism/Preview/Protocols/Socks5/UdpAssoc.hpp:303)；[Preview/Protocols/Socks5/UdpAssoc.hpp:55](I:/code/Prism/Preview/Protocols/Socks5/UdpAssoc.hpp:55)。

### Q50 detached driver 异常后跳过通知/关闭并静默退出

**P1 / 确认异常隔离缺口 / Protocols/Xhttp**

try 只围住 Wire Write/Flush，读取、Session.Feed 的分配等异常会跳过尾部 NotifyEof/Response 通知。当前 Boost.Asio co_spawn 把异常交给 detached_handler，后者忽略 completion；不能称为必然逃出 io_context 或终止线程。实际问题是调用方缺少失败通知/统一收口，需故障注入验证。

文件：[Preview/Protocols/Xhttp/StreamClient.hpp:167](I:/code/Prism/Preview/Protocols/Xhttp/StreamClient.hpp:167)；[Preview/Protocols/Xhttp/SplitClient.hpp:193](I:/code/Prism/Preview/Protocols/Xhttp/SplitClient.hpp:193)；[Preview/Protocols/Xhttp/StreamServer.hpp:163](I:/code/Prism/Preview/Protocols/Xhttp/StreamServer.hpp:163)；[Preview/Protocols/Xhttp/SplitServer.hpp:356](I:/code/Prism/Preview/Protocols/Xhttp/SplitServer.hpp:356)；[Preview/Runtime/Worker.hpp:145](I:/code/Prism/Preview/Runtime/Worker.hpp:145)；[build/_deps/boost_src-src/boost/asio/impl/detached.hpp:28](I:/code/Prism/build/_deps/boost_src-src/boost/asio/impl/detached.hpp:28)。

## 4. 子模块文件覆盖矩阵

“人工项”只指正文关联项；“无关联项”表示本轮未在该目录给出确认结论，不能解释成无缺陷。所有有生产头文件的叶目录均进入 AST 扫描。

| 目录/子模块 | 头文件 | 行数 | 最大文件 | 结构告警位置 | 人工项 |
|---|---:|---:|---:|---:|---|
| Preview/Account | 9 | 1891 | 384 | 0 | Q38 |
| Preview/Application | 14 | 3723 | 525 | 6 | Q09、Q10、Q18、Q23、Q38、Q39、Q40、Q41、Q42、Q43、Q45 |
| Preview/Application/Assembly | 7 | 819 | 347 | 1 | 无关联项 |
| Preview/Application/Configuration | 16 | 2223 | 372 | 0 | 无关联项 |
| Preview/Application/Configuration/Validation | 9 | 2252 | 588 | 4 | 无关联项 |
| Preview/Application/Main | 1 | 66 | 66 | 1 | 无关联项 |
| Preview/Application/Startup | 11 | 863 | 272 | 0 | 无关联项 |
| Preview/Boundary/Contract | 1 | 185 | 185 | 0 | 无关联项 |
| Preview/Boundary/Datagram | 4 | 987 | 348 | 0 | 无关联项 |
| Preview/Boundary/Quic | 2 | 410 | 275 | 0 | Q35 |
| Preview/Composition/Builtin | 7 | 800 | 218 | 0 | 无关联项 |
| Preview/Composition/Protocol | 1 | 212 | 212 | 0 | 无关联项 |
| Preview/Composition/Provider | 2 | 416 | 380 | 0 | Q09 |
| Preview/Composition/Recognition | 15 | 3340 | 416 | 12 | 无关联项 |
| Preview/Contract/Carrier | 1 | 486 | 486 | 0 | 无关联项 |
| Preview/Contract/Ingress | 11 | 537 | 209 | 0 | 无关联项 |
| Preview/Contract/Services | 5 | 162 | 48 | 0 | 无关联项 |
| Preview/Foundation | 8 | 1346 | 318 | 0 | Q15 |
| Preview/Foundation/Cancellation | 2 | 30 | 27 | 0 | 无关联项 |
| Preview/Foundation/Error | 3 | 66 | 33 | 0 | 无关联项 |
| Preview/Foundation/Exception | 4 | 496 | 158 | 0 | 无关联项 |
| Preview/Foundation/Executor | 5 | 353 | 155 | 0 | 无关联项 |
| Preview/Foundation/Fault | 3 | 729 | 275 | 0 | 无关联项 |
| Preview/Foundation/Generation | 1 | 15 | 15 | 0 | 无关联项 |
| Preview/Foundation/Identifier | 3 | 146 | 140 | 0 | 无关联项 |
| Preview/Foundation/Memory | 6 | 730 | 256 | 0 | 无关联项 |
| Preview/Foundation/Utility | 1 | 82 | 82 | 0 | Q13 |
| Preview/Foundation/Utility/Crypto | 9 | 1688 | 454 | 0 | 无关联项 |
| Preview/Foundation/Utility/Diagnose | 10 | 2155 | 489 | 3 | Q16、Q19、Q21 |
| Preview/Foundation/Utility/Diagnose/Detail | 8 | 1902 | 553 | 2 | Q16、Q18、Q20、Q22、Q23 |
| Preview/Foundation/Utility/Rate | 1 | 251 | 251 | 0 | 无关联项 |
| Preview/Lifecycle | 10 | 1727 | 595 | 2 | 无关联项 |
| Preview/Net | 2 | 435 | 398 | 1 | 无关联项 |
| Preview/Net/Datagram | 1 | 56 | 56 | 0 | 无关联项 |
| Preview/Net/Dialer | 1 | 154 | 154 | 0 | 无关联项 |
| Preview/Net/Dns | 12 | 4037 | 591 | 5 | Q11、Q12 |
| Preview/Net/Dns/Detail | 6 | 867 | 457 | 1 | 无关联项 |
| Preview/Net/Relay | 3 | 274 | 123 | 0 | 无关联项 |
| Preview/Net/Services | 3 | 229 | 130 | 0 | 无关联项 |
| Preview/Operations | 8 | 1690 | 471 | 4 | Q14、Q41、Q44、Q45 |
| Preview/Operations/Routes | 3 | 1312 | 600 | 6 | Q38、Q39、Q40、Q42、Q43、Q44 |
| Preview/Performance | 1 | 76 | 76 | 0 | 无关联项 |
| Preview/Protocols/Anytls | 12 | 1217 | 289 | 0 | 无关联项 |
| Preview/Protocols/Common | 12 | 1399 | 340 | 1 | Q31、Q32 |
| Preview/Protocols/Ech | 4 | 413 | 243 | 0 | 无关联项 |
| Preview/Protocols/Gun | 10 | 1550 | 329 | 4 | Q27 |
| Preview/Protocols/Http1 | 12 | 3975 | 578 | 0 | 无关联项 |
| Preview/Protocols/Http2 | 5 | 1335 | 565 | 1 | 无关联项 |
| Preview/Protocols/Http2/Detail | 5 | 1115 | 424 | 2 | Q03、Q04、Q05、Q06 |
| Preview/Protocols/Http3 | 12 | 2851 | 589 | 9 | Q28、Q29 |
| Preview/Protocols/Http3/Detail | 6 | 823 | 221 | 18 | Q28、Q29 |
| Preview/Protocols/Hysteria2 | 14 | 4118 | 591 | 1 | Q31 |
| Preview/Protocols/Mux | 20 | 3041 | 434 | 0 | Q15 |
| Preview/Protocols/Mux/H2Mux | 10 | 1107 | 347 | 0 | 无关联项 |
| Preview/Protocols/Mux/SingMux | 3 | 470 | 165 | 0 | 无关联项 |
| Preview/Protocols/Mux/Smux | 6 | 519 | 311 | 0 | 无关联项 |
| Preview/Protocols/Mux/Yamux | 6 | 786 | 521 | 0 | 无关联项 |
| Preview/Protocols/Native | 3 | 175 | 135 | 0 | 无关联项 |
| Preview/Protocols/Quic | 14 | 4323 | 572 | 20 | 无关联项 |
| Preview/Protocols/Reality | 13 | 2807 | 381 | 11 | 无关联项 |
| Preview/Protocols/Restls | 6 | 1909 | 564 | 2 | 无关联项 |
| Preview/Protocols/Shadowsocks2022 | 20 | 4477 | 599 | 4 | Q36 |
| Preview/Protocols/Shadowtls | 10 | 2251 | 516 | 3 | 无关联项 |
| Preview/Protocols/Socks5 | 18 | 3425 | 482 | 1 | Q31、Q32、Q47、Q48、Q49 |
| Preview/Protocols/Trojan | 12 | 2001 | 557 | 1 | 无关联项 |
| Preview/Protocols/Trusttunnel | 11 | 2697 | 411 | 2 | Q01、Q02、Q37 |
| Preview/Protocols/Tuic | 16 | 3602 | 569 | 2 | 无关联项 |
| Preview/Protocols/Vless | 12 | 2416 | 497 | 1 | Q30、Q31、Q32、Q33 |
| Preview/Protocols/Vless/Xudp | 5 | 678 | 267 | 0 | 无关联项 |
| Preview/Protocols/Vmess | 21 | 4137 | 514 | 6 | 无关联项 |
| Preview/Protocols/Ws | 10 | 1954 | 462 | 0 | 无关联项 |
| Preview/Protocols/Xhttp | 14 | 2433 | 427 | 19 | Q24、Q25、Q26、Q37、Q50 |
| Preview/Resource | 5 | 366 | 180 | 0 | 无关联项 |
| Preview/Runtime | 17 | 3554 | 596 | 5 | Q13、Q50 |
| Preview/Runtime/Middleware | 2 | 232 | 125 | 0 | Q07 |
| Preview/Runtime/Middleware/Builtin | 4 | 421 | 198 | 0 | 无关联项 |
| Preview/Runtime/Recognition | 30 | 5854 | 598 | 4 | 无关联项 |
| Preview/Runtime/Session | 7 | 1655 | 369 | 4 | Q08、Q17 |
| Preview/Statistics | 10 | 951 | 219 | 1 | Q34、Q44、Q46 |
| Preview/Transport | 14 | 4309 | 515 | 8 | 无关联项 |

## 5. 全部结构告警：逐文件、逐位置

下面列出全部 178 个自动告警位置，涉及 88 个文件。它们是规则/审查入口，不能直接作为运行缺陷数量。第三方 ABI 需要保留固定签名；格式化 variadic 接口也不能为凑参数数目伪装成万能 context。lambda 的跨度包括捕获/参数列表，部分 body 本身不超过 10 行，表中同时给出 body 行数。

| 类型 | 文件位置 | 名称/形态 | 数量 | 审查解释 |
|---|---|---|---:|---|
| 参数 | [Preview/Application/Assembly/AccountAssembly.hpp:226](I:/code/Prism/Preview/Application/Assembly/AccountAssembly.hpp:226) | AccountMatchesQuicCredential | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Application/BoundaryStartup.hpp:286](I:/code/Prism/Preview/Application/BoundaryStartup.hpp:286) | lambda | 21 | body 18 行，表达式跨度 21 行 |
| lambda | [Preview/Application/BoundaryStartup.hpp:165](I:/code/Prism/Preview/Application/BoundaryStartup.hpp:165) | lambda | 19 | body 17 行，表达式跨度 19 行 |
| 参数 | [Preview/Application/Configuration/Validation/ProtocolIndependentValidation.hpp:384](I:/code/Prism/Preview/Application/Configuration/Validation/ProtocolIndependentValidation.hpp:384) | ReadScriptNumber | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Application/Configuration/Validation/ProtocolIndependentValidation.hpp:162](I:/code/Prism/Preview/Application/Configuration/Validation/ProtocolIndependentValidation.hpp:162) | ValidateServerNameList | 5 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Application/Configuration/Validation/ReferenceValidation.hpp:350](I:/code/Prism/Preview/Application/Configuration/Validation/ReferenceValidation.hpp:350) | ValidateProtocolBindings | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Application/Configuration/Validation/ReferenceValidation.hpp:239](I:/code/Prism/Preview/Application/Configuration/Validation/ReferenceValidation.hpp:239) | ValidateProtocols | 5 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Application/Main/PreviewMain.hpp:40](I:/code/Prism/Preview/Application/Main/PreviewMain.hpp:40) | lambda | 24 | body 22 行，表达式跨度 24 行 |
| lambda | [Preview/Application/OperationsStartup.hpp:316](I:/code/Prism/Preview/Application/OperationsStartup.hpp:316) | lambda | 40 | body 39 行，表达式跨度 40 行 |
| lambda | [Preview/Application/OperationsStartup.hpp:275](I:/code/Prism/Preview/Application/OperationsStartup.hpp:275) | lambda | 28 | body 27 行，表达式跨度 28 行 |
| lambda | [Preview/Application/ProtocolAcceptors.hpp:188](I:/code/Prism/Preview/Application/ProtocolAcceptors.hpp:188) | lambda | 11 | body 9 行，表达式跨度 11 行 |
| 参数 | [Preview/Application/ProtocolProfile.hpp:224](I:/code/Prism/Preview/Application/ProtocolProfile.hpp:224) | AppendRecognitionCandidate | 10 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Composition/Recognition/AnytlsCarrier.hpp:57](I:/code/Prism/Preview/Composition/Recognition/AnytlsCarrier.hpp:57) | lambda | 23 | body 21 行，表达式跨度 23 行 |
| 参数 | [Preview/Composition/Recognition/CandidateRegistry.hpp:285](I:/code/Prism/Preview/Composition/Recognition/CandidateRegistry.hpp:285) | BuildFrom | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Composition/Recognition/RestlsCarrier.hpp:149](I:/code/Prism/Preview/Composition/Recognition/RestlsCarrier.hpp:149) | lambda | 19 | body 17 行，表达式跨度 19 行 |
| lambda | [Preview/Composition/Recognition/ShadowtlsCarrier.hpp:125](I:/code/Prism/Preview/Composition/Recognition/ShadowtlsCarrier.hpp:125) | lambda | 14 | body 11 行，表达式跨度 14 行 |
| lambda | [Preview/Composition/Recognition/TlsCandidateFactory.hpp:74](I:/code/Prism/Preview/Composition/Recognition/TlsCandidateFactory.hpp:74) | lambda | 11 | body 9 行，表达式跨度 11 行 |
| 参数 | [Preview/Composition/Recognition/TlsCandidateFactory.hpp:30](I:/code/Prism/Preview/Composition/Recognition/TlsCandidateFactory.hpp:30) | Make | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Composition/Recognition/TlsCarrierHelpers.hpp:174](I:/code/Prism/Preview/Composition/Recognition/TlsCarrierHelpers.hpp:174) | lambda | 51 | body 47 行，表达式跨度 51 行 |
| 参数 | [Preview/Composition/Recognition/TlsCarrierHelpers.hpp:167](I:/code/Prism/Preview/Composition/Recognition/TlsCarrierHelpers.hpp:167) | MakeGunServerAccept | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Composition/Recognition/TlsCarrierHelpers.hpp:135](I:/code/Prism/Preview/Composition/Recognition/TlsCarrierHelpers.hpp:135) | lambda | 23 | body 20 行，表达式跨度 23 行 |
| lambda | [Preview/Composition/Recognition/TlsCarrierHelpers.hpp:91](I:/code/Prism/Preview/Composition/Recognition/TlsCarrierHelpers.hpp:91) | lambda | 32 | body 29 行，表达式跨度 32 行 |
| lambda | [Preview/Composition/Recognition/TlsCarrierHelpers.hpp:54](I:/code/Prism/Preview/Composition/Recognition/TlsCarrierHelpers.hpp:54) | lambda | 16 | body 14 行，表达式跨度 16 行 |
| 参数 | [Preview/Composition/Recognition/TlsRecognitionHelpers.hpp:113](I:/code/Prism/Preview/Composition/Recognition/TlsRecognitionHelpers.hpp:113) | InspectFeatures | 5 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Foundation/Utility/Diagnose/ContextState.hpp:370](I:/code/Prism/Preview/Foundation/Utility/Diagnose/ContextState.hpp:370) | lambda | 13 | body 12 行，表达式跨度 13 行 |
| 参数 | [Preview/Foundation/Utility/Diagnose/Detail/AsyncBackendState.hpp:80](I:/code/Prism/Preview/Foundation/Utility/Diagnose/Detail/AsyncBackendState.hpp:80) | AsyncBackendState | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp:269](I:/code/Prism/Preview/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp:269) | QueueFailure | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Foundation/Utility/Diagnose/Facade.hpp:184](I:/code/Prism/Preview/Foundation/Utility/Diagnose/Facade.hpp:184) | SubmitFormatted | 5 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Foundation/Utility/Diagnose/FieldCodec.hpp:28](I:/code/Prism/Preview/Foundation/Utility/Diagnose/FieldCodec.hpp:28) | lambda | 13 | body 12 行，表达式跨度 13 行 |
| 函数体 | [Preview/Lifecycle/TaskRegistry.hpp:378](I:/code/Prism/Preview/Lifecycle/TaskRegistry.hpp:378) | SpawnTracked | 141 | 超过 120 行；按真实 owner/状态机拆分 |
| lambda | [Preview/Lifecycle/TaskRegistry.hpp:444](I:/code/Prism/Preview/Lifecycle/TaskRegistry.hpp:444) | lambda | 71 | body 70 行，表达式跨度 71 行 |
| lambda | [Preview/Net/Dns/Answer.hpp:149](I:/code/Prism/Preview/Net/Dns/Answer.hpp:149) | lambda | 58 | body 57 行，表达式跨度 58 行 |
| 参数 | [Preview/Net/Dns/Detail/Fallback.hpp:82](I:/code/Prism/Preview/Net/Dns/Detail/Fallback.hpp:82) | ResolveFallback | 5 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Net/Dns/Format.hpp:529](I:/code/Prism/Preview/Net/Dns/Format.hpp:529) | lambda | 19 | body 18 行，表达式跨度 19 行 |
| lambda | [Preview/Net/Dns/Format.hpp:438](I:/code/Prism/Preview/Net/Dns/Format.hpp:438) | lambda | 13 | body 12 行，表达式跨度 13 行 |
| lambda | [Preview/Net/Dns/Resolver.hpp:516](I:/code/Prism/Preview/Net/Dns/Resolver.hpp:516) | lambda | 29 | body 27 行，表达式跨度 29 行 |
| lambda | [Preview/Net/Dns/Upstream.hpp:223](I:/code/Prism/Preview/Net/Dns/Upstream.hpp:223) | lambda | 19 | body 17 行，表达式跨度 19 行 |
| lambda | [Preview/Net/UdpRelay.hpp:86](I:/code/Prism/Preview/Net/UdpRelay.hpp:86) | lambda | 36 | body 32 行，表达式跨度 36 行 |
| 参数 | [Preview/Operations/Router.hpp:265](I:/code/Prism/Preview/Operations/Router.hpp:265) | Router | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Operations/Router.hpp:173](I:/code/Prism/Preview/Operations/Router.hpp:173) | State | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Operations/Router.hpp:155](I:/code/Prism/Preview/Operations/Router.hpp:155) | lambda | 11 | body 10 行，表达式跨度 11 行 |
| lambda | [Preview/Operations/Router.hpp:116](I:/code/Prism/Preview/Operations/Router.hpp:116) | lambda | 12 | body 10 行，表达式跨度 12 行 |
| lambda | [Preview/Operations/Routes/HttpJson.hpp:454](I:/code/Prism/Preview/Operations/Routes/HttpJson.hpp:454) | lambda | 44 | body 43 行，表达式跨度 44 行 |
| 函数体 | [Preview/Operations/Routes/RequestParser.hpp:99](I:/code/Prism/Preview/Operations/Routes/RequestParser.hpp:99) | ParseRequest | 136 | 超过 120 行；按真实 owner/状态机拆分 |
| lambda | [Preview/Operations/Routes/RouteDispatch.hpp:434](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:434) | lambda | 12 | body 11 行，表达式跨度 12 行 |
| 参数 | [Preview/Operations/Routes/RouteDispatch.hpp:179](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:179) | ReadCorrelation | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Operations/Routes/RouteDispatch.hpp:165](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:165) | ReadBooleanParameter | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Operations/Routes/RouteDispatch.hpp:136](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:136) | ReadParameter | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Protocols/Common/Address.hpp:121](I:/code/Prism/Preview/Protocols/Common/Address.hpp:121) | lambda | 32 | body 31 行，表达式跨度 32 行 |
| lambda | [Preview/Protocols/Gun/GrpcSession.hpp:210](I:/code/Prism/Preview/Protocols/Gun/GrpcSession.hpp:210) | lambda | 17 | body 16 行，表达式跨度 17 行 |
| lambda | [Preview/Protocols/Gun/GrpcSession.hpp:191](I:/code/Prism/Preview/Protocols/Gun/GrpcSession.hpp:191) | lambda | 19 | body 18 行，表达式跨度 19 行 |
| lambda | [Preview/Protocols/Gun/GrpcStream.hpp:206](I:/code/Prism/Preview/Protocols/Gun/GrpcStream.hpp:206) | lambda | 29 | body 28 行，表达式跨度 29 行 |
| lambda | [Preview/Protocols/Gun/GrpcStream.hpp:183](I:/code/Prism/Preview/Protocols/Gun/GrpcStream.hpp:183) | lambda | 23 | body 22 行，表达式跨度 23 行 |
| 参数 | [Preview/Protocols/Http2/Codec.hpp:108](I:/code/Prism/Preview/Protocols/Http2/Codec.hpp:108) | EncodeInt | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Http2/Detail/FrameProcessor.hpp:251](I:/code/Prism/Preview/Protocols/Http2/Detail/FrameProcessor.hpp:251) | FinishHeaders | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Http2/Detail/FrameProcessor.hpp:37](I:/code/Prism/Preview/Protocols/Http2/Detail/FrameProcessor.hpp:37) | FrameProcessor | 5 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Http3/Auth.hpp:116](I:/code/Prism/Preview/Protocols/Http3/Auth.hpp:116) | ResponseHead | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:134](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:134) | Session::CbEndStream | 4 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:118](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:118) | Session::CbStopSending | 5 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:91](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:91) | Session::CbRecvData | 6 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:63](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:63) | Session::CbEndHeaders | 5 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:34](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:34) | Session::CbRecvHeader | 8 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:13](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:13) | Session::CbBeginHeaders | 4 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/Detail/SessionContract.hpp:197](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionContract.hpp:197) | SubmitResponseHeaders | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Http3/Detail/SessionContract.hpp:171](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionContract.hpp:171) | ReadResponseBody | 7 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/Detail/SessionContract.hpp:165](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionContract.hpp:165) | CbEndStream | 4 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/Detail/SessionContract.hpp:159](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionContract.hpp:159) | CbStopSending | 5 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/Detail/SessionContract.hpp:152](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionContract.hpp:152) | CbRecvData | 6 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/Detail/SessionContract.hpp:146](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionContract.hpp:146) | CbEndHeaders | 5 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/Detail/SessionContract.hpp:137](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionContract.hpp:137) | CbRecvHeader | 8 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/Detail/SessionContract.hpp:132](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionContract.hpp:132) | CbBeginHeaders | 4 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/Detail/SessionOutput.hpp:172](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionOutput.hpp:172) | Session::ReadResponseBody | 7 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/Detail/SessionOutput.hpp:135](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionOutput.hpp:135) | Session::SubmitResponseHeaders | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Http3/Detail/Varint.hpp:83](I:/code/Prism/Preview/Protocols/Http3/Detail/Varint.hpp:83) | WriteVarint | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Http3/Detail/Varint.hpp:27](I:/code/Prism/Preview/Protocols/Http3/Detail/Varint.hpp:27) | ReadVarint | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Http3/NativeClient.hpp:551](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:551) | ReadRequestBody | 7 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/NativeClient.hpp:533](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:533) | CbResetStream | 5 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/NativeClient.hpp:528](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:528) | CbStopSending | 5 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/NativeClient.hpp:517](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:517) | CbEndStream | 4 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/NativeClient.hpp:511](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:511) | CbRecvData | 6 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/NativeClient.hpp:499](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:499) | CbEndHeaders | 5 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/NativeClient.hpp:465](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:465) | CbRecvHeader | 8 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Http3/NativeClient.hpp:453](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:453) | CbBeginHeaders | 4 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Hysteria2/Conn.hpp:65](I:/code/Prism/Preview/Protocols/Hysteria2/Conn.hpp:65) | Conn | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Quic/GatewayCommon.hpp:141](I:/code/Prism/Preview/Protocols/Quic/GatewayCommon.hpp:141) | RegisterTypedConnection | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Quic/GatewayCommon.hpp:108](I:/code/Prism/Preview/Protocols/Quic/GatewayCommon.hpp:108) | RegisterConnection | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Quic/NativeConnection.hpp:495](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:495) | NewConnectionId | 5 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Quic/NativeConnection.hpp:486](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:486) | VersionNegotiation | 4 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Quic/NativeConnection.hpp:478](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:478) | RecvDatagram | 5 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Quic/NativeConnection.hpp:471](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:471) | StreamClose | 6 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Quic/NativeConnection.hpp:461](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:461) | RecvStreamData | 8 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Quic/NativeConnection.hpp:454](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:454) | RecvCryptoData | 6 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Quic/NativeConnection.hpp:446](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:446) | AddHandshakeData | 4 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Quic/NativeConnection.hpp:440](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:440) | SetWriteSecret | 5 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Quic/NativeConnection.hpp:434](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:434) | SetReadSecret | 5 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:303](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:303) | NativeConnection::NewConnectionId | 5 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:252](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:252) | NativeConnection::VersionNegotiation | 4 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:213](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:213) | NativeConnection::RecvDatagram | 5 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:193](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:193) | NativeConnection::StreamClose | 6 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:158](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:158) | NativeConnection::RecvStreamData | 8 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:146](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:146) | NativeConnection::RecvCryptoData | 6 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:92](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:92) | NativeConnection::AddHandshakeData | 4 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:69](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:69) | NativeConnection::SetWriteSecret | 5 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 参数 | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:46](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:46) | NativeConnection::SetReadSecret | 5 | 第三方固定 C 回调签名；保留 ABI，检查内部转换/异常边界 |
| 函数体 | [Preview/Protocols/Reality/Carrier.hpp:49](I:/code/Prism/Preview/Protocols/Reality/Carrier.hpp:49) | MakeFacadeCarrier | 139 | 超过 120 行；按真实 owner/状态机拆分 |
| lambda | [Preview/Protocols/Reality/Carrier.hpp:54](I:/code/Prism/Preview/Protocols/Reality/Carrier.hpp:54) | lambda | 135 | body 132 行，表达式跨度 135 行 |
| 函数体 | [Preview/Protocols/Reality/CarrierHandshake.hpp:67](I:/code/Prism/Preview/Protocols/Reality/CarrierHandshake.hpp:67) | ParseClientHello | 144 | 超过 120 行；按真实 owner/状态机拆分 |
| lambda | [Preview/Protocols/Reality/KeyMaterial.hpp:229](I:/code/Prism/Preview/Protocols/Reality/KeyMaterial.hpp:229) | lambda | 15 | body 12 行，表达式跨度 15 行 |
| lambda | [Preview/Protocols/Reality/KeyMaterial.hpp:78](I:/code/Prism/Preview/Protocols/Reality/KeyMaterial.hpp:78) | lambda | 24 | body 23 行，表达式跨度 24 行 |
| lambda | [Preview/Protocols/Reality/SessionId.hpp:184](I:/code/Prism/Preview/Protocols/Reality/SessionId.hpp:184) | lambda | 16 | body 15 行，表达式跨度 16 行 |
| 参数 | [Preview/Protocols/Reality/Tls13.hpp:339](I:/code/Prism/Preview/Protocols/Reality/Tls13.hpp:339) | DecryptTlsRecord | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Reality/Tls13.hpp:310](I:/code/Prism/Preview/Protocols/Reality/Tls13.hpp:310) | EncryptTlsRecord | 5 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Reality/Tls13.hpp:142](I:/code/Prism/Preview/Protocols/Reality/Tls13.hpp:142) | Aes128GcmOpen | 5 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Reality/Tls13.hpp:85](I:/code/Prism/Preview/Protocols/Reality/Tls13.hpp:85) | Aes128GcmSeal | 5 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Reality/Tls13.hpp:56](I:/code/Prism/Preview/Protocols/Reality/Tls13.hpp:56) | ExpandTls13Label | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Protocols/Restls/Carrier.hpp:86](I:/code/Prism/Preview/Protocols/Restls/Carrier.hpp:86) | lambda | 76 | body 74 行，表达式跨度 76 行 |
| 函数体 | [Preview/Protocols/Restls/Conn.hpp:142](I:/code/Prism/Preview/Protocols/Restls/Conn.hpp:142) | async_read_some | 147 | 超过 120 行；按真实 owner/状态机拆分 |
| 参数 | [Preview/Protocols/Shadowsocks2022/ChunkCodec.hpp:250](I:/code/Prism/Preview/Protocols/Shadowsocks2022/ChunkCodec.hpp:250) | AeadOpen | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Shadowsocks2022/ChunkCodec.hpp:125](I:/code/Prism/Preview/Protocols/Shadowsocks2022/ChunkCodec.hpp:125) | AeadSeal | 5 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Shadowsocks2022/ChunkCodec.hpp:65](I:/code/Prism/Preview/Protocols/Shadowsocks2022/ChunkCodec.hpp:65) | AeadSeal | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 函数体 | [Preview/Protocols/Shadowsocks2022/ResponseCodec.hpp:451](I:/code/Prism/Preview/Protocols/Shadowsocks2022/ResponseCodec.hpp:451) | ParseUdpPacket | 146 | 超过 120 行；按真实 owner/状态机拆分 |
| lambda | [Preview/Protocols/Shadowtls/Carrier.hpp:44](I:/code/Prism/Preview/Protocols/Shadowtls/Carrier.hpp:44) | lambda | 30 | body 28 行，表达式跨度 30 行 |
| 参数 | [Preview/Protocols/Shadowtls/RecordProtector.hpp:151](I:/code/Prism/Preview/Protocols/Shadowtls/RecordProtector.hpp:151) | RecordProtector | 6 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 函数体 | [Preview/Protocols/Shadowtls/Server.hpp:204](I:/code/Prism/Preview/Protocols/Shadowtls/Server.hpp:204) | Run | 151 | 超过 120 行；按真实 owner/状态机拆分 |
| 参数 | [Preview/Protocols/Socks5/ConnHandshake.hpp:72](I:/code/Prism/Preview/Protocols/Socks5/ConnHandshake.hpp:72) | WriteHandshake | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Trojan/Conn.hpp:66](I:/code/Prism/Preview/Protocols/Trojan/Conn.hpp:66) | Conn | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Protocols/Trusttunnel/Http2Client.hpp:198](I:/code/Prism/Preview/Protocols/Trusttunnel/Http2Client.hpp:198) | lambda | 37 | body 36 行，表达式跨度 37 行 |
| lambda | [Preview/Protocols/Trusttunnel/Http2Client.hpp:158](I:/code/Prism/Preview/Protocols/Trusttunnel/Http2Client.hpp:158) | lambda | 17 | body 15 行，表达式跨度 17 行 |
| 参数 | [Preview/Protocols/Tuic/Conn.hpp:54](I:/code/Prism/Preview/Protocols/Tuic/Conn.hpp:54) | Conn | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Tuic/ConnSession.hpp:40](I:/code/Prism/Preview/Protocols/Tuic/ConnSession.hpp:40) | ConnSession | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Vless/Conn.hpp:63](I:/code/Prism/Preview/Protocols/Vless/Conn.hpp:63) | Conn | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Vmess/AuthCrypto.hpp:148](I:/code/Prism/Preview/Protocols/Vmess/AuthCrypto.hpp:148) | ValidAesGcmInput | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Protocols/Vmess/AuthId.hpp:98](I:/code/Prism/Preview/Protocols/Vmess/AuthId.hpp:98) | lambda | 16 | body 15 行，表达式跨度 16 行 |
| lambda | [Preview/Protocols/Vmess/AuthKdf.hpp:38](I:/code/Prism/Preview/Protocols/Vmess/AuthKdf.hpp:38) | lambda | 19 | body 18 行，表达式跨度 19 行 |
| lambda | [Preview/Protocols/Vmess/AuthKdf.hpp:43](I:/code/Prism/Preview/Protocols/Vmess/AuthKdf.hpp:43) | lambda | 13 | body 11 行，表达式跨度 13 行 |
| 参数 | [Preview/Protocols/Vmess/Conn.hpp:48](I:/code/Prism/Preview/Protocols/Vmess/Conn.hpp:48) | Conn | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Vmess/ConnSession.hpp:38](I:/code/Prism/Preview/Protocols/Vmess/ConnSession.hpp:38) | ConnSession | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Xhttp/Entry.hpp:22](I:/code/Prism/Preview/Protocols/Xhttp/Entry.hpp:22) | Connect | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Xhttp/SplitClient.hpp:247](I:/code/Prism/Preview/Protocols/Xhttp/SplitClient.hpp:247) | ConnectSplit | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Protocols/Xhttp/SplitClient.hpp:197](I:/code/Prism/Preview/Protocols/Xhttp/SplitClient.hpp:197) | lambda | 29 | body 28 行，表达式跨度 29 行 |
| lambda | [Preview/Protocols/Xhttp/SplitClient.hpp:129](I:/code/Prism/Preview/Protocols/Xhttp/SplitClient.hpp:129) | lambda | 28 | body 27 行，表达式跨度 28 行 |
| lambda | [Preview/Protocols/Xhttp/SplitClient.hpp:94](I:/code/Prism/Preview/Protocols/Xhttp/SplitClient.hpp:94) | lambda | 17 | body 15 行，表达式跨度 17 行 |
| lambda | [Preview/Protocols/Xhttp/SplitServer.hpp:358](I:/code/Prism/Preview/Protocols/Xhttp/SplitServer.hpp:358) | lambda | 35 | body 34 行，表达式跨度 35 行 |
| 参数 | [Preview/Protocols/Xhttp/SplitServer.hpp:154](I:/code/Prism/Preview/Protocols/Xhttp/SplitServer.hpp:154) | HandleSplitServerHeaders | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Protocols/Xhttp/StreamClient.hpp:252](I:/code/Prism/Preview/Protocols/Xhttp/StreamClient.hpp:252) | ConnectStream | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Protocols/Xhttp/StreamClient.hpp:169](I:/code/Prism/Preview/Protocols/Xhttp/StreamClient.hpp:169) | lambda | 34 | body 33 行，表达式跨度 34 行 |
| lambda | [Preview/Protocols/Xhttp/StreamClient.hpp:99](I:/code/Prism/Preview/Protocols/Xhttp/StreamClient.hpp:99) | lambda | 24 | body 20 行，表达式跨度 24 行 |
| lambda | [Preview/Protocols/Xhttp/StreamClient.hpp:84](I:/code/Prism/Preview/Protocols/Xhttp/StreamClient.hpp:84) | lambda | 14 | body 12 行，表达式跨度 14 行 |
| lambda | [Preview/Protocols/Xhttp/StreamClient.hpp:69](I:/code/Prism/Preview/Protocols/Xhttp/StreamClient.hpp:69) | lambda | 15 | body 12 行，表达式跨度 15 行 |
| lambda | [Preview/Protocols/Xhttp/StreamClient.hpp:53](I:/code/Prism/Preview/Protocols/Xhttp/StreamClient.hpp:53) | lambda | 14 | body 13 行，表达式跨度 14 行 |
| 函数体 | [Preview/Protocols/Xhttp/StreamServer.hpp:51](I:/code/Prism/Preview/Protocols/Xhttp/StreamServer.hpp:51) | Run | 150 | 超过 120 行；按真实 owner/状态机拆分 |
| lambda | [Preview/Protocols/Xhttp/StreamServer.hpp:165](I:/code/Prism/Preview/Protocols/Xhttp/StreamServer.hpp:165) | lambda | 34 | body 32 行，表达式跨度 34 行 |
| lambda | [Preview/Protocols/Xhttp/StreamServer.hpp:103](I:/code/Prism/Preview/Protocols/Xhttp/StreamServer.hpp:103) | lambda | 44 | body 41 行，表达式跨度 44 行 |
| lambda | [Preview/Protocols/Xhttp/StreamServer.hpp:91](I:/code/Prism/Preview/Protocols/Xhttp/StreamServer.hpp:91) | lambda | 11 | body 9 行，表达式跨度 11 行 |
| lambda | [Preview/Protocols/Xhttp/StreamServer.hpp:73](I:/code/Prism/Preview/Protocols/Xhttp/StreamServer.hpp:73) | lambda | 14 | body 13 行，表达式跨度 14 行 |
| 参数 | [Preview/Protocols/Xhttp/StreamTransport.hpp:265](I:/code/Prism/Preview/Protocols/Xhttp/StreamTransport.hpp:265) | WriteRequest | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Runtime/Listener.hpp:350](I:/code/Prism/Preview/Runtime/Listener.hpp:350) | RunSession | 5 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Runtime/Listener.hpp:128](I:/code/Prism/Preview/Runtime/Listener.hpp:128) | AdmissionRequest | 7 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 函数体 | [Preview/Runtime/Recognition/ConfiguredMode.hpp:73](I:/code/Prism/Preview/Runtime/Recognition/ConfiguredMode.hpp:73) | Recognize | 141 | 超过 120 行；按真实 owner/状态机拆分 |
| 函数体 | [Preview/Runtime/Recognition/MixedTrialMode.hpp:46](I:/code/Prism/Preview/Runtime/Recognition/MixedTrialMode.hpp:46) | Recognize | 211 | 超过 120 行；按真实 owner/状态机拆分 |
| 参数 | [Preview/Runtime/Recognition/RawIngressProbe.hpp:115](I:/code/Prism/Preview/Runtime/Recognition/RawIngressProbe.hpp:115) | Rejected | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Runtime/Recognition/Route.hpp:92](I:/code/Prism/Preview/Runtime/Recognition/Route.hpp:92) | lambda | 13 | body 11 行，表达式跨度 13 行 |
| lambda | [Preview/Runtime/SessionControl.hpp:500](I:/code/Prism/Preview/Runtime/SessionControl.hpp:500) | lambda | 14 | body 13 行，表达式跨度 14 行 |
| lambda | [Preview/Runtime/SessionControl.hpp:360](I:/code/Prism/Preview/Runtime/SessionControl.hpp:360) | lambda | 11 | body 10 行，表达式跨度 11 行 |
| 参数 | [Preview/Runtime/SessionControl.hpp:204](I:/code/Prism/Preview/Runtime/SessionControl.hpp:204) | ReportErrorOnExecutor | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Runtime/Session/LogState.hpp:92](I:/code/Prism/Preview/Runtime/Session/LogState.hpp:92) | lambda | 14 | body 11 行，表达式跨度 14 行 |
| 参数 | [Preview/Runtime/Session/RecognitionLogging.hpp:316](I:/code/Prism/Preview/Runtime/Session/RecognitionLogging.hpp:316) | WriteRecognitionFailure | 7 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Runtime/Session/RecognitionLogging.hpp:243](I:/code/Prism/Preview/Runtime/Session/RecognitionLogging.hpp:243) | WriteLog | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 参数 | [Preview/Runtime/Session/RecognitionLogging.hpp:52](I:/code/Prism/Preview/Runtime/Session/RecognitionLogging.hpp:52) | WriteRecognition | 5 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| 函数体 | [Preview/Statistics/Redaction.hpp:96](I:/code/Prism/Preview/Statistics/Redaction.hpp:96) | RedactSensitiveText | 121 | 超过 120 行；按真实 owner/状态机拆分 |
| lambda | [Preview/Transport/Connector.hpp:442](I:/code/Prism/Preview/Transport/Connector.hpp:442) | lambda | 35 | body 34 行，表达式跨度 35 行 |
| 参数 | [Preview/Transport/Connector.hpp:363](I:/code/Prism/Preview/Transport/Connector.hpp:363) | PostCompletion | 4 | 项目接口/内部 helper；按领域拆职责，variadic 单独判断 |
| lambda | [Preview/Transport/Connector.hpp:234](I:/code/Prism/Preview/Transport/Connector.hpp:234) | lambda | 17 | body 16 行，表达式跨度 17 行 |
| lambda | [Preview/Transport/Connector.hpp:175](I:/code/Prism/Preview/Transport/Connector.hpp:175) | lambda | 41 | body 40 行，表达式跨度 41 行 |
| lambda | [Preview/Transport/Encrypted.hpp:360](I:/code/Prism/Preview/Transport/Encrypted.hpp:360) | lambda | 14 | body 13 行，表达式跨度 14 行 |
| lambda | [Preview/Transport/Reliable.hpp:238](I:/code/Prism/Preview/Transport/Reliable.hpp:238) | lambda | 12 | body 11 行，表达式跨度 12 行 |
| lambda | [Preview/Transport/Transmission.hpp:210](I:/code/Prism/Preview/Transport/Transmission.hpp:210) | lambda | 17 | body 16 行，表达式跨度 17 行 |
| lambda | [Preview/Transport/Transmission.hpp:167](I:/code/Prism/Preview/Transport/Transmission.hpp:167) | lambda | 17 | body 16 行，表达式跨度 17 行 |

## 6. 对比较清楚的部分与不能误判的情况

- AccountLease/StreamLease：不可复制、移动后源失活、析构释放，策略与 runtime 保活边界清楚。未把使用范围广视为高耦合。
- Lifecycle：取消请求与真实 drain 分开，弱 parent/child 联系及 reclaimer 是必要生命周期机制。TaskRegistry 的超长函数/lambda 已列出，并非说明全部机制失效。
- SOCKS5/SS2022 新 binding：Prepared、共享唯一 material、activity 与 Close/Drain 的方向清楚；UDP 路径仍需独立修正。
- AnyTLS root/writer：tracked loops/children/writes、active buffer 和 completion 边界较好；Deque 的容量和整体外部互操作仍需独立验证。最终 State 的关闭异常记录改动来自其他工作。
- Boundary：CID/peer/lease 与 socket owner 已分开；TCP acceptor 仍位于 Runtime/Listener，是当前实现位置，不能写成已全部迁入 Boundary。
- Composition：ProtocolBuiltins 从 ProtocolCatalog 派生已有进步；不应再声称二者维护重复名称表。真正缺口是部分协议仍从应用层专门构造。
- Operations Router：typed 模型、strand 和值结果的隔离较好；Application 的具体命令 handler 未兑现部分模型字段。
- HTTP/3 HeaderBlock：arena owner 先于 PMR 容器声明，move-only 边界有价值；原生 header callback 的预算/异常隔离是另一个问题。
- Network fallback、日志旧文件 .legacy 归档、与外部 wire 实现互操作不等于保留 Preview 旧 API，不能按关键字一刀切删除。

## 7. 静态门禁盲区与验证次序

当前结构门禁检查行数、路径大小写、退役清单和部分 include 方向；未检查 Foundation→Statistics/Transport，也不验证 callback 强引用环、异步 writer 所有 completion、管理命令执行范围或 RFC 行为。即使 exit 0，正文问题仍可以存在。

建议先做命令范围（worker drain/stream cancel/revoke）、强引用环/写失败完成通知、SOCKS5 远程 UDP/来源检查、HTTP/2/3 预算与规范；随后收敛 Application/Composition 与 Runtime Context，补完整 capability/metrics。每个修复分别验证源码、构建、focused、全量、真实请求/互操作、性能，保留原失败证据和当前二进制/配置 hash。

需要运行验证的具体输入：两个并发 writer 中首写失败；在途 FIN 与 Close；正常/失败客户端结束后的 weak owner 释放；未知 HTTP/2 帧；GOAWAY+debug data；不带 END_HEADERS 的连续 continuation；多条/超大原生 HTTP/3 header；远程 SOCKS5 UDP 与第三方 source；无回复目标之后的第二 UDP 包与单包多回复；跨 IPv4/IPv6；带 worker/stream/task 的管理命令。

## 8. 规范与外部库依据

- [RFC 9113 5.5：未知扩展帧](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.5)
- [RFC 9113 6.8：GOAWAY](https://www.rfc-editor.org/rfc/rfc9113.html#section-6.8)
- [RFC 1928 7：UDP association 来源约束](https://www.rfc-editor.org/rfc/rfc1928.html#section-7)
- [build/_deps/nghttp3-src/lib/includes/nghttp3/nghttp3.h:2473](I:/code/Prism/build/_deps/nghttp3-src/lib/includes/nghttp3/nghttp3.h:2473)：默认 max_field_section_size 接近协议最大值，并不是项目 64 KiB/128 字段预算。
- [build/_deps/boost_src-src/boost/asio/impl/detached.hpp:28](I:/code/Prism/build/_deps/boost_src-src/boost/asio/impl/detached.hpp:28)：completion 被忽略；co_spawn 负责捕获 coroutine 异常。不要把 detached 异常直接等同于 terminate。

## 9. 人工项证据文件 SHA-256

生产头文件的完整 hash 在最终静态 JSON；下表也包含测试、第三方库等人工项引用。报告中的行号是该快照定位点。

| 文件 | SHA-256 |
|---|---|
| [Preview/Account/Runtime.hpp](I:/code/Prism/Preview/Account/Runtime.hpp) | dee87be6e15395813ab33fb2c18cb3e27205587c12d284688a326c11bb1e11d6 |
| [Preview/Application/DiagnoseRuntime.hpp](I:/code/Prism/Preview/Application/DiagnoseRuntime.hpp) | 24b0bb678456785523c0e9ddfbc91c411516caefb77a06eeab4a2d2129f6d5ac |
| [Preview/Application/OperationsStartup.hpp](I:/code/Prism/Preview/Application/OperationsStartup.hpp) | 9c66ddd75d6d1c751ab53463d63024829441b82bc931e18759f6e5a2f5daa43c |
| [Preview/Application/ProtocolAcceptors.hpp](I:/code/Prism/Preview/Application/ProtocolAcceptors.hpp) | 1ae310c8947653c8042b15e2bee0881b37baf6720712dad70980c074c3021d17 |
| [Preview/Application/ProtocolProfile.hpp](I:/code/Prism/Preview/Application/ProtocolProfile.hpp) | 30c2a3a402d90056d2472de71179af83f8e47df31393cf5064f4bc5807a83674 |
| [Preview/Application/Shutdown.hpp](I:/code/Prism/Preview/Application/Shutdown.hpp) | 8d9bae563c8d62236c1b2966a7a9eebe328fbf4a1672d20354f30842c2f525e9 |
| [Preview/Boundary/Quic/QuicConnectionRegistry.hpp](I:/code/Prism/Preview/Boundary/Quic/QuicConnectionRegistry.hpp) | ffa4d3e2129f8f46e67fdf1a6ddd557cc2ff31c5b99cb5553dcf98591da55ab9 |
| [Preview/Composition/Provider/ProviderCatalog.hpp](I:/code/Prism/Preview/Composition/Provider/ProviderCatalog.hpp) | c1f61c3907c30173d2c8d22aa6982db772b6c79ce7a79c42a4663ab3faae1cea |
| [Preview/Foundation/SessionBase.hpp](I:/code/Prism/Preview/Foundation/SessionBase.hpp) | f834aed131a5e44b66f19ce0b42cee5444b16b1fcc5d5985a70e99c1f198dbd6 |
| [Preview/Foundation/Utility/Diagnose/ContextState.hpp](I:/code/Prism/Preview/Foundation/Utility/Diagnose/ContextState.hpp) | 8b22dc99dfce0122b34e86cef459e8c72301a8fb596cddfc5f77a7b0df1e2427 |
| [Preview/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp](I:/code/Prism/Preview/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp) | 864a885811ca07e8b7c19461ddd73f443844a3802f874bd36239c7c5e01720a1 |
| [Preview/Foundation/Utility/Diagnose/Detail/BackendLifecycle.hpp](I:/code/Prism/Preview/Foundation/Utility/Diagnose/Detail/BackendLifecycle.hpp) | 6ae565b73f3d0a1cda7eaf70abb1337acb970e0dd9bb88ef0699e81c8d549dfb |
| [Preview/Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp](I:/code/Prism/Preview/Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp) | 40fbb7c6eddf2c7e38a04fafe0e15b5a63476d55b9c13f46fde9f930e7e2ec3e |
| [Preview/Foundation/Utility/Diagnose/Detail/SinkSet.hpp](I:/code/Prism/Preview/Foundation/Utility/Diagnose/Detail/SinkSet.hpp) | 1dc33fdad508aa6e393218d48114762d94a4d9536ca0ae26b5ef28c3ced63b20 |
| [Preview/Foundation/Utility/Diagnose/FieldCodec.hpp](I:/code/Prism/Preview/Foundation/Utility/Diagnose/FieldCodec.hpp) | e984c5ba5c9a3a53b66636c18052440511a1bd4e4feb9f93d8bc1c4ff874080c |
| [Preview/Foundation/Utility/Diagnose/SubmissionReceipt.hpp](I:/code/Prism/Preview/Foundation/Utility/Diagnose/SubmissionReceipt.hpp) | fe0d25682ab6a583526952142c0132c3e0edf6ad20f1d0a275bd3b4f9c13b954 |
| [Preview/Foundation/Utility/TrafficSink.hpp](I:/code/Prism/Preview/Foundation/Utility/TrafficSink.hpp) | 56e12b8704b4831af09ec4c719a0a97c36ff4d6b68c49ecd241cb7d2c9b1aab0 |
| [Preview/Net/Dns/Resolver.hpp](I:/code/Prism/Preview/Net/Dns/Resolver.hpp) | db85c97096ea33dd12c5387eff4756cc461df4c3196febb287522e252cbf4214 |
| [Preview/Operations/HttpConnection.hpp](I:/code/Prism/Preview/Operations/HttpConnection.hpp) | 4dc04d97fb6d2613a478506a417899fb9c5bfa510a0830614a99c47479fb8462 |
| [Preview/Operations/HttpServer.hpp](I:/code/Prism/Preview/Operations/HttpServer.hpp) | c45573e73c820219101e40d979ad174b647bf6a0f6e013eb5a795e20909a9ba3 |
| [Preview/Operations/Models.hpp](I:/code/Prism/Preview/Operations/Models.hpp) | 2fb9ac303adef0e7c5a5da661f127ceabe1c7b2075f091f712e95b0e2849c540 |
| [Preview/Operations/Router.hpp](I:/code/Prism/Preview/Operations/Router.hpp) | b69e60a608954636209467fb795be7878bf30c6991cea936d3b47999158e3e50 |
| [Preview/Operations/Routes/RouteDispatch.hpp](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp) | 0d2475b659471f5497b66882bf1b8047044ce1c32cdee1d427717745570a4443 |
| [Preview/Protocols/Common/DatagramRelay.hpp](I:/code/Prism/Preview/Protocols/Common/DatagramRelay.hpp) | 15ff06b6aaf02807fd0bef15f6badce9fd698173aef45c5d80316e2571cafa93 |
| [Preview/Protocols/Gun/GrpcSession.hpp](I:/code/Prism/Preview/Protocols/Gun/GrpcSession.hpp) | 7f6ebc46167b20fbe39cffd4e0c3c1e311d6d026464860b175c8d0d123c62065 |
| [Preview/Protocols/Gun/GrpcStream.hpp](I:/code/Prism/Preview/Protocols/Gun/GrpcStream.hpp) | 3cff9f29a4bc32c9ad69b8c201d519be1cc50c8bebb42209fb2583e64778e150 |
| [Preview/Protocols/Http2/Detail/ConnectionState.hpp](I:/code/Prism/Preview/Protocols/Http2/Detail/ConnectionState.hpp) | ae8e6eeb709a929df75475eb19fb5d7756600bf968514244a68a9b32663ba969 |
| [Preview/Protocols/Http2/Detail/FrameProcessor.hpp](I:/code/Prism/Preview/Protocols/Http2/Detail/FrameProcessor.hpp) | abda6c829b3c979ddfba697f97b150db65e19001b4144f7017bfd371370d3101 |
| [Preview/Protocols/Http3/Decoder.hpp](I:/code/Prism/Preview/Protocols/Http3/Decoder.hpp) | 1e0e12bd3f844b1b330841a961205d55d3713772aa444b1745d30b2c1c08db67 |
| [Preview/Protocols/Http3/Detail/SessionCallbacks.hpp](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp) | 4c77ab2bbc882e8be35887bc670ae1bf99d3f1abe6cda97baabb9c38e8f61750 |
| [Preview/Protocols/Http3/Detail/SessionLifecycle.hpp](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionLifecycle.hpp) | 5131439130052e8236f72f12ec4da8eef7b512d4f31084f1b1983a121954ad3e |
| [Preview/Protocols/Http3/NativeClient.hpp](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp) | 3f39f1125eec03949fbb5988532f49a0886c1c2c86b1f0d7ce124577b2636462 |
| [Preview/Protocols/Hysteria2/DatagramSession.hpp](I:/code/Prism/Preview/Protocols/Hysteria2/DatagramSession.hpp) | 5189c34cd232a1d43157c38c3dbac50178966362d248d7de2a5ae4840e0417ca |
| [Preview/Protocols/Mux/RootSession.hpp](I:/code/Prism/Preview/Protocols/Mux/RootSession.hpp) | 9e5cf7bb6cf8da8e8ec509c2f3bc577e36d6268531bbc94fa2be280ebd8aec3f |
| [Preview/Protocols/Mux/Stream.hpp](I:/code/Prism/Preview/Protocols/Mux/Stream.hpp) | 8f6a7c96b5250c526f670296deeca069c99502c955a4190987aee97f73d09754 |
| [Preview/Protocols/Mux/StreamState.hpp](I:/code/Prism/Preview/Protocols/Mux/StreamState.hpp) | 4eb62b28824faab42361ca36305287e9acdb08a13fb16b28bec4382eb251e6c1 |
| [Preview/Protocols/Shadowsocks2022/GatewayState.hpp](I:/code/Prism/Preview/Protocols/Shadowsocks2022/GatewayState.hpp) | eed107e13831f51fec241fab03969250408f213d7ebd2766be792822ea98d770 |
| [Preview/Protocols/Shadowsocks2022/Ss2022Gateway.hpp](I:/code/Prism/Preview/Protocols/Shadowsocks2022/Ss2022Gateway.hpp) | 13465ff3d0aeda17018c14f148a038e970b13e8f7ae9056bcffeeab0a87c242c |
| [Preview/Protocols/Socks5/Binding.hpp](I:/code/Prism/Preview/Protocols/Socks5/Binding.hpp) | 686a60bf57d7430b885573fa9f5fbe7528c4395c09e6e255e6f3dd07fc5b18bd |
| [Preview/Protocols/Socks5/UdpAssoc.hpp](I:/code/Prism/Preview/Protocols/Socks5/UdpAssoc.hpp) | 0ad5e473e021b158b80c90d06fb64fb39d5e5fc40798123327d6fd0004ac2d26 |
| [Preview/Protocols/Trusttunnel/Http2Client.hpp](I:/code/Prism/Preview/Protocols/Trusttunnel/Http2Client.hpp) | 542f8daaed84bec67dbdddd159f95026c38d5447f600f1149a3268ccdd162d33 |
| [Preview/Protocols/Trusttunnel/Http2Stream.hpp](I:/code/Prism/Preview/Protocols/Trusttunnel/Http2Stream.hpp) | a19d2aab24d2d8c50f64010fdd709fcac868c448fb916399502ed8cbe7fed27d |
| [Preview/Protocols/Trusttunnel/Http2Wire.hpp](I:/code/Prism/Preview/Protocols/Trusttunnel/Http2Wire.hpp) | 34491807c496648811072a2eec327c0cf967006e94c56077e3e894c3ec9f2304 |
| [Preview/Protocols/Vless/UdpTunnel.hpp](I:/code/Prism/Preview/Protocols/Vless/UdpTunnel.hpp) | 85a9cc62af32b9d6e54e16cd24e83be79dedf32c6ed963f821ac526106967071 |
| [Preview/Protocols/Xhttp/SplitClient.hpp](I:/code/Prism/Preview/Protocols/Xhttp/SplitClient.hpp) | 716b9ee611827ba4ba19a4a7dcc53328be5ffe3136fc3993e714993e8a420850 |
| [Preview/Protocols/Xhttp/SplitServer.hpp](I:/code/Prism/Preview/Protocols/Xhttp/SplitServer.hpp) | ced641255e290791e038b643af8e521f624f9a8fd49235c6ee326ffcdde697ab |
| [Preview/Protocols/Xhttp/StreamClient.hpp](I:/code/Prism/Preview/Protocols/Xhttp/StreamClient.hpp) | f8020720fa4e28cf1b2f6604b1685f9622e7a9cb622a1c2da8b10ded5b81c33d |
| [Preview/Protocols/Xhttp/StreamServer.hpp](I:/code/Prism/Preview/Protocols/Xhttp/StreamServer.hpp) | 22a61628c7ae4e7912bd9de17d26b0f382130d67010a83c4d7f0157d710ab0d3 |
| [Preview/Protocols/Xhttp/StreamTransport.hpp](I:/code/Prism/Preview/Protocols/Xhttp/StreamTransport.hpp) | 150807dfe40c17632452eb006da6b4dac5ac6ce6b36238302b81c903104b33a5 |
| [Preview/Runtime/Middleware/Context.hpp](I:/code/Prism/Preview/Runtime/Middleware/Context.hpp) | d1f3194704273f7149e5719c42d869fc3e52289b7ea7510e6dda5f417624afe2 |
| [Preview/Runtime/Middleware/Pipeline.hpp](I:/code/Prism/Preview/Runtime/Middleware/Pipeline.hpp) | 48a972a21b38600bd906732c7aab8df652e2f8c144b4f548eb22e7843176aa6f |
| [Preview/Runtime/Session/DataPlaneRelay.hpp](I:/code/Prism/Preview/Runtime/Session/DataPlaneRelay.hpp) | 7e1eefcb73829f2ba67bf57682593758800848d6e5f6f04bda36a011ac016190 |
| [Preview/Runtime/Session/RecognitionAdmission.hpp](I:/code/Prism/Preview/Runtime/Session/RecognitionAdmission.hpp) | 8585f059b833de63efc19e2945013ccf6466aa1a74ab669a3437a7212fa9c19a |
| [Preview/Runtime/Session/RecognitionLogging.hpp](I:/code/Prism/Preview/Runtime/Session/RecognitionLogging.hpp) | f4ed7a4ed8cfbd66c4bd10ad62142a8f9e5eb946e5756640984f6e15b009d464 |
| [Preview/Runtime/Statistics.hpp](I:/code/Prism/Preview/Runtime/Statistics.hpp) | b850aa5f8afd4098e5796e9a5fe68e19d7ee3633d59b29ddc8bbbe92bd82d9b8 |
| [Preview/Runtime/Worker.hpp](I:/code/Prism/Preview/Runtime/Worker.hpp) | 4a9cd64c136b9c391b8d94abedeb526eeaa40bec550b0857af3d3b101e381c68 |
| [Preview/Statistics/EventRing.hpp](I:/code/Prism/Preview/Statistics/EventRing.hpp) | 75769408e026b482417988f82607059ef64e1bd2d17ecb74af6c009065680bf9 |
| [Preview/Statistics/Redaction.hpp](I:/code/Prism/Preview/Statistics/Redaction.hpp) | a1593449d6e398e02a17bb82c61733d3edb951b6f679ce0c32f2680375a1e9c8 |
| [Preview/Statistics/Types.hpp](I:/code/Prism/Preview/Statistics/Types.hpp) | e03fd1a2cde8cab843ddc013f3d35e55d50ab8427c15b565b90b272dab9f8069 |
| [build/_deps/boost_src-src/boost/asio/impl/detached.hpp](I:/code/Prism/build/_deps/boost_src-src/boost/asio/impl/detached.hpp) | 1b9f180c6443b9d8e43b92db0c8a258c8c28c067c9da67743826994cf45bd6b5 |
| [build/_deps/spdlog-src/include/spdlog/details/mpmc_blocking_q.h](I:/code/Prism/build/_deps/spdlog-src/include/spdlog/details/mpmc_blocking_q.h) | 66ed3083a98e5cc142aa8d9dc18ce8de5ff32f82382386546f6ff302a01fc6c6 |
| [tests/Preview/core/diagnose/ContextLifetimeTest.cpp](I:/code/Prism/tests/Preview/core/diagnose/ContextLifetimeTest.cpp) | 3381c649f399ac67d5903019fd87734a338beb099e4357df41cdb3e94ce4c017 |
| [tests/Preview/protocols/http2/H2CodecTest.cpp](I:/code/Prism/tests/Preview/protocols/http2/H2CodecTest.cpp) | ab72d83760c87d405d09fd4b9872244fa5c66eec2ad86e9b390b2d373a89f737 |

## 10. 审查结束前的源码变更对照

正文形成后，其他工作继续更新了 11 个生产头文件。本报告保留发现快照和随后快照，避免把已经修改的代码继续写成当前缺陷。

- Q24：StreamOne 客户端和服务端已采用 WeakState/具名 handler，所列强引用环在当前源码中已解除；没有重跑运行验证。SplitClient/SplitServer 的 Q25 不因此自动通过。
- Q50：只是把长 lambda 提取成具名 driver；RunClientDriver/RunServerDriver 中 Feed/读取准备仍在局部 try 外，尾部通知仍可能被异常跳过。本地 detached_handler 忽略异常 completion 的解释保持有效。
- Runtime 的 Listener/Session/Registration/识别代码也被更新，正文中宽 Middleware Context、Application 的特定协议装配、管理命令实际范围等相关文件保持其已核对行为；本轮不对其他工作变更进行签收。

当前补充快照：[2026-10-08-preview-quality-current.json](2026-10-08-preview-quality-current.json)。641 个头文件、5119 函数定义、458 lambda、5678 声明器；8 超长函数、58 lambda 跨度告警、99 参数告警，共 165 位置、85 文件。未分类解析错误仍为 0，默认参数恢复 133。

原 178 告警是正文发现快照，不能冒充随后快照的当前数目。参数中固定回调位置 40 个。

### 10.1 变更文件及随后 SHA-256

| 文件 | 随后 SHA-256 |
|---|---|
| [Preview/Protocols/Xhttp/StreamClient.hpp](I:/code/Prism/Preview/Protocols/Xhttp/StreamClient.hpp) | 8441c709c9fbb46e563f4346ab3ef8cef111ae2b0ae4039e8e129a29f6cb570c |
| [Preview/Protocols/Xhttp/StreamServer.hpp](I:/code/Prism/Preview/Protocols/Xhttp/StreamServer.hpp) | a46a05ff0407f26459d6bc4d74996ca0751badbc9ae45b1074bf5bdddf5704d0 |
| [Preview/Runtime/Listener.hpp](I:/code/Prism/Preview/Runtime/Listener.hpp) | 7449e939dee398ece5c150c9d5ca6ab02772db35883edaa5278c55c6aafd3694 |
| [Preview/Runtime/Recognition/ConfiguredMode.hpp](I:/code/Prism/Preview/Runtime/Recognition/ConfiguredMode.hpp) | 1ea2a5c03cc73c41bff9f2e7282784153e57f837584ec42e198a59342bfbc5b5 |
| [Preview/Runtime/Recognition/MixedTrialMode.hpp](I:/code/Prism/Preview/Runtime/Recognition/MixedTrialMode.hpp) | 1223f346adc8286055e2d01298352750843355a2c31dc10e710a16adcfdeebbf |
| [Preview/Runtime/Session.hpp](I:/code/Prism/Preview/Runtime/Session.hpp) | 508f68665013b7c3c0e61ddd7ded29cf6a8db51aa4e371a5868ea21a50cb03ce |
| [Preview/Runtime/SessionRegistry.hpp](I:/code/Prism/Preview/Runtime/SessionRegistry.hpp) | 5d7dc39f6f45c2b45ff1efd3d449382d04b7f0618a95f743a289b3050e7bddf2 |
| [Preview/Runtime/SessionRegistryModel.hpp](I:/code/Prism/Preview/Runtime/SessionRegistryModel.hpp) | 0e86914eb304a8e1e1f3d8a85960259016aabf6b9058671d137ba8630137c65c |
| [Preview/Runtime/SessionRegistryStorage.hpp](I:/code/Prism/Preview/Runtime/SessionRegistryStorage.hpp) | d83a5aa91719b7a2c15520a32034e25b6227652fe20197cba9cbe7f0542393c0 |
| [Preview/Runtime/Session/RecognitionAdmission.hpp](I:/code/Prism/Preview/Runtime/Session/RecognitionAdmission.hpp) | 1c8946eeb85f7cb06629b304e4370af64c6af7d873f9999fe505ad1715b26270 |
| [Preview/Runtime/Session/RunContext.hpp](I:/code/Prism/Preview/Runtime/Session/RunContext.hpp) | 2846f1ed94e7553c5215a0748beda3ffeeae176373964a8b2ab53746edda34ac |

### 10.2 随后快照全部结构告警

| 类型 | 文件位置 | 名称/形态 | 数量 | 说明 |
|---|---|---|---:|---|
| parameters | [Preview/Application/Assembly/AccountAssembly.hpp:226](I:/code/Prism/Preview/Application/Assembly/AccountAssembly.hpp:226) | AccountMatchesQuicCredential | 4 | 领域/结构规则审查项 |
| lambda | [Preview/Application/BoundaryStartup.hpp:286](I:/code/Prism/Preview/Application/BoundaryStartup.hpp:286) | lambda | 21 | 领域/结构规则审查项 |
| lambda | [Preview/Application/BoundaryStartup.hpp:165](I:/code/Prism/Preview/Application/BoundaryStartup.hpp:165) | lambda | 19 | 领域/结构规则审查项 |
| parameters | [Preview/Application/Configuration/Validation/ProtocolIndependentValidation.hpp:384](I:/code/Prism/Preview/Application/Configuration/Validation/ProtocolIndependentValidation.hpp:384) | ReadScriptNumber | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Application/Configuration/Validation/ProtocolIndependentValidation.hpp:162](I:/code/Prism/Preview/Application/Configuration/Validation/ProtocolIndependentValidation.hpp:162) | ValidateServerNameList | 5 | 领域/结构规则审查项 |
| parameters | [Preview/Application/Configuration/Validation/ReferenceValidation.hpp:350](I:/code/Prism/Preview/Application/Configuration/Validation/ReferenceValidation.hpp:350) | ValidateProtocolBindings | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Application/Configuration/Validation/ReferenceValidation.hpp:239](I:/code/Prism/Preview/Application/Configuration/Validation/ReferenceValidation.hpp:239) | ValidateProtocols | 5 | 领域/结构规则审查项 |
| lambda | [Preview/Application/Main/PreviewMain.hpp:40](I:/code/Prism/Preview/Application/Main/PreviewMain.hpp:40) | lambda | 24 | 领域/结构规则审查项 |
| lambda | [Preview/Application/OperationsStartup.hpp:316](I:/code/Prism/Preview/Application/OperationsStartup.hpp:316) | lambda | 40 | 领域/结构规则审查项 |
| lambda | [Preview/Application/OperationsStartup.hpp:275](I:/code/Prism/Preview/Application/OperationsStartup.hpp:275) | lambda | 28 | 领域/结构规则审查项 |
| lambda | [Preview/Application/ProtocolAcceptors.hpp:188](I:/code/Prism/Preview/Application/ProtocolAcceptors.hpp:188) | lambda | 11 | 领域/结构规则审查项 |
| parameters | [Preview/Application/ProtocolProfile.hpp:224](I:/code/Prism/Preview/Application/ProtocolProfile.hpp:224) | AppendRecognitionCandidate | 10 | 领域/结构规则审查项 |
| lambda | [Preview/Composition/Recognition/AnytlsCarrier.hpp:57](I:/code/Prism/Preview/Composition/Recognition/AnytlsCarrier.hpp:57) | lambda | 23 | 领域/结构规则审查项 |
| parameters | [Preview/Composition/Recognition/CandidateRegistry.hpp:285](I:/code/Prism/Preview/Composition/Recognition/CandidateRegistry.hpp:285) | BuildFrom | 4 | 领域/结构规则审查项 |
| lambda | [Preview/Composition/Recognition/RestlsCarrier.hpp:149](I:/code/Prism/Preview/Composition/Recognition/RestlsCarrier.hpp:149) | lambda | 19 | 领域/结构规则审查项 |
| lambda | [Preview/Composition/Recognition/ShadowtlsCarrier.hpp:125](I:/code/Prism/Preview/Composition/Recognition/ShadowtlsCarrier.hpp:125) | lambda | 14 | 领域/结构规则审查项 |
| lambda | [Preview/Composition/Recognition/TlsCandidateFactory.hpp:74](I:/code/Prism/Preview/Composition/Recognition/TlsCandidateFactory.hpp:74) | lambda | 11 | 领域/结构规则审查项 |
| parameters | [Preview/Composition/Recognition/TlsCandidateFactory.hpp:30](I:/code/Prism/Preview/Composition/Recognition/TlsCandidateFactory.hpp:30) | Make | 4 | 领域/结构规则审查项 |
| lambda | [Preview/Composition/Recognition/TlsCarrierHelpers.hpp:174](I:/code/Prism/Preview/Composition/Recognition/TlsCarrierHelpers.hpp:174) | lambda | 51 | 领域/结构规则审查项 |
| parameters | [Preview/Composition/Recognition/TlsCarrierHelpers.hpp:167](I:/code/Prism/Preview/Composition/Recognition/TlsCarrierHelpers.hpp:167) | MakeGunServerAccept | 4 | 领域/结构规则审查项 |
| lambda | [Preview/Composition/Recognition/TlsCarrierHelpers.hpp:135](I:/code/Prism/Preview/Composition/Recognition/TlsCarrierHelpers.hpp:135) | lambda | 23 | 领域/结构规则审查项 |
| lambda | [Preview/Composition/Recognition/TlsCarrierHelpers.hpp:91](I:/code/Prism/Preview/Composition/Recognition/TlsCarrierHelpers.hpp:91) | lambda | 32 | 领域/结构规则审查项 |
| lambda | [Preview/Composition/Recognition/TlsCarrierHelpers.hpp:54](I:/code/Prism/Preview/Composition/Recognition/TlsCarrierHelpers.hpp:54) | lambda | 16 | 领域/结构规则审查项 |
| parameters | [Preview/Composition/Recognition/TlsRecognitionHelpers.hpp:113](I:/code/Prism/Preview/Composition/Recognition/TlsRecognitionHelpers.hpp:113) | InspectFeatures | 5 | 领域/结构规则审查项 |
| lambda | [Preview/Foundation/Utility/Diagnose/ContextState.hpp:370](I:/code/Prism/Preview/Foundation/Utility/Diagnose/ContextState.hpp:370) | lambda | 13 | 领域/结构规则审查项 |
| parameters | [Preview/Foundation/Utility/Diagnose/Detail/AsyncBackendState.hpp:80](I:/code/Prism/Preview/Foundation/Utility/Diagnose/Detail/AsyncBackendState.hpp:80) | AsyncBackendState | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp:269](I:/code/Prism/Preview/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp:269) | QueueFailure | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Foundation/Utility/Diagnose/Facade.hpp:184](I:/code/Prism/Preview/Foundation/Utility/Diagnose/Facade.hpp:184) | SubmitFormatted | 5 | 领域/结构规则审查项 |
| lambda | [Preview/Foundation/Utility/Diagnose/FieldCodec.hpp:28](I:/code/Prism/Preview/Foundation/Utility/Diagnose/FieldCodec.hpp:28) | lambda | 13 | 领域/结构规则审查项 |
| function | [Preview/Lifecycle/TaskRegistry.hpp:378](I:/code/Prism/Preview/Lifecycle/TaskRegistry.hpp:378) | SpawnTracked | 141 | 领域/结构规则审查项 |
| lambda | [Preview/Lifecycle/TaskRegistry.hpp:444](I:/code/Prism/Preview/Lifecycle/TaskRegistry.hpp:444) | lambda | 71 | 领域/结构规则审查项 |
| lambda | [Preview/Net/Dns/Answer.hpp:149](I:/code/Prism/Preview/Net/Dns/Answer.hpp:149) | lambda | 58 | 领域/结构规则审查项 |
| parameters | [Preview/Net/Dns/Detail/Fallback.hpp:82](I:/code/Prism/Preview/Net/Dns/Detail/Fallback.hpp:82) | ResolveFallback | 5 | 领域/结构规则审查项 |
| lambda | [Preview/Net/Dns/Format.hpp:529](I:/code/Prism/Preview/Net/Dns/Format.hpp:529) | lambda | 19 | 领域/结构规则审查项 |
| lambda | [Preview/Net/Dns/Format.hpp:438](I:/code/Prism/Preview/Net/Dns/Format.hpp:438) | lambda | 13 | 领域/结构规则审查项 |
| lambda | [Preview/Net/Dns/Resolver.hpp:516](I:/code/Prism/Preview/Net/Dns/Resolver.hpp:516) | lambda | 29 | 领域/结构规则审查项 |
| lambda | [Preview/Net/Dns/Upstream.hpp:223](I:/code/Prism/Preview/Net/Dns/Upstream.hpp:223) | lambda | 19 | 领域/结构规则审查项 |
| lambda | [Preview/Net/UdpRelay.hpp:86](I:/code/Prism/Preview/Net/UdpRelay.hpp:86) | lambda | 36 | 领域/结构规则审查项 |
| parameters | [Preview/Operations/Router.hpp:265](I:/code/Prism/Preview/Operations/Router.hpp:265) | Router | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Operations/Router.hpp:173](I:/code/Prism/Preview/Operations/Router.hpp:173) | State | 4 | 领域/结构规则审查项 |
| lambda | [Preview/Operations/Router.hpp:155](I:/code/Prism/Preview/Operations/Router.hpp:155) | lambda | 11 | 领域/结构规则审查项 |
| lambda | [Preview/Operations/Router.hpp:116](I:/code/Prism/Preview/Operations/Router.hpp:116) | lambda | 12 | 领域/结构规则审查项 |
| lambda | [Preview/Operations/Routes/HttpJson.hpp:454](I:/code/Prism/Preview/Operations/Routes/HttpJson.hpp:454) | lambda | 44 | 领域/结构规则审查项 |
| function | [Preview/Operations/Routes/RequestParser.hpp:99](I:/code/Prism/Preview/Operations/Routes/RequestParser.hpp:99) | ParseRequest | 136 | 领域/结构规则审查项 |
| lambda | [Preview/Operations/Routes/RouteDispatch.hpp:434](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:434) | lambda | 12 | 领域/结构规则审查项 |
| parameters | [Preview/Operations/Routes/RouteDispatch.hpp:179](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:179) | ReadCorrelation | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Operations/Routes/RouteDispatch.hpp:165](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:165) | ReadBooleanParameter | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Operations/Routes/RouteDispatch.hpp:136](I:/code/Prism/Preview/Operations/Routes/RouteDispatch.hpp:136) | ReadParameter | 4 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Common/Address.hpp:121](I:/code/Prism/Preview/Protocols/Common/Address.hpp:121) | lambda | 32 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Gun/GrpcSession.hpp:210](I:/code/Prism/Preview/Protocols/Gun/GrpcSession.hpp:210) | lambda | 17 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Gun/GrpcSession.hpp:191](I:/code/Prism/Preview/Protocols/Gun/GrpcSession.hpp:191) | lambda | 19 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Gun/GrpcStream.hpp:206](I:/code/Prism/Preview/Protocols/Gun/GrpcStream.hpp:206) | lambda | 29 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Gun/GrpcStream.hpp:183](I:/code/Prism/Preview/Protocols/Gun/GrpcStream.hpp:183) | lambda | 23 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Http2/Codec.hpp:108](I:/code/Prism/Preview/Protocols/Http2/Codec.hpp:108) | EncodeInt | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Http2/Detail/FrameProcessor.hpp:251](I:/code/Prism/Preview/Protocols/Http2/Detail/FrameProcessor.hpp:251) | FinishHeaders | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Http2/Detail/FrameProcessor.hpp:37](I:/code/Prism/Preview/Protocols/Http2/Detail/FrameProcessor.hpp:37) | FrameProcessor | 5 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Http3/Auth.hpp:116](I:/code/Prism/Preview/Protocols/Http3/Auth.hpp:116) | ResponseHead | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:134](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:134) | Session::CbEndStream | 4 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:118](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:118) | Session::CbStopSending | 5 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:91](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:91) | Session::CbRecvData | 6 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:63](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:63) | Session::CbEndHeaders | 5 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:34](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:34) | Session::CbRecvHeader | 8 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:13](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionCallbacks.hpp:13) | Session::CbBeginHeaders | 4 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/Detail/SessionContract.hpp:197](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionContract.hpp:197) | SubmitResponseHeaders | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Http3/Detail/SessionContract.hpp:171](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionContract.hpp:171) | ReadResponseBody | 7 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/Detail/SessionContract.hpp:165](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionContract.hpp:165) | CbEndStream | 4 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/Detail/SessionContract.hpp:159](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionContract.hpp:159) | CbStopSending | 5 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/Detail/SessionContract.hpp:152](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionContract.hpp:152) | CbRecvData | 6 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/Detail/SessionContract.hpp:146](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionContract.hpp:146) | CbEndHeaders | 5 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/Detail/SessionContract.hpp:137](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionContract.hpp:137) | CbRecvHeader | 8 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/Detail/SessionContract.hpp:132](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionContract.hpp:132) | CbBeginHeaders | 4 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/Detail/SessionOutput.hpp:172](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionOutput.hpp:172) | Session::ReadResponseBody | 7 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/Detail/SessionOutput.hpp:135](I:/code/Prism/Preview/Protocols/Http3/Detail/SessionOutput.hpp:135) | Session::SubmitResponseHeaders | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Http3/Detail/Varint.hpp:83](I:/code/Prism/Preview/Protocols/Http3/Detail/Varint.hpp:83) | WriteVarint | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Http3/Detail/Varint.hpp:27](I:/code/Prism/Preview/Protocols/Http3/Detail/Varint.hpp:27) | ReadVarint | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Http3/NativeClient.hpp:551](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:551) | ReadRequestBody | 7 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/NativeClient.hpp:533](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:533) | CbResetStream | 5 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/NativeClient.hpp:528](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:528) | CbStopSending | 5 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/NativeClient.hpp:517](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:517) | CbEndStream | 4 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/NativeClient.hpp:511](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:511) | CbRecvData | 6 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/NativeClient.hpp:499](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:499) | CbEndHeaders | 5 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/NativeClient.hpp:465](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:465) | CbRecvHeader | 8 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Http3/NativeClient.hpp:453](I:/code/Prism/Preview/Protocols/Http3/NativeClient.hpp:453) | CbBeginHeaders | 4 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Hysteria2/Conn.hpp:65](I:/code/Prism/Preview/Protocols/Hysteria2/Conn.hpp:65) | Conn | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Quic/GatewayCommon.hpp:141](I:/code/Prism/Preview/Protocols/Quic/GatewayCommon.hpp:141) | RegisterTypedConnection | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Quic/GatewayCommon.hpp:108](I:/code/Prism/Preview/Protocols/Quic/GatewayCommon.hpp:108) | RegisterConnection | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Quic/NativeConnection.hpp:495](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:495) | NewConnectionId | 5 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Quic/NativeConnection.hpp:486](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:486) | VersionNegotiation | 4 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Quic/NativeConnection.hpp:478](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:478) | RecvDatagram | 5 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Quic/NativeConnection.hpp:471](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:471) | StreamClose | 6 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Quic/NativeConnection.hpp:461](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:461) | RecvStreamData | 8 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Quic/NativeConnection.hpp:454](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:454) | RecvCryptoData | 6 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Quic/NativeConnection.hpp:446](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:446) | AddHandshakeData | 4 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Quic/NativeConnection.hpp:440](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:440) | SetWriteSecret | 5 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Quic/NativeConnection.hpp:434](I:/code/Prism/Preview/Protocols/Quic/NativeConnection.hpp:434) | SetReadSecret | 5 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:303](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:303) | NativeConnection::NewConnectionId | 5 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:252](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:252) | NativeConnection::VersionNegotiation | 4 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:213](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:213) | NativeConnection::RecvDatagram | 5 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:193](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:193) | NativeConnection::StreamClose | 6 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:158](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:158) | NativeConnection::RecvStreamData | 8 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:146](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:146) | NativeConnection::RecvCryptoData | 6 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:92](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:92) | NativeConnection::AddHandshakeData | 4 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:69](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:69) | NativeConnection::SetWriteSecret | 5 | 固定第三方回调签名 |
| parameters | [Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:46](I:/code/Prism/Preview/Protocols/Quic/NativeConnectionCallbacks.hpp:46) | NativeConnection::SetReadSecret | 5 | 固定第三方回调签名 |
| function | [Preview/Protocols/Reality/Carrier.hpp:49](I:/code/Prism/Preview/Protocols/Reality/Carrier.hpp:49) | MakeFacadeCarrier | 139 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Reality/Carrier.hpp:54](I:/code/Prism/Preview/Protocols/Reality/Carrier.hpp:54) | lambda | 135 | 领域/结构规则审查项 |
| function | [Preview/Protocols/Reality/CarrierHandshake.hpp:67](I:/code/Prism/Preview/Protocols/Reality/CarrierHandshake.hpp:67) | ParseClientHello | 144 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Reality/KeyMaterial.hpp:229](I:/code/Prism/Preview/Protocols/Reality/KeyMaterial.hpp:229) | lambda | 15 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Reality/KeyMaterial.hpp:78](I:/code/Prism/Preview/Protocols/Reality/KeyMaterial.hpp:78) | lambda | 24 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Reality/SessionId.hpp:184](I:/code/Prism/Preview/Protocols/Reality/SessionId.hpp:184) | lambda | 16 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Reality/Tls13.hpp:339](I:/code/Prism/Preview/Protocols/Reality/Tls13.hpp:339) | DecryptTlsRecord | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Reality/Tls13.hpp:310](I:/code/Prism/Preview/Protocols/Reality/Tls13.hpp:310) | EncryptTlsRecord | 5 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Reality/Tls13.hpp:142](I:/code/Prism/Preview/Protocols/Reality/Tls13.hpp:142) | Aes128GcmOpen | 5 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Reality/Tls13.hpp:85](I:/code/Prism/Preview/Protocols/Reality/Tls13.hpp:85) | Aes128GcmSeal | 5 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Reality/Tls13.hpp:56](I:/code/Prism/Preview/Protocols/Reality/Tls13.hpp:56) | ExpandTls13Label | 4 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Restls/Carrier.hpp:86](I:/code/Prism/Preview/Protocols/Restls/Carrier.hpp:86) | lambda | 76 | 领域/结构规则审查项 |
| function | [Preview/Protocols/Restls/Conn.hpp:142](I:/code/Prism/Preview/Protocols/Restls/Conn.hpp:142) | async_read_some | 147 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Shadowsocks2022/ChunkCodec.hpp:250](I:/code/Prism/Preview/Protocols/Shadowsocks2022/ChunkCodec.hpp:250) | AeadOpen | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Shadowsocks2022/ChunkCodec.hpp:125](I:/code/Prism/Preview/Protocols/Shadowsocks2022/ChunkCodec.hpp:125) | AeadSeal | 5 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Shadowsocks2022/ChunkCodec.hpp:65](I:/code/Prism/Preview/Protocols/Shadowsocks2022/ChunkCodec.hpp:65) | AeadSeal | 4 | 领域/结构规则审查项 |
| function | [Preview/Protocols/Shadowsocks2022/ResponseCodec.hpp:451](I:/code/Prism/Preview/Protocols/Shadowsocks2022/ResponseCodec.hpp:451) | ParseUdpPacket | 146 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Shadowtls/Carrier.hpp:44](I:/code/Prism/Preview/Protocols/Shadowtls/Carrier.hpp:44) | lambda | 30 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Shadowtls/RecordProtector.hpp:151](I:/code/Prism/Preview/Protocols/Shadowtls/RecordProtector.hpp:151) | RecordProtector | 6 | 领域/结构规则审查项 |
| function | [Preview/Protocols/Shadowtls/Server.hpp:204](I:/code/Prism/Preview/Protocols/Shadowtls/Server.hpp:204) | Run | 151 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Socks5/ConnHandshake.hpp:72](I:/code/Prism/Preview/Protocols/Socks5/ConnHandshake.hpp:72) | WriteHandshake | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Trojan/Conn.hpp:66](I:/code/Prism/Preview/Protocols/Trojan/Conn.hpp:66) | Conn | 4 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Trusttunnel/Http2Client.hpp:198](I:/code/Prism/Preview/Protocols/Trusttunnel/Http2Client.hpp:198) | lambda | 37 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Trusttunnel/Http2Client.hpp:158](I:/code/Prism/Preview/Protocols/Trusttunnel/Http2Client.hpp:158) | lambda | 17 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Tuic/Conn.hpp:54](I:/code/Prism/Preview/Protocols/Tuic/Conn.hpp:54) | Conn | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Tuic/ConnSession.hpp:40](I:/code/Prism/Preview/Protocols/Tuic/ConnSession.hpp:40) | ConnSession | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Vless/Conn.hpp:63](I:/code/Prism/Preview/Protocols/Vless/Conn.hpp:63) | Conn | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Vmess/AuthCrypto.hpp:148](I:/code/Prism/Preview/Protocols/Vmess/AuthCrypto.hpp:148) | ValidAesGcmInput | 4 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Vmess/AuthId.hpp:98](I:/code/Prism/Preview/Protocols/Vmess/AuthId.hpp:98) | lambda | 16 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Vmess/AuthKdf.hpp:38](I:/code/Prism/Preview/Protocols/Vmess/AuthKdf.hpp:38) | lambda | 19 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Vmess/AuthKdf.hpp:43](I:/code/Prism/Preview/Protocols/Vmess/AuthKdf.hpp:43) | lambda | 13 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Vmess/Conn.hpp:48](I:/code/Prism/Preview/Protocols/Vmess/Conn.hpp:48) | Conn | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Vmess/ConnSession.hpp:38](I:/code/Prism/Preview/Protocols/Vmess/ConnSession.hpp:38) | ConnSession | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Xhttp/Entry.hpp:22](I:/code/Prism/Preview/Protocols/Xhttp/Entry.hpp:22) | Connect | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Xhttp/SplitClient.hpp:247](I:/code/Prism/Preview/Protocols/Xhttp/SplitClient.hpp:247) | ConnectSplit | 4 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Xhttp/SplitClient.hpp:197](I:/code/Prism/Preview/Protocols/Xhttp/SplitClient.hpp:197) | lambda | 29 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Xhttp/SplitClient.hpp:129](I:/code/Prism/Preview/Protocols/Xhttp/SplitClient.hpp:129) | lambda | 28 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Xhttp/SplitClient.hpp:94](I:/code/Prism/Preview/Protocols/Xhttp/SplitClient.hpp:94) | lambda | 17 | 领域/结构规则审查项 |
| lambda | [Preview/Protocols/Xhttp/SplitServer.hpp:358](I:/code/Prism/Preview/Protocols/Xhttp/SplitServer.hpp:358) | lambda | 35 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Xhttp/SplitServer.hpp:154](I:/code/Prism/Preview/Protocols/Xhttp/SplitServer.hpp:154) | HandleSplitServerHeaders | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Xhttp/StreamClient.hpp:283](I:/code/Prism/Preview/Protocols/Xhttp/StreamClient.hpp:283) | ConnectStream | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Protocols/Xhttp/StreamTransport.hpp:265](I:/code/Prism/Preview/Protocols/Xhttp/StreamTransport.hpp:265) | WriteRequest | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Runtime/Listener.hpp:128](I:/code/Prism/Preview/Runtime/Listener.hpp:128) | AdmissionRequest | 7 | 领域/结构规则审查项 |
| parameters | [Preview/Runtime/Recognition/RawIngressProbe.hpp:115](I:/code/Prism/Preview/Runtime/Recognition/RawIngressProbe.hpp:115) | Rejected | 4 | 领域/结构规则审查项 |
| lambda | [Preview/Runtime/Recognition/Route.hpp:92](I:/code/Prism/Preview/Runtime/Recognition/Route.hpp:92) | lambda | 13 | 领域/结构规则审查项 |
| lambda | [Preview/Runtime/SessionControl.hpp:500](I:/code/Prism/Preview/Runtime/SessionControl.hpp:500) | lambda | 14 | 领域/结构规则审查项 |
| lambda | [Preview/Runtime/SessionControl.hpp:360](I:/code/Prism/Preview/Runtime/SessionControl.hpp:360) | lambda | 11 | 领域/结构规则审查项 |
| parameters | [Preview/Runtime/SessionControl.hpp:204](I:/code/Prism/Preview/Runtime/SessionControl.hpp:204) | ReportErrorOnExecutor | 4 | 领域/结构规则审查项 |
| lambda | [Preview/Runtime/Session/LogState.hpp:92](I:/code/Prism/Preview/Runtime/Session/LogState.hpp:92) | lambda | 14 | 领域/结构规则审查项 |
| parameters | [Preview/Runtime/Session/RecognitionLogging.hpp:316](I:/code/Prism/Preview/Runtime/Session/RecognitionLogging.hpp:316) | WriteRecognitionFailure | 7 | 领域/结构规则审查项 |
| parameters | [Preview/Runtime/Session/RecognitionLogging.hpp:243](I:/code/Prism/Preview/Runtime/Session/RecognitionLogging.hpp:243) | WriteLog | 4 | 领域/结构规则审查项 |
| parameters | [Preview/Runtime/Session/RecognitionLogging.hpp:52](I:/code/Prism/Preview/Runtime/Session/RecognitionLogging.hpp:52) | WriteRecognition | 5 | 领域/结构规则审查项 |
| function | [Preview/Statistics/Redaction.hpp:96](I:/code/Prism/Preview/Statistics/Redaction.hpp:96) | RedactSensitiveText | 121 | 领域/结构规则审查项 |
| lambda | [Preview/Transport/Connector.hpp:442](I:/code/Prism/Preview/Transport/Connector.hpp:442) | lambda | 35 | 领域/结构规则审查项 |
| parameters | [Preview/Transport/Connector.hpp:363](I:/code/Prism/Preview/Transport/Connector.hpp:363) | PostCompletion | 4 | 领域/结构规则审查项 |
| lambda | [Preview/Transport/Connector.hpp:234](I:/code/Prism/Preview/Transport/Connector.hpp:234) | lambda | 17 | 领域/结构规则审查项 |
| lambda | [Preview/Transport/Connector.hpp:175](I:/code/Prism/Preview/Transport/Connector.hpp:175) | lambda | 41 | 领域/结构规则审查项 |
| lambda | [Preview/Transport/Encrypted.hpp:360](I:/code/Prism/Preview/Transport/Encrypted.hpp:360) | lambda | 14 | 领域/结构规则审查项 |
| lambda | [Preview/Transport/Reliable.hpp:238](I:/code/Prism/Preview/Transport/Reliable.hpp:238) | lambda | 12 | 领域/结构规则审查项 |
| lambda | [Preview/Transport/Transmission.hpp:210](I:/code/Prism/Preview/Transport/Transmission.hpp:210) | lambda | 17 | 领域/结构规则审查项 |
| lambda | [Preview/Transport/Transmission.hpp:167](I:/code/Prism/Preview/Transport/Transmission.hpp:167) | lambda | 17 | 领域/结构规则审查项 |

### 10.3 快照之后仍有并行修改

最后链接核对时，SessionRegistryStorage.hpp 又发生更新（观察到的 SHA-256：519b003af4122cf807b3f44fe57d753394622156d03d9cc831f20c4a2acebe09）。它没有被正文作为具体缺陷的主证据；本报告的全量数字绑定 quality-current.json 的捕获时间，后续版本应按自己的 hash 复核，不能宣称工作树从此不变。
