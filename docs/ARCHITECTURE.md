# Prism 架构：Preview 主线与 legacy 参考

本文档先描述当前 Preview，再保留后面的旧版四层资料。审查 Preview 时沿 [`Preview/Application/Main/PreviewMain.hpp`](../Preview/Application/Main/PreviewMain.hpp)、[`Preview/Application/Startup/Start.hpp`](../Preview/Application/Startup/Start.hpp)、[`Preview/Runtime/Session.hpp`](../Preview/Runtime/Session.hpp) 和 [`Preview/Boundary/`](../Preview/Boundary/) 追踪真实路径；`include/prism/`、`src/prism/` 的旧工厂、旧资源容器和旧测试只能作为 legacy 对照。

维护快照：2026-10-09。本文档是源码/CMake 结构说明，不是当前全量 CTest、真实请求、第三方互操作或性能通过报告。

## 2026-10-09 11:15 当前验收范围

Preview 当前生产源码为 640 个 header、0 个生产 `.cpp`，入口由 `Application/Main/PreviewMain.hpp` 编译。MinGW 的根构建契约统一传递 `BOOST_ASIO_HAS_PTHREADS=1`，防止标准库与 Asio 的 include 顺序改变线程类型 ABI。原配置化 TCP 工厂超时用例、100 次重复中的 600 次启动停机以及 Application 32/32 focused 已在新二进制上通过，证据分别见 [ABI 回归](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-asio-backend-regression-green.log) 和 [Application focused](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-asio-app-32-green.log)。

当前 Main SHA256 为 `EFB86D372401DC81EF712D7EA33E5A3C4429E4282B3EC6B2666DE3EECB1744E0`。其 [Provider Application](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-new-abi-provider/cases.json) 18 个场景通过，19 个本任务进程已退出且 live 临时目录已清理；该 harness 的主动终止不作为 Main 优雅停机证明。TUIC 20 轮正在验证自然 drain；Hysteria2、structured Mihomo、417 目标整体构建、当前全量 CTest、性能、独立头与严格 ODR 仍须分别签收。

测试 owner 映射、600/800 行约束和无兼容层要求按当前 AGENTS 执行，源码风格和异常路径收口尚未全部完成。MuxRealRoot 的 64 MiB/64 KiB、45 cases/105 lanes 与 TransferP01 的 256 MiB/64 KiB、4096 blocks 分属不同测量合同。旧 Main 与旧测量继续只对应各自原始输入，详见 [执行状态](preview-refactor/2026-10-03-preview-no-compat-status.md)。

## 2026-10-09 新 ABI 之前的历史检查点

以下内容记录当时快照，其中的“当前”仅指该历史时点，不用于签收上面的新 ABI 二进制。

测试映射已按实际生产 owner 收口：`Application/Configuration` 负责配置，`Composition` 负责编译装配，`Lifecycle` 负责取消与 drain，`Boundary` 负责 socket/CID，`Runtime` 负责调度与 Session，各 `Protocols/<Name>` 负责独立 wire/session；只有真实跨模块请求进入按协议与场景细分的 `Integration`，独立实验归 `tests/Experiments`，`Common` 只覆盖真实 Common 契约。测试正文仅放 `.cpp`（不超过 800 行），共享 HPP 需有多个 CPP 的真实共同封装；项目自有标识符 PascalCase、中文 Doxygen，函数不超过 120 行、lambda 不超过 10 行、参数通常不超过 2 个（复杂边界最多 3 个）。不保留旧分类、旧 target 或兼容入口。当前生产源为 live640 headers、0 个 Preview 生产 `.cpp`；这个源码层事实不代替构建、测试或请求验收。

当前 `Preview/Protocols/Mux/Stream.hpp` 源 SHA256 为 `82718A908A656B9667DE3DBC51AF7EE8A19DBF4D81270F74D9FC422A1E4EF82A`。retired handle 的 `Tasks == nullptr` 是合法终态，`CloseOnExecutor` 只做同 executor 幂等关闭并跳过不存在的 task/wire；构造时非空强合同保留，不恢复旧 API。独立回归由 crash `-1073741819` RED 收口到 `Decorator` 11/11 GREEN；原 Mux 122/128、6 fail 和 XML 仍是原始范围，同一 6 项新源码重跑 6/6 GREEN，不等于 128 或全量当前通过。

DNS cache 仅 validate-only exit0，540-row matrix 未完成；DNS Session 在 client 未 half-close 的首轮 hang 后补 `Shutdown`，真实 1/1 natural exit0。ListenerAdmission 6、SessionOrchestration 9、SessionServices 6 均 natural exit0；Session 19 target/100 CTest 属 Stream 修复前历史快照。Root 已在 live640 Tree 上完成当前 Main build，`build/src/PrismPreview.exe` SHA256 `431CE70117019FC0A46F2C76087BB6B5F02A3BE5D514BF6DFB0A0454F802FD5E`；`coordinator-9-tree-contained-provider.log` 记录 Provider Application interop 18 cases，Root 另记录 19 个 owned PID 已清理。该结果仍只覆盖限定 Application/provider 场景，不能扩大为全量当前 runtime；`D535...`、6B6/32DA、Hysteria/TUIC 140 次和 structured Mihomo 只绑定历史 EXE。

Standalone 60 rows 的 54 pass/6 blocked/0 fail、exit2 只绑定其历史 EXE，six interface/unavailable 仍 pending。Transfer 当前 45 groups/105 lanes/9 summaries 实际 exit0；scatter 成本偏高仅是 baseline，未据此声明性能改善或采用生产算法。当前 source gate 为 live640 production headers、0 production `.cpp`，通过仅证明源码层。Root 已完成 live640 Main 重编；全量 CTest、严格风格、Main 全互操作、性能对照、ODR、Linux、旧对象精确清理和 production shell audit 仍未闭合。

上海 2026-10-08 21:30 历史检查点：测试正在逐用例按 Preview 的生产 owner 对齐。Boundary 的 socket/CID、Composition 的配置装配、Runtime 的调度与 Session、各 Protocols 的独立 wire/session、Foundation/Lifecycle/Net/Operations/Statistics/Transport 的正式契约各有自己的测试目录。真正跨模块的请求路径按 Integration/Session 的协议与场景细分；独立 golden/fuzz 回到单协议 leaf，Common 只测试实际 Common 契约。旧版 prism 测试已从 Preview 树迁回旧版模块，实验单独登记；不保留旧分类或 target 的兼容入口。

测试仅 CPP 承载用例正文，最多800物理行；真正多 CPP 共用的封装才使用模块共享 HPP。函数120行、lambda10行、参数通常2/复杂3、PascalCase 与中文 Doxygen 正在按模块整改，静态 AST 结果必须再经实际编译和行为检查。新布局 CMake 的 target graph、exact case、生产/测试 closure 已重新配置通过；本轮编译暴露部分缺声明、重复类型和错误调用，Root 正在精确修复。源码结构门禁通过、部分 target 链接通过都不能代表严格风格或最终全量通过。

当前生产 Main EXE SHA256 为6B6BD58D8C5E9B741D7CD09C9060563F862A041F2B4C0C4824A946071D14279E，已取得限定 Hysteria2、TUIC20轮/140次、SOCKS5 literal/structured终止证据。standalone互操作矩阵当前54通过/6阻断/0失败，退出码2诚实保留未覆盖项；其Hysteria2夹具的头与payload分段提前FIN已由真实2项RED到3项GREEN证明并修正。这些不替代全协议Main、同输入五轮性能、最终全量CTest、严格ODR和Linux验收。详细原始证据与当前剩余项见[执行状态](preview-refactor/2026-10-03-preview-no-compat-status.md)和[实施台账](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/progress.md)。

以下21:30、17:50及更早段落保留历史检查点范围，不能当作最新源码或新测试布局通过结果。

上海 2026-10-08 17:50 历史检查点：Preview 仍在实施中，当前源码、生产接口和测试夹具尚未形成最终验收快照。真实 owner 链为 `Application/Startup` 冷路径 generation 与 typed `ProtocolServices::Prepare/Bind`，经 `ProtocolProfile::MakeTcpProfile` 发布 immutable profile/resolver，Runtime/Boundary 消费已编译 typed data-plane，具体协议目录拥有 wire、认证、stream/datagram 和 close/drain；名称解析不进入热路径。该结构说明不等于全量测试、当前 Main、standalone 互操作或性能通过。

当前分层证据：Root92389 的现有 Makefile2 12-target aggregate0 是此前构建层证据，Hys/Gun 等后续 source change 仍需 fresh recompile。Root 的完整当前 CTest 为 `4896 registered / 25 disabled / 4871 participating / 23 failed-or-not-run / EXIT8`，原始 [`parallel-full-current-ctest.log`](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/parallel-full-current-ctest.log) 和 XML 保留真实失败，不宣称全量通过。Context 1、Ownership 4、DNS 14、CanonicalDatagram 2、Adapter 14 共 35/35 fresh focused 通过；Go config 1 与旧 GoCompat 4 仅证明旧层。Hysteria 标准 response 的两个正向 regression 曾实际 RED，variant/string source fix 尚未 fresh green；GunOwned、RawWriteCancellation、Stream owner guard 等仍待当前批次重编，不能写成已验收。

Main `5769C3...` 的 TUIC20轮/140次单拨号及 Hysteria 正负 TCP/UDP 结果只绑定后续已变化的历史 snapshot，不再称最终当前 Main；`B38A...`、`1B72...` 继续保留为历史限定数据。`PreviewInteropMatrix` 当前仍是 standalone preview-only protocol harness，不能冒充 Main inner protocol 或全 carrier 互操作；当前性能也未完成统一验收。执行计划、台账和 raw 状态分别见 [`2026-10-03-preview-no-compat-execution.md`](preview-refactor/2026-10-03-preview-no-compat-execution.md)、[`progress.md`](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/progress.md) 和上述 raw CTest 文件。D5 45-file manifest 当前只记录 `18 match / 26 drift / 1 retired-missing`，不更新为最终 hash 包。

12:41 的 B38 Main 是历史限定 snapshot：`B38A88E89CC54A93B0EDEAC58B15528E36741599BC516A4DA523087580390071` 曾有 Application/Provider focused 22/22、TUIC 20 轮/140 次、SOCKS5/SS2022 provider 18 场景和 Hysteria TCP/UDP 运行证据；随后发现 SOCKS5 多绑定 UDP 权限放大问题，且当前生产源码已继续变化。本段只保留其历史范围，不代表当前 Main。

16:16 的 Main `5769C3C1235598E036E45D2A55C05549E3491F6940F0C33ABA1A491FD7AA5A2F` 也只是历史限定 snapshot：TUIC 20 轮/140 次和 Hysteria 正负 TCP/UDP、自然 drain/exit0 证据位于既有 task-4-evidence 目录；后续生产变化使该 executable 不能作为最终当前 Main hash。

10月8日07:27历史限定运行证据：Main `1B726DC7154512A449666B9EDADF25079AB94821339C58422FBF147C43BC6A0F`、配置 `E8BCACB9DF18A410FC9BB999070056C413E41B9637DD021865186F2DDA3BBA9E` 的 SOCKS5 pending session 已完成真实 POST、Session Cancel、peer EOF、account/registry 归零和 Completed=1；运行期间 metadata 为 worker 1、account 1、generation 1、protocol 2、target `127.0.0.1:49293`，stream7/task9 的 `target_unsupported` HTTP400 被拒绝而 root literal 继续，traffic=72 无重复计数。同一历史 epoch 的 XUDP 限定结果为 109/109 字节、Completed=2、drops=0、两个 association 的 sibling continuation 和自然退出均已核对；TUIC 的 20 轮、140 次 client、单次拨号无 retry 属于旧 Main5295，尚未在 Main1B72 重跑。原始 JSON/XML 保存在现有 [`task-4-evidence`](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/) 目录。它们绑定各自当时的运行时源/配置快照，不能替代全量 CTest、Linux、第三方互操作或性能验收。

上述 `1B726...` 结果属于07:27历史限定请求 epoch，晚于 DA66 识别取消修复和当前统计/Session metadata 收口，但不能被引用为最新完整 Main 通过；QUIC、剩余 no-compat source、全量 CTest、ODR、Linux 和性能矩阵仍待验收。VMess 8/8、SS2022 5/5、TrustTunnel 5/5 的当前 runtime 结果只覆盖各自 target/epoch，不能扩大为全协议 Main 通过。旧 Main5295/BF 与旧 T20 结果继续作为历史快照保留。认证仍只有 [`Preview/Account/Authenticator.hpp`](../Preview/Account/Authenticator.hpp) 与 [`Preview/Account/Lease.hpp`](../Preview/Account/Lease.hpp) 这一 typed shared owner：`InspectCredential` 不领 lease，`Authenticate` 成功才发布唯一数值账户身份和 `AccountLease`，旧 `Check` bridge/第二 owner 不再是正式入口。

S5 selector 对非零 stream/task 选择器返回 `target_unsupported`/Rejected；worker `TaskRegistry` snapshot 沿正式 parent→child→grandchild tracked descendants 聚合，root cancel 不被伪装成 child 取消。原 `GatewayCommon` 已整体移至 [`tests/Experiments/Preview/Quic/GatewayCommon.hpp`](../tests/Experiments/Preview/Quic/GatewayCommon.hpp)，生产 CMake 登记已删除，并在测试专用 PreviewTestSupport 登记完整实验 owner，当前只剩 `Task9FrontIntegration.cpp` 与 `RecognitionQuicCarrier.cpp` 两个测试消费者；该测试骨架不证明真实 QUIC Main。

10 月 5 日 D5 候选 manifest 记录 45 路文档；当前比对为 `18 match / 26 drift / 1 retired-missing`。原 13 路文档基线、Diagnose 约 53KB 历史资料和原始失败证据继续保留，最终 manifest 需在 Task8 再捕获。

Task7B 的 RecognitionPerf owner harness 已编译，固定 trace 为 CID scale 与 SNI route capacity `8/64/1024`，A 使用真实 `DatagramClassifier`、编译后的 `Profile::LookupRoute` 和 `DirectoryAuthenticator`，B 的 account 路径仅是标明下界的 idealized lease model；分配与采样口径正在复核，最终270行对照尚未运行。DnsPerf 的1/2/4独立owner各5轮共15轮已自然 exit0，包含取消/恢复、TTL/淘汰/负缓存预检，它是当前 coalescer 的规模基线。其余 mux、I/O、Registry/DNS候选比较及最终五轮 raw 矩阵仍待完成，当前没有采纳性能候选。

## Preview 主线

### 启动和真实请求链

[`Preview/Application/Main/PreviewMain.hpp`](../Preview/Application/Main/PreviewMain.hpp) 的 `main()` 读取命令行配置；没有参数时读取可执行文件同目录 `PreviewConfiguration.json`，并把 `PRISM_PREVIEW_SECRET_<REFERENCE>` 环境变量解析器交给 `Application::Options`。`Application::Run()` 调用 `Application::Start()`，启动失败返回非零退出码。

当前 `Application::Start()`/`StartupRuntime()` 的顺序是：

```text
main (PreviewMain.hpp)
  -> Application::Run -> Application::Start
     -> GenerationPhase::Build
        -> schema/reference/capability/secret validation
        -> immutable ConfigurationGeneration
     -> ProcessServices::Build
        -> ProtocolServices::Prepare
        -> ProtocolServices::Bind
           -> typed ProviderCatalog Prepare/Freeze/Bind
           -> DatagramServices / QuicServices
           -> ProtocolProfile::MakeTcpProfile
     -> BoundaryPhase::Start
        -> Runtime::TcpListener
        -> Boundary::Datagram::DatagramListener when configured
     -> OperationsPhase::Start -> PublishPhase::Publish
     -> StartupTransaction::Commit
```

来源是 [`Preview/Application/Startup/Start.hpp`](../Preview/Application/Startup/Start.hpp)、[`GenerationBuilder.hpp`](../Preview/Application/Configuration/GenerationBuilder.hpp)、[`ProtocolServices.hpp`](../Preview/Application/Startup/ProtocolServices.hpp) 和 [`BoundaryPhase.hpp`](../Preview/Application/Startup/BoundaryPhase.hpp)。generation、prepared service、bound catalog 和 listener 未成功前不会发布 `Readiness`；typed 失败由 startup transaction 回滚。

TCP acceptor/accept loop 当前实际位于 [`Preview/Runtime/Listener.hpp`](../Preview/Runtime/Listener.hpp) 的 `Runtime::TcpListener`；UDP socket、分类和 receive loop 位于 [`Preview/Boundary/Datagram/DatagramListener.hpp`](../Preview/Boundary/Datagram/DatagramListener.hpp)；QUIC packet gateway/CID registry 位于 [`Preview/Boundary/Quic/`](../Preview/Boundary/)。`Runtime::Session::RunCore()` 绑定入站 executor，运行 recognition admission，再运行 `SessionDataPlaneRelay`。这些位置不能用旧版 listener 或旧版 `src/main.cpp` 替代。

### Preview 模块所有权

| 模块 | 当前 owner | 应拥有的责任 | 不应拥有的责任 |
| --- | --- | --- | --- |
| `Application/` | `Application/Startup/Start.hpp`、`Application/Shutdown.hpp`、`RuntimeState.hpp` | 配置 generation、进程服务、启动/回滚/停机 | 协议 wire/auth、协议 root/stream 业务 |
| `Composition/` | `Composition/Builtin/Registry.hpp`、`Composition/Provider/ProviderCatalog.hpp` | 冷路径能力校验、typed prepare/freeze/bind、依赖注入 | 协议帧循环、认证业务、UDP relay、协议 close |
| `Boundary/` | `Boundary/Datagram/*`、`Boundary/Quic/*` | UDP socket/分类/入口 drain、QUIC CID/连接入口 | Hysteria2/TUIC/SS2022 凭据和协议业务 |
| `Runtime/` | `Runtime/Listener.hpp`、`Runtime/Session.hpp`、`Runtime/Session/*`、`Runtime/Session/Delivery.hpp`、`Runtime/Recognition/*` | TCP accept/worker 分发、识别、通用 session/task/relay 生命周期和唯一 delivery owner | 具体协议 wire/auth 和 Composition 注册 |
| `Protocols/<Name>/` | `Protocols/Socks5/*`、`Shadowsocks2022/*`、`Anytls/*`、`Vless/*` 等 | wire、认证、连接/stream/datagram 状态机和协议级 close/drain | Application 启停、跨协议 registry、通用 CID 分发 |
| `Foundation/` | `Foundation/Fault/*`、`Foundation/Memory/*`、`Foundation/Utility/Diagnose/*` | fault、memory、日志和基础值类型 | 具体协议装配和应用启动 |
| 中立生命周期/契约 | `Lifecycle/*`、`Contract/Ingress/*`、`Contract/Carrier/*`、`Contract/Services/*`、`Net/*`、`Transport/*`、`Account/*` | `TaskRegistry`/drain、typed request/result、carrier handoff、dial/relay、transport、账户记录/lease | 按字符串热路径分派、旧接口双向同步 |

当前源码路径核对：`Preview/Composition/AnytlsService.hpp`、`VlessXudp.hpp`、`MuxService.hpp`、`SingMux.hpp`、`H2MuxServer.hpp` 和 `UdpService.hpp` 均不存在。对应 wire/session owner 位于 `Preview/Protocols/Anytls/`、`Protocols/Vless/Xudp/`、`Protocols/Mux/` 及其 `SingMux/`、`H2Mux/` 子目录；Composition 只保留冷装配/provider 边界。`Preview/Runtime/SessionServices.hpp` 当前也没有 `Routes` 或 `Scheme` 字段。该段是当前源/include 定位事实，不是运行通过证明。

认证契约与实现统一由 [`Preview/Account/Authenticator.hpp`](../Preview/Account/Authenticator.hpp) 拥有。`InspectCredential` 只查询凭据，不领取 lease 或消耗 rate；`DirectoryAuthenticator` 持有账户目录，唯一运行态 `Authenticate` 成功结果拥有数值 `AccountId` 和一次 `AccountLease`。该所有权迁移及旧 `Check`/bridge 的调用者删除仍按[当前验收状态](preview-refactor/2026-10-03-preview-no-compat-status.md)分别验证，不能把源码位置更新当成整项测试通过。

root request 按值移动该 lease，child 通过 `StreamAdmission` 获得 `StreamLease`。stream wire 和 FIN/半关闭由协议 session owner 管理，通用双向 relay 由 `Net/` owner 管理；`BoundCatalog::Close/Drain`、协议 root/session 和 `Application/Shutdown` 负责逐层 close/drain。executor 由 Application/worker/session services 注入，观察失败不得转成业务 fault。纯 carrier 的握手状态、错误、transport 和 replay handoff 位于 [`Contract/Carrier/FacadeCarrier.hpp`](../Preview/Contract/Carrier/FacadeCarrier.hpp)，协议通过该中立合同装配实际 wire owner。

统计使用 [`Foundation/Utility/TrafficSink.hpp`](../Preview/Foundation/Utility/TrafficSink.hpp) 的唯一数值 `TrafficEvent`：成功写入提交 `Bytes` 增量，最终完成提交零字节 `Completed`，后者才增加事件次数。Runtime 的 [`TrafficCounter`](../Preview/Runtime/Statistics.hpp) 持有有界 worker 队列，控制 executor 定时聚合到唯一 `SparseCounters`；满队列、过期 generation 和聚合失败分别计数，业务生产者 drain 后才 seal 和最终 flush。stream 的统计键包含真实父 SessionId 与 wire StreamId；QUIC/raw UDP 没有 Runtime worker/session 来源时保留缺失身份，不能编造数值 ID。该接线有当前限定测试和真实请求证据，整项结果仍见执行状态。

`SessionRegistry` 只通过 `Register(SessionInfo, SessionControl)` 产生 move-only token。listener 注册真实 worker/generation，协议 admission 在同一 token 上发布账户、目标和协议值，COW CAS 重试保留完整请求并拒绝不同 worker/generation、退休或复用的 entry。Session owner 持 token 至最终关闭及错误投递结束，`RunContext` 只在当前 Run 内借用；Operations 从该值快照读取 worker/generation，不从全局状态补造会话身份。识别 route 只使用 `Pattern`，旧 `Domain` 回退与错误枚举别名已删除。

### 冷路径和热路径规则

`Builtin`/`ProtocolId`/`MuxModes` 的名称解析、能力校验和 `ProviderCatalog::Prepare`/`Freeze`/`Bind` 只属于启动冷路径；request/packet/frame 热路径消费已编译 profile、resolver、typed provider binding 和 protocol session，不重新按名查找或扫描空 factory 表。当前 S5/SS2022 configured mux 已进入 Task4 的 focused real-run 单元，但 Task4 仍 WIP：001/002 的 16 case、003 的 SOCKS5 root run、004 的两族 root run、005 的两族 echo/cancel 4 case分别只证明各自窄范围；006 quota2 最终6 case已由Root核源码/XML/当前源hash后接受第二流wire拒绝与第一流真实续传范围，首次与中间失败分别保留。不能把这些层级累加成整项完成。

### 构建和门禁

`Preview/Application/CMakeLists.txt` 将 `Startup/Start.hpp` 和 `Main/PreviewMain.hpp` 作为 CXX source；`PrismPreview` 输出 `build/src/PrismPreview.exe`，POST_BUILD 复制 `PreviewConfiguration.json` 到 `build/src/PreviewConfiguration.json`。只使用 `build/`，构建前记录上海时间，白天 `-j 16`、夜间 `-j 1`。生产 header 不超过 600 行，函数不超过 120 行，lambda 不超过 10 行，普通参数最多 2 个、复杂边界最多 3 个；不得新增 Compat/Legacy adapter、旧 overload、作用域 include、假 target 或万能 context。

验收分开报告源码/CMake 静态检查、configure/build、focused CTest、全量 tests、真实请求/关闭/drain、互操作和性能。旧 951 名称基线、2026-09-26 Diagnose 387/387 和历史 epoch 只保留日期与范围。

## legacy：旧版四层资料

以下正文只适用于旧版 `include/prism/` + `src/prism/`。它保留旧版 detached/PMR 的具体安全规则，不能直接当作 Preview owner 表。

## 设计原则

Prism 采用纯协程（C++20 coroutine + Boost.Asio awaitable）架构，所有 I/O 操作异步执行。在这种架构下，**对象生命周期**与**资源所有权**是设计层面的核心问题——一个看似正确的对象引用，可能因为 detached 协程的存在而变成悬垂指针。

本文档定义 Prism 的四层资源所有权模型，明确 detached 协程的资源使用规则，从设计层面消除 use-after-free 类 bug。

---

## 四层所有权模型

Prism 所有资源按所有权范围分四层：

| 层 | 所有者 | 寿命 | 典型资源 | detached 协程可引用？ |
|----|--------|------|---------|---------------------|
| **L1 进程** | 进程 | 启动到退出 | `resource::process`（cfg / ssl / accounts）、`memory::system::global_pool()`、`handshake::scheme_registry` | ✅ 永远安全 |
| **L2 worker** | worker 线程 | worker 创建到销毁 | `resource::worker`（ioc / pool / router / dns / outbound / traffic / rate / tasks） | ✅ worker 不死即可 |
| **L3 session** | session 对象 | 单次连接 | `resource::session`（conn / buffer / inbound / outbound / detected / lease / meta / trace / arena / src） | ❌ 严禁 |
| **L4 detached** | detached 协程 | 协程启动到结束 | `multiplexer.transport_`、`multiplexer.prefix_`（shared_ptr 值持有）、`multiplexer.self`（shared_from_this） | 自带，不依赖外层 |

---

## detached 协程规则

凡是 `net::co_spawn + net::detached`（或 Boost.Asio 等价机制）启动的协程，**完全脱离调用者的协程上下文**，独立运行直到自身结束。

### lambda 捕获规则

detached 协程的 lambda 捕获列表：

✅ **允许捕获**：
- 值类型（POD、enum、值副本）
- `std::shared_ptr<T>`（共享所有权，自动延长 T 的生命周期）
- L1/L2 层引用（worker 永生）
- 自身 `shared_from_this()`（典型 RAII 模式）

❌ **严禁捕获**：
- `resource::session&` 或 `resource::session*`（裸引用/指针，session 可死）
- `ctx.arena.get()`（PMR allocator，session 级）
- `ctx.inbound&` / `ctx.outbound&`（引用捕获，session 级）
- 其他 L3 资源的裸引用/指针

### 资源使用规则

detached 协程内需要的资源：

- **session 资源** → 必须先 **move**（如 `transport` 所有权转移）或 **值拷贝**（如 `prefix_`、`proto_`）
- **PMR allocator** → 必须用 L1/L2 资源（`global_pool` 或 `local_pool`），禁止用 `frame_arena.get()`
- **router/traffic** → 通过 L2 引用（`ctx.worker->outbound`、`ctx.worker->traffic`）

---

## PMR allocator 规则

Prism 使用 PMR（polymorphic memory resource）实现热路径零堆分配。但 PMR allocator 的 `memory_resource*` 是裸指针，**不会自动跟随对象生命周期**。一旦 allocator 指向的对象析构，PMR container 的 `m_resource` 字段悬垂。

### 各层 PMR 使用规则

- **L3 对象**：可用 `frame_arena`（session 级 PMR pool）。session 析构时 frame_arena 一起析构，所有从 frame_arena 分配的对象随 session 释放
- **L4 对象**：必须用 `global_pool`（永生）或自带 `monotonic_buffer_resource`（detached 协程内独立池）

### 典型反例（已修复）

`transport::preview` 持有 `preread_buffer_`（`pmr::vector<byte>`），曾接受外部 `mr` 参数：

```cpp
// 危险代码（已删除）
preview::preview(shared_transmission inner, span<const byte> preread, memory::resource_pointer mr)
    : preread_buffer_(preread.begin(), preread.end(), mr) {}
```

调用方传入 `ctx.arena.get()`，让 `preread_buffer_.m_resource` 指向 session 的 frame_arena。但 `preview` 可能被 `multiplexer.transport_` 持有，multiplexer 是 detached 协程（`co_spawn(run(), detached)`），生命周期脱离 session。session 析构后 frame_arena 失效，preview 析构时 `m_resource` 悬垂 → 段错误。

**修复**：preview 构造去掉 `mr` 参数，内部强制用 `global_pool`（PMR 默认资源）。

---

## 已知约束（Prism 现状）

### multiplexer 是 L4

`multiplex::multiplexer`（smux/yamux/h2mux 的基类）通过 `co_spawn(run(), detached)` 启动帧循环，生命周期独立于 session。

- `transport_`：通过 `multiplex::bootstrap` 从 caller move 进来。**若 transport 是 preview，preview 必须用 global_pool**
- `outbound_`：L2 非拥有引用（`worker.outbound`），安全
- `config_`：L1 值引用（多路复用配置），安全
- `prefix_`：值持有 `shared_ptr<diagnose::context>`，安全
- `mr_`：PMR 资源，必须用 L1/L2 资源（`global_pool` / `local_pool`），禁止 `frame_arena`

### anytls scheme.cpp 的 detached task

`anytls::scheme::handle_first_stream` 启动 `mux_task` 和 `forward_task`（detached）。两个 task 捕获 `session_ptr`（`resource::session*` 裸指针）。

**安全性来源**：task 同时捕获 `keepalive`（`shared_ptr`），keepalive 持有 session 引用计数，保证 session 在 task 期间不析构。因此 `session_ptr` 在 task 期间有效。

**类型化要求**：`keepalive` 字段类型必须是 `std::shared_ptr`（不能是裸指针），让安全性在类型层面体现，防止未来误删 keepalive。

### stream / datagram

`multiplex::stream` 和 `multiplex::datagram` 通过 `shared_from_this()` 持有自身，绑定到 `multiplexer`。它们继承 `multiplexer` 的 L4 属性，同样禁止使用 `frame_arena`。

---

## 审计与检查

### 静态审计

Prism 提供 `scripts/audit_detached.sh` 脚本，扫描所有 `net::co_spawn + net::detached` 的 lambda 捕获，检测危险模式（session&/*、frame_arena.get() 等）。

```bash
bash scripts/audit_detached.sh src/
```

预期：0 DANGEROUS，若干 REVIEW（人工确认）。

### 代码审查 checklist

新增 detached 协程或修改 PMR allocator 时，审查者必须确认：

- [ ] lambda 捕获列表中没有 session 裸引用/指针
- [ ] PMR container 没有用 `frame_arena.get()` 作为 allocator
- [ ] 通过 shared_ptr 持有的对象，对应的所有权链完整（如 keepalive）
- [ ] L4 对象的所有字段要么是值/shared_ptr，要么是 L1/L2 引用

---

## 参考实现

### 安全的 detached 协程模式

```cpp
// multiplexer::start() 内部
auto self = shared_from_this();          // self 是 shared_ptr<multiplexer>
auto run_wrapper = [self]() -> net::awaitable<void>
{
    co_await self->run();                // self 持有 multiplexer，multiplexer 持有 transport_（global_pool）
};
net::co_spawn(transport_->executor(), run_wrapper(),
    [self](const std::exception_ptr &ep) { self->on_exception(ep); });
```

### 危险模式（已被审计脚本检测）

```cpp
// ❌ 危险：捕获 session 裸引用
net::co_spawn(exec, [session = &ctx]() {  // session 是 session&
    co_await session->something();         // session 可能已析构
}, net::detached);

// ❌ 危险：PMR allocator 来自 frame_arena
auto v = memory::vector<byte>(data, ctx.frame_arena.get());
// v 可能被 detached 协程持有，析构时 m_resource 悬垂
```

---

## 三层资源容器（resource/ 模块）

重构后（2026-07）resource/ 模块提供三层纯数据容器，替代旧的 resources/ 虚基类体系。

### 所有权链

```
main
  └─ shared_ptr<resource::process>           ← L1 进程级，唯一持有者
       └─ shared_ptr<resource::worker>       ← L2 工作级，runtime::worker + 所有 session 共享
            └─ shared_ptr<resource::session>  ← L3 会话级，runtime::session 持有
```

**对外共享，对内独占**。shared_ptr 跨层传递，值持有自己层的资源。上层释放 → 引用计数递减 → 所有引用释放后自动析构。

### 函数：只 2 个

| 函数 | 所在层 | 作用 |
|------|--------|------|
| `alive()` | worker, session | 检查资源链存活（atomic acquire），协程判断是否停止 |
| `stop()` | worker | 触发 io_context 停机，启动关机级联 |

`resource::process` 零函数，纯数据。其余全部是**公有字段**，不提供 getter/setter，调用方链式访问：

```cpp
ctx.trace                              // session 级
ctx.worker->traffic.on_connect()       // worker 级
ctx.worker->process->cfg->buffer.size  // 进程级
ctx.worker->outbound->make_router()    // unique_ptr 用 ->
```

### 新增资源规则

1. 放到实际归属层，不跨层
2. 作为公有字段，不加 getter
3. 不加透传：L2 加字段后 L3 不需要同步加同名方法
4. 不加新函数：2 个函数是上限。业务逻辑放业务类

### 构造模式

```cpp
// 每层都有一个嵌套 ::options struct 收敛构造参数
auto proc_opts = resource::process::options{cfg, ssl, accounts};
auto proc = std::make_shared<resource::process>(std::move(proc_opts));

auto wrk_opts = resource::worker::options{proc, mr, index};
auto wrk = std::make_shared<resource::worker>(std::move(wrk_opts));

auto ses_opts = resource::session::options{wrk, conn, buffer, inbound, src, trace, meta};
auto ses = std::make_shared<resource::session>(std::move(ses_opts));
```

---

## 模块依赖规范

### 依赖层次（禁止反向）

```
Level 0: foundation/                  ← 零外部依赖（fault/exception/memory/coroutine/rate）
Level 1: crypto/  diagnose/           ← 仅依赖 foundation
Level 2: net/  user/                  ← foundation + diagnose + crypto
Level 3: resource/                    ← 聚合 net/user/diagnose/settings（L1/L2/L3 纯数据容器）
Level 4: protocol/                    ← net + user + crypto + resource
Level 5: handshake/                   ← net + protocol + crypto + resource + settings
Level 6: settings/  runtime/          ← 顶层：settings 聚合全量配置 schema，runtime 编排
```

### 允许/禁止表

| 模块 | 可依赖 | 禁止依赖 |
|------|--------|---------|
| `foundation/` | 无 | 任何其他 |
| `crypto/` `diagnose/` | foundation | net, protocol, handshake, resource, runtime |
| `net/` | foundation, diagnose, user, resource | protocol, handshake, runtime |
| `user/` | foundation, net | protocol, handshake, resource, runtime |
| `resource/` | foundation, diagnose, net, user, settings | protocol, handshake, runtime |
| `protocol/` | foundation, diagnose, net, user, crypto, resource | handshake, runtime |
| `handshake/` | foundation, diagnose, net, protocol, crypto, resource, settings | runtime |
| `settings/` `runtime/` | 所有下层 | 无（顶层） |

### 已知依赖环（待治理）

- `settings ↔ runtime`：`settings/settings.hpp` 引 `runtime/config.hpp` 聚合配置类型，`runtime/front/listener.hpp` 引 `settings/settings.hpp`
- `net ↔ resource`：`net/connection/tunnel/tunnel.hpp` 引 `resource/session.hpp`（拿 `session` 资源），`resource/worker.hpp` 引 `net/...`（持有 dialer/routes）

环本身能编译，但破坏严格的 DAG 分层。重构方向：把 `resource/session` 中 tunnel 所需的纯数据字段下沉到 `net`，或让 tunnel 改用抽象接口而非直接引 `resource/session`。

### 头文件规则

- 前向声明优先：`.hpp` 中能前向声明就不 `#include`
- `unique_ptr<T>` 的 T 前向声明时，析构函数在 `.cpp` 中定义
- 禁止上行包含：下层 `.hpp` 绝不包含上层模块（已知环除外）
- 聚合头维护：新增子头文件须同步更新模块聚合头

### 审计

```bash
grep -rn '#include <prism/\(protocol\|handshake\|runtime\)' include/prism/net/
grep -rn '#include <prism/\(net\|protocol\|handshake\|resource\|runtime\)' include/prism/foundation/
grep -rn '#include <prism/\(handshake\|runtime\)' include/prism/protocol/
grep -rn '#include <prism/\(protocol\|handshake\|runtime\)' include/prism/resource/
# 除已知环外应 0 命中
```

---

## 传参规范

- 函数参数 ≤ 3，超过用 struct 收敛
- opts struct 不继承，独立 POD
- 需要资源：`(resource::session&, opts)` 或 `(resource::worker&, opts)` — 2 参数上限
- 不需要资源：`(opts)` — 1 参数

```cpp
struct handler_params { resource::session& ctx; span<const byte> data; };
auto forward(resource::session& ctx, forward_options opts) -> awaitable<void>;
auto dial(resource::worker& w, const target& t, dial_options opts) -> awaitable<dial_result>;
auto tunnel(tunnel_options opts) -> awaitable<void>;
```
