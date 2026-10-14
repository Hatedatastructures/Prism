# Preview 主线维护入口

本文档是 `Preview/` 当前维护入口。它描述的是当前源码结构和已确认的启动装配路径；它不是互操作、性能或全量测试通过声明。Preview 不以 `include/prism/`、`src/prism/` 的旧版工厂、资源容器或测试结果作为当前实现事实。

## 2026-10-09 22:46 当前磁盘快照

本节以 2026-10-09 22:46:10 +08:00 的当前磁盘核对为边界。当前 `Preview/` 生产实现为 **639 个 `.hpp`、0 个生产 `.cpp`**；最终入口仍是 [`Application/Main/PreviewMain.hpp`](Application/Main/PreviewMain.hpp)，启动 owner 仍是 [`Application/Startup/Start.hpp`](Application/Startup/Start.hpp)。当前入口文件 SHA256 为：`PreviewMain.hpp=D6A84733F33ACE31DCE6865B4DE0BD6E08A4E93946572051B3FC8919A1D219C8`、`Start.hpp=3D03F6661DA7CA90ECF3CC40E87F7D3F42676C83AB64A2EC09C239AAB6B46E90`。

当前 `build/src/PrismPreview.exe` SHA256 为 `F5363B287941A4B6B7599FCD1EC041311885B8A4100A219FEF0487794523F3DC`（文件时间 22:36:01）；配置模板与 `build/src/PreviewConfiguration.json` 副本均为 `C245C56845ACC08F415F14CB372F1FABE54F541241E914880A0BE536D80E3501`。该 EXE 目前只有当前磁盘文件事实；没有把上述当前 source/config hash 与它绑定的 build manifest/log，因此缺少当前 source→binary build provenance，不能单独作为当前 Main acceptance。此前用户给出的 `88922FAC...` 已因当前磁盘二进制漂移降为历史候选，不能继续作为 current hash。19:04 捕获的 [`coordinator-9-current-source-v3.json`](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-current-source-v3.json) 仍保存旧入口 hash，不能绑定到上述 22:13 后的当前源码；其 [`coordinator-9-current-source-v3-build.log`](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-current-source-v3-build.log) 的 exit0 只证明当时指定目标的构建，不是当前 Main 真实验收。

当前 Provider Application 限定证据为 [`coordinator-9-current-provider-application.log`](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-current-provider-application.log)：`cases=18`、exit0；对应 [`coordinator-9-new-abi-provider-cleanup.json`](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-new-abi-provider-cleanup.json) 为 `Remaining=0`、19 个 owned 进程、live 目录无残留，但 `NaturalMainExitClaim=false`。该 Provider18 记录没有当前 source/EXE/config 三元 hash binding；它只是 Provider18 的请求/认证/UDP 关闭与清理证据，不是 I02 的 Main 自然 drain，也不能升级为当前 Main acceptance。

I02 所需 runner 已在 [`scripts/interop/Run-Matrix.ps1`](../scripts/interop/Run-Matrix.ps1) 及 [`tests/Preview/Integration/Matrix`](../tests/Preview/Integration/Matrix) 具备 hash、payload、drain、自然退出和 owned-process 字段合同；当前仍没有对应当前 Main 的 Hysteria2 三次、TUIC 20 轮×7 模式和重复 Mihomo runtime acceptance。最新 preview-only 矩阵为 `60 total / 53 pass / 6 blocked / 1 failed`、EXIT1，原始汇总见 [`build/interop-results/summary.json`](../build/interop-results/summary.json)，锁定重跑退出记录见 [`coordinator-9-current-interop-matrix-locked-rerun.log`](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-current-interop-matrix-locked-rerun.log)；该结果没有当前 Main source/EXE/config 三元 hash binding，不能升级为 I02 Main acceptance 或全协议互操作通过。

P04 仍未闭合：[`coordinator-9-current-DnsCacheCompare-preflight.log`](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-current-DnsCacheCompare-preflight.log) 和 DnsCache smoke 的 validate/preflight 为 exit0，但 ABC `540` 同 trace 矩阵未运行。旧 [`coordinator-9-current-dnsperf-coalescer.log`](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-current-dnsperf-coalescer.log) 的 `EXIT=-1073741819` RED 与后续 [`coordinator-9-dns-coalescer-fix-verify.log`](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-dns-coalescer-fix-verify.log) 的 1/2/4 owners×5 rounds `valid=yes`/exit0 green 均保留，但两类记录都没有当前 source/EXE/config hash/epoch binding，不能当作当前性能验收。G02 的 `640-row` standalone-header/ODR/CXX owners、CMake target-graph/exact-case 与五边 negative/restore 输入均是 `pre-current` prepared inputs，仍未运行，不能写成 PASS。

A01 只读阶段一采用 D06 按当时磁盘计数派生的 fixed639 normalized ledger，记录为 `A10/B0/C26/D1/N602/E50/F14`，`safe-delete=0`；它不是当前实时总数，也不能与 live640 混读。阶段二没有用户批准，也没有因本次文档同步执行删除、迁移或生产接线。A01、G02、P04、I02 和 Linux 的局部或预检证据都不替代当前 Main runtime、全量 CTest、ODR、Linux 或最终文档验收。D08 只修正文档路径与 provenance 口径；下一张 Root review card 仍是 D5/D01 current-epoch review，需复核三文件的 delta、链接/锚点、CLI/config、入口/二进制 hash、source→binary binding 和未运行层级。原始 dated 段继续保留，当前任务不能称全量完成。

## 2026-10-09 11:15 历史验收范围

当前生产源码为 640 个 header、0 个生产 `.cpp`，最终入口为 `Application/Main/PreviewMain.hpp`。根构建契约在 MinGW 下统一传递 `BOOST_ASIO_HAS_PTHREADS=1`，消除不同 include 顺序造成的 Asio POSIX/Windows 线程 ABI 混用。原 60 秒超时的配置化 TCP 工厂用例已在新二进制上通过；100 次重复、600 次协议启动停机以及 Application 32/32 focused 用例均自然退出。原始证据见 [ABI 回归](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-asio-backend-regression-green.log) 和 [Application focused](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-asio-app-32-green.log)。

当前 `build/src/PrismPreview.exe` SHA256 为 `EFB86D372401DC81EF712D7EA33E5A3C4429E4282B3EC6B2666DE3EECB1744E0`。这份二进制的限定 [Provider Application 结果](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-new-abi-provider-result.json) 已通过 18 个请求、认证与 UDP 关闭场景；19 个本任务进程已退出，live 临时目录已清理。该 harness 主动终止自己的 Main，优雅停机须由独立 drain 场景证明。新 ABI 的 TUIC 20 轮正在执行；Hysteria2、structured Mihomo、全量 CTest、性能、独立头编译与严格 ODR 尚未签收。

417 个目标的统一重编仍在执行，测试 CPP 的风格与异常收口也尚未完成。旧 `431CE...`、`35A2...` Main、旧 ID90 成本矩阵以及下面的历史测试结果均保留其原源码、配置和二进制范围。MuxRealRoot 的 64 MiB/64 KiB、45 cases/105 lanes 与 TransferP01 的 256 MiB/64 KiB、4096 blocks 是两个独立输入合同。完整状态见 [执行状态](../docs/preview-refactor/2026-10-03-preview-no-compat-status.md)。

## 2026-10-09 新 ABI 之前的历史检查点

以下内容记录当时快照，其中的“当前”仅指该历史时点，不用于签收上面的新 ABI 二进制。

当前测试目录按实际生产 owner 对齐：配置归 `Application/Configuration`，编译装配归 `Composition`，取消与 drain 归 `Lifecycle`，socket/CID 入口归 `Boundary`，调度与 session 归 `Runtime`，独立 codec/session 归 `Protocols/<Name>`；只有真实跨模块请求才进入按协议和场景细分的 `Integration`，独立实验归 `tests/Experiments`，`Common` 只覆盖真实 Common 契约。测试正文放 `.cpp` 且不超过 800 行；共享 HPP 只承载多个 CPP 实际共用的模块封装。项目自有标识符用 PascalCase、中文 Doxygen，函数不超过 120 行、lambda 不超过 10 行，参数通常不超过 2 个（复杂边界最多 3 个），不保留旧接口或兼容入口。

当前 `Protocols/Mux/Stream.hpp` 唯一生产修复源 SHA256 为 `82718A908A656B9667DE3DBC51AF7EE8A19DBF4D81270F74D9FC422A1E4EF82A`：retired handle 的 `Tasks == nullptr` 是合法终态，`CloseOnExecutor` 对该状态幂等关闭并跳过不存在的 task/wire；构造时非空强合同保留，不恢复旧 API。独立回归先实际 RED（crash `-1073741819`），随后 `Decorator` 11/11 GREEN。原 Mux focused 122/128、6 fail 及失败 XML 保留；同一 6 项在新源码上 6/6 GREEN，不能扩写为 128 或全量当前通过。

`DnsCache` validate-only 实际 exit0，不代表 540-row matrix；`DnsSession` 初次真实路径因 client 未 half-close hang，补 `Shutdown` 后 1/1 natural exit0。`ListenerAdmission` 6、`SessionOrchestration` 9、`SessionServices` 6 均 natural exit0；Session 19 target/100 CTest 属 Stream 修复前的历史限定快照。Root 已在 live640 Tree 上重新构建 Main，当前 `build/src/PrismPreview.exe` SHA256 为 `431CE70117019FC0A46F2C76087BB6B5F02A3BE5D514BF6DFB0A0454F802FD5E`；`.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-tree-contained-provider.log` 记录 Provider Application interop `cases=18`，Root 同时记录 19 个 owned PID 已清理。该证据只覆盖这 18 个 Application 场景，不扩大为全量当前 runtime；`D535...`、`6B6B`/`32DA`、Hysteria/TUIC 140 次及 structured Mihomo 继续按历史 EXE 解释。

Standalone preview-only 矩阵的历史结果为 60 rows、54 pass、6 blocked、0 fail、exit2，仍只绑定当时 EXE；six interface/unavailable 项保持显式 pending。Transfer 当前 artifact 为 45 groups、105 lanes、9 summaries、实际 exit0；其 scatter 成本偏高只是 baseline 观察，不形成性能改善声明或生产算法采用结论。当前 source gate 为 live640 production headers、0 production `.cpp`；通过仅属源码层，不能替代全量 CTest、全部协议请求或性能验收。

22:26 用户指出子代理重复旧卡和 AST0/hash 虚签后，扩张式派单已暂停；后续小批必须以 actual compile、focused test 和交叉审查收口。Root 已完成 live640 Tree 的当前 Main 重编；全量 CTest、严格风格、全部 Main 互操作、性能对照、ODR、Linux、旧对象精确清理和 production shell audit 仍待完成。

## 2026-10-08 20:30 历史验收检查点

测试结构正在按实际生产 owner 迁移。配置归 `tests/Preview/Application/Configuration`，编译装配归 `Composition`，取消与 drain 归 `Lifecycle`，socket/CID 入口归 `Boundary`，单协议 codec/session 归各 `Protocols/<Name>`；只有真实跨模块请求场景进入按场景细分的 `Integration`。`Core/Coroutine`、`Stealth` 和旧 `perf` 分类正在退役，不保留转发入口或兼容 target。旧版 `prism/...` 和独立实验的测试分别回到旧版目录与 `tests/Experiments`，不能代替 Preview 生产验收。

生产 Main 已在 Hysteria2 标准认证字段、Gun 协程输入所有权和 Mux 取消等修复后重编，当前 EXE SHA256 为 `6B6BD58D8C5E9B741D7CD09C9060563F862A041F2B4C0C4824A946071D14279E`。这个版本已取得 Hysteria2 正负认证与 TCP/UDP、TUIC 20 轮共 140 次单拨号，以及 SOCKS5 三次独立 literal HTTP 响应与 structured Worker/Session 关闭链的实际通过结果；都核对了自然退出和自身进程清理。它们仍是限定场景证明，全部 carrier/inner-protocol、性能、Linux 和最终全量回归尚未完成。

测试 CPP/HPP 的 800 行、路径大小写、生产零 CPP、方向与退役接口门禁已通过当前源码检查。进一步的语法树风格扫描仍发现长函数、长 lambda 和宽参数接口，正在按模块窄修；共享 HPP 必须由至少两个 CPP 实际使用其封装，普通测试使用 GoogleTest，不建立声明头与实现 CPP 配对。新布局尚未统一构建和完成全量 CTest，不能引用旧布局的绿色结果签收。本任务首轮全量的 23 个失败或未运行结果继续保留为原始证据。

用户已授权的 23 个退役测试 EXE 已逐项核对 source、binary hash 和进程后删除，清理证据见现有 [退役产物清单](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/preview-retired-core-build-artifacts.json)。有效测试产物和性能对照 baseline 保留；构建仍只使用现有 `build/`，由 Root 在源码冻结后统一执行。

## 2026-10-08 17:50 历史验收检查点

上海 17:50：Preview 仍在实施中，当前工作树、生产接口和测试夹具尚未形成最终验收快照。真实 owner 链仍是 `Application/Startup` 冷路径生成与 typed `ProtocolServices::Prepare/Bind`，随后由 `ProtocolProfile::MakeTcpProfile` 发布 immutable profile/resolver；Runtime/Boundary 消费已编译的 typed data-plane，协议目录拥有 wire、认证、stream/datagram 和 close/drain。名称解析只发生在 generation/profile/provider 冷路径，不能把 standalone harness 或旧版 `include/prism`/`src/prism` 结果写成当前 Main 能力。

当前分层证据如下：源码层仍有 no-compat、owner、文档和性能整改未冻结；Root92389 的现有 Makefile2 12-target aggregate0 是此前构建层证据，Hys/Gun 等后续 source change 仍需 fresh recompile。Root 的完整当前 CTest 为 `4896 registered / 25 disabled / 4871 participating / 23 failed-or-not-run / EXIT8`，原始日志和 XML 在 [`parallel-full-current-ctest.log`](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/parallel-full-current-ctest.log) 与同目录 XML，不能写成全量通过。新鲜 focused 结果为 Context 1、Ownership 4、DNS 14、CanonicalDatagram 2、Adapter 14，共 35/35 自然完成；Go config 1 和旧 GoCompat 4 只属于旧层证据。Hysteria 标准 response 的两个正向回归此前为 RED，variant/string source fix 尚未取得 fresh green；GunOwned、RawWriteCancellation、Stream owner guard 等仍是 source-ready/待当前批次重编，不能提前签收。

当前 Main 的 `5769C3...` TUIC 20 轮/140 次单拨号和 Hysteria 正负 TCP/UDP 证据只绑定那个历史 snapshot；Root 后续生产源码已变化，因此不再称为最终当前 Main 请求验收。`B38A...` 和 `1B72...` 记录继续作为历史限定快照保留。当前 `PreviewInteropMatrix` 是 standalone preview-only harness，不是 Main inner-protocol/carrier 验收；结果与 blocked/failed 细节见现有 [`build/interop-results/summary.json`](../build/interop-results/summary.json)。性能方面，Recognition 默认 10 场景实际 PASS 用时 1646.60s，但这不是性能候选验收；其它性能矩阵仍有未构建、超时或无 measurement row 的项。

执行边界和剩余项以[无兼容层执行计划](../docs/preview-refactor/2026-10-03-preview-no-compat-execution.md)、[当前执行状态](../docs/preview-refactor/2026-10-03-preview-no-compat-status.md)和现有 [`progress.md`](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/progress.md) 为准。D5 的 45-file 文档 manifest 仍是中间比对：`18 match / 26 drift / 1 retired-missing`；本轮不把它的旧 hash 包装成最终文档验收。

12:41 的 B38 Main 是历史限定 snapshot：`B38A88E89CC54A93B0EDEAC58B15528E36741599BC516A4DA523087580390071` 曾有 Application/Provider focused 22/22、TUIC 20 轮/140 次、SOCKS5/SS2022 provider 18 场景和 Hysteria TCP/UDP 运行证据；随后发现 SOCKS5 多绑定 UDP 权限放大问题，且当前生产源码已继续变化。本段只保留其历史范围，不代表当前 Main。

16:16 的 Main `5769C3C1235598E036E45D2A55C05549E3491F6940F0C33ABA1A491FD7AA5A2F` 也只是历史限定 snapshot：TUIC 20 轮/140 次和 Hysteria 正负 TCP/UDP、自然 drain/exit0 证据位于既有 task-4-evidence 目录；后续生产变化使该 executable 不能作为最终当前 Main hash。

07:27 历史 Main `1B726DC7154512A449666B9EDADF25079AB94821339C58422FBF147C43BC6A0F`、配置 `E8BCACB9DF18A410FC9BB999070056C413E41B9637DD021865186F2DDA3BBA9E` 的 SOCKS5 pending session 已完成真实 POST、Session Cancel、peer EOF 和自然 drain：运行中 metadata 为 worker 1、account 1、generation 1、protocol 2、target `127.0.0.1:49293`；POST child 为 stream 7/task 9，`HTTP 400 target_unsupported` 被拒绝而 root literal 继续，关闭后 account/registry 归零、Completed=1、traffic=72 且无重复计数，App/echo 自然退出。结果 `23F495FDEFE7A76231B5AA907AA22AEC33745305178812162B32B6FA0B6DAE57` 与原始进程记录位于现有 [`task-4-evidence`](../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/) 目录。

同一历史 epoch 的 XUDP 限定结果为 109/109 字节、Completed=2、drops=0、两个 association 的 sibling continuation 和自然退出均已核对；对应配置 SHA256 为 `58E4FB80B524FDFBC9A4CDB34E29A311F42177FD03FEF7B93FEBE8FE98784771`，原始结果位于 `task-4-evidence/parallel-live-stats-xudp-1b72-result.json`。该 epoch 当时的 TUIC20轮证据绑定旧 Main5295；上面的12:41快照已另取得 B38 Main 的20轮证据。上述是限定请求证据，不代表全量 CTest、全协议互操作或性能矩阵完成。

上述 `1B726...` 运行已晚于 DA66 识别取消修复和当前统计/Session metadata 收口，但仍只覆盖限定 S5/XUDP 请求；QUIC、剩余 no-compat source、全量 CTest、ODR、Linux 和性能矩阵仍未签收。VMess 8/8、SS2022 5/5、TrustTunnel 5/5 的当前 runtime 结果已由 Root 单独记录，不能扩大为全协议或全 Main 通过。旧 Main5295/BF 与旧 T20 结果继续作为历史快照保留。当前认证唯一 owner 仍是 [`Account/Authenticator.hpp`](Account/Authenticator.hpp) 与 [`Account/Lease.hpp`](Account/Lease.hpp)：`InspectCredential` 只做查询，成功 `Authenticate` 才产生唯一 `AccountId`/`AccountLease`，不保留旧 `Check` bridge 或第二 shared owner。

S5 的 selector 现在对非零 `stream/task` 选择器返回正式 `target_unsupported`/Rejected，不能把 root cancel 冒充成 child 取消；worker 的 `TaskRegistry` snapshot 沿真实 parent→child→grandchild tracked descendants 聚合，不能只读父层计数。原 `GatewayCommon` 已整体移至 [`tests/Experiments/Preview/Quic/GatewayCommon.hpp`](../tests/Experiments/Preview/Quic/GatewayCommon.hpp)，生产 CMake 登记已删除，并在测试专用 PreviewTestSupport 登记完整实验 owner，现仅由两个既有测试消费者使用；它是测试骨架，不证明真实 Main QUIC 能力。

文档 D5 仍未重捕获：原始 13 路文档基线与 10 月 5 日 45 路 manifest 需保留；当前比对为 `18 match / 26 drift / 1 retired-missing`，不能当作当前最终文档验收。

## 先看这些文件

| 主题 | 当前入口 |
| --- | --- |
| 进程入口 | [`Application/Main/PreviewMain.hpp`](Application/Main/PreviewMain.hpp) |
| 启动事务 | [`Application/Startup/Start.hpp`](Application/Startup/Start.hpp) |
| 默认配置 | [`Application/Configuration/PreviewConfiguration.json`](Application/Configuration/PreviewConfiguration.json) |
| 配置生成与秘密解析 | [`Application/Startup/GenerationPhase.hpp`](Application/Startup/GenerationPhase.hpp)、[`Application/Configuration/GenerationBuilder.hpp`](Application/Configuration/GenerationBuilder.hpp) |
| 应用停机与回滚 | [`Application/Shutdown.hpp`](Application/Shutdown.hpp)、[`Application/Startup/StartupTransaction.hpp`](Application/Startup/StartupTransaction.hpp) |
| TCP 会话入口 | [`Runtime/Listener.hpp`](Runtime/Listener.hpp)、[`Runtime/Session.hpp`](Runtime/Session.hpp) |
| UDP 边界 | [`Boundary/Datagram/DatagramListener.hpp`](Boundary/Datagram/DatagramListener.hpp)、[`Boundary/Datagram/DatagramClassifier.hpp`](Boundary/Datagram/DatagramClassifier.hpp) |
| QUIC 边界 | [`Boundary/Quic/QuicPacketGateway.hpp`](Boundary/Quic/QuicPacketGateway.hpp)、[`Boundary/Quic/QuicConnectionRegistry.hpp`](Boundary/Quic/QuicConnectionRegistry.hpp) |
| 协议冷装配 | [`Composition/Provider/ProviderCatalog.hpp`](Composition/Provider/ProviderCatalog.hpp)、[`Application/Startup/ProtocolServices.hpp`](Application/Startup/ProtocolServices.hpp) |
| 账户与租约 | [`Account/Account.hpp`](Account/Account.hpp)、[`Account/Directory.hpp`](Account/Directory.hpp)、[`Account/Lease.hpp`](Account/Lease.hpp) |
| Diagnose | [`Foundation/Utility/Diagnose/README.md`](Foundation/Utility/Diagnose/README.md) |
| 所有权与 legacy 参考 | [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md) |
| CMake 边界 | [`CMakeLists.txt`](CMakeLists.txt)、[`CMake/PreviewBoundary.cmake`](CMake/PreviewBoundary.cmake) |

账户认证与租约的正式 owner 是 `Preview/Account/`：`AccountStore` 单次发布 `AccountBinding`（材料、冻结策略与唯一运行账本），`CredentialIndexView` 按编译 scope 做 typed `InspectCredential`，`Authenticator::Authenticate` 返回唯一 move-only `AccountLease`。文档不能通过别名、转发头或第二套事实重新引入旧认证接口。

## 当前启动链

`PreviewMain.hpp` 是 CMake 的 CXX source。`main()` 读取命令行配置；没有命令行参数时，读取可执行文件同目录的 `PreviewConfiguration.json`，并把 `PRISM_PREVIEW_SECRET_<REFERENCE>` 环境变量解析器交给 `Application::Options`。`Application::Run()` 调用 `Application::Start()`，启动失败返回非零退出码。

当前源码中的控制线程装配顺序如下：

```text
main (PreviewMain.hpp)
  -> Application::Run
     -> Application::Start
        -> Startup::GenerationPhase::Build
           -> schema/reference/capability/secret validation
           -> ConfigurationGeneration (immutable generation)
        -> ProcessServices::Build
           -> DiagnoseRuntime install + process/worker services
        -> ProtocolServices::Prepare
           -> native TLS, dial/resolver and timeout services
        -> ProtocolServices::Bind
           -> typed protocol preparation/bind, datagram/quic services
           -> ProtocolProfile::MakeTcpProfile
           -> compiled profile/resolver stored in SessionServices
        -> BoundaryPhase::Start
           -> Runtime::TcpListener
           -> Boundary::Datagram::DatagramListener when configured
        -> OperationsPhase::Start
           -> operations endpoint and signal handling
        -> PublishPhase::Publish
           -> READY line and Readiness snapshot
        -> StartupTransaction::Commit
```

`GenerationPhase::Build` 失败时不会发布监听入口。`StartupRuntime` 对准备、绑定、边界启动和 Operations 启动按顺序返回 typed `StartupError`；事务负责未发布资源的回滚。成功发布后，`Application::Stop()` 只请求一次停机，真正的顺序由 `Shutdown::ShutdownRuntime` 驱动。

## 请求路径和所有权

TCP 入站目前由 `Runtime::TcpListener` 持有 acceptor、accept loop 和 worker 分发；它为每条连接创建 `Runtime::Session`。这是当前代码事实，不能把 TCP acceptor 的实现位置写成已经迁入 `Boundary/`。UDP socket、分类和 receive loop 位于 `Boundary/Datagram/`；QUIC CID/连接注册、数据报网关和入口 drain 位于 `Boundary/Quic/`。

`Runtime::Session::Run()` 先把控制状态绑定到入站 executor，再进入识别准入和数据面 relay。`SessionRecognitionAdmission` 处理识别/候选选择，`SessionDataPlaneRelay` 消费已编译的 profile、dial、egress 和协议 owner。协议 wire、认证和协议会话仍由 `Protocols/<Name>/` 拥有；Runtime 不实现 SOCKS5、SS2022、AnyTLS、VLESS 或 QUIC 协议帧。

| 边界 | 当前 owner 和真实来源 | 责任 | 生命周期结论 |
| --- | --- | --- | --- |
| `Application/` | `Application/Startup/Start.hpp`、`Application/Shutdown.hpp` | 读取已编译配置，构造进程级服务，启动/回滚/停机 | `StartupTransaction` 管未发布资源；控制线程最终调用 `FinalizeRuntimeResources()` |
| `Composition/` | `Composition/Provider/ProviderCatalog.hpp`、`Composition/Builtin/Registry.hpp` | 冷路径能力校验、协议实例 `Prepare`/`Freeze`/`Bind`、服务注入 | `BoundCatalog` 调用协议 owner 的 `Close`/`Drain`；不拥有协议 wire/auth 规则 |
| `Boundary/` | `Boundary/Datagram/DatagramListener.hpp`、`Boundary/Quic/QuicPacketGateway.hpp`、`QuicConnectionRegistry.hpp` | UDP socket/分类/receive、QUIC 网关、CID 连接登记和入口排空 | `ShutdownRuntime` 先 stop/drain，再释放 datagram/QUIC boundary；QUIC 连接 lease 请求各连接关闭 |
| `Runtime/` | `Runtime/Listener.hpp`、`Runtime/Session.hpp`、`Runtime/Session/ClosePolicy.hpp` | TCP accept/worker 分发、识别、通用 session/relay 生命周期 | `SessionClosePolicy` 触发协议 mux/datagram/active transport close；Runtime 不成为协议 root owner |
| `Protocols/<Name>/` | 例如 `Protocols/Socks5/`、`Protocols/Shadowsocks2022/`、`Protocols/Anytls/`、`Protocols/Vless/` | wire、认证、连接/stream/datagram 状态机和协议级 close | 协议认证产生 typed `AccountLease`；root/child 由协议 session 及其 task scope drain |
| `Foundation/` | `Foundation/Fault/`、`Foundation/Memory/`、`Foundation/Utility/Diagnose/` | 中立错误、内存、日志和基础值类型 | 不持有具体协议装配；Diagnose backend 在应用控制边界安装和最终关闭 |
| 中立生命周期 | `Lifecycle/` | `TaskRegistry`、取消、task drain 和生命周期交接 | 不拥有具体协议认证或应用装配 |
| 中立契约 | `Contract/Ingress/`、`Contract/Services/`、`Net/`、`Transport/`、`Account/` | typed ingress/request、dial/relay/traffic、传输和账户租约契约 | 不按协议名称做热路径分派；持有方通过值/`shared_ptr`/move 明确生命周期 |

认证和租约的当前事实是：`Preview/Account/Authenticator.hpp` 的 `DirectoryAuthenticator` 从编译后的 `CredentialIndexView` 直接取得 `AccountLease`；`AccountLease` 的最终释放者是持有它的 root/session，子 stream 通过 `StreamAdmission` 获得自己的 `StreamLease`。`Contract/Ingress/MuxSession.hpp` 的 `MuxRootRequest` 按值携带 root lease 和元数据，不能在 Runtime 中复制第二份 lease。

stream 的 wire 和 FIN/半关闭由具体协议 session 管理；通用双向 relay 位于 `Net/Relay/` 及其服务封装。root close/drain 由协议 owner 收口，`Composition::Provider::BoundCatalog::Drain()` 等待这些 owner 的 drain，`Application::Shutdown` 再按 operations、QUIC registry、provider catalog、TCP listener、datagram、worker task registry 的顺序收尾。executor 由应用/worker/session services 注入；`Runtime::Session::RunCore()` 会回到入站 executor 后再运行准入和数据面。

## 冷路径绑定与热路径约束

配置中的 `Builtin`、`ProtocolId` 和 `MuxModes` 只在配置校验、generation、`ProviderCatalog::Prepare`/`Freeze`/`Bind` 以及 `ProtocolProfile::MakeTcpProfile` 等启动冷路径解析。请求处理应消费已编译的 profile、resolver、typed provider binding 和协议 session；每个 packet/frame 不能重新按字符串查找、动态注册或走空 factory 表。

当前 S5/SS2022 configured mux 已有分层 focused 证据，但仍属于 Task4 WIP：001/002 的 16 个 focused case、003 的 SOCKS5 单 child 真 root run、004 的两族单 child 真 root run、005 的两族 echo/cancel 4 case分别只证明各自窄范围；006 的 quota2 最终版本已由 Root 签收 6 case：第二 wire child 被拒绝且无新 dial，第一 child 随后完成独立 literal continuation 回显，最终计数归零并 drain；首轮与中间失败分别保留。上述热路径规则和 focused green 都不能宣称 configured mux 整体、所有协议或真实 `PrismPreview` listener 已通过。

## 构建、配置和测试分层

只使用仓库现有的 `build/`。构建前记录上海时间：08:00–22:00 使用 `-j 16`，22:00–08:00 使用 `-j 1`。当前 target 命令为：

```text
cmake --build build --config Release --target PrismPreview -j 16
```

夜间把 `-j 16` 改为 `-j 1`。首次配置仍使用现有 `build/`，不要创建 `build_debug`、`out` 或其他构建目录。

`Preview/Application/CMakeLists.txt` 将 `Startup/Start.hpp` 作为 `PreviewApplication` 的 CXX source，并将 `Main/PreviewMain.hpp` 作为 `PrismPreview` 的 CXX source；target 输出固定为 `build/src/PrismPreview.exe`。POST_BUILD 会把 [`Application/Configuration/PreviewConfiguration.json`](Application/Configuration/PreviewConfiguration.json) 复制到 `build/src/PreviewConfiguration.json`。运行时默认配置路径就是这个复制位置。

这两个 `LANGUAGE CXX` 头文件各自承载唯一翻译单元，禁止生产头或测试 include 它们。`Start.hpp` 的 `Application::Start()` 是类外非 inline 定义，重复 include 会产生链接期重复定义；`PreviewMain.hpp` 承载进程入口。`scripts/check_preview_reachability.mjs` 从 CMake 的 `LANGUAGE CXX` 登记解析这些入口，并以 `tuRootIncluders` 检查根路径及相对路径 include；结果必须为空。

验收必须分层记录：

1. 源码和 CMake include/target 边界静态检查。
2. `PrismPreview` configure/build 及当前源、配置、可执行文件 hash。
3. focused CTest；CTest 注册名和 GoogleTest suite 名要写清楚。
4. 必要的全量 CTest；不能用旧 XML 或旧名称清单冒充当前全量。
5. 真实 listener 请求、认证正反、payload 重复、半关闭、root/child close、drain、进程结束和日志关联。
6. 厂内互操作、第三方 wire 互操作和性能基准；每项都要绑定相同源快照、配置和 executable hash。

源码门禁仍适用于新增或迁移的 Preview owner：生产实现保持 header-only，不重新引入生产 `.cpp`；每个生产 header 不超过 600 行；函数体不超过 120 行；lambda 不超过 10 行；普通函数参数不超过 2 个，复杂边界最多 3 个；公共契约写明输入所有权、输出/错误、取消、半关闭、最终关闭者和 executor。不得用 `Compat`/`Legacy` adapter、旧 overload、万能 context、作用域 include 或假 CMake target 制造模块边界。

## 当前状态和未完成项

截至 2026-10-08，Task1、Task2、Task3A/3B/3C 已分别签收；Task4 尚未最终冻结，Task5 与6A 的接口迁移已有限定验收，6B 的当前统计接线已有173个focused用例及真实请求证据，Session metadata/Operations Cancel 已在当前 Main 得到限定结果，6C在并行整改。各次 focused、旧951名称基线和2026-09-26 Diagnose 387/387 都是日期绑定证据，不能合并为当前全仓通过；最新结果与剩余项见[当前执行状态](../docs/preview-refactor/2026-10-03-preview-no-compat-status.md)。

S5/SS2022 configured mux 的 quota、replacement、兄弟 root 和 drain 已有 focused 实证；AnyTLS、Trojan/VMess 三 mux 模式及 XUDP 也已验证真实 Main 请求。后续公共接口变化仍需重建这些路径，完成全 scope contract/style/detached、完整互操作、全量 CTest 和同输入性能比较。`Statistics.Enabled/Interval` 由 Application 安装唯一数值 TrafficCounter 并在控制域定时刷新；成功写入只提交 bytes 增量，最终关闭只提交零字节 Completed 事件，停机在业务 drain 后最终 flush。当前173个focused用例、TCP 36B 统计、XUDP 109B 统计、Session metadata 和 Operations Cancel 均已有限定版本真实证据；后续源修改仍需 Root 以当前 epoch 重建，不能据此宣称全量验收。

Task7B 的 owner harness 当前源路径为 `tests/Preview/Performance/RecognitionPerf.cpp`；旧 `tests/Preview/perf/RecognitionPerf.cpp` 源路径已退役，旧 `build/tests/Preview/perf/RecognitionPerf.exe` 只属于 stale 产物，不作为当前证据。当前磁盘源文件 SHA256 为 `2BB356AA4E29FD3CBD9AEC26FB58120DC7C129E08EF7479C1B24ACBE0829F3C5`，当前 `build/tests/Preview/Performance/RecognitionPerf.exe` SHA256 为 `261C7577D8CDDA575082A647787BF8AEE849273DF97318FEE74C29F0E45203F9`；两者只标识当前磁盘输入和产物边界，尚无与该边界绑定的 `--owner-compare` raw 运行证据，不能写成性能完成。当前固定 trace 覆盖 CID scale 与 SNI route capacity `8/64/1024`，保留真实 `DatagramClassifier`、`Profile::LookupRoute` 和 `DirectoryAuthenticator` baseline；Account 候选明确是 idealized lease lower bound。原 Task7B 的 mux、coalescer、I/O、真实 Application 路径和最终五轮 raw 证据仍待 Root 串行验收。

所有测试、server/client、bench 和临时 probe 都必须记录 PID/path/start time，并在使命完成后清理。本轮复用现有工作树、`build/`、客户端与台账，保留用户已有改动和用户进程；构建、运行与文档检查分别记录证据。
