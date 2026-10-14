# Preview 全模块重构续作：删除旧接口与兼容层

用户授权：2026-10-03 明确要求继续执行并开始修改，旧接口不再兼容，不保留兼容层。本计划续接原全模块计划及当天执行质量复核，不把已经通过的文件拆分重复记为新成果。

2026-10-05 补充要求：子代理按用户最新选择统一使用 `gpt-5.6-luna/max`，由 Root 编写具体任务卡并核对完成度与质量；更新 Preview 及相关 Markdown，不用旧接口、旧配置或历史测试结果描述当前实现。当前进度以[执行状态](2026-10-03-preview-no-compat-status.md)为准。

## 固定约束与当前基线

- 复用 `I:/code/Prism` 的 `codex/preview-refactor-20260928` 分支与现有脏工作树，起始 HEAD `3c5b678f2e06227b2a5da5b1ac406b5f79ea9828`；起始 Git 可见 471 个改动路径。保留所有已有改动。
- 只使用既有 `build/`；每次构建先输出上海时间，08:00–22:00 用 `-j 16`，22:00–08:00 用 `-j 1`。所有构建串行，本轮实施授权包含必要构建、测试与本地真实请求验收。
- 不执行 commit/push/amend；不使用 Python；只清理本轮创建的进程与临时产物。
- Preview 生产实现继续 `.hpp`，每个生产 header <=600 行；函数 <=120 行，lambda <=10 行；公共接口默认 <=2 参数，复杂边界 <=3，不能以万能 context 隐藏耦合。
- 删除旧 API、旧 alias、兼容 adapter、fallback 与重复正式数据源；全部消费者和测试同步迁移。协议标准 wire 保持当前合同，移除内部兼容入口不等于静默改变标准协议字节。
- Composition 只负责注册、配置 prepare、冻结、bind；协议目录拥有协议运行态、认证、配额和关闭；Application 只负责进程服务与启动/回滚/停机；Boundary 只负责入口。
- 每卡须有真实行为测试、当前构建与 scoped review；原测试需迁移其行为覆盖，不能仅为编译绿灯删除有效断言。新缺陷先记录 red，再修改生产代码。
- 按用户10月7日的新要求，四个子任务角色轮转、可运行的三个子代理按文件所有权并行；Root管理共享接口交接、唯一构建、验证和审查。复用现有计划、进度与证据目录，不再为每个小修创建独立brief/report/脚本/target。必要新生产owner须有真实职责，源码移动必须删除旧路径并迁调用者；子代理不再派代理。不能因阶段通过结束整张计划。

## 2026-10-09 22:46 当前 epoch 文档同步门禁

D06 当前同步只更新文档，不改源码、CMake、脚本、测试或原始证据，不构建、不运行 CTest、不启动进程。当前磁盘边界为 `Preview/` 生产 639 个 `.hpp`、0 个 `.cpp`；`PreviewMain.hpp` SHA256=`D6A84733F33ACE31DCE6865B4DE0BD6E08A4E93946572051B3FC8919A1D219C8`、`Start.hpp` SHA256=`3D03F6661DA7CA90ECF3CC40E87F7D3F42676C83AB64A2EC09C239AAB6B46E90`、`build/src/PrismPreview.exe` SHA256=`F5363B287941A4B6B7599FCD1EC041311885B8A4100A219FEF0487794523F3DC`，配置模板/副本均为 `C245C56845ACC08F415F14CB372F1FABE54F541241E914880A0BE536D80E3501`。该 EXE 目前只有当前磁盘文件事实；没有把上述当前 source/config hash 与它绑定的 build manifest/log，因此缺少当前 source→binary build provenance，不能单独作为当前 Main acceptance。旧的 19:04 source-v3 manifest 只能作为旧入口快照，不能覆盖当前源码漂移；`88922FAC...` 是本轮较早磁盘快照，不是 current hash。

Provider 当前只接受 18-case/exit0 与 `Remaining=0` 的清理证据；现有 Provider18 记录没有当前 source/EXE/config 三元 hash binding，cleanup 明确不是 Main natural-exit 证明，也不能升级为当前 Main acceptance。I02 runner 已存在于 [`scripts/interop/Run-Matrix.ps1`](../../scripts/interop/Run-Matrix.ps1) 和 [`tests/Preview/integration/Matrix`](../../tests/Preview/integration/Matrix)，但当前 Main Hysteria2/TUIC/Mihomo runtime acceptance 尚未运行/签收。preview-only Interop 最新为 `53 pass / 6 blocked / 1 failed`、EXIT1；该结果同样没有当前 Main source/EXE/config 三元 hash binding，不能升级为 I02 Main acceptance，因此计划中的 I02 仍保持未完成。

P04 后续证据只到 DnsCache validate/preflight、smoke 和部分 DNS coalescer 记录，ABC `540` matrix 未闭合。旧 `coordinator-9-current-dnsperf-coalescer.log` 的 `EXIT=-1073741819` RED 与后续 `coordinator-9-dns-coalescer-fix-verify.log` 的 1/2/4 owners×5 rounds `valid=yes`/exit0 green 均保留，但两类记录都没有当前 source/EXE/config hash/epoch binding，不能当作当前性能验收。G02 的 `640-row` standalone-header/ODR/CXX owners、CMake target-graph/exact-case 与 negative/restore 输入均标为 `pre-current` prepared inputs，仍未运行。A01 阶段一采用 D06 按当时磁盘计数派生的 fixed639 normalized ledger，写为 `A10/B0/C26/D1/N602/E50/F14`，`safe-delete=0`；不与 live640 混读，阶段二仍无批准。Linux 继续 blocked，未运行 Linux 编译/CI。D08 只修正文档路径与 provenance 口径；下一 Root 复核卡是 D5/D01 current-epoch 文档复核，需统一检查本三文件的 delta、路径、锚点、命令、配置、hash、source→binary binding、证据层级和历史标注；本计划不因 D06/D08 文档更新而变成阶段二或 Task 8 完成。

## Task 1: Boundary 拒绝后保留 packet 所有权

目标：消除 `BoundaryDispatcher -> QuicPacketGateway::Handle` 移动 packet 后拒绝并回落的数据丢失。gateway 只借用 packet，拒绝不改变 payload/CID/peer/sequence，只有正式交接的最终 handler 消费值所有权。直接迁移所有消费者，不添加旧按值 overload 或 alias。

可编辑范围：`Preview/Boundary/Contract/BoundaryDispatcher.hpp`、`Preview/Boundary/Quic/QuicPacketGateway.hpp`，当前测试为 `tests/Preview/Boundary/{BoundaryDispatcherTest.cpp,QuicPacketGatewayLifecycleTest.cpp,DatagramBoundaryServiceTest.cpp}` 与 `tests/Preview/integration/Session/Datagram/DatagramProtocolServiceTest.cpp`。原 `tests/Preview/core/runtime/{BoundaryDispatcherTest,QuicPacketGatewayLifecycleTest,DatagramServiceTest}.cpp` 是迁移前历史 locator；其中 `DatagramServiceTest.cpp` 已拆分，旧路径不作为 current。若真实调用者还需迁移，仅修改必要调用点并在报告列明。不编辑 Application、Provider、公共 CMake、其他模块。

TDD：先补 gateway unknown CID、closed/draining、budget exceeded、handler 拒绝时的 fallback 字节与完整 metadata 断言，旧实现须稳定失败；accepted case 只进入 QUIC handler。literal fixture 独立给定 payload、CID、peer、sequence，不只检查调用次数。旧行为红灯后改变正式 borrowed packet 接口，迁移调用者，再运行 Boundary/Datagram/QUIC focused 集合。

拒收：仅拷贝一份备用 packet 掩盖 owner 合同、保留旧 overload、fallback 字节丢失、把回调计数当 payload 验收。退出 gate：红灯/绿灯、完整 packet 回落、当前 targets、scoped review 均通过。

## Task 2: Application 启动事务和服务所有权

目标：所有 fallible startup 分支使用唯一回滚合同；Mux 服务不捕获拥有自己的 SessionServices。以具有明确生命周期的协议服务快照或独立 relay services 注入 Mux 回调，禁止用“停机清空所有回调”掩盖设计循环。成功 Stop、profile 构建失败、child drain 后 owner 实际释放。

可编辑范围：`Preview/Application/{Startup,Assembly,Application.hpp,RuntimeState.hpp,Shutdown.hpp,ProtocolAcceptors.hpp,ProtocolProfile.hpp}`、`Preview/Application/Startup/{ProtocolServices.hpp,QuicServices.hpp}`、`Preview/Runtime/SessionServices.hpp` 及 Application/Mux focused 测试。旧 `Preview/Application/MuxStartup.hpp` 是退役历史 locator；当前相关 mux/cold-bind owner 以 `ProtocolAcceptors.hpp`、`ProtocolProfile.hpp` 和 `Startup/ProtocolServices.hpp` 为准。新 header 的 CMake source 登记由该卡串行集成。不得加纯测试用途的生产 getter/hook。实现可观察失败路径/释放测试，先失败后修复。

同时把 `Application::Start` 按 generation、process services、protocol binding、boundary、operations 和 publish 分为真实责任函数，各 <=120 行；Mux 日志和 handler 不再用四/五个参数或长业务 lambda。旧 startup helper/API 全部迁移并删除，不留 forwarding wrapper。

## Task 3: Provider 拥有真实 factory 与 active binding

目标：Hysteria2/TUIC/SS2022/SOCKS5 的 descriptor prepare 接收真实协议配置和实际能力，Bind 返回拥有具体 factory/active handle 的 typed binding；BoundCatalog 管理这些资源的唯一关闭合同，Application 不再选择协议并构造具体 factory。删除 AllCapabilities 假供给、空/标志 owner、旧 ProtocolAcceptAdapter gate 和 Application protocol factory 构造路径。

范围：`Preview/Composition/Provider`、`Preview/Composition/Quic`、必要中立合同、协议 prepare/binding、`Preview/Application/{Assembly,ProtocolAcceptors.hpp,ProtocolProfile.hpp,BoundaryStartup.hpp,ProtocolCarrierRegistration.hpp}`、`Preview/Application/Startup/{ProtocolServices.hpp,QuicServices.hpp}`、相关 tests 与 CMake。旧 `Preview/Application/QuicStartup.hpp` 是退役历史 locator，不作为 current。禁止 Protocols 反向 include Composition/Application。

验证：能力缺失、secret/协议配置非法时无资源发布；实际 QUIC/raw UDP/control-stream factory 被消费；generation pin、重复 Bind、取消、失败回滚和真实资源 exactly-once close。Hysteria2/TUIC/SS2022/SOCKS5 真实 listener 数据与认证正负例，最终 hash 记录。只移 factory 文件或新增 bool gate 不计完成。

## Task 4: 协议运行态归位及 UDP owner 收口

目标：AnyTLS frame/stream service、VLESS XUDP association、generic Mux/SingMux writer/root-child/StreamLease、SOCKS5/Trojan/VLESS/VMess UDP service 全部由协议 owner 持有。Composition 只产生 typed binding，Runtime 只消费正式 stream/datagram/mux contract。

删除中心 `Composition/UdpService` 的协议 RTTI/检测分派与 fallback；删除 `Composition/{AnytlsService,VlessXudp,MuxService,SingMux,H2MuxServer}` 的旧运行态入口，迁全部实际调用者与测试。raw UDP、QUIC DATAGRAM、stream/control association 保持不同 wire，但共享明确的 exchange/取消/关闭契约，不做万能上下文。

验证：真实 TCP/UDP/多流 payload、partial I/O、取消/半关闭、MaxStreams=1 的真实 child admission、parent drain 后连接/流计数归零和 report exactly once。

## Task 5: 唯一 typed handoff 与中立 carrier contract

目标：保留一个正式的 move-only typed protocol accept outcome，target/account/transport/PostDial 不再在 Handler、TypedAcceptResult、Context 之间双向同步。删除旧 AcceptResult shape、SessionOptions 裸服务字段、Context 兼容字段与 Materialize/Synchronize fallback；协议、middleware、测试同步迁移。

`FacadeCarrier` 等纯 carrier 契约下沉中立层，Reality/Restls/ShadowTLS 等协议不能 include Composition。Header/API/CMake 同时验证依赖方向。移除纯兼容 overload、大小写别名、旧 result/callback 名称；保留有实际领域语义的类型。

验证：认证成功唯一 lease 转移、认证拒绝不构造可转发 plane、post-dial reply/cancel、mux 根/child 类型、所有协议 encode/accept/relay 的 focused 与真实请求。

## Task 6: 旧消费者退役与目录合同收尾

目标：迁移后删除旧 Settings/JSON parser、Runtime/Front、Foundation Utility Account/Coroutine registry、legacy Authenticator::Check 和 Composition/Api 等第二套入口。Net/Outbound/Route、ProbeDefense、Scheduler、双统计轨需明确唯一生产 owner；没有生产 consumer 的实验实现移出生产 target，不能当成已部署能力。

清理旧 API 的 tests/bridges/CMake source 登记，迁其有效行为覆盖；更新 include/CMake 物理图检查。按原 77 目录逐项记录实质接口、不变量或删除证据；新增目录独立列出，不改变历史分母。不得为“每个目录都改”制造无意义代码。

## Task 7: 真实互操作稳定性与算法/I/O gate

目标：定位并修复 TUIC 连续 handshake/close 不稳定，不增加 sleep/retry 掩盖；Hysteria2/TUIC、所有代理/carrier 在当前源码+配置+exe hash 上验证认证、真实 bytes、取消、半关闭、drain 和清理。已有同 trace SessionRegistry/DNS 比较补真实 Listener/Operations Cancel/Drain、Resolver 和 eviction 语义；完成 CID/SNI/mux/account/I/O 后续对照，收益不足时保留现状并给出最终结论。

仅在正确性通过后采纳算法。至少五轮交错、1/2/4 并发，吞吐、p50/p95/p99、分配/内存保留原始结果；不以 Perf label PASS 证明改进。获得 Linux 编译证据；如环境不存在，先完成可执行 CI/交叉检查配置并准确列环境边界，不伪报。

## Task 8: 最终整体验收与交付

目标：正式旧接口、兼容层与反向依赖清零；600 行/函数/参数/ODR/source ownership 门禁、配置/build、focused、全量 CTest、真实请求/互操作/性能分别留当前证据。一次 broad review 后修复所有阻断项，记录唯一最终状态，不混写累计成果和本轮增量。

没有剩余实施卡与阻断缺陷才称全模块任务完成。用户进程/脏工作树受保护，只清理本轮资源；不提交或推送。报告写中文，保留 technical identifiers。

## Task 9: Preview 测试结构与命名整顿（2026-10-08 追加授权）

本卡与原 Task 4–8 共同完成，不取消尚未闭合的行为、互操作和性能验收。用户要求 `tests/Preview` 全部使用 PascalCase，测试实现按功能放入不超过 800 行的 CPP；仅多个 CPP 真正消费的模块内部封装可使用共享 HPP，禁止测试声明与实现配对、搬正文入 HPP、文本拼接、无语义编号和丢失断言。普通行为测试继续使用 GoogleTest，实际 client/server、压力和性能入口保留其可核查契约。

迁移前快照为 `.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/preview-test-layout-baseline.json`：448 文件、351 CPP、24 HPP、46 个 CPP 超过 800 行、2907 个源码测试宏定义。宏定义数不等于 CTest 注册数，参数化、禁用和独立入口需分别核对。此前完整测试为 4896 注册、25 disabled、4871 参与、23 失败或未运行；重组不能把旧 binary/XML 当新结构的通过证据。

| 模块卡 | 唯一编辑范围 | 集成与验收责任 |
| --- | --- | --- |
| T-Core | 原 `core/Core` 内容及其真实生产 owner 对应的目标测试目录 | 逐 API 归 Account、Application/Configuration、Composition、Foundation、Lifecycle、Net、Runtime、Transport 等，不保留 Core/Coroutine 中间层，保持所有权与错误回归 |
| T-Protocols | `tests/Preview/Protocols`（迁移前 `protocols`）及其子 CMake | 直接按生产协议 owner 拆分，退役 Stealth/Core 旧分类；保 codec/wire、认证、FIN/RST、取消与 drain 强断言 |
| T-Perf | `tests/Preview/Performance`（迁移前 `perf`）及其子 CMake | 与实际 Performance 命名对齐，按 trace、测量 owner、正确性预检和报告职责拆分，保原 CLI、输入规模、五轮顺序和计时边界 |
| T-Integration | `tests/Preview/Integration`（迁移前 `integration`）及其子 CMake | 按真实 client/server 与认证/请求行为组织，保第三方标准和完整 payload/自然关闭证据 |
| 主会话集成 | Carrier、Stress、Interop、根 CMake、共享中立 TestSupport、脚本、文档和门禁 | 接收 old→new 源/target/CLI 映射，核对所有外部引用，清理精确退役构建产物，统一重新配置、构建和运行 |

每张模块卡先给旧用例/主入口/CLI、文件 hash 与功能边界，完成后列新文件行数、共享 HPP 实际消费者和不变的行为断言。主会话逐项核查源码和运行结果，不能凭子代理总结签收。并发目标为主会话加四个模块子代理，实际运行不得超过工具提供的槽位；槽位不足时明确排队，不虚报同时运行。

用户已批准删除此次修改后退役的旧构建内容。清理前保存证据并核对对应 source/target、完整路径及本任务进程退出，再删除旧 EXE、对象与生成登记；有效测试产物、依赖缓存和整个 `build/` 保留。没有 commit/push/amend、Python、新构建目录或用户进程清理权限。最终以新目录、新 CMake、新源码及 binary hash 的分层验收收口。

## 文档同步任务卡（2026-10-05）

文档与代码同步推进，正式文件的修改避开编译输入快照。每张卡列出修改文件、旧说法、真实源位置、实际验证层级及未完成责任；Root 逐项核对后签收。历史报告保留原日期和当时结果，不倒填今日验收。

| 卡 | 范围与执行者 | 必须交付与退出条件 |
| --- | --- | --- |
| D1 当前开发入口 | 文档代理：`Preview/README.md`、`docs/ARCHITECTURE.md` | 真实启动与请求路径；五个 owner 边界与中立契约；header-only/所有权/executor/关闭说明；旧版架构单列；所有路径可定位 |
| D2 模块文档 | 同一文档代理：当前 `Preview/Account/README.md`、`Preview/Foundation/Utility/Diagnose/README.md` | 清除不存在文件和接口；旧 `Preview/Foundation/Utility/Account/README.md` 仅为退役历史 locator；说明当前正式 Account owner 与存量待退役目录；Diagnose 公开 API/backend/日志失败边界逐段核源，不能用历史 387 用例签当前 |
| D3 用户操作入口 | Root 或后续文档代理：根 `README.md`、`docs/index.md`、五篇 `docs/tutorial/` 指南 | 统一 PrismPreview、PreviewConfiguration.json、现有 build/；真实命令行、严格字段与 secret 规则；不提供未接线配置或虚假服务安装指令；静态核对示例与全部本地链接 |
| D4 台账与历史导航 | Root：当前执行计划/状态、dated Preview 分析与验收文档的状态入口 | 当前任务状态与剩余责任准确；历史文档明确快照，链接当前入口；构建、focused、全量、真实请求、互操作、性能分开，不修改原始证据 |
| D5 最终文档复核 | Root 于 Task 8 完成 | 按最终源码重查所有本轮文件、路径/锚点/字段/命令和证据 SHA；列完整文档 delta 与待验证平台；实现未结束时不写“全模块完成” |

本轮文档基线为 `.superpowers/sdd/2026-10-03-preview-no-compat-execution/docs-20261005-baseline/manifest.json`，包含 12 个已有文件和一个缺席的 Preview 入口。无 Python、无新增构建目录、无 commit/push；实际命令与静态文档校验分别记录。
