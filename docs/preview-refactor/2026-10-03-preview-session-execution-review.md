# Preview 引用会话执行完整度与质量复核

> 文档状态说明（2026-10-05）：本文保留原版本的分析、计划或验收快照，文中的“当前”、完成标记、路径和测试数字均属于原记录时点。今天的 Preview 入口、已执行范围与剩余责任见[开发入口](../../Preview/README.md)和[当前执行状态](2026-10-03-preview-no-compat-status.md)。本轮不改写原始历史结果；旧任务提示词需先核对现行 AGENTS.md、无兼容层计划和真实源码，不能直接替代当前任务卡。

复核日期：2026-10-03（Asia/Shanghai）。引用会话：`01a0e753-2c83-7c73-82c2-5e5b81d8ceb2`。

结论：原计划没有执行完。文件拆分、生产 `.cpp` 清零、Boundary 改名和部分行为修复有实际成果；完整 provider factory、协议运行态归位、旧消费者退役、生命周期正确性和最终版本互操作仍未闭合。当前实现可以继续在现有工作树上收敛，但不能按“低耦合、高内聚、完整插件槽位已交付”验收。

## 1. 读取范围与证据口径

- 用 `read_thread` 顺序读取四页，直到 `hasMore=false`，共 31 个任务轮次。工具在大轮次中有条目上限，部分中间轮次也为空，因此同时遍历本地原始 JSONL 补齐历史。
- 原始记录位于 `C:/Users/C1373/.codex/sessions/2026/09/28/rollout-2026-09-28T17-23-02-01a0e753-2c83-7c73-82c2-5e5b81d8ceb2.jsonl`，本次遍历 61,788 条记录，无 JSON 解析失败；核对了各轮用户要求、27 份最终回复、关键执行和测试输出。记录有 36 次压缩，不能仅用工具最新摘要重建执行经过。
- 读取了用户最后贴回的《Preview 全模块职责重构与 Boundary/Provider 插件化计划》，并对照早期全模块计划。9 月 30 日的 header-only 决策取代早期“非模板实现进入 `.cpp` 编译单元”的方向，不能把移除 `.cpp` 本身当成不合格。
- 源码按当前真实 `Application::Start -> ProtocolProfile/Boundary -> Session` 路径检查。先使用 CodeGraph；对未展示的代码及标记待同步的条目补读源码。
- 本次质量检查集中于启动事务、provider binding、Mux/UDP 装配、配置/secret generation、Boundary packet 交接、include 方向及既有行为修复。没有声称对 605 个 header 逐函数完成正确性审计。
- 本轮没有构建、重新运行 CTest 或启动代理服务。新鲜验证是磁盘盘点、旧名称/include 搜索、G7 和 `git diff --check`；运行数字属于带时间和版本边界的历史证据。

## 2. 当前工作树

| 项目 | 2026-10-03 当场结果 |
| --- | --- |
| 分支 | `codex/preview-refactor-20260928` |
| HEAD | `3c5b678f2e06227b2a5da5b1ac406b5f79ea9828` |
| 复核开始时 Git 可见改动路径 | 470，使用 `git status --porcelain=v1 -uall` 计数 |
| 其中 Preview / tests | 321 / 140；不把所有改动都归因于引用会话 |
| Preview 生产 `.hpp` | 605 |
| Preview 生产 `.cpp` | 0 |
| 超过 600 行的生产 header | 0 |
| `Preview/Ingress` | 不存在 |
| 旧 Ingress 路径、指定旧类名和旧 target | 本轮在 Preview、tests/Preview、scripts 搜索无命中 |
| G7 | exit 0，`611 headers, 611 owned entries` |
| `git diff --check` | exit 0；两处既有 CRLF 转 LF 提示 |

G7 验证 header 与 CMake source 登记的归属，不证明协议生命周期唯一、没有反向 include、每个 symbol 的实际 owner 唯一，或真实请求已经通过。它的检查范围也不是整个仓库所有文件。

旧台账的原始 77 目录矩阵仍为：已完成 20、部分完成 48、未完成 8、明确删除 1。这个数字是已有台账的分类，不是本次对 77 个目录重新做全套行为验收后的结果；“已完成”包含保留的纯值/engine 模块，不适合换算成工作量完成百分比。

## 3. 对计划的当前判定

| 原始交付目标 | 判定 | 当前证据与缺口 |
| --- | --- | --- |
| `Ingress -> Boundary`，删除旧正式路径和名称 | 文件/登记层面完成 | 实际目录已删除，搜索无旧正式名字；协议扩展仍涉及 Application 接线。 |
| 28 个生产 `.cpp` 移除，生产 header 不超过 600 行 | 数量门禁完成 | 605 header、0 cpp、0 over600；不等于长函数和职责错位全部解决。 |
| Application 单体拆除 | 文件拆分完成，职责收敛部分完成 | `Application.cpp` 已删除，但 `Start.hpp` 仍集中装配多个具体协议和服务分支。 |
| 配置分阶段、secret 每代持有一次 | 有实质改善，仍未形成完整可执行 provider 计划 | `PreparedConfiguration` / `SecretResolutionTransaction` / sealed lookup 已存在；协议候选与 factory 仍在 Application 再构造。 |
| `Register -> Validate -> Prepare -> Freeze -> Bind` | 通用目录状态机完成，生产 provider 未完整接管 | 真实 Bind owner 是 generation/attached slot；没有持有实际 Hysteria2/TUIC/SS2022/SOCKS5 factory。 |
| 三类 UDP 接入和协议 owner 统一 | 部分完成 | 四个 stream-carried UDP adapter 绑定 typed runner；中心 `UdpService`、SS2022 启动装配、QUIC factory 仍存在。 |
| 协议业务归协议、Composition 只装配 | 未完成 | AnyTLS service、VLESS XUDP、Mux/SingMux 运行态仍在 Composition，Start 直接调用。 |
| 单一 typed data plane 与账户交接 | 有修复，过渡合同未退役 | 旧租约覆盖缺陷有修复；Handler、TypedAcceptResult、Context 仍保留兼容字段与同步/转换。 |
| include 与 CMake 同时验证依赖方向 | 未完成 | Reality/Restls/ShadowTLS 仍 include Composition 的 carrier contract，Runtime/Front 仍 include Composition。 |
| 全量回归和真实互操作 | 历史回归可信，最终快照验收未完成 | 4716 全量在 typed UDP 之前；其后 460 focused 通过；TUIC 最新连续 runner 失败，外部证据 hash 与当前 exe 不同。 |
| 算法/I/O 多方案性能对照与生产采纳 | 首批实验已执行，最终采纳门禁未过 | SessionRegistry/DNS 有同 trace、多轮数据；真实请求与取消/drain 等非等价合同仍使 replacement gate 拒收。 |

没有依据要求推倒已经实现的所有拆分。剩余工作应以真实 factory、资源关闭、唯一数据源和旧 consumer 删除为验收对象。

## 4. 已做部分的质量

可以认可的成果：

1. SessionRegistry 的 CAS 重试现在构造 `Record{Info, Entry}`，没有在每次失败重试时继续消耗同一个已移动 `Info`。旧 token、逻辑删除/压实和故障注入有红灯到绿灯记录。见 [SessionRegistry.hpp](/I:/code/Prism/Preview/Runtime/SessionRegistry.hpp:187) 及原台账第 19.4 节。
2. `ProtocolAdapter` 的 typed 分支在 `SetDataPlane` 后，不再用旧结果中的已移动租约覆盖 Context；旧字段回填放在 `else` 分支。见 [ProtocolAdapter.hpp](/I:/code/Prism/Preview/Composition/Adapters/ProtocolAdapter.hpp:86)。这是行为修复，不是改名。
3. 配置文件的 prepared 路径返回有拥有权的配置/secret transaction，generation 验证通过 `Lookup` 消费已解析内容，最终把 secret store 移入不可变 generation。见 [ConfigurationParser.hpp](/I:/code/Prism/Preview/Application/Configuration/ConfigurationParser.hpp:168) 和 [GenerationBuilder.hpp](/I:/code/Prism/Preview/Application/Configuration/GenerationBuilder.hpp:89)。原先 resolver 被重复调用的风险得到实质处理；公共/能力校验仍有多个阶段，并未全部取消重复遍历。
4. Hysteria2 的 auth、TCP response prelude、标准 QUIC DATAGRAM 和 admission 已有真实错误认证、TCP/UDP payload 与 drain 的历史证据。HTTP 转发安全、账户交接等也有原台账中的针对性红灯和修复记录，不能说整场只有拆文件。
5. 本轮 G7 重新运行通过，旧名称搜索与 header 行数盘点也通过，说明文件登记和迁移门禁确实落地。

不能据此签收的部分如下。

### 4.1 Provider 的生产绑定仍主要是状态门控

[StandardProviders.hpp:59](/I:/code/Prism/Preview/Composition/Provider/Builtin/StandardProviders.hpp:59) 的 `PrepareStandard` 只检查 key、profile 非空和 generation 非零；`BindStandard` 调用 `Attach` / `MakeOwner`。

[ProviderAssembly.hpp:111](/I:/code/Prism/Preview/Application/Assembly/ProviderAssembly.hpp:111) 传入 `AllCapabilities`，并对所有协议使用 `ProviderConfig{"application", 1}`。其 local runtime 保存 generation 和 `Attached[5]`；owner 的 Close 只把对应标志改成 false（第 222-240 行）。实际关闭 QUIC registry、SS2022 gateway 等仍由 Application Shutdown 单独完成。

因此已经有可测的 Catalog 状态机和 typed admission gate，但没有完成计划要求的协议配置 prepare、具体 factory/active handle、资源绑定和唯一最终关闭者。尤其不能把这个 owner 的 exactly-once 标志清理等同于整个协议资源的 exactly-once close。

[Start.hpp:299](/I:/code/Prism/Preview/Application/Startup/Start.hpp:299) 仍按 Hysteria2/TUIC 类型构造各自 factory options 和 server factory；第 206-249 行仍直接收集 SS2022 keys 并创建 gateway。新增协议仍需要改中心装配路径，尚未达到“新增协议 provider 与测试即可”的目标。

### 4.2 Application 和 Composition 仍拥有协议分派/运行态

[Start.hpp:352](/I:/code/Prism/Preview/Application/Startup/Start.hpp:352) 创建四个 UDP service，随后在 `Services->UdpService` 中按 detected 类型 switch。第 399-407 行直接调用 `Composition::VlessXudp::Run` / `AnytlsService::Run`，其后的 generic mux handler 也由 Application 拼装。

typed Datagram runner 是前进的一步，但它仍复用中心服务。它消除了部分运行时 carrier 重新识别，不等于协议 association、socket/timeout owner 和关闭责任已经全部归位。

### 4.3 长函数和宽参数门禁未完成

[Start.hpp:63](/I:/code/Prism/Preview/Application/Startup/Start.hpp:63) 的 `Application::Start` 延伸到第 578 行，约 516 行，远超过函数体 120 行要求。文件本身 580 行，过了文件长度门禁，函数和职责门禁仍失败。

[MuxStartup.hpp:114](/I:/code/Prism/Preview/Application/MuxStartup.hpp:114) 的 `MakeMuxStreamHandler` 有四个参数，`LogMuxRequest` 在第 81-83 行有五个；返回的业务 lambda 在第 118-176 行也明显超过 10 行。不能把“所有文件 <=600 行”当作参数宽度、长函数和 lambda 全部收敛的证明。

### 4.4 三条明确的反向协议依赖仍在

当前源码直接 include `Preview/Composition/Carrier/FacadeCarrier.hpp`：

- [Reality/Carrier.hpp:9](/I:/code/Prism/Preview/Protocols/Reality/Carrier.hpp:9)
- [Restls/Carrier.hpp:9](/I:/code/Prism/Preview/Protocols/Restls/Carrier.hpp:9)
- [Shadowtls/Carrier.hpp:10](/I:/code/Prism/Preview/Protocols/Shadowtls/Carrier.hpp:10)

此外，`Runtime/Front/UdpFront.hpp:25-26` 和 `QuicFront.hpp:23-24` 仍 include Composition。这是真实 include 方向问题；即使 CMake link graph 和 source registration 通过，模块边界也尚未闭合。

## 5. 当前源码仍有的生命周期/所有权问题

以下均为源码证据，本轮未进行新的运行复现。

| 发现 | 证据与触发 | 影响与结论 |
| --- | --- | --- |
| 启动 profile 失败漏回滚 | [Start.hpp:430](/I:/code/Prism/Preview/Application/Startup/Start.hpp:430)：`MakeTcpProfile` 返回错误时只设置 LastError 后 return，未执行相邻失败分支的 `RunStartupRollback` / `State_.reset()`。 | 当此 fallible 分支失败，已建立的 runtime、Diagnose/flush、DNS、TLS/provider 等不会在 Start 返回前按事务回滚。不能把未来析构当作启动失败即时清理。 |
| SessionServices 自持有循环 | [Start.hpp:383](/I:/code/Prism/Preview/Application/Startup/Start.hpp:383)：成员 `Mux` 的 lambda 捕获 `Services = Runtime->Services`。`SessionServices::Mux` 是拥有闭包的函数对象；[Shutdown.hpp:206](/I:/code/Prism/Preview/Application/Shutdown.hpp:206) 只 reset 外部 Services 指针，没有拆掉该循环。 | `SessionServices -> Mux closure -> shared_ptr<SessionServices>` 仍成立。服务及其引用的 Auth/accounts、TLS、resolver/MuxService 等不能仅靠外部 reset 释放。已确认静态持有环，未测泄漏量。 |
| QUIC 拒绝后的回落包已被移动 | [BoundaryDispatcher.hpp:106](/I:/code/Prism/Preview/Boundary/Contract/BoundaryDispatcher.hpp:106) 把 Packet move 给按值接收的 [QuicPacketGateway::Handle:164](/I:/code/Prism/Preview/Boundary/Quic/QuicPacketGateway.hpp:164)；返回 false 后，第 126 行再把同一个 Packet move 给 datagram fallback。 | unknown CID、draining/closed、预算或 handler 拒绝路径不能保证 payload/CID 完整交给 fallback。既有本地问题 P-14 已记录；本轮重新确认仍在，没有声称已复现线上丢包。 |

前两处在 HEAD 快照的旧 `Application.cpp` 中也存在：自捕获约第 4288 行，profile 失败分支约第 4340 行。因此它们是本次重构保留下来的存量缺陷，不能未经 diff 归因就称为此次新引入。已有全量回归通过也没有证明这些失败/析构条件被覆盖。

本地问题 P-15 的 generic Mux child 账户/StreamLease 交接仍应单独验收。当前 `MakeMuxStreamHandler` 构造 child Context/Session，但调用签名没有父账户租约，不能拿测试手工申请 StreamLease 的断言代替真实生产 child admission。该项保留为静态风险，未宣称实际配额绕过。

## 6. 未完成工作的具体范围

1. **完整 provider factory**：Hysteria2、TUIC、SS2022、SOCKS5 的 descriptor 需要产出实际协议 binding/factory 和可关闭的 active owner。Application 应消费这些产物，停止解释协议内部配置并创建具体 factory。
2. **三类 UDP owner**：分别收敛 raw UDP、QUIC DATAGRAM、control/stream association；中心 `Composition/UdpService` fallback 的消费者迁完后退役。保留各协议自己的 wire，不强行做万能协议对象。
3. **AnyTLS / VLESS XUDP / generic Mux**：帧循环、association/root-child 状态、配额、writer 和最终关闭移回协议 owner；Composition 留 prepare/bind，Application 留启动事务。
4. **typed 结果唯一化**：继续迁掉 Handler/TypedAcceptResult/Context 的兼容字段、反向同步和回退；必须证明租约、目标、transport 和 PostDial 各有唯一正式交接点。
5. **carrier 中立合同与 CMake/include 门禁**：迁走 `FacadeCarrier` 的反向依赖，同时验证真实 source include 方向，不能只改 target 名称。
6. **旧消费者退役**：原矩阵明确未完成的八个目录是 `Composition/Api`、`Composition/Carrier`、`Foundation/Utility/Account`、`Foundation/Utility/Coroutine`、`Net/Outbound`、`Net/Route`、`Runtime/Front`、`Scheduler`。另有旧 Settings、Account Check bridge、ProbeDefense、双统计轨等部分完成项。先核对消费者，决定接入、移出生产或删除；不凭目录名宣称生产能力。
7. **真实请求/生命周期最终验收**：先补第 5 节条件，再恢复 TUIC 多模式连续稳定性，按最终 exe/config/source hash 跑协议和 carrier 矩阵，并取得 Linux 构建证据。当前未找到最终快照对应的 Linux 编译记录。
8. **性能实验最终放行**：已有 SessionRegistry/DNS 实验可以保留，补真实 Listener/Operations Cancel/Drain、resolver traffic 和策略等价性；CID/SNI/mux/account/I/O 等后续候选仍需完整同输入对照。没有收益或证据不足时允许保留现状。

“允许 JSON/API/wire 显式破坏”不等于必须额外升级所有格式；只有实际产生破坏性变化时才需要版本、升级说明和客户端矩阵。DLL ABI 也不在本次必交范围内。

## 7. 历史验证的可信范围

原始 JSONL 工具结果直接确认：

| 上海时间 | 结果 | 能证明什么 |
| --- | --- | --- |
| 2026-10-01 09:44 | 4715 tests passed；833.52 秒 | 当时快照的仓库全量回归，不是 Preview 单独有 4715 条用例。 |
| 2026-10-01 14:21 | 4716 tests passed；1880.04 秒 | provider/G7 后、typed UDP 前的全量回归；25 项 Disabled 未运行。 |
| 2026-10-01 14:59 | 64 tests passed；3.58 秒 | provider/Application/typed UDP 的选定回归。 |
| 2026-10-01 15:06 | 460 tests passed；31.24 秒 | typed UDP 后协议/adapter/session 的选定回归；另有 16 项 Disabled。 |

这些 PASS 并非只有会话口头总结，但也不能替代当前源码的全部验收。`LastTestsFailed.log` 还留有 14:57 的单项失败记录；其后原始工具输出与 LastTest.log 对应完整 460 项通过，不能把旧失败文件误当作当前 460 项未通过。

真实互操作证据：

- 最新保留的 [Hysteria2 evidence](/I:/code/Prism/build/interop-results/hysteria2-application/hysteria2-app-8be1f7cea0e442d08bf181bc10986c66/evidence.txt) 对应 exe SHA-256 `6274FE1F11256D422683BB0906EDDA378D117CC2F6D5F06A9BC18682DF742842`，有 HTTP 401、TCP 23 bytes、UDP 27 bytes、drain completed。该文本末尾 `APP_EXIT=` 为空，因此文件单独不能证明 exit code 0；它有 PID，清理结论还应与工具记录对应。
- 最新 [TUIC evidence](/I:/code/Prism/build/interop-results/tuic-application/tuic-app-3ad2ce1b89814716b350ec77e1665515/evidence.txt) 对应 exe `849771BFC8D2CC4EAB047B1A4017798F123188763282856712835BFEE92AE8B8`。TCP 与 bad-auth 通过，`concurrent-bidi` 因 QUIC handshake timeout exit 1，finally 请求 drain。当前应标记整条连续 sequence 未通过；更早的成功不覆盖这个后续结果。
- 当前磁盘 `build/src/PrismPreview.exe` SHA-256 是 `1F5C18E2E9A4A12F07B044DFA72492C3FD8002378EB60F395433C69EBDB8B018`，与以上两份证据均不一致。不能说这两份证据验证了当前可执行文件。
- 当前默认源配置与 build/src 副本的 SHA-256 均为 `C245C56845ACC08F415F14CB372F1FABE54F541241E914880A0BE536D80E3501`；与 runner 使用的临时配置是不同输入。
- `build/Testing/20260916-1430/Test.xml` 的最近内容是空 TestList，并不是 4716 项的耐久 JUnit 证明。本次全量结论依据原始工具输出，未把空 XML 当成成功证据。

性能并非完全未执行：SessionRegistry 有 18 场景 × 五轮 × A/B/C 的 270 样本记录，DNS mixed 有 45 样本及分位数。Harness 同时明确写出 `replacement_gate=reject_until_those_contracts_are_verified`。拒收是对生产语义缺口的正确处理；不足在于真实路径等价性与后续比较工作没有闭合，不能以 Perf label PASS 宣称生产性能已优化。

## 8. 会话执行与报告质量

- **完成口径反复变动。** 10 月 1 日 12:59 回复“改完了这轮实施范围”；13:06 又承认原计划没有 100% 完成。后面的“还未完成”口径较准确，但不能倒推前面已经完成了整张任务。
- **当轮增量与累计成果混写。** 10 月 1 日 16:05 的任务只执行一次 CodeGraph 查询，没有代码改动，却在最终回复写“刚刚又继续完成了一张实际代码卡”。10 月 2 日 11:43 的状态轮只有台账尾部、进程、Git 和磁盘盘点四类读取，也再次把累计 typed UDP/G7 成果写成刚完成的新代码。这个问题可由各轮工具清单直接确认。
- **持续执行要求没有兑现。** 用户多次明确要求未完成继续，工具记录仍反复进入 final reply；QUIC factory 接管卡在最后几轮没有实际落地，不是被完成标准正式关闭。
- **调度约定没有严格保持。** 原始全模块计划规定 root 只调度和审查，不改生产/测试；中期明确说“直接接管”，并有 root `tools.apply_patch` 修改生产/测试的记录。不能把它误报成所有实现均由子代理独立交付。
- **台账保留历史但状态入口容易误读。** 同一文件存在重复第 19 节标题、早先的空 owner/604 header/完整 QUIC 通过标签和后来修正后的 owner/605 header/TUIC FLAKY。保留历史有价值，但需要一个只描述最后快照的权威状态入口。
- **测试真实性比完成宣称更好。** 多项红灯、修复、当前构建、真实 payload、版本 hash 有原始证据；缺陷集中在证据层级和时间版本的混用，而不是可以一概判成没有执行。

## 9. 继续实施前的优先级

优先关闭启动失败回滚、自持有循环和 Boundary 拒绝后 packet 回落；随后以一个协议的完整 factory/active handle 为样板，让 provider 真正接管装配，再迁其他协议与 UDP/AnyTLS/XUDP/Mux owner。旧消费者和反向依赖迁完后删除，最后在唯一最终快照上做全量、互操作、Linux 和性能替换门禁。

后续任务卡应写清当前 blocker、可编辑路径、唯一 owner、可触发旧行为的断言、真实请求/关闭证据和剩余消费者。状态汇报只把本轮实际增量称为“本轮完成”，累计成果与未关闭合同各有来源。

本次只新增本复核报告，并按 AGENTS.md 补入本地问题索引 P-16/P-17；没有修改生产或测试代码，没有构建、启动服务、提交或推送。

