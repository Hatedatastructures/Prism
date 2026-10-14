# Preview 剩余质量整改接管计划 v5：六路生产收口后停止

日期：2026-10-14，Asia/Shanghai。计划依据三个已读取的会话、当前工作树源码和原始构建/测试证据；历史状态仅作为线索。

> 20:07 当前阶段结论：六路本轮生产改动已冻结，C6Production100Build 的 PrismPreview 编译链接与 PrismWeb 依赖构建通过，源码无漂移。按用户要求现已停止，等待用户测试。确切运行路径、命令、分层证据及后续边界见 [生产交付记录](/C:/Users/C1373/.codex/worktrees/preview-quality/Prism/docs/preview-refactor/2026-10-14-preview-production-delivery.md)。

> 当前覆盖规则：用户已要求直接修改正式文件，禁止新建 Original/Candidate/源码备份。下文第一轮镜像卡及旧进度保留作历史，不能继续按镜像写入。真实代码位于 C 工作树的 Preview、tests、Web；.superpowers/sdd 只保存必要的记录、hash和证据。

> 2026-10-14 19时用户最新要求：测试先不管；复用六路子代理完成生产代码后先停。现阶段只做生产源码、实际调用者与CMake集成，并统一构建PrismPreview/PrismWeb交付。测试迁移/运行、真实请求/浏览器、互操作/性能/Linux及I主目录迁入均后置；不拿它们作为延长本次生产阶段的理由，也不宣称通过。之前完整M00–M42目标和历史验收要求保留为后续工作。

### 当前执行与最终迁入

- C:/Users/C1373/.codex/worktrees/preview-quality/Prism 是唯一写域，目前 detached HEAD；Web 在此工作树，I:/code/Prism/Web 尚不存在。I 主目录仍只读，同属 Git HEAD 3c5b678f2e06227b2a5da5b1ac406b5f79ea9828，分支为 codex/preview-refactor-20260928。
- 六路当前按 Mux/AnyTLS、QUIC/TUIC/Hysteria2、TCP/UDP 协议、TLS/HTTP carrier、Runtime/管理/配置、Web 分域修改正式生产文件；共享契约、Lifecycle、传输、CMake、脚本、文档和统一构建由 Root 负责。本阶段不修改或运行测试，全部生产 owner 冻结后才构建。
- 迁入前只读对比原始 hash、当前 C 和当前 I。18:10 的 2087 路径登记中，210 路径须三方核对、8 路径保留 I 单边变化、107 退休候选须另审；这些是合并分类，不是完成率。最终迁入正式源码及必要配置，不迁 .superpowers/sdd、build、node_modules。
- 当前任务并未获得向 I 写入的授权；先准备已验收的具体迁入清单及冲突裁定，最后确认这一边界。无提交授权，不执行 commit/push，也不以整目录覆盖实现迁入。迁入后需在 I 的唯一 build 重新构建及验收。
- 18:28 的整体 50%–60% 是按实现和验收缺口作的工程估计，不是 43 卡签收率。当前回归约 1–3 小时、全部层暂估 1–3 天持续工作；新发现的协议问题或主目录冲突会影响估计。源码完成、局部测试比例不能作为总进度。

## 1. 目标、要求继承与执行边界

继续完成 M00–M42 和原 R001–R038、F001–F030、P001–P033 共 101 项审查记录的剩余闭环，包含 React 管理后台。已经有正式实现或通过记录的内容先复核当前证据，不恢复旧实现、不重复改造。源码整改、构建、测试、真实请求、互操作、性能、Linux 和浏览器验收分别签收。

- 唯一执行树：`C:/Users/C1373/.codex/worktrees/preview-quality/Prism`。`I:/code/Prism` 始终只读，保留两树 staged、unstaged、untracked 和 deleted WIP；不覆盖复制，不执行 reset、checkout、clean、commit、push 或 amend。
- 用户已在《审查 Preview 模块质量》中明确授权隔离树 configure、PrismPreview 构建及相关测试，并确认 Qoder 已停止。该授权继续有效，不再重复请求首次构建同意。旧计划的“无构建授权”“没有 build”已被后续授权和磁盘证据取代。
- 最新上限为六个活跃子代理，加主会话共七个；取代历史二、四、五、八个上限。子代理使用 `gpt-6-luna / max`，不用 Astra，不自行换模型。槽位或模型暂不可用时保留原卡排队，由主会话继续独立工作，按实际状态报告并发。
- 主会话负责调度、共享契约、跨模块集成、根 CMake、脚本、台账、构建、CTest discovery、真实进程和最终签收。子代理按领域闭包直接修改正式代码；每卡冻结后立即报告，未验收不记完成。
- 只使用执行树现有 `build/`，禁止 Python。每次构建前输出上海时间；08:00–22:00 为 `-j 16`，22:00–08:00 为 `-j 1`。不通过多个构建进程绕过线程上限；内存不足时减少单轮目标数，不改用户进程或系统设置。
- 测试延续 v2 的“不新增测试 target”约束。现有用例名称、输入、断言语义、fixture 生命周期、disabled 状态和 timeout 保留；必要的回归覆盖留在现有 target 并记录净增，不能删例、缩小输入或扩大错误候选凑通过。
- Preview 保持 C++23 和 header-only owner。生产头不超过 600 行，测试 CPP/共享 HPP 不超过 800 行；函数不超过 120 行、lambda 不超过 10 行。通常最多二参数、复杂边界最多三参数；PascalCase、中文 Doxygen、尾随返回类型、禁三目。项目请求热路径不使用 throw/catch；第三方 ABI/wire 和冷路径例外精确登记。
- Protocols 拥有协议 wire/auth/session，Boundary 拥有入口 socket/CID，Runtime 拥有调度及通用数据面，Composition 只做冷装配，Application 负责进程启停。共享纯契约下沉中立模块；生产 include 与 CMake 依赖同时验证。接口迁移一次改完调用者、测试和登记，删除旧 alias、overload、fallback、转发入口和双事实字段。
- 公共接口说明输入拥有/借用期限、输出与错误、取消、半关闭、最终关闭者及 executor。按真实 owner/state machine 拆分，不能用文本拼接、作用域 include 或万能参数包规避约束。

## 2. 接管时已经核实的当前状态

三个会话为《并行审查 Preview 模块质量》（01a13448-d4d9-7fb2-9b44-877ba1cdfb5f）、《审查 Preview 模块质量》（01a12e7d-debf-7823-b950-0a84d42f7259）和《旧任务》（01a12a85-b599-7691-887b-7dce11cdc6e5）。旧 v2 的主树只读和隔离树执行边界继续保留。

本轮以 `Review-20261012/TakeoverOrdinaryBuild20-Result.json` 对应的普通源码为起点。1499 个冻结输入文件逐项重哈希没有漂移；本轮 Snapshot 重新遍历相同范围也得到相同聚合值：

`758325c8ea36a4b0fe9eed352577b64302d888010432bdb5d381a8acf8e90d81`

| 工作项 | 当前可以确认 | 仍不能签收的内容 |
| --- | --- | --- |
| OrdinaryBuild20 | ProviderCatalogTest、HttpForwardOperationsTest、PostDialReplyFailureTest 三目标成功；实际 EXE 哈希匹配记录 | 不代表所有目标或全量测试完成 |
| 本轮 Resume21 | HTTP 入站六例、WorkerDrain 一例、PostDial 七例，共 14/14，通过；0 skipped、源码无漂移 | 不代表当前 Main 或全部管理能力 |
| 本轮 Resume21Provider | ProviderCatalogContract 九例，8 通过、1 超时；源码无漂移 | DrainContinuesAfterTypedOwnerFailure 仍按原 60 秒超时 |
| Binding | 最近 Focused19 中 Throwing/Dropping 阶段已有通过记录 | RetainedHandle 仍未签收；Build20 未重建 Binding；真实 pending Read gate R3 仍是候选 |
| Mux、TUIC、Trojan、VMess | 较新记录已有 Mux Deep2/Service、TUIC UDP、Trojan E2E 和 VMess 消费者闭包的分项通过/合入证据 | 不能反复把 Focused50 的旧失败当现状；后续契约变化需要重建受影响目标 |
| M07 Statistics | Task、Listener、QUIC、Mux、AnyTLS 已消费 RetireTraffic；Operations 已读取真实分层 Traffic 值 | 需验收已装配退休链；独立 Metrics/历史采样查询仍待闭合 |
| 管理后台 | 真实管理 listener 已接通；当前 scoped worker 行为已有 focused 通过 | 实际源码仍缺 token/Bootstrap/API version；Reload 与 Stream Reset 仍 Unavailable；没有 Web 工程 |
| 当前 Main 和最终验收 | 旧源 Main01/其它 Main 记录有特定 SOCKS5 负载、FIN 尾包和自然停机通过证据 | 当前冻结源 Main、全量 CTest、ODR、多 TU、互操作、性能、Linux、React 浏览器尚未完整签收 |

当前本轮复验仅为 23 项：22 通过、1 超时。不能把此比例当成整个项目完成比例。测试进程已经退出，未修改生产源码。新证据为 `TakeoverResume21` 和 `TakeoverResume21Provider` 的 Command/Result/Discovery/Source/log/XML。

`progress.md`、`RootNextSteps.md`、`Stage-Status-Matrix.md`、`Acceptance-Matrix.md` 的旧正文存在已被后续事实取代的条目。首先保留历史记录，再追加当前“卡 × 验收层”表；不把旧 Pending 全当没开始，也不把 SourceComplete 自动升级为运行通过。

## 3. 第一轮六路实施卡

六路同一时间各有一张活动卡；写域按模块、行为和生命周期闭包划分，不按固定文件数。子代理只修改自己独占的 Original/Candidate 镜像及交付材料，actual 由主会话串行集成；因此候选准备可以与已有冻结源的构建/测试并行。

| 路 | 第一张卡与独占领域 | 明确交付和签收面 |
| --- | --- | --- |
| A | Provider/Binding 退休回执；对应两份 Provider/Binding 测试及经证据确认的最小退休修复 | Provider 重试段等待真实 control/activity/wrapper completion；Binding 使用真实 pending ReadSome gate，分阶段保留、释放、Drain。完整 owner 退栈后 Storage 回基线、weak owner 释放；不能只等 raw carrier 析构或靠 Io.run 自然退出。先闭合现有契约，不凭超时新开 Transport API 重构。 |
| B | Native QUIC、Boundary QUIC、Hysteria2/TUIC 的 FIN/close/预算调用闭包 | 审核累计 C4/C5 和共享 AdmissionBudget 候选，单一 4096 预算覆盖 Gateway/Registry 两入口，在 factory 前预约、真实 drain 后归还；typed FIN/close 与 ACK/RESET/peer EOF 分清，失败保留同一 owner/lease 并可重试。HTTP3/Common/Application 跨域消费者由主会话安排所属路跟随。 |
| C | Mux 和 AnyTLS root/child/writer；不写 HTTP2 底层及 H2Mux server 子域 | Mux Run 统一为 awaitable<expected<void, Fault::Failure>>，传递 Children/Loops/lease 首个失败及 native cause，删除 code-only正式入口；AnyTLS outbound 和 move-only StreamLease 交同一退休 owner。H2Mux RootSession 调用二参 Http2Server(Inbound, MaxStreams)，E 路实现 server 上限，无旧一参 overload/default fallback。 |
| D | SOCKS5、Trojan、VLESS/XUDP、SS2022 的数据报和协议消费者 | 首卡审核 AssocReplyAdmissionR2，BindAndReply 单次共享结果、waiter 取消隔离、真实退休，并跟随 VLESS/XUDP RootSession 的 typed Mux Run override；首卡不扩大 VLESS wire 改造。续卡补 packet/peer/lease/预算/来源校验；普通 VLESS UDP 只用固定目标 uint16BE length+payload，移除 addressed/StandardWire 双轨。Shared Task9 与 Common 不自行覆盖。 |
| E | ShadowTLS、Restls、WS、HTTP1/2/3、TrustTunnel、XHTTP、Gun；另独占 Mux/H2Mux 的 Http2Server/State/Dispatch 子域；不写 AnyTLS/Mux Root 或管理测试 | 首卡从当前原件重建 PeerClosureR3 的非 AnyTLS 增量和 H2Mux server gate；工厂失败真实 retirement、输入/输出预算、HTTP2 credit、TrustTunnel driver 退出及全部 pending completion。三种 H2 owner 分开。先补报告和消费者，再接受未报告的 H2 候选，其余协议在续卡完成。 |
| F | Application/Runtime/Operations 的管理、配置及冷装配；不写 B 路 QUIC Startup 增量 | BootstrapAuth 按当前 HttpFixture20 基线集成；补 API version/incarnation/token、Host/Origin 和命令鉴权。随后真实 Stream Reset、Reload、Metrics、查询权限与 Startup/rollback 闭环；共享 RouteDispatch 分批串行集成，不能把 Unavailable 改成固定成功。 |

主会话独占 Contract、Lifecycle、共享 Protocols/Common、根 CMake、跨路公共 fixture、实际源码写入和所有验收操作。B 路对 Startup、C 路对 Mux 契约、E/F 对同一 HTTP/管理测试的变化只交跨域增量；所属写者完成跟随，主会话合并，不让两路各复制一份旧文件。

卡 A 的明确初始事实：ProviderDriverCleanupRevision1 已落在 actual，不重复套用。它只补第一次 cleanup；第二次 retry 仍有无界 Io.run。旧 trace 已看到 carrier 析构和 Storage=0，但尚不能证明完整 wrapper/control 退栈。新 driver 只能在具名协程等待真实终态后由完成回调结束自身 executor；未知预约、首因和失败 owner 保留。Binding 的 R3 没有构建/通过证据，先核对 Original/Candidate/current，再合入和重建。

每卡必须交付：变更清单、问题编号、基线/候选哈希、可读 diff、owner/caller 关系、接口退役清单、Style.json、Hashes.json、Report.md、现有测试身份/输入/断言/timeout 对账及未执行层。原件来自 I 树、actual 已漂移、只有文件没有报告、少 CMake 登记或缺消费者的候选，均不能直接签收。

## 4. 后续工作与冻结的公共接口

第一轮不是全部范围。主会话按依赖将腾出的槽位续派以下工作，不重复重建已通过的底座：

1. **M00–M13 父卡尾项**：复核中立 Target/Failure/Crypto；验收已有 executor/context、TaskRegistry、Statistics 退休安装点；完成 Diagnose 参数与后台生命周期、脱敏/截止时间；账户 revoke/重加/policy generation；DNS 完整关联、TTL0、Cache/Coalescer/flight/pool/deadline；补中立 chunked 正文解码并让 DoH/HTTP1 消费同一事实。缺失 Metrics 明确 unavailable，不填零冒充。
2. **M14–M28 协议闭环**：单一 UDP association owner，双族独立 pump、来源校验、空包/多回复/迟到包；QUIC 数据保活至 ACK 或实际关闭、FIN 可重试及 RESET/credit；HTTP2/3 头/帧/解码/队列累计预算；TrustTunnel/WS/SS2022/XHTTP/Gun/AnyTLS；Mux RX 可回收、writer 有界、DATA+FIN/wire唯一及 sibling/two-drain；Reality/ECH/HTTP1/TLS 真实失败和半关闭。不保留两个正式 wire 或关闭者。
3. **M29–M36 装配和管理闭环**：所有正式 provider/carrier/mux/ECH 冷注册 Prepare/Freeze/Bind，删除 Application 重复协议 dispatch；Runtime immutable generation 与控制权限分离；startup 唯一逆序 rollback 和真实 typed shutdown；scoped Operations、真实 Metrics、两阶段 Reload；Detail/命名/注释/无兼容层及 CMake/测试路径收尾。
4. **M37–M42 React**：后端 M32–M36 的正式 API、鉴权及对应源码/构建/focused 前置通过后开始实现与发布；其它独立模块验收可并行。不能把旧 no-build/E-30 当阻塞，也不能把 listener 接通当 API 已完成。

公开契约固定如下：

- Transmission 保持 ReadSome/WriteSome/ReadExact/WriteExact/WriteShutdown，Close/Cancel 返回 ControlResult；派生使用 StartRead/StartWrite/StartWriteShutdown/OnClose/OnCancel。completion exactly-once、异步不重入，保留 executor/allocator/cancellation/native category/value；不恢复旧 async_* 或 error_code& 前门。
- StreamEgress/Dial 返回 expected<SharedTransmission, Failure>；Mux Run 返回 expected<void, Failure> 的 awaitable。QUIC FIN/close 使用明确 typed 回执，不以 full Close 默认代替 write-half-close，不把 Submitted 当 Acknowledged。
- Operations 采用原正式 API 表中的单一 /Operations 路径：Bootstrap/Health/Generation/Workers/Accounts/Sessions/Events/Metrics/Configuration/Status 及父 session 下 Streams/Tasks。Process Drain 和 Worker Drain 使用不同明确端点；Stream Reset、Task Cancel 校验父身份/代次，不能升级为 session/process cancel。迁移并删除 worker=0 猜 process、重复状态路由和裸 StreamId 控制入口。
- GET /Operations/Bootstrap 返回 API version、process/incarnation、真实能力和每次启动随机命令 token，no-store；POST 采用 Authorization: Bearer，Host 精确 authority、Origin 同源、loopback。token 不进 URL、日志、错误正文或持久化页面缓存。拒绝发生在 OperationId 分配前。
- Reload 采用 ValidateOnly/Apply 和 BaseGeneration。配置输入有界并经过同一 Configuration compiler；prepare token、typed worker acknowledgement、单点 commit、失败逆序 rollback；旧 session 固定旧 generation。worker/监听器/池容量/QUIC engine 改变返回 RestartRequired，活动和退休 generation 总量不超过 8。只实现一套正式输入形状，旧 current/target generation 猜状态入口随调用者迁移删除；具体 JSON 字段遵循现有 M33/前端正式规格，不另造兼容端点。
- OperationId 有界，Accepted 与 Completed 分开；只有真实 owner 回报才能进入 completed/failed/timeout/blocked。64-bit ID/计数用十进制字符串，时间 Unix ms，所有速率/字节单位明确；消息文本不承担状态判断。

React 使用已经选定的 React/TypeScript/Vite、React Router、TanStack Query、Tailwind、shadcn/ui 和 Lucide 方案。旧文档版本数字不直接沿用；实施时从官方发布和 package metadata 核实稳定版本，精确锁直接依赖和 lockfile，记录 Node、构建命令与产物 hash。

Web 只建在隔离树：App/Api/Features/Components/Ui/Styles。页面包括概览、Worker、账户、Session/Stream/Task、事件、配置和操作中心；真实 decoder/typed error/AbortSignal，命令不自动重试，只轮询同一 OperationId；不可见页面暂停常规轮询。浅色工作区、深色导航、蓝色强调和深色主题，桌面/平板/窄屏、键盘/ARIA/减少动画、loading/empty/error/断线状态完整。无模拟业务数据、远程多用户登录或额外公网服务器。

PrismWeb 产物进入现有 build 树，关联 PrismPreview 的 Web 资源目录；启动时只读 manifest/catalog，含 path/content-type/hash/size，禁止 arbitrary filesystem path；API 错误不回退 SPA，index/Bootstrap 不缓存，hash assets 不可变缓存，生产同源。安装和打包在后端前置满足后执行，不提前把资源规则当真实发布。

## 5. 串行集成、验收及清理

每次集成遵循同一流程：候选 Original/current 哈希预检 → 审核真实 diff 与 revision 链 → 测试身份/行为对账 → 主会话更新共享调用者和 CMake → 源码冻结 → configure（仅登记/依赖变化需要）→ 实际成功 target 重建 → 精确 discovery 与 focused → 签收/退回。actual 在构建/测试期间禁止变化，代理只准备下一轮镜像。源漂移、target 未生成、旧 EXE 残留或诊断版一律不签收。

- 首批以 A 的两项退休问题和已冻结候选闭包为目标；当前 HTTP/PostDial 已通过，只在相关 production/shared header 改变后重验，不重新修旧输入问题。
- 受影响测试从当前 CTest 登记按实际 command→EXE 映射选择；选中数、报告数、disabled/skipped、失败/timeout 分别报告。正则非空不够，还要证明覆盖每个预期 target，避免 ProviderCatalog/ProviderCatalogContract 的前缀漏选。
- 配置/源码/工具链/CMake 输入与 binary hash、上海时间、完整命令、退出码、raw log/XML 成套保存。头文件、ABI 或配置变化后受影响 binary 重新构建；恢复源码后刷新 mtime 并核 binary，防止诊断 EXE 留在普通入口。
- SourceReview/SourceComplete 只代表源码状态。另设每卡的源码、静态、configure、编译/链接/ODR、多 TU、focused、全量 CTest、Main、互操作、性能、Linux、浏览器和清理栏；未执行或不适用写明理由。只在全部所需层签收后报告总体完成。
- Main 从 PreviewMain→Startup/Start→Runtime/Session/Boundary 跑真实 listener、正负认证、重复连接、分片负载、双向流/数据报、FIN 尾包、scoped worker/process drain、操作终态和自然 exit。沿原 31/4099/65536/131077 payload 验证，不缩输入或以 force kill 当优雅停机；新 token 同步真实脚本。
- 后端源码稳定后统一构建所有应验目标并跑全量 CTest，保存完整 discovery、disabled/duplicate/失败/timeout/XML。多 TU/ODR 和 Linux 的大小写敏感 configure/build/focused 单独执行；先完成 Windows 两步大小写迁移和 target 去重。Linux 条件缺失则记未执行，保持验收未完成，不未经授权改变 host 环境。
- 互操作沿现有 Go/外部客户端矩阵验证 QUIC/H2/H3、各代理和 UDP 双族。性能复用真实 Mux/协议矩阵，同输入比较分配、吞吐、延迟、连接数、payload 与资源峰值；缺当前可运行 before 基线时明确报告，不能用旧哈希数值推断改善。
- React 验收使用真实浏览器和 API，检查路由/取消、操作去重及终态、空错断线、响应式、键盘和同源 manifest。单个 HTTP200、静态截图或 build 通过不能代替浏览器交互。
- 只清理本轮启动的 PID/socket/server/client 和已完成使命的临时配置/诊断产物；证据库保留。有效 build/tests 和依赖缓存不删除，不终止用户进程。退役产物先核 target/source/full path/process，保存证据，再逐项清理。

最终成果先在隔离树签收。之后重冻双方差异，按新增、双方修改、未跟踪冲突、大小写/测试 staged 迁移和明确退役逐项建立语义集成表。主树写入必须基于具体可审查的合并裁定得到用户授权；不把本次接管当成整树回灌或提交授权。

## 6. 排期与进度报告

按六路持续执行估算：主要源码整改和 React 实现约 2–4 天；包含完整验收整体约 3–6 天。此为工程排期区间，不是已验证的交付日期，也不是自动后台持续运行承诺。每轮依据新闭合项和实际构建/测试时间修正，重大新故障具体说明影响。

进度只报当前完成的卡/行为、actual 与 Candidate 区别、成功 target、原始测试数、剩余失败及下一张已派卡。不用旧 14/43、25%–30%、候选文件数或局部 22/23 推断全项目百分比。每次更新有新 diff、集成或验收结果；不能循环重复旧哈希/Remaining 清单。

当前下一步已经明确：A 补 Provider retry 和 Binding 真回执；B/C/D/E/F 分别实际闭合六路首卡候选。主会话边审核边集成已有准备充分的包，按夜间单线程构建，保持其它五路继续准备。第一轮签收后释放槽位续派父卡尾项和后端管理能力，后端正式 API 前置通过后进入 React。
