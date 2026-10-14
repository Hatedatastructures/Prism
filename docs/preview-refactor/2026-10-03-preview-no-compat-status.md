# Preview 无兼容层续作：当前执行状态

更新日期：2026-10-09。本文是当前执行状态入口；9月28日分析台账与10月3日会话质量复核保留各自历史快照。用户已授权继续实施、必要本地构建和测试，明确不保留旧接口与兼容层。最新模型要求已替代原限制：子代理统一使用 `gpt-5.6-luna/max`，Root 负责任务拆分、源码与证据复核。

## 10月9日22:46 当前 epoch 文档边界

本节是 D06 文档同步前按当前磁盘重新核对的入口，时间边界为 2026-10-09 22:46:10 +08:00。当前 `Preview/` 生产源码为 639 个 `.hpp`、0 个 `.cpp`；`Preview/Application/Main/PreviewMain.hpp` SHA256=`D6A84733F33ACE31DCE6865B4DE0BD6E08A4E93946572051B3FC8919A1D219C8`，`Preview/Application/Startup/Start.hpp` SHA256=`3D03F6661DA7CA90ECF3CC40E87F7D3F42676C83AB64A2EC09C239AAB6B46E90`。当前 `build/src/PrismPreview.exe` SHA256=`F5363B287941A4B6B7599FCD1EC041311885B8A4100A219FEF0487794523F3DC`（文件时间 22:36:01）；配置模板和构建副本均为 `C245C56845ACC08F415F14CB372F1FABE54F541241E914880A0BE536D80E3501`。该 EXE 目前只有当前磁盘文件事实；没有把上述当前 source/config hash 与它绑定的 build manifest/log，因此缺少当前 source→binary build provenance，不能单独作为当前 Main acceptance。此前 `88922FAC...` 已因当前磁盘二进制漂移降为历史候选。19:04 捕获的 `coordinator-9-current-source-v3.json` 使用旧入口 hash，已不能作为当前源码 manifest；只读核对没有改写原始证据。

当前 Provider18 证据为 [`coordinator-9-current-provider-application.log`](../../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-current-provider-application.log)：18 个 case、exit0；[`coordinator-9-new-abi-provider-cleanup.json`](../../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-new-abi-provider-cleanup.json) 记录 `Remaining=0`、19 个 owned 进程和 live directory remaining=false，但明确 `NaturalMainExitClaim=false`。这组 Provider18 记录没有当前 source/EXE/config 三元 hash binding；它只覆盖 Provider Application 的请求/认证/UDP 关闭与清理，不覆盖 I02 的 Main 自然 drain，也不能升级为当前 Main acceptance。

I02 runner 已实现，入口为 [`scripts/interop/Run-Matrix.ps1`](../../scripts/interop/Run-Matrix.ps1) 及 [`tests/Preview/integration/Matrix`](../../tests/Preview/integration/Matrix) 的 Mihomo/runner contract 文件；当前尚未取得当前 Main Hysteria2 三次、TUIC 20 轮×7 原模式和重复 Mihomo的真实 runtime acceptance。最新锁定 preview-only 矩阵记录为 `60 total / 53 pass / 6 blocked / 1 failed`、EXIT1，见 [`coordinator-9-current-interop-matrix-locked-rerun.log`](../../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-current-interop-matrix-locked-rerun.log) 与 [`build/interop-results/summary.json`](../../build/interop-results/summary.json)；该结果没有当前 Main source/EXE/config 三元 hash binding，不能写成 I02、Main acceptance 或全协议互操作通过。

P04 仍是后续责任：[`coordinator-9-current-DnsCacheCompare-preflight.log`](../../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-current-DnsCacheCompare-preflight.log) 和 DnsCache smoke 有 exit0 证据，但 `540` 行 ABC 同 trace 矩阵尚未运行。旧 [`coordinator-9-current-dnsperf-coalescer.log`](../../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-current-dnsperf-coalescer.log) 的 `EXIT=-1073741819` RED 与后续 [`coordinator-9-dns-coalescer-fix-verify.log`](../../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-dns-coalescer-fix-verify.log) 的 1/2/4 owners×5 rounds `valid=yes`/exit0 green 均保留，但两类记录都没有当前 source/EXE/config hash/epoch binding，不能把 preflight/smoke 或 coalescer green 当 P04 完成。G02 的 `640-row` standalone-header/ODR/CXX owners、CMake target-graph/exact-case 与五边 negative/restore 输入均是 `pre-current` prepared inputs，仍未运行。Linux 仍 blocked，边界见 [`coordinator-9-linux-inventory.json`](../../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/coordinator-9-linux-inventory.json)；没有 Linux build/CI 通过证据。

A01 阶段一只读口径采用 D06 按当时磁盘计数派生的 fixed639 normalized ledger，记录为 `A10/B0/C26/D1/N602/E50/F14`、`safe-delete=0`；它不是当前实时总数。原始 live640/固定 epoch 漂移材料见 [`A01-PHASE1-RETRY-live640-current.json`](../../.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/A01-PHASE1-RETRY-live640-current.json)，该 JSON 的 live640 字段与 fixed639 normalized ledger 不混读。阶段二仍未批准，本卡没有执行删除、迁移或生产接线。所有 focused、局部构建、preview-only interop 和 preflight 均继续按各自层级记录，不替代当前 Main runtime、全量 CTest、ODR、Linux 或最终文档验收。D08 只修正文档路径与 provenance 口径；下一 Root 文档复核卡为 **D5/D01 current-epoch review**：复核三文件的 delta、链接/锚点、CLI/config、入口/二进制 hash、source→binary binding 和未运行层级；在此之前不得写“全模块完成”。

## 10月9日14:09 历史接管增量

本回合由当前 Root 会话统一接管，未调用旧会话执行任务。四轮只读审计代理和四轮修复代理均由当前会话创建、按独占范围交付后关闭；没有提交、推送、reset、checkout、clean 或新建 build 目录。

当前 source/target 证据已从混合 epoch 中重新分离：12:17:06 捕获 current source manifest，417 个有效 target 全部尝试，初始失败 9 个；随后对 9 个 target 逐项修复/重编，当前修复 target 全部达到 compile/link exit 0。汇总证据为 `task-4-evidence/coordinator-9-current-epoch-final-summary.json`，初始 build 为 `coordinator-9-current-epoch-all-build.json`，修复 build 为 `coordinator-9-current-repair-build.json`。

当前修复后的直接行为证据：Carrier handshake error 19/19、HTTP response 20/20、Provider accept 7/7、Reality carrier 4/4、Restls carrier 3/3、SS2022 UDP 3/3、VLESS TCP 8/8、VLESS upstream-abort 1/1；`Ss2022DgramSession` CTest 6/6。VLESS 测试已按真实功能拆为 `VlessE2ETest.cpp` 552 行、`VlessUpstreamAbortE2ETest.cpp` 107 行及共享 `VlessTestSupport.hpp` 247 行，原 9 个测试身份保留。

当前结构门禁为 contract 640 headers/1189 consumers/0 production implementations、G7 666/666。`PrismPreview.exe` 当前 SHA256 为 `EFB86D372401DC81EF712D7EA33E5A3C4429E4282B3EC6B2666DE3EECB1744E0`，配置模板/副本仍为 `C245C56845ACC08F415F14CB372F1FABE54F541241E914880A0BE536D80E3501`。全量 CTest 已启动到注册项 `PreviewInteropMatrix`：前20项通过，矩阵生成446个原始证据文件后 runner 无继续进展，Root已终止本会话自有 CTest/runner；后续4894个 testcase未运行，不能称全量通过。

`InteropRecognition` 单独运行只启动 listener 后等待外部 client，最终 timeout；该结果归 I03 外部互操作阻碍，不改写为单元失败或通过。生产空壳阶段二仍无用户对具体阶段一批次的批准，未执行任何删除、迁移或生产接线。

TaskIdSet 当前二进制已完成 90-row 对照并自然 exit 0：64/1024/32768 ids、1/2/4 lanes、5 rounds、AB/BA，共90行，90/90 `valid=yes`、`errors=0`、9个 trace hash；同时记录可用样本的 working-set/commit，未把 unavailable peak 写成0。原始日志为 `task-4-evidence/coordinator-9-current-task-id-90-run.log`，汇总为 `coordinator-9-current-task-id-90-validation.json`。这是当前 primitive 成本证据，不是 Main 吞吐或生产结构采纳结论。

TransferPerf 当前 `--io-compare` 自然 exit 0，9个 summary（direct-handler、awaitable-bridge、connector-scatter × 1/2/4 lanes）均 valid，完整收发256MiB、双端 hash一致、errors=0；connector-scatter 的 partial count被原始日志保留，working-set/private-commit、p50/p95/p99和分配统计均已记录。SessionRegistry/DnsCache 当前 `--validate-only` 均 exit0，但其 replacement/ABC矩阵仍未执行，且 SessionRegistry 明确保留 `replacement_gate=reject_until_those_contracts_are_verified`。

SessionRegistry 当前完整矩阵随后自然 exit 0：18场景、A/B/C三模型、active 64/1024/10000、executors 1/2/4、read-heavy/churn、5轮交错，共270 rows，270/270 `invalid=false`；原始日志为 `coordinator-9-current-session-registry-270-run.log`，汇总为 `coordinator-9-current-session-registry-270-validation.json`。async SessionControl Cancel/Drain 与真实 Listener/Operations 仍未覆盖，因此生产 replacement gate 继续拒收。

全量 CTest 当前只完成到 `PreviewInteropMatrix` 入口：前20个 testcase通过，矩阵 runner生成446个原始文件后无进展，Root终止本会话自有 CTest/runner；后续测试未运行。CTest discovery当前4915注册、25 disabled，并存在 `ProbeDefenseCoverage_NOT_BUILT` 历史登记警告，不能把本轮写成全量通过。

## 10月9日08:09 当前源码与验证

原 Task1–9、D1–D5 仍未整体完成。当前已有一项通过原生栈定位并实际修复的构建 ABI 缺陷：MinGW 的 `<memory>` 可先引入 `_POSIX_THREADS`，生产启动编译单元与先包含 Asio 的测试编译单元因此分别生成 POSIX/Windows 线程类型。同一 EXE 在 `ContextOwner::Io` 析构时把 `posix_thread::func` 交给 `win_thread::join`，原六协议启动/停止用例在60秒预算下挂起。Root 在真实共享 Boost CMake 依赖的 `if(MINGW)` 条件中传递 `BOOST_ASIO_HAS_PTHREADS=1`，统一后端，未改依赖源码、测试输入、超时或跳过场景。当前生产库和测试的实际 flags 已核一致。

新编后的同一回归自然0.04秒通过，随后同一 EXE 100 次重复、600 次原六协议启动/停止全部自然exit0。证据为 `coordinator-9-asio-backend-regression-green` 与 `coordinator-9-asio-backend-100-repeat.json/log`，EXE SHA256 为 `61EEFBE9690E9C1C4E336F5EE21C671EBBB73E62C8984DB11F70500A6E0E4AC3`。仅为诊断启动的 PID38516 已核对身份并终止，其关联临时配置移入审计；诊断手动结束不当自然运行成功。

当前全量417个有效目标正在新ABI输入下重编，Root 是唯一构建者。清单包含原411个登记Preview目标、新TaskIdSetCompare和TrojanDgramSession、PrismPreview及三项旧AnyTLS helper归位验证，当前CMake目标表中没有不存在的名字。每个目标构建前记录上海时间与退出码，夜间开始的单回归使用 `-j1`，08:05:58开始的全量队列使用 `-j16`。生产、共享头、CMake与未来消费者输入冻结；只有已实编且消费闭包安全的独立CPP可另卡释放。证据为 `coordinator-9-asio-all-build-targets.json`、`coordinator-9-asio-all-build-source.json`、`coordinator-9-asio-all-build.json/.log`，未完成的队列不记全构建通过。

在此前编译epoch，Main35A已实际通过Provider18、Hysteria2三次尝试和TUIC20轮×7模式140次真实client调用，Operations drain自然退出、owned进程gone、runid目录归档captured。140是TUIC客户端调用数，不是Hysteria2/TUIC CTest数。新ABI会改变消费者二进制，必须重编Main后再记录新EXE/config/hash与真实请求；这些旧epoch证据不回写成新结果。

当前TaskIdSet比较源 `710A...` 的90行、45对、9组五轮成本比较此前自然1233.23秒完成，完整校验同trace/order、6N操作、3N成功CAS、局部完整历史及整体retire、errors0；32768规模1/2/4lane五轮中位耗时std-set分别66.6633/67.488074/110.139924秒，TaskIdSet分别0.104438/0.151248/0.158263秒。原始输入与EXE hash保存在 `coordinator-9-final-task-id-90-*`。累计请求分配量与RSS/commit峰值是不同口径，45行没有峰值样本不能当作0内存；primitive ID成本不宣称Main吞吐，新ABI下仍须核比较EXE是否变化。

fresh全tests/Preview源码530文件的严格AST检查为11个长函数、317个长lambda、11个普通宽参数、parse0、4个精确ALPN ABI例外，尚未整体验收。已实施的Protocol/Transport/Runtime/Integration owner提取必须分别实编、跑原身份/输入/断言并核实际资源关闭，不将AST0当运行通过。只读A–F审计与D1–D5具体材料保留固定639/77/45分母，新640源码另列live表；生产阶段二仍没有用户明确批准。Linux环境边界仍见当前 `coordinator-9-linux-inventory.json`，未安装环境或推送CI。

## 10月9日03:45 历史检查点与验证

当前原任务仍未整体完成。Root 正在统一重编 412 个当前 Preview 可执行目标，每个 target 保存开始/结束时间、线程数与退出码；尚未编完，不能将已通过的局部目标写成全量成功。此批冻结了生产与测试输入，包含本轮 HTTP/1、Gun、配置化 admission/cancel/commit、Account 认证/重载、Registry 模型和 TaskIdSet 比较的最新补丁。构建实际使用现有 `build/`，夜间 `-j1`。源码快照与逐项记录为 `coordinator-9-current-all-targets-source.json`、`coordinator-9-current-all-targets-build.json/.log`。

新增 TaskRegistry 边界回归已实际先红后绿：保留 ID 1 的 registry，在另一个 registry 的最大 ID 任务完成并退场后，自动 ID 原先错误返回空；仅将提前重复检查限定为显式 Requested ID 后，自动分配跳过 ID 1 并得到 ID 2，显式重复 ID 仍拒绝、耗尽时仍拒绝、完成计数仍为一次。当前生产 TaskRegistry SHA256 为 `F369035286685D92FFE4214B89F5C91DFA80D5D503CB4F71A47259FD90325BB1`，该回归实际 build/test 均 exit0。其余消费者需要此批新编译；旧 Main `431CE...` 的18个真实 SOCKS5/SS2022场景只属此前 Tree 版本，19个 owned PID 当时均已退出。

TaskIdSet 原完整五轮比较此前自然1223.92秒退出0，90行、45对、9组，所有行保留6N操作、3N成功CAS、局部历史保留至整体Retire、immutable/weak/final0与同trace/order校验。该结果绑定比较程序 `8C971...` 源与 `3FAC7B...` EXE。随后线程输入和验证职责按领域拆分以收口参数规则，最新比较源为 `2FDBE64F...`，必须重编并重新运行原90行；不得把旧结果签给新源。原45组Mux、105lane和32768 wrap结果同样保留其当时生产版本范围。

最新源码所有权门禁666/666、生产结构合同640HPP/1186消费者/611测试布局、生产AST结构均实际exit0；仍只证明静态范围。测试AST仍有655条长lambda、19条超参数与5个parser问题，整体验收未通过。HTTP正向Application共享夹具截断的MakeOriginHost声明已按实际唯一定义修复，两目标与ConfigurationValidationCompare实际重编exit0，focused和性能矩阵尚待统一运行。

当前Linux检查：WSL无已安装发行版、docker/podman未找到；现有内网SSH连接超时，另一个现有SSH主机拒绝当前非交互认证。没有修改SSH/known_hosts、安装环境或推送CI，Linux编译仍未运行。证据为 `coordinator-9-linux-inventory.json`。原Task1–9、D1–D5继续，审计阶段二仍待用户明确批准具体结论/批次。

## 10月9日01:23 历史检查点与验证

主会话及四个子代理的实际运行记录已逐个核对：Root为 `gpt-6.1-sol/max`，四子为显式工具参数创建的 `gpt-5.6-luna/max`。旧继承6.1的代理已停止写入；替代代理接续其已保存补丁。证据为 `coordinator-9-runtime-model-audit.json` 与 `coordinator-9-luna-runtime-model-audit.json`，不能把正文模型声称当运行设置。

当前生产源码640个HPP、0个CPP。源码结构与方向门禁实际exit0；生产AST结构检查640文件、41个精确foreign ABI例外，header/function/lambda/parameters超限与parse error均0，仍只证明这项静态范围。新 `TaskIdSet.hpp` 为不可变AVL快照owner，替换TaskRegistry全局与本registry历史ID集合的整树复制；原ID生成、冲突、复用及scope释放条件保持，修改前内容/hash保存到 `coordinator-9-task-id-before-source.json`。

旧ID集合下原45 Mux矩阵在50.64秒真实RED，首轮4lane出现1,129,599,628次普通分配、46,257,268,156累计请求字节。新集合实际编译后42个身份/生命周期用例GREEN；原45组矩阵26.88秒自然GREEN，105条lane逐条64MiB、固定hash、FIN/EOF、drain、quota0、weak及dials=1均核正确。原32768次stream-ID wrap/下一ID65537自然1.14秒GREEN，强化partial write、双端hash与FIN/EOF的SOCKS5两个原用例也自然GREEN。独立集合五轮AB/BA成本比较仍未执行，不能仅凭这批绿色签最终算法或全量。

此前当前版本的Recognition默认1000/7/10000自然1361.85秒exit0，完整raw核10行、failures全0；JUnit成功输出截断1024字节，原始LastTest全文已另存而非拿截断XML凑矩阵。该结果属ID集合修改前的生产闭包。Registry新sampling/BC并发失败hook/线程创建rollback预检在实编修正后validate-only真实0；270模型矩阵仍未验。App/配置/Mux故障共51 focused、Boundary/Control26、H2/Reality52均分别有其对应源码与EXE证据，不拼成同一全量epoch。

Main的FF264E36版本在ID修改前已重建，并实际18个SOCKS5/SS2022 listener场景PASS、cleanup Remaining为空；它现在属于旧生产闭包，Tree版本Main需要重新编译与真实请求。01:23上海时间-j1开始411个当前已注册Preview可执行target完整baseline build，编译输入冻结，独立只读审查与未登记性能源码继续；完整退出结果、唯一CTest、全量、全部当前Main/carrier互操作、ODR/Linux、最终D5及精准旧objects清理均未闭合。新字段集合基线测试不替代实际listener/关闭合同。

测试风格现场检查仍有25个长函数、734个长lambda、24个超参数及8个待分类parser节点，按当前未冻结功能闭包处理，不能沿旧数字或把parse0当编译。生产空壳审计严格定义修正表覆盖原639头，新640头epoch另标，原77目录分母和新增owner另列；A10/B0/C27/D1/E24/F14是专题标签且有交叉，F14另属实验分母，不等于缺陷总数。阶段二仍须用户明确批准审计结论及批次，尚未执行。原Task1–9与D1–D5整体没有完成。

## 10月8日23:30 移交后历史验证

新主会话已完整读取仓库规则与 `coordinator-8-handoff.md`，原地接管现有脏分支，保留原 Task4–8 和追加 Task9。运行时实际成功启动四个子代理，形成主会话加四子共五个代理；本轮遵照移交要求不传模型 override，全局配置实际为 `gpt-6.1-sol/max`。各独立队列继续推进，只有编译输入、共享接口、构建写入和性能采样互斥。

23:17 入口快照保存1254个源码/配置/CMake文件SHA256与1485个Git脏路径，未发现既存构建或测试进程。23:22上海时间 `-j1` 重建 `PrismPreview` 实际退出0，最新EXE SHA256为 `FF264E36E683838F88681A814A177B078030E5ABEC6500E517BFBD46C4424CEB`；当前生产输入相对入口无漂移。旧D535真实请求结果仍只证明其当时版本，本轮Main尚待实际请求复跑。

新编后的SOCKS5两个目标实际9+2用例自然退出0；新编SessionDelivery实际5/5自然退出0。CTest保留原 `SessionLifecycleTest` 用例前缀，JSON已核实际执行的是新 `SessionDeliveryLifecycleTest.exe`。Recognition原未编五文件及本轮正式声明/唯一allocation owner修复后，实际compile/link退出0，原默认1000/7/10000输入运行中；其当前运行尚未签收。SessionControl实编仍RED，其限定调用者补丁已保存待编；第一批整体构建最终退出2，不能写成整批成功。

本轮证据位于 `.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/` 的 `coordinator-9-entry-snapshot.json`、`coordinator-9-first-acceptance-manifest.json`、独立build日志与focused XML；持续台账为同计划目录的 `coordinator-9-progress.md`。全量当前build/CTest、Mux重项、当前全部Main互操作、五轮同输入性能、严格风格/ODR/Linux、旧objects精准清理与生产空壳阶段一审计仍未闭合，原整体任务没有完成。生产空壳阶段二仍未批准，阶段一仅提供只读结论和具体建议批次。

## 10月8日22:30 历史检查点与后续责任

当前测试模块按 `Preview/` 实际生产 owner 映射：配置归 `Application/Configuration`，编译装配归 `Composition`，取消与 drain 归 `Lifecycle`，socket/CID 入口归 `Boundary`，调度与 Session 归 `Runtime`，独立 codec/session 归各 `Protocols/<Name>`；只有真实跨模块请求按协议和场景进入 `Integration`，独立实验归 `tests/Experiments`，`Common` 只覆盖真实 Common 契约。测试正文仅在 `.cpp` 且不超过 800 行；共享 HPP 仅用于多个 CPP 的真实共享封装。项目自有标识符 PascalCase、中文 Doxygen、函数不超过 120 行、lambda 不超过 10 行、参数通常不超过 2 个（复杂边界最多 3 个），不保留旧 API 或兼容层。

当前 `Preview/Protocols/Mux/Stream.hpp` 唯一生产修复源 SHA256 为 `82718A908A656B9667DE3DBC51AF7EE8A19DBF4D81270F74D9FC422A1E4EF82A`：retired handle 的 `Tasks == nullptr` 是合法终态，`CloseOnExecutor` 对该状态同 executor 幂等关闭并不提交 task/wire；构造时非空强合同保留，不恢复旧 API。独立回归实际由 crash `-1073741819` RED 到 `Decorator` 11/11 GREEN。原 Mux focused 122/128、6 fail 和失败 XML 保留；旧 6 failed 在新源码上 6/6 GREEN，但不能称 128 或全量当前通过。

`DnsCache` 仅 validate-only actual exit0，540-row matrix 尚未完成；`DnsSession` 首轮因 client 没有 half-close hang，补 `Shutdown` 后真实 1/1 natural exit0。`ListenerAdmission` 6、`SessionOrchestration` 9、`SessionServices` 6 均 natural exit0；Session 19 target/100 CTest 是 Stream 修复前的历史限定结果。新 Main 夜间 `-j1` actual build exit0，SHA256 `D53559EFEFCF73D9E86DE008FBB47D192031DF12B9438EBA8874CBDF54BCC508`；`current-contained-provider` 的 18 个 SOCKS5/SS2022 Application 场景全部 exit0，raw cleanup `Remaining=[]`。Main `6B6B`/`32DA`、Hysteria/TUIC 140 次和 structured Mihomo 均只绑定历史 EXE，不能覆盖 D535 当前 Main。

Standalone 60 rows 的历史结果为 54 pass、6 blocked、0 fail、exit2，只绑定其当时 EXE；six interface/unavailable 仍显式 pending。Transfer `transfer-current-45-validation` 为 45 groups、105 lanes、9 summaries、actual exit0；当前 scatter 成本偏高属于 baseline 事实，不声明改善，也不表示生产已采用某算法。最新源码 gate 为 639 production headers、0 production `.cpp`、606 test-layout files，属于 source-level 通过。

22:26 用户指出子代理循环后，重复旧卡和 AST0/hash 虚签已收住，扩张式派单暂停；后续每个窄批必须 actual compile、focused test 和交叉审查。Root 22:30 的全 Preview 夜间 `-j1` compile 仍进行，源码尚未冻结；全量 CTest、严格 style、全部 Main 互操作、性能对照、ODR、Linux、旧对象精确 cleanup 和 production shell audit 仍 pending。本段只更新当前事实，原检查点和历史证据继续保留。

## 10月8日20:30 历史事实与下一步

原 Task4–8 继续执行，同时落实用户追加的 Task9 测试规范：逐用例按 `Preview/` 的实际接口 owner 映射，不把多个独立协议测试堆在 Common/Runtime；真实跨模块场景按 Integration 的场景与协议细分。普通测试仅 CPP，最多800物理行；共享 HPP 仅用于多个 CPP 真正共用的模块封装。函数120行、lambda10行、参数通常2/复杂3、PascalCase 与中文 Doxygen 都属于验收范围。模块代理只改分配范围，Root 串行整合 CMake、文档和引用并唯一编跑。

当前 Main EXE SHA256 为 `6B6BD58D8C5E9B741D7CD09C9060563F862A041F2B4C0C4824A946071D14279E`。Hysteria2 认证正负与真实 TCP/UDP、TUIC20轮/140次单次拨号、SOCKS5三次精确29字节HTTP响应与 Worker/Session terminal/phase/target evidence 都已实际通过且自然退出；SS2022标准Go客户端的重复底层Close夹具已改唯一真实Close owner，双向完整echo也已通过。其余真实请求和完整矩阵仍需当前版本验收，不能扩大这些结论。

当前生产639 HPP/0 CPP；源码方向、大小写、退役接口和测试800行布局门禁通过。独立AST风格扫描仍有长函数、长lambda和宽接口问题；新布局正在源码阶段修正，没有最终当前build/CTest/性能签收。23个退役旧测试EXE已精确删除并保存旧hash与清理结果；有效build/tests、依赖与性能baseline保留。首轮全量4896注册/25禁用/23失败或未运行是历史失败证据，重组后的完整新回归尚未运行。

所有原始检查点和实施卡保留在下方及现有 [progress.md](../../.superpowers/sdd/2026-10-03-preview-no-compat-execution/progress.md)。只读生产空壳/未接线审计的阶段二仍未批准，未执行生产删除或功能接线。

## 历史事实与实施检查点

Task 1、2、3A、3B、3C 已按各自范围签收；Task 4 的最终当前消费者回归与整体冻结仍未完成。Task 5 和 6A 已推进实际接口退役；6B 已有当前统计接线、Session metadata、Operations Cancel 和限定真实请求证据，但整项仍未签收；6C 按独立 owner 并行整改。Root 协调并独占构建与真实运行，三个子代理分工实现、只读质量检查和独立状态机整改；工具并发配额含 Root 共四席。当前源代码与文档仍未达到 Task 8 最终验收，不提交或推送。

当前工具限额包含 Root 共四席，三个子代理按不重叠的文件处理 XHTTP 生命周期、识别取消收口和 Restls 状态机；Root 负责交叉审查、共享控制路径、文档及集中验收。构建、CTest discovery 与运行只由 Root 执行，所有编译输入在该阶段冻结。任务复用现有台账、客户端和 build/，新增必要 XML、请求记录与日志用于实际验收，不创建每卡一套计划、脚本或 target。

当前文档与运行证据必须按 epoch 解读：Main `1B726DC7154512A449666B9EDADF25079AB94821339C58422FBF147C43BC6A0F` 已在当前源上完成限定 SOCKS5 selector/pending 请求和 XUDP 请求；它晚于 DA66 识别取消修复及当前统计/Session metadata 收口，但不能写成最新完整 Main 绿灯。旧 Main5295/BF、旧 T20 与旧 XML 仍保留为历史证据。认证唯一 shared owner 是 `Preview/Account/Authenticator.hpp` + `Preview/Account/Lease.hpp` 的 typed `InspectCredential`/`Authenticate` 链；旧 `Check` bridge 和第二事实不保留。S5 非零 stream/task selector 正式返回 `target_unsupported`/Rejected，worker Tasks snapshot 沿 parent→child→grandchild tracked descendants 聚合，root cancel 不冒充 child cancel。

原 `GatewayCommon` 已完整移至 `tests/Experiments/Preview/Quic/GatewayCommon.hpp`，生产 CMake 登记已删除，并在测试专用 PreviewTestSupport 登记完整实验 owner；当前仅 `tests/Preview/integration/Task9FrontIntegration.cpp` 与 `tests/Preview/integration/Carrier/RecognitionQuicCarrier.cpp` 两个测试消费者使用它。该骨架只证明测试域行为，不证明真实 QUIC Main。10 月 5 日 45 路文档 manifest 相对当前磁盘已有 22 项 SHA 漂移和 1 个已删除 Account README；原 13 路基线与 Diagnose 约 53KB 历史资料继续保留，D5 仍待 Task8 最终重捕获。

Task 4 最近单元的签收范围如下，不能累计成整个 Task 4 的当前源码通过：

| 单元 | 已核对结果 | 证明范围 |
| --- | --- | --- |
| 001–002 | 三个 target 构建成功，同一批 16/16 用例通过；SS2022 fixture 改为真实解码的 PSK | SOCKS5/SS2022 cold binding、外层认证和原 binding 生命周期；还不是 MuxSession::Run |
| 003 | 新增 SOCKS5 configured Smux 会话，1/1 通过 | 真正运行 root/child，TCP loopback backend 校验固定 payload、EOF、lease 与 drain |
| 004 | 保留 SOCKS5 并新增 SS2022，2/2 通过 | 两族各一条真实 child；不能代表多流、quota 或真实 PrismPreview listener |
| 005 | 保留两条 echo，新增两族 pending read 的 catalog 取消，4/4 通过 | backend/client 实际 I/O 退栈、root 返回 Canceled、连接/流计数归零、weak root 释放；watchdog 未触发 |
| 006 | 2026-10-05 quota2版本已由Root签收，6/6通过；首轮与中间失败分别保留 | 真实 cold 账户 MaxStreams=1；第二 wire child status1、无新dial；第一 child 拒绝后继续 literal回显；最终0/0及drain/weak；不含JSON quota/listener |
| 007 | final 8/8由Root签收 | 两族同一root在第一child FIN和真实释放后replacement，第二dial/echo、活跃1/1、最终0/0；不含multi-root/multi-waiter |
| 008 | 三target构建成功，24/24由Root签收 | Catalog保存首个typed异常、继续其余owner的真实drain后重抛；错误fixture与真实red分开保存 |
| 009A | 三源码路径拆分、七target构建成功、98/98；Root核disk/raw/XML，独立C0/I0/M0签限定范围 | 冷carrier注册完整owner拆分，MakeTcpCandidateRegistry由203行缩至21行；额外异常契约修正仅注释，代码token相同 |
| 009B | 六header注释已完成并由Root核token/AST与真实契约；没有重复构建 | 所有权/错误/取消/半关闭/关闭者/executor；另纠正共享引用、可重复cold view及支持StreamFactory的variant措辞，不替代行为回归 |
| 010 | 双factory/root夹具修正后，当前全部10/10通过；旧超时/失败分别保留 | 同prepare/bind真实两次认证和lease、两个真实后端独立literal、首root关闭后兄弟续传、同控制executor两个Drain waiter、2/2→1/1→0/0、弱owner释放 |
| 011A | Password类型修复后，当前真实Main v1/v2两正例通过，错误密码被协议阶段拒绝；两个实例Operations自然exit0 | TLS/认证/首PSH目标与37字节literal、两流、FIN后兄弟继续、peer EOF、重复Close；负例echo无payload记录，未单独统计上游socket accept数 |
| 013 | 修正EOF与executor初始化夹具后两个target构建成功，当前19/19用例通过 | 保留原7关联owner场景，补IPv4→IPv6同关联、unknown Keep无stream/额外report、IPv6 codec、truncated/option/unknown、writer partial/error/cancel；只签该范围 |
| 012 | 两target已构建，实际21-case运行中AnyTLS全11通过；Multi另外失败后已单独修复 | 非法SETTINGS/SYN六输入、真实pending writer/dial取消、observer throw保业务、repeat Close、零字节流完成报告一次；没有成功路径手动放开dial gate |
| 014 | H2 quota/replacement与partial/error关闭测试构建并在158个focused用例中通过 | 真实H2账户、第二流拒绝无dial、END_STREAM后replacement、pending read/FlushGate/weak关闭；原大lambda债务单列 |

008最终XML SHA256为`2757775D2CDA96ABAEDDFDF812CAF149837D04F3EFCCF805F021AEBBCFB30663`，覆盖ProviderCatalog、BindingLifetime与ConfiguredMuxSession共24用例；multi-root/factory容器和multi-waiter仍待010卡验证。009A的98用例对应10月5日构建，XML SHA256为`52CF301028F14F71EC35E6A0C1E0FB0FA6E89997C6C667800A6A5956469FB050`。10月7日Root核7个exe与配置hash一致；新header额外中文注释修正与该构建源码1940个AST token完全相同，仍不是今天完整App/全量回归。文档45路径已同步，详见[10月5日文档证据](2026-10-05-preview-documentation-update.md)。

005 的当前验收 XML 为 `.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4luna005-evidence/ctest.xml`，SHA256 `5E518B508669B99531DB6A3291061A3E5CA1B65345F6BDEDA18D61AE59234C97`；对应 `ConfiguredMuxSessionTest.exe` SHA256 `A01DFAD48413BB5EB47C273227DAD8F4836B18E9166CC271979D519848EA75FA`。Root 核对 1927 个源路径的编译前/后及当前哈希，漂移为零。006 开始前再次检查同一 1927 路径，漂移为零。

配置账户的实际装配目前仍使用默认 `QuotaPolicy{}` 与 `UnlimitedRatePolicy{}`。006 注入真实 cold 账户 policy，不能称为 JSON 配额已实现。SS2022 旧字符串密钥推导入口已在 6A 删除，正式 API 使用显式 16 字节 PSK；当前专项协议、互操作与性能闭包仍需在最终源上重建，002 的历史 fixture 结果不替代这项验收。

013当前验收XML SHA256为`D3AF60DC7E73E05CD21FFEFBF3395C444E46683766D276E5001E1D37F4F454E6`，19 testcase、failure/error/skip均0，实际CTest exit0；此前并行首轮29中23通过、6失败的原XML另存，未改写为生产red。实际AnyTLS正确密码诊断确认TLS与识别成功后账户认证失败：Application创建Password，IngressFactory曾按Token查找；修复后只保留Password，不同时尝试旧类型。该诊断运行的原PID已退出，临时配置/log已归集并清理；当次未保留自然exit code，未报exit0。

按用户要求并行推进的独立6A子项已删除Boundary两处numeric-CID map、旧Register/Remove overload及fallback，四个已有文件源码迁移与实际消费者重建完成；19个账户/边界用例及25个实际DatagramService/Task9Front用例通过（重叠1项，共43个独立名称）。其中暴露的旧VMess测试把DatagramServices填入Accounts，已迁为正式Datagrams字段并通过。原 GatewayCommon 测试骨架现已整体移至 `tests/Experiments/Preview/Quic/GatewayCommon.hpp`，生产 CMake 登记已删除，并在测试专用 PreviewTestSupport 登记完整实验 owner，两个测试 consumer 保留；这不等于真实 QUIC Main 能力。HTTP正式IngressFactory、实际CMake与消费者迁移已在158个HTTP/H2 focused用例中通过。TrustTunnel正式owner及同wire/auth binding已构建，新wire用例仍在修复fixture时序；Application八槽acceptor/第二工厂的正式删除正在并行实施，不宣称整个Task5完成。

10月7日18:14更新：现有MuxPerf新增的真实Trojan账户/root/child/loopback路径，按64MiB、64KiB、1024样本执行；去掉定位输出后，原6项与新增Smux/Yamux/标准H2三项全部通过。断言包括独立payload/hash、FIN与peer EOF、root/binding drain、账户连接/stream归零和weak owner释放。普通与aligned new仅统计payload测量窗口内的C++分配，不等于全部malloc/PMR/copy/syscall；单次结果是当前绝对基线，完整交错性能比较仍在7B。合并XML `parallel-trust-mux-focused.xml`为14项中的13通过、Trust新wire1失败，不能写整个XML全绿；后续Trust诊断单项通过亦不能替代消除fixture共享标志短路的最终验证。

10月7日19:34更新：Trojan/VMess两个既有客户端的真实application-mux六场景已经通过，分别覆盖Smux、Yamux、标准H2。首响应分别核外层H2状态和内层sing-mux admission字节，两个stream同时存活，FIN1/EOF后同一个sibling实际继续传输；三个独立payload逐字节比较，客户端、App、echo均自然exit0，账户active sessions归零、Sessions为空，原PID均退出。两个错误凭据场景client exit1、backend无payload，App/echo自然exit0。该层验收使用Main SHA256 `D0C9F73172FD3D3C6249A8A77F72F3DEF3B7C9F1655F769018AC200A655176E3`，不能替代后续6A接口变化后的重建。

VLESS XUDP旧Main握手Recognition超时的根因是合法Mux头仅19B而candidate要求22B。修正正式边界及纯凭据inspection后，当前App真实两association、first End、未知Keep精确End/OptionError、未知End后same sibling continuation均通过。实际UDP literal为32/32/45B；前两association源端口不同，continuation复用第二端口。去掉定位输出后的客户端也再次通过，客户端、App、echo自然exit0，账户active/session列表和原PID收口。最初timeout、回包读取失败和修复过程均保留，未以client padding、sleep或retry获得绿灯。

唯一 cold builder 与中立 carrier 迁移的 Main 及9个测试 target 已构建，97/97 focused 用例通过，XML SHA256 `C978098BA6AB9748A5BD63CBB55AE788F559E073DBFC61219ECB529E50F1BD58`。TrustTunnel 同 wire binding、真实 TLS/HTTP2 payload 与关闭的最终5个专项用例也已通过，XML SHA256 `0C20D359AE3C24C9E3C96E0F7A5AB1CF9BE3A33D4CF187D74928C363C1ECAB72`。这些均绑定当次源码，后续改动需当前回归。

20:36 更新：认证归 Account、SS2022 显式 PSK、唯一 cold schema/recognition model 的调用者迁移完成一轮 core 验收。Main SHA256 `41BDFF7720EF5C7780778C45D586E3A542F3C6AA8AC7B4649A5DAB9F2A6A7D0B`，15个 core target 的实际258个 focused 用例全部通过，XML SHA256 `FBA87B6FD95D59CB3AE45D9168B2D157C67600957DD452F94799825A1B69093F`。该 Main 的六个 Trojan/VMess mux 模式、一个 XUDP 正例及两个错误凭据负例再次完成真实 listener 验证，App/echo 自然退出且原 PID 均退出；这些配置关闭 Statistics，不能证明统计接线。

Route/Outbound/Scheduler 与 ProbeDefense 无生产调用者，已整体移到 `tests/Experiments/Preview` 并删除生产 target/source 边。原 Route/Outbound/Scheduler 15个用例全部通过，XML SHA256 `399225E9188CB3EBD2C82F9521B7C5A1A8366034B6C564A271899D92EADF46D2`；原 SchedulerBenchmark 两组200000操作自然退出。HTTP/2 首非 P 字节静默 bypass 已删除，合法完整/分片前言保留，HPACK 长函数分解后的全部46个 codec/session 用例通过，XML SHA256 `0E0B869CCB46925AD9F6FD907A116470A772D58A5D4CF3F2D95E29DDD4E736AB`；后续 Trust/Gun/XHTTP/Main 闭包仍需统一重建。

22:00 更新：SessionRegistry 无 control 的 `Put` 已删除，15个正式注册/快照/并发/取消/分配失败用例通过，XML SHA256 `5DAF63732E0F0268C476DC3BFE99EF2C1428A53698E8B5095912BD98F4B2BF3F`。CarrierValidation 单长函数拆成8个真正 typed 验证分支，配置与 secret 冻结的89+7个独立用例全部通过，XML SHA256 `0B2A4901973326D1785512F2250E974CDEBDA0621167900B87E4C248017E76E4`。期间并发测试发现曾损坏生成的 CTest 注册文件，原始内容和重复注册的110次执行另存；恢复后的96个唯一名称才是本次有效计数。构建、测试发现和测试执行以后均由 Root 串行协调。

6B 的数值事件、固定容量队列、定时/最终刷新和 Operations 已落源码。Stream 统计键包含父 session，避免两个 root 的同号 wire stream 混计；旧字符串/COW 计数器已删除。原5个加7个队列/容量/epoch/并发/终结/同号流用例在第一版完成观察上通过，XML SHA256 `A69E5B68C21BBE156C1F03E697F50E3A1E2729B838B30B3B04C3C02D24F34CDF`。后续增加 `Bytes/Completed` 实时增量，并迁唯一 shared sink；Root 退回了额外 observation 回退和空析构器包装裸指针的实现，调用者已继续迁移。该接线随后已完成173个focused用例及Main真实TCP/XUDP增量验收，具体哈希见下文10月8日证据；之后Session metadata、取消收口与其他源码仍在继续整改，不能标成整个6B通过。

10月8日00:06更新：最新17个测试 target 的173个独立 focused 用例全部通过，XML SHA256 `F05B83754CD52A84D9337714162E7228C592CDA35CAF3615A3D2ECD90BD3274C`。覆盖统计定时/最终刷新、真实两 worker relay 的 idle/write/关闭异常、AnyTLS 真实 outbound 关闭异常、XUDP DNS/cancel/quota/地址族/兄弟流，以及 SOCKS5/VLESS/SS2022/Hysteria2/TUIC UDP 和生命周期。此前100个用例的4项失败、166个用例的7项失败及后续单项失败均保留；后来的通过没有改写旧结果。

此前 Main SHA256 `BF644F197BBD7005D91622CA1C03292791F00D0333E0C97736CC21EF3B6DF074` 的 36B SOCKS5 与 XUDP 32/32/45B 结果保留为历史快照。此前 Main SHA256 `52950078611C4D77FE15A16E1ECB726752A84326005B6CBBC96F2AE3633D1064`、配置 SHA256 `8E45B02863D658AB1C69587BE83ADD1BF8C46C8FAC9F64ABB7F709C2135FB88E` 已验证真实 SOCKS5 pending session：运行期间 metadata 为 worker1/account1/generation1/protocol2/target `127.0.0.1:57344`，完成 POST、Session Cancel、peer EOF 后 account 归零、registry 为空、Completed=1，App/echo 自然退出。该 epoch 的 XUDP 限定结果为 109/109B、Completed=2、drops=0、自然退出；原始 JSON/XML 与进程记录位于现有 `task-4-evidence` 目录。该证据修正了“metadata 仍为空/Cancel 尚未验证”的过时描述，但仍不代表完整 6B、全量 Operations 或 Task 8 验收。

Reality 完整握手已由 Composition 移回 `Protocols/Reality/Prepared.hpp`，协议拥有认证、flight、Finished 校验、错误关闭和最终 record stream；Composition 只消费已解析 ClientHello 并转换一次正式结果。`ConfigurationStartup` 按共享 listener、协议需求、carrier、外层 TLS、冻结 builtin 分解冷校验，仍待当前 App 构建与启动验收。当前 QUIC 和 SS2022 raw UDP 没有 Runtime worker/session/task 身份来源，报告保留真实 generation/account 和控制槽，不伪造其他 ID。

用户新增要求的 Markdown 同步已拆分为开发者入口/架构与 Account/Diagnose 文档、根 README 与用户教程/索引、历史分析台账与验收文档三个范围。源代码代理编译时，文档代理先准备可审查草稿；编译安全边界后逐文件应用，保留历史报告日期和原始结论。文档改前字节固定在 `.superpowers/sdd/2026-10-03-preview-no-compat-execution/docs-20261005-baseline/`。

Task 4 尚缺完整运行态边界、所有有效消费者当前回归、当前 PrismPreview 真实请求与完整源码审查。Task 5 → 6A → 6B → 6C → 7A → 7B → 8 顺序及原范围保持；全量 CTest、完整互操作、性能对照、Linux 编译与最终无兼容层验收均没有在本状态中签通过。

## 已签收卡的范围

| 卡 | 最终限定结果 | 当前仍需区分的后续责任 |
| --- | --- | --- |
| 1 | Boundary packet 借用/最终转移合同，拒绝回落保留 payload/CID/metadata，独立审查通过 | 最终当前真实入口统一回归在 7/8 |
| 2 | StartupTransaction、无环服务快照、失败回滚/owner 释放，独立审查通过 | 后续接口变化后仍需重建和最终 Application 验收 |
| 3A | 唯一中立 handoff、协议 UDP owner、旧 fallback 退役；68 targets，652/652 selected，生命周期 250 次执行 | 此结果对应 3A 当时源快照；不能替代今天的全量 |
| 3B | SOCKS5/SS2022 prepared factory/binding；73 targets，737/737 selected；18 listener 场景/12 literal records；独立 C0/I0 | 部分 runner 强杀退出不等于自然 App drain；最终仍在 7/8 验证 |
| 3C | Hysteria2/TUIC 及 Catalog；105 targets，951/951 selected；21 场景各10轮；两族各3 native run 自然 App exit0；独立 C0/I0/M0 | 只覆盖 3C 最终源；全协议互操作、性能与整项验收仍未完成 |

3C 最终 selected XML SHA256 为 `42241B578384146B7A8B5972B8D6AFF1054AA66DFEAC2644DC68920959FB42F4`，当时 PrismPreview SHA256 为 `7FF04B14F4BF1FA8D5BCDFA5F1220059EB48957A8E034C6DBB06F45729A5F315`。此版本与 Task 4 后续构建分别记录。

## 10月8日新增限定证据

此前统计接线 epoch 的17个测试目标共173个唯一用例实际通过；XML SHA256 为 `F05B83754CD52A84D9337714162E7228C592CDA35CAF3615A3D2ECD90BD3274C`。当前 Main `1B726DC7154512A449666B9EDADF25079AB94821339C58422FBF147C43BC6A0F`、配置 `E8BCACB9DF18A410FC9BB999070056C413E41B9637DD021865186F2DDA3BBA9E` 已完成真实 SOCKS5 POST、Session Cancel、peer EOF 和自然 drain：运行期间 metadata 为 worker1/account1/generation1/protocol2/target `127.0.0.1:49293`，stream7/task9 的 `target_unsupported` HTTP400 被拒绝而 root literal 继续，关闭后 account/registry 归零、Completed=1、traffic=72 无重复计数。App/echo 自然退出，结果 `23F495FDEFE7A76231B5AA907AA22AEC33745305178812162B32B6FA0B6DAE57` 与原始进程记录位于现有 `task-4-evidence` 目录。

新增四线程×100轮并发元数据更新测试在旧实现实际出现273次不完整更新；Root修正CAS重试值保存后全17个Registry用例通过。TaskRegistry的完整命令执行阶段迁入已有 `TaskRegistryCommands.hpp`，相关27个生命周期用例全部通过，包含Listener错误hook。Session token保持到Session owner最终关闭和listener错误投递结束，不在RunCore返回时提前退休。

00:36–00:39 TUIC Application实际连续20轮、七模式/轮、140次客户端全部exit0，每次只拨号一次、无retry；App通过Operations drain自然exit0，原PID29128已退出。该结果绑定 Main `BF644F197BBD7005D91622CA1C03292791F00D0333E0C97736CC21EF3B6DF074`、Go client `BB920548CB3527609081CEEC13D46D135BC0F379B46FBD21AFE49BB0F57D2EEC`、配置 `B5B1A6805042E0B384C5561E12000769E4F72EFB55B78869971507F02E4157C5`；原始证据SHA256为 `CDB52972931FD8D9DD72E4283C926C3F0DBF0662A61ACDCD986CD39C8C54D191`。它不能替代随后修改的XHTTP、Recognition和最终Main验收。

10月8日当前源快照的新增限定结果：同一当前 Main 的 XUDP 为 109/109B、Completed=2、drops=0、两个 association 的 sibling continuation 和自然退出均已核对；配置 SHA256 为 `58E4FB80B524FDFBC9A4CDB34E29A311F42177FD03FEF7B93FEBE8FE98784771`，结果位于 `task-4-evidence/parallel-live-stats-xudp-1b72-result.json`。T20 当前 Main 完成20轮、每轮7模式、共140次 client，单次拨号、无 retry，App 自然退出。当前 TaskLifecycle 28/28、SessionLifecycle 18/18（含 P1 final hook、registry 1→0）和 Configuration 89/89 的 XML 均保存在既有证据目录；XHTTPMatrix 15、Ngx 3、Reality 4、Restls 3 也只按各自当时源码范围记录为通过。`Preview/Runtime/Session/Delivery.hpp` 是当前唯一必要 production owner，结构 gate 覆盖642 headers、1030 consumers、0 production `.cpp`，这些结果仍不等于全量 CTest、Linux、全协议互操作或 Task 8 签收。

交叉审查曾发现 XHTTP detached driver 借局部 shared_ptr、关闭不取消真实 TLS read、END_STREAM/RST 分类，以及 Recognition 取消后固定 100ms 返回却未等待 losing operation 完成等问题；当前 Recognition join/cleanup 修复已进入最新源码输入，需由 Root 统一构建验证。兼容退休包含唯一 Recognition.Pattern（删除 Domain 回退）、canonical ProfileError 与 CandidateBitmap.Test；所有受影响测试与文档继续同步。当前风格门禁、完整互操作/性能、一次完整 CTest 和 Task 8 仍未完成。

## 剩余任务与验收边界

| 卡 | 状态 | 必须闭合的责任 |
| --- | --- | --- |
| 4 | RUNNING，未整体签收 | 两族 mux quota/reuse/multi/cancel；AnyTLS/XUDP/标准 H2 状态与关闭边界；有效旧消费者当前回归；当前 App 请求；完整源码冻结与审查 |
| 5 | 独立HTTP子项通过，Trust与唯一cold binding进行中，未整体签收 | typed carrier/accept owner；Application 数组/旧 adapter 退役，认证/lease/PostDial 唯一合同 |
| 6A | 独立子项进行中，未整体签收 | 第二 parser、旧 Account/Check、字符串统计及剩余内部 fallback；SS2022共享caller退役；未部署研究闭包隔离。numeric-CID、旧Composition API/Coroutine Registry按各自实证验收 |
| 6B | 当前173/173 focused、真实TCP36B与XUDP109B统计、Session metadata 和 Operations Cancel 均有限定版本证据；尚未整项签收 | Enabled/Interval、成功写入增量与零字节最终事件、有界观察及最终flush已有对应运行证据；后续源变更仍需当前 epoch 重建，不能据限定 Main 宣称整项通过 |
| 6C | RUNNING，门禁尚未清零 | 固定原77目录台账、物理 include/CMake 所有权与无环；600/120/10/通常2复杂3参数；新增目录另列 |
| 7A | RUNNING；旧 Main5295 的 TUIC 20轮/140次限定运行已通过，Main1B72 尚待重跑 | 历史结果为单次拨号、无 retry、App自然exit0；当前S5 selector和XUDP已实际验证，所有最终源的全协议/carrier矩阵及自然drain仍待收口 |
| 7B | source harness 已就绪，未编译/运行 | `RecognitionPerf --owner-compare` 当前覆盖固定 trace 的 CID scale 与 SNI route capacity 8/64/1024，A 使用真实 CID/SNI/account owner，B 的 account 仅为 idealized lease lower bound；原 Task7B 的 mux/coalescer/I/O、真实 Application 路径及最终五轮交错 raw 对照仍待执行，不能以 source-ready 或 Perf label 当完成 |
| 8 | 待前置 | 当前全部 affected build、focused 与一次完整 CTest、headers/ODR、全互操作/性能/broad review、最终文档和清理 |

10 月 8 日 06:50 的整体源码结构检查为 641 个生产 header，超 600 行文件、超 120 行函数、超 10 行 lambda、内部超 3 参数接口和解析错误均为 0；另列 41 项按文件、符号和参数数目精确匹配的第三方 C ABI 合同。该快照只证明结构检查，最终仍须复核通常最多 2 个参数的职责、输入所有权和完整消费者闭包。

6C 接口源码仍在当前 epoch 继续变化；641-header 结构快照、函数/参数门禁和 41 项精确 C ABI 例外清单都只是中间审查结果，未完成当前完整 Main/消费者闭包、ODR 与最终风格签收。

Linux 预检没有可用 WSL、docker/podman 或已获得连接的 SSH 工具链；本轮没有安装或改系统/SSH。所有可完成的本地工作继续，Linux 编译尚未执行，不能报通过。

## 原始证据与历史

具体 brief、report、独立 review、immutable source baseline、source/binary/config manifests、raw logs/XML 保存在 `.superpowers/sdd/2026-10-03-preview-no-compat-execution/`。本文件更新前包含的详细过程已按原始字节保存在 `docs-20261005-baseline/docs/preview-refactor/2026-10-03-preview-no-compat-status.md`，文档基线 manifest SHA256 为 `51D9AC8431EFBB24A7DFC525CD49DBE683D492680D7F883B13FDCB2AAACECE5F`。最终 Task 8 将所需证据整理到耐久交付路径。

历史失败、源版本、fixture 修正、强杀与自然退出分别保留，不用后来绿灯重写之前结果。角色交接和旧模型要求以当时记录为准，当前角色和模型以上文为准。

- [执行计划](2026-10-03-preview-no-compat-execution.md)
- [10月3日会话质量复核](2026-10-03-preview-session-execution-review.md)
- [9月28日分析台账](2026-09-28-preview-module-refactor-analysis.md)

## 10月8日当前 source 台账补充（增量）

当前 77 目录 denominator 仍固定来自 `original-77-directory-inventory.json`；新增 `Boundary`、`Contract`、`Composition/Provider`、`Runtime/Session`、`Account`、`Operations` 和实验目录单列，不折算进 77。当前 source gate 为 639 个 production headers，包含实验 owner 的扩展 source gate 为 664；这些是结构/所有权事实，不是全量运行通过。

当前已记录的 scoped evidence 包括 QUIC Native loopback 9/9、close lifecycle 4/4、CandidateFactory 16/16、Recognition 实验 35 + TLS reassembly 44 + scheme 3、TaskLifecycle 31/31、WorkerGroup 8/8 以及限定的 App/S5 selector/XUDP 请求证据。最近 Main `5B03` 在后续 cold-owner 迁移前构建，必须视为 stale epoch；旧 Main5295 的 TUIC T20、Main `1B72` 的 S5/XUDP 和历史 XML 不得覆盖当前源。

当前仍未完成 whole CTest/discovery、ODR、Linux build/CI、最终 Main 多协议/carrier 互操作、完整 cancel/drain、Task7B 五轮 raw throughput 和 D5 manifest。`docs/preview-refactor/2026-09-28-preview-module-refactor-analysis.md` 末尾的第 21 节保存逐 #1–#77 的 current-source owner、生命周期不变量、源码/CMake定位和 pending 边界；本段不改写本文件此前的历史表格和历史证据。

## 10月8日 runtime/build 增量

`SessionDelivery` 当前生产 SHA 为 `632C0A36F02DF19FBF3CCDEB341FD9F66AABC2FC0EDCE5A1301ACEA1A3EBA61C`，`SessionLifecycle` 当前 21/21，证据为 `parallel-delivery-weak-signal-context-current.xml`。Trojan 当前 8/8、VLESS TCP 9/9、VLESS UDP 3/3、Socks5 longitudinal 5/5 已有对应 current XML；这些只覆盖对应 target 与 weak-signal/ack lifecycle，不构成全量 Preview CTest 或全协议互操作通过。

VMess/SS2022 consumer source 已把 Completed、字节和 numeric account 断言放到真实 `Listener.Shutdown()` 后；最新编译 batch `14189` exit0 后，Root 实际运行 VMess 8/8、SS2022 5/5 均通过，包含 TrafficIdentity；证据为 `parallel-terminal-VMessE2ETest-current.xml` 和 `parallel-terminal-SS2022E2ETest-current.xml`。SS2022 的 expected AccountId=1 来自现有 `tests/TestSupport/Preview/ProviderBindings.hpp` 的 `ProviderDirectory` fixture。Trust source `D853053E...` 已由 Root 重编 batch `34808` exit0，并实际通过 TrusttunnelHttp2Transport 5/5，证据为 `parallel-trust-value-state-current.xml`；Factory/Registry/ProfileBuilder/Application cold owner 源码已落盘但尚未当前重建。Main `5B03` 仍是 stale epoch，`1B72` 只覆盖 S5/XUDP 72/109 的限定证据，TUIC 20/140 属旧 Main5295 epoch。

## 10月8日12:27 当前构建与限定验收

最新 Main SHA256 为 `B38A88E89CC54A93B0EDEAC58B15528E36741599BC516A4DA523087580390071`，构建 `current-App-and-Main-binding-policy` 实际 exit0；模板及构建复制的配置 SHA256 均为 `C245C56845ACC08F415F14CB372F1FABE54F541241E914880A0BE536D80E3501`。本段取代上文“cold owner 未重建”的当前状态说法，上文各时间段数据保留为历史证据。

当前 Composition 冷路径 Registry14、Factory16、Profile19、Carrier25 已实跑通过；随后 Application 的 ConfiguredMuxSession11、ConfiguredMuxProvider3、ProviderAcceptPath7、ProviderClosingOwner1 共22项全部通过，XML 为既有 task-4-evidence 下 `parallel-current-binding-*.xml`。新增真实 VLESS fixture 覆盖同协议两条绑定的 UDP 策略与两种顺序：启用者成功响应，禁用者拒绝并关闭。正式 BindingId/UdpEnabled 已从配置贯通至工厂，删除协议级第一绑定选择及 mux 名称后缀猜测。

账户 generation2/generation7 的首次 policy 发布不一致已用失败测试复现并修复；AccountNgx29/29 当前实跑通过。DNS 取消不写负缓存，下一独立请求可成功；DnsResolverNgx12/12 与 DnsPerf coalescer 的1/2/4 owner各5轮共15轮已实跑通过。后者是当前生产 coalescer 的规模基线，不能证明替代算法收益。双编译单元严格 ODR 链接及29项测试通过，只覆盖这两单元共享头；本轮临时 ODR exe 已经用户授权并精确清理。

当前完整 Preview 依赖构建与新 Main 的 TUIC20轮正在执行，尚未声明通过；全量 CTest、其它当前协议/carrier 互操作、剩余性能对照、公共所有权合同、最终文档和平台边界仍待收口。额外空壳/未接线审计只读执行，阶段二清理尚未获批。不能据本段限定结果宣称整项任务完成。

## 10月8日14:18 当前增量与剩余阻断

12:27 段开始的 B38 Main TUIC20轮已实际完成，140次client全部成功、单次拨号无retry，App经Operations drain自然exit0；Hysteria2负认证401、TCP23/UDP27字节及自然exit0也通过。随后 S5 和 Shutdown 源码继续变更，因此上述结果只属于 B38 epoch，最终 Main 要重新验收。

当前 S5 多绑定 UDP 权限泄漏已取得两顺序有效失败回归并修复；派生 view 只存命令 policy 与 mux，认证材料仍由唯一 BindingState 持有。保留已关闭 view 的认证器/目录释放回归同样先真实失败，修复后 BindingLifetime8/8 实跑通过。当前 ConfiguredMuxProvider4/4、ConfiguredMuxSession11/11 都实际通过，包含 UDP两顺序、mux quota、取消、FIN、双root与drain。正式旧 WithMux（S5）、未消费的 global Mux 字段和 BindingMuxModeMap 输出已删除，真实调用者同步迁移；SS2022 的 raw UDP仍为协议实例共享能力。

Shutdown 的超时后提前释放 provider owner 已由真实活动与 barrier 回归复现：22ms自然失败，仅“超时后 owner 应继续存活”断言失败。当前修复把 HTTP/TCP/provider/UDP/task 的实际 owner 移入具名按值协程，保持至操作退栈，保留超时失败和有界退出；源码 SHA `BFDA4F9CD9E0FFE7F66279C180E51F20D2CE0A01AACA2679017919BA33F94D3E`，尚待当前编译和完整生命周期运行。源码门禁已通过639 headers/1030消费者/0生产cpp，600/120/10/参数/parse均0，不把源码门禁当运行验收。

Mux 性能夹具的正常失败未发布完成信号已用真实错误认证取得红绿；45场景吞吐矩阵仍未运行。I/O 夹具第一次实跑卡在 lazy co_spawn 自等待，修正后自然运行到 bridge 预检又发现错误 category 被丢弃，尚无有效性能样本；继续严格修投影后复测。Registry 五轮比较只完成13个独立场景的195条有效数据，剩余5场景未完成；DNS coalescer15轮是生产规模基线。所有候选仍未采纳，完整性能、当前全量CTest、其它Main互操作、D5与平台边界继续执行。

当前 TCP/UDP/QUIC Mihomo runner 已按现有文件补入字节/hash、自然drain/exit0和进程身份核验，并删除无消费者的secret/warmup兼容参数；这些新脚本尚未真实运行。空壳审计保持只读，639头分类主干和证据差量在复核，safe-delete-now0，阶段二未批准。
