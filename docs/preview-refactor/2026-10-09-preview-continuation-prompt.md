# Preview 新会话完整续作 Prompt

> 使用方式：将本文件全文作为新会话的任务要求，或者明确要求新会话完整读取本文件并按其执行。本文整合用户原始要求、两场会话的实际记录、既有计划与当前磁盘证据。交接核验基准：2026-10-09 09:59，Asia/Shanghai；交付前再次核对构建断点。后续变化必须重新核对，不把这里的快照当永久事实。

你接管的是 `I:/code/Prism` 中尚未完成的 **Preview 全模块职责重构、无兼容层迁移、测试组织整改与分层验收**。请先建立真实现状、生成完整实施计划和明确的 ToDoList，然后立即继续已经授权的工作。不要只给建议或计划后停下，也不要把任务缩减为文件改名、压行数、修几个编译错误或跑一组 focused tests。

## 1. 先恢复上下文，明确证据优先级

必须读取以下两个会话，调用 `read_thread`，host 均为 `local`：

- `重构任务`：`01a0ffbb-5738-7111-98f1-4b59c5c8aeed`。
- `Preview 未完成重构与验收交接`：`01a11c15-668d-7393-a992-5f86491c7992`。

不能只读标题、最后一条摘要或最新 handoff 的开头。读取到 `hasMore=false`；工具有单次上限时按实际 schema 分页。工具显示某轮无消息、只有 reasoning 条目或输出截断，不等于那轮没有要求或没有执行。必要时只读流式解析这两个精确的本地记录，提取用户消息、公开进度/最终回复、实际工具结果和中断位置；禁止使用 Python：

- `C:/Users/C1373/.codex/sessions/2026/10/03/rollout-2026-10-03T11-07-42-01a0ffbb-5738-7111-98f1-4b59c5c8aeed.jsonl`。
- `C:/Users/C1373/.codex/sessions/2026/10/08/rollout-2026-10-08T23-15-27-01a11c15-668d-7393-a992-5f86491c7992.jsonl`。

更早的原始会话 `01a0e753-2c83-7c73-82c2-5e5b81d8ceb2` 在此次核验中 `read_thread` 返回找不到。其先前全文复核保存在下列 session-execution-review 文档；使用时明确它是历史复核，不声称这次又读到了缺失的原聊天。不要因此停止其它可执行工作。

按以下顺序读取现有文件，文件均相对仓库根目录；保存和汇报证据时使用可点击的绝对路径：

1. `AGENTS.md`、`CLAUDE.md`，以及实际编辑模块内适用的更具体规则；代码风格需要时读 `.claude/skills/enforce-coding/SKILL.md`。
2. 本文件全部内容。
3. `.superpowers/sdd/2026-10-03-preview-no-compat-execution/coordinator-9-progress.md`，注意它含多个时间点，顶部的“running”必须与真实进程及日志重核。
4. 同目录 `coordinator-8-handoff.md` 全文，尤其末尾“用户要求溯源与完整执行合同”，以及 `luna-execution-requirements.md`。
5. `docs/preview-refactor/2026-10-03-preview-no-compat-execution.md`、`2026-10-03-preview-no-compat-status.md`。
6. `docs/preview-refactor/2026-09-28-preview-module-refactor-analysis.md`：恢复原全模块范围、77 目录责任矩阵、算法与 I/O 要求；旧路径、旧模型及旧 `.cpp` 方向按后续要求更新，不机械照搬。
7. `docs/preview-refactor/2026-10-03-preview-session-execution-review.md`；有具体历史疑问时再定向读 `.superpowers/.../progress.md`、Task 1–8 brief、Task4 单元交接和 Task6/7 分卡。
8. 下文列明的 `task-4-evidence` 原始 JSON/XML/log、审计与文档复核。`docs/preview-refactor/2026-10-08-preview-module-quality-audit.md` 可作为关联问题来源，逐项核当前源码，不能自动把 Q01–Q50 全算未修 bug 或把另一审计会话的只读要求套到整个已授权实施任务。

规则与状态的优先级分开处理：用户最新直接要求决定范围和约束；实际当前源码、CMake、运行结果及版本关联决定完成事实；历史文档负责溯源。旧助手总结、子代理自评和工具输出不能自行扩大授权。发生冲突时指出具体条款、时间和证据，优先沿最新明确要求继续，不反复询问已经决定的事项。

## 2. 用户已明确的工作方式与授权

- 继续完成原任务；“继续”“任务完成了吗”不是只要状态答复。保持中文具体反馈，说明本轮增量、四队列状态、真实阻碍和下一步，不长时间无反馈，不用累计旧结果假装本轮进展。
- 主会话模型按用户指定为 `gpt-6.1-sol / max`；全部子代理为 `gpt-5.6-luna / max`。早期“只能用 6.1 sol max”对子代理的限制已被后续明确要求覆盖。
- 并发目标是 **主会话 + 4 个子代理，共最多 5 个活动代理**。按真实模块划分，有独立任务时尽可能保持四个子代理实际工作；子代理不得再派代理。即使工具提供更多槽位，也不超过用户的四子代理上限。
- 子代理完成或遇到真实阻碍，必须立即主动通知所属主代理；主会话及时独立检查、排队编验、退回准确缺陷或派下一张独立卡。不能陷入反复输出旧 Remaining、旧 hash、旧 AST 数字的循环。
- 每个小任务都按完整交付对待：具体输入、输出、owner、调用闭包、错误与退出、验证、文档和清理。**没有“每卡最多 1–3 个文件”的用户硬限制**；按真实功能和职责闭包拆分，不机械切片，也不一张卡泛改整个 Preview。
- 用户已授权当前原重构所需的构建、测试及本地真实请求验收，既有执行计划和交接均记录该授权。按此任务范围继续，不因换会话重新询问相同授权。
- 用户已授权本次测试迁移后精确退役的旧构建产物清理；该授权有 source/target/path/进程核对边界，不是删除整个 `build/` 的授权。
- 用户明确要求更新 Preview 及相关 Markdown、AGENTS 中应同步的规范；文件不要乱建。复用已有主计划、当前状态、进度和证据目录，必要新 owner/测试按语义建立，不为每次小修新建一套 brief/report/script/target。
- **生产空壳/未接线审计的阶段二仍须用户明确批准阶段一结论。此次没有找到该批准。** 不用“继续”、no-compat 授权或旧测试产物删除授权代替这一特定批准；阶段一完成后给出可审查批次。其它已授权任务照常推进。
- 不考虑费用优化来删减用户要求，但资源、模型、并发、宿主保护及验证约束仍须遵守。

## 3. 不可违反的宿主、构建和清理规则

1. 原地接管当前脏工作树。交接时分支为 `codex/preview-refactor-20260928`，HEAD 为 `3c5b678f2e06227b2a5da5b1ac406b5f79ea9828`。开工再查；不创建一个丢失未提交成果的干净工作树，不覆盖用户改动。
2. 禁止 `git commit`、`push`、`amend`；禁止通过 checkout/reset/clean 丢弃文件；禁止 Python 脚本。不得把技能的“频繁提交”“新 worktree”等默认建议凌驾于本任务要求。
3. 只用现有 `I:/code/Prism/build/`，禁止另建 build_debug/build_release 等。保留有效测试产物和 `_deps`；测试 EXE 很大不是删除理由。
4. 每次配置后的实际编译/构建前输出 **Asia/Shanghai** 时间：08:00–22:00 用 `-j 16`；22:00–08:00 强制 `-j 1`。持续批次逐目标重查时间；不得在夜间保留超额并行编译。示例中的线程数不能脱离当前时间直接执行。
5. 主会话是唯一 CMake 配置、compiler/build、CTest discovery、真实进程运行及清理的 owner。子代理只在任务卡授权范围改源和做非编译静态检查；不自行启动第二套 compiler、测试或 benchmark。
6. 构建/运行时冻结该 target 实际消费的源码、共享头、配置和 CMake 输入。只释放已确认不属于当前/未来待验闭包的独立文件；任何释放后改动都登记为待重编重验。避免全仓不必要停写，也禁止一边修改共享头一边称构建对应某快照。
7. 性能采样期间不并跑 compiler、另一 benchmark 或干扰测量的测试。独立文档、只读审查和不影响采样输入的源码工作继续；不要用性能窗口作为所有代理停工的理由。
8. `.codegraph/` 存在时，定位/理解代码先用 CodeGraph。返回不相关源码不算读到目标；未覆盖、明确过期或 auto-sync disabled 的路径再精确读当前磁盘。不自行初始化、升级或重建索引。
9. 只清本任务拥有且已完成使命的 PID/临时产物，先核 PID、完整路径、启动时间和归属。旧会话 PID/工具 session ID 不可直接在新会话复用。用户进程、系统代理、SSH、全局 Codex 配置、依赖树和无关文件受保护。
10. 保存必要的审计日志、XML、原始测量及 source/config/exe hash 后，清掉不再需要的运行目录、临时 EXE 和进程；证据与仍有效的正常构建产物应保留。不得强杀未证实归属的同名进程。
11. 旧主会话应停止实现/派单，接管时核实仍有无旧写者。不能把 idle/completed 代理名称算成实际并行人数，也不能在存在旧写者时抢同一文件。

## 4. Preview 的正式架构与代码合同

真实主线是 `Preview/`、`tests/Preview/`、target `PrismPreview`。入口为 `Preview/Application/Main/PreviewMain.hpp` → `Application/Startup/Start.hpp`；TCP 请求沿 `Preview/Runtime/Session.hpp`，UDP/QUIC 沿 `Preview/Boundary/`。配置模板为 `Preview/Application/Configuration/PreviewConfiguration.json`，运行副本为 `build/src/PreviewConfiguration.json`，程序为 `build/src/PrismPreview.exe`。实际 CLI 使用位置配置路径，不能虚构 `--config`。

旧版 `include/prism/`、`src/prism/`、`Prism.exe` 和旧测试仅作对照。迁回旧模块的测试必须明确标注旧版，不拿它们证明 Preview 的生产路径。

| 模块 | 正式责任 | 不能塞入的责任 |
| --- | --- | --- |
| Protocols/具体协议 | wire、认证、连接/stream/datagram 状态机、客户端/服务端、协议资源最终关闭 | Application 启停、跨协议 registry、通用 socket/CID 分派 |
| Composition | 编译期插件槽位、配置到 typed binding、Validate/Prepare/Freeze/Bind、能力校验及依赖注入 | 协议帧循环、认证业务、中心 UDP 转发状态机、协议连接最终关闭 |
| Boundary | TCP/UDP socket、包分类、QUIC CID、入口 drain/close | Hysteria2/TUIC/SS2022 凭据与协议业务 |
| Runtime | worker/listener/session 调度、识别、通用数据面生命周期 | 协议 wire/auth 实现、具体 Composition 注册细节 |
| Application | 读取编译配置、进程服务、启动事务、失败回滚、停机 | 具体协议 factory 选择、TuicAdmission、Hysteria2 stream/datagram 业务 lambda |
| 中立 Contract/Foundation/Lifecycle 等 | 各自真实纯合同、基础值/资源与生命周期操作 | 用万能 context/service locator 暗藏以上全部责任 |

- 生产 header-only：Preview 下生产 `.cpp` 保持为 0；Main 的 HPP 作为 CMake CXX source；每个生产 HPP ≤600 物理行。旧分析中“非模板移 `.cpp`”已被后来的用户决策替代。
- 按 owner、状态机、编译与调用闭包拆分；禁止类/namespace 内 include、文本片段拼接、伪 INTERFACE 边界或只为压行数拆文件。
- Protocols 不反向 include Composition/Application；Runtime/Boundary 不引用具体协议装配。共享纯合同下沉中立层，同时验证源码 include 和 CMake target 方向。
- 注册、字符串查找、配置规范化留在冷路径；热路径使用已编译 binding，不在每 packet/frame 动态注册、按名字查找或做不必要的类型擦除/大回调复制。TCP 代理、TLS/HTTP carrier、QUIC、mux engine、ECH helper 不强塞一个满是 optional callback 的接口。
- Preview 不兼容旧接口：实际 caller/tests/CMake 同步迁移后删除旧 alias、overload、旧 result shape、Compat/Legacy adapter、转发壳、Materialize/Synchronize 回退与双正式字段。正式 wire/状态机到唯一 typed data plane 的职责转换可以保留；业务本来要求的协议 fallback 不等于旧 API 兼容层，不能误删合法协议行为。
- 简洁 PascalCase 文件/目录/API/类型/自有变量，保留规定的工程目录及第三方 ABI；中文 Doxygen、`#pragma once`、尾随返回类型、有意义返回值 `[[nodiscard]]`。函数 ≤120 行，lambda ≤10 行；通常 ≤2 参数，复杂边界最多 3。领域 request/options 必须有真实语义与生命周期，不能靠大参数包隐藏耦合。
- 每个公共 API 写清输入 owned/borrowed、输出/错误、取消、半关闭、最终关闭者和 executor。遵守 LF，Windows 跟踪路径纯大小写改名使用两步 `git mv`；不凭 Windows include 成功代替 Linux 大小写验证。
- 协程不得同步 DNS、阻塞 socket、sleep、future.get/wait、忙等或使用阻塞 mutex。挂起后重新审查引用/迭代器/裸指针；detached 不引用会过期的 session 资源。新增 detached 或 PMR 变更对照 `docs/ARCHITECTURE.md` 并运行 `scripts/audit_detached.sh`。
- 保留 L1 进程/L2 worker/L3 session/L4 独立操作的必要生命周期分层；以 Diagnose 的稳定 facade、应用拥有 backend、异步前拥有型快照和有序 drain/stop/close 为参考。不能把跨生命周期层次本身当坏设计。
- 日志/诊断失败只属于观察层，不改变业务成功或错误合同。错误分类按真实 enum/category 核实，例如历史 `prism.protocol:18` 是 `Preview::Error::IoError`，不能仅凭整数改写成 ConnectionRefused。

## 5. 测试组织和测试质量的追加硬要求

1. `tests/Preview/` 全部项目自有目录、文件和标识符 PascalCase；文件名短、语义明确、不冲突，不用无意义序号。`CMakeLists.txt`、GoogleTest 和外部 wire/config/API 名称按生态规范保留。
2. 测试目录及 target 必须逐用例映射当前 Preview 的真实被测 API 与 owner。TaskRegistry/cancel/drain 归 Lifecycle，装配归 Composition，配置归 Application/Configuration；没有生产 Coroutine/coro 模块就不能保留历史测试模块。单协议 codec/session 归对应 Protocols leaf，Common 只覆盖真实 Common；只有实际跨模块场景才进 Integration，并按场景/协议细分。实验归 `tests/Experiments`。
3. `TEST`/`TEST_F`/参数化正文和测试实现放 CPP，每个测试 CPP ≤800 物理行；不建立一测试一组 `Foo.hpp/Foo.cpp` 声明实现配对。多个 CPP 真正共同消费的模块封装/构造器/拥有型 fixture 可共享 HPP，HPP 同样 ≤800；列出实际消费者，不用假 include 凑数，不搬单个巨型测试正文进头。
4. 测试同样遵守中文 Doxygen、PascalCase、尾随返回、函数120/lambda10/参数2或复杂3。官方 callback ABI 例外精确到接口，不豁免整个文件；GoogleTest 宏本身不豁免测试体长度。
5. 普通行为用 GoogleTest 精确断言输入、输出、错误与释放；真实 client/server、interop、stress、benchmark 保留真实进程和测量边界，不把一段成功文本当行为通过。
6. 异步 fixture 使用 `co_spawn + io_context.run()`，完整等待自身任务、半关闭、最终释放。不得用 `run_for`/`poll`、过早 `io_context.stop()` 或丢弃异常绕过任务退栈。回调/functor 的生命周期按实际 co_spawn 重载推导，不能把所有临时 lambda 一律误判 UAF。
7. 迁移前后核对用例名称多重集合、重复数、disabled、参数化展开、断言、fixture 与关闭顺序。原基线有 **2907 个源码 GoogleTest 宏身份**，不是 CTest 数；新增用例与迁出旧版/实验的覆盖分别对账，不能丢掉原覆盖。
8. 不删失败用例、不加 skip、不缩 payload/并发/rounds、不扩大错误候选、不松 assert、不关 quota/auth、不通过 retry/sleep、延长 timeout 或多发请求凑通过。新缺陷应保留真实 red/green；无法在当前快照取得历史 red 的，明确证据边界，不回退脏树伪造红灯。
9. 子代理按模块独占；根 CMake、跨模块引用、共享 TestSupport/中立合同、门禁脚本与最终清理由主会话串行集成。所有新测试结构必须重新配置、编译并实际运行后才签收。

## 6. 当前断点：必须从这里接续，不能沿旧交接重复派卡

证据目录统一简称 `E`：

`I:/code/Prism/.superpowers/sdd/2026-10-03-preview-no-compat-execution/task-4-evidence/`

下列数字来自本次核验或已核读的实际历史文件；“历史通过”不表示本次又运行过测试。

| 对象 | 2026-10-09 本次核验结果 | 接管动作及证明边界 |
| --- | --- | --- |
| Git/工作树 | HEAD 与上述一致，工作树大量 dirty/untracked，不能由 HEAD 描述全部成果 | 保存当前差异清单和 hash，不清空、不推倒重做 |
| 当前冻结输入 | `E/coordinator-9-asio-all-build-source.json` 在 08:05:58 冻结 1263 文件；本次逐文件重算为 missing=0、drift=0 | 核验后可复用其对应已完成构建记录；新改动另登记，不能继续标原快照 |
| ABI/线程后端 | 根 `CMakeLists.txt` 的 `if(MINGW)` 给 `BoostSystemHeaderOnly` 传 `BOOST_ASIO_HAS_PTHREADS=1` | 原问题是不同 TU/include order 的 Asio POSIX/Windows thread 后端混用。此 CMake 输入变化建立新编译版本，旧 binary/runtime/perf 不覆盖它 |
| 417 目标重建 | `E/coordinator-9-asio-all-build.json` 为 ExpectedTargets=417、Completed=204、Failed=0；最后完成 `NativeQuicLoopbackOwnershipTest`，09:19:41；剩余213无完成记录 | 第205个 `NativeTlsTest` 开始后中断，不能算 pass，也没有证据算源代码 fail。核 target/依赖/实际产物后续建剩余及漂移项；保存中断日志，不覆盖成一次完整 pass |
| 进程/会话 | 两引用主会话显示 idle/中断；09:59:35 的宿主检查未发现匹配 PrismPreview/compiler/make/ctest/gdb/mihomo/sing-box 的进程 | 再查活跃写者和进程。不把 `coordinator-9-progress.md` 顶部 running、旧 session19407 当当前运行事实 |
| 当前磁盘 Main | SHA256=`35A2C3925F0E0E0EFB4F2707D3FD64B26B9021A1DE82FD74D3E272DAB7A54655` | 仍是新 ABI 构建前的 EXE；必须重建 `PrismPreview` 并取新 hash，不能拿这个 EXE验新设置 |
| 配置模板/副本 | 两者 SHA256 均为 `C245C56845ACC08F415F14CB372F1FABE54F541241E914880A0BE536D80E3501` | 运行每次另核实际配置及动态测试配置，不输出秘密内容 |
| 当前 CMake/TaskRegistry | 根CMake SHA256=`C12D94CA78649F12D907835E95B51E4759B86A63B48C5A5A6A2A3F52DEF75243`；TaskRegistry SHA256=`F369035286685D92FFE4214B89F5C91DFA80D5D503CB4F71A47259FD90325BB1` | 它们是当前版本定位点，不是最终验收结论 |
| 新 ABI 已有 focused | `E/coordinator-9-asio-app-32-green.json`、`E/coordinator-9-asio-app-32-green.xml`、`E/coordinator-9-asio-app-32-green.log` 记录32/32、exit0；同场景100轮/六协议合计600次start-stop记录exit0 | `E/coordinator-9-asio-backend-100-repeat.json`、`E/coordinator-9-asio-backend-100-repeat.log` 对应精确EXE和原输入；可保留该局部证明，不能推广到全部417目标/所有Main请求 |
| 生产源码数量 | 本次盘点640个HPP、0个CPP、0个HPP超过600行 | 只证明此数量与长度层；`E/coordinator-9-asio-epoch-contracts.log`、`E/coordinator-9-asio-epoch-owners.log` 另有 contract640/1187消费者/612布局、G7 666/666历史执行输出 |
| 测试布局数量 | 本次454个CPP、76个HPP，共530个C++源文件；CPP/HPP均无超过800行 | 不代表共享HPP、命名、owner及全部风格已验收 |
| 测试风格未收口 | `E/coordinator-9-asio-epoch-test-style.json`、`E/coordinator-9-asio-epoch-test-style.log`：11个长函数、317个长lambda、11个普通宽参数，共339记录，parseErrors=0，精确foreign ABI=4 | 这些源与当前冻结版本一致。按实际缺陷/模块拆卡，不将parse0称为style通过 |
| CTest discovery | `coordinator-9-current-discovery.json` 记录4915注册；台账记录25 disabled、重复名0 | 只是旧时点登记，不是4915已运行。新ABI最终布局需重新 discovery/核唯一性/全量运行 |
| 旧target清理 | 23退役EXE历史已清；`coordinator-9-retired-objects-cleanup.json` 又记录23旧.dir/登记、466文件已清、remaining0 | 不再把这批对象清理写成未做；新残留逐项核，不重复删除有效目标 |
| Linux | 上一会话未获得可用WSL发行版/容器/既有SSH验收环境，没有Linux build通过证据 | 接管时只读重查可用环境；不擅装工具、改SSH/全局配置或push触发CI。缺口保留为外部阻碍 |

417 队列的精确目标来自 `E/coordinator-9-asio-all-build-targets.json`，当前构建脚本为 `E/coordinator-9-build-current-targets.ps1`。先读脚本的参数、日志覆盖行为及目标来源，再制定续跑清单；不要从旧 `.obj.d` 推导已退役目标。旧批次曾有5个 NoRule ghost：`ApplicationCarrierTest`、`ApplicationProtocolTest`、`ApplicationValidationTest`、`TaskLifecycleConcurrency`、`TaskLifecycleSession`，应与真正 source compiler error 分开。

### 已做的实质工作及其版本边界

- 不要重新派旧交接首卡：SOCKS5 value/shared owner、Recognition 缺正式声明、Session Delivery 错型、Restls header-only ODR 等已有后续实施/局部实际验收。对当前残留按最新编译日志判定，不凭23:10旧缺陷重复改。
- Mux 关闭时 registry/handle 退场后重复 Close/Reset/Shutdown 崩溃已有修复及回归。旧6个失败曾复验6/6，不能当成整个Mux128已在当前版本重跑。
- TaskRegistry 历史集合全复制的 O(n²) 问题已引入 `Preview/Lifecycle/TaskIdSet.hpp` 的不可变AVL路径复制；另修了max ID释放后的自动ID误拒绝。45组Mux矩阵、32768 stream wrap/下一ID65537曾在相应源码版本通过。不要删除该工作或再次派“从零实现TaskIdSet”。
- 当前 TaskIdSet 原90组成本比较存在完整证据 `coordinator-9-final-task-id-90-validation.json`：90rows/45pairs/9groups，6N操作、3N successful CAS、相同paired trace、完整local history/retire、errors0，7输入hash匹配。该运行在新ABI设置前；allocatedBytes是累计分配，45行PeakAvailable=no不能当0驻留内存，primitive成本不能当Main吞吐收益。
- Recognition 默认1000/7/10000曾自然exit0；owner270仍是单独验收，不能合并。Transfer原45组合/105lane、每lane256MiB/64KiB/4096block、双端hash、五轮曾通过；scatter4lane高分配不能包装成性能改善。后续源和ABI变化须按对应版本重验。
- 35A Main曾验证Provider Application18场景、Hysteria2三次、TUIC20轮×7模式=140个client启动/完成且无坏退出。140不是Hys/TUIC的CTest数量。Provider harness主动回收Main只证明相应请求/认证/association，不能冒充Main优雅停机；QUIC自然drain证据另查。新ABI Main尚无这些整体验收。
- 旧全量4896注册/25disabled/4871参与、23失败或未运行是历史失败快照；新布局曾有135 scoped通过，其中39属于旧版AnyTLS helper归位，不能当Preview135或当前全量。
- 旧独立互操作60项为54pass/6blocked/0failed、exit2。六缺口为Reality/Restls两个方向共4、ShadowTLS owning TLS client1、NativeTLS独立wire/vector入口1。逐项找原因和可实现验证路径，不能把blocked/exit2改写pass，也不能以独立矩阵代替Main全部carrier/inner-protocol。
- 生产独立头640、严格双TU ODR的637普通头+3独立CXX owner，以及CMake五边negative/restore已有准备文件；**准备不等于运行通过**。见 `coordinator-9-check-standalone-headers.ps1`、`coordinator-9-strict-odr-input.json`、`coordinator-9-cmake-negative-input.json`。逐头独立语法与all-include双TU互不替代；不能用allow-multiple-definition掩盖问题。
- A–F审计原 `coordinator-9-audit.*` 分类曾误判，后由 `E/coordinator-9-docs-review.md`、`E/coordinator-9-docs-review.json` 修正。其报告有A10/B0/C27/D1/E24/F14，D是C子集、F在生产树外；旧639与新640分母不同，safe-direct-delete=0。这些是现有报告的主张，主会话要逐证据复核，不凭数字签收或执行删除。

### 必须接走的具体未验补丁和独立审查发现

下面来自coordinator-9台账及D9-24/D9-26复核，不能遗漏在“继续风格整改”一句话里。它们要先读当前源和caller再裁定；不把报告中的静态风险直接写成已经复现的运行故障。

- **Trojan `ConnectAcceptEcho`**：旧源在原60秒预算下真实timeout、CTest exit8，原因记录指向保存 `co_spawn(..., use_awaitable)` 结果而没有实际启动server；P31/P32已改eager启动/完成链路，但当前版本的同用例green仍须Root确认。保留原60秒和原payload/断言，先复验同一case，再扩到ConnSession15、DgramSession7及ConnErrorMatrix5的原身份集合。
- **F29三协议纵向集成**：`tests/Preview/Integration/Session/Vless/`、`Trojan/`、`Vmess/` 六个TCP/UDP E2E CPP共34个原身份。D9-26指出TCP start/dial/no-proxy等提前返回可能跳过 `Stop*TcpEcho`/Done消费；Trojan/VMess UDP `ProbeError` 分支也可能跳过对应Stop。这是报告确认的静态cleanup/control-flow缺口，尚无实际runtime leak结论，优先核实并补足失败路径的等待与释放。
- **F29首异常收口**：六个 `Stop*Echo` 在close→await Done后rethrow首异常，可能跳过后面的父 `Listener.Shutdown()`。保留首异常同时保证父子都drain；不得简单吞异常或stop IOC获得通过。accepted TCP socket靠coroutine frame内RAII析构关闭的观察，只是待核合同风险，不等于socket未释放，也不要求机械加重复close。
- **R29 callback fixture**：`tests/Preview/Transport/ReliableCallbackTest.cpp` 的第二条 `std::thread` 创建失败后，第一条joinable线程的rollback；completion与watchdog从不同executor reset同一 `HandlerWork` 的串行化/最终owner。D9-26将其列为既有静态风险/未运行假设，需按真实路径核实；保留3个case、`Calls==1`、首错误、HandlerThread/SocketThread、payload/timeout/cancel断言。
- 上述所需公共 `tests/TestSupport/Fixtures/RuntimeTestHelpers.hpp` 改动由Root独占集成；模块代理不能顺手改共享层。正常路径先前已补拥有型echo owner/Done，不再重复报旧“所有路径都未等待”的结论。

## 7. 原 Task1–9 与文档 D1–D5 全部继承

原77目录分母固定，新owner另列，不能用历史“20已完成/48部分/8未完成/1删除”换算当前完成百分比。每个叶模块要有真实公开接口、不变量、生产消费者、CMake/tests、已验层级和残余责任。已正确完成的部分保留并记录，无需为了“每个目录都改”制造改动。

| 原任务 | 必须闭合的责任与验收 |
| --- | --- |
| Task1 Boundary packet交接 | 拒绝/unknown CID/预算/closed/draining后fallback保留完整payload、CID、peer、sequence；接受才由最终handler消费；borrow→consume边界唯一，无旧按值overload |
| Task2 Application事务 | 所有fallible启动路径一致逆序回滚；SessionServices/Mux无自持有环；成功Stop、失败profile、child drain后owner真释放；不靠临停清空回调掩盖设计环 |
| Task3 真实Provider | Hysteria2/TUIC/SS2022/SOCKS5真实配置Prepare与能力校验、typed factory/active binding/唯一关闭；Application消费binding，bool/空owner/搬文件不算完成；generation、重复Bind、失败回滚与真实监听正负认证 |
| Task4 协议运行态 | AnyTLS frame/stream、VLESS XUDP association、Mux/SingMux root/child/writer/lease、各UDP服务归协议owner；中心Composition运行态入口退役；真实bytes、partial I/O、取消/FIN、MaxStreams=1、计数归零与exactly-once |
| Task5 唯一typed handoff | move-only正式accept outcome唯一交接target/account/transport/PostDial；删除旧result/context回填及Materialize/Synchronize回退；FacadeCarrier等纯合同中立化；认证拒绝不可产出可转发plane |
| Task6 消费者/目录收尾 | Settings、Runtime/Front、旧Account/Coroutine registry、旧Auth Check、Composition/Api第二入口退出；Net/Outbound/Route、ProbeDefense、Scheduler、统计明确正式owner；实验不冒充已部署，迁移保有效行为覆盖 |
| Task7 真实请求与性能 | TUIC连续handshake/close稳定性；所有代理/carrier当前source/config/exe上的认证正负、完整payload、cancel/FIN/drain/清理；Registry/DNS/CID/SNI/mux/account/I/O等同输入对照与生产采纳门禁；Linux证据或明确阻碍 |
| Task8 最终验收 | 无兼容层/依赖/600行/参数/ODR/source-owner/配置/build/focused/全量/真实Main/外部互操作/性能各有最终版本证据；独立broad review后修阻断，最终文档和资源清理 |
| Task9 测试追加 | 全tests/Preview按真实模块、PascalCase、CPP≤800与真共享HPP组织；old→new source/target/CLI与用例多重集合对账；新构建/运行证明及精确退役产物清理；不替代Task4–8 |

D1：`Preview/README.md`、`docs/ARCHITECTURE.md` 的真实启动/请求、owner、executor和关闭合同。D2：当前 `Preview/Account/README.md`、Diagnose模块README，旧Account路径仅历史导航；不能用历史387例描述当前。D3：根README、`docs/index.md`、五篇tutorial的实际CLI/config/secret字段与用户操作，不写未接线能力或虚假服务安装。D4：现有计划/状态/台账及dated历史导航，历史原结果不倒填。D5：最终所有文档delta、本地链接/锚点/字段/命令、代码片段与最终source/binary hash一致性。仅修一个broken link不算D5完成。

## 8. 先生成计划和明确 ToDoList，再立即按依赖执行

第一阶段完成上下文和实时盘点后，在现有主计划/当前状态/进度入口建立一份可持续更新的完整执行计划。不要只贴本prompt的概括，也不要另造一套互相冲突的账本。为本次续接划定唯一当前状态入口，保留原时间快照和证据。

计划至少包含：

- **需求覆盖表**：用户要求 → 原Task/D卡/审计阶段 → 本次卡ID → owner/文件与target → 当前证据/残缺 → 完成标准，任何要求不能悬空。
- **明确ToDoList**：每项写唯一ID、可观察目标、具体当前文件/真实符号/调用者、允许和禁止写路径、先决依赖、并行/互斥关系、实施步骤、测试及完整命令、预期结果、source/config/exe证据、资源清理、后继卡。
- **状态分级**：未开始 / 正在实现 / 已改待编译 / 已编待测试 / focused已验 / 待真实请求或性能 / 主会话已验收 / 外部阻碍 / 等阶段二批准。不是所有状态都简写Done。
- **四队列调度表**：实际agent/model/effort、当前卡、独占写路径、依赖冻结、最近真实delta/完成通知、验收队列与下一独立卡。
- **分层验收矩阵**：源码静态、configure、compile/link、focused、全量、真实Main、第三方互操作、性能、Linux分别记录，不互相替代。
- **完成判定和阻碍处理**：明确哪些因环境暂缺，哪些仍是实现缺陷，哪些仅为未授权阶段二。只对确实需要的新授权提出具体可审查请求，其余继续。

以下为最低覆盖的待办骨架。把它展开为当前精确任务卡；历史已验项经版本核查可标已完成并挂证据，禁止无理由从零重做。

- [ ] H01：读两会话与全部必读文件；导出需求覆盖和冲突裁定，确认唯一新主及旧写者/进程状态。
- [ ] H02：记录当前Git差异、源/配置/构建设置/EXE清单；逐文件比对1263输入冻结，列source drift和ABI版本。
- [ ] H03：核实际模型和工具槽位，启动最多四个 `gpt-5.6-luna/max` 模块代理，记录真实派发设置与独占范围。
- [ ] B01：重建计划417与实际当前target图对账；承认204完成的精确范围，补NativeTlsTest及其余无完成记录目标，剔除有证据的退役ghost；修复实际失败并保原失败日志。
- [ ] B02：确认所有产生Asio代码的受影响活跃target继承统一MinGW宏；旧记录551个活跃target需按当前图核对，不能把417测试/入口集合当整个依赖集合。宏传播与实际重编分别记录；最终全量CTest/interop/perf会消费、但不在417清单中的受影响目标，也须补齐当前编译/链接证据。
- [ ] B03：单独确认新ABI `PrismPreview`编译/链接exit0、源码/配置/EXE hash；后续Main场景只接受该版本。
- [ ] S01：按 `coordinator-9-asio-epoch-test-style.json` 和 `coordinator-9-docs-review.md` 的D9-28精确记录收口11函数/317lambda/11参数；逐协议/真实模块独占卡，无机械大波替换。
- [ ] S02：核测试模块映射、PascalCase、CPP/HPP行数、共享HPP真实多CPP消费者；清掉伪头源配对和历史分类，保owner/fixture/关闭顺序。
- [ ] S03：新旧source/target/CLI/测试身份多重集合对账，包括2907原宏、参数化/disabled/旧版与实验迁出；每次改源都登记重编复验。
- [ ] Q01：审查已改未验的Ws、Trojan/SOCKS5、InteropL4/ShadowTLS、Runtime/Transport/Application等当前delta；实际callee/caller、namespace、所有权和多TU链接按目标验证，不凭AST签收。
- [ ] Q02：重验Mux真实root/child/writer、失败唤醒、短传输不得complete、线程部分创建失败回滚、取消/FIN/drain/weak/counter及ID wrap；原45组/32768输入保留。
- [ ] Q03：按原Task1–6与77目录逐条核真实生产调用、typed binding/plane、依赖与唯一close；只修当前确证残缺，不把旧源码位置当当前缺陷。
- [ ] Q04：逐项接收上文Trojan Echo、F29提前返回/ProbeError/首异常、R29线程创建rollback及work guard owner审查，区分补丁待验、确认静态缺口与待复现风险；保持原身份/超时/错误/关闭断言。
- [ ] G01：当前production/test风格、no-compat、include方向、source-owner、600/800及测试边界门禁；修真实失败，官方ABI仅精确例外。
- [ ] G02：执行当前640头独立闭包、严格双TU ODR及3个CXX owner各自验证；执行CMake target-graph/exact-case/standalone与五边negative/restore，串行保证恢复真实配置。
- [ ] T01：当前布局重新CTest discovery，核重复名、disabled、命令指向和真实EXE路径；按风险完成focused，读取实际XML/exit。
- [ ] T02：在最终对应源码和编译设置上完整运行全量；单列disabled/失败/未运行，修阻断后补受影响验证。历史全量+后续局部green不能拼成一次当前全量green。
- [ ] I01：当前Main Provider Application18场景，完整TCP/UDP字节/hash、正负凭据、拒绝无egress、association退出与资源证据。
- [ ] I02：当前Main Hysteria2三次、TUIC20轮×7原模式和重复Mihomo互操作；保同peer重连、auth-close之后pending、payload分段、FIN/EOF、Operations drain和自然退出，不加sleep/retry。
- [ ] I03：覆盖剩余Main carrier/inner-protocol与Operations/XUDP等真实装配；独立60矩阵六blocked逐项补环境/runner或列精确外部阻碍，不藏缺口。
- [ ] P01：新ABI与最终相关源码复验TaskIdSet90、Mux45/wrap、Transfer45，核正确性/测量边界/原始分配和内存口径。
- [ ] P02：Recognition configured默认输入与owner270（CID/SNI/Account、8/64/1024、1/2/4、五轮AB/BA）分别完成；合规修拆分不丢正式声明/导出。
- [ ] P03：SessionRegistry三模型270、真实Listener/Operations Cancel/Drain与生命周期合同；采样线程异常/count_down、End发布、FailedErrorHook race、部分线程创建stop/join正确，不把validate-only当完整矩阵。
- [ ] P04：DnsCache同trace ABC540、DnsCoalescer15和真实Resolver/eviction语义；ProtocolTransferBench默认30及chunk五轮AB/BA；配置/TokenBucket/Mailbox等原7B逐项核证据并补缺。
- [ ] A01：严格A–F阶段一对当前全Preview逐项六列证据复核、总表/子集/批次；独立审查旧分类修正及639→640变化，交可审批结论，未批准不执行阶段二。
- [ ] D01：D1–D4随实施同步；D5最终文档全量delta、链接/锚点/CLI/config/片段/状态/hash复核，历史结果不倒填。
- [ ] L01：只读核当前可用Linux环境，完成获授权的Linux验证；确实不可用则保留具体阻碍及可执行后续路径，不假报通过。
- [ ] C01：核原23EXE及23对象目录清理证据，处理新增精确退役残留与本任务运行资源；保持build/tests与依赖有效产物。
- [ ] F01：主会话按最后变更进行跨模块broad review和最终源/配置/EXE/测试/性能/文档证据一致性核对；逐需求签收，残余实施/阻断不得隐藏。

风格卡可优先复用D9-28的准确入口：Composition/Carrier的Reality、Foundation/Memory生命周期、Integration的Hysteria2/TUIC/SS2022进程入口、Protocols/Restls/Native/Http3/SS2022/Vless/Vmess/Xhttp及其它有长lambda的协议leaf。具体位置须重查；不能只派“把317减到0”。共享头改动交主会话冻结/调度，CPP已编后再改必须重新编验。

## 9. 四子代理的具体调度与任务卡

默认队列：P=Protocols协议leaf；F=Performance及明确分配的Integration功能闭包；R=Runtime/Application/Boundary/Composition/其它核心测试按真实owner逐卡；D=文档与生产只读A–F审计。队列是调度角色，不授权跨模块随意写。主会话统一协调共享文件，必要时重新分配独占范围并通知交接。

实际派发必须设置 `model="gpt-5.6-luna"`、`reasoning_effort="max"`。检查当前工具支持的fork方式；若完整历史fork不能覆盖模型，使用 `fork_turns="none"` 或支持覆盖的必要轮次，并把必需上下文和所有约束写进卡。旧会话曾错误地继承6.1子代理，后才核实际记录更正；不能再只在prompt声称Luna。当前工具若不支持指定模型，准确报告限制，不偷偷换模型或降effort；主会话先继续不依赖派发的工作。

每次派发把以下字段全部填实，不能交空模板或一句“禁止敷衍”：

```text
卡ID、角色、模型/effort、对应原Task/用户要求。
当前事实：已验版本/未验delta；具体错误原文或待满足合同；source/target/证据路径。
目标：用具体输入→输出/错误/资源释放定义，能被独立验证或否决。
唯一写范围：精确模块/文件/完整功能闭包；禁止写路径；共享依赖及冻结状态。
先读内容：AGENTS/CLAUDE、本完整交接、Luna要求、本卡真实callee/caller及owner声明。
输入/输出接口：准确类型/签名、所有权、executor、取消、半关闭与最终关闭者。
实施步骤：先CodeGraph/当前源查明→保留或补回归→完成正式owner/调用闭包→迁测试→给Root集成清单。
不可减弱：本卡原用例、输入规模/trace/rounds、错误category、认证/配额、bytes/hash、FIN/drain/weak/counter等具体断言。
质量约束：生产HPP600/无CPP；测试CPP800/真共享HPP；函数120/lambda10/参数2或复杂3；PascalCase/中文Doxygen/尾随返回；无兼容/文本拼接/万能context。
禁止动作：跨模块抢写、commit/push/amend、Python、reset/checkout/clean、新build、自行编跑/清理/改系统配置、再派代理、减测/skip/sleep/retry/延timeout。
允许检查：限定静态检查的命令与范围，给真实exit；编译/CTest/真实进程统一申请Root验证，不自行执行。
交付：准确diff含untracked文件、行数和共享HPP消费者、工具生成hash、保留断言说明、应跑target/case与期待、未运行层级、原始证据和资源状态。
完成通知：立即collaboration.send_message给Root，卡ID/实际delta/检查与exit/未运行/阻碍/active工具/下一独立项；随后简短final。
状态：实施完成只能报“已改待Root验收”；没有实现delta或新证据不能重复认领旧成果。
```

主会话收到通知后立即查真实diff、新文件、声明/调用者与CMake；检查owner/异常/取消/半关闭/最终关闭、强断言和源漂移，明确“签收/待编验/退回具体缺陷”。等待编验的代理可接其它无依赖卡；当前结果的依赖后继必须等对应验收。不要形成四队列一起等待的全局串行门。

连续报告同一Remaining而无delta/新证据时，检查active工具、卡边界与阻碍；中止无效循环，改派准确下一动作或由Root解决共享前置。复用上下文正确的代理，不为形式不断重启；不用的代理按工具实际生命周期释放/中断，不复活旧会话写者。

## 10. 生产空壳/未接线审计：完整保留用户专项合同

阶段一对生产源码、测试与CMake只读。基于真实Main/Startup/TCP/UDP/QUIC可达闭包检查全部Preview HPP，正常实现也计入覆盖分母；F另审实验残留。不能把CMake登记、一个bool、仅有测试或直接include零命中当生产装配证明。

| 类别 | 判定 |
| --- | --- |
| A 转发存根 | 整体只有pragma once和恰好一条同概念目标include，自有声明0 |
| B 空占位 | 只有include，无自有类型/函数/别名声明；不是“文件很短” |
| C 聚合 | include多个兄弟头、无自有实现；公共聚合有真实消费者可以合理存在 |
| D 漂移聚合 | 相对正式应导出契约漏新项或仍导出退役项；逐成员证明，不机械导出所有内部Detail |
| E 未接线实现 | 有真实实现却不在生产可达闭包，仅tests/Experiments或其它tests消费；零代码消费者单列，测试夹具用途单列；独立客户端API不自动等于服务端能力缺失 |
| F 移出生产的实验残留 | 原生产路径不存在，仅tests/Experiments有副本；核源和登记，不能把生产仍存在的文件算F |

每项六列必须齐全：

1. 精确相对路径和物理行数。
2. 自有类型/函数/别名数量；宏、模板、条件编译不能被regex漏掉后误判为0。
3. 完整内部include列表。
4. 全仓消费者路径/位置，标注Preview生产、Preview CMake source、tests、tests/Experiments、docs；区分直接include、聚合/转发可达和真实运行闭包。
5. CMake具体文件/行及所属target_sources/add_library；无登记明确写无。
6. E类精确候选缺失装配点的符号/路径、需求依据、接线/实验/退役理由；候选不能写成已部署能力。

逐项建议保留/合并迁引用后删除/补实现/修聚合/接生产/移实验/退役。每个建议删除项给全仓include/CMake/docs硬引用证据；仍有引用只能列“先迁引用再复核”，不能塞进可立即安全删除子集。

交付完整总表 `文件 | A-F | 行数 | 自有声明数 | 生产消费者数 | 测试消费者数 | 结论`、分类计数、正常实现及分母、可安全删除/需接线/约定漂移子集、相互独立的建议批次；每批列全部改动/删除/迁移消费者/CMake文件。D等重叠标签不重复加总，F不混入生产HPP分母。

阶段二必须等用户明确批准具体阶段一结论/批次。获批后先迁真实消费者include到唯一目标、修聚合、同步全部CMake，再删已无消费者的旧文件；不得把空壳清理与未接线功能实现混批。每批执行 `scripts/check_common_headers.ps1`、`scripts/check_preview_contracts.ps1`、CMake target-graph/exact-case/standalone断言、相关构建/focused；给删除后零引用证据、真实exit、source/binary hash和资源清理。无证据不能宣称废弃，不能批量sed后不核消费者。

## 11. 验收和性能证据必须达到的质量

- 每条结果关联当前源快照（含untracked和dirty）、编译选项/ABI、配置、EXE SHA256、完整命令、上海时间、实际exit、raw stdout/stderr、XML/JSON和owned清理。hash由工具生成，禁止手填假值或借旧版本。
- 静态语法/AST、源码结构、配置、compile/link、focused、全量、真实listener/Main、第三方互操作、性能是独立层。端口ready、一个HTTP200、无编译错误、fixture内factory返回值，都不能代替完整请求/关闭验收。
- CTest XML按真正testcase统计，不把failure断言节点算用例；保留原suite/name，不重复拼前缀；分别统计失败/error/skip/disabled。自然退出与超时后强制回收分开，不能将手工停进程写成优雅停机。
- 实际请求覆盖认证正负、完整payload和双端hash、partial read/write、error-with-bytes、EOF/FIN/半关闭、取消、配额、parent/child drain、weak owner释放、连接/流计数归零、资源exactly-once和无egress拒绝。测试必须真正调用RootSession/Listener/Main需要证明的那层。
- 性能先正确性，再同输入同构建对照，至少五轮交错AB/BA，1/2/4并发；记录trace/hash、热身/采样窗口、吞吐、p50/p95/p99、分配次数/字节、RSS/commit峰值、错误、自然退出与cleanup。计时口径改变明确说明，不能用旧不可恢复口径声称提速。
- Registry/DNS等实验必须证明真实Listener/Operations Cancel/Drain、Resolver/eviction等语义等价才能替换生产。收益不足或噪声内可明确保留生产方案；“benchmark target pass”不等于优化成立。没有采集峰值就写不可用，不写0。
- source或共享ABI变动后失效的是相应依赖闭包的验收；保留旧证据，不倒填、不混版本。稳定且版本一致的局部证据可以有边界地复用；最终整体验收必须有完整覆盖，不无理由反复跑相同已通过检查拖延任务。
- 不修改门禁阈值或扩大排除范围来掩盖真实违规；若parser误判合法默认参数、GoogleTest形状或第三方callback，先以精确正负控制证明修正规则，不让无关宽参数/长函数漏检，再由Root集成并重跑。
- 更新实际缺陷时同步 `logs/issues.md` 相关索引；运行日志不可提交。已有其它会话审计结论逐项核源，不把所有结构警告统称bug，不把未复现风险说成已证实崩溃。

## 12. 新会话第一份输出、持续执行与最终交付

完成初始核验后，第一份实质输出必须给：

1. 对两会话和文件的读取覆盖，以及哪些历史证据当前不可读/不可复用。
2. 当前版本、构建断点、主要已完成成果、已改未验与明确失败/阻碍，避免虚构完成百分比。
3. 完整计划和可追踪ToDoList，包含上述H/B/S/Q/G/T/I/P/A/D/L/C/F覆盖、依赖/并发安排及每项验收。
4. 四子代理实际模型/effort/角色/第一张准确任务卡、Root的构建与验收队列；工具受限则说明真实限制。
5. 立即继续执行已授权的首批动作；不要以“计划写好了，要不要开始”结束。需要阶段二批准时先完成可审查结论，单列请求，并继续其它无依赖授权工作。

持续反馈真实新进展，收到子代理完成通知及时处理。源冻结、构建、测量和等待都按依赖协调，不全局空等；已经授权的事项不反复问。

最终中文交付必须列：各原Task/新增要求的签收表；准确文件/模块delta和为何改；每层当前验证、原始证据与版本；完整测试身份/目录映射、文档与旧产物清理；模型并发与子代理质量复核；剩余外部阻碍/未批准阶段二及其影响。只有原已授权实施、阻断缺陷和所需验收全部闭合，才可以说整个重构完成。若Linux/外部互操作或明确审批仍缺，按实质边界报告，不能把“已做完可做部分”改写成“全量完成”。

现在开始：先读上下文和实时盘点，生成具体计划与ToDoList，然后按四个独立模块队列推进；保留已经取得的成果，以当前代码和可复核证据逐项收口。
