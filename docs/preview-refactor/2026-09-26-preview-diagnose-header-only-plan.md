'# Preview Diagnose 日志模块重构实施计划

> 文档状态说明（2026-10-05）：本文保留原版本的分析、计划或验收快照，文中的“当前”、完成标记、路径和测试数字均属于原记录时点。今天的 Preview 入口、已执行范围与剩余责任见[开发入口](../../Preview/README.md)和[当前执行状态](2026-10-03-preview-no-compat-status.md)。本轮不改写原始历史结果；旧任务提示词需先核对现行 AGENTS.md、无兼容层计划和真实源码，不能直接替代当前任务卡。

状态：PLANNED。本文档是执行规格，不代表源码已经修改或验证完成。

范围：Preview 生产代码、Preview 日志测试和 Preview CMake。生产 psm::diagnose 只作为底层 spdlog 适配对象审查，不把 Preview 业务模块耦合到生产业务 API。

## 1. 目标

默认人类日志保持旧项目格式，只显示时间、线程、级别和两个固定上下文前缀 [W<worker>]、[S<session>]。默认形式：

    [2026-09-24 21:22:38.414] [ 4416] [info] [W2][S183] session established, 127.0.0.1 -> 127.0.0.1

字段扩展能力存在但默认不显示；字段定义、类型约束和编码器集中在 Preview Diagnose 内部；业务模块只借用已有变量，不实现日志注册函数、格式化函数或日志插件基类。

## 2. 强制不变量

1. 命名空间使用 Preview::Diagnose；新增类、函数、变量、文件夹、文件名全部使用 PascalCase。
2. 新日志核心文件全部使用 .hpp，单文件不得超过 600 行；超过必须按真实职责拆分，禁止 include 片段拼装类体。
3. 不使用通用且易冲突的 Api.hpp、Context.hpp、Field.hpp、FieldRegistry.hpp、OutputMode.hpp、Sinks.hpp、Backend.hpp。
4. 默认输出不铺开 ProcessId、GenerationId、TaskId、OperationId、Protocol、Route、Stream 等扩展字段。
5. WorkerId 和 SessionId 是稳定编号，不是 worker 数量和 active session 数量。
6. Worker 创建时只绑定 WorkerId；Session 创建时从 WorkerContext 派生 SessionId。
7. 业务模块只调用通用 With(FieldKey, Value)，不得新增 RegisterLogFields、RegisterQuicFields、FormatLogField、CreateSessionLogContext 等日志函数。
8. 不使用虚拟字段基类、虚拟 formatter、std::any、std::function 或每条日志的 unordered_map。
9. 默认热路径不得遍历插件字段、查字段名称、调用插件 formatter、构造 JSON、重新生成 [W][S] 或加 Worker/Session 锁。
10. 异步队列不得保存业务裸指针或无生命周期保证的 std::string_view；提交边界必须生成安全快照。
11. Preview 业务代码不得公开或依赖任何 spdlog logger、sink、thread pool 类型。
12. 普通 debug/info 可丢弃但必须计数；Warn/Error/Critical 失败策略必须可测试。

## 3. 目标文件

Preview/Foundation/Utility/Diagnose/
    Facade.hpp
    ContextState.hpp
    FieldKey.hpp
    FieldCodec.hpp
    FieldCatalog.hpp
    PrefixCache.hpp
    RenderMode.hpp
    RuntimeOptions.hpp
    SubmissionReceipt.hpp

Preview/Foundation/Utility/Diagnose/Detail/
    SubmissionRecord.hpp
    ContextDecoder.hpp
    BackendBridge.hpp
    AsyncBackendState.hpp
    AsyncSubmission.hpp
    SinkSet.hpp
    BackendLifecycle.hpp

## 4. 文件职责

Facade.hpp：唯一业务日志入口，提供 Debug、Info、Access、Warn、Error、Critical 及 ContextState 重载，使用 compile-time format string，不包含 spdlog 公共类型。

ContextState.hpp：不可变、值语义、可派生 Context，提供 Empty 和模板 With，使用固定小容量 inline 字段包，With 不修改父 Context。

FieldKey.hpp：定义 FieldId、字段 key 和 Fields::Worker、Fields::Session、Fields::Route、Fields::Protocol、Fields::Stream，业务模块只借用这些变量。

FieldCodec.hpp：定义字段可编码 concept、FieldEncoder、EncodedFieldValue 和基础类型编码；字段格式化通过 Diagnose 内部静态定义或 traits 完成，不使用继承。

FieldCatalog.hpp：保存字段名称、FieldId、类型、可见性、顺序和敏感标志；初始化后冻结，热路径只读。Worker/Session 默认 HumanVisible，其他字段默认 StructuredOnly。

PrefixCache.hpp：只负责 [W]、[W][S] 缓存。WorkerContext 派生时生成 Worker 前缀，SessionContext 派生时生成最终前缀；提交不重新 snprintf 或 to_string。

RenderMode.hpp：定义 CompactHuman、HumanWithFields、Structured，默认 CompactHuman。

RuntimeOptions.hpp：只保存级别、目录、文件名、控制台、队列大小、轮转大小和轮转文件数；flush、overflow、fallback 留在 backend 内部。

SubmissionReceipt.hpp：定义 SubmissionStatus 和 SubmissionReceipt，不返回 spdlog 类型。

Detail/SubmissionRecord.hpp：保存等级、固定前缀、安全字段快照、消息信息和 sequence，业务模块不构造。

Detail/ContextDecoder.hpp：CompactHuman 只读取 PrefixCache；扩展模式才解码插件字段，并执行脱敏和长度限制。

Detail/BackendBridge.hpp：Facade 与 spdlog backend 的窄边界，只暴露 Preview Diagnose 类型。

Detail/AsyncBackendState.hpp：保存状态、配置、计数器和 queue 指标，不创建 sink。

Detail/AsyncSubmission.hpp：封装 async submit、overflow、drop 计数和高等级 fallback。

Detail/SinkSet.hpp：封装 rotating file sink、console sink、目录、轮转和 legacy 文件处理。

Detail/BackendLifecycle.hpp：封装 Initialize、Flush、Drain、Shutdown，明确幂等和失败返回，不能无限阻塞。

## 5. 上下文生命周期

RootContext 只由 Diagnose::ContextState::Empty 创建。WorkerId 由现有 Worker 或 Listener 分配，业务侧只派生 WorkerContext：Empty().With(Fields::Worker, WorkerId)。

SessionId 由现有 Session factory 分配，业务侧从 WorkerContext 派生 SessionContext：WorkerContext.With(Fields::Session, SessionId)。不得要求 Worker 创建时知道未来 SessionId，也不得让 Session 反向查询全局 Worker。

临时字段使用值派生：SessionContext.With(Fields::Route, RouteName)。业务模块不得提供 LogContext、RegisterFields 或 formatter 辅助函数。

同一 owner 内可传 ContextState 引用；跨协程、跨 worker、脱离 Session owner 时按值保存 Context。提交到异步 backend 前必须保证字符串和业务值生命周期安全。

## 6. 热路径

CompactHuman 提交只允许级别过滤、读取固定前缀缓存、复制少量固定值、调用 async submit、返回 SubmissionReceipt。

禁止字段目录遍历、动态字段名查找、插件 formatter、JSON、动态 map、每条日志生成 [W][S]、业务对象指针入队和 Worker/Session 锁。

扩展字段模式必须显式选择并单独基准测试，不能影响 CompactHuman 默认路径。

## 7. 依赖边界

业务模块允许包含 Facade.hpp、ContextState.hpp、FieldKey.hpp、FieldCatalog.hpp。业务模块禁止包含 Detail/AsyncBackendState.hpp、Detail/AsyncSubmission.hpp、Detail/SinkSet.hpp、Detail/BackendLifecycle.hpp 和任何 spdlog header。

Preview target closure 不得暴露生产 PrismStaticLibrary、include/prism 或 src/prism。若需要生产 spdlog backend，只能作为 Diagnose backend owner 的窄依赖并由 CMake boundary 记录。

## 8. 迁移映射

Preview/Foundation/Utility/Diagnose/Log.hpp -> Facade.hpp：迁移公共 facade。
Preview/Foundation/Utility/Diagnose/Context.hpp -> ContextState.hpp 和 PrefixCache.hpp：拆出派生上下文和固定前缀。
Preview/Foundation/Utility/Diagnose/Logger.hpp -> SubmissionReceipt.hpp、RuntimeOptions.hpp、Detail/BackendBridge.hpp：拆出值类型和 backend 边界。
旧 queue/thread/sink -> Detail/AsyncSubmission.hpp、Detail/SinkSet.hpp、Detail/BackendLifecycle.hpp：只保留一个 backend。

兼容期可以保留很薄的转发头，但只能 include 目标头和提供别名，不能保存实现，仍须少于 600 行。

## 9. 执行任务

### Task A：基线审计
只改文档和报告。确认 Git 状态；列出现有 Diagnose include、调用点、public symbol、配置 pattern、CMake target、依赖闭包和 spdlog 泄露点。完成条件是完整 symbol mapping。

### Task B：公共值类型和字段目录
写入 ContextState.hpp、FieldKey.hpp、FieldCodec.hpp、FieldCatalog.hpp、PrefixCache.hpp、RenderMode.hpp、RuntimeOptions.hpp、SubmissionReceipt.hpp。禁止修改 Preview/Runtime、Preview/Application、Preview/Protocols 和 src/prism。完成条件：With 不改父 Context；WorkerContext 不要求 SessionId；SessionContext 可派生；默认只有 [W][S]；覆盖父 Context、字段覆盖、类型约束和文本边界测试。

### Task C：解码和内部记录
写入 Detail/SubmissionRecord.hpp、Detail/ContextDecoder.hpp。完成 compact、extended、structured；compact 不调用插件 formatter；扩展字段脱敏、限长；异步记录不保存业务裸指针。

### Task D：spdlog backend
写入 Detail/BackendBridge.hpp、Detail/AsyncBackendState.hpp、Detail/AsyncSubmission.hpp、Detail/SinkSet.hpp、Detail/BackendLifecycle.hpp。完成单一 async backend、旧 pattern、overflow、drop、flush、rotation、fallback、shutdown；backend 测试覆盖初始化、重复初始化、配置不一致和资源释放。

### Task E：Facade 和调用迁移
写入 Facade.hpp 及实际需要迁移的 Preview/Application、Preview/Runtime、Preview/Composition、Preview/Ingress 文件。先接入 Application/Worker/Session 派生，再迁移 Session、MUX、QUIC。调用只使用 Fields 和已有变量；ownerless 旧调用必须明确迁移、保留或禁用，不得静默丢日志。

### Task F：CMake 集成
写入 Preview/CMakeLists.txt、Preview/CMake/PreviewBoundary.cmake、Preview/Application/CMakeLists.txt、tests/Preview/core/diagnose/CMakeLists.txt。每个 HPP 只登记到一个真实 target；Detail 不向业务 INTERFACE target 泄露；验证唯一 backend owner。

### Task G：测试和门禁
写入 tests/Preview/core/diagnose、tests/Preview/core/Application、tests/TestSupport/Preview。覆盖 Worker/Session 派生、父 Context 不变、默认 [W][S]、扩展字段默认隐藏、扩展模式、编译期约束、跨协程快照、drop、rotation、shutdown、脱敏和 spdlog 隔离。保留原始输出、性能 JSON 和失败证据。

## 10. 验收

统一使用 build，不创建新构建目录。执行代理先记录时间、Git 状态和配置。

    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build --config Release -j 16
    ctest --test-dir build -R PreviewDiagnose --output-on-failure -j 1
    ctest --test-dir build -R PreviewLogger --output-on-failure -j 1
    ctest --test-dir build -R G2Log --output-on-failure -j 1
    ctest --test-dir build -R PreviewApplication --output-on-failure -j 1
    git diff --check

如当前用户明确授权更高并发，执行代理必须记录实际并发，不得因并发改变测试范围。

## 11. 禁止事项

- 禁止业务模块日志注册函数、字段 formatter 和日志继承接口。
- 禁止 Preview 业务代码包含 spdlog。
- 禁止使用全局 MDC 作为 Session 主上下文。
- 禁止动态 map、每条日志生成 [W][S]、所有字段固定拼接或业务指针入队。
- 禁止用超过 600 行的单体 Logger.hpp 重新聚合实现。
- 禁止删除测试、降低断言、提交、push、reset 或回退无关改动。

## 12. 交付物

1. 文件级 diff 和每个目标文件职责。
2. Root -> Worker -> Session -> per-call Context 生命周期图。
3. 字段目录及类型、可见性、长度和脱敏策略。
4. Preview CMake target ownership 和依赖闭包报告。
5. 编译命令和完整结果。
6. Diagnose、Logger、Application CTest 结果。
7. 默认输出样例，确认只有 [W][S] 固定前缀。
8. CompactHuman 与扩展模式分开的热路径基准。
9. 失败时的测试输出、日志和进程清理记录。
10. 未完成或有争议项目标记 WAITING_FOR_VERIFICATION，不得宣称已完成。
## 13. 公共 API 契约

Facade 只提供两组函数：无上下文调用和 ContextState 调用。函数名使用 Debug、Info、Access、Warn、Error、Critical。format 参数必须使用 compile-time format string，禁止把 std::string 先拼成完整消息再提交。

ContextState 公开 Empty 和模板 With。With 必须返回新的 ContextState，不修改父值；相同 FieldKey 再次 With 时覆盖旧值，而不是生成重复字段。

业务代码只能提供已有变量，例如 WorkerId、SessionId、RouteName。业务代码不得保存 FieldId 全局注册状态，不得调用 backend Initialize、Drain、Shutdown。

SubmissionReceipt 只返回 Diagnose 自有状态和 sequence。业务代码必须决定普通日志是否忽略 Dropped；terminal 日志必须检查失败并记录失败路径。

## 14. FieldKey 和 Codec 契约

每一个 FieldKey 必须携带 ValueType 和 FieldId。With 在编译期约束 Value 与 ValueType；不允许通过 void pointer、std::any 或运行时字符串绕过类型检查。

Codec 必须区分整数、枚举、布尔、短文本和受限文本。文本编码必须规定最大长度、截断行为和敏感字段策略。任何截断都必须有测试。

Worker 与 Session Codec 只编码数字，不在每条日志中格式化字符串。PrefixCache 在派生时生成短前缀，CompactHuman 只读取缓存。

插件字段的 Codec 只能定义在 Diagnose 字段目录或 Diagnose traits 中。Preview Protocol、Runtime、Composition、Ingress 不得定义 formatter 函数或 formatter 类。

## 15. Context 生命周期和安全快照

RootContext 不包含 Worker 或 Session。WorkerContext 只在 WorkerId 已分配后派生。SessionContext 只在 SessionId 已分配后从 WorkerContext 派生。

每个 Session 必须拥有自己的 SessionContext 值，不能从全局 current context、MDC 或线程局部变量推导 session。

同 owner 的同步调用可以借用 const ContextState 引用；进入 async backend 前必须复制需要的 Worker、Session 和已选择的字段值。

如果 Context 包含 RouteName 等文本，必须明确是调用期间借用还是 capture 后拥有。异步线程不能保存指向 Session、配置字符串或临时 string_view 的裸指针。

Session 销毁后仍可能写入的 detached operation 必须持有 CapturedContext 值；禁止通过延长整个 Session 生命周期来掩盖快照设计错误。

## 16. Header-only 约束

公共 HPP 不得包含 spdlog 实现头。业务模块只看到 Facade、ContextState、FieldKey、FieldCatalog。

Detail backend HPP 如果必须包含 spdlog，只能由 Diagnose backend owner target 使用；不得通过 Preview 业务 INTERFACE target 传播。

所有非模板函数、inline 状态、静态局部和 backend 生命周期函数必须审查 ODR、初始化顺序和 shutdown 顺序。

若 header-only 方案导致 spdlog include 泄露、重复 thread pool、重复全局状态或编译时间异常，执行代理必须停止并提出单一 backend translation unit 方案，不得偷偷扩大依赖闭包。

## 17. 精确测试计划

新增 ContextStateTest：Empty 不输出前缀；WorkerContext 只输出 W；SessionContext 输出 W 和 S；父 Context 在 With 后不变；重复 FieldKey 覆盖旧值。

新增 FieldCodecTest：正确类型可编译；错误类型被 concept 拒绝；无符号、枚举、布尔、短文本、超长文本和敏感文本均有断言。

新增 ContextDecoderTest：CompactHuman 不遍历扩展字段；HumanWithFields 输出选择字段；Structured 输出字段快照；字段顺序稳定。

新增 ContextLifetimeTest：临时 With 字段在提交后不会读取悬空引用；跨协程复制后的 Context 在原 owner 释放后仍安全。

新增 DiagnoseFacadeTest：六个等级的格式参数、无上下文调用、带上下文调用、Filtered、Dropped、Stopped 和 sequence。

新增 AsyncBackendTest：初始化、重复初始化、冲突配置、目录失败、文件打开失败、queue capacity、rotation、flush、drain、shutdown 幂等。

新增 CompactPathBenchmark：只比较 CompactHuman；单独记录提交延迟、CPU、分配次数、queue high water。

新增 ExtendedPathBenchmark：单独测 HumanWithFields 和 Structured，不得把两种模式混成一个平均值。

所有日志内容测试必须扫描 password、token、secret、psk、authorization、private_key 等 canary，确认正式输出和 fallback 都不泄露。

## 18. 测试隔离和生命周期

每个 logger lifecycle 测试必须明确自己是否拥有 backend。一个进程内只能有一个有效 backend owner。

测试结束顺序必须是：停止业务 owner、停止提交、drain queue、确认 receipt、shutdown backend、确认 thread pool 和 sink 释放。

不允许测试先 shutdown 再在同一进程隐式重新 Initialize，除非该测试明确验证重启策略。默认策略是进程级初始化一次、关闭一次。

测试启动的进程、端口、日志目录和临时文件必须由测试自己清理；失败时保留 evidence 路径但不能留下运行进程。

## 19. CMake 精确要求

每个新 HPP 必须登记到一个明确 target。公共 HPP 登记到 PreviewFoundation 或对应 Diagnose interface target；Detail spdlog HPP 只登记到 backend owner。

不得把项目实现源通过 INTERFACE_SOURCES 注入多个下游 target。若以后新增 cpp，必须有唯一 STATIC 或 OBJECT owner。

PreviewBoundary 必须检查：业务 Preview target 不依赖 PrismStaticLibrary；业务 Preview include closure 不含 src/prism 和生产 include；唯一例外只允许 backend owner。

CMake 集成后必须生成 target closure 记录，说明每个 target 获得哪些 include、link 和 source。

## 20. 执行代理工作协议

每个代理开始先读取本计划、AGENTS.md、当前 Git 状态和自己任务的写入范围。未读取完成不得修改文件。

每个代理只能修改任务列出的文件；发现需要越界修改时先停止并报告，不得顺手修改调用方或 CMake。

每个代理完成后必须报告：修改文件、未修改文件、公开 symbol 变化、编译命令、测试命令、失败证据和清理结果。

任务之间必须按依赖执行：A 完成后才能 B；B 完成后才能 C；C 和 D 完成后才能 E；E 完成后才能 F 和 G；F 必须在最终构建前完成。

执行代理不得提交、push、reset、checkout 或回退其他人的改动。

## 21. 代码审查检查表

审查者逐文件检查：PascalCase 命名；include 自包含；namespace 自包含；单文件少于 600 行；无循环 include；无业务模块日志注册函数；无 spdlog 泄露；无动态 map 热路径；With 父值不可变；Worker/Session 创建顺序正确；Context snapshot 生命周期安全。

审查者必须搜索以下反模式：std::unordered_map、std::any、std::function、thread_local context、spdlog::default_logger、spdlog::logger、RegisterLogFields、FormatLogField、snprintf 每条日志、to_string 每条日志。

审查者必须确认默认输出只含固定 [W][S]，且扩展字段只有显式 RenderMode 才能出现。

## 22. 性能验收

CompactHuman 必须单独报告无字段和 W/S 上下文两组结果。不得用包含 Structured 字段的结果代表默认性能。

至少记录：平均提交耗时、p95、p99、每条日志分配次数、线程 CPU、queue high water、普通 drop 数和 terminal drop 数。

性能测试不得把文件 IO 时间和业务线程提交时间混在一个指标中；必须分别报告 submit、drain、flush。

任何新增锁、共享指针引用计数、字符串堆分配或字段遍历必须有基准对比和理由。

## 23. 失败处理和回滚

编译失败：停止当前任务，保留首个错误和 compile_commands 信息，不扩大修改范围。

CMake boundary 失败：撤回当前 CMake 改动，先修正 target ownership 设计，不允许绕过断言。

生命周期测试失败：禁止增加无限重试或延长全局对象生命周期；先确认 owner、drain barrier 和 shutdown 顺序。

性能回归：保留结果，区分默认 CompactHuman 和扩展模式，禁止通过删除字段测试掩盖回归。

发现业务模块出现日志注册函数或 spdlog include：立即停止迁移任务，退回 Facade/FieldCatalog 边界重新设计。

## 24. 最终交接

交接包必须包含最终目录树、symbol mapping、依赖图、字段目录、Context 生命周期图、CMake closure、编译输出、相关 CTest XML、性能 JSON、默认日志样例和清理报告。

任何未完成项目必须标记 WAITING_FOR_VERIFICATION；没有 fresh build、fresh test、fresh output 和清理证据，不得标记 VERIFIED。
