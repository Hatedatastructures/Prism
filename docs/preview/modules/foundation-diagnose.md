# Preview Foundation / Diagnose

Diagnose 提供类型化日志 facade、不可变上下文、字段目录、有界消息捕获和后台输出生命周期。详细合同集中在本页；[本地 README](../../../Preview/Foundation/Utility/Diagnose/README.md) 是短入口。

## 职责与边界

普通提交在调用线程完成级别/准入判断，并将格式、参数、上下文复制到固定槽；唯一 backend worker 消费同一记录队列，格式化、脱敏、渲染并写文件/可选控制台。日志失败作为观察结果和 backend 回执发布，不会回写已经完成的业务操作结果。

Diagnose 不拥有业务 Session，不保留调用者的消息/context 引用，也不负责协议取消、半关闭或连接最终关闭。异步队列拥有记录快照和 render epoch pin；它不 pin 业务 Session。Detail 是内部 owner 实现，业务代码应使用 facade、ContextState、RuntimeOptions 和 SubmissionReceipt。

## 当前源码与调用者

- public facade、上下文和字段值：[Facade.hpp](../../../Preview/Foundation/Utility/Diagnose/Facade.hpp)、[ContextState.hpp](../../../Preview/Foundation/Utility/Diagnose/ContextState.hpp)、[FieldKey.hpp](../../../Preview/Foundation/Utility/Diagnose/FieldKey.hpp)、[FieldCatalog.hpp](../../../Preview/Foundation/Utility/Diagnose/FieldCatalog.hpp)、[FieldCodec.hpp](../../../Preview/Foundation/Utility/Diagnose/FieldCodec.hpp)、[SubmissionReceipt.hpp](../../../Preview/Foundation/Utility/Diagnose/SubmissionReceipt.hpp)。
- 配置值、格式额度和输出选择：[RuntimeOptions.hpp](../../../Preview/Foundation/Utility/Diagnose/RuntimeOptions.hpp)、[FormattingLimits.hpp](../../../Preview/Foundation/Utility/Diagnose/FormattingLimits.hpp)、[RenderMode.hpp](../../../Preview/Foundation/Utility/Diagnose/RenderMode.hpp)、[PrefixCache.hpp](../../../Preview/Foundation/Utility/Diagnose/PrefixCache.hpp)。
- 文本与秘密处理：[Text/View.hpp](../../../Preview/Foundation/Utility/Text/View.hpp)、[Text/FixedText.hpp](../../../Preview/Foundation/Utility/Text/FixedText.hpp)、[Text/Truncate.hpp](../../../Preview/Foundation/Utility/Text/Truncate.hpp)、[Text/Redaction.hpp](../../../Preview/Foundation/Utility/Text/Redaction.hpp)、[Crypto/SecretScope.hpp](../../../Preview/Foundation/Utility/Crypto/SecretScope.hpp)。
- 单次提交边界：[Detail/SubmissionSlot.hpp](../../../Preview/Foundation/Utility/Diagnose/Detail/SubmissionSlot.hpp)、[Detail/SubmissionRequest.hpp](../../../Preview/Foundation/Utility/Diagnose/Detail/SubmissionRequest.hpp)、[Detail/BackendBridge.hpp](../../../Preview/Foundation/Utility/Diagnose/Detail/BackendBridge.hpp)、[Detail/DeferredMessage.hpp](../../../Preview/Foundation/Utility/Diagnose/Detail/DeferredMessage.hpp)、[Detail/FormatValidation.hpp](../../../Preview/Foundation/Utility/Diagnose/Detail/FormatValidation.hpp)。
- context/queue/记录/renderer：[Detail/ContextStorage.hpp](../../../Preview/Foundation/Utility/Diagnose/Detail/ContextStorage.hpp)、[Detail/ContextSnapshot.hpp](../../../Preview/Foundation/Utility/Diagnose/Detail/ContextSnapshot.hpp)、[Detail/AsyncBackendState.hpp](../../../Preview/Foundation/Utility/Diagnose/Detail/AsyncBackendState.hpp)、[Detail/AsyncSubmission.hpp](../../../Preview/Foundation/Utility/Diagnose/Detail/AsyncSubmission.hpp)、[Detail/SubmissionRecord.hpp](../../../Preview/Foundation/Utility/Diagnose/Detail/SubmissionRecord.hpp)、[Detail/ContextDecoder.hpp](../../../Preview/Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp)、[Detail/RenderRecord.hpp](../../../Preview/Foundation/Utility/Diagnose/Detail/RenderRecord.hpp)。
- worker、sink 与 lifecycle：[Detail/BackendWorker.hpp](../../../Preview/Foundation/Utility/Diagnose/Detail/BackendWorker.hpp)、[Detail/SinkSet.hpp](../../../Preview/Foundation/Utility/Diagnose/Detail/SinkSet.hpp)、[Detail/PathSinkOwner.hpp](../../../Preview/Foundation/Utility/Diagnose/Detail/PathSinkOwner.hpp)、[Detail/RenderEpoch.hpp](../../../Preview/Foundation/Utility/Diagnose/Detail/RenderEpoch.hpp)、[Detail/BackendLifecycle.hpp](../../../Preview/Foundation/Utility/Diagnose/Detail/BackendLifecycle.hpp)。
- 应用级 owner：[Application/DiagnoseRuntime.hpp](../../../Preview/Application/DiagnoseRuntime.hpp)。

## Include、CMake 与配置绑定

在 [Preview/CMakeLists.txt](../../../Preview/CMakeLists.txt) 中，PreviewFoundation 登记 facade、context、字段、消息快照、format validation、context storage 和 worker 等头；PreviewDiagnoseBackend 登记 BackendBridge、BackendLifecycle、ContextDecoder、SinkSet、AsyncSubmission、AsyncBackendState、SubmissionRecord，并通过后续 target_sources 登记 PathSinkOwner 和 RenderEpoch。PreviewDiagnoseBackend 依赖 PreviewFoundation。

PreviewApplication 私有链接 PreviewDiagnoseBackend 与 spdlog::spdlog。当前 Diagnose 输出源码实际由 PathSinkOwner 写文件、SinkSet 可选写 stdout；应用的 spdlog target edge 本身不表示 Diagnose sink 走 spdlog API。当前普通提交也不调用单独的 EmergencyWriter；该 FILE 写入 helper 由 detail 内声明并在专门测试中直接覆盖。

Application 配置模型在 [PreviewConfiguration.hpp](../../../Preview/Application/Configuration/PreviewConfiguration.hpp)。默认 level 为 Info、render mode 为 CompactHuman、目录/文件为 logs/preview.log、console 关闭、RotateBytes 为 64 MiB、RotateFiles 为 8、FlushIntervalMs 为 250。MakeDiagnoseConfiguration 与启动装配从配置读取 level、render mode、目录/文件名、console、轮转、trace selection、flush interval 和 generation；当前 JSON 配置没有队列容量、QueueBytes 或 Formatting 字段，因此这些值采用 RuntimeOptions 默认值，除非更高层直接构造 DiagnoseRuntimeConfiguration。PublicSettingsValidator 与 BackendLifecycle 分别校验配置字段和 backend options。

启动由 [Startup/ProcessServices.hpp](../../../Preview/Application/Startup/ProcessServices.hpp) 创建并安装应用唯一 DiagnoseRuntime。reload 路径由 [ReloadGenerationPreparation.hpp](../../../Preview/Application/ReloadGenerationPreparation.hpp) 准备新配置，再由 [Reload/PublicationTransaction.hpp](../../../Preview/Application/Reload/PublicationTransaction.hpp) 在 generation 发布时切换 render/sink epoch。Epoch 更新保留既有 facade 与唯一 worker；每条已入队记录 pin 自己的 epoch。

## 提交合同与唯一数据流

1. Facade 的 LogLevel 包含 Trace、Debug、Info、Access、Warn、Error、Critical 和 Off；Audit 是 SubmissionKind，不是 LogLevel。它用 SubmissionSlot 中同一原子里的 closed/active/epoch 状态预约直接调用。关闭时先封止新预约，控制线程等待已有调用退出后移除 owner。普通级别被过滤时不进入记录队列，也不捕获格式参数。Audit 与 Critical 绕过普通等级阈值；Access 有独立的阈值规则。
2. BackendBridge 使用调用者 ContextState 中 pin 的 epoch；没有 pin 时使用 active epoch。过期/关闭 epoch 返回 Stopped。
3. AsyncSubmission 使用非阻塞 producer gate，并把 Message、Flush、Barrier 都放进同一固定容量队列。producer gate 竞争失败或队列满返回 Dropped/ResourceUnavailable；不存在普通提交等待队列空间的路径。
4. 取得消息槽后，DeferredMessage 同步复制格式文本、文本参数和 context 字段；数值按原始标准类型复制。ContextSnapshot 拥有自己的固定字段文本，不保留调用者引用或长期 ContextStorage 引用。
5. 全部快照成功后才发布槽与 Sequence。后台 worker 按发布顺序消费、格式化、脱敏、渲染并写 sink；只有消费/写入完成后才 reset message/epoch 并推进 Read，所以正在处理的记录仍占一个队列容量。
6. Accepted 只证明拥有型快照进入 backend 队列；它不表示格式化、sink write、flush 或持久化已完成。Sequence 从当前 backend 的首条成功发布记录开始，只在完整捕获后发布时递增；Filtered、Dropped 和 Failed 不取得记录序号。普通日志没有逐条取消句柄；owner 关闭时停止接收，再排空已经接收的记录。

RenderEpoch pin 是配置/render/sink 代际所有权；ContextState 不 pin 业务 Session。消息/context 捕获失败、队列满、worker 渲染失败和 sink 失败分别记录，不混为同一个业务错误。

## 容量与资源预算

|资源|当前默认或上限|合同|
|---|---|---|
|记录队列|QueueCapacity 默认 4096；QueueBytes 默认 64 MiB|冷构造实际分配 QueueCapacity 个 SubmissionSnapshot；校验 QueueCapacity 不为零且 QueueCapacity × sizeof(SubmissionSnapshot) 不超过 QueueBytes。预算值不是固定 64 MiB 队列预分配。消息与 Flush/Barrier 共用槽位，消费中的槽计入占用。|
|单条消息快照|格式文本与全部文本参数共用 8192 字节；数值/其他标准值 tuple 最多 512 字节、最多 16 个实参|超过快照空间返回 Failed/OversizedMsg；语义参数不静默截短。|
|格式化|默认每字段 width ≤ 64 KiB、precision ≤ 4096；每记录 WorkBytes 默认 256 KiB，配置硬上限 1 MiB|工作预算计入格式解析、输入扫描、转义、浮点精度与估算输出工作量；64 KiB 的渲染缓冲不是 CPU 工作量上限。|
|消息输出|格式渲染最多 64 KiB；脱敏后再写入相同大小的安全缓冲|截断在 UTF-8 字符边界以 ...[truncated] 收尾，并设置 Truncated；结构化输出额外写 MessageTruncated=true。|
|长期上下文|进程静态 ContextPool 共 4096 槽|每个槽的文本存储由 FieldCatalog 各字段 MaxLength 求和生成；不按每个连接再分配一份。池耗尽的 With 产生 Failed 上下文，后续快照返回 ResourceUnavailable。|
|字段与 per-call context|当前内置字段 19 个；TryWith 最多 4 个不同 inline 字段|每字段按目录自身 MaxLength 限长；替换同一 inline 字段不增加占用。NativeError 是 256 字节敏感文本字段。|
|文件轮转|RotateBytes 默认 64 MiB，范围 4 KiB–1 GiB；RotateFiles 默认 8，范围 1–64|轮转与 sink 文件生命周期由 PathSinkOwner 管理。|
|应用周期 flush|FlushIntervalMs 默认 250 ms，范围 1–600000 ms|Application timer 仅提交非阻塞 Flush 命令；队列满时该周期请求可以跳过。|

ContextPool 是进程级固定静态池，TryAcquire 不等待。长期 With 在返回前复制文本；上下文副本共享槽引用，With 派生独立可修改副本，替换字段保存当前值而不累积历史值。最后一个 ContextState owner 释放引用并归还槽。

TryWith 的文本仅接受正式 ViewInput：标准 char_traits 的 string/string_view、FixedText、有效 NUL 终止 char 指针或 char 数组。输入文本需保持有效到同步提交返回；任意用户转换、自定义 char_traits 或临时文本不进入借用路径。第五个不同 per-call 字段返回 ContextCapacityExceeded，不删除字段或伪装成完整上下文。Worker/Session 身份进入 PrefixCache，CompactPrefix 直接读取固定前缀。

## 格式化、渲染与脱敏

公共日志方法以 std::format_string 在编译期检查语法。实参快照只接受文本、算术值和标准地址值；领域类型需先显式提取稳定值。格式与文本参数同步复制，Reset 使用 SecretScope 清除快照字节。

FormatValidation 在发布队列前检查动态 width/precision、字段索引/说明符和累计工作预算。负动态值、索引/说明符不合法或整数 c 超出 char 表示范围返回 Failed/InvalidArgument；超过 width、precision、快照或工作额度返回 Failed/OversizedMsg。有效说明符由标准 formatter 在后台真正执行，不会被静默忽略；格式工作量还估算被丢弃输出、debug 转义和最大四字节 fill 的成本。后台使用 std::locale::classic()，避免进入外部用户 locale facet。

渲染模式由 RenderEpoch 冻结：CompactHuman 输出 Worker/Session 前缀和正文；HumanWithFields 按 TraceSelection 选择身份字段并输出 HumanVisible 字段；Structured 输出 Unix 毫秒时间、Sequence、Level、Kind、Worker、Session、Fields 和 Message。字符串按 JSON 规则转义，输出超限时附 MessageTruncated。

字段编码根据 FieldCatalog 的 MaxLength 做 UTF-8 边界截断并保留 Truncated 位。NativeError 标记为 256 字节敏感字段；消息和敏感 context 文本在进入 sink 前走固定 key=value/key:value/JSON 风格脱敏，识别 password、token、secret、credential、PSK、authorization、private key 和常见 API/client/access/refresh key 名称。字段名使用 ASCII 不区分大小写比较；带引号值会跳过反斜线转义，Authorization Bearer 保留冒号/等号语法差异。自动脱敏只能识别受支持的字段语法，不能替代调用方避免记录任意秘密。

## 指标含义

- Dropped(Level)：当前 backend 因 producer gate 竞争或队列满拒绝的记录数，按请求 level 累计。
- DroppedAudits()：应用 public getter，映射 backend TerminalFailures；当前在 Audit 记录因队列无法接收时递增。它不表示审计已持久化。
- AdmissionFailures()：进程范围 facade 原子预约竞争失败数；不是当前 backend 队列拒绝数。
- FormatFailures()：进程范围 facade 中因 InvalidArgument/OversizedMsg 返回 Failed 的格式/参数快照拒绝数；它不是所有 CaptureFailures 的总和。
- CaptureFailures：当前 backend 的消息/context 快照失败与 sequence 资源边界失败数。
- RenderFailures：已接受记录因缺少可用 epoch/sink 或 worker 不可恢复失败而没有渲染的数量。
- Written：sink 成功写入的记录数，不是字节数。
- SinkFailures：文件/console write、flush 或关闭时观察到的输出失败数。
- QueueHighWatermark：当前 backend 已观察到的最大队列占用；可由 owner 重置。

这些计数是观察数据，不应求和后当作业务 Errors，也不能用 Accepted 替代 Written。Preview::Diagnose::Observability 的 HdrHistogram、rate meter 和 sampled ring 是独立统计原语，不是日志队列计数或业务错误。

## Flush、Barrier 与最终关闭

Flush 只尝试把 Flush 控制记录写进同一队列，不等待空间，也不在调用协程上做文件 I/O；容量不足时可跳过。Warn/Error/Critical 写入时 SinkSet 自身也会尝试 flush 输出。

DrainOnControlThread 仅能从非协程、非 I/O 的控制线程调用。它取单一 steady_clock 绝对 deadline，以非阻塞方式预约并重试入队 Barrier，再等待 worker 已处理此前记录、完成 sink flush 并发布 barrier 确认。并发 barrier 会被明确拒绝；超时后已入队 barrier 继续由 queue owner 保活到消费，不能提前复用其槽。Flushed 回执的 Sequence 是 barrier 确认时最后成功写入记录的序号；Flushed 不承诺 fsync。

BeginShutdown 可从应用关闭协程调用：封止 facade/backend 新提交，但不等待活动调用、不排空、不 join。FinalizeShutdown 必须在 Asio 运行循环退出后由控制线程调用：禁用并移除 facade backend、等待直接 facade 调用归还预约、停止 producer、唤醒 worker 排空现存记录、执行真实最终 flush、join 唯一 worker、关闭 sink 和释放队列。只有 worker、最终 flush、sink close 均成功且没有 sink failure 时返回 Closed；否则返回 Failed。Closed 仍不承诺 fsync 或断电持久性。

BackendWorker 的线程入口收口不可恢复异常，停止接收并按仍 pending 的队列记录计 RenderFailures、清除槽和尝试 flush。普通 Facade→BackendBridge→AsyncSubmission 路径不格式化、不等待队列、不执行同步文件 sink fallback；独立 EmergencyWriter detail helper 有界写 FILE，仅由测试直接调用。

PathSinkOwner 在冷准备时解析路径、创建缺失目录并以 append 打开文件；只在确认成功写入后标记日志文件有内容。关闭时 flush/close；若本次 prepare 新建的文件从未写入，则删除该文件并逆序移除本 owner 创建且仍为空的目录。

## 测试登记与证据口径

当前测试登记在 [tests/Preview/Foundation/Utility/Diagnose/CMakeLists.txt](../../../tests/Preview/Foundation/Utility/Diagnose/CMakeLists.txt)：ObservabilityTest、ContextStateTest、FieldCodecTest、ContextDecoderTest、ContextLifetimeTest、SessionAuditTest、DiagnoseFacadeTest、AsyncBackendInitializationTest、AsyncBackendQueueTest、AsyncBackendFallbackTest、AsyncBackendRotationTest、AsyncBackendShutdownTest 与 LoggerTest。

本页只列当前源码接线与测试映射，不登记执行结果。任何通过结论均须来自绑定当次源码、配置与 binary hash 的报告。
