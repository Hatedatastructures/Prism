# Diagnose 模块使用与维护

Diagnose 提供稳定的业务 facade 和一个 Application backend owner。业务提交只做级别检查、有界准入及格式描述、参数、上下文的同步快照；消息格式化、脱敏、Human/JSON 渲染和真实 sink I/O 全部在独立日志 worker 上执行。

当前源代码整改采用一条正式记录队列。原 spdlog async pool 已退役；spdlog 同步 logger 只作为后台输出能力，不再另建消息队列。

## 提交路径和唯一事实

1. Trace/Debug/Info/Access/Warn/Error/Critical/Audit 使用 std::format_string 在编译期检查格式和参数。
2. Facade 在 closed/active/epoch 的单原子上取得活动预约，再读取当前 raw owner/callback。关闭在同一原子封止；控制线程等全部预约退出并退休 epoch 后才摘除 owner。级别被过滤时不取得队列槽、不捕获参数。
3. BackendBridge 检查 typed level；AsyncSubmission 非阻塞取得 producer 门闩并检查真实队列容量。
4. 取得槽后 DeferredMessage 复制格式文本和参数文本。数值保留其原始标准类型；不会保存调用方引用。ContextSnapshot 同步复制字段和身份值，不 pin 业务 Session。
5. 捕获全部成功后一次发布槽和 Sequence。后台 worker 按该发布顺序消费，格式化、脱敏、渲染并写入同步 spdlog sinks。
6. 当前记录写入返回后才擦除参数存储并归还槽。正在处理的记录计入容量，不能提前宣称已释放。

Accepted 只表示队列已接受拥有型快照，不表示渲染、sink 写入或 flush 已完成。Drain barrier 返回 Flushed 时，此前记录已成功交给同步 sink 且 sink flush 完成；Sequence 是最后成功写入记录的序号。Shutdown 返回 Closed 时，后台队列已排空、最终 flush 完成、worker 已 join 且 owner 已关闭。Flushed/Closed 不承诺 fsync 或断电持久性。后台输出失败只增加观察指标，不修改业务返回值。普通提交的 Sequence 只在成功发布时递增，反映当前 backend 的实际发布顺序；新安装 backend 是新的序列 epoch。

## 公开入口和归属

|入口或文件|正式职责|
|---|---|
|Facade.hpp|稳定等级函数、编译期格式检查、唯一提交槽和活动调用保护|
|ContextState.hpp|不可变长期字段 owner 与四槽 per-call 借用|
|FieldKey.hpp / FieldCatalog.hpp|类型化字段与冻结字段目录|
|FieldCodec.hpp|纯值编码、UTF-8 截断；拥有型字符串编码只用于后台或冷路径|
|RuntimeOptions.hpp|冷构造的日志容量、级别、文件和轮转设置|
|SubmissionReceipt.hpp|观察状态、Sequence 和独立 Fault::Failure|
|Detail/DeferredMessage.hpp|固定格式及参数 storage，标准格式化在后台执行|
|Detail/ContextStorage.hpp|process 有界上下文池，每字段只保存最新拥有值|
|Detail/ContextSnapshot.hpp|队列直接拥有的固定上下文字节与数值|
|Detail/AsyncBackendState.hpp|唯一队列、日志线程、控制 barrier 和真实观察计数|
|Detail/AsyncSubmission.hpp|非阻塞准入，Flush/Barrier 复用同一队列|
|Detail/SubmissionSlot.hpp|同一原子的 closed/active/epoch 预约、封止与 typed 安装注册|
|FormattingLimits.hpp / Detail/FormatValidation.hpp|冷冻结额度与发布前的动态参数/工作量值验证|
|Text/View.hpp / Text/Truncate.hpp|精确无用户转换文本类型与统一 UTF-8 截断收尾|
|Detail/BackendWorker.hpp|唯一后台消费及线程异常边界|
|Detail/SinkSet.hpp|同步 spdlog 输出，只由日志 worker 使用|
|Detail/BackendLifecycle.hpp|冷安装、停止接收、最终队列/线程退休|
|Application/DiagnoseRuntime.hpp|应用级唯一 owner；安装 facade，保护直接调用|
|Foundation/Utility/Text|中立 TraceSelection、无分配字段比较、转义正确的脱敏和固定观察文本|

Detail 不供业务创建 queue、thread、sink 或 State。公共输入、输出和生命周期以对应接口的中文契约为准。

## 容量与资源

|资源|默认与约束|
|---|---|
|记录队列|QueueCapacity=4096，包含消息、flush、barrier 和当前消费槽|
|实际队列存储|QueueBytes=64 MiB；冷校验 QueueCapacity <= QueueBytes / sizeof(SubmissionSnapshot)|
|单记录消息快照|8 KiB，共同覆盖格式文本和全部文本实参；最多 16 个标准参数，数值 tuple 不超过 512 字节|
|格式化工作|MaximumWidth=64 KiB，MaximumPrecision=4096，WorkBytes=256 KiB；累计计算格式解析、原文本扫描、debug 转义、浮点精度和最多四字节 fill 的保守工作额度|
|消息渲染|最多保留 64 KiB；第一次格式截断立即按 UTF-8 字符边界加 marker，后台脱敏发生截断也明确输出 MessageTruncated|
|长期上下文|process 4096 个可回收槽；内置 19 字段，文本区按各字段真实 MaxLength 相加，未保存历史副本|
|per-call 字段|最多 4 个不同字段；替换同一字段不增加槽数|
|字段文本|各字段的既有 MaxLength 和 UTF-8 截断标志保留；NativeError 为敏感字段|
|文件轮转|RotateBytes 默认 64 MiB，范围 4 KiB–1 GiB；RotateFiles 默认 8，范围 1–64|

这些是 process 观察资源，不按每个空闲连接预分配日志最大预算。队列满或门闩竞争返回 Dropped/ResourceUnavailable；格式和实参共同超过 8 KiB 返回 Failed/OversizedMsg，不悄悄截短语义参数。上下文池无法取得槽时 With 产生 Failed 上下文，后续实际提交返回 Failed/ResourceUnavailable。

上下文、固定消息和队列归还不分配、不抛项目异常。参数缓冲区退休使用既有 Crypto::SecretScope 可靠擦除。调用方仍不得主动记录秘密材料；自动脱敏只能识别字段语法，不能识别所有任意文本中的秘密。

## ContextState

With(Key, Input) 在返回前同步复制长期文本，父上下文保持不变；新上下文直接拥有各字段当前文本。重复替换同一 key 不追加旧文本。复制 ContextState 只增加有界槽引用，最后引用释放时归还槽。

TryWith(Key, Input) 使用四槽 per-call 区，文本只允许左值并借用到同步日志提交返回；临时文本被编译期拒绝。第五个不同字段返回 ContextCapacityExceeded；不会删字段或把缺失字段冒充完整上下文。

Worker/Session 写入 PrefixCache，读取 CompactPrefix 不重新格式化。FieldCount 计算实际不同字段，不将空槽当作 Worker 字段。ContextSnapshot 从长期槽及 inline 值产生独立快照，提交返回后可以释放上下文和输入文本。

## 格式与脱敏

标准格式说明符、索引、精度和动态宽度由后台标准格式化器处理，不能接受格式后忽略说明符。请求快照在发布前以值验证动态 width/precision、整数 c 的可表示性和累计工作额度。负 width/precision、非法动态参数或字符转换越界返回 Failed/InvalidArgument；合法格式超过声明额度返回 Failed/OversizedMsg，不封止 backend，也不改变输入或说明符。工作额度同时限制被丢弃输出的格式化量，不能把 64 KiB 保留量当作 CPU 工作界限。后台显式使用标准 classic locale，L 仍由标准 locale-aware formatter 实现，避免进入外部用户 facet 的无界行为。

Context 与消息共享 Text/View.hpp 的精确类型约束：标准 char_traits 的 string/string_view、有效 NUL 终止 char 指针/数组和正式 FixedText。任意自定义 operator string_view、char_traits 或 allocator 行为不在热转换内调用；allocator 只负责原 string 存储。领域类型先显式取得稳定 View，不能靠一个 noexcept 用户转换隐藏分配。

CompactHuman 输出 Worker/Session 前缀及正文。HumanWithFields 按中立 TraceSelection 选择身份字段，并输出目录中的 HumanVisible 字段。Structured 输出 Unix 毫秒时间、Sequence、Level、Kind、Worker、Session、Fields 和 Message；超出消息输出预算时附 MessageTruncated=true。控制字符与 JSON 字符串按既有规则转义。

Text::IsSensitiveField 比较 ASCII 字段名，不建立动态小写字符串。引号值扫描跳过反斜线转义字节，遇到真正的闭合引号后才继续处理下一字段。Authorization Bearer 的冒号/等号语义保留。受控 token 的 PascalCase 格式和用户文本相互区分。

## Flush、Barrier 与最终关闭

Flush 只尝试把控制命令放进同一队列，不等待空间、不在协程执行文件 I/O。容量不足时可以跳过周期 flush；最终关闭仍执行真实 flush。

DrainOnControlThread 仅允许在非协程控制线程调用。它使用一个 steady_clock 绝对 deadline：非阻塞入队竞争、队列空间等待、worker flush 和确认都受该 deadline 约束。不创建临时 logger/promise，不使用 spdlog block overflow policy。并发 drain 控制者被明确拒绝；超时的 barrier 仍由队列 owner 保活到后台消费，不释放仍在使用的槽。

BeginShutdown 可以在协程调用，只禁止新 facade/backend 提交。FinalizeShutdown 必须在 Asio 运行循环退出后由控制线程执行：禁用 facade、等待已进入调用、停止 producer、请求 worker 排空、真实 flush、join，最后释放队列和 sinks。不能在协程或日志 worker 上 join。Closed 的最终关闭意味着队列和线程退休且输出未报告失败；Flushed 仅表示 sink 输出与 flush 返回成功，不声明 fsync；Failed 表示观察输出有失败事实，不能据此改写业务退出结果。

后台不可恢复异常只在 BackendWorker::Entry 的线程入口收口，封止观察接入、按真实 pending 数记录失败并退休槽。冷安装是独立的资源创建边界；普通提交链没有 throw/catch、PMR 分配或同步 sink fallback。

## 指标含义与维护边界

Dropped(Level) 是当前 backend 队列竞争/容量拒绝；AdmissionFailures 是 process 范围 facade 原子预约的竞争拒绝，不与当前 backend epoch 混作一项；DroppedAudits 是 Audit 未入队；CaptureFailures 是快照未能完整形成；FormatFailures 统计 facade 的消息快照/格式值/工作额度拒绝；RenderFailures 是已接受记录在后台不可恢复失败时未能渲染的数量；Written 是实际 sink 写入成功的记录数；SinkFailures 是 spdlog 输出错误计数。不能把这些计数求和后当作业务 Errors，也不能用 Accepted 代替 Written。

Observability.hpp 的直方图、EWMA 和采样环属于独立的观察数值能力，其质量整改和统计发布由 M07 承接。M06 的源码审查不代表这些采样算法已经完成验收。

当前阶段只实施源码与既有消费者迁移。未执行构建、测试、真实请求、性能或浏览器验收。后续需要分别核对多 producer/队列满、上下文池耗尽、动态格式、输入销毁、escaped quoted redaction、绝对 deadline、sink 失败、停止接入与最终 join；历史测试数量或旧 binary hash 不能替代当前证据。
