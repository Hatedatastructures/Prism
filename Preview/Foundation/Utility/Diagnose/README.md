# Diagnose 模块使用与实现指南

本文档面向需要使用、维护或分析 `Preview::Diagnose` 的开发者与 AI 助手。它说明公开入口、字段类型约束、消息渲染、异步提交、关闭时序和性能边界。接口行为以当前头文件实现为准；修改接口或语义时，应同步更新本文档和对应测试。

## 1. 模块职责与边界

Diagnose 是 Preview 的日志 facade 和异步输出 backend。业务模块只通过 `Preview::Diagnose` 的自由函数提交日志；应用级 `DiagnoseRuntime` 独占负责安装和关闭 backend。模块把消息与上下文捕获为拥有型记录后交给 spdlog 异步队列，由后台 worker 写轮转文件，并可选地写入 stdout。

```text
业务调用点
  -> Preview::Diagnose::Trace/Debug/Info/Access/Warn/Error/Critical/Audit
  -> 同步格式化消息
  -> BackendBridge：级别检查、消息脱敏、Context 快照
  -> AsyncSubmission：渲染输出、非阻塞入队尝试
  -> spdlog 有界队列（discard_new，1 个 worker）
  -> 轮转文件 sink + 可选 stdout sink
```

`Accepted` 表示记录已被异步 backend 接收，不表示已经写入文件、完成 flush 或具备崩溃后持久性。`Audit` 会绕过普通级别阈值，但仍可能因提交竞争或队列满而返回 `Dropped`。

### 1.1 目录与头文件

| 文件 | 用途 |
| --- | --- |
| [Facade.hpp](Facade.hpp) | 业务日志入口和 `std::format` 格式化提交。 |
| [ContextState.hpp](ContextState.hpp) | 值语义上下文；提供长期字段和固定容量 per-call 字段。 |
| [FieldKey.hpp](FieldKey.hpp) | `FieldId`、字段值种类、可见性、编译期字段定义及内置 `Fields::...` key。 |
| [FieldCodec.hpp](FieldCodec.hpp) | 字段值类型约束、UTF-8 限长、文本脱敏和自有值编码。 |
| [FieldCatalog.hpp](FieldCatalog.hpp) | 从编译期定义生成的冻结字段目录。 |
| [RuntimeOptions.hpp](RuntimeOptions.hpp) | 级别阈值、文件、队列、控制台和轮转参数。 |
| [RenderMode.hpp](RenderMode.hpp) | `CompactHuman`、`HumanWithFields`、`Structured` 三种模式。 |
| [SubmissionReceipt.hpp](SubmissionReceipt.hpp) | 提交状态、提交种类和序号回执。 |
| [PrefixCache.hpp](PrefixCache.hpp) | Worker/Session 固定身份前缀的定长缓存。 |
| [Observability.hpp](Observability.hpp) | 独立的直方图、EWMA 速率计和采样环；不负责写日志。 |
| [Detail/SubmissionRequest.hpp](Detail/SubmissionRequest.hpp) | Facade 与 backend 间的同步借用请求。 |
| [Detail/SubmissionRecord.hpp](Detail/SubmissionRecord.hpp) | 入队前已拥有消息和字段快照的记录。 |
| [Detail/ContextDecoder.hpp](Detail/ContextDecoder.hpp) | 按渲染模式捕获字段并生成文本/JSON。 |
| [Detail/BackendBridge.hpp](Detail/BackendBridge.hpp) | 把 facade 请求转换为拥有型记录。 |
| [Detail/AsyncSubmission.hpp](Detail/AsyncSubmission.hpp) | 序号、队列提交、丢弃计数和异步 flush 请求。 |
| [Detail/AsyncBackendState.hpp](Detail/AsyncBackendState.hpp) | 配置、spdlog 资源句柄和运行指标。 |
| [Detail/SinkSet.hpp](Detail/SinkSet.hpp) | 文件/控制台 sink、drain barrier 和 sink flush。 |
| [Detail/BackendLifecycle.hpp](Detail/BackendLifecycle.hpp) | backend 安装、停止接收、drain 和最终关闭。 |

`Detail` 是实现边界。业务代码不应直接创建 `SubmissionRequest`、`AsyncBackendState`、sink 或 spdlog logger。

### 1.2 一条记录的完整执行路径

以下顺序用于定位某条日志在哪个阶段被过滤、丢弃或失败。除 `Runtime` 初始化/关闭接口外，日志提交链路发生在发起日志的线程上，直到记录进入 spdlog 队列后才由后台 worker 消费。

1. **Facade 入口**：`SubmitFormatted()` 原子读取进程级 `SubmissionSlot`。没有已安装 callback 时直接返回 `Stopped`。随后按 facade 中缓存的 `LogLevel` 过滤普通记录；该检查发生在 `std::format` 之前。
2. **Facade 活动调用保护**：通过过滤后，Facade 增加 `ActiveCalls`，读取 backend owner，并再次确认 callback 未在并发关闭中被替换。owner/callback 不匹配时释放计数并返回 `Stopped`。这段计数用于阻止 backend 在 callback 仍使用 owner 时析构。
3. **消息格式化**：`std::format` 在当前线程运行，构造拥有型 `std::string`。Facade 将 `SubmissionRequest` 同步传给 callback；其中 `Context` 是借用指针，仅保证在 callback 返回前有效。
4. **Runtime 状态快照**：应用 callback 进入 `DiagnoseRuntime` / `BackendLifecycle`，用 `shared_ptr` 取得当前 `AsyncBackendState`。提交期间的共享引用使并发摘除状态时对象仍然存活；`Accepting == false` 时返回 `Stopped`。
5. **Bridge 捕获**：`BackendBridge` 再次检查级别和状态，复制消息并执行 `RedactSensitiveText()`，然后调用 `ContextDecoder::Capture()`。Structured 模式在此处记录 Unix 毫秒时间；人类模式的时间由 sink pattern 添加。两种格式都不输出操作系统线程号。
6. **拥有型记录**：ContextDecoder 选择字段、复制文本、应用字段敏感策略和最大 UTF-8 字节数。完成后 `SubmissionRecord` 不再借用原 Context 或调用方文本，因此可安全跨越异步队列边界。
7. **同步渲染和入队**：`AsyncSubmission` 分配本 backend 的 `Sequence`，用 `EnqueueGate_` 做一次不等待的竞争尝试。门闩忙立即返回 `Dropped`。取得门闩后在生产者线程生成 Human/JSON payload，再向 spdlog logger 提交；队列为 `discard_new`。代码比较 spdlog discard counter 以识别本次队列满丢弃。
8. **后台消费**：专属 spdlog pool 的单个 worker 依次处理日志和 flush 请求，再顺序调用文件 sink 和可选 stdout sink。sink 错误不会回溯修改已经返回的 `Accepted` 回执。

`Sequence` 在门闩竞争前分配，因此并发线程拿到较小序号的记录可能晚于较大序号的记录入队。它用于标记 backend 提交尝试，不是跨线程提交顺序、文件行顺序或持久化确认。

### 1.3 所有权模型

| 对象 | 谁拥有 | 允许的生命周期/边界 |
| --- | --- | --- |
| `SubmissionSlot::Owner` | slot 不拥有，只保存 owner 指针 | `InstallSubmissionBackend()` 到 `RemoveSubmissionBackend()` 之间有效；移除时先禁用 callback，再等待 `ActiveCalls == 0`。 |
| `DiagnoseRuntime` | 应用运行时 | 必须活到 `FinalizeShutdown()` 完成；析构会同步关闭 backend。 |
| `AsyncBackendState` | `BackendLifecycle` 原子 `shared_ptr` | 每个正在提交的调用可持有自己的快照，状态被摘除后仍可安全结束该调用。 |
| spdlog pool | `AsyncBackendState` / `SinkSet` 共享管理 | 本 Diagnose 实例独占创建，配置为 1 个 worker；不关闭 spdlog 的进程全局 pool。 |
| Context 文本 | `With()` 的 `Auxiliary::OwnedText` 或 `TryWith()` 调用方 | `With()` 会拥有副本；`TryWith()` 文本借用至同步提交结束；入队前再复制到记录。 |
| `PrefixCache::View()` | `PrefixCache` / `ContextState` 对象 | 视图不拥有文本；对象销毁或赋值覆盖后不可使用。 |

这个表用于审查异步边界：任何排队记录都必须拥有其消息、字段文本和渲染所需的身份快照，不能让 worker 解引用调用栈上的 Context 或 `string_view`。

## 2. 应用初始化和配置

### 2.1 Backend owner

应用集成桥位于 [`Preview/Application/DiagnoseRuntime.hpp`](../../../Application/DiagnoseRuntime.hpp)。Preview 当前由一个 `DiagnoseRuntime` 安装进程内唯一的 facade backend；普通模块只调用 facade。不要在每个 worker、session 或协议对象中分别安装 backend。

```cpp
Preview::Application::DiagnoseRuntime Runtime;
Preview::Application::DiagnoseRuntimeConfiguration Configuration;

Configuration.Logging.Level = Preview::Diagnose::LogLevel::Info;
Configuration.Logging.Directory = "logs";
Configuration.Logging.FileName = "preview.log";
Configuration.Logging.Console = false;
Configuration.Mode = Preview::Diagnose::RenderMode::CompactHuman;

if (const auto Result = Runtime.Install(Configuration); !Result)
{
    // Result.error().Code、Path、Message 描述初始化失败。
}
```

安装是同步初始化操作，会校验参数、创建目录、处理不兼容的旧格式文件、打开 sink 并启动 spdlog worker。不要把安装放在低延迟请求热路径或 Asio 协程中。再次安装相同设置可幂等成功；已有不同设置或另一个 owner 时会失败。

安装错误通过 `std::expected<void, DiagnoseRuntimeError>` 返回。错误类别为 `InvalidOptions`、`Directory`、`FileOpen`、`LegacyArchive`、`ConfigurationConflict`、`OwnerConflict`、`WorkerStart`；错误对象还包含相关路径和维护者可读的 `Message`。

应用正常调用点只需包含 facade 和需要的字段头文件：

```cpp
#include <Preview/Foundation/Utility/Diagnose/Facade.hpp>
#include <Preview/Foundation/Utility/Diagnose/FieldKey.hpp>
```

### 2.2 默认值和边界

| 参数 | 默认值 | 当前约束或说明 |
| --- | --- | --- |
| `RuntimeOptions::Level` | `Info` | 普通日志阈值；`Audit` 与 `Critical` 有绕过规则。 |
| `Directory` | `logs` | 必须非空；由应用 owner 在安装时创建。 |
| `FileName` | `preview.log` | 必须是文件名，不能为空、`.`、`..` 或含 `/`、`\\`、`:`。 |
| `Console` | `false` | 为 true 时，在文件 sink 外增加 stdout sink。 |
| `QueueCapacity` | `4096` | spdlog 队列槽位数；必须大于 0。队列主要承载日志记录，也可能包含 flush/barrier 请求；容量限制条目数，不限制总字节数。 |
| `RotateBytes` | `64 MiB` | 范围为 4 KiB 到 1 GiB。 |
| `RotateFiles` | `8` | 范围为 1 到 64。 |
| `DiagnoseRuntimeConfiguration::Mode` | `CompactHuman` | 输出模式，见第 5 节。 |
| `FlushIntervalMs` | `250` | 范围为 1 到 600000 ms；定时调度由应用 Asio timer 执行，不是 backend 自建定时线程。 |

Preview JSON 配置使用大驼峰选项名，当前默认配置可参考 [`PreviewConfiguration.json`](../../../Application/Configuration/PreviewConfiguration.json)。配置中的 `Logging` 包含 `Level`、`RenderMode`、`Directory`、`FileName`、`Console`、`RotateBytes`、`RotateFiles`、`FlushIntervalMs`；`Trace` 包含 `IncludeCorrelation`、`IncludeWorker`、`IncludeSession`、`IncludeStream`。当前 JSON 配置没有 `QueueCapacity` 项，应用使用 `RuntimeOptions` 的默认队列容量；直接构造 `DiagnoseRuntimeConfiguration` 时可以设置该值。

JSON 中 `Logging.Level` 接受 `Trace`、`Debug`、`Info`、`Access`、`Warn`、`Error`、`Critical`、`Off`；`Logging.RenderMode` 接受 `CompactHuman`、`HumanWithFields`、`Structured`。大小写必须匹配解析器中的名称。C++ 侧的 `LogLevelName(Level)` 返回大驼峰名称；`IsLevelEnabled(Configured, Requested)` 执行基础阈值判断，Facade 另对 `Audit` 和 `Critical` 应用绕过规则。

`FlushIntervalMs` 只是应用发出异步 flush 请求的间隔。直接嵌入 `DiagnoseRuntime` 的宿主必须自行决定何时调用 `Flush()`；单独调用 `Install()` 不会创建周期 timer。

## 3. 日志等级、过滤和提交回执

### 3.1 Facade 方法

`Facade.hpp` 提供以下函数，每个函数都有两个重载：`Function(Context, Format, Args...)` 和 `Function(Format, Args...)`。不带 `Context` 的重载等价于使用 `ContextState::Empty()`。

| 方法 | `LogLevel` / `SubmissionKind` | 语义 |
| --- | --- | --- |
| `Trace` | `Trace` / `Ordinary` | 识别细节、UDP 会话汇总和 Mux 流量计数；不逐数据报输出。 |
| `Debug` | `Debug` / `Ordinary` | 运行就绪、简短识别结果和少量关键分支决策；常规成功阶段不逐条记录。 |
| `Info` | `Info` / `Ordinary` | 仅认证成功的用户身份与实际目标请求；不记录逐阶段成功信息。 |
| `Access` | `Access` / `Ordinary` | 受单独规则筛选的访问记录，不等同于绕过阈值的 `Audit`。 |
| `Warn` | `Warn` / `Ordinary` | 可恢复异常或需要关注的情况。 |
| `Error` | `Error` / `Ordinary` | 当前操作失败，但进程仍可继续。 |
| `Critical` | `Critical` / `Ordinary` | facade 不受普通级别阈值过滤；仍可能无法入队。 |
| `Audit` | `Access` / `Audit` | 绕过普通级别阈值的终态审计记录；仍可能被丢弃。 |

PrismPreview 的 `Info` 只有两类：`AuthenticationSucceeded SourceIp=... User=...` 和 `Request SourceIp=... Target=... [User=...]`。Mux、AnyTLS 和 VLESS XUDP 请求行附带 `StreamId`，用于区分同一会话中的目标流。认证身份只使用明确的非敏感 `DisplayIdentity`；为空时显示数值 `AccountId`。UUID 等凭据派生的运行时 `Identity` 不得作为日志用户名。Mux 每个目标 stream 记录一条请求；UDP 在实际目标可确定时记录一次请求，不逐数据报输出。Socks5、Trojan、Vless、Vmess、VlessXudp、Hysteria2 和 TUIC 的数据报服务在会话结束时以 `UdpSessionSummary` 汇总包数和字节数。Session 关闭记录继续走独立的 `Access/Audit`。

识别成功在 `Debug` 输出一次候选摘要；`Trace` 至多补一条包含模式和探测摘要的记录。后续认证或拨号失败使用 `AuthenticationFailed`、`DialFailed` 等实际失败阶段，不复用 `RecognitionAccepted`；成功记录不附加 `FaultCode=Success`。Worker/Session 从上下文输出；仅当 Task 与 Session 不同，或 Generation 大于 1 时才附加，避免常见情况下重复输出相同 ID 和默认代数。

TCP 的 `SourceIp` 从 accept endpoint 进入每会话 `SessionOptions`；QUIC 在 CID admission 时从 peer endpoint 捕获 `SourceIp`，通过独立的 `QuicPeerLogContext` 传给连接回调。QUIC 当前没有派发到 `WorkerGroup`，因此不伪造 `Worker` 身份。客户端地址不写进共享 `QuicAdmissionContext`。

格式参数使用 `std::format_string<Args...>`，格式串在编译期与参数类型检查。级别过滤发生在格式化前，因此被过滤的普通日志不会执行 `std::format`。通过过滤后，格式化在调用线程同步完成；格式化异常被捕获，回执为 `Failed`，并增加 `FormatFailures()`。

`IsEnabled(Level)` 可在准备昂贵的 Debug/Trace 参数前查询当前 facade 阈值；它不保留 backend，也不保证后续提交一定被接受。提交入口仍会重新检查安装状态和级别。

### 3.2 阈值规则

通常情况下，`Trace < Debug < Info < Access < Warn < Error < Critical`。`Access` 是特殊通道：阈值设为 `Trace`、`Debug` 或 `Info` 时普通 `Access()` 可通过；阈值为 `Access` 时只放行 `Access()`；阈值为 `Warn` 或更高时不放行普通 `Access()`。`Off` 过滤所有普通级别。无论阈值如何，`Audit()` 和 `Critical()` 都会绕过 facade 的普通级别过滤。

绕过阈值不等于可靠写入：`Audit()` 和 `Critical()` 都要经过同一个有限队列和入队门闩。队列满或并发提交门闩忙时，结果仍是 `Dropped`。

下表是 facade 对 `Ordinary` 方法的最终放行规则；`Audit` 列按 `SubmissionKind::Audit` 判断，始终绕过级别阈值。`Critical` 的 `Y*` 表示 facade 特例绕过阈值。backend 未安装或正在关闭时，即使表中为 `Y` 仍会返回 `Stopped`。

| 配置阈值 | Trace | Debug | Info | Access | Warn | Error | Critical | Audit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `Trace` | Y | Y | Y | Y | Y | Y | Y* | Y |
| `Debug` | - | Y | Y | Y | Y | Y | Y* | Y |
| `Info` | - | - | Y | Y | Y | Y | Y* | Y |
| `Access` | - | - | - | Y | - | - | Y* | Y |
| `Warn` | - | - | - | - | Y | Y | Y* | Y |
| `Error` | - | - | - | - | - | Y | Y* | Y |
| `Critical` | - | - | - | - | - | - | Y* | Y |
| `Off` | - | - | - | - | - | - | Y* | Y |

### 3.3 回执

| `SubmissionStatus` | 含义 |
| --- | --- |
| `Accepted` | 异步 backend 已接受请求；不表示 sink 已写入或 flush。 |
| `Filtered` | 普通记录因级别阈值被跳过。 |
| `Dropped` | 入队门闩忙或队列满，记录没有进入异步队列。 |
| `Stopped` | backend 未安装，或已禁止新提交。 |
| `Failed` | 格式化、捕获、提交或 sink flush 等操作失败。 |
| `TimedOut` | 控制线程 drain barrier 未按等待阶段的截止时间完成。 |
| `FallbackWritten` | 兼容旧回执的状态；当前常规 facade 不执行同步 fallback 写入。 |
| `ContextCapacityExceeded` | 保留在状态枚举中；`ContextState::TryWith()` 实际通过 `ContextError` 返回容量错误。 |

`SubmissionReceipt::Accepted()` 对 `Accepted` 和兼容状态 `FallbackWritten` 返回 true。`Sequence` 是 backend 生命周期内的提交尝试序号，不是持久化确认；并发提交时序号分配发生在入队门闩之前，不应假设它与文件行顺序完全一致。过滤、停止或捕获失败等尚未分配序号的请求通常是 0。

## 4. 上下文和类型化字段

### 4.1 长期字段与 per-call 字段

`ContextState` 是不可变值类型：`With()` 和 `TryWith()` 返回新上下文，不改父上下文。可把 worker/session/process 等长期身份存在基础上下文，再为单条记录添加阶段字段。

```cpp
const Preview::ProcessId ProcessId{42};
const auto SessionContext = Preview::Diagnose::ContextState::Empty()
    .With(Preview::Diagnose::Fields::Worker, Preview::WorkerId{3})
    .With(Preview::Diagnose::Fields::Session, Preview::SessionId{128})
    .With(Preview::Diagnose::Fields::Process, ProcessId);

const std::string_view Stage{"TlsHandshake"};
const auto PerCall = SessionContext.TryWith(Preview::Diagnose::Fields::Stage, Stage);
if (PerCall)
{
    (void)Preview::Diagnose::Debug(*PerCall, "Stage={} Result={}", Stage, "Accepted");
}
```

- `With(Key, Value)` 创建长期字段。文本会在派生时复制、脱敏、按字段上限截断，并由上下文拥有；适合跨函数或异步边界保存的字段。写时复制和动态拥有区可能分配内存，不应在高频热路径中反复派生大型上下文。
- `TryWith(Key, Value)` 只使用固定的 4 个 inline 槽位，不创建长期字段区。它适合单条日志的短期扩展；同一字段 ID 会替换原值，不增加槽位数。添加第 5 个不同的 inline 字段时返回 `ContextError::ContextCapacityExceeded`。
- `TryWith()` 的文本实参必须是左值，且其字符存储至少要活到同步日志调用返回。命名的 `std::string`/`std::string_view` 和字符串字面量可安全用于单次提交；临时 `std::string` 或临时 `std::string_view` 不满足约束。若上下文要保留更久、跨协程挂起或异步保存，请用会复制文本的 `With()`。
- 非文本 `TryWith()` 值按值保存。Worker 和 Session 是上下文身份，只能通过 `With()` 设置。
- 调用 facade 时 backend 会在返回前捕获所需字段。捕获后异步记录不再借用原 `ContextState` 或 per-call 文本。

主要接口：

| 接口 | 用途 |
| --- | --- |
| `ContextState::Empty()` | 创建空上下文。 |
| `ContextState::With(Key, Value)` | 派生拥有型长期上下文。 |
| `ContextState::TryWith(Key, Value)` | 派生最多 4 个不同 inline 字段的单次上下文，返回 `std::expected<ContextState, ContextError>`。 |
| `CompactPrefix()` | 读取 `[W<id>][S<id>]` 固定前缀视图；视图由上下文拥有。 |
| `WorkerId()` / `SessionId()` | 读取可选的 Worker/Session 强类型身份。 |
| `FieldCount()` | 统计普通字段数，不包含 Worker/Session 身份。 |

### 4.2 内置字段目录

字段以 `Fields::<Name>` 类型化 key 写入。字段名也是 Human/JSON 输出中的稳定字段名。文本上限以 UTF-8 **字节**计，可能追加 `...[truncated]` 标记并在字符边界处截断。

| Key | 值类型 | `HumanWithFields` 输出规则 | 文本上限/安全策略 |
| --- | --- | --- | --- |
| `Worker` | `Preview::WorkerId` | 由 `TraceSelection.IncludeWorker` 控制；同时生成固定 `W` 前缀。 | 数值身份。 |
| `Session` | `Preview::SessionId` | 由 `TraceSelection.IncludeSession` 控制；同时生成固定 `S` 前缀。 | 数值身份。 |
| `Correlation` | `Preview::RequestId` | 由 `TraceSelection.IncludeCorrelation` 控制。 | 数值身份。 |
| `Process` | `Preview::ProcessId` | 结构化输出。 | 数值 ID。 |
| `Generation` | `Preview::GenerationId` | 结构化输出。 | 数值 ID。 |
| `Task` | `Preview::TaskId` | 结构化输出。 | 数值 ID。 |
| `Operation` | `Preview::OperationId` | 结构化输出。 | 数值 ID。 |
| `Protocol` | `std::string_view` | 结构化输出。 | 64 字节。 |
| `Route` | `std::string_view` | 结构化输出。 | 64 字节。 |
| `Stream` | `Preview::StreamId` | 由 `TraceSelection.IncludeStream` 控制。 | 数值 ID。 |
| `Carrier` | `std::string_view` | 可见。 | 64 字节。 |
| `Sni` | `std::string_view` | 可见。 | 64 字节。 |
| `Alpn` | `std::string_view` | 结构化输出。 | 64 字节。 |
| `TlsVersion` | `std::string_view` | 可见。 | 64 字节。 |
| `Stage` | `std::string_view` | 结构化输出。 | 64 字节。 |
| `Status` | `std::string_view` | 结构化输出。 | 64 字节。 |
| `FaultCode` | `std::string_view` | 结构化输出。 | 64 字节。 |
| `NativeError` | `std::string_view` | 结构化输出。 | 256 字节，字段策略标为敏感并执行脱敏。 |
| `ElapsedMs` | `std::uint64_t` | 结构化输出。 | 毫秒数值。 |

`HumanWithFields` 会输出可见字段以及由 `TraceSelection` 选中的 Correlation、Worker、Session、Stream。`Structured` 会输出目录中所有已设置字段，不受 `TraceSelection` 和 `FieldVisibility` 限制；Worker/Session 身份放在 JSON 顶层而不是 `Fields` 对象中。

### 4.3 编译期字段约束和安全

- `FieldDefinition` 的模板参数依次是字段 ID、声明值类型、编码种类、可见性、文本最大字节数、是否敏感、是否作为上下文身份。`FieldKey<Definition>` 将定义变为可在 `ContextState` 中使用的类型化 key。
- 文本值要求可转换为 `std::string_view`；非文本值要求去除 cv/ref 后与定义的 `ValueType` 完全一致。数值、枚举和强类型 ID 最终以 `uint64_t` 保存，布尔值单独保存。
- 消息正文在 `BackendBridge` 中会调用项目的 `RedactSensitiveText()`；标为 `Sensitive` 的字段在编码/捕获阶段也执行脱敏。自动脱敏不保证能识别所有秘密格式，调用方不得把口令、令牌、私钥、认证凭据或原始用户载荷放进日志消息或普通字段。
- 消息正文没有字段目录的 `MaxLength` 上限。高体量或外部输入应由调用方先限长；有限队列只限制记录条数，不会给任意长度消息提供字节级内存上限。
- 通用模板可以接受自定义 `FieldDefinition`，但输出 decoder 只遍历冻结的 `BuiltinFieldPack`。新增内置字段时必须同步维护 `FieldId`、`FieldName()`、`Fields` 定义/key、`BuiltinFieldPack` 和字段/输出测试；仅声明自定义 key 不会自动出现在日志中。

字段元数据辅助接口：`FieldName(FieldId)` 返回稳定名称，未知枚举值返回空视图；`FieldCatalog::Count` 是内置字段数，`Descriptors()` 返回指向静态目录的固定长度只读 span，`Find(Id)` 返回描述副本或 `std::nullopt`。`FieldValueCompatible<Key, Value>` 是编译期兼容性 concept；`EncodeFieldValue(Key, Value)` 返回拥有型 `EncodedFieldValue`，文本已经复制、脱敏和限长。一般业务代码应调用 `ContextState::With/TryWith`，不直接编码字段。

`PrefixCache` 可独立构造并通过 `WithWorker(Id)`、`WithSession(Id)` 返回派生缓存；`Worker()`/`Session()` 返回可选身份，`View()` 返回对象内部 `[W...][S...]` 字符串的非拥有视图。不要在缓存对象销毁或被赋值覆盖后继续使用该视图。

### 4.4 调用示例与常见错误

#### 构造长期上下文并提交一条记录

```cpp
const Preview::ProcessId Process{42};
const auto SessionContext = Preview::Diagnose::ContextState::Empty()
    .With(Preview::Diagnose::Fields::Process, Process)
    .With(Preview::Diagnose::Fields::Worker, Preview::WorkerId{3})
    .With(Preview::Diagnose::Fields::Session, Preview::SessionId{128});

const std::string_view SourceIp{"192.0.2.10"};
const std::string_view Target{"example.com:443"};
const auto Receipt = Preview::Diagnose::Info(
    SessionContext, "Request SourceIp={} Target={}", SourceIp, Target);
```

`SessionContext` 可被多个调用只读复用。日志消息格式串是编译期格式串；不要先用字符串拼接构造整条消息。若调用方要根据提交结果做诊断，应处理 `Receipt.Status`，不要忽略 `[[nodiscard]]` 警告：

```cpp
switch (Receipt.Status)
{
case Preview::Diagnose::SubmissionStatus::Accepted:
    break; // 仅表示进入异步 backend。
case Preview::Diagnose::SubmissionStatus::Filtered:
    break; // 这是配置结果，不是 backend 故障。
case Preview::Diagnose::SubmissionStatus::Dropped:
    // 由上层计数或采样；不要在同一拥塞 logger 上递归输出错误日志。
    break;
case Preview::Diagnose::SubmissionStatus::Stopped:
case Preview::Diagnose::SubmissionStatus::Failed:
    break; // 停机或本次格式化/捕获提交失败。
}
```

#### 添加 per-call 字段并处理容量错误

```cpp
const std::string_view Stage{"TlsHandshake"};
const auto LocalContext = SessionContext.TryWith(Preview::Diagnose::Fields::Stage, Stage);
if (!LocalContext)
{
    // 记录上下文拼装失败的独立指标，或退回不带 Stage 的 SessionContext。
}
else
{
    (void)Preview::Diagnose::Debug(*LocalContext, "HandshakeStage={}", Stage);
}
```

一个 `ContextState` 最多容纳 4 个不同 inline 字段，但已有长期字段不消耗这 4 个槽位。对同一 `FieldId` 再次 `TryWith()` 会替换该 inline 值；超容量时不会截断或修改父上下文，而是返回 `ContextError::ContextCapacityExceeded`。

#### 提交终态事件

```cpp
const auto Receipt = Preview::Diagnose::Audit(
    SessionContext, "SessionClosed Status={} FaultCode={}", Status, FaultCode);
if (Receipt.Status != Preview::Diagnose::SubmissionStatus::Accepted)
{
    // 将未接收结果返回给上层控制逻辑；不要把 Accepted 当作文件已落盘。
}
```

`Audit()` 固定使用 `Access` 级别和 `SubmissionKind::Audit`。它只绕过级别过滤，不会等待队列、执行同步 fallback 或确认落盘。若业务要求“即使进程崩溃也必须持久化”，当前 Diagnose facade 不提供这样的事务/持久化契约。

### 4.5 字段扩展步骤

新增内置字段时按以下顺序检查，避免出现“编译能写入但 decoder 不输出”的字段：

1. 在 `FieldKey.hpp` 为 `FieldId` 追加唯一 ID，并更新 `FieldName()` 的 `switch`。
2. 在 `Fields` 命名空间定义 `FieldDefinition`，核对准确的值类型、`FieldValueKind`、Human 可见性、最大 UTF-8 字节数、敏感标记和身份标记。
3. 声明对应 `FieldKey<Definition>` 常量，并把 Definition 加进 `BuiltinFieldPack`。
4. 检查 `ContextState::With/TryWith` 的类型约束及该字段是不是应该有专用 identity 语义；除 Worker/Session 外，identity 标记不能随意启用。
5. 检查 `ContextDecoder::IsSelected()`、`Capture()`、Human 与 Structured 输出；Structured identity 当前另写顶层键。
6. 补 codec、Context lifetime、decoder 两种输出、敏感文本/截断和日志文件断言，并更新本文档字段表。

不要改变已有 `FieldId` 的顺序/含义或已有 JSON 字段名/类型来复用槽位；下游采集器可能依赖当前 schema。

## 5. 输出格式

### 5.1 `CompactHuman`

只使用固定 Worker/Session 前缀，不遍历普通字段目录。时间由 sink pattern 添加；正文等级标签由 backend 添加。线程号不输出，Worker 身份通过上下文前缀表达。示意：

```text
[2026-09-27 12:34:56.789] [Info] [W3][S128] Request SourceIp=192.0.2.1 Target=example.com:443 User=alice
```

### 5.2 `HumanWithFields`

在 Compact 前缀基础上输出可见/选中的字段，字段放在方括号中：

```text
[2026-09-27 12:34:56.789] [Debug] [W3][S128] RecognitionAccepted Candidate=ProtocolSocks5
[2026-09-27 12:34:56.790] [Debug] [W3][S128] RecognitionAccepted Candidate=ProtocolShadowsocks2022
[2026-09-27 12:34:56.791] [Trace] [W3][S128] RecognitionDetails Protocol=Shadowsocks Mode=MixedTrial ProbeBytes=420 FirstByte=0xBB CryptoTrials=2
[2026-09-27 12:34:56.792] [Warn] [W3][S128] DialFailed Protocol=Shadowsocks FaultCode=IoError
```

`TraceSelection` 只控制 Correlation、Worker、Session、Stream；其他字段由其 `FieldVisibility` 决定。默认值为 Correlation/Worker/Session 开启、Stream 关闭。

### 5.3 `Structured`

每条记录输出为一行 UTF-8 JSON（JSON Lines）。当前顶层键为 `Timestamp`（Unix 毫秒）、`Sequence`、`Level`、`Kind`、`Worker`、`Session`、`Fields`、`Message`。字段和值使用 JSON 类型；无 Worker/Session 时对应顶层值为 `null`。等级和字段名保持大驼峰。日志不记录操作系统线程号；需要按执行单元归属时使用 `Worker`，统计 API 也通过 `Scope::Worker` 和 `WorkerId` 聚合。

```json
{"Timestamp":1790502896789,"Sequence":7,"Level":"Info","Kind":"Ordinary","Worker":3,"Session":128,"Fields":{"Carrier":"Tcp","Sni":"example.com"},"Message":"Request SourceIp=192.0.2.1 Target=example.com:443 User=alice"}
```

Structured 在提交线程捕获时间戳，并捕获所有已设置的目录字段。字段目录以外的字段不会输出。`Worker` 是上下文提供的 Preview worker 身份，不是操作系统线程号。修改键名、层级或类型会影响下游采集器，应视为日志 schema 变更。

所有人类可读消息会把换行、回车和控制字节转义，保持每条记录单行。Structured 使用 JSON 转义。不同 RenderMode 写同一个已存在日志文件时，sink 会检查首个有效字符；检测到格式不兼容时会尝试归档旧文件。

## 6. 同步、异步、阻塞和关闭

### 6.1 普通 facade 调用

`Trace()` 等 facade 在调用线程同步完成级别检查、`std::format`、消息脱敏、上下文捕获、输出字符串构造和入队尝试。sink 文件写入由后台线程执行。常规路径不等待队列空位或 sink 写完；它采用立即丢弃策略，但不能因此称为“零开销”或“严格 wait-free”：格式化、字符串/容器分配、原子操作和 spdlog 队列操作仍消耗调用线程 CPU，内存分配器也可能带来延迟。

本 backend 的 spdlog pool 有 **1 个 worker**。所有记录按该 worker 串行经过文件/控制台 sink。提交期间的 `EnqueueGate_` 是非等待 `atomic_flag` 门闩：竞争失败即丢弃，即使队列仍有空间也可能发生。实际队列满时使用 `discard_new`，丢弃新记录，不阻塞生产者。`Dropped(Level)` 同时统计门闩竞争和队列满。

队列容量以记录条目计，不是字节容量。消息体没有统一最大长度；大消息会增加调用线程格式化/复制开销和队列内存占用。多个 sink 共用同一个 worker，慢文件系统或 stdout 也会降低消费速度，继而抬高队列水位并增加丢弃。

### 6.2 Flush 和 drain

| 操作 | 可从协程/I/O worker 调用？ | 等待语义 |
| --- | --- | --- |
| `DiagnoseRuntime::Flush()` | 可以 | 非阻塞地提交异步 flush 请求；入队门闩正忙时跳过本次请求，后续周期可重试。 |
| `BeginShutdown()` | 可以 | 立即关闭新提交入口；不等待活动调用、不排空队列、不 join worker。 |
| `DrainOnControlThread(Timeout)` | 不可以 | 同步 barrier；只能由非 Asio 控制线程调用。 |
| `FinalizeShutdown()` / `Shutdown()` | 不可以 | 最终同步关闭，可能等待 facade/direct 调用、排队写入和 worker join；没有总时限参数。 |

应用集成桥还提供 `Install(Configuration)`、`Submit(Level, Context, Message)`、`Audit(Context, Message)`、`IsInstalled()`、`Dropped(Level)`、`DroppedAudits()`、`QueueHighWatermark()`、`ResetQueueHighWatermark()`、`CaptureFailures()`、`FormatFailures()` 和 `SinkFailures()`。业务日志优先使用 `Preview::Diagnose` facade，让它保留编译期格式检查；`Submit()`/`Audit()` 是接收已构造 `std::string` 的直接 owner 接口。

`DrainOnControlThread()` 将 barrier 放入与日志相同的 spdlog pool，再等待它 flush 实际 sinks。barrier logger 使用 spdlog 的 `block` overflow policy；源码中的 `Timeout` 只限制 barrier **成功入队之后**的 future 等待，队列满时 barrier 入队本身可能阻塞并超过该时间。因此不得在协程、I/O worker 或需要硬超时保证的线程调用它。

最终关闭必须发生在 Asio 运行循环退出之后：先停止业务生产者并调用 `BeginShutdown()`，然后从控制线程调用 `FinalizeShutdown()`。最终关闭会停止新提交、等待活动 facade/direct 调用退出，释放异步 logger/pool 并 join worker，最后同步 flush 实际 sinks。析构也会调用同步关闭；不要让 `DiagnoseRuntime` 在仍运行的 I/O 线程上析构。

应用集成中，Asio timer 周期调用 `Flush()`；异步停机期间先停止新的连接/worker，再在运行循环外执行最终资源回收。参考 [`Application.cpp`](../../../Application/Application.cpp) 中 `ArmDiagnoseFlush()`、`ReleaseRuntimeResources()` 和 `FinalizeRuntimeResources()` 的调用关系。

### 6.3 Audit 与可靠性边界

`Audit()` 是优先级/筛选语义，不是持久化协议。它提交前仍可能被门闩竞争或队列满丢弃，`DroppedAudits()` 统计此类未入队数；入队成功后 sink 后续仍可能失败，查看 `SinkFailures()`。Audit 使用 `Access`/spdlog Info 级别，不会触发 spdlog `flush_on(Warn)`。正常退出时最终 join+sink flush 能处理已接受记录，但崩溃、断电或文件系统错误仍不受 facade 回执保证。

`FallbackWritten` 虽保留在 `SubmissionStatus`，普通 facade 不会在队列失败时同步写 stderr。`Detail::EmergencyWriter` 是单独的同步应急工具，调用会执行 `fwrite` 和 `fflush`，而且单条最多 2048 字节；只能在控制线程按明确的故障策略使用，不要放入请求热路径或协程。

## 7. 指标和观测工具

### 7.1 Backend 运行指标

`DiagnoseRuntime` 提供下列读取接口：

| 接口 | 含义 |
| --- | --- |
| `Dropped(Level)` | 指定等级因门闩竞争或队列满未入队次数。 |
| `DroppedAudits()` | 未能入队的 `Audit` 次数；不等于所有 audit 的 sink 错误数。 |
| `QueueHighWatermark()` | 安装以来观察到的队列长度近似高水位。 |
| `ResetQueueHighWatermark()` | 以调用时观察到的当前队列长度作为新的基线。 |
| `CaptureFailures()` | 消息脱敏、上下文捕获、输出构造或入队前 backend 处理阶段的异常次数。 |
| `FormatFailures()` | facade 同步格式化/请求构造异常次数。 |
| `SinkFailures()` | spdlog 错误处理器或最终 sink flush 观察到的失败次数。 |

计数器使用 relaxed 原子操作；并发读取是观测值，不构成多指标的同一时刻事务快照。QueueHighWatermark 是观测到的近似峰值，重置时队列也可能继续变化。

### 7.2 独立观测类型

这些类型在 [Observability.hpp](Observability.hpp) 中，不自动接入 backend：

- `HdrHistogram(MaxValue)`：原子指数分桶；0 上限按 1 处理，超上限值封顶到末桶。`Count()` 是并发下逐桶累加的近似快照；`Percentile(0, 100]` 返回桶代表值而非原始精确分位数，无样本或无效百分位返回 0，100 百分位返回配置上限。
- `EwmaMeter(WindowMs=1000)`：`Mark(N)` 累加事件；`RatePerSecond(NowMs)` 由调用方提供统一毫秒时钟并更新 EWMA。窗口 0 归一为 1ms；首次读取只建立时间基准并返回 0，时间不前进时返回旧速率；读取更新发生竞争时立即返回最近发布值。
- `SampleTracer(Ratio=1, RingSize=256)`：按分母抽样，Ratio 为 1 表示全采样。RingSize 必须为 2 的幂，否则采用 256；大于 65536 时封顶。环满后覆盖旧槽位。`Drain(Output)` 是非破坏性地从新到旧复制最多 8 个槽位，不是清空操作；尚无样本时也可能读到初始化的 0，应结合 `SampledCount()` 和 `TotalCount()` 判定。

## 8. 性能分析和后续优化指南

分析日志性能时，先区分调用线程成本和后台消费成本：

1. **调用线程**：级别判断、`std::format`、消息脱敏、字段复制/脱敏/限长、Structured 时间捕获、Human/JSON 字符串构造、队列门闩和入队。当前不捕获操作系统线程号。过滤发生在格式化之前；如果要省掉昂贵参数计算，调用方还需在计算参数前做等级判断，而当前 facade 没有懒求值 lambda 接口。
2. **后台 worker**：单线程消费所有队列记录并写所有 sink；磁盘、轮转和 stdout 吞吐决定消费速度。高水位和丢弃率应与 sink 耗时一起看。
3. **上下文**：`CompactHuman` 只复制缓存前缀，不遍历字段目录；扩展模式需要扫描冻结字段目录并复制已设置字段。长期 `With()` 可能复制/分配辅助存储；高频 per-call 字段优先评估 `TryWith()`，但严格遵守文本生命周期。
4. **消息体**：没有统一长度上限。大量参数、长文本和 JSON 转义都可能增加 CPU、分配和队列驻留内存。不要只看平均提交时间；同时关注 P95/P99、CPU、分配数、队列水位、Dropped、drain 和 shutdown 耗时。
5. **并发**：单一非等待门闩把并发生产者串行化，失败者直接丢弃。高并发稳定性必须用多生产者负载测量吞吐、丢弃、尾延迟、队列消费和关闭排空；单生产者结果不能证明高并发稳定。

现有路径基准位于 [`DiagnosePathBenchmark.cpp`](../../../../tests/Preview/perf/DiagnosePathBenchmark.cpp)。它对不同上下文/渲染模式和 128/512/2048 字节消息采集提交耗时、P95/P99、生产者线程 CPU、分配数、队列峰值、丢弃数、drain 和 shutdown 耗时；循环由一个生产线程执行，不是高并发压力测试。基准会做显式 drain，因此它的提交区间与生产环境持续积压场景不同。阅读结果前必须核对当前源码、编译宏、运行参数和机器环境，不要把旧 JSON 数值写成实现保证。

优化前至少回答：

- 目标是降低单次同步调用的 CPU/尾延迟、降低每条记录分配，还是提升后台 sink 消费能力？三者不是同一个瓶颈。
- 在目标并发数、消息长度分布、字段数量、RenderMode、sink 类型、队列容量和磁盘条件下，是否同时记录 P50/P95/P99、Dropped、QueueHighWatermark、CPU 和内存？
- 若调整队列策略、门闩或 worker 数，是否保留了明确的丢弃/背压语义、记录顺序预期、shutdown 排空语义和 sink 错误可观测性？
- 是否将任何同步 sink 写入、等待队列空间或阻塞 drain 引入 Asio 协程/I/O worker？如果是，必须停止并重新设计调用边界。
- 是否改变 `Accepted`、Audit、JSON schema、敏感字段处理或 borrowed text 生命周期？这些都是调用方可见契约，不能当成内部微优化。

## 9. 修改字段、格式或 backend 时的维护清单

- 新增/变更字段：检查 `FieldId`、`FieldName()`、`Fields` 定义、`BuiltinFieldPack`、值类型约束、敏感标记、Human 可见性、长度上限，以及 Structured/Human 输出测试。
- 变更 `ContextState`：覆盖 `With()` 的写时复制和文本拥有语义、`TryWith()` 的 4 槽容量/替换行为、borrowed text 活跃期与异步捕获。
- 变更队列/锁策略：分别记录队列满与门闩竞争时回执、计数器、Audit 行为、flush/drain barrier 与并发尾延迟。
- 变更 shutdown：验证 `BeginShutdown()` 不阻塞、活动调用退出、Asio loop 退出后的 worker join、最终 sink flush、析构位置及文件可重新打开。
- 变更 RenderMode/JSON：视为日志格式契约变更；验证大驼峰键、类型、null 身份、转义、单行输出和旧文件归档。
- 不要用 `FallbackWritten`、`Accepted()` 或序号推断文件已持久化；不要把 `Flush()` 描述为同步确认；不要把 `DrainOnControlThread()` 的 Timeout 描述成全程硬上限。

相关聚焦用例位于 [`DiagnoseFacadeTest.cpp`](../../../../tests/Preview/core/diagnose/DiagnoseFacadeTest.cpp) 和 [`LoggerTest.cpp`](../../../../tests/Preview/core/diagnose/LoggerTest.cpp)。这是导航信息，不表示本次文档变更运行或通过了这些用例。

## 10. 按现象排查

先看单条调用的 `SubmissionReceipt.Status`，再看运行计数器。计数器只给出聚合证据，不能替代调用点和 backend 阶段的追踪。

| 现象/状态 | 先检查 | 可以得出的结论 | 不能据此得出的结论 |
| --- | --- | --- | --- |
| `Filtered` | `RuntimeOptions::Level`、请求 `LogLevel`、是否为 `Audit`/`Critical` | 普通日志未进入格式化和队列阶段。 | 这不是 sink 写失败；通常不会增加 `Dropped`。 |
| `Dropped` | `Dropped(Level)` 增量、`DroppedAudits()`、`QueueHighWatermark()` 和 `QueueCapacity` | 记录未进入 spdlog 队列；Audit 丢弃也会计入 `DroppedAudits()`。 | 当前实现把入队门闩竞争和队列满合并为一个结果/计数，没有公开拆分计数器，不能仅凭 `Dropped` 认定一定是队列容量不足。 |
| `Stopped` | `IsInstalled()`、安装结果、是否已调用 `BeginShutdown()` | facade/backend 不存在或已停止接收新记录。 | 不代表格式串错误或文件 sink 故障。 |
| `Failed` | 同时读取 `FormatFailures()`、`CaptureFailures()`；确认调用是否是 `Drain` | facade 格式化异常会增加 `FormatFailures()`；backend 捕获/渲染/提交异常会增加 `CaptureFailures()`。Drain 的 `Failed` 是 barrier flush 结果。 | `Failed` 本身没有细分错误码；不应假定任何 Failed 都会增加同一个计数器。 |
| `TimedOut` | 是否从控制线程调用了 `DrainOnControlThread()`，队列压力、barrier 队列策略 | barrier 未按等待阶段完成，或共享提交门闩正忙。 | 不是单条日志的提交超时；而且 Timeout 不限制 barrier 的阻塞式入队时间。 |
| `Accepted`，文件暂时没看到 | RenderMode、目录/文件名、异步 worker 是否还有积压、sink 错误计数 | 仅能确定请求进入异步 backend。 | 不能认为它已写到磁盘、已 flush 或遇到进程崩溃仍可恢复。 |
| `SinkFailures()` 增长 | spdlog error handler、文件权限/磁盘空间、轮转、最终 flush 结果 | sink 报错或控制线程最终 flush 失败曾被计数。 | `SinkFailures()==0` 不能证明每条已 Accepted 记录都已持久化。 |

`QueueHighWatermark()` 是观测期间的高水位，不是当前队列深度；`DiagnoseRuntime` 没有公开当前 `QueueSize()` 查询。高水位接近容量且持续增加，支持“消费者跟不上生产者/短时突发”的判断；低高水位同时有 `Dropped`，可能是门闩竞争、短时采样遗漏或队列状态已变化。现有指标不能精确区分这些原因。

### 10.1 推荐诊断顺序

1. 从调用点保存并检查真实回执，不要只看最终文件。
2. 核对 `DiagnoseRuntime::Install()` 是否成功、`IsInstalled()` 当前值和配置的 `Level/RenderMode`。
3. 如果是 `Filtered`，沿生产者向上检查是否还存在调用点自己的采样、条件分支或等级包装函数。
4. 如果是 `Dropped`，记录计数器差值、高水位、队列容量、提交速率和 sink 配置；标明“门闩竞争/队列满尚不能由当前 API 分离”。
5. 如果是 `Accepted` 但尚无文件行，只在非 Asio 控制线程用 drain 做测试/诊断；生产协程只能调用异步 `Flush()`。
6. 检查实际目录、文件名、RenderMode 和 `SinkFailures()`。模式变化时，sink 可能先归档格式不兼容的现有文件。
7. 如果关闭慢，分别测量停止生产者、drain（仅用于受控测试）和最终 join/flush 的耗时；`FinalizeShutdown()` 没有超时接口。

## 11. 测试和基准索引

以下是当前目录中的用例导航。用例名说明测试意图，不代表当前工作树的测试已运行或通过。

| 测试文件 | 适合核对的问题 |
| --- | --- |
| [`ContextStateTest.cpp`](../../../../tests/Preview/core/diagnose/ContextStateTest.cpp) | 空上下文、身份前缀、不可变派生、字段替换、长期字段和第 5 个 per-call 字段的容量错误。 |
| [`ContextLifetimeTest.cpp`](../../../../tests/Preview/core/diagnose/ContextLifetimeTest.cpp) | 捕获后的字段快照能否独立于 coroutine/原上下文继续存活。 |
| [`FieldCodecTest.cpp`](../../../../tests/Preview/core/diagnose/FieldCodecTest.cpp) | UTF-8 边界截断、敏感 descriptor 脱敏、强类型 ID 编码。 |
| [`ContextDecoderTest.cpp`](../../../../tests/Preview/core/diagnose/ContextDecoderTest.cpp) | 三种渲染模式、TraceSelection、字段目录顺序、JSON 转义和敏感字段处理。 |
| [`DiagnoseFacadeTest.cpp`](../../../../tests/Preview/core/diagnose/DiagnoseFacadeTest.cpp) | 格式化、等级入口、回执序号、关闭后提交、消息脱敏和 Human 输出。 |
| [`LoggerTest.cpp`](../../../../tests/Preview/core/diagnose/LoggerTest.cpp) | Structured 字段输出及关闭后文件句柄释放。 |
| [`AsyncBackendInitializationTest.cpp`](../../../../tests/Preview/core/diagnose/AsyncBackendInitializationTest.cpp) | 目录初始化失败和冲突配置。 |
| [`AsyncBackendRotationTest.cpp`](../../../../tests/Preview/core/diagnose/AsyncBackendRotationTest.cpp) | 当前格式日志文件轮转。 |
| [`AsyncBackendQueueTest.cpp`](../../../../tests/Preview/core/diagnose/AsyncBackendQueueTest.cpp) | Access 阈值规则、Error 阈值下 Audit 提交和 EmergencyWriter 脱敏/限长。现有断言没有构造持续满队列或多生产者竞争负载。 |
| [`AsyncBackendFallbackTest.cpp`](../../../../tests/Preview/core/diagnose/AsyncBackendFallbackTest.cpp) | EmergencyWriter 单条应急写入行为；该名字不表示普通 facade 当前会 fallback。 |
| [`AsyncBackendShutdownTest.cpp`](../../../../tests/Preview/core/diagnose/AsyncBackendShutdownTest.cpp) | BeginShutdown 停止新提交、control-thread finalization、重复 finalization。 |
| [`SessionAuditTest.cpp`](../../../../tests/Preview/core/diagnose/SessionAuditTest.cpp) | Session 关闭 Audit 事件的集成路径和一次性断言。 |
| [`ObservabilityTest.cpp`](../../../../tests/Preview/core/diagnose/ObservabilityTest.cpp) | HdrHistogram、EwmaMeter、SampleTracer 的边界行为。 |

在本次静态检查时，`tests/Preview/core/diagnose/*.cpp` 通过 `DrainOnControlThread()` 等待队列的用例可见，但未发现直接调用应用层 `DiagnoseRuntime::Flush()` 的断言；因此不能从这些单元测试推断周期 Flush timer 的行为已经验证。该目录也没有证明多生产者门闩竞争、高并发队列满时的丢弃率或长时间运行稳定性的测试。

### 11.1 当前需要先核实的源码/测试差异

静态对照发现以下断言与当前 renderer 文本不一致。此处记录的是源文件字面差异；本次没有运行测试，不能据此断言整个测试 target 的实际运行结果：

- [`Detail/ContextDecoder.hpp`](Detail/ContextDecoder.hpp) 的 JSON 顶层身份键为 `Worker`、`Session`，不包含操作系统线程号；[`SessionAuditTest.cpp`](../../../../tests/Preview/core/diagnose/SessionAuditTest.cpp) 检查大驼峰身份键与 `SessionClosed` 消息。
- `RuntimeOptions.hpp::LogLevelName()` 返回 PascalCase 等级名；`AsyncSubmission.hpp::BuildPayload()` 将等级标签写在 Human 正文前。对应输出断言位于 [`DiagnoseFacadeTest.cpp`](../../../../tests/Preview/core/diagnose/DiagnoseFacadeTest.cpp) 和 [`ContextDecoderTest.cpp`](../../../../tests/Preview/core/diagnose/ContextDecoderTest.cpp)。

未来 AI 修改日志 schema 或更新测试时，应先决定“当前源码实现”与“已有测试预期”哪一方代表批准的目标，再把两者同步；不要为了让文档或旧断言看起来一致而擅自修改 renderer。

## 12. 面向 AI 的工作流程

收到 Diagnose 相关任务时，按下面顺序收集可核对证据：

1. **界定问题**：确认目标是漏日志、级别筛选、字段/文本错误、性能、队列丢弃、sink 写入还是停机卡住。不要把这些现象都归结为“日志库慢”。
2. **找调用点**：本仓库根目录有 `.codegraph/`，按根级 `AGENTS.md` 的要求先用 CodeGraph 查询符号和调用链，再读当前源码确认实现。从生产者追到具体的 `Trace/Debug/Info/Access/Warn/Error/Critical/Audit` 调用；记录调用点是否有额外 if、采样或 `TryWith()` 错误处理。
3. **沿边界追踪**：按 1.2 的顺序核对 `Facade.hpp`、`DiagnoseRuntime.hpp`、`BackendLifecycle.hpp`、`BackendBridge.hpp`、`ContextDecoder.hpp`、`AsyncSubmission.hpp`、`SinkSet.hpp`，只追与问题相关的阶段。
4. **区分契约层次**：说明一项结论来自源码实现、测试断言、实际运行观测，还是基于指标的推测。特别区分 `Accepted`、队列写入、sink 写入和最终 flush。
5. **核对生命周期**：涉及文本字段时确认 borrowed/owned；涉及线程时确认协程/Asio worker/control thread；涉及 backend 时确认唯一 owner 和 shutdown 的调用线程。
6. **选择对应证据**：从第 11 节选窄用例或基准；检查断言本身是否与当前源码一致。若用户没有要求执行测试/构建，不要把阅读用例说成运行通过。
7. **改动后更新契约**：任何 public status、filter、字段目录、JSON schema、queue overflow、flush/shutdown 变化都应更新本文件对应章节和测试；结果中列出实际执行的验证命令与未验证项。

推荐在 AI 的诊断结果中使用以下结构：

```text
观察到的事实：<当前回执/计数器/源码分支/测试断言>
推断：<由上述事实支持的解释，标记为推断>
未能证明：<当前指标或用例无法区分的情况>
下一项最小验证：<目标日志调用、断言、测量窗口或控制线程 drain>
```

不要从日志文本反推完整状态机，除非状态转移由代码或结构化字段明确给出；Message 是业务提供的自由文本，不是强类型 schema。跨版本比较 JSONL 时先核对字段名、类型、RenderMode 和等级名。

## 13. 性能实验记录模板

每次比较优化前后至少保存这些条件，避免把不同工作负载或不同源码的数字直接比较：

```text
源码 revision / 工作树改动：
编译器、版本、配置和优化选项：
RenderMode：
Console / sink 类型：
QueueCapacity：
生产者线程数：
每线程提交数和持续时间：
消息长度分布（均值 / P95 / 最大）：
每条记录设置字段数和文本字段长度：
日志等级及过滤比例：
目标磁盘 / 文件系统 / 轮转设置：
Facade submit P50 / P95 / P99：
生产者 CPU、分配次数和分配字节：
每秒提交 / Accepted / Dropped：
QueueHighWatermark：
Drain 耗时 / 最终 Shutdown join+flush 耗时：
运行次数、预热方式和方差：
```

`DiagnosePathBenchmark.cpp` 当前预热 10000 次，每个 repetition 执行 20000 次，共 5 轮；消息长度为 128、512、2048 字节。它用单个 producer 调用 `Info()`，记录单次提交时间分位数、producer thread CPU、调用线程的 `operator new` 次数、队列高水位、Dropped Info、drain 和 shutdown 时间。分配次数不是分配字节数，也不覆盖后台 worker 的 thread-local 分配计数；该基准不提供多线程竞争、生产环境磁盘分布或长期稳态证据。

作为容量估算的初步模型，如果稳定消费速率为 `mu` 条/秒、突发生产速率为 `lambda` 条/秒且 `lambda > mu`，忽略门闩竞争和 flush/barrier 占槽时，容量 `C` 大约能承受 `C / (lambda - mu)` 秒的突发。这个公式只用于设置实验范围：门闩竞争可以在队列未满时直接丢弃；消息长度不同会使同样的条目容量占用不同内存；增大容量不会提升单 worker 消费速度，而且可能增加驻留内存、排队延迟和最终关闭时间。
