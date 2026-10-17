# Statistics 模块

## 职责与边界

Statistics 拥有数值统计 API、稀疏计数表、有界历史和事件环。数据面通过 Foundation 的 `TrafficSink`/`RecognitionLatencySink` 提交数值事件；运行时统计 owner 将 worker producer 的有界队列刷新到控制 executor 上的唯一计数表。

本模块不拥有代理连接或任务本身，不将账户凭据或显示 identity 作为统计键，也不据统计丢失改写业务成功/失败。事件和快照只保留值及数值身份，不保活业务 owner。

## 关键源码

- [Types.hpp](../../../Preview/Statistics/Types.hpp)、[Snapshots.hpp](../../../Preview/Statistics/Snapshots.hpp)：scope、metric、事件和查询快照值。
- [SparseCounters.hpp](../../../Preview/Statistics/SparseCounters.hpp)、[TrafficDelta.hpp](../../../Preview/Statistics/TrafficDelta.hpp)：唯一稀疏计数表与 worker-local bounded batch。
- [EventRing.hpp](../../../Preview/Statistics/EventRing.hpp)、[History.hpp](../../../Preview/Statistics/History.hpp)：有界详细事件和流量历史。
- [Statistics.hpp](../../../Preview/Statistics/Statistics.hpp)：统计模块聚合入口。
- [Foundation/Utility/TrafficSink.hpp](../../../Preview/Foundation/Utility/TrafficSink.hpp)、[Runtime/Statistics.hpp](../../../Preview/Runtime/Statistics.hpp)、[Runtime/SessionServices.hpp](../../../Preview/Runtime/SessionServices.hpp)：数据面观察契约、运行时计数器和会话服务注入。
- [Application/OperationsMetrics.hpp](../../../Preview/Application/OperationsMetrics.hpp)、[Application/OperationsEventProducer.hpp](../../../Preview/Application/OperationsEventProducer.hpp)：管理查询与操作事件 producer。

## include 与 CMake 依赖

- `Preview/CMakeLists.txt` 将 Statistics 的 counters、event ring、history、snapshots、sparse counters、traffic delta 和 types 登记到 `PreviewStatistics` INTERFACE target；它依赖 `PreviewFoundation`。
- `PreviewRuntime` 消费 `PreviewStatistics`，并实现 `TrafficSink` 数值观察；`PreviewOperations` 也消费统计 target 以提供管理查询。当前 Composition 的 CMake 还因 C05 过渡边依赖 Statistics，详见 [Composition 页面](composition.md)。
- 测试由 [tests/Preview/Statistics/CMakeLists.txt](../../../tests/Preview/Statistics/CMakeLists.txt) 登记；HTTP 查询另在 Operations tests 覆盖。

## 当前数据流

1. `SessionServices` 和中间件 Context 持有 `shared_ptr<TrafficSink>`；另有可选 recognition latency sink。数据面按真实 generation、worker、session、stream、task 和 account 数值 id 报告增量/终态，不报告凭据或显示名称。
2. `Runtime::TrafficCounter::Report` 按 worker 数值槽写入固定容量无锁队列；队列满、worker id 不合法、generation 不再保留或 owner 已封止时只记录观察丢弃。
3. Application 控制 executor 刷新队列，将累计值写入 `SparseCounters`；只有真实 flush 会追加 `TrafficHistory` 样本。动态 session/stream/task owner 在实际业务 owner drain 后调用统计退休，失败留下 typed 失败观察并保留相应键。
4. Application 的操作事件 producer 把管理命令接受/终态转成 `DetailedEvent` 追加到 `EventRing`。Operations 查询使用计数、历史和事件的值快照。

## 所有权、错误与执行器

- `TrafficCounter` 拥有 worker 队列、稀疏计数表、history 和控制 executor reclaimer；`Report` 要求非阻塞、无分配、`noexcept`，满队列只丢观察。
- `SparseCounters`、`TrafficHistory`、`EventRing` 的写入/刷新由 Application 控制 executor 独占；分页/快照在查询边界返回 owning value。
- 计数容量拒绝、数值溢出、队列丢弃和事件覆盖有独立计数/状态。统计失败不改变实际关闭结果；`Retire` 返回 `Fault::Failure`，调用者先完成真实 owner 关闭与 producer drain。
- Statistics 不执行 socket cancel、stream half-close 或最终 close；这些仍归产生统计事件的业务 owner。

## 配置支持、生产接线与运行证据

- **模型与配置支持：** `StatisticsConfiguration` 位于 [PreviewConfiguration.hpp](../../../Preview/Application/Configuration/PreviewConfiguration.hpp)；统计 scope、metric 与快照形状由本模块类型定义。
- **生产接线：** Application RuntimeState 创建 EventRing，运行时 session service 将 `TrafficSink` 注入数据面，Operations handler 读取控制面统计 owner；这些是生产代码接线，不是运行结果记录。
- **运行证据边界：** 本页只列源码接线与测试映射，不登记 build、CTest、运行或互操作结果；通过结论只能来自绑定当次源码、配置和 binary hash 的验收报告。本页不声称通过。

## 测试位置

- [tests/Preview/Statistics](../../../tests/Preview/Statistics/)：统计 API 和设置相关测试。
- [tests/Preview/Operations](../../../tests/Preview/Operations/)：统计查询和 HTTP 序列化路径。
- 根登记见 [tests/Preview/CMakeLists.txt](../../../tests/Preview/CMakeLists.txt)。
