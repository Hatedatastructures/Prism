# Preview Lifecycle

`Preview/Lifecycle/` 提供 tracked task、取消域、关闭预约和真实 drain 原语。它负责记录与等待工作项的生命周期，不替任务、stream 或 protocol owner 关闭传输。

## 职责与非职责

- [`TaskRegistry`](../../../Preview/Lifecycle/TaskRegistry.hpp) 在固定 executor 上跟踪 task、父子 scope、取消和退休状态。`CreateChild` 创建子 registry；`Cancel` 发布取消请求；`Seal` 封止新提交；`Drain` 等待已登记任务实际退出。
- [`TaskHandle`](../../../Preview/Lifecycle/TaskRegistry.hpp) 是稳定身份、结果和状态的观察句柄。释放 handle 不取消 task；`RequestCancel` 只请求一次取消 hook；`WaitForRetirementAsync` 等待清理及 completion handler 真正退栈。
- [`CancellationDomain`](../../../Preview/Lifecycle/CancellationDomain.hpp) 在绑定 executor 上发布取消树信号，支持弱观察者和子节点。取消只唤醒/打断操作，不表示半关闭、传输关闭或 owner 已排空。
- [`DrainBarrier`](../../../Preview/Lifecycle/DrainBarrier.hpp) 以真实活动计数和 executor 通知等待 owner 归还预约。`Seal` 后拒绝新进入；`Leave` 只在真实 owner 结束时减计数；`Blocked`、executor 错误或取消都不会伪造计数清零。

Lifecycle 不拥有具体协议的 wire、账户 lease、stream half-close 或 socket final close。实际资源 owner 必须在收到取消后继续完成关闭和清理，并持有 registry/barrier 所需对象直到 drain 返回。

## 配置与生产接入

Lifecycle 没有独立的 JSON 配置字段，也不直接绑定 provider。WorkerResources 为 worker 创建 root TaskRegistry；Runtime listener/session、Transport activity 和 protocol admission 在各自 owner 已确定 executor 后使用 task/barrier 原语登记活动。Composition 的 provider prepare/freeze/bind 是冷路径，Lifecycle 只协助实际 owner 管理运行期工作与 retirement，不负责选择协议。

实际 worker root registry 的创建位置见 [WorkerResources.hpp](../../../Preview/Resource/WorkerResources.hpp)；Runtime listener/session、Transport activity 和 protocol admission 则在各自 owner/executor 已确定后创建活动任务或 drain reservation。

## Executor、错误与 drain 约定

task 的取消 hook 回到原 task executor 执行。`CancellationDomain` 的树链接与取消信号也在其绑定 executor 发出；跨线程操作通过 `ExecutorReclaimer` 投递，投递失败会留下可观察的 blocked 状态。`DrainBarrier` 通过 reclaimer 固定 executor，并用 `ContextOwner` pin 保护 wait/channel 所需的执行上下文。

公开等待通常返回 `std::expected<void, Preview::Fault::Failure>`。计数未归还、通知投递失败、context 不可调度或清理结果失败都会保留失败，而不当成完成。Task handle 的逻辑完成状态和 retirement receipt 是不同事实：任务函数结束后，handler、关闭预约和资源仍可能未退栈。取消、半关闭、最终关闭与 drain 的区别见[所有权与生命周期](../ownership-and-lifecycle.md)。

## 当前源码与 CMake 依赖

重点源码包括 [`CancellationDomain.hpp`](../../../Preview/Lifecycle/CancellationDomain.hpp)、[`DrainBarrier.hpp`](../../../Preview/Lifecycle/DrainBarrier.hpp)、[`DrainReservation.hpp`](../../../Preview/Lifecycle/DrainReservation.hpp)、[`TaskReservation.hpp`](../../../Preview/Lifecycle/TaskReservation.hpp)、[`TaskSubmission.hpp`](../../../Preview/Lifecycle/TaskSubmission.hpp)、[`TaskRegistry.hpp`](../../../Preview/Lifecycle/TaskRegistry.hpp) 及 TaskRegistry 的 State/Commands/RetirementReceipt 支持头。

[`Preview/CMakeLists.txt`](../../../Preview/CMakeLists.txt) 将这些头登记在 `PreviewLifecycle` `INTERFACE` target，并只直接链接 `PreviewFoundation`。`PreviewResource`、`PreviewRuntime`、Transport 与 protocol targets 按各自 owner 通过此公共生命周期层链接；Lifecycle 不依赖 Application、Composition 或具体协议装配。

## 测试位置与证据边界

[`tests/Preview/Lifecycle/CMakeLists.txt`](../../../tests/Preview/Lifecycle/CMakeLists.txt) 登记 `TaskRegistryTest`、`TaskRegistryDanglingOwnerAuditTest`、`TaskRegistryCoreLifecycleTest`、`TaskRegistryDrainLifecycleTest`、`TaskOwnershipLifecycleTest` 和 `TaskIdSetTest`。Runtime 的 session control/delivery 测试还会使用 task registry，但不改变生产 owner。

这些路径只列当前源码与 CMake 测试映射，不登记测试或运行结果。本页不声称通过；通过结论只能来自与当次源码、配置和 binary hash 绑定的验收报告，取消与关闭时序也按该报告判断。
