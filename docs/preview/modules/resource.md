# Preview Resource

`Preview/Resource/` 放置进程、worker、session 和 stream 级的资源 owner/句柄。它不是旧版 Prism 的层级 PMR 别名，也不把 session/stream 的非拥有句柄解释成父 owner。

## 所有权模型

| 类型 | 当前持有内容 | 不拥有的内容 |
| --- | --- | --- |
| [`ProcessResources`](../../../Preview/Resource/ProcessResources.hpp) | process/generation ID、process memory resource、共享有界 `BytePool` 与 stopping 状态 | 不替 worker/session 执行关闭；具体服务由 Runtime/Application owner 管理。 |
| [`WorkerResources`](../../../Preview/Resource/WorkerResources.hpp) | worker identity、独立 `ContextOwner`/IoContext/PMR pool、scheduler、dial service、root `TaskRegistry`、work guard 和统计 | 不替 session 或 protocol owner 关闭其 I/O；正常停机须先处理 task 和 DNS owner。 |
| [`SessionResources`](../../../Preview/Resource/SessionResources.hpp) | process/worker/generation/session typed ID、executor 和 PMR 非拥有句柄 | 不拥有 process 或 worker。 |
| [`StreamResources`](../../../Preview/Resource/StreamResources.hpp) | stream/session/worker/generation typed ID、executor 和 PMR 非拥有句柄 | 不拥有父级资源，也不创建 detached 生命周期。 |

Process 的 BytePool 由真实 shared pointer/lease 保活，不按连接重复建最大预算存储。正常 worker 关闭由 `WorkerGroup::Shutdown` 先 drain task，再关闭 dial/DNS owner 并检查 executor/storage fence。`WorkerResources::Stop` 只在确认 root registry 为空时尝试退休任务；否则它会请求取消并停止 IoContext，这个紧急路径不证明在途 task 或 transport 已关闭。Session/stream 记录只是交给更高层 owner 使用的值句柄；协议连接、stream 和传输的最终关闭权仍由实际 session/protocol owner 持有。

当前 [`Resource.hpp`](../../../Preview/Resource/Resource.hpp) 只包含 `ExecutorReclaimer`。它不是 `ProcessResources`、`WorkerResources`、`SessionResources`、`StreamResources` 的聚合入口；使用这些类型应包含各自精确头文件。

## Executor、错误与关闭边界

`WorkerResources` 通过 `ContextOwner` pin IoContext 与 PMR pool，并提供 scheduler executor、TaskRegistry 和 worker-local dial service；`SessionResources`/`StreamResources` 只保存 executor 副本及非拥有 PMR pointer，不能单独延长父级 owner 寿命。资源结构自身不定义 protocol error、取消 signal、stream half-close 或底层 socket final close；这些操作返回的 typed failure 和 drain receipt 归 Worker、Runtime、Lifecycle、Transport 或具体 protocol owner。正常 worker shutdown 由 [`WorkerGroup::Shutdown`](../../../Preview/Runtime/WorkerGroup.hpp) 先关闭 admission，再等待每个 worker task drain 与 executor/storage fence；紧急 `Stop` 不证明任务或传输已关闭。

## 构造、依赖与调用路径

这些类型不对应配置 JSON 中的独立字段。Application/Runtime 在构造 process 和 workers 时，将 generation、executor、memory pool 与服务按值或 owning handle 装入资源对象；session/stream 资源值随后由上层 task/session owner 传递。协议页中引用资源类型时，应继续检查它们是否为 owning shared pointer、值句柄、PMR 非拥有 pointer 或 lease。

[`Preview/CMakeLists.txt`](../../../Preview/CMakeLists.txt) 将 Process/Worker/Session/Stream resource headers 和 `Resource.hpp` 登记在 `PreviewResource` `INTERFACE` target，并链接 `PreviewFoundation` 与 `PreviewLifecycle`。`PreviewRuntime` 使用 `PreviewResource` 和 Lifecycle；依赖具体协议的代码不应反向放入 Resource。

## 测试位置与证据边界

当前没有单独的 `tests/Preview/Resource/` 子树。worker resource 的生命周期场景归在 [`tests/Preview/Runtime/WorkerGroupTest.cpp`](../../../tests/Preview/Runtime/WorkerGroupTest.cpp)；memory primitive 的场景在 [`tests/Preview/Foundation/Memory/`](../../../tests/Preview/Foundation/Memory/CMakeLists.txt)，task/resource retirement 的场景在 [`tests/Preview/Lifecycle/`](../../../tests/Preview/Lifecycle/CMakeLists.txt)。测试映射按实际被测 owner 看待，而不把这些路径伪装成 Resource 专属 target。

上述路径只列资源源码与测试映射，不登记测试结果。本页不声称资源清理、PMR 生命周期或运行期内存行为通过；任何通过结论只能来自与当次源码、配置和 binary hash 绑定的验收报告。
