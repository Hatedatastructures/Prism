---
name: co-lifecycle-audit
description: 修改 shared_ptr、enable_shared_from_this、co_spawn 捕获或 co_await 后资源访问时，审查 Prism 对象和资源生命周期。
---

# 协程生命周期审计

## 审计范围

- `enable_shared_from_this`、`shared_ptr`、`unique_ptr` 和自定义 RAII 对象
- `co_spawn` lambda 的捕获、session/worker/process 资源引用
- `co_await` 前后引用、迭代器、span、string_view 和 executor
- detached 协程、关闭顺序、容器擦除和移动操作

## Prism 所有权模型

- L1：进程级资源，可被 worker 和 session 使用。
- L2：worker 级资源，只能由所属 worker 生命周期覆盖。
- L3：session 级资源，只能在 session 存活期间使用。
- L4：detached 任务必须拥有独立资源，禁止保存 L3 的引用、指针或 allocator。

## 审计步骤

1. 标记每个协程入口和所有异步挂起点。
2. 说明每个跨挂起点对象的拥有者、存活保证和释放时机。
3. 检查 lambda 是否按值捕获必要的拥有句柄；不要机械要求所有任务都捕获 `self`。
4. 检查 `co_await` 恢复后是否重新获取可能失效的引用和迭代器。
5. 检查 `erase`、rehash、move、socket close 和 coroutine cancellation 的边界。
6. 检查 PMR 容器使用的 memory resource 是否覆盖整个使用期。

## 常见风险

- lambda 只捕获裸指针，拥有者在挂起期间释放。
- 保存容器元素引用后跨 `co_await`，期间发生 `erase` 或重分配。
- detached 协程引用 session 的日志、统计、allocator 或 socket。
- 移动后源对象仍被使用，或析构函数重复释放资源。
- 关闭流程只关闭 socket，没有取消等待中的 timer、channel 或子任务。

## 验证

审计报告必须给出对象所有者、挂起点、取消路径和修复建议。修改 detached 协程或 PMR allocator 后，运行 `scripts/audit_detached.sh` 及相关生命周期测试。

## 相关 Skill

协程操作纯度见 `coroutine-audit`，并发状态见 `concurrency-audit`，PMR 细节见 `audit-memory`。
