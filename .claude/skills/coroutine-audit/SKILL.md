---
name: coroutine-audit
description: 修改 Prism 协程、异步 I/O、定时器或事件循环驱动代码时，审查纯协程约束和任务完成路径。
---

# 协程纯度审计

## 触发条件

- 新增或修改 `co_await`、`co_return`、`co_spawn` 或 `net::awaitable`
- 修改 socket、resolver、timer、channel 或 worker 事件循环
- 修改异步测试的启动、停止、取消和异常处理

## 审计流程

1. 找出协程入口、调用的异步操作和任务持有者。
2. 检查每个 I/O 是否通过 Asio 异步 API 完成。
3. 检查错误、取消、超时和正常完成是否都能退出或通知等待者。
4. 检查 `co_await` 前后引用、迭代器、裸指针和 executor 关联是否仍有效。
5. 检查 detached 任务是否有明确的 L1/L2/L3/L4 所有权边界。

## 禁止项

- `std::mutex`、`std::lock_guard`、阻塞 socket 操作
- `std::this_thread::sleep_for`、同步 `getaddrinfo`、忙等待
- 在协程内调用可能阻塞的文件、进程或 DNS API
- 用 `poll()`、`run_for()` 代替完整的测试事件循环
- 启动无人监听且无人记录异常的 detached 任务

## 重点检查

- timer 和 socket 取消后，错误码是否按预期传播。
- 多个操作竞争同一状态时，是否使用 executor/strand/原子状态，而不是阻塞锁。
- `co_spawn` 的 completion handler 是否处理异常，或者明确采用受控的 `net::detached`。
- 协程停止后，所有 channel、socket 和 timer 是否被关闭或取消。
- 测试是否使用 `net::co_spawn(...); ioc.run();` 驱动完整生命周期。

## 验证

优先运行对应的单元或集成测试；需要构建时遵守 `AGENTS.md` 的授权、统一 `build/` 目录和线程规则。审计结论必须列出实际入口、挂起点、所有权依据和未覆盖的取消路径。

## 相关 Skill

对象存活和 detached 资源见 `co-lifecycle-audit`，跨线程状态见 `concurrency-audit`，错误传播见 `error-chain-audit`。
