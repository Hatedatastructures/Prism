---
name: coroutine-audit
description: 修改协程（co_await/co_return/co_spawn）、异步 I/O、定时器、多线程相关 C++ 代码时触发。
---

# Skill: 协程纯度审计

采用 **每线程一个 io_context** 的纯协程架构。每个 worker 线程运行一个 `io_context`，所有 I/O 操作通过协程异步完成。**任何阻塞调用都会卡住整个 worker 线程**，导致该线程上所有会话停滞。

## 触发条件

修改以下类型的 C++ 代码时必须检查：
- 新增或修改协程函数（`co_await`/`co_return`/`co_yield`）
- 修改 `co_spawn`、`net::detached`、回调 lambda 相关代码
- 修改异步 I/O 操作（`async_read`/`async_write`/`async_connect`）
- 修改定时器相关代码（`net::steady_timer`）
- 引入新的第三方库调用（需验证是否阻塞）
- 修改网络 I/O、文件 I/O 相关代码

## 禁止清单

### 1. 互斥锁与同步原语

| 禁止 | 替代方案 |
|------|----------|
| `std::mutex` / `std::lock_guard` / `std::unique_lock` | `std::atomic`（无锁）、`strand`（序列化）、`net::post`（跨线程派发） |
| `std::shared_mutex` / `std::shared_lock` | 多线程只读无需锁；写操作用 `strand` 包装 |
| `std::condition_variable` | `net::steady_timer`（异步等待） |
| `std::semaphore` / `std::latch` / `std::barrier` | 仅限非协程的 stress test 代码中使用 |

**例外**：
- `std::pmr::synchronized_pool_resource`（全局池，由 PMR 内部管理）
- `trace/spdlog` 子系统的日志初始化（非热路径）

### 2. 阻塞系统调用

| 禁止 | 替代方案 |
|------|----------|
| `std::this_thread::sleep_for()` / `sleep_until()` | `net::steady_timer::async_wait()` |
| `::Sleep()` / `usleep()` / `nanosleep()` | `net::steady_timer::async_wait()` |
| 阻塞 socket read/write（`recv`/`send`/`read`/`write`） | `async_read_some`/`async_write_some`/`async_read`/`async_write` |
| `::connect()` 同步连接 | `socket.async_connect()` |
| `::getaddrinfo()` / `gethostbyname()` 同步 DNS | `resolver.async_resolve()` 或自定义异步 DNS 管道 |
| 阻塞文件 I/O（`fread`/`fwrite`/`ifstream`） | `net::io_context` + `boost::asio::streambuf` 或异步文件库 |
| `std::future::get()` / `std::future::wait()` | `co_await` 异步结果 |

### 3. 忙等待与自旋锁

| 禁止 | 替代方案 |
|------|----------|
| `while (!flag) {}` / `while (flag.load()) {}` | `co_await` 异步等待 + 通知机制 |
| `CAS` 自旋循环（无退出条件） | CAS 带降级：先尝试 CAS，失败则 `co_await` 异步等待信号 |
| `SpinLock` / 自定义自旋锁 | `std::atomic` + `net::steady_timer` |

### 4. 跨线程阻塞调用

| 禁止 | 替代方案 |
|------|----------|
| `thread.join()` 在协程中调用 | 使用 `std::jthread`（自动 join）或 `net::post` 异步通知 |
| `std::thread` 创建后同步等待结果 | `net::post` + `co_await` |
| 在协程中调用 `io_context.run()`/`run_one()` | 所有操作通过 `co_await` 完成 |

### 5. 库函数陷阱

以下函数在协程中**禁止直接调用**，必须使用异步替代：

| 禁止 | 原因 | 替代方案 |
|------|------|----------|
| `OpenSSL::SSL_read()` / `SSL_write()` | 阻塞 | `ssl::stream::async_read_some`/`async_write_some` |
| `getaddrinfo()` | 阻塞 DNS | `resolver::async_resolve()` |
| `getsockname()`/`getpeername()` | 通常非阻塞但依赖内核 | socket 已打开后调用无阻塞风险，但避免在热路径频繁调用 |
| `spdlog` 同步 logger | 可能阻塞写文件 | 使用 `spdlog::async_logger`（项目已配置） |

## 正确模式

### 异步等待替代 sleep

```cpp
// ❌ 禁止：阻塞当前线程
std::this_thread::sleep_for(std::chrono::milliseconds(100));

// ✅ 正确：异步定时器
net::steady_timer timer(executor());
timer.expires_after(std::chrono::milliseconds(100));
co_await timer.async_wait(net::use_awaitable);
```

### 原子操作替代锁

```cpp
// ❌ 禁止：协程中使用互斥锁
std::lock_guard<std::mutex> lock(mutex_);
data_.push_back(item);

// ✅ 正确：使用原子标志 + 单线程保证
// worker 线程模型保证同一 io_context 上的协程不会并发
closed_.store(true, std::memory_order_release);

// ✅ 跨线程派发使用 net::post
net::post(target_ioc, [self = shared_from_this()]()
{
    // 在目标 io_context 上执行
});
```

### 异步 DNS 替代同步解析

```cpp
// ❌ 禁止：阻塞 DNS 解析
auto results = ::getaddrinfo(host.c_str(), nullptr, &hints, &result);

// ✅ 正确：异步 DNS 解析
auto results = co_await resolver.async_resolve(host, port);
```

### CAS 带降级

CAS 失败的降级策略（重试 vs 异步等待 vs 放弃）详见 `concurrency-audit` Section 3（TOCTOU 与 CAS 防御）。本 skill 仅关注"禁止忙等待"，CAS 的正确使用模式由 `concurrency-audit` 覆盖。

## 审计流程

修改代码后逐项检查：

1. **扫描新增调用**：搜索所有函数调用，识别上述禁止清单中的函数
2. **检查协程边界**：所有返回 `net::awaitable<T>` 的函数内部不得包含阻塞调用
3. **检查回调内阻塞**：lambda 回调（如 `co_spawn` 的 completion handler）内也不得阻塞
4. **验证第三方调用**：新增的库调用是否文档标注为线程安全且非阻塞
5. **确认定时器模式**：所有延迟/等待逻辑是否使用 `net::steady_timer`

## 正确模式（高级）

### Deadline 竞速（超时取消）

```cpp
// ✅ 使用 awaitable_operators::operator|| 竞速
// 注意：operator|| 必须通过 ADL 在 using 命名空间后才能用于 awaitable，
//       此处 using 仅限局部作用域且是 Boost.Asio 官方用法，不适用项目
//       "禁止 using namespace" 规则的例外。
using namespace boost::asio::experimental::awaitable_operators;
auto result = co_await (
    recognize(transport) || deadline_timer.async_wait(net::use_awaitable)
);
// recognize 超时后自动取消，协程正常返回
```

### Socket 跨线程迁移

```cpp
// ✅ 将 socket 从 listener 的 io_context 迁移到 worker 的 io_context
auto native_handle = sock.release();
tcp::socket migrated(target_ioc);
migrated.assign(protocol, native_handle, ec);
// 迁移后在新 io_context 上启动协程
net::post(target_ioc, start_session(std::move(migrated)));
```

### co_spawn 带完成处理

```cpp
// ✅ 带异常捕获的 co_spawn
net::co_spawn(ioc, std::move(process),
    [](std::exception_ptr eptr)
    {
        try
        {
            if (eptr)
            {
                std::rethrow_exception(eptr);
            }
        }
        catch (const psm::exception::deviant& e)
        {
            /* 业务异常 */
        }
        catch (const std::exception& e)
        {
            /* 系统异常 */
        }
    });
```

### co_spawn 带取消信号

```cpp
// ✅ 绑定取消槽，可从外部取消协程
auto cancel_signal = std::make_shared<net::cancellation_state>();
net::co_spawn(executor, std::move(relay_coro),
    net::bind_cancellation_slot(cancel_signal->slot(), net::detached));

// 需要取消时
cancel_signal->emit(net::cancellation_type::all);
```

### 定时器带错误重定向

```cpp
// ✅ 避免 timer 取消时抛异常
net::steady_timer timer(co_await net::this_coro::executor);
timer.expires_after(timeout);
boost::system::error_code ec;
co_await timer.async_wait(net::redirect_error(net::use_awaitable, ec));
if (ec == net::error::operation_aborted)
{
    /* 正常取消 */
}
```

## 约定

- **Worker 线程模型**：每个 worker 运行一个 `io_context`，同一线程上的协程天然串行，无需互斥
- **跨线程派发**：使用 `net::post(target_ioc, handler)` 将任务派发到目标线程
- **原子操作足够**：`std::atomic` 配合 `memory_order` 可以满足大部分跨协程状态同步需求
- **spdlog 已是异步**：项目使用 `async_logger`，日志调用本身不阻塞（写入环形队列后返回）

## 交叉引用

- `enforce-coding` 覆盖了本 skill 未深入探讨的 C++ 编码规范、命名约定、代码结构约束维度
- `co-lifecycle-audit` 覆盖了协程对象生命周期悬挂、shared_ptr 捕获、co_await 后引用失效维度
- `audit-memory` 覆盖了本 skill 未深入探讨的 PMR 内存分配安全、容器生命周期维度
- `concurrency-audit` 覆盖了本 skill 未深入探讨的原子操作内存序、CAS 降级策略、定时器生命周期维度 — 本 skill 管"禁止什么"，concurrency-audit 管"允许但要用对"
