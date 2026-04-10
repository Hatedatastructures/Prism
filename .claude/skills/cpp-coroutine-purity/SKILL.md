---
name: cpp-coroutine-purity
description: 协程纯度审计。Prism 是纯协程架构，禁止在协程中使用任何阻塞调用、互斥锁、忙等待等会阻塞 io_context 线程的操作。编写或修改 C++ 代码时必须遵循此规范。
---

# Skill: 协程纯度审计

Prism 采用 **每线程一个 io_context** 的纯协程架构。每个 worker 线程运行一个 `io_context`，所有 I/O 操作通过协程异步完成。**任何阻塞调用都会卡住整个 worker 线程**，导致该线程上所有会话停滞。

## 触发条件

编写或修改 C++ 代码时，涉及以下场景必须检查：
- 新增函数或协程
- 修改异步操作相关代码
- 引入新的第三方库调用
- 修改网络 I/O、文件 I/O、定时器相关代码

## 禁止清单

### 1. 互斥锁与同步原语

| 禁止 | 替代方案 |
|------|----------|
| `std::mutex` / `std::lock_guard` / `std::unique_lock` | `std::atomic`（无锁）、`strand`（序列化）、`concurrent_channel`（异步通信） |
| `std::shared_mutex` / `std::shared_lock` | 多线程只读无需锁；写操作用 `strand` 包装 |
| `std::condition_variable` | `net::steady_timer`（异步等待）、`concurrent_channel`（异步通知） |
| `std::semaphore` / `std::latch` / `std::barrier` | 仅限非协程的 stress test 代码中使用 |

**唯一例外**：`std::pmr::synchronized_pool_resource`（全局池，由 PMR 内部管理）。

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
| `SpinLock` / 自定义自旋锁 | `std::atomic` + `net::steady_timer` 或 `concurrent_channel` |

### 4. 跨线程阻塞调用

| 禁止 | 替代方案 |
|------|----------|
| `thread.join()` 在协程中调用 | 使用 `std::jthread`（自动 join）或 `net::post` 异步通知 |
| `std::thread` 创建后同步等待结果 | `net::post` + `co_await` 或 `concurrent_channel` |
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
// Prism 的 worker 线程模型保证同一 io_context 上的协程不会并发
closed_.store(true, std::memory_order_release);
```

### 异步通知替代条件变量

```cpp
// ❌ 禁止：条件变量
std::unique_lock lock(mutex_);
cv_.wait(lock, [&] { return !queue_.empty(); });

// ✅ 正确：concurrent_channel
auto item = co_await channel_.async_receive(net::use_awaitable);
```

### CAS 带降级（yamux 窗口模式）

```cpp
// ✅ 正确：CAS 快路径 + 异步等待慢路径
while (!acquired && active())
{
    auto old = window.load(std::memory_order_acquire);
    if (old >= needed && window.compare_exchange_weak(old, old - needed))
    {
        acquired = true;
        break;
    }
    // 降级到异步等待，不忙等
    co_await signal->async_wait(net::use_awaitable);
}
```

## 审计流程

修改代码后逐项检查：

1. **扫描新增调用**：搜索所有函数调用，识别上述禁止清单中的函数
2. **检查协程边界**：所有返回 `net::awaitable<T>` 的函数内部不得包含阻塞调用
3. **检查回调内阻塞**：lambda 回调（如 `co_spawn` 的 completion handler）内也不得阻塞
4. **验证第三方调用**：新增的库调用是否文档标注为线程安全且非阻塞
5. **确认定时器模式**：所有延迟/等待逻辑是否使用 `net::steady_timer`

## 项目特有约定

- **Worker 线程模型**：每个 worker 运行一个 `io_context`，同一线程上的协程天然串行，无需互斥
- **concurrent_channel**：跨流通信使用 `net::experimental::concurrent_channel`，内部有锁但不阻塞 io_context（等待时协程挂起）
- **原子操作足够**：`std::atomic` 配合 `memory_order` 可以满足大部分跨协程状态同步需求
- **spdlog 已是异步**：项目使用 `async_logger`，日志调用本身不阻塞（写入环形队列后返回）
