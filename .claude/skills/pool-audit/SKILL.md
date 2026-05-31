---
name: pool-audit
description: 修改连接池、资源池的 checkout/checkin 逻辑、健康检查、驱逐策略、资源上限配置时触发。
---

# Skill: 连接池资源审计

连接池是有限网络资源的缓存和复用机制。与普通缓存不同，连接池中的资源是有状态的（TCP 连接、TLS 会话），泄漏不仅是内存浪费——文件描述符耗尽会导致整个服务无法接受新连接。连接池审计的核心原则只有两条：**每条路径都归还**，**归还的连接仍然有效**。

## 触发条件

- 修改连接池的 checkout（借出）/checkin（归还）逻辑
- 修改连接健康检查或有效性验证代码
- 修改连接驱逐或空闲回收策略
- 修改池大小上限或资源限制配置
- 修改使用池连接的上层代码（连接建立、隧道转发等）
- 新增连接复用策略

## 核心原理

### 归还保证是连接池的生命线

连接池中的每个 checkout 必须在某个时刻对应一个 checkin。如果存在任何代码路径（成功、失败、异常、协程取消）跳过了 checkin，该连接永久丢失。泄漏在低负载下不明显，但在长时间运行的服务中会逐步累积，最终耗尽文件描述符。

"所有路径都归还"的审计需要枚举 checkout 之后的所有退出路径。协程架构中尤其需要关注取消路径——如果持有连接的协程被取消（连接关闭、服务停止），连接归还必须在 RAII 析构中保证，而非依赖手动调用。

### 健康检查是一致性窗口

健康检查在"检查"和"使用"之间打开了一个时间窗口：检查时连接有效，使用时连接可能已失效（对端关闭、网络中断）。这个窗口无法完全消除，但可以通过原子化的检查-驱逐和合理的重试策略来缩小。

## 审计清单

### 1. 归还保证

| 检查项 | 说明 |
|--------|------|
| **RAII 归还模式** | checkout 返回的连接是否通过 RAII 包装器（如 `unique_ptr` 自定义删除器、`scope_guard`）保证归还？手动调用 checkin 不可靠——任何中间的异常或提前返回都会跳过归还 |
| **取消路径的归还** | 持有连接的协程被取消时，连接是否在 RAII 析构中归还？`co_await` 恢复后检查取消状态并提前返回时，必须确保 RAII 包装器仍然有效 |
| **checkout 失败的资源回收** | checkout 过程中分配了部分资源后失败（如建立了 TCP 连接但 TLS 握手失败），部分资源是否正确回收？部分失败的资源如果不归还池，等同于泄漏 |
| **移动语义与归还** | 连接对象被 `std::move` 后，原对象的 RAII 析构是否仍然触归还？如果移动构造函数转移了归还责任但原对象的析构仍然尝试归还，会导致双重归还 |

### 2. 健康检查一致性

| 检查项 | 说明 |
|--------|------|
| **非破坏性检测** | 健康检查是否是非破坏性的？TCP peek（预读不消耗数据）是常用方法，但 TCP FIN 不产生可读数据——peek 无法检测对端已发送 FIN 的情况。需要理解每种检测方法的局限性 |
| **模式恢复** | 健康检查临时修改连接状态（如设置非阻塞模式）后，是否在所有路径（成功/失败/异常）恢复原始状态？未恢复的模式变更会影响后续的正常读写操作 |
| **检查与驱逐的原子性** | 健康检查失败后的驱逐操作是否原子化？如果检查和驱逐之间存在窗口，另一个 checkout 可能获取了已标记为驱逐的连接 |
| **驱逐期间的活跃使用** | 空闲超时驱逐的连接是否可能正在被使用？如果驱逐定时器触发的回收与活跃的 checkout 存在竞争，需要用标志或引用计数保护正在使用的连接 |

### 3. 资源上限

| 检查项 | 说明 |
|--------|------|
| **池大小可配置** | 池的最大连接数是否可配置？硬编码的上限无法适应不同部署规模。配置中应包含：最大总连接数、每个目标的最大连接数 |
| **单目标连接数限制** | 是否有单个目标地址的连接数限制？如果没有，对单个上游的连接可能耗尽整个池，导致其他目标无法获取连接 |
| **空闲超时合理性** | 空闲连接的最大存活时间是否合理？过短导致频繁重建连接（增加延迟），过长导致对端已关闭但池中仍保留死连接。合理的超时应小于对端 TCP keepalive 的间隔 |
| **等待超时** | 池耗尽时，checkout 的等待是否有超时？无限等待会导致调用方挂起。超时后应返回错误（而非静默等待），让调用方决定是否直接建立新连接 |

### 4. 并发安全

| 检查项 | 说明 |
|--------|------|
| **checkout/checkin 线程安全** | 如果池被多个 worker 线程共享（通常不推荐），checkout 和 checkin 是否线程安全？推荐架构是每个 worker 有自己的池，避免跨线程竞争 |
| **统计与实际的一致性** | 池中维护的"活跃连接数"统计是否与实际的 checkout 计数一致？如果统计和实际使用不同的同步机制，可能出现统计与实际不一致的情况 |
| **清理协程的启动时序** | 池的内部清理协程（驱逐空闲连接）是否在事件循环启动之前创建？如果清理协程在第一次 checkout 时才懒创建，可能在需要清理时事件循环尚未运行 |

## 审计流程

1. **绘制归还路径图**：对每个 checkout 点，枚举所有退出路径（成功/失败/异常/取消），验证每条路径都归还连接
2. **验证 RAII 包装器**：检查 checkout 返回的 RAII 包装器的析构函数是否在所有条件下都调用 checkin
3. **评估健康检查**：检查健康检查方法的局限性和恢复保证
4. **验证资源上限**：检查所有上限参数是否可配置、默认值是否合理
5. **验证并发模型**：确认池的使用方式与线程模型一致（单线程池 vs 共享池）

## 常见反模式（禁止）

### 非 RAII 归还

```cpp
// ❌ 手动调用 checkin — 异常路径会跳过
auto conn = pool.checkout(target);
auto result = co_await use_connection(conn, request);
pool.checkin(conn);  // 如果 use_connection 抛异常，永远不会执行

// ✅ RAII 包装器保证归还
{
    auto conn = pool.checkout(target);  // 返回 RAII 包装器
    auto result = co_await use_connection(conn, request);
    // conn 析构时自动归还，即使 use_connection 抛异常
}
```

### 取消路径泄漏

```cpp
// ❌ 协程取消时 RAII 析构被跳过（如果使用裸指针）
auto raw_conn = pool.checkout_raw(target);
co_await use_connection(raw_conn, request);
// 如果协程在 co_await 期间被取消，raw_conn 永远不会归还

// ✅ 使用 RAII 包装器，析构在取消路径上同样执行
auto conn = pool.checkout(target);  // 返回 shared_ptr/unique_ptr with deleter
co_await use_connection(conn.get(), request);
// 即使协程被取消，conn 的析构函数仍然执行
```

### 健康检查不恢复模式

```cpp
// ❌ 非阻塞检查后不恢复
void health_check(socket& sock)
{
    sock.set_non_blocking(true);
    auto [ec, n] = sock.peek(buffer);
    if (ec) evict(sock);
    // 忘记恢复 — 后续的 async_read_some 行为异常
}

// ✅ 检查后恢复原始模式
void health_check(socket& sock)
{
    auto original_mode = sock.get_mode();
    scope_guard guard([&] { sock.set_mode(original_mode); });
    sock.set_non_blocking(true);
    auto [ec, n] = sock.peek(buffer);
    if (ec) evict(sock);
}
```

### 无单目标连接数限制

```cpp
// ❌ 对单个目标无连接数限制
auto conn = pool.checkout(target);
// 如果 target 是热门上游，可能耗尽整个池

// ✅ 每个目标有独立的连接数上限
auto conn = pool.checkout(target);
// pool 内部维护 per-target 计数器，超过限制时等待或拒绝
```

### 双重归还

```cpp
// ❌ 移动后原对象仍触发归还
auto conn1 = pool.checkout(target);
auto conn2 = std::move(conn1);
// conn1 析构：检查到已移动，不归还
// conn2 析构：正常归还
// 如果移动构造函数未正确转移"归还责任"，两个析构都尝试归还

// ✅ 移动构造函数转移归还责任
class pooled_connection
{
    bool owns_ = true;
public:
    pooled_connection(pooled_connection&& other) noexcept
        : pool_(other.pool_), conn_(std::move(other.conn_))
    {
        other.owns_ = false;  // 原对象不再拥有，析构时不归还
    }
    ~pooled_connection() noexcept
    {
        if (owns_ && conn_) pool_->checkin(std::move(conn_));
    }
};
```

## 交叉引用

- `coroutine-audit` 覆盖了协程取消时的资源释放维度
- `co-lifecycle-audit` 覆盖了 RAII 析构在所有路径上执行、移动语义维度
- `tunnel-audit` 覆盖了使用池连接的隧道转发、关闭顺序维度
- `concurrency-audit` 覆盖了池的线程安全、CAS 限额检查维度
- `error-chain-audit` 覆盖了 checkout 失败时的错误传播维度
