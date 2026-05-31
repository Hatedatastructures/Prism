---
name: co-lifecycle-audit
description: 新增或修改 enable_shared_from_this 类、co_spawn 调用、shared_ptr 捕获的 lambda、co_await 后的成员访问时触发。
---

# Skill: 协程对象生命周期审计

在 C++ 异步编程模型中，协程的挂起与恢复会打断正常的栈帧生命周期保证。`co_await` 挂起点是引用失效、对象提前析构、循环引用的唯一来源。每个挂起点都必须被视为"对象可能已部分析构"的边界。

## 触发条件

- 新增继承 `enable_shared_from_this` 的类
- 新增 `co_spawn` 调用
- 修改 `shared_ptr` 捕获的 lambda（尤其是 `self = shared_from_this()`）
- 修改 `co_await` 恢复后的成员访问（引用、指针、迭代器）
- 修改 `friend class` 声明（特权访问影响封装边界）
- 新增持有 `shared_ptr` 成员的类（潜在的循环引用）

## 核心原理

### 挂起点即危险边界

协程在 `co_await` 处挂起时，控制权交还给事件循环。在挂起期间：

- 同一执行器上的其他协程可能运行并修改共享状态
- 外部代码可能关闭连接、取消操作、重置对象
- 容器可能发生扩容、删除、重哈希

恢复后，挂起前获取的所有引用、指针、迭代器都必须视为**可能已失效**。

### 循环引用的隐蔽性

`shared_ptr` 的循环引用通过 `co_spawn` lambda 捕获形成时特别隐蔽：对象持有成员协程，协程通过 `self` 捕获持有对象，形成闭环。这种循环不会导致立即崩溃，而是导致对象永远不被析构，造成缓慢的内存泄漏。

## 审计清单

### 1. shared_from_this 使用正确性

| 检查项 | 说明 |
|--------|------|
| **构造期禁止调用** | 构造函数（含委托构造）中调用 `shared_from_this()` 是未定义行为。对象必须先被 `shared_ptr` 管理后才能调用。如果构造阶段需要传递 `self`，使用 `static create()` 工厂模式延迟获取 |
| **析构期禁止调用** | 析构函数中调用 `shared_from_this()` 是未定义行为。析构时引用计数已归零 |
| **lambda 按值捕获** | `co_spawn` 的 lambda 必须按值捕获 `self`（`[self = shared_from_this()]`），禁止按引用捕获（`[&self]`）或捕获裸指针（`[this]`）。按引用捕获的 `self` 在 lambda 被存储后可能悬挂 |
| **循环引用检测** | 如果 `self` 捕获导致对象 → 协程 → 对象的闭环，考虑使用 `weak_ptr` 打破循环。典型场景：长期运行的读/写循环协程持有 `self`，而对象管理这些协程 |

### 2. co_await 悬挂引用

| 检查项 | 说明 |
|--------|------|
| **容器引用失效** | `co_await` 恢复后，之前从容器获取的引用/指针/迭代器是否已失效。`vector` 扩容使所有引用失效；`unordered_map` 的 `erase` 可能触发重哈希使所有迭代器失效；`string` 的任何修改使所有引用失效 |
| **erase 后迭代器** | `erase()` 后必须使用返回值更新迭代器，不得对旧迭代器执行 `++it`。在循环中 `erase` 后继续遍历时，使用 `it = container.erase(it)` 模式 |
| **span 底层容器** | `span` 或 `string_view` 引用的底层容器在 `co_await` 期间是否可能被修改或销毁。`span` 不拥有数据，底层容器被销毁后 span 悬挂 |
| **成员指针** | `co_await` 恢复后，通过 `this` 访问的成员指针是否仍然有效。如果其他协程可能修改了该成员（如 `reset()`、`clear()`），指针悬挂 |

### 3. co_spawn 保活审计

| 检查项 | 说明 |
|--------|------|
| **detached 协程的裸指针** | 使用 `net::detached` 的 `co_spawn` 中，是否存在裸指针或引用指向可能在协程运行期间析构的对象。`detached` 意味着没有人等待协程完成，对象的生命周期必须由 `self` 捕获保证 |
| **显式 completion handler** | 使用显式 completion handler 的 `co_spawn` 是否正确处理 `std::exception_ptr`。未处理的异常会调用 `std::terminate` |
| **执行器一致性** | `co_spawn` 的执行器是否与对象所属的 `io_context` 一致。在错误的执行器上 spawn 会导致对象在不同线程被访问，违反单线程假设 |
| **协程取消安全** | 协程被取消（通过 `cancellation_slot` 或 `io_context` 停止）时，持有的资源是否正确释放。取消路径不得跳过 RAII 析构 |

### 4. friend 特权访问审计

| 检查项 | 说明 |
|--------|------|
| **最小接口原则** | `friend class` 声明是否限于必要的最小接口。如果友元类只访问一个方法，考虑将该方法改为 `protected` 或 `public` 而非授予全部访问权 |
| **生命周期依赖** | 友元类访问的对象成员是否保证在友元调用期间有效。友元关系绕过了封装，调用方和被访问对象的生命周期约定必须显式文档化 |
| **新增友元的评估** | 新增 `friend` 声明时是否评估了对封装的影响。每增加一个友元，类的维护者就多了一个需要同步修改的外部代码 |

### 5. RAII 资源管理

| 检查项 | 说明 |
|--------|------|
| **socket 关闭时序** | `close()` 后 pending 的异步操作 completion handler 是否需要对象存活？ |
| **timer/channel 取消** | 取消后关联协程是否能安全退出？未消费的数据是否泄漏？ |
| **析构顺序** | 成员变量析构顺序是否安全（后构造的先析构）？ |

### 6. PMR 与内存资源

| 检查项 | 说明 |
|--------|------|
| **PMR allocator 传播** | 移动 PMR 容器时 allocator 是否正确传播？ |
| **上游资源释放** | `monotonic_buffer_resource` reset 前是否全部不再使用？ |
| **线程本地池** | `unsynchronized_pool_resource` 是否在正确的线程使用？ |

### 7. 移动语义与所有权

| 检查项 | 说明 |
|--------|------|
| **移动后状态** | 对象 `std::move` 后是否仅以定义好的方式使用（通常仅析构）。移动后的源对象不应被假设为特定状态（如"空"或"零"），除非类文档明确保证 |
| **管道传递的所有权** | 对象在处理管道中传递时，所有权是否明确。`shared_ptr` 表示共享所有权（生命周期由最后一个持有者保证），`unique_ptr` 表示独占所有权（传递后原持有者不得访问） |
| **拷贝的独立性** | 对象的拷贝是否产生独立状态。如果拷贝构造函数共享了内部资源（如 PMR 容器共享同一内存资源），两个副本的修改可能互相影响 |

## 审计流程

1. **绘制所有权图**：列出对象之间的 `shared_ptr`/`weak_ptr`/裸指针关系，标注生命周期依赖方向。检查是否存在环路（循环引用）
2. **标记挂起点**：在协程函数中标注所有 `co_await` 位置。对每个挂起点，列出恢复后仍然使用的引用/指针/迭代器
3. **验证悬挂风险**：对每个挂起点后的引用使用，验证引用的源对象在挂起期间不可能被修改或析构
4. **验证保活**：对每个 `co_spawn` 调用，验证 lambda 捕获了足够的 `shared_ptr` 以保持所有需要长寿的对象存活
5. **验证取消路径**：对每个协程，追踪取消时的资源释放路径。确认 RAII 析构在取消路径上同样执行

## 常见反模式（禁止）

### co_await 后使用前置引用

```cpp
// ❌ co_await 恢复后使用前置引用
auto& item = map[key];
co_await async_write(item.data(), item.size());
// 挂起期间其他协程可能修改 map，item 引用悬挂

// ✅ co_await 后重新获取
co_await async_write(item.data(), item.size());
// 或者：将数据拷贝出来，不持有引用
auto data = item.data_copy();
co_await async_write(data.data(), data.size());
```

### co_spawn 不保活

```cpp
// ❌ co_spawn 不捕获 self — 对象可能在协程完成前析构
void start_loop()
{
    net::co_spawn(executor(), read_loop(), net::detached);
    // read_loop 是成员协程，但 detached 不持有 self
    // 如果外部释放了对象的 shared_ptr，this 悬挂
}

// ✅ lambda 捕获 self 保持对象存活
void start_loop()
{
    net::co_spawn(executor(),
        [self = shared_from_this()]()
            -> net::awaitable<void>
        {
            co_await self->read_loop();
        }, net::detached);
}
```

### 循环引用

```cpp
// ❌ 对象持有协程，协程持有对象 — 永不释放
class session : public std::enable_shared_from_this<session>
{
    void start()
    {
        net::co_spawn(executor(),
            [self = shared_from_this()]()
                -> net::awaitable<void>
            {
                co_await self->relay_loop();  // 长期运行
            }, net::detached);
        // self 捕获使引用计数 +1
        // session 对象永远不会析构（引用计数永远 > 0）
    }
};

// ✅ 使用 weak_ptr 或外部管理生命周期
class session : public std::enable_shared_from_this<session>
{
    void start()
    {
        net::co_spawn(executor(),
            [self = shared_from_this()]()
                -> net::awaitable<void>
            {
                co_await self->relay_loop();
                self->on_complete();  // 显式完成回调，释放资源
            }, net::detached);
    }
    void on_complete()
    {
        // 主动清理成员，打破循环引用链
        transport_.reset();
    }
};
```

### 构造函数调用 shared_from_this

```cpp
// ❌ 构造函数中调用 shared_from_this — UB
class handler : public std::enable_shared_from_this<handler>
{
    handler(transport& t)
    {
        start_reading(shared_from_this());  // UB: 尚未被 shared_ptr 管理
    }
};

// ✅ 工厂模式延迟获取
class handler : public std::enable_shared_from_this<handler>
{
    explicit handler(transport& t)
        : transport_(t)
    {}
public:
    [[nodiscard]] static auto create(transport& t)
        -> std::shared_ptr<handler>
    {
        auto ptr = std::make_shared<handler>(t);
        ptr->start_reading();  // 此时已由 shared_ptr 管理
        return ptr;
    }
};
```

### erase 后使用旧迭代器

```cpp
// ❌ erase 后 ++it — 悬挂迭代器
for (auto it = streams_.begin(); it != streams_.end(); ++it)
{
    if (it->second.expired())
    {
        streams_.erase(it);
        // ++it 使 it 跳过一个元素或悬挂
    }
}

// ✅ 使用 erase 返回值
for (auto it = streams_.begin(); it != streams_.end(); )
{
    if (it->second.expired())
    {
        it = streams_.erase(it);
    }
    else
    {
        ++it;
    }
}
```

## 交叉引用

- `coroutine-audit` 覆盖了协程纯度（禁止阻塞调用、禁止互斥锁）维度
- `audit-memory` 覆盖了 PMR 分配器选择（MR 类型选择、MR 参数传递、frame_arena 生命周期）维度 — 本 skill 不涉及分配器选择，仅关注对象级别的生命周期安全
- `probe-audit` 覆盖了时序侧信道（响应时间分布一致性）维度
- `enforce-coding` 覆盖了编码规范中的生命周期与资源安全规则
- `error-chain-audit` 覆盖了异步任务中未监控错误的传播链完整性维度
- `mux-audit` 覆盖了多路复用流的读写循环退出协调、流生命周期、关闭幂等性维度
- `tunnel-audit` 覆盖了双向转发的 transport 保活、close 幂等性、装饰器层关闭穿透维度
- `pool-audit` 覆盖了连接池 RAII 归还保证、移动语义与归还责任转移维度
