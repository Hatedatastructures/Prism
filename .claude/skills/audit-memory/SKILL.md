---
name: audit-memory
description: 修改 PMR 分配器、内存池配置、热路径容器、对象生命周期管理代码后触发。
---

# Skill: 内存安全审计

## 触发条件

修改 PMR 内存资源、热路径容器、对象池、frame_arena、pooled_object 相关代码后触发。

## 核心原理

### PMR 分层资源模型

Prism 的 PMR 采用三层资源模型，从上到下性能递增、线程安全性递减：

```
global_pool (synchronized_pool)    — 跨线程安全，全局唯一
    │
    ▼
local_pool (unsynchronized_pool)   — thread_local，无锁，热路径默认
    │
    ▼
frame_arena (monotonic_buffer)     — 栈上 512B，函数级作用域，零碎片
```

每层的使用场景严格区分：
- **global_pool**：跨线程对象（如 balancer 分发时的共享状态）、启动阶段配置解析
- **local_pool**：同一线程上的所有热路径容器（session、protocol handler、tunnel）
- **frame_arena**：单次协议处理中的临时分配（帧解析缓冲区、地址字符串），函数退出时统一释放

### 热路径零分配原则

代理服务器的数据转发路径（read → parse → encrypt → write）在每次请求中可能执行数千次。每次系统 malloc 调用都涉及全局锁竞争和内核态切换。PMR 池分配将此开销降至一次指针推进（amortized O(1)）。

违反零分配的常见路径：在转发循环中构造临时 `std::string`（应用 `memory::string`）、在帧处理中 `push_back` 触发 `vector` 扩容（应预分配或使用 `frame_arena`）。

### 与 co-lifecycle-audit 的职责边界

两个 skill 都涉及内存安全，但关注层面不同：

| 维度 | audit-memory（本 skill） | co-lifecycle-audit |
|------|--------------------------|---------------------|
| 分配器选择 | MR 类型选择、MR 参数传递 | — |
| 容器 MR 一致性 | PMR 容器是否使用正确的 MR | — |
| frame_arena | 栈缓冲区生命周期、reset 时机 | — |
| 对象生命周期 | — | shared_ptr 循环引用、悬挂引用 |
| co_await 后引用 | 仅关注容器扩容导致的迭代器失效 | 全面关注引用/指针/迭代器失效 |
| co_spawn 保活 | — | lambda 捕获 self 保持对象存活 |

简言之：**本 skill 管"内存从哪来、怎么分配"；co-lifecycle-audit 管"对象什么时候活着、什么时候析构"**。

## 审计清单

### 1. PMR 资源选择

- [ ] 热路径（per-thread）使用 `unsynchronized_pool`（无锁，thread_local）
- [ ] 跨线程共享使用 `synchronized_pool`（线程安全，全局池）
- [ ] 临时帧分配使用 `frame_arena`（栈上 512-byte monotonic buffer）
- [ ] 超过 `max_size`（16KB）的分配有合理理由，不浪费池空间

### 2. 容器安全性

- [ ] `memory::vector` 扩容后所有迭代器/指针/引用已失效并重新获取
- [ ] `co_await` 恢复后未持有容器引用（悬挂风险）
- [ ] `erase()` / `insert()` 后使用返回值更新迭代器
- [ ] PMR 容器的 MR 参数正确传递（不依赖默认构造）

### 3. pooled_object 使用

- [ ] 热路径频繁创建/销毁的对象考虑继承 `pooled_object<T>`（可选优化，当前代码库尚未广泛采用）
- [ ] 若使用：`pool_type` 选择正确 — `local`（默认，单线程）vs `global`（跨线程）
- [ ] 若使用：大对象（>16KB）不走池分配（池上限 `max_size = 16384`）
- [ ] `operator new[]` 走池分配时不产生对齐问题

### 4. 生命周期审计

- [ ] `co_spawn` lambda 按值捕获 `self`（shared_ptr），非引用捕获
- [ ] `co_await` 恢复后裸指针/引用/迭代器已重新获取
- [ ] `frame_arena` 使用范围不超出所在函数（它是栈对象）
- [ ] `unique_ptr`/`shared_ptr` 的自定义删除器与分配方式一致（池分配需池回收）

### 5. 泄漏检测

- [ ] `frame_arena` 在函数退出前调用 `reset()` 或依赖 RAII 析构
- [ ] 长生命周期容器（连接池、session map）有淘汰机制和容量上限
- [ ] strand 内操作不泄漏临时 PMR 对象
- [ ] `memory::system::enable_pooling()` 在 `main()` 最早期调用

## PMR 基础设施速查

```
memory::string              → std::pmr::string
memory::vector<T>           → std::pmr::vector<T>
memory::map<K,V>            → std::pmr::map<K,V>
memory::unordered_map<K,V>  → std::pmr::unordered_map<K,V>

memory::current_resource()      → 获取当前默认 PMR 资源
memory::effective_mr(mr)        → mr ?: default_resource，安全获取有效 MR

memory::system::global_pool()   → synchronized_pool（线程安全，跨线程对象）
memory::system::local_pool()    → unsynchronized_pool（thread_local，热路径）
memory::system::hot_pool()      → local_pool() 的语义别名
memory::system::enable_pooling() → 设置 global_pool 为默认 PMR 资源

memory::frame_arena          → 512-byte 栈上 monotonic buffer
                               .get() → resource_pointer
                               .reset() → 释放所有分配
                               上游资源为 local_pool（栈缓冲耗尽后溢出到线程池）

memory::pooled_object<T>     → CRTP 基类，重载 operator new/delete
                               小对象（<=16KB）走池，大对象走系统堆
                               注：当前代码库尚未广泛采用，为可选优化
```

## 常见反模式（禁止）

### 在协程中 new/delete 裸指针

```cpp
// ❌ 协程被取消时 delete 永远不会执行
auto* buf = new std::byte[4096];
co_await async_write(buf, size);
delete[] buf;

// ✅ RAII 保证释放
auto buf = memory::vector<std::byte>(memory::effective_mr(mr));
buf.resize(4096);
co_await async_write(buf.data(), buf.size());
```

### frame_arena 跨函数传递

```cpp
// ❌ arena 是栈对象，函数返回后内存全部释放
auto make_arena() -> memory::frame_arena* {
    memory::frame_arena arena;
    return &arena;  // 悬挂
}

// ✅ 在调用者的栈上创建，传递 resource_pointer
void process_request(memory::frame_arena& arena)
{
    memory::vector<std::byte> buf(arena.get());
    // buf 的分配来自 arena，函数返回时 arena 统一释放
}
```

### vector 扩容后使用旧迭代器

```cpp
// ❌ push_back 可能触发扩容，所有迭代器失效
auto it = vec.begin();
vec.push_back(x);
*it;  // 悬挂迭代器

// ✅ push_back 后重新获取迭代器
vec.push_back(x);
auto it = vec.begin() + offset;  // 重新获取
```

### effective_mr 未使用

```cpp
// ❌ 默认构造的 PMR 容器可能走了系统 malloc
memory::vector<std::byte> buf;

// ✅ 显式传递 MR
memory::vector<std::byte> buf(memory::effective_mr(mr));
// 或使用当前线程的 local_pool
memory::vector<std::byte> buf(memory::current_resource());
```

### frame_arena reset 后访问已分配对象

```cpp
// ❌ reset 后所有从 arena 分配的对象全部失效
memory::frame_arena arena;
auto* p = arena.allocate(64);
arena.reset();
// p 现在指向已释放的内存
std::memcpy(p, data, 64);  // use-after-free

// ✅ reset 前确保不再访问任何 arena 分配的对象
// 先完成所有使用，再 reset
process(arena);
arena.reset();  // 此后不再使用从 arena 分配的任何指针
```

### PMR 容器作为函数返回值

```cpp
// ❌ 返回的 vector 的 MR 指向局部 arena，arena 析构后 MR 失效
auto parse_address(std::span<const std::byte> data) -> memory::vector<std::uint8_t>
{
    memory::frame_arena arena;
    memory::vector<std::uint8_t> result(arena.get());
    // ... 解析填充 result ...
    return result;  // 移动后 result 的 MR 仍指向 arena
    // arena 析构 → result 的 MR 失效 → 后续任何分配操作 UB
}

// ✅ 使用调用者提供的 MR
auto parse_address(std::span<const std::byte> data, std::pmr::memory_resource* mr)
    -> memory::vector<std::uint8_t>
{
    memory::vector<std::uint8_t> result(mr);
    // ... 解析填充 result ...
    return result;  // MR 由调用者保证存活
}
```

### unsynchronized_pool 跨线程共享

```cpp
// ❌ unsynchronized_pool 无锁，跨线程使用是数据竞争
memory::unsynchronized_pool pool;
// thread A: allocate from pool
// thread B: allocate from pool  → UB

// ✅ 跨线程用 synchronized_pool 或 system::global_pool()
```

## 交叉引用

- `co-lifecycle-audit` 覆盖了对象生命周期管理（shared_ptr 循环引用、co_await 后悬挂引用、co_spawn 保活）维度 — 本 skill 管"内存从哪来"，co-lifecycle-audit 管"对象什么时候活着"
- `coroutine-audit` 覆盖了协程中的阻塞操作和异步安全维度
- `leak-audit` 覆盖了通过日志/响应泄漏内存布局信息和实现独特行为的维度
- `debug-cpp` 提供了内存问题的系统排查流程（PMR 增长诊断、悬挂引用定位）
- `pool-audit` 覆盖了连接池资源的 MR 一致性、归还后资源的正确释放维度
