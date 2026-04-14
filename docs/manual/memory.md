# Memory/PMR 模块设计

本文档描述 Prism 内存管理子系统的架构设计与使用规范。PMR（Polymorphic Memory Resource）是 Prism 实现热路径零堆分配的核心基础设施。

## 模块概述

Prism 采用 C++23 纯协程架构处理高并发代理连接，对内存分配延迟极其敏感。传统的 `new`/`malloc` 在高频 I/O 路径上会引入不可控的延迟抖动和缓存失效。为此，Prism 基于 `std::pmr` 构建了分层内存管理体系，将分配器决策从对象层面提升到架构层面。

整个模块位于 `include/prism/memory/`，全部 header-only，分为三个子文件：

| 文件 | 职责 |
|------|------|
| [container.hpp](../../../include/prism/memory/container.hpp) | PMR 容器别名、内存资源类型、分配器定义 |
| [pool.hpp](../../../include/prism/memory/pool.hpp) | 全局池/线程局部池管理、帧分配器、池化对象基类 |
| [pointer.hpp](../../../include/prism/memory/pointer.hpp) | 智能指针扩展预留（当前未实现） |

命名空间：`psm::memory`

## 设计目标

**热路径零堆分配**是内存模块的核心设计目标。具体拆解为四项原则：

1. **热路径无分配** -- 网络 I/O、协议解析、数据转发等热路径严禁直接使用 `new` 或 `malloc`
2. **线程封闭** -- 通过线程局部池实现无锁并发，消除热路径上的互斥竞争
3. **大小分类** -- 小对象（<=16KB）走池化路径，大对象直通系统堆
4. **生命周期分层** -- 全局池用于跨线程对象，线程局部池用于临时对象，帧分配器用于请求级瞬时对象

## container.hpp -- 容器别名体系

### 基础类型

模块定义了三个基础类型别名，作为 PMR 体系的基础设施：

| 别名 | 底层类型 | 说明 |
|------|----------|------|
| `resource` | `std::pmr::memory_resource` | 内存资源抽象基类 |
| `resource_pointer` | `resource*` | 内存资源裸指针，用于函数间传递 |
| `allocator<T>` | `std::pmr::polymorphic_allocator<T>` | 多态内存分配器模板 |

### 全局访问接口

```cpp
inline auto current_resource() -> resource_pointer
{
    return std::pmr::get_default_resource();
}
```

`current_resource()` 返回当前默认内存资源指针。若程序调用了 `system::enable_global_pooling()`，则返回全局同步池；否则返回 `std::pmr::new_delete_resource()`。

源码：[container.hpp](../../../include/prism/memory/container.hpp)

### 内存资源类型

模块封装了三种 `std::pmr` 标准内存资源：

| 别名 | 底层类型 | 线程安全 | 适用场景 |
|------|----------|----------|----------|
| `synchronized_pool` | `std::pmr::synchronized_pool_resource` | 是 | 全局共享池，跨线程对象分配 |
| `unsynchronized_pool` | `std::pmr::unsynchronized_pool_resource` | 否 | 线程局部池，单线程热路径分配 |
| `monotonic_buffer` | `std::pmr::monotonic_buffer_resource` | 否 | 帧分配器的底层资源，仅分配不释放 |

### 容器别名

所有标准容器均有对应的 PMR 别名，确保统一使用多态分配器：

| 别名 | 底层类型 | 典型用途 |
|------|----------|----------|
| `string` | `std::pmr::string` | 域名、地址、日志字符串 |
| `vector<T>` | `std::pmr::vector<T>` | IP 列表、端点列表、缓冲区 |
| `list<T>` | `std::pmr::list<T>` | 有序链表（当前较少使用） |
| `map<K, V>` | `std::pmr::map<K, V>` | 有序映射（红黑树） |
| `unordered_map<K, V>` | `std::pmr::unordered_map<K, V>` | 哈希映射，广泛用于缓存和路由表 |
| `unordered_set<K>` | `std::pmr::unordered_set<K>` | 哈希集合 |

使用示例（DNS 解析中的典型用法）：

```cpp
// 从指定内存资源创建向量
memory::vector<net::ip::address> filtered(mr_);
filtered.reserve(result.ips.size());

// 从指定内存资源创建字符串
memory::string result(domain, mr);
```

源码：[container.hpp](../../../include/prism/memory/container.hpp)

## pool.hpp -- 内存池系统

### policy -- 策略配置

`policy` 结构体定义内存池的调优参数，针对代理服务器典型负载优化：

| 参数 | 值 | 说明 |
|------|-----|------|
| `max_blocks` | 256 | 每个 Chunk 的最大块数，限制为 256 x 16KB = 4MB 最大 Chunk |
| `max_pool_size` | 16384 (16KB) | 最大池化阈值，覆盖 HTTP Header、RPC 元数据和小型 Payload |
| `small_buffer_size` | 8192 (8KB) | 小型缓冲区大小，适用于临时缓冲区、栈上数组 |

大于 `max_pool_size` 的对象将直通系统堆 `malloc`，避免长期占用池内存。

源码：[pool.hpp](../../../include/prism/memory/pool.hpp)

### system -- 全局内存系统管理器

`system` 类提供三个静态方法访问不同层级的内存池：

#### global_pool()

```cpp
static synchronized_pool *global_pool()
```

返回全局线程安全池单例。使用 `new` 创建，确保在静态析构阶段后仍可用。

**适用场景**：
- 跨线程共享的对象（如 session、connection）
- 生命周期不确定的长期对象（如全局配置、共享缓存）
- `pooled_object` 基类默认使用的池

#### thread_local_pool()

```cpp
static unsynchronized_pool *thread_local_pool()
```

返回线程局部无锁池单例。使用 `thread_local` 存储，每个线程独立实例。

**适用场景**：
- 局部临时计算和中间结果
- 单线程处理流水线中的临时对象

**技术特性**：完全无锁设计，每个线程独立实例，随线程销毁自动清理。

#### hot_path_pool()

```cpp
static unsynchronized_pool *hot_path_pool()
```

`thread_local_pool()` 的语义化别名，无额外开销。提供语义化名称，强制开发者在热路径中使用无锁分配器。

**适用场景**：
- 网络 I/O 回调中的临时分配
- 协议解析和数据转发路径
- 协程切换和异步操作中的对象分配

**约束**：热路径分配的对象生命周期必须与当前线程绑定，禁止跨线程传递。

#### enable_global_pooling()

```cpp
static void enable_global_pooling()
```

将 C++ 标准库的默认内存资源设置为全局内存池。调用后，所有使用 `std::pmr::polymorphic_allocator` 且未指定显式内存资源的容器将自动使用 `global_pool()`。**应在程序启动早期调用（`main()` 首行），一旦启用不应再修改。**

启动流程中的位置（参见 [architecture.md](architecture.md)）：

| 步骤 | 操作 | 说明 |
|------|------|------|
| 1 | `enable_global_pooling()` | 初始化全局内存池，必须在所有 PMR 容器创建前调用 |

源码：[pool.hpp](../../../include/prism/memory/pool.hpp)

### frame_arena -- 帧分配器

`frame_arena` 是 Prism 中最轻量的分配器，专为请求处理周期内的瞬时分配设计。

#### 设计原理

```
  栈缓冲 (128 字节)          线程局部池
  ┌──────────────┐           ┌──────────────┐
  │ 小分配直接满足 │  用尽后 → │ 无锁单调增长  │
  └──────────────┘           └──────────────┘
         ↑                         ↑
      零系统调用              自动回退
```

- **栈缓冲区**：128 字节栈上数组作为一级缓存，避免小分配穿透到堆
- **单调增长**：使用 `std::pmr::monotonic_buffer_resource` 实现线性分配
- **无锁上游**：以 `thread_local_pool()` 作为后备资源，确保无锁性能

#### 关键接口

| 方法 | 说明 |
|------|------|
| `get()` | 返回内部 `monotonic_buffer_resource` 指针，用于创建 PMR 容器 |
| `reset()` | 释放所有已分配内存，重置游标到初始位置 |

#### 与 session 的关系

每个 session 持有一个 `frame_arena` 成员，生命周期与会话绑定：

```cpp
class session : public std::enable_shared_from_this<session>
{
    // ...
    memory::frame_arena frame_arena_;  // 帧内存池
    session_context ctx_;              // 上下文持有 frame_arena 引用
};
```

`session_context` 通过引用持有 `frame_arena`，在会话处理过程中为各模块提供统一的临时内存来源：

```cpp
struct session_context
{
    memory::frame_arena &frame_arena;  // 帧内存池引用
    // ...
};
```

**设计选择**：内部缓冲区仅 128 字节（而非 `policy::small_buffer_size` 的 8KB），目的是避免 session 对象本身过大。大部分内存请求直接透传给 `thread_local_pool`，无锁且高效。

源码：[pool.hpp](../../../include/prism/memory/pool.hpp)、[session.hpp](../../../include/prism/agent/session/session.hpp)、[context.hpp](../../../include/prism/agent/context.hpp)

### pooled_object -- 池化对象基类

`pooled_object<T>` 使用 CRTP 惯用法，通过重载 `operator new`/`operator delete` 使继承类自动使用内存池分配。

#### 工作原理

```
  pooled_object<T>::operator new(size)
       │
       ├─ size <= 16KB → global_pool()->allocate(size)
       │                  线程安全池化路径
       │
       └─ size > 16KB  → ::operator new(size)
                          直通系统堆
```

- **单对象版本**：`operator new` / `operator delete` 根据对象大小选择池化或系统堆
- **数组版本**：`operator new[]` / `operator delete[]` 同样支持，逻辑一致

#### 使用方式

```cpp
class my_component : public memory::pooled_object<my_component>
{
    // ...
};

// 自动使用 global_pool 分配
auto obj = std::make_shared<my_component>(...);
```

**设计选择**：使用 `global_pool()`（同步池）而非 `thread_local_pool()`，因为通用对象的生命周期通常跨越多个线程或不确定。大小阈值遵循 `policy::max_pool_size`。

源码：[pool.hpp](../../../include/prism/memory/pool.hpp)

## pointer.hpp -- 智能指针预留

当前 `pointer.hpp` 为预留文件，尚未实现具体功能。规划中的功能包括：

| 规划类型 | 说明 |
|----------|------|
| `unique_ptr<T>` | 支持自定义池删除器的 unique_ptr 别名 |
| `shared_ptr` 支持 | 内存池分配的 shared_ptr 创建函数 |
| `make_unique` 工厂 | 从指定内存池创建 unique_ptr |

源码：[pointer.hpp](../../../include/prism/memory/pointer.hpp)

## 实际使用模式

以下从 Prism 各模块的源码中总结 PMR 的典型集成方式。

### session -- 帧分配器持有

Session 是 `frame_arena` 的主要持有者。每个会话创建时构造一个 `frame_arena`，通过 `session_context` 传递给下游模块使用。

```cpp
// session 构造函数初始化 frame_arena
session::session(session_params params)
    : id_(detail::generate_session_id()),
      ctx_{id_, params.server, params.worker, frame_arena_, ...}
{
}
```

Worker 上下文通过 `memory_pool` 字段传递线程局部池资源，Session 的 `frame_arena` 提供更低粒度的帧级分配。

### resolve -- PMR 容器透传

DNS 解析模块（recursor）是 PMR 容器最密集的使用者。recursor 持有一个 `memory::resource_pointer mr_` 成员，所有内部容器均从该资源分配：

```cpp
// recursor 构造时接收内存资源
recursor::recursor(net::io_context &ioc, config cfg, const memory::resource_pointer mr)
    : ioc_(ioc), mr_(mr ? mr : memory::current_resource()),
      upstream_(ioc_, mr_),
      cache_(mr_, config_.cache_ttl, config_.cache_size, config_.serve_stale),
      rules_(mr_), coalescer_(mr_), ...
{
}
```

查询管道中的典型用法：

```cpp
// 域名规范化：从指定资源创建 PMR 字符串
auto recursor::normalize(const std::string_view domain, const memory::resource_pointer mr)
    -> memory::string
{
    memory::string result(domain, mr);
    // 转小写、去末尾点号 ...
    return result;
}

// 查询管道：所有返回值使用 PMR 向量
auto recursor::query_pipeline(const std::string_view domain, const qtype qt)
    -> net::awaitable<std::pair<fault::code, memory::vector<net::ip::address>>>
{
    // ...
    memory::vector<net::ip::address> filtered(mr_);
    filtered.reserve(result.ips.size());
    // ...
}
```

DNS 解析器（resolver）同样广泛使用 PMR 容器，包括 HTTP 请求构建（`memory::string`）、响应缓冲（`memory::vector<uint8_t>`）和 SSL 缓存键（`memory::string`）等。

### pipeline -- 协议处理中的临时容器

协议处理模块在解析请求时使用 PMR 容器进行临时分配。由于 `frame_arena` 通过 `session_context` 传递，处理器可以获取帧级内存资源，在请求结束后通过 `reset()` 一次性释放所有临时对象。

### trace -- 日志中的 PMR 字符串

日志模块使用 `memory::string` 构建追踪名称，确保日志格式化路径同样受益于池化分配。

## 内存分配策略选择指南

根据使用场景选择合适的分配策略：

```
                       生命周期
                    短 ←──────────→ 长
                    │                │
     线程封闭       │  frame_arena   │  thread_local_pool
     (单线程)       │  (请求级瞬时)  │  (线程级临时)
                    │                │
     跨线程         │  不适用        │  global_pool
                    │                │  (全局共享)
```

| 场景 | 推荐策略 | 说明 |
|------|----------|------|
| 请求处理中的临时字符串/向量 | `frame_arena::get()` | 请求结束后统一释放，零碎片 |
| 线程内部临时计算 | `system::thread_local_pool()` | 无锁分配，线程封闭 |
| 热 I/O 路径中的对象 | `system::hot_path_pool()` | 语义化别名，强调热路径约束 |
| 跨线程共享对象 | `system::global_pool()` | 线程安全，互斥保护 |
| 池化对象基类 | 继承 `pooled_object<T>` | 自动使用 `global_pool` |
| 大对象 (>16KB) | 默认 `new`/`malloc` | 自动穿透，不占用池内存 |
| 未指定资源的 PMR 容器 | `current_resource()` | 调用 `enable_global_pooling()` 后为 `global_pool` |

**关键原则**：

- 热路径必须使用 `hot_path_pool()` 或 `frame_arena`，严禁直接 `new`
- `frame_arena` 分配的内存仅在当前请求周期内有效，禁止跨请求持有
- `thread_local_pool` 和 `hot_path_pool` 分配的对象禁止跨线程传递
- 大对象自动穿透到系统堆，无需特殊处理

## 性能考量

### 分配延迟分层

| 分配器 | 典型延迟 | 锁竞争 | 适用场景 |
|--------|----------|--------|----------|
| `frame_arena` (栈缓冲内) | <10ns | 无 | 128 字节以内的小分配 |
| `frame_arena` (回退到线程池) | <50ns | 无 | 超过栈缓冲的帧级分配 |
| `thread_local_pool` / `hot_path_pool` | <50ns | 无 | 线程局部临时对象 |
| `global_pool` | 100-500ns | 有互斥 | 跨线程共享对象 |
| 系统 `new`/`malloc` | 100ns-1us | 有 | 大对象、非热路径 |

### 内存碎片控制

- **策略参数调优**：`policy::max_blocks = 256` 限制单个 Chunk 最大 4MB，降低内存峰值
- **单调增长资源**：`frame_arena` 内部的 `monotonic_buffer` 仅分配不释放，避免碎片
- **大小分类**：超过 16KB 的对象不走池化，避免大块内存长期驻留池中
- **批量释放**：`frame_arena::reset()` 一次性释放所有帧内分配，远快于逐个 `delete`

### 缓存局部性

`frame_arena` 的栈缓冲区设计使得小于 128 字节的分配直接命中栈内存，具有最优的缓存局部性。更大的分配通过 `monotonic_buffer_resource` 在连续内存区域上分配，同样具有良好的空间局部性。

## 模块架构总览

```
  main.cpp
  └─ enable_global_pooling() ── 设置默认内存资源为 global_pool
       │
       ├─ global_pool (synchronized_pool)
       │   ├─ pooled_object<T> 基类自动使用
       │   └─ 未指定资源的 PMR 容器默认使用
       │
       ├─ thread_local_pool (unsynchronized_pool)  ── 每线程独立
       │   ├─ hot_path_pool() 语义化别名
       │   └─ frame_arena 的上游资源
       │
       └─ frame_arena  ── 每会话独立
           ├─ 128 字节栈缓冲（一级缓存）
           └─ monotonic_buffer_resource（二级，上游为线程局部池）
```
