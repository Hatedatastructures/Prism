# Prism 架构：资源所有权模型

## 设计原则

Prism 采用纯协程（C++20 coroutine + Boost.Asio awaitable）架构，所有 I/O 操作异步执行。在这种架构下，**对象生命周期**与**资源所有权**是设计层面的核心问题——一个看似正确的对象引用，可能因为 detached 协程的存在而变成悬垂指针。

本文档定义 Prism 的四层资源所有权模型，明确 detached 协程的资源使用规则，从设计层面消除 use-after-free 类 bug。

---

## 四层所有权模型

Prism 所有资源按所有权范围分四层：

| 层 | 所有者 | 寿命 | 典型资源 | detached 协程可引用？ |
|----|--------|------|---------|---------------------|
| **L1 全局** | 进程 | 进程启动到退出 | `memory::system::global_pool()`、`stealth::scheme_registry`、`config`（loader 加载后） | ✅ 永远安全 |
| **L2 worker** | worker 线程 | worker 创建到销毁 | `connect::router`、`stats::traffic::traffic_state`、`outbound::proxy`、`ssl::context`、`net::io_context`、`memory::local_pool()`（thread_local） | ✅ worker 不死即可 |
| **L3 session** | session 对象 | 单次连接处理周期 | `memory::frame_arena`、`inbound`/`outbound` transport、`account::lease`、`context::session` 本身 | ❌ 严禁 |
| **L4 detached** | detached 协程自身 | 协程启动到结束 | `multiplex::core.transport_`、`craft.prefix_`（值副本）、`craft.self`（shared_from_this） | 自带，不依赖外层 |

---

## detached 协程规则

凡是 `net::co_spawn + net::detached`（或 Boost.Asio 等价机制）启动的协程，**完全脱离调用者的协程上下文**，独立运行直到自身结束。

### lambda 捕获规则

detached 协程的 lambda 捕获列表：

✅ **允许捕获**：
- 值类型（POD、enum、值副本）
- `std::shared_ptr<T>`（共享所有权，自动延长 T 的生命周期）
- L1/L2 层引用（worker 永生）
- 自身 `shared_from_this()`（典型 RAII 模式）

❌ **严禁捕获**：
- `context::session&` 或 `context::session*`（裸引用/指针，session 可死）
- `ctx.frame_arena.get()`（PMR allocator，session 级）
- `ctx.inbound&` / `ctx.outbound&`（引用捕获，session 级）
- 其他 L3 资源的裸引用/指针

### 资源使用规则

detached 协程内需要的资源：

- **session 资源** → 必须先 **move**（如 `transport` 所有权转移）或 **值拷贝**（如 `prefix_`、`proto_`）
- **PMR allocator** → 必须用 L1/L2 资源（`global_pool` 或 `local_pool`），禁止用 `frame_arena.get()`
- **router/traffic** → 通过 L2 引用（`ctx.worker_ctx.router`、`ctx.worker_ctx.traffic`）

---

## PMR allocator 规则

Prism 使用 PMR（polymorphic memory resource）实现热路径零堆分配。但 PMR allocator 的 `memory_resource*` 是裸指针，**不会自动跟随对象生命周期**。一旦 allocator 指向的对象析构，PMR container 的 `m_resource` 字段悬垂。

### 各层 PMR 使用规则

- **L3 对象**：可用 `frame_arena`（session 级 PMR pool）。session 析构时 frame_arena 一起析构，所有从 frame_arena 分配的对象随 session 释放
- **L4 对象**：必须用 `global_pool`（永生）或自带 `monotonic_buffer_resource`（detached 协程内独立池）

### 典型反例（已修复）

`transport::preview` 持有 `preread_buffer_`（`pmr::vector<byte>`），曾接受外部 `mr` 参数：

```cpp
// 危险代码（已删除）
preview::preview(shared_transmission inner, span<const byte> preread, memory::resource_pointer mr)
    : preread_buffer_(preread.begin(), preread.end(), mr) {}
```

调用方传入 `ctx.frame_arena.get()`，让 `preread_buffer_.m_resource` 指向 session 的 frame_arena。但 `preview` 可能被 `multiplex::core.transport_` 持有，core 是 detached 协程（`co_spawn(run_wrapper, detached)`），生命周期脱离 session。session 析构后 frame_arena 失效，preview 析构时 `m_resource` 悬垂 → 段错误。

**修复**：preview 构造去掉 `mr` 参数，内部强制用 `global_pool`（PMR 默认资源）。

---

## 已知约束（Prism 现状）

### multiplex::core 是 L4

`multiplex::core`（yamux/smux/h2mux 的基类）通过 `co_spawn(run_wrapper, detached)` 启动主循环，生命周期独立于 session。

- `core.transport_`：通过 `multiplex::bootstrap` 从 caller move 进来。**若 transport 是 preview，preview 必须用 global_pool**
- `core.router_`：L2 引用（`worker.router`），安全
- `core.traffic_`：L2 指针（`worker.traffic`），安全
- `core.prefix_`：值副本（`session_prefix` 是 POD），安全
- `core.cfg_`：L1 引用（`config` 进程级），安全

### anytls scheme.cpp 的 detached task

`anytls::scheme::handle_first_stream` 启动 `mux_task` 和 `forward_task`（detached）。两个 task 捕获 `session_ptr`（`context::session*` 裸指针）。

**安全性来源**：task 同时捕获 `keepalive`（`shared_ptr<session>`），keepalive 持有 session 引用计数，保证 session 在 task 期间不析构。因此 `session_ptr` 在 task 期间有效。

**类型化要求**：`keepalive` 字段类型必须是 `std::shared_ptr<context::session>`（不是 `std::shared_ptr<void>`），让安全性在类型层面体现，防止未来误删 keepalive。

### duct / parcel

`multiplex::duct` 和 `multiplex::parcel` 通过 `shared_from_this()` 持有自身，绑定到 `core`。它们继承 `core` 的 L4 属性，同样禁止使用 `frame_arena`。

---

## 审计与检查

### 静态审计

Prism 提供 `scripts/audit_detached.sh` 脚本，扫描所有 `net::co_spawn + net::detached` 的 lambda 捕获，检测危险模式（session&/*、frame_arena.get() 等）。

```bash
bash scripts/audit_detached.sh src/
```

预期：0 DANGEROUS，若干 REVIEW（人工确认）。

### 代码审查 checklist

新增 detached 协程或修改 PMR allocator 时，审查者必须确认：

- [ ] lambda 捕获列表中没有 session 裸引用/指针
- [ ] PMR container 没有用 `frame_arena.get()` 作为 allocator
- [ ] 通过 shared_ptr 持有的对象，对应的所有权链完整（如 keepalive）
- [ ] L4 对象的所有字段要么是值/shared_ptr，要么是 L1/L2 引用

---

## 参考实现

### 安全的 detached 协程模式

```cpp
// multiplex::core::start() 内部
auto run_wrapper = [self = shared_from_this()]()  // self 是 shared_ptr<core>
    -> net::awaitable<void>
{
    trace::scope_guard guard(self->prefix_);  // prefix_ 是 POD 值副本
    co_await self->run();                      // self 持有 core，core 持有 transport_（global_pool）
};
net::co_spawn(transport_->executor(), run_wrapper(), net::detached);
```

### 危险模式（已被审计脚本检测）

```cpp
// ❌ 危险：捕获 session 裸引用
net::co_spawn(exec, [session = &ctx]() {  // session 是 session&
    co_await session->something();         // session 可能已析构
}, net::detached);

// ❌ 危险：PMR allocator 来自 frame_arena
auto v = memory::vector<byte>(data, ctx.frame_arena.get());
// v 可能被 detached 协程持有，析构时 m_resource 悬垂
```
