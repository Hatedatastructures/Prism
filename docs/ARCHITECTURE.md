# Prism 架构：资源所有权模型

## 设计原则

Prism 采用纯协程（C++20 coroutine + Boost.Asio awaitable）架构，所有 I/O 操作异步执行。在这种架构下，**对象生命周期**与**资源所有权**是设计层面的核心问题——一个看似正确的对象引用，可能因为 detached 协程的存在而变成悬垂指针。

本文档定义 Prism 的四层资源所有权模型，明确 detached 协程的资源使用规则，从设计层面消除 use-after-free 类 bug。

---

## 四层所有权模型

Prism 所有资源按所有权范围分四层：

| 层 | 所有者 | 寿命 | 典型资源 | detached 协程可引用？ |
|----|--------|------|---------|---------------------|
| **L1 进程** | 进程 | 启动到退出 | `resource::process`（cfg / ssl / accounts）、`memory::system::global_pool()`、`stealth::scheme_registry` | ✅ 永远安全 |
| **L2 worker** | worker 线程 | worker 创建到销毁 | `resource::worker`（ioc / pool / router / dns / outbound / traffic / rate / tasks） | ✅ worker 不死即可 |
| **L3 session** | session 对象 | 单次连接 | `resource::session`（conn / buffer / inbound / outbound / detected / lease / meta / trace / arena / src） | ❌ 严禁 |
| **L4 detached** | detached 协程 | 协程启动到结束 | `multiplex::core.transport_`、`craft.prefix_`（值副本）、`craft.self`（shared_from_this） | 自带，不依赖外层 |

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

---

## 三层资源容器（resource/ 模块）

重构后（2026-07）resource/ 模块提供三层纯数据容器，替代旧的 resources/ 虚基类体系。

### 所有权链

```
main
  └─ shared_ptr<resource::process>           ← L1 进程级，唯一持有者
       └─ shared_ptr<resource::worker>       ← L2 工作级，runtime::worker + 所有 session 共享
            └─ shared_ptr<resource::session>  ← L3 会话级，runtime::session 持有
```

**对外共享，对内独占**。shared_ptr 跨层传递，值持有自己层的资源。上层释放 → 引用计数递减 → 所有引用释放后自动析构。

### 函数：只 2 个

| 函数 | 所在层 | 作用 |
|------|--------|------|
| `alive()` | worker, session | 检查资源链存活（atomic acquire），协程判断是否停止 |
| `stop()` | worker | 触发 io_context 停机，启动关机级联 |

`resource::process` 零函数，纯数据。其余全部是**公有字段**，不提供 getter/setter，调用方链式访问：

```cpp
ctx.trace                              // session 级
ctx.worker->traffic.on_connect()       // worker 级
ctx.worker->process->cfg->buffer.size  // 进程级
ctx.worker->outbound->make_router()    // unique_ptr 用 ->
```

### 新增资源规则

1. 放到实际归属层，不跨层
2. 作为公有字段，不加 getter
3. 不加透传：L2 加字段后 L3 不需要同步加同名方法
4. 不加新函数：2 个函数是上限。业务逻辑放业务类

### 构造模式

```cpp
// 每层都有一个嵌套 ::options struct 收敛构造参数
auto proc_opts = resource::process::options{cfg, ssl, accounts};
auto proc = std::make_shared<resource::process>(std::move(proc_opts));

auto wrk_opts = resource::worker::options{proc, mr, index};
auto wrk = std::make_shared<resource::worker>(std::move(wrk_opts));

auto ses_opts = resource::session::options{wrk, conn, buffer, inbound, src, trace, meta};
auto ses = std::make_shared<resource::session>(std::move(ses_opts));
```

---

## 模块依赖规范

### 依赖层次（禁止反向）

```
Level 0: foundation/  rate/           ← 零外部依赖
Level 1: trace/  crypto/              ← foundation only
Level 2: net/                         ← foundation + trace + crypto
           ├── connect/types.hpp      ← protocol_type
           ├── connect/target.hpp     ← target
           ├── transport/
           ├── connect/outbound/
           ├── connect/tunnel/
           └── dns/
Level 3: account/                     ← foundation + crypto + net
Level 4: protocol/                    ← net + account + crypto
Level 5: stealth/                     ← net + protocol + crypto
Level 5: resource/                    ← 纯聚合，仅被 runtime 头文件包含
Level 6: config/  runtime/            ← 顶层编排
```

### 允许/禁止表

| 模块 | 可依赖 | 禁止依赖 |
|------|--------|---------|
| `foundation/` `rate/` | 无 | 任何其他 |
| `trace/` | foundation | net, account, protocol, stealth, runtime |
| `crypto/` | foundation | net, account, protocol, stealth, runtime |
| `net/` | foundation, trace, crypto | resource, protocol, stealth, runtime |
| `account/` | foundation, crypto, net | protocol, stealth, runtime |
| `protocol/` | net, account, crypto | stealth, runtime |
| `stealth/` | net, protocol, crypto | runtime |
| `resource/` | net, account, crypto, trace | protocol, stealth, runtime |
| `config/` `runtime/` | 所有下层 | 无（顶层） |

### 头文件规则

- 前向声明优先：`.hpp` 中能前向声明就不 `#include`
- `unique_ptr<T>` 的 T 前向声明时，析构函数在 `.cpp` 中定义
- 禁止上行包含：下层 `.hpp` 绝不包含上层模块
- 聚合头维护：新增子头文件须同步更新模块聚合头

### 审计

```bash
grep -rn '#include <prism/\(resource\|stealth\|runtime\)' include/prism/net/
grep -rn '#include <prism/\(net\|resource\|protocol\|stealth\|runtime\)' include/prism/foundation/
grep -rn '#include <prism/\(stealth\|runtime\)' include/prism/protocol/
grep -rn '#include <prism/\(protocol\|stealth\|runtime\)' include/prism/resource/
# 全部应 0 命中
```

---

## 传参规范

- 函数参数 ≤ 3，超过用 struct 收敛
- opts struct 不继承，独立 POD
- 需要资源：`(resource::session&, opts)` 或 `(resource::worker&, opts)` — 2 参数上限
- 不需要资源：`(opts)` — 1 参数

```cpp
struct handler_params { resource::session& ctx; span<const byte> data; };
auto forward(resource::session& ctx, forward_options opts) -> awaitable<void>;
auto dial(resource::worker& w, const target& t, dial_options opts) -> awaitable<dial_result>;
auto tunnel(tunnel_options opts) -> awaitable<void>;
```
