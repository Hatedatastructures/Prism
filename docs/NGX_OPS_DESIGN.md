# Next-Gen 运营层设计（NGX_OPS_DESIGN.md）

> 目标：为 tests/common（psmtest）设计**接口先行、积木式**的运营层
> （认证 / 统计 / 账户 / 限速 / 可观测 / 会话注册表 / 管理 API）。
> 每个积木 = 独立头文件 + 独立测试 target + 明确热路径代价 + 可替换实现。
> 积木之间只通过接口组合，不硬编码耦合。
>
> 配套：任务入口 `docs/NEXTGEN_TASK.md` 的 T5 系列（T5-0 设计 → T5-1~T5-7 积木实现）。
> 参照：主项目 `include/prism/user/stats/traffic.hpp`（per-worker 原子 + COW 聚合）、
> `user/entry.hpp`（原子账户）、`user/directory.hpp`（COW map）。

---

## 0. 设计原则（积木纪律）

1. **接口先行**：每个积木先定义纯接口（无实现依赖），再提供 1 个默认实现 + 1 个 mock 实现。
2. **热路径代价明示**：每个接口方法标注代价等级：
   - `O(1)` 原子 / 条件分支 → 可进热路径（每包/每连接）
   - `COW` 读快照 → 温路径（每事件）
   - `冷路径` → 独立 io_context，不占 worker
3. **可组合**：积木通过接口指针注入（如 `traffic_sink*`），管道/会话只认识接口。
4. **可测试**：每个积木一个测试 target（`<Module>Test.cpp`），mock 驱动。
5. **可替换**：实现类不泄漏到上层；更换实现只改注入点。
6. **禁用全局可变状态**：跨 worker 聚合走 COW 注册表（对齐主项目 register_instance 模式）。

---

## 1. 积木总览

```
                    ┌─────────────────────────────────────────┐
                    │           T4 会话编排（pipeline）          │
                    │  context{identity, traffic, target,...}  │
                    └──────────────┬──────────────────────────┘
                                   │ 接口注入（非耦合）
      ┌──────────────┬─────────────┼─────────────┬────────────┐
      ▼              ▼             ▼             ▼            ▼
  [O1 auth]     [O2 stats]    [O3 account]   [O4 rate]   [O5 observe]
  认证积木        统计积木       账户积木       限速积木     可观测积木
  (已有接口)     (已有雏形)      (新建)        (部分已有)    (预留接口)
      │              │             │             │            │
      └──────────────┴──────┬──────┴──────┬──────┴────────────┘
                            ▼             ▼
                     [O6 registry]   [O7 api]
                     会话注册表        管理 API（冷路径，独立 ioc）
```

依赖方向：O1-O5 只依赖 core；O6 依赖 O2/O3 快照类型；O7 依赖 O1-O6 全部（冷路径）。

---

## 2. O1 auth 认证积木（已有接口，补生产实现）

**头文件**：`core/authenticator.hpp`（已存在 ✅）

```cpp
struct auth_result { bool ok; std::string identity; };   // identity 供统计聚合
class authenticator {
    virtual ~authenticator() = default;
    [[nodiscard]] virtual auto check(std::string_view identity, std::string_view secret) const
        -> auth_result = 0;
};
```

**已有实现**：`static_authenticator`（静态比对）、`reject_authenticator`（测试）。
**待补实现（T5-1）**：`directory_authenticator`——对接 O3 directory，检查账户存在 + 凭据匹配 + 未禁用/未过期；通过时返回 entry 的 identity。
**扩展点**：`check` 后置钩子（失败计数 → O4 rate 动态封禁）；多因子预留（凭据类型枚举）。

**热路径代价**：`O(1)`（hash 查找 + 比对），握手期调用非每包。
**测试**：`AuthenticatorTest.cpp`（已有）+ directory 认证器测试（存在/禁用/过期/错误凭据）。

---

## 3. O2 stats 统计积木（已有雏形，补完整接口）

**头文件**：`core/middleware/context.hpp`（traffic_sink 已存在）+ 新 `core/stats/traffic.hpp`

### 3.1 事件接口（积木入口）

```cpp
// context.hpp 现有（保持兼容）：
struct traffic_sink {
    virtual auto report(std::string_view identity, std::size_t up, std::size_t down) -> void = 0;
    virtual ~traffic_sink() = default;
};

// 新：连接生命周期事件（对齐主项目 traffic_state 语义）
struct session_observer {            // 可选积木：任何关心会话事件的模块实现它
    virtual ~session_observer() = default;
    virtual void on_connect() noexcept {}
    virtual void on_protocol_detected(std::uint16_t detected) noexcept {}
    virtual void on_disconnect(std::uint16_t detected) noexcept {}
    virtual void on_auth_success(std::string_view identity) noexcept {}
    virtual void on_auth_failure() noexcept {}
};
```

### 3.2 默认实现（T5-2）

`per_worker_traffic`：per-worker 原子计数（alignas(64) 防伪共享），
`on_*` 为原子操作；`report(identity, up, down)` 聚合到 identity 维度 + 协议维度。
跨 worker 聚合：COW 注册表（`register_instance/unregister_instance/aggregate`，
对齐主项目 `traffic_state` 静态成员）。
**快照类型**：`traffic_snapshot`（协议分布 + 用户分布 + 总量），纯数据 POD。

### 3.3 测试

`StatsBlockTest.cpp`：单 worker 原子累加；多 worker 聚合一致性；identity 维度正确；
快照离散一致性（主项目要求）。mock：`null_traffic`（丢弃）用于单元测试。

**热路径代价**：`on_*` = 1 原子；`report` = 2 原子（会话结束调一次）。

---

## 4. O3 account 账户积木（新建）

**头文件**：`core/account/entry.hpp` + `core/account/directory.hpp`（替换现有 README 空壳）

```cpp
struct entry {                                   // 原子账户运行时状态（对齐主项目）
    std::uint32_t max_connections{0};
    std::atomic_uint64_t uplink_bytes{0};
    std::atomic_uint64_t downlink_bytes{0};
    std::atomic_uint32_t active_connections{0};
    // 预留（配额/禁用/过期，T5 扩展）：
    std::uint32_t daily_quota{0};                // 0 = 不限
    std::int64_t  expires_at{0};                 // 0 = 永不过期（epoch ms）
    bool          disabled{false};
};

class directory {                                 // COW map（对齐主项目）
public:
    void upsert(std::string_view credential, uint32_t max_connections = 0);
    void remove(std::string_view credential);
    [[nodiscard]] auto find(std::string_view credential) const -> std::shared_ptr<entry>;
    // 新增（主项目 TODO #account）：
    template <typename F> auto for_each(F&& f) const -> void;   // 冷路径遍历
};
```

**设计要点**：COW map 指针交换实现热更新；`find` 为 O(1) 哈希（握手期）；
`for_each` 仅供冷路径（管理 API / 统计聚合），不允许进热路径。
**预留接口**：`lease`（会话配额 RAII：构造占用 active_connections，析构释放 +
累计流量；对齐主项目 `user::lease`），T5-3 实现。
**测试**：`AccountBlockTest.cpp`：CRUD、并发读写、for_each 遍历、过期/禁用判定。

---

## 5. O4 rate 限速积木（部分已有，补令牌桶）

**已有**：`core/rate/counter.hpp`（探测防御：滑动窗口失败计数 + 挑战判定，per-worker）。
**待补（T5-4）**：`core/rate/token_bucket.hpp`

```cpp
class token_bucket {                    // 每连接/每用户一份
public:
    token_bucket(std::uint64_t rate_bps, std::uint64_t burst_bps);
    [[nodiscard]] auto try_take(std::uint64_t bytes) noexcept -> bool;  // O(1) 原子
    void refill() noexcept;             // 定时或惰性补币
};
```

**组合点**：`rate_limiter`（聚合 counter + token_bucket）→ 注入 pipeline
（新中间件 `throttle_middleware`，消费 ctx.identity 找 per-user 桶，per-connection 桶内建）。
**扩展点**：配额联动（O3 daily_quota → 断连）、动态封禁（counter 达阈值 →
`ban_middleware` 拒绝新连接，带过期）。
**热路径代价**：`try_take` = 1 CAS（缺失补币走定时器，不进每包路径）。
**测试**：`RateBlockTest.cpp`：令牌桶速率/突发/耗尽；counter 窗口/阈值/过期；
throttle 中间件全链路（限制内正常、超限拒绝）。

---

## 6. O5 observe 可观测积木（接口预留，先定义后实现）

**头文件**：`core/observe/hdr.hpp` + `core/observe/ewma.hpp` + `core/observe/trace.hpp`（T5-5）

```cpp
// 阶段枚举：accept / dns / dial / tls / first_byte / first_response
struct latency_observer {                       // 可选积木：HDR 直方图
    virtual ~latency_observer() = default;
    virtual void record(std::uint8_t stage, std::int64_t us) noexcept = 0;  // 1 CAS
};

struct rate_observer {                          // EWMA 实时速率
    virtual ~rate_observer() = default;
    virtual void sample(std::uint64_t bytes, std::int64_t dt_us) noexcept = 0; // 1 原子
};

struct trace_observer {                         // 采样追踪（1/N 原子采样 + SPSC ring）
    virtual ~trace_observer() = default;
    virtual void mark(std::uint8_t stage, std::int64_t us) noexcept = 0;
};
```

**设计定位**：三个 observer 均为**可选旁路**——会话编排在阶段点调用
（若 observer 注入则 1 原子记录，否则零代价 if 分支）；冷路径导出（T8 管理 API 消费）。
**实现顺序**：接口 + mock（T5-5）→ 完整实现（T5-6，EWMA → HDR → 采样追踪）。
**热路径代价**：每阶段 ≤1 原子（未注入时 0）。
**测试**：`ObserveBlockTest.cpp`：bucket 精度/聚合、EWMA 收敛、采样率统计。

---

## 7. O6 registry 会话注册表（新建，COW 快照）

**头文件**：`core/registry/session_registry.hpp`（T5-7）

```cpp
struct session_snapshot {                       // 纯数据值拷贝，严禁引用
    std::uint64_t session_id;
    std::uint16_t protocol;
    std::string   identity;
    std::string   target;
    std::uint64_t up_bytes, down_bytes;
    std::int64_t  started_at_ms;
    std::uint8_t  stage;                        // 当前阶段（O5 枚举）
    // 预留：实时速率（EWMA 快照）
};

class session_registry {
public:
    void put(const session_snapshot& s);        // COW 写（温路径：每事件）
    void remove(std::uint64_t id);              // COW 写
    [[nodiscard]] auto snapshot_all() const -> memory::vector<session_snapshot>; // 冷路径读
};
```

**实现**：复用 O3 directory 的 COW map 模式（模板化 `cow_map<K,V>` 下沉到
`core/memory/cow_map.hpp`，O3/O6 共用——**积木复用点**）。
**热路径代价**：put/remove 仅会话级事件（温路径），不进每包循环。
**测试**：`RegistryBlockTest.cpp`：并发读写、值拷贝语义（写入后源对象释放不影响）、
快照一致性。

---

## 8. O7 api 管理 API（冷路径，消费 O1-O6）

**头文件**：`core/api/manager.hpp`（T5-8，接口 + 骨架）

```cpp
struct api_options {                            // 积木注入点
    const auth::authenticator*       admin_auth;   // 管理面认证（复用 O1）
    const stats::aggregate_sink*     traffic;      // O2 聚合快照
    const account::directory*        directory;    // O3
    const registry::session_registry* sessions;    // O6
    const observe::latency_observer* latency;      // O5
    std::uint16_t                    port;         // 默认 9090 本机绑定
};

class manager {                                 // 独立 io_context，冷路径
public:
    explicit manager(api_options opts);
    void start();                               // 独立线程 run
    void stop();
};
```

**设计定位**：本积木只定义**资源树契约**（路由 → 数据源映射）与骨架，
实现放 T8（管理面全景）。接口先行保证 O1-O6 快照类型稳定。
**预留**：SSE 流（/traffic 实时、/alerts）、Bearer token 认证、/reload（COW 热更新）。
**测试**：`ApiBlockTest.cpp`：路由注册/资源树/鉴权拒绝（mock 数据源）。

---

## 9. 积木实现顺序（T5 系列任务）

| 任务 | 积木 | 内容 | 依赖 |
|---|---|---|---|
| T5-1 | O1 | directory_authenticator + 账户判定 | T5-3 前可先用静态目录 |
| T5-2 | O2 | per_worker_traffic + 快照 + COW 聚合 | 无 |
| T5-3 | O3 | entry/directory/lease + cow_map 下沉 | 无（cow_map 先做） |
| T5-4 | O4 | token_bucket + throttle/ban 中间件 | T5-3（per-user 桶） |
| T5-5 | O5 | 接口 + mock（hdr/ewma/trace） | 无 |
| T5-6 | O5 | 完整实现（EWMA→HDR→采样追踪） | T5-5 |
| T5-7 | O6 | session_registry（复用 cow_map） | T5-3 |
| T5-8 | O7 | api manager 接口 + 骨架 + 路由契约 | T5-1..T5-7 |

**积木独立性**：T5-2/T5-3/T5-5 可并行；T5-4/T5-7 依赖 T5-3；T5-8 依赖全部快照类型。

---

## 10. 会话编排接入点（T4 集成）

```
session 编排（T4-2）：
  accept → recognition(detected)
    → observer.on_connect()                        [O2/O5 可选]
    → pipeline:
         auth_middleware       → directory_authenticator.check() [O1] → ctx.identity
         throttle_middleware   → token_bucket [O4]（可选）
         dial_middleware       → dialer [T3]
         relay_middleware      → 双向转发，结束 report(identity, up, down) [O2]
    → observer.on_disconnect() [O2]
    → registry.put/remove(snapshot) [O6]（会话级）
```

**接口注入方式**：`session_options` 结构承载 observer/traffic/registry 指针
（接口指针，非具体类型）——积木替换只改装配点，不动编排逻辑。

---

## 11. 验收总则

- 每个积木独立测试 target，mock 驱动，`co_spawn + ioc.run()` 模式。
- **无人值守数据记录**：每积木完成后把四象限原始数据写入
  `docs/ngx-test-data/<积木>.md`（模板见 NEXTGEN_TASK 2.4），状态 PASS 才进入下一积木；
  不向用户汇报，用户只查看数据文件。
- **四象限测试（与 NEXTGEN_TASK 2.3 一致）**：
  - Q1 分支覆盖（G13）：每积木按分支核对清单测试——正常路径、每个 if/else、每个
    switch case、边界（0/1/最大/溢出）、坏数据、超时/取消路径；用例以
    `// 分支: <路径>` 注释标注。
  - Q2 覆盖率（G14）：新积木模块覆盖率 ≥ 80%（行+分支），报告随 TASK_PROGRESS 记录。
  - Q3 性能（G12）：热路径方法建 bench 记录基线（如 token_bucket::try_take、
    directory::find、HDR::record、traffic on_*），回归对比 ±3%。
  - Q4 压测（G15/G16）：有状态/并发积木建 stress（并发认证、16 worker 统计聚合、
    COW 高压替换、满速率限速、万级会话注册、ring 高速写入），记录内存曲线无泄漏。
  - 小改动（行为无变化或 ≤10 行非逻辑改动）可豁免 Q3/Q4，需在数据文件中注明依据；
    Q1/Q2 永不免除。
- 热路径代价审计：O2 on_* ≤1 原子；O4 try_take ≤1 CAS；O5 record ≤1 CAS；
  O3 find O(1)；O6 put 仅会话级。逐项写入 TASK_PROGRESS 决策记录与数据文件。
- 全量回归绿；G4（命名）、G5（接口）、G7（CMake）零命中。
- 快照类型全 POD（值拷贝语义），严禁 L3 引用泄漏进快照。
