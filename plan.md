# Prism 代理服务器 — 8 周详细开发计划

> **编制日期**: 2026/05/01
> **时间跨度**: 2026/05/01 — 2026/06/30 (共 8 周)
> **编制依据**:
> - `logs/forward.log` 基准测试日志全量分析
> - `docs/prism/performance-report.md` 性能报告
> - 全项目源码深度审计（42 测试文件、12 基准套件、~9000 行源码）
> - 与 mihomo/Xray/sing-box/HAProxy/shadowsocks-rust 等同类项目性能对比

---

## 一、项目现状总览

### 1.1 已完成（生产就绪）

| 模块 | 状态 | 关键文件 |
|------|------|---------|
| HTTP 代理 | 完成 | `src/prism/pipeline/protocols/http.cpp` |
| SOCKS5 (TCP+UDP) | 完成 | `src/prism/pipeline/protocols/socks5.cpp` |
| Trojan (TCP+UDP+MUX) | 完成 | `src/prism/pipeline/protocols/trojan.cpp` |
| VLESS (TCP+UDP+MUX) | 完成 | `src/prism/pipeline/protocols/vless.cpp` |
| SS2022 AEAD (TCP+UDP) | 完成 | `src/prism/pipeline/protocols/shadowsocks.cpp` |
| Reality TLS 伪装 | 完成 | `src/prism/stealth/reality/` |
| ShadowTLS v2 | 完成 | `src/prism/stealth/shadowtls/` |
| smux v1 多路复用 | 完成 | `src/prism/multiplex/smux/` |
| yamux 多路复用 | 完成 | `src/prism/multiplex/yamux/` |
| 七阶段 DNS 解析 | 完成 | `src/prism/resolve/dns/` |
| Happy Eyeballs (RFC 8305) | 完成 | `include/prism/channel/eyeball/` |
| 连接池 + 健康检查 | 完成 | `src/prism/channel/connection/pool.cpp` |
| 加权负载均衡 | 完成 | `src/prism/agent/balancer/` |
| PMR 内存管理 | 完成 | `include/prism/memory/` |
| 协议识别 (Probe→Arrival→Handshake) | 完成 | `src/prism/recognition/` |
| 测试套件 | 42 个测试文件 | `tests/` |
| 基准套件 | 12 个基准文件 | `benchmarks/` |

### 1.2 未完成 / TODO（本次计划要解决）

| # | TODO 位置 | 问题描述 | 优先级 |
|---|----------|---------|--------|
| 1 | `src/prism/stealth/restls/scheme.cpp:55` | Restls 握手为 TODO 桩，直接返回 `protocol_type::tls` | CRITICAL |
| 2 | `include/prism/recognition/arrival/ech.hpp:50,55` | ECH 分析器未注册，`return false` | HIGH |
| 3 | `include/prism/recognition/arrival/anytls.hpp:47,54` | AnyTLS 返回 `confidence::none`，未注册 | HIGH |
| 4 | `src/prism/resolve/router.cpp:49-56` | 正向代理 `async_positive()` 返回 `not_supported` | HIGH |
| 5 | `include/prism/channel/eyeball/racer.hpp:28` | Happy Eyeballs 需重构 | MEDIUM |
| 6 | `src/prism/resolve/detail/upstream.cpp:19` | DNS 截断响应处理 TODO（代码已实现，缺测试） | LOW |
| 7 | `include/prism/multiplex/yamux.hpp:21` | Yamux 窗口流控 TODO（代码已实现，缺压力测试） | LOW |

### 1.3 性能瓶颈（基准测试暴露）

| 瓶颈 | 当前值 | 业界标准 | 差距倍数 | 根因 |
|------|--------|---------|---------|------|
| **AES-256-GCM 吞吐** | **205 Mi/s** | 2.0+ Gi/s (AES-NI) | **10x** | `CMakeLists.txt:78` 禁用 ASM |
| X25519 密钥交换 | 81.5 us | ~50 us | 1.6x | EVP_PKEY 高阶 API 开销 |
| 全局内存池 4T | 3530 ns | <100 ns | 35x | `synchronized_pool` 锁竞争 |
| 连接延迟 P99 | 336 us | <200 us | 1.7x | 健康检查 + DNS 偶发阻塞 |
| TCP Echo 64B | 20.1 us | ~5 us | 4x | 内核 syscall 开销 |

### 1.4 代码质量问题

| 问题 | 位置 | 影响 |
|------|------|------|
| `dynamic_cast` 3 处 | `restls/scheme.cpp:46`, `shadowtls/scheme.cpp:44` | 依赖 RTTI，包装传输时失败 |
| 协议处理器重复 ~150 行 | `trojan.cpp` vs `vless.cpp` vs `socks5.cpp` | 维护成本高 |
| 缺少 eyeball/health/tunnel 测试 | `tests/` 目录 | 关键路径无覆盖 |
| 无性能回归监控 | 无 `RegressionBench` | 退化无法自动发现 |

---

## 二、性能目标（Before → After）

| 指标 | Before | 第 2 周目标 | 第 8 周目标 | 业界对标 |
|------|--------|------------|------------|---------|
| AES-256-GCM | 205 Mi/s | **2.0+ Gi/s** | 2.0+ Gi/s | shadowsocks-rust 1-2 Gi/s |
| AES-128-GCM | 245 Mi/s | **1.5+ Gi/s** | 1.5+ Gi/s | — |
| X25519 交换 | 81.5 us | 45-55 us | 45-55 us | WireGuard ~40 us |
| 全局池 4T | 3530 ns | <150 ns | <100 ns | — |
| 连接 P50 | 95 us | 90 us | 85 us | Envoy ~100 us |
| 连接 P99 | 336 us | <250 us | <200 us | — |
| TCP 64B | 20.1 us | 15 us | 10 us | — |
| TCP 128KB | 7.11 Gi/s | 7.11 Gi/s | 7.11 Gi/s | HAProxy ~10 Gbps |
| 未完成 TODO | 7 个 | 0 | 0 | — |
| `dynamic_cast` | 3 处 | 0 | 0 | — |
| 测试文件 | 42 | 48+ | 55+ | — |

---

## 三、第一阶段 (第 1-2 周): 关键性能修复

### 第 1 周

#### 任务 1.1: 启用 BoringSSL AES-NI 汇编【优先级: CRITICAL — 最大性能瓶颈】

**根因定位**: `CMakeLists.txt:76-78`

```cmake
# 当前 (行 76-78):
# MinGW + Windows 下 NASM 汇编存在兼容性问题（fiat_p256_adx 链接失败），
# 暂时使用 OPENSSL_NO_ASM 纯 C 实现。AES-GCM ~240 Mi/s 对代理场景已足够。
set(OPENSSL_NO_ASM ON CACHE BOOL "" FORCE)
```

这行代码禁用了 **所有** BoringSSL 汇编优化，包括：
- AES-NI (编译器内建汇编，不依赖 NASM)
- SHA extensions
- ADX/AVX2 优化

实际上 `fiat_p256_adx` 链接失败仅影响 ADX 扩展的 NASM 汇编文件，不影响 AES-NI 的编译器内建汇编（`<wmmintrin.h>` / `<immintrin.h>`）。

**修改方案**: 将 `CMakeLists.txt:76-78` 替换为平台感知策略：

```cmake
# BoringSSL 汇编启用策略
# MinGW 下 NASM 与 fiat_p256_adx 不兼容，但 AES-NI 使用编译器内建汇编不受影响
# 因此仅 MinGW 保持纯 C，其他平台全开 ASM
if(MINGW)
    # MinGW: NASM 兼容性问题，保持纯 C 实现 (~240 Mi/s)
    set(OPENSSL_NO_ASM ON CACHE BOOL "" FORCE)
elseif(MSVC)
    # MSVC: BoringSSL 支持 Go 汇编生成器，无需 NASM
    set(OPENSSL_NO_ASM OFF CACHE BOOL "" FORCE)
else()
    # Linux/Clang: 完整 ASM 支持
    set(OPENSSL_NO_ASM OFF CACHE BOOL "" FORCE)
endif()
```

**复用现有**: `benchmarks/crypto_bench.cpp` 已有 AEAD 吞吐量基准，可直接验证。

**预期效果**: AES-256-GCM 从 205 Mi/s → 2.0+ Gi/s（约 10 倍提升）

**验证步骤**:
1. 删除 `build_release/`，重新配置 `cmake -B build_release -DCMAKE_BUILD_TYPE=Release`
2. `cmake --build build_release --config Release`
3. 观察 BoringSSL 编译输出中是否包含 `aesni-gcm-avx2-x86_64.s` 或 `ghash-ssse3-x86_64.s`
4. 运行 `build_release/benchmarks/crypto_bench.exe`，确认 AEAD throughput >2 Gi/s

**风险**: 如果在 MSVC 下 Go 汇编生成器仍有问题，备选方案是使用 OpenSSL 替代 BoringSSL（需修改 CMake 依赖和 `#include` 路径）。

---

#### 任务 1.2: X25519 密钥交换优化

**涉及文件**:
- `src/prism/crypto/x25519.cpp` — 当前使用 `EVP_PKEY` 高阶 API
- `include/prism/crypto/x25519.hpp` — 公开接口
- `benchmarks/crypto_bench.cpp` — X25519 基准

**当前实现分析**: 使用 `EVP_PKEY_CTX_new()`, `EVP_PKEY_keygen_init()`, `EVP_PKEY_derive()` 等 OpenSSL 高阶 API，每次调用涉及：
- `EVP_PKEY` 对象分配
- `EVP_PKEY_CTX` 上下文初始化
- 参数编码/解码

这些在 ASM 启用后标量乘法本身会加速，但 EVP 层开销仍存在。

**优化方案**（在任务 1.1 完成后评估是否需要）:

1. 先运行 1.1 后的基准测试，如果 X25519 已 <50 us 则跳过。
2. 若仍高于 50 us，将 `x25519.cpp` 中的 EVP_PKEY 替换为 BoringSSL 低层 API：

```cpp
// 替换前 (EVP_PKEY):
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
EVP_PKEY_derive_init(ctx);
EVP_PKEY_derive(ctx, out, &out_len);

// 替换后 (低层 X25519):
#include <openssl/curve25519.h>
if (!X25519(shared.data(), private_key.data(), peer_public_key.data()))
    return {fault::code::crypto_error, {}};
```

3. `generate_x25519_keypair()` 同样替换为 `X25519_keypair(pub, priv)`。

**预期效果**: 81.5 us → 45-55 us（若 ASM 已启用，可能已达标）

**验证**: `build_release/benchmarks/crypto_bench.exe --benchmark_filter=*X25519*`

---

#### 任务 1.3: 全局内存池分片化

**涉及文件**:
- `include/prism/memory/pool.hpp:47-59` — `system::global_pool()` 当前返回 `synchronized_pool`
- `benchmarks/MemoryBench.cpp` — 需添加并发基准

**当前问题**: `std::pmr::synchronized_pool` 内部使用全局互斥锁。基准数据显示 4 线程下从 142 ns 退化到 3530 ns（26.5 倍），8 线程退化到 10422 ns（73 倍）。

**实施方案**:

在 `include/prism/memory/pool.hpp` 中新增 `sharded_pool` 类：

```cpp
class sharded_pool : public std::pmr::memory_resource {
    static constexpr std::size_t shard_count = 8;
    struct alignas(64) aligned_shard { // cache line 对齐防止 false sharing
        std::pmr::unsynchronized_pool_resource pool;
    };
    std::array<aligned_shard, shard_count> shards_;

    auto do_allocate(std::size_t bytes, std::size_t alignment)
        -> void* override
    {
        auto const id = std::hash<std::thread::id>{}(std::this_thread::get_id());
        return shards_[id % shard_count].pool.allocate(bytes, alignment);
    }

    void do_deallocate(void* p, std::size_t bytes, std::size_t alignment) override {
        // 遍历分片查找归属（或通过元数据记录）
        for (auto& s : shards_) {
            if (s.pool.is_this_thread_allocator(p)) {
                s.pool.deallocate(p, bytes, alignment);
                return;
            }
        }
    }

    [[nodiscard]] auto do_is_equal(std::pmr::memory_resource const& other) const noexcept
        -> bool override { return this == &other; }
};
```

修改 `system::enable_global_pooling()` 和 `system::global_pool()` 使用 `sharded_pool`。

**复用现有**: `benchmarks/MemoryBench.cpp` 已有 `BM_GlobalPool` / `BM_ThreadLocalPool` 基准，添加多线程版本。

**预期效果**: 4T 下 3530 ns → <150 ns

**验证**: 运行 `build_release/benchmarks/memory_bench.exe`

---

#### 任务 1.4: P99 尾延迟优化

**涉及文件**:
- `include/prism/channel/connection/pool.hpp` — 连接池 `async_acquire()`
- `include/prism/channel/eyeball/racer.hpp:28` — Happy Eyeballs TODO

**当前问题**: 基准数据显示 P50=95 us，P99=336 us（3.5 倍差距），说明偶发系统级停顿。

**实施方案**:

1. **快速路径跳过健康检查** (`pool.hpp` 的 `async_acquire()`):
   ```cpp
   // 如果连接在最近 1 秒内使用过，跳过 healthy_fast() 检查
   auto const now = std::chrono::steady_clock::now();
   if ((now - item.last_used) < std::chrono::seconds(1)) {
       co_return item.conn; // 快速路径
   }
   ```

2. **预创建机制**: 当池为空需要新建连接时，后台预创建第二个：
   ```cpp
   if (cache.empty()) {
       // 立即创建第一个
       auto conn = co_await create_connection();
       // 后台预创建第二个
       net::co_spawn(executor, [this]() {
           return async_prewarm();
       }, net::detached);
       co_return conn;
   }
   ```

3. **Happy Eyeballs 竞态取消** (`racer.hpp`): 确保 `race_context::winner` 写入后立即调用 `cancel_all()`。

**预期效果**: P99 336 us → <250 us

---

### 第 2 周

#### 任务 2.1: 小报文 TCP 优化

**涉及文件**:
- `include/prism/channel/transport/reliable.hpp` — 底层传输
- `include/prism/pipeline/primitives.hpp` — `tunnel()` / `forward()` 函数

**当前问题**: 64B TCP Echo 20.1 us，主要开销在 kernel syscall + IOCP 完成端口调度。

**实施方案**:

1. 审查 `reliable.hpp` 中 `async_read_some` / `async_write_some` 的调用链，确保无多余 `buffered_reader` / `preview` 等包装层增加间接开销。

2. 在 `tunnel()` 函数中对小报文（<1KB）尝试合并读写：读取到缓冲区后一次性写入，减少协程挂起/恢复次数。

3. Windows 下 ~5 us 理论极限需要内核旁路（io_uring 仅 Linux），当前目标先降至 12-15 us。

**预期效果**: 64B TCP Echo 20.1 us → 12-15 us

---

#### 任务 2.2: 性能回归基准

**新建文件**: `benchmarks/RegressionBench.cpp`

**实施方案**:

创建回归基准测试，覆盖所有关键路径：

| 指标 | 基准函数 | 阈值 |
|------|---------|------|
| AES-256-GCM | `BM_AeadContinuousSealAes256Gcm` | >500 Mi/s |
| X25519 | `BM_X25519KeyExchange` | <50 us |
| 全局池 4T | `BM_GlobalPoolConcurrent` | <150 ns |
| 连接 P99 | `BM_ConnectionLatencyP99` | <250 us |
| TCP 64B | `BM_TcpEcho64B` | <15 us |

输出格式：JSON + 控制台表格，退化 >10% 退出非零。

**同时新建**: `benchmarks/baselines.json` 存储基准阈值。

---

#### 任务 2.3: 第一阶段整体验证

```bash
# 全量基准
build_release/benchmarks/crypto_bench.exe
build_release/benchmarks/memory_bench.exe
build_release/benchmarks/io_bench.exe
build_release/benchmarks/latency_bench.exe
build_release/benchmarks/RegressionBench.exe

# 全量测试
ctest --test-dir build_release --output-on-failure
```

**通过标准**: 所有 Phase 1 性能目标达成，全部测试通过。

---

## 四、第二阶段 (第 3-4 周): 补全未完成功能

### 第 3 周

#### 任务 3.1: 实现 Restls 完整握手流程

**涉及文件**:
- `src/prism/stealth/restls/scheme.cpp:33-67` — 当前 `execute()` 为 TODO 桩
- `include/prism/stealth/restls/scheme.hpp` — 需添加私有辅助方法
- **新建**: `include/prism/stealth/restls/handshake.hpp`
- **新建**: `src/prism/stealth/restls/handshake.cpp`

**当前代码分析** (`scheme.cpp:33-67`):
```cpp
auto scheme::execute(scheme_context ctx) -> net::awaitable<scheme_result>
{
    // ... dynamic_cast 获取 reliable transport ...
    // TODO: 实现完整的 Restls 握手流程
    // 1. 读取客户端 TLS ClientHello
    // 2. 建立到后端 TLS 服务器的连接
    // 3. 在 TLS 应用数据中验证客户端身份
    // 4. 认证成功后，使用 restls-script 控制流量模式
    result.detected = protocol::protocol_type::tls;
    result.transport = std::move(ctx.inbound);  // 直接 pass-through
    co_return result;
}
```

**Restls 协议流程** (参照 https://github.com/3andne/restls):

1. **ClientHello 阶段**: 客户端发送 TLS ClientHello，其中包含 Restls 标识（特定 SNI 或 extension）
2. **后端连接阶段**: 服务端连接到真实后端 TLS 服务器（如 `www.microsoft.com:443`）
3. **认证阶段**: 客户端在 TLS 应用数据中发送认证信息（密码哈希）
4. **流量控制阶段**: 认证通过后，使用 restls-script 控制流量模式（模拟真实 TLS 流量时序）

**实施步骤**:

1. 在 `handshake.hpp` 中定义：
   ```cpp
   struct handshake_result {
       bool authenticated = false;
       shared_transmission transport;
       fault::code error;
   };
   auto handshake(shared_transmission client, const config &cfg,
                  const net::any_io_executor &executor)
       -> net::awaitable<handshake_result>;
   ```

2. 在 `handshake.cpp` 中实现：
   - 读取 ClientHello 并解析 SNI（复用 `src/prism/recognition/arrival/` 中的 ClientHello 解析逻辑）
   - 通过 `channel::eyeball::racer` 连接到后端 TLS 服务器（复用 `src/prism/resolve/dns/upstream.cpp:133-147` 的 TLS 握手逻辑）
   - 建立后端 TLS 连接后，进入认证循环
   - 读取客户端首条 TLS 应用数据记录，验证密码哈希
   - 成功则返回 `authenticated=true` 的 transport
   - 失败则返回 `error`

3. 在 `scheme.cpp:execute()` 中替换 TODO 桩：
   ```cpp
   auto hs_result = co_await handshake(std::move(ctx.inbound), cfg, executor);
   if (hs_result.authenticated) {
       result.detected = protocol::protocol_type::tls;
       result.transport = std::move(hs_result.transport);
   } else {
       result.error = hs_result.error;
       result.transport = std::move(ctx.inbound);
   }
   co_return result;
   ```

4. 在 `include/prism/config.hpp` 的 `stealth.restls` 配置中确认包含 `host` / `port` / `password` 字段。

**复用现有代码**:
- ClientHello 解析: `src/prism/recognition/arrival/`
- TLS 后端连接: `src/prism/resolve/dns/upstream.cpp` TLS 握手
- 密码哈希: `src/prism/crypto/sha224.cpp` 或 BLAKE3

**验证**:
- 运行 `build_release/tests/Restls.exe`
- 补充握手成功/失败测试用例

---

#### 任务 3.2: 启用 ECH 分析器

**涉及文件**:
- `include/prism/recognition/arrival/ech.hpp` — 第 50 行 `return false`，第 55-56 行注释掉的注册
- `include/prism/config.hpp` — 需添加 `stealth.ech` 配置

**当前代码分析** (`ech.hpp`):
```cpp
auto ech_analyzer::analyze(const clienthello_features &features,
                            const psm::config &cfg) const
    -> std::pair<confidence, arrival_action> override
{
    if (features.has_ech_extension) {
        return {confidence::high, arrival_action::accept};  // 分析逻辑正确
    }
    return {confidence::none, arrival_action::pass};
}
// ...
auto ech_analyzer::is_enabled(const psm::config &cfg) const noexcept -> bool override
{
    return false;  // TODO: 第 50 行 — 硬编码 false，导致永不启用
}
// 第 55-56 行: // REGISTER_ARRIVAL(ech)  — 被注释掉了
```

**修改步骤**:

1. `ech.hpp:50`: 改为 `return cfg.stealth.ech.enabled;`
2. `ech.hpp:55-56`: 取消注释 `REGISTER_ARRIVAL(ech)`
3. `config.hpp`: 在 stealth 配置中添加：
   ```cpp
   struct ech_config {
       bool enabled = false;
   } ech;
   ```

**预期效果**: ECH 分析器被注册到 `arrival::registry`，TLS ClientHello 含 ECH 扩展时可被识别为 ECH 方案。

---

#### 任务 3.3: 实现 AnyTLS 分析器 + 伪装方案

**涉及文件**:
- `include/prism/recognition/arrival/anytls.hpp:47,54` — 返回 `confidence::none`，未注册
- **新建**: `include/prism/stealth/anytls/scheme.hpp`
- **新建**: `src/prism/stealth/anytls/scheme.cpp`
- `include/prism/config.hpp` — 添加 `stealth.anytls` 配置

**分析**: AnyTLS 无 ClientHello 层特征（外观为标准 TLS），所以 `arrival::anytls` 正确返回 `confidence::none`——它将作为 fallback scheme 在 stealth executor 中被尝试。

**实施步骤**:

1. 在 `config.hpp` 中添加：
   ```cpp
   struct anytls_config {
       bool enabled = false;
       std::string password;
   } anytls;
   ```

2. 新建 `stealth/anytls/scheme.hpp`:
   ```cpp
   namespace psm::stealth::anytls {
       class scheme : public stealth_scheme {
           auto is_enabled(const config &cfg) const noexcept -> bool override;
           auto name() const noexcept -> std::string_view override;
           auto execute(scheme_context ctx) -> net::awaitable<scheme_result> override;
       };
   }
   ```

3. 新建 `stealth/anytls/scheme.cpp`:
   - `is_enabled()`: 返回 `cfg.stealth.anytls.enabled && !cfg.stealth.anytls.password.empty()`
   - `execute()`: 读取 TLS 应用数据 → 前 32 字节与 `SHA256(password)` 比对 → 匹配则剥离认证头返回 transport → 不匹配则 pass-through

4. `anytls.hpp:54`: 取消注释 `REGISTER_ARRIVAL(anytls)`

**验证**: 新建 `tests/AnyTls.cpp` 测试认证成功/失败场景。

---

#### 任务 3.4: 消除 stealth 方案中的 dynamic_cast

**涉及文件**:
- `src/prism/stealth/restls/scheme.cpp:46` — `dynamic_cast<channel::transport::reliable *>`
- `src/prism/stealth/shadowtls/scheme.cpp:44` — `dynamic_cast<channel::transport::reliable *>`
- `include/prism/channel/transport/transmission.hpp` — 基类
- `include/prism/channel/transport/reliable.hpp` — 派生类

**当前问题**:
```cpp
// restls/scheme.cpp:46:
auto *rel = dynamic_cast<channel::transport::reliable *>(ctx.session->inbound.get());

// shadowtls/scheme.cpp:44:
auto *rel = dynamic_cast<channel::transport::reliable *>(ctx.inbound.get());
```

问题：
1. 需要 RTTI（`-frtti`），增加二进制体积
2. 如果 `inbound` 被 `preview` 等装饰器包装，`dynamic_cast` 失败

**修改步骤**:

1. 在 `include/prism/channel/transport/transmission.hpp` 中添加虚方法：
   ```cpp
   /**
    * @brief 获取底层 raw socket（仅可靠传输支持）
    * @return tcp::socket* 如果是可靠传输，否则返回 nullptr
    */
   [[nodiscard]] virtual tcp::socket* raw_socket() noexcept { return nullptr; }
   ```

2. 在 `include/prism/channel/transport/reliable.hpp` 中覆写：
   ```cpp
   tcp::socket* raw_socket() noexcept override { return &socket_; }
   ```

3. 替换 3 处 `dynamic_cast`:
   ```cpp
   // 替换前:
   auto *rel = dynamic_cast<channel::transport::reliable *>(ctx.inbound.get());
   // 替换后:
   auto *rel = ctx.inbound->raw_socket();
   ```

4. 在 `CMakeLists.txt` 中添加 `-fno-rtti`（Linux/Clang）或 `/GR-`（MSVC）编译选项。

5. 验证全量编译通过且 42 个测试全部通过。

**预期效果**: 消除 RTTI 依赖，减少二进制体积，装饰器模式下也能正确获取 raw socket。

---

### 第 4 周

#### 任务 4.1: 实现正向代理模式

**涉及文件**:
- `src/prism/resolve/router.cpp:49-56` — 当前返回 `not_supported`
- `include/prism/resolve/router.hpp` — `async_positive()` 声明
- `include/prism/agent/config.hpp` — `positive_host_` / `positive_port_` 配置字段
- `include/prism/protocol/http/` — 复用 HTTP CONNECT 解析逻辑

**当前代码** (`router.cpp:49-56`):
```cpp
auto router::async_positive(const std::string_view host, const std::string_view port)
    -> net::awaitable<std::pair<fault::code, pooled_connection>>
{
    // TODO: 正向代理模式暂未实现，当前没有后端服务无法测试
    static_cast<void>(host);
    static_cast<void>(port);
    co_return std::make_pair(fault::code::not_supported, pooled_connection{});
}
```

**实施方案**:

1. 通过 `pool_.async_acquire(positive_host_, positive_port_)` 获取到上游代理的 TCP 连接。

2. 构造并发送 HTTP CONNECT 请求：
   ```
   CONNECT {host}:{port} HTTP/1.1\r\n
   Host: {host}:{port}\r\n
   \r\n
   ```

3. 读取 HTTP 响应，解析状态码（复用 `protocol::http` 的解析逻辑，期望 `HTTP/1.1 200 Connection Established`）。

4. 如果认证成功，将 TCP 连接包装为 `pooled_connection` 返回。

5. 如果失败（非 200 或超时），返回对应的 `fault::code`。

**复用现有代码**:
- HTTP 响应解析: `include/prism/protocol/http/parser.hpp`
- 连接获取: `pool_.async_acquire()` 已有完整实现
- 配置读取: `cfg_.positive_host` / `cfg_.positive_port`

**验证**: 新建 `tests/ForwardProxy.cpp`：
- 成功 CONNECT 到上游代理
- 上游代理返回 407 (Proxy Auth Required)
- 上游代理不可达

---

#### 任务 4.2: 重构 Happy Eyeballs

**涉及文件**:
- `include/prism/channel/eyeball/racer.hpp:28` — `// TODO: refactor happy eyeballs logic`
- `src/prism/channel/eyeball/racer.cpp` — 实现文件

**当前问题**:
1. 250ms 延迟硬编码
2. 取消逻辑可能不完整（需验证 winner 写入后立即取消所有定时器）
3. 无可配置参数

**实施方案**:

1. **添加配置结构** 到 `config.hpp`:
   ```cpp
   struct eyeball_config {
       std::chrono::milliseconds delay = std::chrono::milliseconds(250);
       std::chrono::milliseconds timeout = std::chrono::seconds(10);
       bool prefer_ipv6 = false;
   };
   ```

2. **审查取消逻辑**: 确保 `race_context::set_winner()` 中调用 `cancel_all()` 取消所有 pending timers 和未赢的 socket。

3. **添加指标**: 在 racer 中记录：
   - 首端点胜率
   - 后续端点胜率
   - 平均竞态时间

4. **简化代码结构**: 将 `race()` 函数拆分为 `create_endpoint()` / `handle_connect_result()` / `cancel_remaining()` 等辅助函数。

**验证**: 新建 `tests/EyeballRacer.cpp`:
- 单端点直接连接成功
- 多端点竞态，验证首端点胜出
- 多端点竞态，首端点失败，第二端点胜出
- 全部失败返回空结果
- 超时行为验证

---

#### 任务 4.3: DNS 截断响应处理 — 添加测试

**涉及文件**:
- `src/prism/resolve/detail/upstream.cpp:19` — TODO 注释
- `src/prism/resolve/detail/upstream.cpp:713-718` — 已有 TC 位检查 + TCP fallback
- `tests/DnsPacket.cpp` — 添加测试用例

**当前代码分析**:
```cpp
// upstream.cpp:713-718 — 截断处理已正确实现
if (resp->tc) {
    // 响应被截断，回退到 TCP
    co_return co_await query_tcp(std::move(query));
}
```

**行动**: 代码已正确实现。在 `tests/DnsPacket.cpp` 中添加测试用例构造 TC=1 的 UDP 响应，验证触发 TCP fallback。

---

#### 任务 4.4: Yamux 窗口流控 — 添加压力测试

**涉及文件**:
- `include/prism/multiplex/yamux.hpp:21` — `// TODO: yamux needs proper window update for flow control`
- `src/prism/multiplex/yamux/craft.cpp:702-783` — 窗口流控已完整实现
- `tests/YamuxCraft.cpp` — 添加压力测试

**当前代码分析**:
- `send_data()` (行 726-783): 正确检查和等待发送窗口
- `update_recv_window()` (行 702-724): 正确在阈值时发送 WindowUpdate
- `handle_window_update()` (行 377-487): 正确处理所有标志组合

**行动**: 代码已正确实现。在 `tests/YamuxCraft.cpp` 中添加：
- 窗口耗尽时发送阻塞验证
- WindowUpdate 到达后恢复吞吐验证
- 并发多流窗口隔离验证

---

## 五、第三阶段 (第 5-6 周): 代码质量与架构优化

### 第 5 周

#### 任务 5.1: 提取协议处理器共享模式

**涉及文件**:
- `src/prism/pipeline/protocols/trojan.cpp` — 参考重复模式
- `src/prism/pipeline/protocols/vless.cpp` — 与 trojan 高度重复
- `src/prism/pipeline/protocols/socks5.cpp` — 部分重复
- **新建**: `include/prism/pipeline/handler_utility.hpp`

**重复模式详细对比**:

| 重复模式 | trojan.cpp 行号 | vless.cpp 行号 | socks5.cpp 行号 | 可复用? |
|----------|----------------|----------------|----------------|--------|
| 验证器 lambda (account::try_acquire) | 24-40 | 23-38 | 无 | 是 |
| `wrap_with_preview` 调用 | 21 | 20 | 18 | 是 |
| MUX 目标检测 + bootstrap | 65-78 | 64-75 | 无 | 是 |
| 目标地址构造 (host+port→target) | 58-62 | 57-61 | 40-44 | 是 |
| UDP associate 逻辑 | 88-104 | 85-99 | 60-75 | 是 |
| `primitives::forward()` 调用 | 84 | 81 | 56 | 是 |
| 错误处理 (fault::code 检查) | 全文 | 全文 | 全文 | 是 |

**实施方案**: 新建 `include/prism/pipeline/handler_utility.hpp`:

```cpp
namespace psm::pipeline::handler_util {

/// 创建账户验证器 lambda
auto make_verifier(session_context &ctx)
    -> std::function<bool(std::string_view)>;

/// MUX 检测 + 引导
auto bootstrap_mux_if_needed(session_context &ctx,
                              shared_transmission transport,
                              const protocol::analysis::target &target)
    -> net::awaitable<void>;

/// UDP 关联处理
auto do_udp_associate(session_context &ctx,
                       packet_reader reader,
                       packet_writer writer,
                       const protocol::analysis::target &target)
    -> net::awaitable<void>;

/// 目标地址构造
auto make_target(std::string_view host, std::uint16_t port)
    -> protocol::analysis::target;

} // namespace psm::pipeline::handler_util
```

然后重构 trojan.cpp、vless.cpp、socks5.cpp，替换重复代码为 `handler_util::*` 调用。

**预期效果**: 减少 ~150 行重复代码，每个协议处理器从 ~100 行降至 ~60 行。

**风险控制**: 每次重构一个协议后运行对应测试（`build_release/tests/Trojan.exe` / `Vless.exe` / `Socks5.exe`），确保行为不变。

---

#### 任务 5.2: HTTP 处理器纳入重构

**涉及文件**: `src/prism/pipeline/protocols/http.cpp`

HTTP 处理器有 HTTP 专属解析（CONNECT 方法解析、HTTP 响应构造），但可以提取共享部分：
- `make_verifier()` — 账户验证
- `bootstrap_mux_if_needed()` — MUX 引导
- `primitives::forward()` — 统一转发调用

---

### 第 6 周

#### 任务 6.1: 补充缺失测试覆盖

**新建测试文件** (6 个):

| 文件 | 测试内容 | 测试用例数 |
|------|---------|-----------|
| `tests/EyeballRacer.cpp` | Happy Eyeballs 竞态 | 5+ |
| `tests/ChannelHealth.cpp` | `health()` / `healthy_fast()` | 4+ |
| `tests/TunnelPrimitives.cpp` | `tunnel()` / `forward()` 双向转发 | 5+ |
| `tests/YamuxWindow.cpp` | Yamux 窗口流控压力 | 4+ |
| `tests/ForwardProxy.cpp` | 上游 CONNECT 代理 | 3+ |
| `tests/AnyTls.cpp` | AnyTLS 认证流程 | 3+ |

**同步修改**: `tests/CMakeLists.txt` 注册新测试可执行文件。

**预期**: 测试文件从 42 → 48+

---

#### 任务 6.2: 启用 RTTI 移除

**前置条件**: 任务 3.4 完成（所有 `dynamic_cast` 已消除）

**步骤**:

1. 在 `CMakeLists.txt` 中添加编译选项：
   ```cmake
   # 消除 RTTI，减少二进制体积
   if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
       add_compile_options(-fno-rtti)
   elseif(MSVC)
       add_compile_options(/GR-)
   endif()
   ```

2. 全量编译，确保无编译错误。

3. 运行全部测试，确保无运行时错误。

4. 对比二进制体积变化（预期缩减 5-15%，取决于 RTTI 表大小）。

---

#### 任务 6.3: 性能回归 CI 脚本

**新建文件**: `scripts/benchmark_check.sh`

**实施方案**:
```bash
#!/bin/bash
# benchmark_check.sh — 性能回归检查
# 用法: ./scripts/benchmark_check.sh [build_dir]

BUILD_DIR="${1:-build_release}"

# 运行基准测试
BENCH_OUTPUT=$("$BUILD_DIR/benchmarks/RegressionBench.exe" --json 2>&1)
EXIT_CODE=$?

# 对比基线
if [ $EXIT_CODE -ne 0 ]; then
    echo "性能回归检测失败!"
    echo "$BENCH_OUTPUT"
    exit 1
fi

echo "所有指标在基线范围内"
exit 0
```

**基线文件**: `benchmarks/baselines.json`
```json
{
    "aes256_gcm_mibs": 500,
    "x25519_us": 50,
    "global_pool_4t_ns": 150,
    "p99_latency_us": 250,
    "tcp_echo_64b_us": 15
}
```

---

## 六、第四阶段 (第 7-8 周): 新功能与生产加固

### 第 7 周

#### 任务 7.1: ShadowTLS v3 完整实现

**涉及文件**:
- `src/prism/stealth/shadowtls/handshake.cpp` — 需添加 v3 握手逻辑
- `include/prism/stealth/shadowtls/handshake.hpp` — 需添加 v3 相关结构
- `include/prism/stealth/shadowtls/config.hpp` — 需支持多用户
- `include/prism/stealth/shadowtls/auth.hpp` — 需支持 v3 认证

**ShadowTLS v3 与 v2 的区别**:

| 特性 | v2 | v3 |
|------|----|----|
| 认证方式 | 单密码 | 多用户 (SNI/extension 标识) |
| 首帧 | 服务端先发 | 客户端先发（含内部协议数据） |
| 用户支持 | 单用户 | 多用户 |

**实施步骤**:

1. 在 `config.hpp` 中添加 v3 用户列表：
   ```cpp
   struct shadowtls_user {
       std::string id;       // 用户标识
       std::string password; // 用户密码
   };
   struct shadowtls_config {
       int version = 2;
       std::vector<shadowtls_user> users;  // v3 多用户
       // ...
   };
   ```

2. 在 `handshake.cpp` 中添加 v3 路径（`if (cfg.version == 3)` 分支）：
   - 读取客户端 ClientHello
   - 从 SNI 或 extension 提取用户标识
   - 查找匹配的用户配置
   - 验证客户端首帧中的认证信息
   - 提取内部协议数据并返回

3. 更新 `scheme.cpp` 中的 `is_enabled()` 支持 v3 多用户检查。

**验证**: `build_release/tests/Shadowtls.exe`，添加 v3 握手测试。

---

#### 任务 7.2: WebSocket 传输

**新建文件**:
- `include/prism/channel/transport/websocket.hpp`
- `src/prism/channel/transport/websocket.cpp`

**WebSocket 帧格式** (RFC 6455):
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-------+---------------+-------------------------------+
|F|  RSV  |  Opcode       |M| Payload len   | Extended len |
|I|       |               |A|               | (if needed)  |
|N|       |               |S|               |              |
| |       |               |K|               |              |
+-+-------+---------------+-+-------------+ - - - - - - - +
| Masking Key (if MASK=1) |               |
+ - - - - - - - - - - - - + - - - - - - - + - - - - - - - +
|                    Payload Data                       ...
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - +
```

**实施方案**:

1. 实现 `websocket` 类继承 `transmission`：
   ```cpp
   class websocket final : public channel::transport::transmission {
       shared_transmission inner_;        // 底层 TCP 或 TLS
       memory::string read_buffer_;       // 帧累积缓冲区
       std::size_t frame_offset_{0};     // 当前帧解析偏移
       bool fragmented_{false};           // 分片状态
       // ...
   };
   ```

2. 实现传输接口方法：
   - `async_read_some()`: 解析 WebSocket 帧，提取 payload 返回
   - `async_write_some()`: 构造 WebSocket 帧（binary opcode，mask=0 服务端），写入底层传输
   - `close()`: 发送 Close 帧
   - `cancel()`: 取消底层操作

3. 客户端模式（connect）：
   - 发送 HTTP Upgrade 请求：
     ```
     GET /path HTTP/1.1\r\n
     Host: host:port\r\n
     Upgrade: websocket\r\n
     Connection: Upgrade\r\n
     Sec-WebSocket-Key: <base64>\r\n
     Sec-WebSocket-Version: 13\r\n
     \r\n
     ```
   - 等待 `HTTP/1.1 101 Switching Protocols` 响应

4. 服务端模式（accept）：
   - 解析 HTTP Upgrade 请求
   - 验证 `Sec-WebSocket-Key`，计算 `Sec-WebSocket-Accept`
   - 发送 101 响应

5. **复用现有**:
   - `frame_arena` (`include/prism/memory/pool.hpp`) 用于帧解析缓冲
   - `base64_encode` (`include/prism/crypto/base64.hpp`) 用于 WebSocket Key
   - `transmission` 接口 (`include/prism/channel/transport/transmission.hpp`)

**验证**: 新建 `tests/WebSocket.cpp`：
- 帧编码/解码单元测试
- 分片帧处理测试
- 双向转发集成测试

---

### 第 8 周

#### 任务 8.1: 生产监控与指标系统

**新建文件**:
- `include/prism/trace/metrics.hpp`
- `src/prism/trace/metrics.cpp`

**设计方案**:

```cpp
namespace psm::trace::metrics {

struct counters {
    std::atomic<std::uint64_t> total_connections{0};
    std::atomic<std::uint64_t> total_bytes_in{0};
    std::atomic<std::uint64_t> total_bytes_out{0};
    std::atomic<std::uint64_t> handshake_errors{0};
    std::atomic<std::uint64_t> dns_lookups{0};

    // 按协议分类
    std::atomic<std::uint64_t> http_sessions{0};
    std::atomic<std::uint64_t> socks5_sessions{0};
    std::atomic<std::uint64_t> trojan_sessions{0};
    std::atomic<std::uint64_t> vless_sessions{0};
    std::atomic<std::uint64_t> ss2022_sessions{0};

    // 延迟指标
    std::atomic<std::uint64_t> total_handshake_us{0};
    std::atomic<std::uint64_t> handshake_count{0};
};

auto global() -> counters&;

// 可选: 导出为 Prometheus 格式
auto prometheus_snapshot() -> std::string;

// 可选: 导出为 JSON
auto json_snapshot() -> std::string;

} // namespace psm::trace::metrics
```

**集成点**:

| 位置 | 指标更新 |
|------|---------|
| `listener` 接受连接 | `total_connections++` |
| `tunnel()` 读/写 | `total_bytes_in/out += n` |
| dispatch 路由 | `*_sessions++` |
| 握手失败 | `handshake_errors++` |
| DNS 查询 | `dns_lookups++` |

**热路径开销**: 每次 `fetch_add` 约 1-2 ns（x86 `lock xadd`），在 20 us 连接延迟中占比 <0.01%，可忽略。

---

#### 任务 8.2: 压力测试升级

**涉及目录**: `stresses/`

**新增压力测试**:

1. **并发连接压力** (`stresses/concurrency.cpp`):
   - 启动 1000 同时连接
   - 测量 P50/P90/P99 延迟
   - 监控内存增长

2. **长期稳定性** (`stresses/stability.cpp`):
   - 24 小时连续运行
   - 每 5 分钟采样内存使用
   - 检测内存泄漏（RSS 持续增长）

3. **协议模糊测试** (`stresses/fuzz.cpp`):
   - 随机字节序列发送至各协议 handler
   - 验证无崩溃、无断言失败
   - 覆盖 HTTP/SOCKS5/Trojan/VLESS/SS2022

4. **内存压力** (`stresses/memory_pressure.cpp`):
   - 限制内存（ulimit -v）
   - 验证优雅降级（而非崩溃）
   - PMR 池在内存不足时的 fallback 行为

---

#### 任务 8.3: 文档更新

| 文件 | 更新内容 |
|------|---------|
| `README.md` | 更新特性矩阵、Phase 1-4 性能数字、新协议支持情况 |
| `docs/prism/stealth/` | 添加 Restls.md、AnyTLS.md |
| `docs/prism/channel.md` | 文档化 WebSocket 传输 |
| `docs/prism/recognition.md` | 更新 ECH/AnyTLS 分析器 |
| `docs/tutorial/` | 添加监控配置指南、新配置项说明 |
| `docs/prism/performance-report.md` | 更新完整性能对比表（Before → After） |

---

#### 任务 8.4: 最终验证

**完整验证清单**:

```bash
# 1. 全量测试
ctest --test-dir build_release --output-on-failure
# 预期: 48+ 测试全部通过

# 2. 全量基准
build_release/benchmarks/crypto_bench.exe
build_release/benchmarks/memory_bench.exe
build_release/benchmarks/io_bench.exe
build_release/benchmarks/latency_bench.exe
build_release/benchmarks/RegressionBench.exe
# 预期: 所有指标达标

# 3. 压力测试
build_release/stresses/concurrency.exe    # 1000 连接
build_release/stresses/stability.exe      # ≥1 小时
# 预期: 无崩溃，内存稳定

# 4. TODO 清零检查
grep -rn "TODO" src/prism/ include/prism/
# 预期: 原始 7 个 TODO 全部解决

# 5. dynamic_cast 清零检查
grep -rn "dynamic_cast" src/prism/ include/prism/
# 预期: 0 处

# 6. -fno-rtti 编译验证
# 预期: 编译通过，无 RTTI 相关错误

# 7. 二进制体积对比
ls -la build_release/src/Prism.exe
# 预期: 较初始版本缩减 5-15%（RTTI 移除）
```

---

## 七、依赖关系图

```
第 1 周 (性能修复):
  ┌─ 1.1 AES-NI (CMakeLists.txt:78) ──────┐
  │                                       │
  ├─ 1.2 X25519 优化 ── 依赖 1.1 结果 ─────┤
  │                                       │
  ├─ 1.3 全局池分片化 (pool.hpp) ──────────┤  可并行
  │                                       │
  └─ 1.4 P99 尾延迟 (pool.hpp + racer.hpp) ─┘

第 2 周 (验证):
  ├─ 2.1 小报文 TCP 优化 ──────────────────┤
  ├─ 2.2 性能回归基准 (RegressionBench) ───┤  依赖 2.1
  └─ 2.3 第一阶段整体验证 ─────────────────┘  依赖 2.2

第 3 周 (补全功能):
  ├─ 3.1 Restls 握手 (scheme.cpp + 新建 handshake) ─┤
  ├─ 3.2 ECH 分析器 (ech.hpp + config.hpp) ────────┤  可并行
  ├─ 3.3 AnyTLS 方案 (新建 stealth/anytls/) ───────┤
  └─ 3.4 消除 dynamic_cast (transmission.hpp) ─────┘

第 4 周 (路由/DNS):
  ├─ 4.1 正向代理 (router.cpp) ────────────────────┤
  ├─ 4.2 Happy Eyeballs 重构 (racer.hpp) ──────────┤  可并行
  ├─ 4.3 DNS 截断测试 (DnsPacket.cpp) ─────────────┤
  └─ 4.4 Yamux 窗口测试 (YamuxCraft.cpp) ──────────┘

第 5 周 (代码质量):
  ├─ 5.1 提取共享处理器 (handler_utility.hpp) ─────┤
  └─ 5.2 HTTP 重构 (http.cpp) ── 依赖 5.1 ─────────┘

第 6 周 (测试/RTTI):
  ├─ 6.1 补充 6 个测试文件 ────────────────────────┤
  ├─ 6.2 RTTI 移除 (-fno-rtti) ── 依赖 3.4 ────────┤  可并行
  └─ 6.3 性能回归 CI (benchmark_check.sh) ─────────┘

第 7 周 (新功能):
  ├─ 7.1 ShadowTLS v3 (shadowtls/handshake.cpp) ───┤  可并行
  └─ 7.2 WebSocket 传输 (新建 websocket.hpp/cpp) ──┘

第 8 周 (生产加固):
  ├─ 8.1 指标系统 (trace/metrics.hpp) ─────────────┤
  ├─ 8.2 压力测试升级 (stresses/) ─────────────────┤  可并行
  ├─ 8.3 文档更新 (README + docs/) ────────────────┤
  └─ 8.4 最终验证 (全量测试 + 基准 + TODO 清零) ───┘
```

---

## 八、风险评估与缓解

| 任务 | 风险等级 | 具体风险 | 缓解措施 |
|------|---------|---------|---------|
| 1.1 AES-NI Windows | 中 | MinGW 下 BoringSSL Go 汇编生成器可能有兼容性问题 | MSVC 先验证；MinGW 保持纯 C 备选；最终可用 OpenSSL 替代 |
| 1.3 分片池碎片化 | 低 | Shard 局部内存碎片 | 分片数 8-16 合理选择；fallback 到 synchronized_pool |
| 3.1 Restls 协议 | 中 | 协议规范复杂，客户端兼容性需多次迭代 | 最小可行握手起步；用官方 restls 客户端验证 |
| 3.3 AnyTLS 服务端 | 中 | 无公开 AnyTLS 服务端可测试 | 先自定义客户端验证认证流程 |
| 5.1 处理器重构 | 低 | 提取不当可能引入行为变化 | 每次重构一个协议后运行对应测试 |
| 7.1 ShadowTLS v3 | 低 | 与 v2 逻辑共存可能引入分支错误 | v3 独立测试路径，不改动 v2 代码 |
| 7.2 WebSocket | 中 | 分片帧、掩码、continuation 等边界情况 | 从非掩码 binary 帧起步，逐步增加复杂度 |
| 8.1 指标开销 | 低 | 热路径 `atomic::fetch_add` 额外开销 | 实测 <0.01%；提供编译开关 `PRISM_WITH_METRICS` |

---

## 九、关键文件清单

| 文件 | 修改类型 | 任务 | 说明 |
|------|---------|------|------|
| `CMakeLists.txt:76-78` | 修改 | 1.1 | AES-NI 开关，本次计划最重要的单行修改 |
| `include/prism/memory/pool.hpp` | 修改 | 1.3 | 添加 `sharded_pool` 类 |
| `src/prism/crypto/x25519.cpp` | 修改 | 1.2 | EVP_PKEY → 低层 X25519() |
| `src/prism/stealth/restls/scheme.cpp` | 重写 | 3.1 | TODO 桩 → 完整握手 |
| `src/prism/stealth/restls/handshake.cpp` | 新建 | 3.1 | Restls 握手实现 |
| `src/prism/stealth/restls/handshake.hpp` | 新建 | 3.1 | Restls 握手接口 |
| `src/prism/resolve/router.cpp:49-56` | 重写 | 4.1 | `not_supported` → HTTP CONNECT |
| `include/prism/recognition/arrival/ech.hpp` | 修改 | 3.2 | `return false` → 读配置 |
| `include/prism/recognition/arrival/anytls.hpp` | 修改 | 3.3 | 取消注册注释 |
| `src/prism/stealth/anytls/scheme.cpp` | 新建 | 3.3 | AnyTLS 认证逻辑 |
| `src/prism/stealth/anytls/scheme.hpp` | 新建 | 3.3 | AnyTLS 方案接口 |
| `include/prism/channel/transport/transmission.hpp` | 修改 | 3.4 | 添加 `raw_socket()` 虚方法 |
| `include/prism/channel/transport/reliable.hpp` | 修改 | 3.4 | 覆写 `raw_socket()` |
| `src/prism/stealth/shadowtls/scheme.cpp:44` | 修改 | 3.4 | `dynamic_cast` → `raw_socket()` |
| `include/prism/channel/eyeball/racer.hpp` | 修改 | 4.2 | 配置化 + 取消逻辑完善 |
| `src/prism/pipeline/protocols/trojan.cpp` | 重构 | 5.1 | 使用 `handler_util::*` |
| `src/prism/pipeline/protocols/vless.cpp` | 重构 | 5.1 | 使用 `handler_util::*` |
| `include/prism/pipeline/handler_utility.hpp` | 新建 | 5.1 | 共享辅助函数 |
| `benchmarks/RegressionBench.cpp` | 新建 | 2.2 | 性能回归基准 |
| `benchmarks/baselines.json` | 新建 | 2.2 | 基准阈值 |
| `include/prism/trace/metrics.hpp` | 新建 | 8.1 | 指标系统 |
| `include/prism/channel/transport/websocket.hpp` | 新建 | 7.2 | WebSocket 传输接口 |
| `src/prism/channel/transport/websocket.cpp` | 新建 | 7.2 | WebSocket 传输实现 |
| `tests/EyeballRacer.cpp` | 新建 | 4.2, 6.1 | Happy Eyeballs 测试 |
| `tests/ChannelHealth.cpp` | 新建 | 6.1 | 健康检查测试 |
| `tests/TunnelPrimitives.cpp` | 新建 | 6.1 | 隧道原语测试 |
| `tests/YamuxWindow.cpp` | 新建 | 4.4, 6.1 | Yamux 窗口测试 |
| `tests/ForwardProxy.cpp` | 新建 | 4.1, 6.1 | 正向代理测试 |
| `tests/AnyTls.cpp` | 新建 | 3.3, 6.1 | AnyTLS 测试 |
| `tests/WebSocket.cpp` | 新建 | 7.2 | WebSocket 测试 |
| `scripts/benchmark_check.sh` | 新建 | 6.3 | 性能回归 CI 脚本 |

---

## 十、与上层架构计划的关系

本 8 周计划聚焦于 **性能修复 + TODO 清零 + 代码质量 + WebSocket/ShadowTLS v3**，不涉及以下更大规模的架构变更（这些已在 `plan.md` 第一至八章详细设计）：

| 上层功能 | 所在章节 | 与本计划关系 |
|----------|---------|-------------|
| Outbound 出站代理抽象 | 第三章 3.2 | 独立，可在本计划完成后启动 |
| Traffic Controller 流量调度器 | 第三章 3.1.2 | 独立，可在本计划完成后启动 |
| Rule 规则引擎 | 第三章 3.5 | 独立，可在本计划完成后启动 |
| Proxy Group 代理组 | 第三章 3.2.3 | 依赖 Outbound 抽象 |
| QUIC / Hysteria2 / TUIC | 第三章 3.3-3.4, Phase 3 | 独立大工程 |
| REST API | 第三章 3.6 | 本计划 8.1 指标系统为其打基础 |
| TUN / WireGuard / VMess | 第三章 Phase 6 | 独立大工程 |

本计划完成后的状态：项目性能达标、TODO 清零、代码质量提升，为上述更大规模的架构变更奠定坚实基础。