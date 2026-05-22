# Prism 代理服务器 — 开发计划（第三版）

> **编制日期**: 2026/05/01
> **修订日期**: 2026/05/22
> **时间跨度**: 2026/05/22 — 2026/07/31 (共 10 周)
>
> **修订说明** (2026/05/22):
> - 反映 2026/05/19 架构重构：agent→instance、channel→connect/transport、pipeline→protocol+connect、resolve/router→connect/dial
> - 架构重构完成约 90%（15 步中 13.5 步），87 个文件已删除但未提交
> - 基于全项目 6 维度深度审计（代码完整性、测试覆盖、生产就绪、安全协议、架构质量、路线图完成度）
> - 新增 P0 生产阻塞项：优雅关闭、CI 修复、握手超时
> - 路线图完成度约 25-30%，偏离了原定的性能修复优先路径
> - 标注所有已删除文件的新位置映射

---

## 一、项目现状总览

### 1.1 架构重构完成度

基于 `docs/superpowers/specs/2026-05-19-architecture-refactor-design.md` 设计规范，15 步实施进度：

| # | 重构内容 | 状态 | 说明 |
|---|---------|------|------|
| 1 | 提取 `protocol/protocol_type.hpp` + `protocol/common/target.hpp` | ✅ | 已完成 |
| 2 | 移动 TLS 解析到 `recognition/tls/` | ⚠️ | 新旧位置都有副本，需清理 |
| 3 | 清理 reality 重复代码 | ✅ | `client_hello_info` 已统一为 `client_hello_features` |
| 4 | 移动 `analysis::resolve()` 和 `detect_tls()` | ✅ | `protocol/analysis.hpp` 已不存在 |
| 5 | 创建 connect 模块骨架 | ✅ | `include/prism/connect/` 完整 |
| 6 | 创建 stats 顶层模块 | ✅ | `include/prism/stats/` 完整 |
| 7 | 创建 account 顶层模块 | ✅ | `include/prism/account/` 完整 |
| 8 | channel → transport | ✅ | 命名空间已更新为 `psm::transport` |
| 9 | pipeline/primitives 拆分 | ✅ | 功能拆散到 connect/、transport/ |
| 10 | resolve/router 拆分 | ✅ | 路由器移至 `connect/dial/router.hpp` |
| 11 | dispatch/table.hpp 移除 | ✅ | 改用 switch 直接调用 |
| 12 | agent → instance | ✅ | 命名空间已更新为 `psm::instance` |
| 13 | 更新聚合头文件 | ✅ | instance/connect/transport 聚合头文件就绪 |
| 14 | 更新 CMakeLists.txt | ✅ | 各子目录 CMakeLists 已更新 |
| 15 | 更新测试文件 | ⚠️ | 缺少 tests/Connect.cpp 和 tests/Stats.cpp |

**剩余工作**: 提交重构（87 个文件删除 + 新增文件）、清理 `protocol/tls/` 双份文件、补测试。

### 1.2 模块映射（旧路径 → 新路径）

| 旧路径 | 新路径 | 状态 |
|--------|--------|------|
| `include/prism/agent/` | `include/prism/instance/` | 已迁移 |
| `include/prism/channel/` | `include/prism/connect/` + `include/prism/transport/` | 已迁移 |
| `include/prism/pipeline/` | `include/prism/protocol/` + `include/prism/connect/` | 已迁移 |
| `include/prism/resolve/router.hpp` | `include/prism/connect/dial/router.hpp` | 已迁移 |
| `src/prism/agent/` | `src/prism/instance/` | 已迁移 |
| `src/prism/channel/` | `src/prism/connect/` + `src/prism/transport/` | 已迁移 |
| `src/prism/pipeline/` | `src/prism/protocol/` + `src/prism/connect/` | 已迁移 |
| `include/prism/protocol/analysis.hpp` | `include/prism/recognition/target.hpp` | 已迁移 |

### 1.3 已完成（生产就绪）

| 模块 | 状态 | 新路径 |
|------|------|--------|
| HTTP 代理 | 完成 | `src/prism/protocol/http/` |
| SOCKS5 (TCP+UDP) | 完成 | `src/prism/protocol/socks5/` |
| Trojan (TCP+UDP+MUX) | 完成 | `src/prism/protocol/trojan/` |
| VLESS (TCP+UDP+MUX) | 完成 | `src/prism/protocol/vless/` |
| SS2022 AEAD (TCP+UDP) | 完成 | `src/prism/protocol/shadowsocks/` |
| Reality TLS 伪装 | 完成 | `src/prism/stealth/reality/` |
| ShadowTLS v3 | 完成 | `src/prism/stealth/shadowtls/` |
| smux v1 多路复用 | 完成 | `src/prism/multiplex/smux/` |
| yamux 多路复用 | 完成 | `src/prism/multiplex/yamux/` |
| 七阶段 DNS 解析 | 完成 | `src/prism/resolve/dns/` |
| Happy Eyeballs (RFC 8305) | 完成 | `src/prism/connect/dial/racer.hpp` |
| 连接池 + 健康检查 | 完成 | `src/prism/connect/pool/` |
| 加权负载均衡 | 完成 | `src/prism/instance/front/balancer.cpp` |
| PMR 内存管理 | 完成 | `include/prism/memory/` |
| TLS 共享层 | 完成 | `include/prism/protocol/tls/` |
| 协议识别 | 完成 | `src/prism/recognition/` + `src/prism/stealth/executor.cpp` |
| 方案注册管道 | 完成 | `include/prism/stealth/registry.hpp`, `executor.hpp` |
| 分层检测管道 | 完成 | `src/prism/recognition/layered_pipeline.hpp` |
| 测试套件 | 47 个测试文件 | `tests/` (281 个测试函数) |
| 基准套件 | 12 个基准文件 | `benchmarks/` |
| 压力测试 | 4 个压力测试 | `stresses/` |
| GitHub Actions CI | 完成 | `.github/workflows/build.yml` |

### 1.4 活跃 TODO 桩（5 个 CRITICAL）

| # | 文件位置 | 问题描述 | 优先级 |
|---|---------|---------|--------|
| 1 | `src/prism/stealth/restls/scheme.cpp:73` | Restls 握手为 TODO 桩，直接 passthrough | CRITICAL |
| 2 | `src/prism/stealth/anytls/scheme.cpp:92` | AnyTLS 握手为 TODO 桩 | CRITICAL |
| 3 | `src/prism/stealth/trusttunnel/scheme.cpp:59` | TrustTunnel 握手为 TODO 桩 | CRITICAL |
| 4 | `src/prism/stealth/ech/util/decrypt.cpp:40` | ECH HPKE 解密返回 `not_supported` | CRITICAL |
| 5 | `src/prism/stealth/anytls/scheme.cpp:52` | ECH 验证 TODO（被 #4 包含） | CRITICAL |

### 1.5 生产就绪性缺口（阻塞部署）

| 缺失能力 | 当前状态 | 影响 |
|----------|---------|------|
| 优雅关闭 | **完全缺失** — 无 SIGTERM/SIGINT 处理，进程被 kill 时连接粗暴中断 | P0 |
| 监控指标系统 | **缺失** — 仅内部负载均衡 3 个原子计数器，不可导出 | P0 |
| 健康检查端点 | **缺失** — 无 `/health`，文档建议 `nc -zv` | P0 |
| 握手超时 | **缺失** — 慢速 TLS 握手可长期占用 worker | P0 |
| 速率限制 | **完全缺失** — 无 per-IP 或全局连接速率限制 | P1 |
| 客户端 IP 黑名单 | **缺失** — 黑名单仅作用于 DNS 解析结果 | P1 |
| 热重载配置 | 底层 `swap_config()` 已就绪，缺上层触发 | P2 |
| Dockerfile | 文档有示例，无实际文件 | P2 |
| 结构化日志 | fmt 文本，无请求 ID，无客户端 IP | P2 |
| 内存使用监控 | PMR 池无水位统计和告警 | P2 |

### 1.6 安全性评估（7/10）

| 方面 | 现状 | 缺失 |
|------|------|------|
| 用户认证 | 完善的统一模型，SHA224 哈希验证 | 配置文件密码明文 |
| 连接限制 | per-user CAS 原子限制 | 无全局最大连接数 |
| TLS 配置 | TLS 1.2-1.3，强加密套件，X25519 | 缺 `SSL_OP_NO_RENEGOTIATION`，无 OCSP |
| DoS 防护 | 全局背压 + 错误指数退避 + HTTP 头 64KB 限制 | 无连接速率限制 |
| 内存安全 | PMR 分层策略安全 | — |
| SS2022 重放 | salt 精确匹配 + PacketID 滑动窗口 | — |

### 1.7 协议完整性

| 协议 | 完整度 | 关键缺失 |
|------|--------|----------|
| SOCKS5 | 85% | GSSAPI、BIND、UDP 分片 |
| HTTP Proxy | 75% | Keep-Alive、Chunked、Pipeline |
| Trojan | 90% | WebSocket 传输 |
| VLESS | 85% | XTLS/Vision、AddnlInfo 拒绝非零 |
| SS2022 | 90% | EIH（多用户扩展头部）、多 PSK |
| WebSocket | 0% | 完全未实现 |
| gRPC | 0% | 未计划 |

### 1.8 测试覆盖缺口

| 状态 | 详情 |
|------|------|
| 已有 | 42 个目标测试 + 3 个额外 + 2 个并发 = 47 个文件，281 个测试函数 |
| **零覆盖** | `outbound/` 模块、`loader/` 模块 |
| **严重不足** | Reality 仅 1 个测试（证书解析）、Restls 仅 3 个配置测试 |
| **缺失** | EyeballRacer、ChannelHealth、TunnelPrimitives、ConnectPool 边界 |
| **CI 问题** | `continue-on-error: true` 导致测试失败不阻止 Release |

### 1.9 代码质量审计

| 问题 | 位置 | 严重度 |
|------|------|--------|
| `dynamic_cast` 4 处 | `stealth/native.cpp:58,63`、`stealth/executor.cpp:36,45` | P2 |
| 热路径异常 | `transport/preview.cpp:22` 抛 `std::runtime_error` | P1 |
| `<boost/asio.hpp>` 超级头文件 | 59 个文件使用，增加编译时间 | P2 |
| 协议处理器重复 | 5 个 `process.cpp` 结构高度相似 | P2 |
| 部分模块用 `std::string` 而非 PMR | `crypto/base64.hpp`、`crypto/sha224.hpp` | P3 |
| `protocol/tls/signal.cpp` 未注册 CMake | 可能链接丢失符号 | P1 |
| `exception/deviant.hpp` 包含 `<filesystem>` | 重量级头文件被广泛传播 | P3 |

---

## 二、性能目标（Before → After）

| 指标 | Before | 当前值 | 最终目标 | 业界对标 |
|------|--------|--------|---------|---------|
| AES-256-GCM | 205 Mi/s | **13.7 Gi/s ✅** | 13.7 Gi/s | shadowsocks-rust 1-2 Gi/s |
| AES-128-GCM | 245 Mi/s | **16.9 Gi/s ✅** | 16.9 Gi/s | — |
| X25519 交换 | 81.5 us | **21.4 us ✅** | 21.4 us | WireGuard ~40 us |
| 全局池 4T | 3530 ns | 3530 ns | <100 ns | — |
| 连接 P50 | 95 us | 95 us | 85 us | Envoy ~100 us |
| 连接 P99 | 336 us | 336 us | <200 us | — |
| TCP 64B | 20.1 us | 20.1 us | 10 us | — |
| TCP 128KB | 7.11 Gi/s | 7.11 Gi/s | 7.11 Gi/s | HAProxy ~10 Gbps |
| 活跃 TODO | 5 个 | 5 个 | 0 | — |
| `dynamic_cast` | 4 处 | 4 处（位置已变） | 0 | — |
| 测试文件 | 47 | 47 | 55+ | — |

---

## 三、Phase A (第 1-2 周): 重构收尾 + 生产阻塞项

> **目标**: 提交架构重构，修复 CI 流程缺陷，实现优雅关闭和握手超时。
> **原则**: 不解决这些，后续所有工作都有风险。

### 任务 A.1: 提交架构重构

**状态**: 重构代码已就绪，87 个文件已删除 + 大量新增文件在 untracked 状态。

**步骤**:

1. **验证全量编译**:
   ```bash
   cmake -B build_release -DCMAKE_BUILD_TYPE=Release
   cmake --build build_release --config Release
   ```

2. **验证全量测试**:
   ```bash
   ctest --test-dir build_release --output-on-failure
   ```

3. **清理 `protocol/tls/` 双份文件**:
   - `include/prism/protocol/tls/signal.hpp` 和 `include/prism/recognition/tls/signal.hpp` 都存在
   - `include/prism/protocol/tls/feature_bitmap.hpp` 和 `include/prism/recognition/tls/feature_bitmap.hpp` 都存在
   - 确认 `protocol/tls/` 下的是否为转发头文件，如果是则保留；如果是副本则删除
   - 确认 `src/prism/protocol/tls/signal.cpp` 是否已注册到 CMakeLists.txt

4. **更新聚合头文件**:
   - `channel.hpp` 是否仍作为兼容层转发到 `connect.hpp`？确认并清理
   - 确认 `stealth.hpp` 包含所有新方案（anytls、trusttunnel、ech）

5. **Git 操作**:
   ```bash
   git add -A  # 暂存所有变更（删除 + 新增 + 修改）
   git status  # 审查变更清单
   git commit  # 提交
   ```

**验证**: 编译通过 + 47 个测试全部通过 + 无断裂引用。

---

### 任务 A.2: 修复 CI — 移除 `continue-on-error: true`

**文件**: `.github/workflows/build.yml`

**当前问题**: 测试步骤 `continue-on-error: true`，导致测试失败不阻止 Release 发布。这意味着可能将带回归缺陷的版本发布给用户。

**修改**: 移除 Test 步骤的 `continue-on-error: true`，确保测试失败时 CI 整体失败。

**验证**: 确认 YAML 语法正确，CI 能正常触发。

---

### 任务 A.3: 优雅关闭（Graceful Shutdown）

**涉及文件**:
- `src/main.cpp` — 当前无信号处理
- `include/prism/instance/worker/worker.hpp` — `run()` 方法无 stop 机制
- `src/prism/instance/front/listener.cpp` — accept 无限循环

**当前问题**: 所有 worker 线程和 listener 通过 `std::jthread` 启动，`main()` 结束后线程被 join 回收并销毁。无 SIGTERM/SIGINT 处理，无 `io_context.stop()` 路径，无 drain 连接逻辑。进程被 kill 时所有活跃连接粗暴中断，连接池缓存的连接不会被优雅关闭，spdlog 异步日志队列可能丢失未刷盘数据。

**实施方案**:

1. **在 `main.cpp` 中添加信号处理**:
   ```cpp
   #include <csignal>
   #include <boost/asio/signal_set.hpp>

   // 在 io_context 上监听 SIGTERM / SIGINT
   net::signal_set signals(ioc, SIGTERM, SIGINT);
   signals.async_wait([&](auto, auto sig) {
       spdlog::info("Received signal {}, shutting down...", sig);
       // 停止接受新连接
       listener.stop();
       // 停止所有 worker
       for (auto& w : workers) { w.stop(); }
       // 刷盘日志
       spdlog::default_logger()->flush();
   });
   ```

2. **在 `listener` 中添加 `stop()` 方法**:
   - 关闭 acceptor（`acceptor_.close()`）
   - 通知所有 worker 进入关闭模式

3. **在 `worker` 中添加 `stop()` 方法**:
   - 设置 `running_ = false` 标志
   - 当前活跃 session 完成后不再接受新 session
   - 可选：设置最大 drain 超时（如 30 秒）

4. **Drain 策略**:
   - 停止 accept 后，等待所有活跃 session 自然完成
   - 设置超时：如果 30 秒后仍有活跃连接，强制 `io_context.stop()`
   - 连接池中缓存的空闲连接全部关闭

5. **日志刷盘**:
   - 在退出前调用 `spdlog::default_logger()->flush()`
   - 调用 `trace::shutdown()` 清理异步日志队列

**验证**: 手动测试 — 启动 Prism，建立连接，发送 SIGTERM，验证连接正常关闭而非粗暴中断。

---

### 任务 A.4: 握手超时 / 读取超时

**涉及文件**:
- `src/prism/instance/session/session.cpp` — session 生命周期
- `src/prism/recognition/recognition.cpp` — 协议识别
- 各协议 `process.cpp` — 协议处理

**当前问题**: 没有针对握手阶段的读取超时。恶意客户端可发送部分 TLS ClientHello 后停滞，长期占用 worker 连接而不释放。每个 worker 只有一个 io_context 线程，被占用的 session 无法服务其他连接。

**实施方案**:

1. **在 session 启动时创建超时定时器**:
   ```cpp
   net::steady_timer deadline_{executor};
   deadline_.expires_after(std::chrono::seconds(30));  // 握手超时 30 秒
   deadline_.async_wait([&](auto ec) {
       if (!ec) {
           // 超时，关闭连接
           transport->cancel();
       }
   });
   ```

2. **在握手完成后取消定时器**:
   ```cpp
   deadline_.cancel();
   ```

3. **可配置化**: 在 `config.hpp` 中添加 `handshake_timeout_ms` 字段，默认 30000。

4. **隧道阶段**: 可选地为 tunnel 阶段也添加空闲超时（如 300 秒），超时后关闭连接。

**验证**: 添加测试 — 建立连接后不发送任何数据，验证 30 秒后被服务端主动关闭。

---

### 任务 A.5: 修复热路径异常

**涉及文件**:
- `src/prism/transport/preview.cpp:22` — 抛出 `std::runtime_error`

**修改**: 将 `throw std::runtime_error(...)` 替换为 `fault::code` 错误返回。传输层是热路径，不应触发异常栈展开。

**验证**: 编译通过 + 测试通过。

---

## 四、Phase B (第 3-4 周): Stealth 握手实现 + 监控基础

> **目标**: 实现 5 个 CRITICAL TODO 桩，建立监控指标系统，添加健康检查端点。

### 任务 B.1: Restls 完整握手

**涉及文件**:
- `src/prism/stealth/restls/scheme.cpp:73` — 当前 TODO 桩
- **新建**: `include/prism/stealth/restls/handshake.hpp`
- **新建**: `src/prism/stealth/restls/handshake.cpp`

**协议流程** (参照 https://github.com/3andne/restls):

1. **ClientHello 阶段**: 客户端发送 TLS ClientHello，含 Restls 标识
2. **后端连接**: 服务端连接到真实后端 TLS 服务器（如配置的 `host:port`）
3. **认证阶段**: 客户端在 TLS 应用数据中发送认证信息（密码哈希）
4. **流量控制**: 认证通过后，使用 restls-script 控制流量模式

**实施步骤**:

1. 定义 `handshake_result` 结构体
2. 实现 `handshake()` 协程函数：
   - 读取 ClientHello 并解析 SNI（复用 `protocol::tls::parse_client_hello()`）
   - 通过 `connect::dial::racer` 连接后端 TLS 服务器
   - 读取客户端首条 TLS 应用数据，验证密码哈希
3. 替换 `scheme.cpp:73` 的 TODO 桩
4. 在 `config.hpp` 确认 `stealth.restls` 包含 `host`/`password`/`restls_script`

**复用**: `protocol::tls::parse_client_hello()`、`crypto::sha224()`、`connect::dial::racer`。

**验证**: 补充 `tests/Restls.cpp` 的握手成功/失败测试用例。

---

### 任务 B.2: AnyTLS 握手实现

**涉及文件**:
- `src/prism/stealth/anytls/scheme.cpp:92` — 当前 TODO 桩

**AnyTLS 特点**: 无 ClientHello 层特征（外观为标准 TLS），在 TLS 应用数据中嵌入认证。应作为 fallback scheme，优先级在 restls 之后、native 之前。

**实施步骤**:

1. 读取客户端首条 TLS 应用数据记录
2. 前 32 字节与 `SHA256(password)` 比对
3. 匹配成功则提取内部协议数据，返回 `scheme_result`
4. 失败则返回错误

**验证**: 新建 `tests/AnyTls.cpp`。

---

### 任务 B.3: ECH HPKE 解密实现

**涉及文件**:
- `src/prism/stealth/ech/util/decrypt.cpp:40` — 当前返回 `not_supported`

**实施步骤**:

1. 实现 HPKE (Hybrid Public Key Encryption) 解密：
   - 从 ClientHello ECH extension 中提取 encapsulated key
   - 使用服务端私钥执行 HPKE SetupBaseR
   - 解密 ECH inner ClientHello
2. 解密成功后，将 inner ClientHello 的 SNI 和特征暴露给后续 scheme
3. 解密失败则返回错误，让 pipeline 继续 fallback

**复杂度**: HPKE 涉及 HKDF-SHA256 + X25519 + AES-128-GCM，需要 ~200 行代码。可复用 BoringSSL 的 HKDF 和 AEAD 接口。

**验证**: 构造含 ECH extension 的 ClientHello 测试数据。

---

### 任务 B.4: TrustTunnel 握手实现

**涉及文件**:
- `src/prism/stealth/trusttunnel/scheme.cpp:59` — 当前 TODO 桩

**复杂度**: 相对较低，基于 TLS 层的特征匹配 + 握手协议。

**实施步骤**: 参考 TrustTunnel 规范实现握手流程（如果无公开规范，需从客户端实现中逆向）。

**验证**: 新建 `tests/TrustTunnel.cpp`。

---

### 任务 B.5: 监控指标系统

**新建文件**:
- `include/prism/trace/metrics.hpp`
- `src/prism/trace/metrics.cpp`

**设计方案**:

```cpp
namespace psm::trace::metrics {

struct counters {
    // 连接
    std::atomic<std::uint64_t> total_connections{0};
    std::atomic<std::uint64_t> active_connections{0};

    // 流量
    std::atomic<std::uint64_t> total_bytes_in{0};
    std::atomic<std::uint64_t> total_bytes_out{0};

    // 错误
    std::atomic<std::uint64_t> handshake_errors{0};
    std::atomic<std::uint64_t> tunnel_errors{0};

    // 协议分布
    std::atomic<std::uint64_t> http_sessions{0};
    std::atomic<std::uint64_t> socks5_sessions{0};
    std::atomic<std::uint64_t> trojan_sessions{0};
    std::atomic<std::uint64_t> vless_sessions{0};
    std::atomic<std::uint64_t> ss2022_sessions{0};

    // DNS
    std::atomic<std::uint64_t> dns_lookups{0};
    std::atomic<std::uint64_t> dns_cache_hits{0};

    // 连接池
    std::atomic<std::uint64_t> pool_acquires{0};
    std::atomic<std::uint64_t> pool_hits{0};
    std::atomic<std::uint64_t> pool_creates{0};

    // 延迟
    std::atomic<std::uint64_t> total_handshake_us{0};
    std::atomic<std::uint64_t> handshake_count{0};
};

auto global() -> counters&;
auto prometheus_snapshot() -> memory::string;
auto json_snapshot() -> memory::string;

} // namespace psm::trace::metrics
```

**集成点**:

| 位置 | 指标更新 |
|------|---------|
| `listener` accept | `total_connections++`、`active_connections++` |
| `session` 关闭 | `active_connections--` |
| `tunnel()` 读写 | `total_bytes_in/out += n` |
| 协议 handler | `*_sessions++` |
| 握手失败 | `handshake_errors++` |
| DNS 查询 | `dns_lookups++` |
| DNS 缓存命中 | `dns_cache_hits++` |
| 连接池 acquire | `pool_acquires++`、`pool_hits++` |

**热路径开销**: 每次 `fetch_add` 约 1-2 ns（x86 `lock xadd`），在 20 us 连接延迟中占比 <0.01%。

**导出方式**: 通过 HTTP `/metrics` 端点（与 B.6 健康检查共用），输出 Prometheus text format。

---

### 任务 B.6: 健康检查端点

**涉及文件**:
- **新建**: `src/prism/instance/health.cpp`
- **新建**: `include/prism/instance/health.hpp`
- `src/main.cpp` — 注册健康检查

**实施方案**:

在主线程或独立线程上启动一个轻量 HTTP 服务器，监听管理端口（默认 `127.0.0.1:9090`）：

```
GET /health     → 200 OK + JSON 健康状态
GET /metrics    → 200 OK + Prometheus text format 指标
GET /ready      → 200 OK / 503 Service Unavailable
```

**健康状态检查项**:
- `io_context_running`: 每个 worker 的 io_context 是否在运行
- `event_loop_lag_us`: 事件循环延迟（来自 `stats::state`）
- `active_sessions`: 活跃会话数
- `memory_pool_ok`: PMR 池状态

**验证**: 启动 Prism → `curl http://127.0.0.1:9090/health` → 返回 200 OK + JSON。

---

## 五、Phase C (第 5-6 周): 路线图遗留性能任务

> **目标**: 完成原计划第一阶段的性能优化目标。

### 任务 C.1: 全局内存池分片化

**涉及文件**:
- `include/prism/memory/pool.hpp:47-59` — `system::global_pool()` 返回 `synchronized_pool`

**当前问题**: `std::pmr::synchronized_pool` 内部全局互斥锁。4T 下 142 ns → 3530 ns（26.5 倍退化）。

**实施方案**: 在 `pool.hpp` 中新增 `sharded_pool` 类：

```cpp
class sharded_pool : public std::pmr::memory_resource {
    static constexpr std::size_t shard_count = 8;
    struct alignas(64) aligned_shard {
        std::pmr::unsynchronized_pool_resource pool;
    };
    std::array<aligned_shard, shard_count> shards_;

    auto do_allocate(std::size_t bytes, std::size_t alignment)
        -> void* override
    {
        auto const id = std::hash<std::thread::id>{}(
            std::this_thread::get_id());
        return shards_[id % shard_count].pool.allocate(bytes, alignment);
    }

    void do_deallocate(void* p, std::size_t bytes,
                       std::size_t alignment) override;

    [[nodiscard]] auto do_is_equal(
        std::pmr::memory_resource const& other) const noexcept
        -> bool override { return this == &other; }
};
```

修改 `system::enable_global_pooling()` 和 `system::global_pool()` 使用 `sharded_pool`。

**预期效果**: 4T 下 3530 ns → <150 ns。

**验证**: `build_release/benchmarks/MemoryBench.exe`

---

### 任务 C.2: P99 尾延迟优化

**涉及文件**:
- `include/prism/connect/pool/pool.hpp` — 连接池 `async_acquire()`

**实施方案**:

1. **快速路径**: 连接在 1 秒内使用过则跳过 `healthy_fast()` 检查
2. **预创建**: 池空新建连接时，后台预创建第二个
3. **Happy Eyeballs 竞态取消**: 确保胜者写入后立即 `cancel_all()`

**预期效果**: P99 336 us → <250 us。

---

### 任务 C.3: 小报文 TCP 优化

**涉及文件**:
- `include/prism/transport/reliable.hpp` — 底层传输
- `src/prism/connect/tunnel/tunnel.cpp` — `tunnel()` 转发

**实施方案**:
- 审查 `async_read_some` / `async_write_some` 调用链，消除多余包装层
- 小报文（<1KB）尝试合并读写
- Windows 目标 12-15 us（理论极限 ~5 us 需内核旁路）

**预期效果**: 64B TCP Echo 20.1 us → 12-15 us。

---

### 任务 C.4: 性能回归基准

**新建文件**:
- `benchmarks/RegressionBench.cpp`
- `benchmarks/baselines.json`

| 指标 | 基准函数 | 阈值 |
|------|---------|------|
| AES-256-GCM | `BM_AeadContinuousSealAes256Gcm` | >500 Mi/s |
| X25519 | `BM_X25519KeyExchange` | <50 us |
| 全局池 4T | `BM_GlobalPoolConcurrent` | <150 ns |
| 连接 P99 | `BM_ConnectionLatencyP99` | <250 us |
| TCP 64B | `BM_TcpEcho64B` | <15 us |

输出 JSON + 控制台表格，退化 >10% 退出非零。

**新建**: `scripts/benchmark_check.sh` — CI 性能回归检查脚本。

---

### 任务 C.5: WebSocket 传输

**新建文件**:
- `include/prism/transport/websocket.hpp`
- `src/prism/transport/websocket.cpp`

**实施方案**:

1. `websocket` 类继承 `transmission`，包装底层 TCP 或 TLS 连接
2. 实现 WebSocket 帧编解码（RFC 6455）
3. 客户端模式：发送 HTTP Upgrade → 等待 101 响应
4. 服务端模式：解析 Upgrade → 验证 Key → 发送 101

**复用**: `frame_arena`（帧缓冲）、`base64_encode`（WebSocket Key）、`transmission` 接口。

**验证**: 新建 `tests/WebSocket.cpp`。

---

## 六、Phase D (第 7-8 周): 正向代理 + 安全加固

> **目标**: 实现正向代理，添加速率限制和连接数硬上限，消除 dynamic_cast。

### 任务 D.1: 正向代理模式

**涉及文件**:
- `src/prism/connect/dial/router.cpp` — `async_positive()` 返回 `not_supported`

**实施方案**:

1. 通过 `pool_.async_acquire(positive_host_, positive_port_)` 获取上游代理连接
2. 构造并发送 HTTP CONNECT 请求
3. 读取 HTTP 响应，解析状态码（复用 `protocol::http` 解析逻辑）
4. 认证成功则返回 `pooled_connection`，失败则返回 `fault::code`

**验证**: 新建 `tests/ForwardProxy.cpp`。

---

### 任务 D.2: 连接速率限制 + 全局连接上限

**新建文件**:
- `include/prism/instance/limiter.hpp`
- `src/prism/instance/limiter.cpp`

**实施方案**:

1. **令牌桶速率限制器**（per-IP）:
   ```cpp
   class rate_limiter {
       struct token_bucket {
           double tokens;
           std::chrono::steady_clock::time_point last_refill;
       };
       concurrent_map<address, token_bucket> buckets_;
   public:
       auto try_acquire(const address& addr) -> bool;
   };
   ```

2. **全局连接数硬上限**:
   - 在 `config.hpp` 添加 `max_total_connections` 字段
   - 在 `listener` 的 accept 循环中检查 `active_connections < max_total_connections`
   - 超限时暂停 accept（复用现有背压机制）

3. **集成到 listener**:
   - accept 后立即检查速率限制
   - 超限则关闭连接并记录日志

**验证**: 新建 `tests/RateLimiter.cpp`。

---

### 任务 D.3: 客户端 IP 黑名单

**涉及文件**:
- `src/prism/instance/front/listener.cpp` — accept 循环
- `include/prism/instance/config.hpp` — 添加黑名单配置

**实施方案**:

1. 在 `config.hpp` 添加 `limit.client_blacklist`（CIDR 列表）
2. 在 listener accept 后检查客户端 IP 是否匹配黑名单
3. 匹配则关闭连接并记录日志

---

### 任务 D.4: 消除 dynamic_cast（4 处）

**涉及文件**:
- `src/prism/stealth/native.cpp:58,63` — `transport::preview*` / `transport::snapshot*`
- `src/prism/stealth/executor.cpp:36,45` — `transport::snapshot*`
- `include/prism/transport/transmission.hpp` — 基类

**实施方案**:

1. 在 `transmission` 基类添加类型标签或虚方法：
   ```cpp
   [[nodiscard]] virtual tcp::socket* raw_socket() noexcept
       { return nullptr; }
   ```
2. 在 `reliable` 中覆写 `raw_socket()`
3. 替换 4 处 `dynamic_cast` 为 `raw_socket()` 或 `find_reliable()` 调用
4. 在 `CMakeLists.txt` 添加 `-fno-rtti`

**验证**: 全量编译通过 + 47 个测试通过。

---

### 任务 D.5: TLS 安全加固

**涉及文件**:
- `src/prism/instance/worker/tls.cpp` — TLS 配置

**修改**:

1. 添加 `SSL_OP_NO_RENEGOTIATION`（防 TLS 重协商攻击）
2. 可选：配置 OCSP Stapling
3. 文档中提示配置文件密码应使用强随机密码

---

## 七、Phase E (第 9-10 周): 测试补全 + 运维完善

> **目标**: 补全缺失测试覆盖，完善运维工具链，文档更新。

### 任务 E.1: 补全缺失测试

| 文件 | 测试内容 | 优先级 |
|------|---------|--------|
| `tests/Outbound.cpp` | outbound/direct.hpp + proxy.hpp | P0（零覆盖） |
| `tests/Loader.cpp` | loader/load.hpp JSON 解析、非法输入 | P0（零覆盖） |
| `tests/RealityHandshake.cpp` | auth_key 验证、short_id 匹配、完整握手 | P1（仅 1 个测试） |
| `tests/ConnectPool.cpp` | max_cache 上限、超时、并发竞争 | P1 |
| `tests/DnsUpstream.cpp` | UDP/TCP 查询、请求合并、缓存并发 | P1 |
| `tests/EyeballRacer.cpp` | 单/多端点竞态、失败 fallback、超时 | P1 |
| `tests/ChannelHealth.cpp` | `health()` / `healthy_fast()` | P1 |
| `tests/TunnelPrimitives.cpp` | `tunnel()` / `forward()` 双向转发 | P1 |
| `tests/GracefulShutdown.cpp` | SIGTERM 处理、连接 drain | P1 |
| `tests/HandshakeTimeout.cpp` | 慢速握手超时关闭 | P1 |

**同步修改**: `tests/CMakeLists.txt` 注册新测试。

**目标**: 测试文件 47 → 57+。

---

### 任务 E.2: 热重载配置

**涉及文件**:
- `include/prism/context/context.hpp:87-93` — `swap_config()` 已就绪

**实施方案**:

1. 在 `main.cpp` 中添加 SIGHUP 信号处理
2. 收到 SIGHUP 后重新加载配置文件
3. 通过 `swap_config()` 原子交换配置
4. 通知 worker 使用新配置（连接池参数、速率限制等）

---

### 任务 E.3: Dockerfile / 容器化

**新建文件**:
- `Dockerfile`（多阶段构建）
- `.dockerignore`
- `docker-compose.yml`（可选）

**Dockerfile 要点**:
- 多阶段构建：构建阶段用 GCC 13 编译，运行阶段仅拷贝二进制
- 添加 `HEALTHCHECK` 指令指向 `/health` 端点
- 基于 A.3 的优雅关闭确保 SIGTERM 正确处理
- 暴露代理端口 + 管理端口

---

### 任务 E.4: 精细化 Boost.Asio include

**涉及文件**: 59 个使用 `<boost/asio.hpp>` 的头文件

**修改**: 将 `<boost/asio.hpp>` 替换为精确子头文件：
- `<boost/asio/awaitable.hpp>`
- `<boost/asio/co_spawn.hpp>`
- `<boost/asio/ip/tcp.hpp>`
- `<boost/asio/steady_timer.hpp>`
- `<boost/asio/use_awaitable.hpp>`
- 等等

**预期效果**: 显著减少编译时间（可能减少 30-50%）。

---

### 任务 E.5: 结构化日志 + 内存监控

**日志增强**:
- 在日志中添加 session_id 贯穿全链路
- 在 listener accept 日志中记录客户端 IP
- 可选：添加独立的 access log 输出通道

**内存监控**:
- 在 PMR 池中添加水位统计（已分配/已释放/当前使用量）
- 定期（如每 60 秒）记录内存使用日志
- 可选：通过 `/metrics` 端点暴露内存指标

---

### 任务 E.6: 协议处理器去重

**涉及文件**:
- `src/prism/protocol/{http,socks5,trojan,vless,shadowsocks}/process.cpp`

**共同模式** (5 个处理器高度相似):
1. `wrap_with_preview` 调用
2. 创建协议代理 → `handshake()` → 结构化绑定
3. 目标地址解析（几乎相同的 `std::to_chars` 代码）
4. 拨号（`dial()` 调用模式相同）
5. 隧道转发

**实施方案**: 提取 `resolve_target()` 和 mux 处理的公共模板函数。每次重构一个协议后运行对应测试。

**预期效果**: 每个 `process.cpp` 从 ~100 行降至 ~60 行。

---

### 任务 E.7: 文档更新

| 文件 | 更新内容 |
|------|---------|
| `README.md` | 更新特性矩阵、新模块名、协议支持 |
| `docs/prism/stealth/` | 添加 Restls.md、AnyTLS.md、ECH.md、TrustTunnel.md |
| `docs/prism/channel.md` | 更新为 transport 模块名 + WebSocket 传输 |
| `docs/prism/agent.md` | 更新为 instance 模块名 |
| `docs/prism/pipeline.md` | 更新为 protocol 模块名 |
| `docs/prism/recognition.md` | 反映分层检测管道架构 |
| `docs/tutorial/` | 添加监控配置指南、新配置项、Docker 部署 |
| `docs/prism/performance-report.md` | 更新完整性能对比表 |
| `docs/wiki/core/` | 将旧路径文档（agent/、channel/）迁移到新模块名 |

---

## 八、依赖关系图

```
Phase A (第 1-2 周): 重构收尾 + 生产阻塞项
  ├─ A.1 提交架构重构 ───────────────────────┐
  ├─ A.2 修复 CI ────────────────────────────┤ 可并行
  ├─ A.3 优雅关闭 (main.cpp + worker) ────────┤
  ├─ A.4 握手超时 (session + recognition) ────┤
  └─ A.5 修复热路径异常 (preview.cpp) ────────┘

Phase B (第 3-4 周): Stealth 握手 + 监控
  ├─ B.1 Restls 握手 (restls/handshake) ──────┐
  ├─ B.2 AnyTLS 握手 (anytls/scheme) ──────────┤ 可并行
  ├─ B.3 ECH HPKE 解密 (ech/decrypt) ─────────┤
  ├─ B.4 TrustTunnel 握手 (trusttunnel) ──────┤
  ├─ B.5 监控指标系统 (trace/metrics) ─────────┤
  └─ B.6 健康检查端点 (health) ─── 依赖 B.5 ──┘

Phase C (第 5-6 周): 性能优化 + WebSocket
  ├─ C.1 内存池分片化 (pool.hpp) ─────────────┐
  ├─ C.2 P99 尾延迟 (pool.hpp + racer) ───────┤ 可并行
  ├─ C.3 小报文 TCP (reliable + tunnel) ──────┤
  ├─ C.4 性能回归基准 (RegressionBench) ─────┤
  └─ C.5 WebSocket 传输 (websocket) ──────────┘

Phase D (第 7-8 周): 正向代理 + 安全加固
  ├─ D.1 正向代理 (router) ───────────────────┐
  ├─ D.2 速率限制 + 全局上限 (limiter) ───────┤ 可并行
  ├─ D.3 客户端 IP 黑名单 (listener) ─────────┤
  ├─ D.4 消除 dynamic_cast (transmission) ────┤
  └─ D.5 TLS 安全加固 (tls.cpp) ─────────────┘

Phase E (第 9-10 周): 测试补全 + 运维完善
  ├─ E.1 补全缺失测试 (10 个新测试文件) ──────┐
  ├─ E.2 热重载配置 (SIGHUP + swap_config) ───┤ 可并行
  ├─ E.3 Dockerfile / 容器化 ─────────────────┤
  ├─ E.4 精细化 Boost.Asio include (59 文件) ─┤
  ├─ E.5 结构化日志 + 内存监控 ───────────────┤
  ├─ E.6 协议处理器去重 (5 个 process.cpp) ───┤
  └─ E.7 文档更新 (README + docs/) ───────────┘
```

---

## 九、风险评估与缓解

| 任务 | 风险等级 | 具体风险 | 缓解措施 |
|------|---------|---------|---------|
| A.1 提交重构 | 低 | 大量文件变更可能有遗漏 | 全量编译 + 测试验证 |
| A.3 优雅关闭 | 中 | Windows 信号处理与 Linux 不同 | 使用 `boost::asio::signal_set` 跨平台 |
| B.1 Restls | 中 | 协议规范复杂，客户端兼容性 | 最小可行握手起步；用官方客户端验证 |
| B.3 ECH HPKE | 高 | HPKE 规范复杂，BoringSSL 可能缺少部分 API | 可先实现基础版，延后完整版 |
| C.1 内存池分片 | 低 | 分片间碎片化 | 分片数 8-16，fallback 到 synchronized_pool |
| C.5 WebSocket | 中 | 分片帧、掩码、continuation 边界 | 从非掩码 binary 帧起步 |
| D.4 RTTI 移除 | 低 | 新 `dynamic_cast` 可能出现 | 编译选项强制 `-fno-rtti` |
| D.2 速率限制 | 低 | per-IP 表在高并发下可能成为瓶颈 | 使用无锁哈希表 + LRU 淘汰 |

---

## 十、完成后状态

本计划完成后的预期状态：

| 维度 | 目标 |
|------|------|
| 活跃 TODO | 0 个 |
| `dynamic_cast` | 0 处 |
| RTTI | 已禁用 (`-fno-rtti`) |
| 优雅关闭 | 完整实现 |
| 监控指标 | Prometheus 格式导出 |
| 健康检查 | `/health` + `/metrics` + `/ready` |
| 测试文件 | 57+ 个 |
| CI | 测试失败阻止发布 + 性能回归检测 |
| WebSocket | 完整实现 |
| 正向代理 | HTTP CONNECT 实现 |
| 速率限制 | per-IP 令牌桶 + 全局连接上限 |
| Dockerfile | 多阶段构建 + HEALTHCHECK |
| 文档 | 全部更新到新模块名 |
| 性能目标 | 全局池 <100ns、P99 <200us、TCP 64B <10us |

---

## 十一、与上层架构计划的关系

本 10 周计划聚焦于 **重构收尾 + 生产阻塞项 + Stealth TODO 清零 + 性能优化 + 安全加固**，不涉及以下更大规模的架构变更：

| 上层功能 | 与本计划关系 |
|----------|-------------|
| Outbound 出站代理抽象 | 独立，可在本计划完成后启动 |
| Traffic Controller 流量调度器 | 独立，可在本计划完成后启动 |
| Rule 规则引擎 | 独立，可在本计划完成后启动 |
| Proxy Group 代理组 | 依赖 Outbound 抽象 |
| QUIC / Hysteria2 / TUIC | 独立大工程 |
| REST API | B.5 指标系统为其打基础 |
| TUN / WireGuard / VMess | 独立大工程 |
| gRPC 传输 | 未计划，需 HTTP/2 framing 层 |
| VLESS XTLS/Vision | 独立，可单独启动 |

本计划完成后的状态：架构重构完成、生产就绪、TODO 清零、性能达标、安全加固，为上述更大规模的架构变更奠定坚实基础。
