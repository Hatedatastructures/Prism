# Prism 问题清单

> 按模块和严重程度排序。CRITICAL = 生产安全风险；HIGH = 功能/性能显著影响；MEDIUM = 代码质量/可维护性；LOW = 改进建议。

---

## 1. 安全 (Security)

### [CRITICAL] S1 — SS2022 server salt 使用 `std::random_device` 而非 CSPRNG

**位置**: `src/prism/protocol/shadowsocks/conn.cpp:242-246`

`std::random_device` 在 MinGW 上不保证是密码学安全随机数生成器，可能退化为确定性 PRNG。SS2022 server salt 用于派生每会话 AEAD 密钥，可预测的 salt 允许对会话加密进行预计算攻击。

```cpp
// 当前代码
std::random_device rd;
for (auto &b : server_salt)
{
    b = static_cast<std::uint8_t>(rd() & 0xFF);
}
```

**修复**: 替换为 `RAND_bytes()`（BoringSSL），与项目中 `x25519.cpp`、`response.cpp` 的做法一致。

---

### [CRITICAL] S2 — AEAD nonce 递增无溢出检测

**位置**: `src/prism/crypto/aead.cpp:197-207`

SS2022 TCP 流的 nonce 从 `0xFF...FF` 悄静回绕到 `0x00...00`。nonce 复用对 AES-GCM 和 ChaCha20-Poly1305 是灾难性的，会破坏所有记录的机密性和真实性。

```cpp
void aead_context::increment_nonce()
{
    for (std::size_t i = 0; i < nonce_len_; ++i)
    {
        nonce_[i]++;
        if (nonce_[i] != 0) { break; }
    }
    // 缺少: 溢出检测 (nonce 全零表示回绕)
}
```

**修复**: 在循环结束后检查是否所有字节为零（表示回绕），若是则返回 `fault::code::nonce_overflow` 并终止连接。

---

### [CRITICAL] S3 — Reality seal 序列号无溢出检测

**位置**: `src/prism/stealth/reality/seal.cpp:160-161, 221-222`

`read_sequence_` 和 `write_sequence_`（`uint64_t`）在每次加解密后递增，无溢出检查。TLS 1.3 (RFC 8446 §5.5) 要求序列号到达 2^64 前终止连接。长连接静默回绕会导致 nonce 复用。

**修复**: 在 `++read_sequence_` / `++write_sequence_` 后检查是否为零（回绕），若是则返回错误并关闭连接。

---

### [CRITICAL] S4 — 仓库包含已跟踪的 TLS 私钥和证书

**位置**: `cert.pem`、`key.pem`（项目根目录，已被 `git add` 跟踪）

`cert.pem` 和 `key.pem` 已提交到 Git 历史且未被 `.gitignore` 排除。任何使用默认配置部署 Prism 的人都会使用这些密钥材料。

**修复**: 从 Git 历史中移除，加入 `.gitignore`，使用 `configuration.json` 中的相对路径或环境变量。若这些密钥曾在公开仓库中暴露，需立即轮换。

---

### [HIGH] S5 — 配置文件包含硬编码密码和密钥

**位置**: `src/configuration.json`

配置文件包含明文密码和密钥：
- Reality X25519 私钥 (`private_key`)
- SS2022 PSK (`psk`)
- ShadowTLS/Restls/AnyTLS/TrustTunnel 密码
- 认证用户密码 (`password: "prism"`)

**修复**: 将 `configuration.json` 改为模板（`configuration.example.json`），实际配置加入 `.gitignore`。

---

### [HIGH] S6 — Reality seal null transport 时返回悬挂 executor

**位置**: `src/prism/stealth/reality/seal.cpp:27-28`

```cpp
if (!transport_)
{
    return net::io_context{}.get_executor(); // 临时 io_context 立即销毁
}
```

返回的 executor 指向已销毁的临时 `io_context`，任何后续 `co_await` 操作是未定义行为。

**修复**: 返回错误码或抛出异常，不返回悬挂引用。

---

### [HIGH] S7 — TLS 记录长度无上限校验

**位置**: `src/prism/stealth/reality/seal.cpp:120-123`

```cpp
const auto record_len = (static_cast<std::size_t>(raw[3]) << 8) | raw[4];
record_body_buf_.resize(record_len); // 最大 65535 字节
```

TLS 1.3 (RFC 8446 §5.2) 限制记录载荷为 16384 字节。接受最大 65535 字节允许恶意对端触发大内存分配。

**修复**: 添加 `if (record_len > 16384 + AEAD_TAG_LEN) return fault::code::record_too_large;`

---

### [MEDIUM] S8 — 连接池 raw `new tcp::socket` 存在泄漏路径

**位置**: `src/prism/connect/pool/pool.cpp:189`

```cpp
auto *sock = new tcp::socket(ioc_);
```

裸指针在 `async_connect` 设置阶段（line 199-205）若抛异常，socket 将泄漏。`delete_socket()` 仅在超时和连接错误路径调用。

**修复**: 使用 `unique_ptr` 保护，仅在成功时 `release()`。

---

### [MEDIUM] S9 — 连接池清理协程捕获裸 `this`

**位置**: `src/prism/connect/pool/pool.cpp:332`

```cpp
auto clean_function = [this, flag]() -> net::awaitable<void>
```

`shutdown_flag_` 信号机制存在竞态窗口：flag 检查与下一次 `co_await` 之间若 `connection_pool` 被销毁，协程访问悬挂指针。

**修复**: 捕获 `shared_from_this()` 或使用 `weak_ptr`。

---

### [MEDIUM] S10 — Trojan/VLESS UDP associate 使用 raw `new traffic_context`

**位置**: `src/prism/protocol/trojan/conn.cpp:296`、`src/prism/protocol/vless/conn.cpp:274`

```cpp
auto *tc = traffic_ ? new traffic_context{traffic_, proto_} : nullptr;
```

手动 `new` + 回调中 `delete`，若 `new` 与循环入口之间抛异常则泄漏。

**修复**: 使用 `unique_ptr` 或 PMR 分配。

---

## 2. 协程纯度 (Coroutine Purity)

### [HIGH] C1 — Yamux `send_data` CAS 自旋等待阻塞 io_context

**位置**: `src/prism/multiplex/yamux/craft.cpp:744-754`

```cpp
while (!window_acquired && is_active())
{
    auto old_val = window->send_window.load(std::memory_order_acquire);
    while (old_val >= payload_size)
    {
        if (window->send_window.compare_exchange_weak(old_val, old_val - payload_size, ...))
        {
            window_acquired = true;
            break;
        }
    }
    // 无 co_await 或 yield 点
}
```

窗口耗尽但 `is_active()` 为真时，CAS 循环在 io_context 线程忙等，饿死同线程所有协程。违反项目禁止"忙等待"的协程纯度规则。

**修复**: CAS 失败后应 `co_await` 异步等待窗口更新通知（`window->notify.acquire()`），而非自旋。

---

### [MEDIUM] C2 — 热路径 `preview::executor()` 抛异常

**位置**: `src/prism/transport/preview.cpp:19`

```cpp
throw std::runtime_error("preview::executor called with null inner transmission");
```

这是传输层热路径函数，应返回 `fault::code` 而非抛异常。项目约定热路径使用错误码、启动/致命错误才用异常。

**修复**: 改为返回默认 executor 或错误码。

---

### [MEDIUM] C3 — `encrypted::close()` 同步调用 `SSL_shutdown`

**位置**: `include/prism/transport/encrypted.hpp:143`

`SSL_shutdown` 在 BoringSSL 上可能执行非平凡的 TLS 拆解计算。在协程上下文中同步调用可能阻塞 io_context 线程。

**修复**: 改为异步或延迟执行（best-effort 关闭可跳过 shutdown 直接 close）。

---

## 3. 性能 (Performance)

### [HIGH] P1 — 隧道缓冲区减半，吞吐量受限

**位置**: `src/prism/connect/tunnel/tunnel.cpp:26-28`

```cpp
const auto half = buffer.size() / 2;
const auto left = std::span(buffer).first(half);
const auto right = std::span(buffer).last(half);
```

单个 `buffer_size` 分配被一分为二给上传/下载。`buffer_size` 默认 65536 时，每方向只有 32KB，配置意图是 64KB。

**修复**: 分配两个独立向量，或总大小翻倍为 `buffer_size * 2`。

---

### [HIGH] P2 — smux/yamux 默认 buffer 仅 4096 字节

**位置**: `include/prism/multiplex/smux/config.hpp:25`、`include/prism/multiplex/yamux/config.hpp:25`

每条 duct 的 `target_read_loop` 每次最多读 `min(buffer_size, 65535)` 字节。默认 4KB 导致 64KB 数据被拆成 16 次读取，产生 16x 帧开销、16x 系统调用。

**修复**: 默认值提升至 32KB-64KB。

---

### [HIGH] P3 — Release 可执行文件以 `-O1` 编译

**位置**: `src/CMakeLists.txt:57-60`

```cmake
target_compile_options(${PROJECT_NAME} PRIVATE
    -g1
    -O1
)
```

静态库正确使用 `-O3`，但最终可执行文件（含 `main.cpp`）被强制覆盖为 `-O1`，抵消了 Release 优化。

**修复**: 移除此编译选项，继承根 CMakeLists.txt 的 Release 配置。

---

### [MEDIUM] P4 — transmission 基类默认实现引入额外协程帧

**位置**: `include/prism/transport/transmission.hpp:127-158`

`async_read_some` 和 `async_write_some` 的 completion-handler 重载通过 `co_spawn` + `detached` 桥接。中间装饰器（`snapshot`、`encrypted`）未覆写这些方法，SSL 操作会多一层协程帧分配。

**修复**: 在 `encrypted` 和 `snapshot` 中覆写 completion-handler 风格方法，直接委托给底层。

---

### [MEDIUM] P5 — 全局 `synchronized_pool` 在单线程 worker 上产生不必要锁开销

**位置**: `include/prism/memory/pool.hpp:100-103`

`enable_global_pooling()` 使所有默认构造的 PMR 容器使用带锁的 `synchronized_pool`。每个 worker 是单线程事件循环，应使用 `thread_local_pool()` 避免锁竞争。

**修复**: 热路径容器显式使用 `thread_local_pool()`，或 worker 启动时切换默认资源。

---

### [MEDIUM] P6 — 无 scatter-gather (writev) 支持

**位置**: `include/prism/transport/transmission.hpp` (async_write 自由函数)

mux 帧头 + 载荷分两次 `async_write_some` 系统调用。合并为单次 `writev` 可减少 syscall 开销。

**修复**: 在 transport 层添加 `async_writev` 接口，支持多 buffer 合并写入。

---

### [LOW] P7 — `frame_arena` 栈缓冲区仅 512 字节

**位置**: `include/prism/memory/pool.hpp:222`

帧解析、地址解析、临时字符串构造常超过 512 字节，频繁回退到上游 `thread_local_pool`。考虑提升至 1024 或 2048 字节。

---

### [LOW] P8 — 隧道数据路径包含过多的 trace::debug 调用

**位置**: `src/prism/connect/tunnel/tunnel.cpp:44-82`

`forward_data` lambda 在读写循环内包含多个 `trace::debug()` 调用。即使日志级别禁用，字符串格式化仍可能产生开销。

**修复**: 添加 `if (trace::is_debug_enabled())` 门卫或移除数据路径日志。

---

## 4. 功能缺口 (Functional Gaps)

### [HIGH] F1 — AnyTLS 后续 stream 静默丢弃

**位置**: `src/prism/stealth/anytls/scheme.cpp:248-250`

```cpp
// 简化处理：后续 stream 直接 tunnel
// 完整实现应解析 SOCKS 地址后 dial + tunnel
co_return;
```

`on_new_stream` 回调对第一个流之后的所有流直接 `co_return`，不做任何处理。这是一个功能性缺陷，不是代码质量问题。

**修复**: 实现 SOCKS 地址解析 + dial + tunnel 完整流程（注意 TODO: 复用 `protocol::anytls::handle` 的地址解析）。

---

### [HIGH] F2 — 正向代理配置已解析但从未使用

**位置**: `src/prism/connect/dial/dial.cpp`（`async_forward` 仅直连）、`router.cpp`（`positive_host_/positive_port_` 存储 but 未使用）

`instance::config::positive` 从 JSON 反序列化，`router::set_positive_endpoint()` 存储，但 `async_forward()` 从不检查或使用正向代理端点。存储的字段是死代码。

**修复**: 在 `dial()` 或 `async_forward()` 中实现通过正向代理（HTTP CONNECT）的连接路径。

---

### [HIGH] F3 — 优雅关机完全缺失

**位置**: `src/main.cpp`

无信号处理（SIGTERM/SIGINT），无 `io_context.stop()`，无 drain 逻辑。进程被杀时资源泄漏，可能损坏 spdlog 异步队列。

**修复**: 注册信号处理器，设置关机标志，等待活跃连接完成或超时后退出。

---

### [HIGH] F4 — 握手超时未实现

**位置**: `src/prism/instance/session/session.cpp`、`src/prism/recognition/`

session 和 recognition 模块无 deadline timer。恶意客户端可建立连接后不发送数据，无限占用资源。

**修复**: 在 session 启动时设置总超时定时器（建议 30s），超时后取消协程并关闭连接。

---

### [MEDIUM] F5 — ECH HPKE 解密为空实现

**位置**: `src/prism/stealth/ech/util/decrypt.cpp:39-50`

格式检查和版本校验已实现，但 HPKE 解密核心返回 `fault::code::not_supported`。任何发送 ECH 的客户端将始终检测失败。

**修复**: 实现 HPKE SetupBaseS + AEAD Open。

---

### [MEDIUM] F6 — SOCKS5 BIND 命令未实现

**位置**: `include/prism/protocol/socks5/config.hpp:35`（`enable_bind` 字段存在）、`conn.cpp:44`（始终返回 `command_not_supported`）

配置字段已解析但功能未实现。

---

### [MEDIUM] F7 — WebSocket 传输零实现

**位置**: 整个代码库无 WebSocket 相关代码

路线图 Phase C.5（第 5-6 周），完全未开始。

---

### [MEDIUM] F8 — HTTP/Shadowsocks 协议未调用 `set_traffic()`

**位置**:
- `src/prism/protocol/http/process.cpp` — 无 `set_traffic` 调用
- `src/prism/protocol/shadowsocks/process.cpp` — 无 `set_traffic` 调用

Trojan、VLESS、SOCKS5 均调用 `agent->set_traffic()`，HTTP 和 Shadowsocks 遗漏，导致这两个协议的流量统计缺失。

**修复**: 在 HTTP relay 和 SS2022 agent 上调用 `set_traffic()`。

---

## 5. 构建与 CI (Build & CI)

### [CRITICAL] B1 — CI `continue-on-error: true` 测试失败不阻塞发布

**位置**: `.github/workflows/build.yml:34, 73`

测试失败不会阻止 Release 上传。带 bug 的二进制文件可能被发布。

**修复**: 移除 `continue-on-error: true`。

---

### [CRITICAL] B2 — 7 个 FetchContent 依赖无完整性校验

**位置**: `CMakeLists.txt` 所有 `FetchContent_Declare` 调用

spdlog、Boost、glaze、BoringSSL、BLAKE3、nghttp2、Google Benchmark 均使用裸 `URL` 下载，无 `URL_HASH` / `SHA256` 校验。MITM 攻击可注入恶意代码。

**修复**: 为每个依赖添加 `URL_HASH SHA256=...`。

---

### [HIGH] B3 — CI 仅在 tag 和手动触发时运行

**位置**: `.github/workflows/build.yml:3-7`

PR 和 push 到 main 无 CI 保护。破损代码可直接合并。

**修复**: 添加 `push: branches: [main]` 和 `pull_request:` 触发器。

---

### [HIGH] B4 — 生产库零编译警告

**位置**: `src/CMakeLists.txt`（`prism_static_library` 无 `-Wall -Wextra`）

仅并发测试子目录有警告标志。整个生产库编译时无任何警告诊断。

**修复**: 在静态库和可执行文件上添加 `-Wall -Wextra -Wpedantic`。

---

### [HIGH] B5 — `cert.pem`/`key.pem` 已跟踪但 `.gitignore` 未排除

**位置**: 项目根目录、`.gitignore`

`.gitignore` 未包含 `*.pem`。`cert.pem` 和 `key.pem` 已在 Git 历史中。`a.exe`（0 字节垃圾文件）也在根目录但未被跟踪。

**修复**: `.gitignore` 添加 `*.pem`、根目录 `/*.exe`（排除 build 目录下的），清理已跟踪文件 `git rm --cached cert.pem key.pem`。

---

### [MEDIUM] B6 — BLAKE3 SIMD 编译选项无平台保护

**位置**: `CMakeLists.txt:241-244`

`-msse2`、`-msse4.1`、`-mavx2`、`-mavx512f` 无条件应用于 BLAKE3 源文件。在 ARM 或非 x86 平台上会编译失败。

**修复**: 添加 `if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i.86")` 保护。

---

### [MEDIUM] B7 — 无 Sanitizer 构建

无 ASan、UBSan、TSan 配置。对于手动加密、协程并发、裸内存操作的网络代理，sanitizer 构建应作为标准 CI 门禁。

**修复**: 添加 CMake option `PRISM_ENABLE_ASAN` 等，在 CI 中增加 sanitizer 构建矩阵。

---

### [MEDIUM] B8 — `cmake/` 目录为空

`cmake/` 目录存在但无文件。应有 `CompilerWarnings.cmake`、`Sanitizers.cmake` 等模块化配置。

---

### [LOW] B9 — MinGW CI 版本 13.2.0 偏旧

**位置**: `.github/workflows/build.yml:19`

项目使用 C++23 特性，MinGW 14.x 有更好的 C++23 支持和优化。

---

## 6. 代码质量 (Code Quality)

### [MEDIUM] Q1 — Trojan/VLESS 验证器 lambda 完全重复

**位置**:
- `src/prism/protocol/trojan/process.cpp:30-45`
- `src/prism/protocol/vless/process.cpp:30-45`

两段代码逐字符一致：检查 `ctx.account_directory`、调用 `account::try_acquire`、存储 `ctx.account_lease`。

**修复**: 提取到 `protocol/common/verify.hpp` 的共享函数。

---

### [MEDIUM] Q2 — Trojan/VLESS mux 引导块复制粘贴

**位置**:
- `src/prism/protocol/trojan/process.cpp:73-89, 117-135`
- `src/prism/protocol/vless/process.cpp:73-91`

相同结构：clear active_stream_close/cancel → `multiplex::bootstrap` → `start()`。

**修复**: 提取 `protocol::common::try_mux_bootstrap()` 辅助函数。

---

### [MEDIUM] Q3 — 三种 stealth TLS 握手模式重复

**位置**:
- `src/prism/stealth/native.cpp:73-101`
- `src/prism/stealth/anytls/scheme.cpp:141-166`
- `src/prism/stealth/trusttunnel/scheme.cpp:116-143`

三者均遵循 `peel_to_raw → wrap_with_preview → ssl_handshake → create encrypted transport` 序列。

**修复**: 提取到 `stealth/common/` 的共享 TLS 握手辅助函数。

---

### [MEDIUM] Q4 — session.cpp 使用原始 switch 替代 dispatch 表

**位置**: `src/prism/instance/session/session.cpp:182-215`

协议分发使用硬编码 `switch` 语句。添加新协议需修改 `session.cpp`，违反开闭原则。CLAUDE.md 文档描述的 dispatch table 架构从未实现。

**修复**: 实现基于 `unordered_map<protocol_type, handler_function>` 或编译期常量数组的 dispatch 机制。

---

### [MEDIUM] Q5 — 错误描述 API 不一致

**位置**:
- `src/prism/protocol/socks5/process.cpp:38` — `fault::cached_message(ec)`
- `src/prism/protocol/http/process.cpp:33` — `fault::describe(ec)`
- `src/prism/protocol/trojan/process.cpp:55` — `fault::describe(trojan_ec)`

两个功能相似的函数 `cached_message` 和 `describe` 混合使用，应统一为一个。

---

### [MEDIUM] Q6 — 协议标签命名不一致

六种协议使用三种命名约定：
- `HttpStr`、`Socks5Str`、`TrojanStr`、`VlessStr`、`ForwardStr` — `PascalCase + Str` 后缀
- `shadowsocks_tag` — `snake_case + _tag` 后缀
- AnyTLS 使用 `tag` — 纯 `tag`

**修复**: 统一为 `PascalCase + Str` 或 `snake_case + _tag`。

---

### [MEDIUM] Q7 — HTTP conn 使用 `std::vector<char>` 而非 PMR

**位置**: `include/prism/protocol/http/conn.hpp:96`

```cpp
std::vector<char> buffer_;
```

HTTP 是唯一未使用 PMR 容器的协议处理器。

**修复**: 改为 `memory::vector<char>`。

---

### [MEDIUM] Q8 — yamux `data_frame` 使用 `std::vector` 而非 PMR

**位置**: `include/prism/multiplex/yamux/frame.hpp:180`

```cpp
std::vector<std::byte> payload;
```

注释说"for testing and debugging"但属于公共 API，可能意外用于生产路径。smux/yamux craft 的 `outbound_frame` 正确使用 `memory::vector`。

**修复**: 改为 `memory::vector<std::byte>`。

---

### [MEDIUM] Q9 — `salt_pool` 使用 `std::unordered_map<std::string>` 堆分配 key

**位置**: `include/prism/protocol/shadowsocks/util/salts.hpp:86, 110`

```cpp
entries_.emplace(std::string(key), now + ttl_);
```

每次插入构造 `std::string` 堆分配。salt 是固定大小（16/32 字节），可使用 `std::array` 或 flat map 避免堆分配。`salt_pool` 是 per-worker `thread_local`，但 `std::unordered_map` 本身仍走系统堆而非 PMR。

**修复**: 使用 `memory::unordered_map` 配合 `thread_local_pool`，或使用固定大小 key 的 flat map。

---

### [LOW] Q10 — `namespace net = boost::asio` 在几乎所有文件重复声明

每个协议 process.hpp、conn.hpp、多数源文件都重新声明此别名。

**修复**: 创建 `include/prism/alias.hpp` 统一定义。

---

## 7. 测试缺口 (Test Coverage)

### [HIGH] T1 — 24+ 源码模块无任何测试

最关键的未测试模块：

| 模块 | 源文件 | 影响 |
|------|--------|------|
| `protocol/anytls` | `process.cpp` | 整个协议零测试 |
| `stealth/anytls` | `scheme.cpp`, `session.cpp`, `padding.cpp` | 握手未验证 |
| `stealth/trusttunnel` | `h2_bridge.cpp`, `scheme.cpp` | h2 桥接未测试 |
| `stealth/ech` | `decrypt.cpp` | 解密未测试 |
| `stealth/restls` | `handshake.cpp`, `transport.cpp` | 握手/传输未测试 |
| `stealth/reality` | `handshake.cpp`, `seal.cpp` | 握手/AEAD 未测试 |
| `multiplex` | `bootstrap.cpp`, `core.cpp`, `parcel.cpp` | 生命周期未测试 |
| `stats` | `runtime.cpp`, `traffic.cpp` | 指标系统未测试 |
| `resolve/dns` | `resolver.cpp`, `upstream.cpp` | DNS 解析未测试 |
| `instance` | `worker.cpp`, `listener.cpp` | 核心 infra 未测试 |
| `transport/encrypted` | `encrypted.cpp` | TLS 传输未测试 |
| `recognition` | `layered_pipeline.cpp`, `tls/signal.cpp` | 管道阶段未测试 |
| `loader` | `load.hpp` | 配置加载未测试 |
| `outbound` | — | 零覆盖 |

---

### [MEDIUM] T2 — 10+ 测试文件未使用共享 TestRunner

`Shadowsocks.cpp`、`Trojan.cpp`、`Socks5.cpp`、`Http.cpp`、`Vless.cpp`、`Regression.cpp`、`Smux.cpp`、`DnsPacket.cpp`、`DnsRules.cpp`、`Crypto.cpp` 自定义 `passed/failed` 计数器和 `LogPass/LogFail`，未使用 `tests/common/TestRunner.hpp`。

**修复**: 统一迁移到 `TestRunner`。

---

### [MEDIUM] T3 — 协议握手测试过浅

- Trojan: 仅 1 个测试（基本 relay 握手）
- SOCKS5: 仅 1 个测试（基本 relay 握手）
- 缺失: 畸形请求、超时、部分读取、认证失败等边界情况

---

### [LOW] T4 — 缺少 DNS 解析和连接池压力测试

DNS 解析管道（resolver + upstream）和连接池在高并发下的行为未被压测。

---

## 8. 文档过时 (Documentation)

### [MEDIUM] D1 — CLAUDE.md 多处与代码不同步

- 引用 `include/prism/agent/` 但实际是 `include/prism/instance/`
- 引用 `include/prism/pipeline/` 目录不存在
- 3 个 "Active TODO" 中 2 个已解决：Restls 握手已完整实现、Reality 类型统一已完成；router 路径已从 `src/prism/resolve/router.cpp` 迁移
- Agent 模块结构描述的目录不存在

**修复**: 更新 CLAUDE.md 反映当前代码结构。

---

### [LOW] D2 — 根目录残留垃圾文件

- `a.exe`（0 字节，未被 git 跟踪但存在于磁盘）
- `Crypto.exe`（未被 git 跟踪但存在于磁盘）

**修复**: 删除文件，`.gitignore` 添加根目录 `/*.exe`。

---

---

## 9. 深度审计发现 (第二轮)

### [CRITICAL] R1 — TrustTunnel 修改共享 SSL_CTX 的 ALPN（竞态 + 正确性）

**位置**: `src/prism/stealth/trusttunnel/scheme.cpp:128`

```cpp
SSL_CTX_set_alpn_protos(ctx.session->server_ctx.ssl_ctx->native_handle(),
                        reinterpret_cast<const unsigned char *>("\x2h2"), 3);
```

`server_ctx.ssl_ctx` 在 `worker/tls.cpp:82-86` 创建，被同 worker 的所有会话共享。每次 TrustTunnel 握手都将共享 `SSL_CTX` 的 ALPN 覆盖为 `h2`-only。

- **正确性**: TrustTunnel 握手后，同 worker 后续的 native TLS / AnyTLS 握手将使用 h2-only ALPN，导致非 h2 协议协商失败。
- **线程安全**: 虽然单 worker 单线程，但 SSL accept 回调可能交错执行，一个 TrustTunnel 的 `SSL_CTX_set_alpn_protos` 可与另一个连接的 `SSL_accept` 读取 ALPN 竞争。

**修复**: 使用 per-SSL 的 `SSL_set_alpn_protos` 而非修改共享 `SSL_CTX`。

---

### [CRITICAL] R2 — AnyTLS session 泄漏（wait_first_stream 失败时）

**位置**: `src/prism/stealth/anytls/scheme.cpp:255-268`

生命周期：
1. `session->start()` 通过 `co_spawn(detached)` 启动 `recv_loop`，recv_loop 捕获 `self` 保持 session 存活
2. `co_await session->wait_first_stream()` 失败
3. 函数返回，但 detached `recv_loop` 仍持有 session 引用
4. 没有人关闭 session 持有的 encrypted transport

结果：anytls_session、SSL 流、底层 TCP socket 持续泄漏直到远端关闭或超时。在阻塞客户端场景下可能无限泄漏。

**修复**: 失败时调用 `session->close()` 或取消 recv_loop。

---

### [CRITICAL] R3 — TrustTunnel h2_bridge 泄漏（wait_first_connect 失败时）

**位置**: `src/prism/stealth/trusttunnel/scheme.cpp:252-262`

与 R2 相同模式：`bridge->start()` 启动 detached recv_loop → `wait_first_connect()` 返回 nullopt → 函数返回但未停止 bridge → detached recv_loop 保持 bridge 活着 → bridge 持有 encrypted transport。

**修复**: 失败时调用 `bridge->stop()` 或取消 recv_loop。

---

### [HIGH] R4 — AnyTLS write_strand_ 声明但未使用，并发写入可交错

**位置**: `include/prism/stealth/anytls/session.hpp:121`

`write_strand_` 在构造函数中初始化，但 `write_frame()`、`write_psh()`、`write_fin()`、`write_synack()` 均未使用 strand 序列化。当多个 stream 并发写入时（如一个 stream 写 PSH 同时 recv_loop 发送心跳响应），帧头和载荷可能交错，破坏数据流。

当前因单 io_context 单线程而安全，但设计意图明确需要 strand（注释写着"写入串行化"），且如果未来改为多线程会立即触发数据损坏。

**修复**: 所有写入操作通过 `write_strand_` 分发，或使用 `net::post(write_strand_, ...)` 包装。

---

### [HIGH] R5 — anytls_session::recv_loop 无顶层异常处理，可导致进程崩溃

**位置**: `src/prism/stealth/anytls/session.cpp:65-303`

`recv_loop` 通过 `co_spawn(detached)` 启动，**无顶层 try-catch**。意外异常（如 `std::bad_alloc` 由畸形帧长度触发、`streams_.emplace` 失败）会传播出协程。`net::detached` 下未捕获异常调用 `std::terminate()`，导致整个进程崩溃。

对比：session::start()、duct::start()、core::start()、craft 的 send/ping/keepalive 循环均有 `catch(...)` 保护。

**修复**: 在 `recv_loop` 添加顶层 `try-catch(...)` 并调用 `close()`。

---

### [HIGH] R6 — h2_bridge::recv_loop 同样缺乏顶层异常处理

**位置**: `src/prism/stealth/trusttunnel/h2_bridge.cpp`

与 R5 相同模式：外部输入处理 + detached 协程 + 无 try-catch。

**修复**: 添加顶层 `try-catch(...)` 并调用 `close()`。

---

### [HIGH] R7 — 连接池无最大并发连接数限制

**位置**: `src/prism/connect/pool/pool.cpp:183-270`

`async_acquire()` 在缓存为空时总是创建新 TCP 连接，无上限。高负载下可打开无限 TCP socket，导致文件描述符耗尽（EMFILE/WSAEMFILE）。`max_cache_per_endpoint` 仅限制空闲缓存，不限制已借出的连接数。

**修复**: 添加 `max_total_per_endpoint` 或全局 `max_connections` 限制，超出时排队等待。

---

### [MEDIUM] R8 — DNS 查询 detached 任务可能比 resolver 存活更久

**位置**: `src/prism/resolve/dns/upstream.cpp:826-858`

`first/fastest` 模式下，DNS 查询通过 `net::co_spawn(ioc_, task, net::detached)` 启动，捕获裸 `this`（upstream 对象）。如果 resolver 在 io_context 仍在运行时被销毁（如配置热重载），detached 任务将访问已销毁对象。

当前因单线程 io_context 在 worker 之前停止而安全，但架构上脆弱。

---

### [MEDIUM] R9 — 配置反序列化后零语义校验

**位置**: `include/prism/loader/load.hpp`、`include/prism/config.hpp`

glaze 反序列化后无验证层，以下无效值被静默接受：
- `buffer.size = 0` → 零长度读缓冲（`tunnel.cpp` 中 `max(ctx.buffer_size, 2U)` 勉强兜底）
- `addressable.port = 0` → 监听端口 0（OS 分配，几乎一定是非预期）
- `dns.ttl_min > dns.ttl_max` → TTL 钳制逻辑反转
- `dns.cache_size = 0` → 零大小缓存立即驱逐
- `trace.queue_size = 0` → 可能导致 spdlog 初始化崩溃
- `shadowsocks.timestamp_window` 为负或零 → 拒绝所有包
- `pool.connect_timeout_ms = 0` → 连接立即超时
- 空 `stealth.reality.private_key` → 握手时才报错
- `shadowtls.users` 空密码 → 静默接受
- 完全省略 `addressable` 字段 → glaze 默认构造 `host=""`, `port=0`

**修复**: 添加 `validate()` 函数在反序列化后校验所有配置项，不合法则抛出明确错误。

---

### [MEDIUM] R10 — `system_state::mark_started` 内存序错误

**位置**: `src/prism/stats/runtime.cpp:126-133`

```cpp
void system_state::mark_started(std::uint32_t worker_count) noexcept
{
    if (started_.exchange(true, std::memory_order_relaxed))
        return;
    start_time_ = std::chrono::steady_clock::now();  // 非原子
    worker_count_ = worker_count;                      // 非原子
}
```

`start_time_` 和 `worker_count_` 在 relaxed store 之后写入。并发 `snapshot()` 可能通过 relaxed load 看到 `started_ == true` 但读到未初始化的 `start_time_`/`worker_count_`。

**修复**: exchange 使用 `memory_order_release`，`snapshot()` 使用 `memory_order_acquire`。

---

### [MEDIUM] R11 — SS2022 padding length 未做边界检查

**位置**: `src/prism/protocol/shadowsocks/conn.cpp:219-224`

```cpp
padding_len = var_header_plain[offset] << 8 | var_header_plain[offset + 1];
offset += 2 + padding_len;
```

`padding_len` 无上限校验。大值导致 `offset` 超出 `var_header_plain.size()`。虽然后续有 `offset < var_header_plain.size()` 检查兜底，但缺少显式边界检查不够健壮。32 位平台上 `offset + 2 + padding_len` 理论上可能溢出 `size_t`。

**修复**: 在推进 offset 前检查 `offset + 2 + padding_len <= var_header_plain.size()`。

---

### [MEDIUM] R12 — SS2022 空分片导致提前 EOF

**位置**: `src/prism/protocol/shadowsocks/conn.cpp:459`

`fetch_chunk` 中 `current_payload_len_ == 0` 时直接返回空 `decrypted_`，导致 `async_read_some` 返回 0 字节。调用方 `transport::async_read` 将 0 视为 EOF，可能提前终止流。

**修复**: `current_payload_len_ == 0` 时应继续读取下一个分片而非返回。

---

### [MEDIUM] R13 — smux pending stream buffer 无上限

**位置**: `src/prism/multiplex/smux/craft.cpp:192-224`

`dispatch_push()` 将数据累积到 `entry.buffer` 无大小限制。恶意客户端可向 pending stream 发送大量 PUSH 帧而不触发激活，导致每个 pending stream 的 buffer 无限增长。`pending_` map 受 `max_streams` 限制，但每个 entry 的 buffer 不受限制。

**修复**: 添加 `max_pending_buffer_size` 限制，超出则丢弃或关闭 stream。

---

### [MEDIUM] R14 — Restls auth_mac 比较使用脆弱的 volatile 模式而非 CRYPTO_memcmp

**位置**: `src/prism/stealth/restls/transport.cpp:216-229`

```cpp
volatile const std::uint8_t *a = received_mac.data();
volatile const std::uint8_t *b = expected_mac.data();
std::uint8_t diff = 0;
for (std::size_t i = 0; i < app_data_mac_len; ++i)
    diff |= a[i] ^ b[i];
```

`volatile` 不保证常量时间执行，编译器优化可能击败此技巧。同项目的 ShadowTLS 正确使用 `CRYPTO_memcmp`。Restls auth_mac 保护每记录完整性，时序泄露可能帮助伪造记录。

**修复**: 替换为 `CRYPTO_memcmp(received_mac.data(), expected_mac.data(), app_data_mac_len)`。

---

### [MEDIUM] R15 — Reality auth 使用非常量时间字符串比较

**位置**: `src/prism/stealth/reality/util/auth.cpp:14-50`

- `match_server_name` 使用 `name == sni`（短路比较）
- `match_short_id` 使用 `std::equal`（短路比较）

攻击者通过时序测量可推断配置的 server_name 列表内容和 short_id 值。

**修复**: 使用 `CRYPTO_memcmp` 进行常量时间比较。

---

### [MEDIUM] R16 — HTTP CONNECT 目标端口未校验

**位置**: `src/prism/protocol/http/conn.cpp`

CONNECT 请求的 `host:port` 中，port 未校验范围（0-65535）或是否为数字。`example.com:99999` 或 `example.com:abc` 将被直接转发。

**修复**: 在 HTTP 层添加端口范围校验。

---

### [MEDIUM] R17 — DNS 查询缺少 EDNS0 OPT 记录

**位置**: `src/prism/resolve/dns/detail/format.cpp:511-528`

DNS 查询构建不含 OPT 伪记录（EDNS0）。无 EDNS0 时 DNS 响应方限制 UDP 响应为 512 字节，导致不必要的截断和 TCP 回退，降低 DNS 解析效率。

**修复**: 添加 EDNS0 OPT 记录，声明 4096 字节 UDP 缓冲区。

---

### [MEDIUM] R18 — TrustTunnel authority 解析不完整

**位置**: `src/prism/protocol/trusttunnel/process.cpp:38-49`

- IPv6 中括号未闭合（如 `[::1`）时回退到非 IPv6 解析路径，导致错误分割
- 空主机名（如 `:443`）被静默接受
- 端口非数字未校验

**修复**: 添加完整的 authority 格式校验。

---

### [LOW] R19 — TLS 服务器配置使用错误 API 设置 TLS 1.3 密码套件

**位置**: `src/prism/instance/worker/tls.cpp:52-60`

`SSL_CTX_set_cipher_list` 中的 TLS 1.3 密码名被 BoringSSL 静默忽略。应使用 `SSL_CTX_set_ciphersuites()`。功能上无害（BoringSSL 默认启用所有三个 TLS 1.3 密码），但具有误导性。

---

### [LOW] R20 — ShadowTLS 多用户匹配时序泄露

**位置**: `src/prism/stealth/shadowtls/handshake.cpp:382-393`

顺序遍历用户列表并在首次匹配时返回。虽然单次 HMAC 比较是常量时间（`CRYPTO_memcmp`），但迭代模式可泄露用户列表大小和匹配位置。

---

### [LOW] R21 — yamux/smux stream_id 0 未被 SYN 帧拒绝

**位置**:
- `src/prism/multiplex/yamux/craft.cpp` — Data(SYN) with stream_id=0 进入 handle_syn
- `src/prism/multiplex/smux/frame.cpp` — SYN with stream_id=0 进入 pending

stream_id 0 在两个 mux 协议中保留给会话级消息。应拒绝 SYN 帧使用 stream_id 0。

---

### [LOW] R22 — 共享 framing 层接受零长度域名和端口 0

**位置**: `include/prism/protocol/common/framing.hpp`

- `parse_domain` 接受 `len = 0`（零长度域名），所有协议继承此行为
- `parse_port` 接受任何 16 位值包括 0，所有协议继承此行为

**修复**: `parse_domain` 拒绝 `len == 0`，`parse_port` 拒绝 0。

---

### [LOW] R23 — `snapshot` 捕获缓冲区无大小限制

**位置**: `include/prism/transport/snapshot.hpp`

`captured_` 随着读取不断增长无上限。长连接上读取大量数据时，captured buffer 无限增长。与 `preview`（固定预读大小）不同。

**修复**: 添加 `max_capture_size` 参数或在 `stop_capture()` 后停止累积。

---

### [LOW] R24 — `account::try_acquire` relaxed 排序允许连接数瞬时溢出

**位置**: `include/prism/account/directory.hpp:197-211`

`compare_exchange_weak` 使用 `memory_order_relaxed`，多 worker 可同时读到相同计数并全部成功，瞬时超过 `max_connections`。溢出幅度最大为 worker 线程数。已文档化为近似限制。

---

### [LOW] R25 — `connection_pool::stat_*` 字段为非原子 `size_t`

**位置**: `include/prism/connect/pool/pool.hpp:328-334`

注释说"计数器使用 memory_order_relaxed"但字段是普通 `size_t` 而非 `atomic<size_t>`。当前因单线程使用而安全，但若 `stats()` 被外部监控端点调用则为数据竞争。

---

### [LOW] R26 — AnyTLS `write_strand_` 声明但从未使用（死代码）

**位置**: `include/prism/stealth/anytls/session.hpp:120`

strand 已初始化但从未被任何写入操作引用，形成误导性死代码。

---

### [LOW] R27 — DNS 压缩指针偏移未校验 16383 上限

**位置**: `src/prism/resolve/dns/detail/format.cpp:127`

DNS 压缩指针使用 14 位偏移（最大 16383）。超过 16383 的偏移会破坏指针类型位。对超过 16KB 的 DNS 响应会产生错误压缩指针。

---

## 统计（含第二轮）

| 严重程度 | 第一轮 | 第二轮 | 合计 |
|----------|--------|--------|------|
| CRITICAL | 6 | 3 | **9** |
| HIGH | 15 | 4 | **19** |
| MEDIUM | 23 | 11 | **34** |
| LOW | 5 | 9 | **14** |
| **合计** | **49** | **27** | **76** |

**建议优先处理顺序**（更新）:
1. **CRITICAL 安全**: S1 (random_device) → S2 (nonce 溢出) → S3 (seal 序列号) → S4 (cert.pem)
2. **CRITICAL 泄漏**: R1 (SSL_CTX ALPN) → R2 (AnyTLS 泄漏) → R3 (TrustTunnel 泄漏)
3. **CRITICAL CI**: B1 (continue-on-error) → B2 (依赖无 SHA256)
4. **HIGH 并发/崩溃**: R4 (strand) → R5 (recv_loop 异常) → R6 (h2_bridge 异常) → R7 (连接池无上限) → C1 (yamux 自旋)
5. **HIGH 性能**: P1 (隧道缓冲) → P2 (mux buffer) → P3 (-O1 编译)
6. **HIGH 功能**: F1-F4 → R11-R13 (协议边界)
7. **MEDIUM 质量轮**: R9 (配置校验) → R14 (Restls 常量时间) → Q1-Q9 → T2-T3
