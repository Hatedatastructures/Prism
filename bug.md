# Prism 问题清单（第七轮全面审计）

> 按模块和严重程度排序。CRITICAL = 生产安全风险；HIGH = 功能/性能显著影响；MEDIUM = 代码质量/可维护性；LOW = 改进建议。
>
> **审计日期**: 2026/05/25
> **审计范围**: 全项目深度审计（5 个并行 agent 覆盖所有模块）
> **审计版本**: main 分支最新
> **对比基准**: 第六轮审计（165 项）

---

## 已修复项（第三轮→第四轮验证通过）

| ID | 问题 | 修复确认 |
|----|------|----------|
| S1 | SS2022 server salt 使用 `std::random_device` | `RAND_bytes()` 已使用 (`conn.cpp:244`) |
| S2 | AEAD nonce 递增无溢出检测 | `increment_nonce()` 检测溢出返回 false (`aead.hpp:204`) |
| B1 | CI `continue-on-error: true` | 已移除 |
| B2 | 依赖无 `URL_HASH` | 全部 6 个依赖已添加 |
| F3 | 优雅关机缺失 | `main.cpp` 已实现 signal_set + graceful shutdown |
| R19-旧 | `preview.cpp` 抛 `std::runtime_error` | — （`snapshot.hpp` 仍抛异常，见 X1） |
| — | Restls/AnyTLS/TrustTunnel TODO 桩 | 三个方案均已完整实现，仅 ECH 和 h2mux sing-mux 各 1 个 TODO |

---

## 1. 安全 (Security)

### [CRITICAL] S2 — AEAD nonce 溢出时密文已生成

**位置**: `src/prism/crypto/aead.cpp:104-121`

`increment_nonce()` 现在正确检测溢出，但错误码在 `EVP_AEAD_CTX_seal()` **成功**之后才返回。密文已写入 `out` 缓冲区但调用方收到的返回值是 `crypto_error`，导致：
- 调用方可能重试加密操作，但密文已产生且 nonce 已处于错误状态
- 若调用方忽略错误码，nonce 复用的密文已被发送

```cpp
// seal() 成功产生密文后才检查 nonce 溢出
const auto result = EVP_AEAD_CTX_seal(...);  // 密文已写入 out
if (!result) return fault::code::crypto_error;
if (!increment_nonce())                       // 溢出才报错
    return fault::code::crypto_error;         // 密文已产出
```

**修复**: 在 `seal()` 调用前检查 nonce 是否即将溢出，而非事后检查。

---

### [CRITICAL] S4 — 仓库包含已跟踪的 TLS 私钥和证书

**位置**: `cert.pem`、`key.pem`（项目根目录）

两个文件存在且已被 git 跟踪，`.gitignore` 未排除 `*.pem`。使用默认配置部署的用户将使用公开的密钥材料。

**修复**: `git rm --cached cert.pem key.pem`，`.gitignore` 添加 `*.pem`，若曾在公开仓库暴露则需轮换密钥。

---

### [CRITICAL] S5 — `open_output_size()` 无符号下溢

**位置**: `include/prism/crypto/aead.hpp:194-198`

```cpp
static constexpr auto open_output_size(std::size_t ciphertext_len) noexcept
    -> std::size_t
{
    return ciphertext_len - tag_length(); // 若 ciphertext_len < 16 则下溢
}
```

`ciphertext_len < tag_length()` 时产生 `size_t` 下溢（~18446744073709551600），调用方基于此分配内存将导致 OOM。

**修复**: 添加 `if (ciphertext_len < tag_length()) return 0;` 前置检查。

---

### [CRITICAL] S6 — TrustTunnel 修改共享 SSL_CTX 的 ALPN

**位置**: `src/prism/stealth/trusttunnel/scheme.cpp:136-137`

```cpp
SSL_CTX_set_alpn_protos(ctx.session->server_ctx.ssl_ctx->native_handle(),
                        reinterpret_cast<const uint8_t *>("\x2h2"), 3);
```

`server_ctx.ssl_ctx` 在 `worker/tls.cpp:82-86` 创建，被同 worker 的所有会话共享。每次 TrustTunnel 握手将共享 `SSL_CTX` 的 ALPN 覆盖为 `h2`-only。后续 native TLS / AnyTLS 握手将使用 h2-only ALPN，导致非 h2 协议协商失败。

**修复**: 使用 per-SSL 的 `SSL_set_alpn_protos()` 而非修改共享 `SSL_CTX`。

---

### [CRITICAL] S7 — Restls `async_read_record` 无条件返回错误

**位置**: `src/prism/stealth/restls/transport.cpp:131-135`

```cpp
const auto *raw = reinterpret_cast<const std::uint8_t *>(header.data());
{
    ec = std::make_error_code(std::errc::protocol_error);
    co_return std::nullopt;
}
```

成功读取 TLS 记录头后，无条件设置 `protocol_error` 并返回。所有 Restls 读取操作均失败，协议完全不工作。这是一段残留的调试/占位代码块——`raw` 被声明但后续 `record_length` 解析代码不可达。

**修复**: 删除无条件的错误返回块，恢复 `record_length` 解析逻辑。

---

### [CRITICAL] S7.1 — BLAKE3 keyed_hash 无 key 长度校验导致 OOB 读

**位置**: `src/prism/crypto/blake3.cpp:40, 48`

```cpp
auto keyed_hasher(std::span<const std::byte> key) -> blake3_hasher
{
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);  // 应为 blake3_hasher_init_keyed
    // 无 key.size() == 32 校验，blake3_hasher_update 直接读取
    blake3_hasher_update(&hasher, key.data(), key.size());
    ...
}
```

`keyed_hasher()` 和 `keyed_hash()` 不验证 key 长度是否为 BLAKE3_KEY_LEN (32)。若传入非 32 字节 key：
- `blake3_hasher_init_keyed()` 内部读取固定 32 字节 key，短 key 导致 OOB 读
- 实际上 `keyed_hasher` 调用了 `blake3_hasher_init` 而非 `blake3_hasher_init_keyed`，keyed 模式完全失效

**修复**: 校验 `key.size() == 32`，使用正确的 `blake3_hasher_init_keyed()` 初始化。

---

### [CRITICAL] S7.2 — smux/yamux handle_syn 不检查 stream_id 冲突

**位置**: `src/prism/multiplex/smux/craft.cpp:182-189`

```cpp
auto handle_syn(std::uint32_t stream_id, ...) {
    streams_[stream_id] = stream_entry{...};  // 直接覆盖
}
```

`handle_syn()` 不检查 `stream_id` 是否已存在于 `streams_` map。恶意客户端可重用已有 stream_id 的 SYN 帧劫持现有流，覆盖其 buffer 和回调。yamux 有相同问题。

**修复**: 添加 stream_id 冲突检查，已存在时发送 RST 拒绝。

---

### [CRITICAL] S7.3 — configuration.json 在 git 中包含明文凭据

**位置**: `src/configuration.json`

配置文件包含明文用户密码（如 Shadowsocks PSK、Trojan UUID、AnyTLS 密码），已被 git 跟踪。任何有仓库访问权限的人都能获取生产凭据。

**修复**: `git rm --cached src/configuration.json`，`.gitignore` 添加 `configuration.json`，提供 `configuration.example.json`。

---

### [HIGH] S7.4 — Restls transport 多个未实现功能

**位置**: `src/prism/stealth/restls/transport.cpp`

- `tls13_` 和 `tls_version_` 成员在构造时存储但从未使用
- `flush_pending()` 声明但无实现（空方法体），写缓冲策略不完整
- `cmd_close` 帧类型未处理，对端关闭连接时无清理逻辑
- `async_write_record()` 在写入时可能阻塞，若 `pending_write_` 非空时新写入将数据丢失

---

### [HIGH] S15 — AnyTLS write_strand_ 声明但未使用 → 帧交错风险

**位置**: `src/prism/stealth/anytls/session.cpp:26`

`write_strand_` 已初始化但从未被任何写入操作引用。所有写入操作（`write_frame`、`write_psh`、`write_fin`、`write_synack`）直接调用 `transport_->async_write_some()`。当多个 stream 并发写入时，帧可能在 TLS 层交错，导致对端解析失败。

**修复**: 所有写入操作必须通过 `write_strand_` 序列化。

---

### [HIGH] S16 — SS2022 连接层 deadline timer 未取消

**位置**: `src/prism/protocol/socks5/conn.cpp:193-198`

认证成功后未取消 deadline timer。timer 在超时时仍触发，取消正在进行的读写操作，导致已认证的连接被意外断开。

**修复**: 在认证成功路径（line 198 后）调用 `timer.cancel()`。

---

### [HIGH] S8 — Reality seal null transport 时返回悬挂 executor

**位置**: `src/prism/stealth/reality/seal.cpp:25-28`

```cpp
if (!transport_)
{
    return net::io_context{}.get_executor(); // 临时 io_context 立即销毁
}
```

返回的 executor 指向已销毁的临时 `io_context`，任何后续 `co_await` 操作是未定义行为。

**修复**: 返回错误码或抛出异常，不返回悬挂引用。

---

### [HIGH] S9 — Reality handshake `release()` + `move` 模式泄漏 socket

**位置**: `src/prism/stealth/reality/handshake.cpp:134, 172`

```cpp
auto *dest_socket_raw = dest_conn.release();
// ... co_await async_write ...
auto dest_trans = transport::make_reliable(std::move(*dest_socket_raw));
```

`release()` 将 socket 从 RAII 包装器取出为裸指针。若 `async_write` 和 `make_reliable` 之间发生异常或提前返回，裸指针永远不会被 `delete`。`fetch_dest_certificate()` 中的 `socket_raw` 有同样问题（line 172）。

**修复**: 使用 `unique_ptr` 或在 `release()` 后立即 `make_reliable`，中间代码出错时手动 delete。

---

### [HIGH] S10 — TLS 记录长度无上限校验

**位置**: `src/prism/stealth/reality/seal.cpp:120-123`

```cpp
const auto record_len = (static_cast<std::size_t>(raw[3]) << 8) | raw[4];
record_body_buf_.resize(record_len); // 最大 65535 字节
```

TLS 1.3 (RFC 8446 §5.2) 限制记录载荷为 16384 字节。接受最大 65535 字节允许恶意对端触发大内存分配。

**修复**: 添加 `if (record_len > 16384 + AEAD_TAG_LEN) return fault::code::record_too_large;`

---

### [HIGH] S11 — TrustTunnel Basic Auth 非常量时间比较

**位置**: `src/prism/stealth/trusttunnel/scheme.cpp:96`

```cpp
if (encoded_str == b64_credentials)
```

`std::string_view::operator==` 是短路比较。攻击者可通过时序测量逐字节推断认证凭据。

**修复**: 使用 `CRYPTO_memcmp()` 进行常量时间比较。

---

### [HIGH] S12 — Reality auth 使用非常量时间字符串比较

**位置**: `src/prism/stealth/reality/util/auth.cpp:14-50`

- `match_server_name` 使用 `name == sni`（短路比较）
- `match_short_id` 使用 `std::equal`（短路比较）

攻击者通过时序测量可推断配置的 server_name 列表和 short_id 值。

**修复**: 使用 `CRYPTO_memcmp()` 进行常量时间比较。

---

### [HIGH] S13 — Restls auth_mac 已修复为 CRYPTO_memcmp

**位置**: `src/prism/stealth/restls/transport.cpp:218`

已确认修复。原先使用 `volatile` 手动比较，现已替换为 `CRYPTO_memcmp()`。

---

### [MEDIUM] S14 — 连接池 raw `new tcp::socket` 存在泄漏路径

**位置**: `src/prism/connect/pool/pool.cpp:189`

```cpp
auto *sock = new tcp::socket(ioc_);
```

裸指针在 `async_connect` 设置阶段若抛异常，socket 将泄漏。

**修复**: 使用 `unique_ptr` 保护，仅在成功时 `release()`。

---

### [MEDIUM] S15 — 连接池清理协程捕获裸 `this`

**位置**: `src/prism/connect/pool/pool.cpp:332`

```cpp
auto clean_function = [this, flag]() -> net::awaitable<void>
```

`shutdown_flag_` 信号机制存在竞态窗口：flag 检查与下一次 `co_await` 之间若 `connection_pool` 被销毁，协程访问悬挂指针。

**修复**: 捕获 `shared_from_this()` 或使用 `weak_ptr`。

---

### [MEDIUM] S16 — Trojan/VLESS UDP associate 使用 raw `new traffic_context`

**位置**: `src/prism/protocol/trojan/conn.cpp:320`、`src/prism/protocol/vless/conn.cpp:306`

```cpp
auto *tc = traffic_ ? new traffic_context{traffic_, proto_} : nullptr;
```

协程取消时，`traffic_context` 不会被 `delete`，导致内存泄漏。

**修复**: 使用 `unique_ptr` 或 PMR 分配，协程退出时确保释放。

---

### [MEDIUM] S17 — 连接池 `const_cast` UB

**位置**: `src/prism/connect/pool/health.cpp`（6 处）

`const_cast` 移除 socket 引用的 const 限定符以调用 `native_handle()`、`available()` 等方法。若底层 socket 确实是 const 对象则写入操作为 UB。

**修复**: 将 `healthy()` 接口改为接受非 const 引用，或使用 `mutable` 成员。

---

### [MEDIUM] S18 — 连接池无最大并发连接数限制

**位置**: `src/prism/connect/pool/pool.cpp:183-270`

`async_acquire()` 在缓存为空时总是创建新 TCP 连接，无上限。高负载下可打开无限 TCP socket，导致文件描述符耗尽（EMFILE/WSAEMFILE）。`max_cache_per_endpoint` 仅限制空闲缓存，不限制已借出的连接数。

**修复**: 添加 `max_total_per_endpoint` 或全局 `max_connections` 限制。

---

### [LOW] S19 — ShadowTLS 多用户匹配时序泄露

**位置**: `src/prism/stealth/shadowtls/handshake.cpp:382-393`

顺序遍历用户列表并在首次匹配时返回。单次 HMAC 比较是常量时间，但迭代模式可泄露用户列表大小和匹配位置。

---

### [LOW] S20 — `account::try_acquire` relaxed 排序允许连接数瞬时溢出

**位置**: `include/prism/account/directory.hpp:197-211`

多 worker 可同时读到相同计数并全部 CAS 成功，瞬时超过 `max_connections`。溢出幅度最大为 worker 线程数。已文档化为近似限制。

---

### [LOW] S21 — `connection_pool::stat_*` 字段为非原子 `size_t`

**位置**: `include/prism/connect/pool/pool.hpp:328-334`

当前因单线程使用而安全，但若 `stats()` 被外部监控端点调用则为数据竞争。

---

## 2. 协程纯度 (Coroutine Purity)

### ~~[CRITICAL] C1 — Yamux `send_data` CAS 自旋等待~~ → **已验证为误报**

**位置**: `src/prism/multiplex/yamux/craft.cpp:735-792`

**第四轮审计修正**: 逐行审查确认，yamux `send_data` 在窗口耗尽时通过 `co_await signal->async_wait()`（line 766）正确挂起协程。内部 CAS 循环（lines 748-755）在 `old_val < payload_size` 时立即退出外层循环，进入 timer await。窗口恢复时 `handle_window_update` 取消 timer 唤醒协程。**非忙等**，设计正确。

---

### [MEDIUM] C2 — `encrypted::close()` 行为确认

**位置**: `include/prism/transport/encrypted.hpp:139-143`

`close()` 明确跳过 `SSL_shutdown`，直接关闭底层 socket。这是有意设计（best-effort 快速拆解），非 bug。

---

### [MEDIUM] C3 — Listener 指数退避 delay 永不重置

**位置**: `src/prism/instance/front/listener.cpp:119`

```cpp
static thread_local std::chrono::milliseconds delay = min_delay;
```

`delay` 是 `thread_local static` 变量，一旦因 EMFILE/ENOMEM 退避到最大值，后续正常 accept 也不再恢复到 `min_delay`。文件描述符耗尽恢复后，accept 循环仍以 5.12s 间隔运行。

**修复**: accept 成功后重置 `delay = min_delay`。

---

## 3. 传输层 (Transport)

### [HIGH] X1 — `snapshot::executor()` 热路径抛异常

**位置**: `include/prism/transport/snapshot.hpp:79-83`

```cpp
throw std::runtime_error("snapshot::executor() called on null inner");
```

传输层热路径函数。项目约定热路径使用错误码、启动/致命错误才用异常。

**修复**: 改为返回默认 executor 或错误码。

---

### [HIGH] X2 — `snapshot` 捕获缓冲区无大小限制

**位置**: `include/prism/transport/snapshot.hpp`

`captured_` 随着读取不断增长无上限。长连接上读取大量数据时，captured buffer 无限增长。

**修复**: 添加 `max_capture_size` 参数或在 `stop_capture()` 后停止累积。

---

### [MEDIUM] X3 — `handshake_result::detected` 无默认初始化

**位置**: `include/prism/stealth/scheme.hpp:109`

```cpp
protocol::protocol_type detected;  // 未初始化
```

`protocol_type` 是 `enum class : uint8_t`，未初始化时值为未定义。若 scheme 握手成功但忘记设置 `detected` 字段，session 层将基于随机值进行协议分发。

**修复**: 添加默认初始化 `protocol_type detected = protocol_type::unknown;`

---

## 4. 性能 (Performance)

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

### [HIGH] P2.1 — smux/yamux send_loop 每帧堆分配

**位置**: `src/prism/multiplex/smux/craft.cpp`、`src/prism/multiplex/yamux/craft.cpp`

`send_loop()` 每次发送数据帧时分配临时缓冲区用于帧头 + 载荷合并。在高吞吐场景下（大量 mux stream），每帧的堆分配成为显著瓶颈。

**修复**: 使用预分配的 thread-local 缓冲区或 scatter-gather write。

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

### [HIGH] P4 — SS2022 `send_chunk` 每次写入堆分配合并向量

**位置**: `src/prism/protocol/shadowsocks/conn.cpp:559`

```cpp
memory::vector<std::byte> chunk_combined(chunk_total, memory::current_resource());
std::memcpy(chunk_combined.data(), len_enc.data(), len_enc.size());
std::memcpy(chunk_combined.data() + len_enc.size(), payload_enc_buf_.data(), payload_enc_buf_.size());
co_await transport::async_write(*next_layer_, chunk_combined, ec);
```

每次发送数据块都分配临时向量合并加密长度块和载荷。这是 SS2022 热路径上的每包堆分配。

**修复**: 使用 scatter-gather write（两次 `async_write_some` 或 `writev`），或复用预分配的合并缓冲区。

---

### [MEDIUM] P5 — transmission 基类默认实现引入额外协程帧

**位置**: `include/prism/transport/transmission.hpp:127-158`

`async_read_some` 和 `async_write_some` 的 completion-handler 重载通过 `co_spawn` + `detached` 桥接。中间装饰器（`snapshot`、`encrypted`）未覆写这些方法，SSL 操作会多一层协程帧分配。

**修复**: 在 `encrypted` 和 `snapshot` 中覆写 completion-handler 风格方法。

---

### [MEDIUM] P6 — 全局 `synchronized_pool` 在单线程 worker 上产生不必要锁开销

**位置**: `include/prism/memory/pool.hpp:100-103`

`enable_global_pooling()` 使所有默认构造的 PMR 容器使用带锁的 `synchronized_pool`。每个 worker 是单线程事件循环，应使用 `thread_local_pool()` 避免锁竞争。

**修复**: 热路径容器显式使用 `thread_local_pool()`，或 worker 启动时切换默认资源。

---

### [MEDIUM] P7 — 无 scatter-gather (writev) 支持

**位置**: `include/prism/transport/transmission.hpp`

mux 帧头 + 载荷分两次 `async_write_some` 系统调用。合并为单次 `writev` 可减少 syscall 开销。

**修复**: 在 transport 层添加 `async_writev` 接口。

---

### [LOW] P8 — `frame_arena` 栈缓冲区仅 512 字节

**位置**: `include/prism/memory/pool.hpp:222`

帧解析、地址解析、临时字符串构造常超过 512 字节，频繁回退到上游 `thread_local_pool`。考虑提升至 1024 或 2048 字节。

---

### [LOW] P9 — 隧道数据路径包含过多的 trace::debug 调用

**位置**: `src/prism/connect/tunnel/tunnel.cpp:44-82`

`forward_data` lambda 在读写循环内包含多个 `trace::debug()` 调用。即使日志级别禁用，字符串格式化仍可能产生开销。

**修复**: 添加 `if (trace::is_debug_enabled())` 门卫或移除数据路径日志。

---

## 5. 功能缺口 (Functional Gaps)

### [CRITICAL] F1 — Restls 传输层死代码导致协议完全不可用

**位置**: `src/prism/stealth/restls/transport.cpp:138-142`

见 S7。Restls 握手虽然已完整实现，但 `async_read_record()` 中的无条件错误返回块导致所有后续数据读取失败。协议处于"握手成功但无法传输数据"状态。

---

### [HIGH] F2 — AnyTLS 后续 stream 静默丢弃

**位置**: `src/prism/stealth/anytls/scheme.cpp:248-250`（原始 TODO 位置）

第一个流之后的 `on_new_stream` 回调需确认是否已完整实现 SOCKS 地址解析 + dial + tunnel。

---

### [HIGH] F3 — 正向代理配置已解析但从未使用

**位置**: `src/prism/connect/dial/dial.cpp`（`async_forward` 仅直连）、`router.cpp`（`positive_host_/positive_port_` 存储但未使用）

`instance::config::positive` 从 JSON 反序列化，`router::set_positive_endpoint()` 存储，但 `async_forward()` 从不使用。存储的字段是死代码。

**修复**: 在 `dial()` 或 `async_forward()` 中实现 HTTP CONNECT 正向代理路径。

---

### [HIGH] F4 — h2mux sing-mux DATA 帧静默丢弃

**位置**: `src/prism/multiplex/h2mux/craft.cpp:474-479`

```cpp
if (const auto pit = self->h2_pending_.find(id); pit != self->h2_pending_.end())
{
    // TODO: 实现 StreamRequest 解析
    return 0;
}
```

sing-mux 模式下首个 DATA 帧携带 StreamRequest，当前直接丢弃返回 0。TrustTunnel 通过 h2mux 发送数据时如果使用 sing-mux 模式，连接建立后将无法传输数据。

**修复**: 实现 StreamRequest 解析，提取目标地址并建立 duct。

---

### [HIGH] F5 — 无空闲超时（idle timeout）

**位置**: `src/prism/instance/session/session.cpp`

握手阶段已有 30 秒 deadline（`session.cpp:147-194`，使用 `||` operator），但 recognition 完成后、客户端不发送请求数据时无超时。恶意客户端完成握手后保持沉默，无限占用连接资源。

**修复**: 在 session 分发到协议处理器后设置 idle timeout（建议 300s）。

---

### [MEDIUM] F6 — ECH HPKE 解密为空实现

**位置**: `src/prism/stealth/ech/util/decrypt.cpp:39`

```cpp
// TODO: 实现 HPKE 解密
return fault::code::not_supported;
```

格式检查和版本校验已实现，但 HPKE 解密核心返回 `not_supported`。发送 ECH 的客户端将始终检测失败。

**修复**: 实现 HPKE SetupBaseS + AEAD Open。

---

### [MEDIUM] F7 — SOCKS5 BIND 命令未实现

**位置**: `include/prism/protocol/socks5/config.hpp:35`（`enable_bind` 字段存在）、`conn.cpp:44`（始终返回 `command_not_supported`）

配置字段已解析但功能未实现。

---

### [MEDIUM] F8 — WebSocket 传输零实现

**位置**: 整个代码库无 WebSocket 相关代码

路线图 Phase C.5，完全未开始。

---

### [MEDIUM] F9 — HTTP/Shadowsocks 协议未调用 `set_traffic()`

**位置**:
- `src/prism/protocol/http/process.cpp` — 无 `set_traffic` 调用
- `src/prism/protocol/shadowsocks/process.cpp` — 无 `set_traffic` 调用

Trojan、VLESS、SOCKS5 均调用 `agent->set_traffic()`，HTTP 和 Shadowsocks 遗漏，导致这两个协议的流量统计缺失。

---

### [MEDIUM] F10 — HTTP forward 泄漏 Proxy-Authorization header 到上游

**位置**: `src/prism/protocol/http/conn.cpp:70-91`

`forward()` 方法将请求行之后的原始 headers 全部转发到上游服务器，包含 `Proxy-Authorization` 头。该头包含客户端认证凭据（Base64 编码的 user:password），不应泄漏到外部服务器。

**修复**: 在转发前过滤 `Proxy-Authorization` 头。

---

### [HIGH] F11 — TrustTunnel 返回 detected=tls 导致 executor 误判

**位置**: `src/prism/stealth/trusttunnel/scheme.cpp:255`

```cpp
result.detected = protocol::protocol_type::tls;
co_return result;
```

TrustTunnel 握手成功后返回 `detected=tls`。`scheme_executor` 将此解释为"此 TLS 连接不匹配任何方案"并传递给 session。session 的 `diversion()` 将 `tls` 类型分发到 native TLS 处理器，尝试再次解析 TLS。应返回特殊值（如 `tls_camouflage`）或直接在 scheme 内完成所有处理。

**修复**: 添加专用的 `protocol_type::stealth_done` 或在 result 中添加标志表示 scheme 已完全处理连接。

---

### [HIGH] F12 — TrustTunnel 未发送 MAX_CONCURRENT_STREAMS 设置

**位置**: `src/prism/multiplex/h2mux/craft.cpp`

nghttp2 服务端未发送 SETTINGS MAX_CONCURRENT_STREAMS。客户端可无限并发 open stream 而不受限，恶意客户端可通过大量并发 CONNECT 耗尽服务器资源。

**修复**: 在 h2mux craft 初始化时设置 `nghttp2_option_set_max_concurrent_streams()`。

---

### [HIGH] F13 — TrustTunnel 先发 200 OK 再建立上游连接

**位置**: `src/prism/stealth/trusttunnel/scheme.cpp:248-250`

```cpp
(void)craft->respond_connect(first.stream_id, 200);  // 先回复 200
co_await craft->send_pending();
co_await craft->activate_stream(first.stream_id);     // 再激活
```

TrustTunnel 对第一个 CONNECT 先回复 200 OK，然后才建立上游连接。若上游不可达，客户端已认为连接建立成功并发送数据，导致数据丢失。后续 stream 通过 `on_connect` 回调处理，可能也有同样问题。

**修复**: 先建立上游连接，成功后再回复 200 OK。

---

### [HIGH] F14 — traffic_state::register_instance 缺少 CAS 保护

**位置**: `src/prism/stats/traffic.cpp:118-148`

```cpp
void traffic_state::register_instance(traffic_state *s) noexcept
{
    auto *next = new registry_vector();
    *next = *old;
    next->push_back(s);
    store_registry(next);  // store 是 atomic，但 read-copy 整体非原子
}
```

COW 模式下 read 和 copy 之间无同步。若两个 worker 同时 register，都读到相同 old，各自 push_back 后 store，后一个覆盖前一个的添加，导致 registry 丢失条目。

**修复**: 使用 mutex 保护 read-copy-store 序列，或使用 `compare_exchange` 循环。

---

### [HIGH] F15 — HTTP 模块不传递 auth lease 给 tunnel

**位置**: `src/prism/protocol/http/process.cpp`

HTTP 代理认证后未将 auth 信息传递给 tunnel forward。若上游需要认证，HTTP 模块无法传递凭据。同时，认证成功后的连接计费（`on_connect`）在 tunnel 结束后未回滚 `on_disconnect`，导致连接计数不一致。

**修复**: 在 forward context 中携带 auth 信息，确保 connect/disconnect 配对调用。

---

## 6. 生命周期安全 (Lifetime Safety)

### [CRITICAL] L1.1 — AnyTLS 首个 stream SOCKS 解析失败未关闭 session

**位置**: `src/prism/stealth/anytls/scheme.cpp:361-365`

```cpp
auto [parse_ec, target] = parse_socks_target(preread_span, ctx.session->frame_arena.get());
if (fault::failed(parse_ec))
{
    trace::warn("{} failed to parse first stream SOCKS target: {}", tag, fault::describe(parse_ec));
    result.error = parse_ec;
    co_return result;  // ← 未调用 session->close()
}
```

`wait_first_stream` 失败路径（line 342）正确调用了 `session->close()`，但 SOCKS 解析失败路径缺少该调用。`session->start()` 已启动 detached `recv_loop`，持有 session shared_ptr。不调用 `close()` 将导致 `recv_loop` 持续运行，session 永不释放。

**修复**: 在 `co_return` 前添加 `session->close()`。

---

### [HIGH] L1.2 — TrustTunnel no-CONNECT 路径双重所有权

**位置**: `src/prism/stealth/trusttunnel/scheme.cpp:222-229`

```cpp
auto first_opt = co_await craft->wait_first_connect();
if (!first_opt)
{
    result.detected = protocol::protocol_type::tls;
    result.transport = std::move(encrypted_trans);  // ← 移交给 result
    co_return result;
    // craft 仍持有 encrypted_trans 的 shared_ptr，frame_loop 继续运行
}
```

`craft` 在 `start()` 时启动了 `frame_loop`，持有 `encrypted_trans` shared_ptr。当无 CONNECT 请求时，`encrypted_trans` 被移交给 `result.transport` 返回给 session。但 `craft` 的 detached `frame_loop` 仍在运行并持有同一 transport 的引用，导致两个所有者同时读写同一 TLS 连接。

**修复**: 无 CONNECT 时先 `craft->stop()` 停止 frame_loop，再移交 transport。

---

### [HIGH] L1.3 — TrustTunnel 认证失败未停止 craft

**位置**: `src/prism/stealth/trusttunnel/scheme.cpp:237-243`

```cpp
if (cfg.users.empty() || !verify_basic_auth(auth_view, cfg.users))
{
    craft->respond_connect(first.stream_id, 407);
    co_await craft->send_pending();
    result.error = fault::code::auth_failed;
    co_return result;  // ← craft->frame_loop 仍在运行
}
```

认证失败后 `co_return`，但 `craft` 的 `frame_loop` 未停止。detached 协程继续从 `encrypted_trans` 读取数据。需确认 `craft` 析构时是否自动停止 `frame_loop`。

**修复**: 认证失败路径添加 `craft->stop()` 或确保析构函数停止 frame_loop。

---

### [CRITICAL] L2 — ShadowTLS/Restls 握手 detached 协程捕获局部引用

**位置**: `src/prism/stealth/shadowtls/handshake.cpp:550`、`src/prism/stealth/restls/handshake.cpp:346`

```cpp
auto relay_done = std::make_shared<std::atomic<bool>>(false);
auto cancel_signal = std::make_shared<net::cancellation_signal>();

auto client_relay = [&client_sock, &backend_sock, tls13,
                     &client_finished, relay_done]()
    -> net::awaitable<void> { ... };

net::co_spawn(executor, std::move(client_relay),
              net::bind_cancellation_slot(cancel_signal->slot(), net::detached));
```

lambda 捕获局部变量 `client_sock`、`backend_sock`、`client_finished` 的**引用**，以 `net::detached` 启动。主协程在 500ms 超时后通过 `relay_done` 标志检查 relay 是否完成，但主协程返回后局部变量被销毁，detached relay 协程的引用变为悬挂。当前通过 `relay_done` 标志同步，但该同步不可靠——detached 协程可能在主协程返回后才被调度。

**修复**: lambda 按值（shared_ptr）捕获所有需要的对象，而非引用捕获。

---

### [CRITICAL] L2.A — AnyTLS close() 调用已释放的 executor 导致 null 解引用

**位置**: `src/prism/stealth/anytls/mux/transport.hpp:112-130`

```cpp
void close() override
{
    if (auto ch = channel_.lock())
    {
        ch->close();
    }
    channel_.reset();
    // session_->executor() 在 channel_ 重置后可能返回无效 executor
    net::post(session_->executor(), [self = session_]() { ... });
}
```

`close()` 先 `channel_.reset()` 清空 weak_ptr，然后通过 `session_->executor()` 获取执行器 post 任务。若 session 在此过程中析构，`executor()` 返回无效引用。更严重的是，`close()` 可能从非 io_context 线程调用，`channel_.reset()` 与 recv_loop 的 channel 访问无同步保护。

**修复**: 先保存 executor，再 reset channel；添加 strand 保护 close() 路径。

---

### [CRITICAL] L2.B — AnyTLS preread 数据同时发送到 first_stream_preread_ 和 channel

**位置**: `src/prism/stealth/anytls/session.cpp:223-230`

```cpp
// 数据同时写入两个地方：
first_stream_preread_ = data;       // wait_first_stream 返回
channel->send(data);                // get_stream_channel 也会收到
```

第一个 stream 的 preread 数据被同时放入 `first_stream_preread_` 和 stream channel。`scheme.cpp` 中通过 `wait_first_stream()` 读取 `first_stream_preread_`，然后通过 `get_stream_channel()` 获取的 transport 也会再次收到相同数据。数据被重复处理，可能导致 SOCKS 解析混乱。

**修复**: 仅发送到 `first_stream_preread_`，或仅通过 channel 发送，不双重投递。

---

### [CRITICAL] L2.C — TrustTunnel/h2mux send_pending() 并发帧交错

**位置**: `src/prism/multiplex/h2mux/craft.cpp`

`send_pending()` 可被多个协程并发调用（`respond_connect` + `activate_stream` 在 `scheme.cpp:248-250` 连续调用且都触发 send_pending）。nghttp2 session 不是线程安全的，并发提交帧可能导致帧交错和数据损坏。

**修复**: 使用 strand 序列化所有 nghttp2 操作，或在单协程中串行化 send_pending 调用。

---

### [CRITICAL] L2.D — Restls write blocking 返回假成功 + 无界 send_buf_

**位置**: `src/prism/stealth/restls/transport.cpp:273-277`

```cpp
if (write_pending_)
{
    send_buf_.insert(send_buf_.end(), data.begin(), data.end());
    co_return data.size();  // 假装成功，数据仅缓冲
}
```

`write_pending_` 时数据被追加到 `send_buf_` 并返回 `data.size()` 声称成功。但 `send_buf_` 无大小上限，恶意客户端可通过触发 write blocking 使缓冲区无限增长。此外，`async_read_some` 中解除写阻塞时（line 99-108）仅 flush 一次 send_buf_，如果新写入恰好又被 blocking，数据静默丢失。

**修复**: 添加 `max_pending_write_size` 限制，超出时返回错误；确保 flush 循环直到 write_pending_ 为 false。

---

### [CRITICAL] L2.E — worker 从未调用 unregister_instance → stats registry 悬挂指针

**位置**: `src/prism/stats/traffic.cpp:110-140`

```cpp
void traffic_state::register_instance(traffic_state *s) noexcept
{
    // 添加到全局 registry
    next->push_back(s);
    store_registry(next);
}
```

`register_instance` 在 worker 启动时被调用，但 `unregister_instance` 从未在任何地方被调用。worker 销毁时，其 `traffic_state` 对象被析构，但全局 registry 仍持有指向已析构对象的裸指针。`broadcast_*` 方法遍历 registry 时触发 use-after-free。

**修复**: 在 worker 析构时调用 `unregister_instance()`。

---

### [HIGH] L2.1 — DNS upstream SNI arg 悬挂引用

**位置**: `src/prism/resolve/dns/upstream.cpp:55-57`

```cpp
SSL_CTX_set_tlsext_servername_arg(
    ctx->native_handle(),
    const_cast<char *>(server.hostname.c_str()));  // server 来自 servers_ 成员
```

`server` 引用来自 `servers_` 向量。`set_servers()` 替换 `servers_` 时（line 67-70），已有 SSL context 中的 SNI arg 指针指向旧 vector 中的 string，变为悬挂。DNS 服务器热更新时触发。

**修复**: 在 `set_servers()` 中不替换旧 vector 或使用 `shared_ptr<string>` 存储 hostname。

---

### [MEDIUM] L2.2 — Worker stop() 非优雅关机

**位置**: `src/prism/instance/worker/worker.cpp:64-67`

```cpp
void worker::stop()
{
    ioc_.stop();  // 立即中断 run()，不等待挂起的协程完成
}
```

`io_context::stop()` 立即返回，所有挂起的 `co_await` 被取消。正在处理中的隧道数据可能丢失。应使用 `io_context::poll()` 排空或设置 drain 期限。

**修复**: 使用 `post(ioc_, [] { ioc_.stop(); })` 排空当前批次，或添加 drain 期限。

---

### [MEDIUM] L2.3 — TLS 证书/私钥不匹配无法检测

**位置**: `src/prism/instance/worker/tls.cpp:8-29`

`configure()` 分别加载证书和私钥，未调用 `SSL_CTX_check_private_key()` 验证匹配。不匹配时运行时 TLS 握手失败，但启动时不会报错。也未检查证书过期时间。

**修复**: 加载后调用 `SSL_CTX_check_private_key(native)` 并检查返回值。可选添加证书有效期预警。

---

### [MEDIUM] L3 — DNS 查询 detached 任务可能比 resolver 存活更久

**位置**: `src/prism/resolve/dns/upstream.cpp:826-858`

`first/fastest` 模式下，DNS 查询通过 `net::co_spawn(ioc_, task, net::detached)` 启动，捕获裸 `this`（upstream 对象）。当前因单线程 io_context 在 worker 之前停止而安全，但架构上脆弱。

---

### [MEDIUM] L4 — Stats COW registry 有意内存泄漏

**位置**: `src/prism/stats/traffic.cpp:118-148`

```cpp
void traffic_state::register_instance(traffic_state *s) noexcept
{
    auto *next = new registry_vector();  // 每次 register/unregister 都 new
    *next = *old;
    next->push_back(s);
    store_registry(next);
    // old 从不 delete
}
```

COW 模式下旧的 registry vector 从不释放。每次 worker 创建/销毁时泄漏一个 `registry_vector`。长期运行的服务器中，若 worker 动态增减，泄漏会累积。

**修复**: 使用 epoch-based 回收或定期清理旧 registry。

---

## 7. 数据完整性 (Data Integrity)

### [CRITICAL] D1.1 — HTTP EOF (n==0) 导致无限忙循环

**位置**: `src/prism/protocol/http/conn.cpp:125-130`

```cpp
auto n = co_await transport.async_read_some(buffer, ec);
if (ec) { ... break; }
// n == 0 时 (EOF) 不 break，循环继续无限读取 0 字节
```

HTTP 读取循环不检查 `n == 0`（EOF 指示）。当客户端关闭连接时，`async_read_some` 返回 0 字节但无 error_code，循环无限运行。

**修复**: 添加 `if (n == 0) break;` 或 `co_return;`。

---

### [CRITICAL] D1.2 — Trojan handshake overconsume 预读数据

**位置**: `src/prism/protocol/trojan/conn.cpp:150`

```cpp
auto n = co_await transport.async_read_some(buffer, ec);
// 使用全部 buffer 内容作为 Trojan 请求
```

Trojan 握手阶段读取时，读取的 `buffer` 可能包含超过一个 Trojan 请求的数据。VLESS 通过 `.first()` 限制消耗量，但 Trojan 消耗全部读取数据，多余部分丢失，导致后续协议解析失败。

**修复**: 根据 Trojan 请求格式精确消耗指定字节数，保存剩余数据。

---

### [HIGH] D1 — SOCKS5 Password Auth 过度读取

**位置**: `src/prism/protocol/socks5/conn.cpp:249`

```cpp
const auto remaining = static_cast<std::size_t>(ulen + 1 + 255);
co_await async_read_impl(std::span(..., remaining), ec);
```

密码认证阶段，无论实际密码长度 (`plen`) 是多少，都读取 `ulen + 1 + 255` 字节。`plen` 最大为 255，但代码应读取 `ulen + 1 + plen`。固定读取 255 字节会消耗流中属于下一个 SOCKS5 阶段的数据，导致后续命令解析失败。

**修复**: 先读取 `ulen + 1`（用户名 + plen 字段），再根据 plen 读取精确长度的密码。

---

### [MEDIUM] D2 — SS2022 padding length 未做边界检查

**位置**: `src/prism/protocol/shadowsocks/conn.cpp:219-224`

```cpp
padding_len = var_header_plain[offset] << 8 | var_header_plain[offset + 1];
offset += 2 + padding_len;
```

`padding_len` 无上限校验。大值导致 `offset` 超出 `var_header_plain.size()`。后续有兜底检查但不健壮。

**修复**: 在推进 offset 前检查 `offset + 2 + padding_len <= var_header_plain.size()`。

---

### [MEDIUM] D3 — SS2022 空分片导致提前 EOF

**位置**: `src/prism/protocol/shadowsocks/conn.cpp:459`

`fetch_chunk` 中 `current_payload_len_ == 0` 时直接返回空 `decrypted_`，导致 `async_read_some` 返回 0 字节。调用方 `transport::async_read` 将 0 视为 EOF，可能提前终止流。

**修复**: `current_payload_len_ == 0` 时应继续读取下一个分片。

---

### [MEDIUM] D4 — HTTP CONNECT 目标端口未校验

**位置**: `src/prism/protocol/http/conn.cpp`

CONNECT 请求的 `host:port` 中，port 未校验范围（0-65535）或是否为数字。

**修复**: 在 HTTP 层添加端口范围校验。

---

### [MEDIUM] D5 — TrustTunnel authority 解析不完整

**位置**: `src/prism/protocol/trusttunnel/process.cpp:38-49`

- IPv6 中括号未闭合（如 `[::1`）时回退到非 IPv6 解析路径
- 空主机名（如 `:443`）被静默接受
- 端口非数字未校验

---

### [LOW] D6 — 共享 framing 层接受零长度域名和端口 0

**位置**: `include/prism/protocol/common/framing.hpp`

- `parse_domain` 接受 `len = 0`
- `parse_port` 接受端口 0

所有协议继承此行为。

---

## 8. 构建与 CI (Build & CI)

### [HIGH] B3 — CI 仅在 tag 和手动触发时运行

**位置**: `.github/workflows/build.yml:3-7`

PR 和 push 到 main 无 CI 保护。破损代码可直接合并。

**修复**: 添加 `push: branches: [main]` 和 `pull_request:` 触发器。

---

### [HIGH] B4 — 生产库零编译警告

**位置**: `src/CMakeLists.txt`

`prism_static_library` 无 `-Wall -Wextra`。整个生产库编译时无任何警告诊断。

**修复**: 添加 `-Wall -Wextra -Wpedantic`。

---

### [HIGH] B5 — `cert.pem`/`key.pem` 已跟踪但 `.gitignore` 未排除

**位置**: 项目根目录、`.gitignore`

`.gitignore` 未包含 `*.pem`。

**修复**: `.gitignore` 添加 `*.pem`，清理 `git rm --cached cert.pem key.pem`。

---

### [MEDIUM] B6 — BLAKE3 SIMD 编译选项无平台保护

**位置**: `CMakeLists.txt:241-244`

`-msse2`、`-msse4.1`、`-mavx2`、`-mavx512f` 无条件应用于 BLAKE3 源文件。在 ARM 或非 x86 平台上会编译失败。

**修复**: 添加 `if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i.86")` 保护。

---

### [MEDIUM] B7 — 无 Sanitizer 构建

无 ASan、UBSan、TSan 配置。对于手动加密、协程并发、裸内存操作的网络代理，sanitizer 构建应作为标准 CI 门禁。

**修复**: 添加 CMake option `PRISM_ENABLE_ASAN` 等。

---

### [LOW] B8 — MinGW CI 版本 13.2.0 偏旧

项目使用 C++23 特性，MinGW 14.x 有更好的 C++23 支持和优化。

---

## 9. 代码质量 (Code Quality)

### [MEDIUM] Q1 — Trojan/VLESS 验证器 lambda 完全重复

**位置**:
- `src/prism/protocol/trojan/process.cpp:30-45`
- `src/prism/protocol/vless/process.cpp:30-45`

两段代码逐字符一致。

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

协议分发使用硬编码 `switch` 语句。添加新协议需修改 `session.cpp`，违反开闭原则。

---

### [MEDIUM] Q4.1 — dynamic_cast 位置修正

**位置**:
- `include/prism/connect/util.hpp:79,84,103` — `connect::as<>()` 包装
- `include/prism/transport/transmission.hpp:210,224` — `as_reliable()`/`as_unreliable()`

先前审计错误标记为 `stealth/native.cpp` 和 `stealth/executor.cpp`（后者实际调用 `connect::as<>()` 封装）。共 4 处 `dynamic_cast`，在 `transmission` 基类添加 `raw_socket()` 虚方法可消除。

---

### [MEDIUM] Q5 — 错误描述 API 不一致

**位置**:
- `src/prism/protocol/socks5/process.cpp:38` — `fault::cached_message(ec)`
- `src/prism/protocol/http/process.cpp:33` — `fault::describe(ec)`
- `src/prism/protocol/trojan/process.cpp:55` — `fault::describe(trojan_ec)`

两个功能相似的函数 `cached_message` 和 `describe` 混合使用，应统一。

---

### [MEDIUM] Q6 — 协议标签命名不一致

六种协议使用三种命名约定：
- `HttpStr`、`Socks5Str`、`TrojanStr`、`VlessStr`、`ForwardStr` — `PascalCase + Str` 后缀
- `shadowsocks_tag` — `snake_case + _tag` 后缀
- AnyTLS 使用 `tag` — 纯 `tag`

---

### [MEDIUM] Q7 — HTTP conn 使用 `std::vector<char>` 而非 PMR

**位置**: `include/prism/protocol/http/conn.hpp:96`

```cpp
std::vector<char> buffer_;
```

HTTP 是唯一未使用 PMR 容器的协议处理器。

---

### [MEDIUM] Q8 — yamux `data_frame` 使用 `std::vector` 而非 PMR

**位置**: `include/prism/multiplex/yamux/frame.hpp:180`

```cpp
std::vector<std::byte> payload;
```

---

### [MEDIUM] Q9 — `salt_pool` 使用 `std::unordered_map<std::string>` 堆分配 key

**位置**: `include/prism/protocol/shadowsocks/util/salts.hpp:86, 110`

每次插入构造 `std::string` 堆分配。salt 是固定大小（16/32 字节），可使用 `std::array` 或 flat map。

---

### [MEDIUM] Q10 — `system_state::mark_started` 内存序错误

**位置**: `src/prism/stats/runtime.cpp:126-133`

```cpp
if (started_.exchange(true, std::memory_order_relaxed))
    return;
start_time_ = std::chrono::steady_clock::now();  // 非原子
worker_count_ = worker_count;                      // 非原子
```

`start_time_` 和 `worker_count_` 在 relaxed store 之后写入。并发 `snapshot()` 可能通过 relaxed load 看到 `started_ == true` 但读到未初始化的字段。

**修复**: exchange 使用 `memory_order_release`，`snapshot()` 使用 `memory_order_acquire`。

---

### [MEDIUM] Q11 — smux pending stream buffer 无上限

**位置**: `src/prism/multiplex/smux/craft.cpp:192-224`

`dispatch_push()` 将数据累积到 `entry.buffer` 无大小限制。恶意客户端可向 pending stream 发送大量 PUSH 帧而不触发激活，导致每个 pending stream 的 buffer 无限增长。

**修复**: 添加 `max_pending_buffer_size` 限制。

---

### [LOW] Q12 — `namespace net = boost::asio` 在几乎所有文件重复声明

**修复**: 创建 `include/prism/alias.hpp` 统一定义。

---

## 10. 测试缺口 (Test Coverage)

### [HIGH] T1 — 24+ 源码模块无任何测试

最关键的未测试模块：

| 模块 | 源文件 | 影响 |
|------|--------|------|
| `stealth/restls` | `transport.cpp` | 传输层死代码未被测试捕获 |
| `stealth/trusttunnel` | `scheme.cpp` | SSL_CTX ALPN 变异未被测试捕获 |
| `stealth/anytls` | `scheme.cpp`, `session.cpp` | 会话泄漏未被测试捕获 |
| `stealth/ech` | `decrypt.cpp` | 解密未测试 |
| `multiplex/h2mux` | `craft.cpp` | sing-mux 丢帧未被测试捕获 |
| `stats` | `runtime.cpp`, `traffic.cpp` | COW 泄漏未被测试 |
| `resolve/dns` | `resolver.cpp`, `upstream.cpp` | DNS 解析未测试 |
| `instance` | `worker.cpp`, `listener.cpp` | 核心 infra 未测试 |
| `transport/encrypted` | `encrypted.cpp` | TLS 传输未测试 |
| `loader` | `load.hpp` | 配置加载未测试 |

---

### [MEDIUM] T2 — 10+ 测试文件未使用共享 TestRunner

`Shadowsocks.cpp`、`Trojan.cpp`、`Socks5.cpp`、`Http.cpp`、`Vless.cpp` 等自定义 `passed/failed` 计数器，未使用 `tests/common/TestRunner.hpp`。

---

### [MEDIUM] T3 — 协议握手测试过浅

- Trojan: 仅 1 个测试（基本 relay 握手）
- SOCKS5: 仅 1 个测试（基本 relay 握手）
- 缺失: 畸形请求、超时、部分读取、认证失败等边界情况

---

## 11. 配置与文档 (Config & Docs)

### [MEDIUM] M1 — 配置反序列化后零语义校验

**位置**: `include/prism/loader/load.hpp`

glaze 反序列化后无验证层，以下无效值被静默接受：
- `buffer.size = 0` → 零长度读缓冲
- `addressable.port = 0` → 监听端口 0
- `dns.ttl_min > dns.ttl_max` → TTL 钳制逻辑反转
- `pool.connect_timeout_ms = 0` → 连接立即超时
- 完全省略 `addressable` → glaze 默认构造 `host=""`, `port=0`

**修复**: 添加 `validate()` 函数在反序列化后校验所有配置项。

---

### [MEDIUM] M2 — DNS 查询缺少 EDNS0 OPT 记录

**位置**: `src/prism/resolve/dns/detail/format.cpp:511-528`

无 EDNS0 时 DNS 响应方限制 UDP 响应为 512 字节，导致不必要的截断和 TCP 回退。

---

### [MEDIUM] M3 — CLAUDE.md 多处与代码不同步

- 引用 `include/prism/pipeline/` 目录不存在
- Agent 模块结构描述的目录不存在
- 活跃 TODO 列表过时

---

### [LOW] M4 — 根目录残留垃圾文件

`a.exe`（0 字节）、`Crypto.exe` 未被 git 跟踪但存在于磁盘。

---

### [LOW] M5 — `cmake/` 目录为空

应有 `CompilerWarnings.cmake`、`Sanitizers.cmake` 等模块化配置。

---

### [LOW] M6 — TLS 服务器配置使用错误 API 设置 TLS 1.3 密码套件

**位置**: `src/prism/instance/worker/tls.cpp:52-60`

`SSL_CTX_set_cipher_list` 中的 TLS 1.3 密码名被 BoringSSL 静默忽略。应使用 `SSL_CTX_set_ciphersuites()`。功能上无害（BoringSSL 默认启用所有 TLS 1.3 密码），但具有误导性。

---

### [LOW] M7 — yamux/smux stream_id 0 未被 SYN 帧拒绝

stream_id 0 在两个 mux 协议中保留给会话级消息。应拒绝 SYN 帧使用 stream_id 0。

---

### [LOW] M8 — DNS 压缩指针偏移未校验 16383 上限

**位置**: `src/prism/resolve/dns/detail/format.cpp:127`

超过 16383 的偏移会破坏指针类型位。

---

### [LOW] M9 — AnyTLS `write_strand_` 声明但从未使用（死代码）

**位置**: `src/prism/stealth/anytls/session.cpp:26`

strand 已初始化但从未被任何写入操作引用，形成误导性死代码。所有写入（`write_frame`、`write_psh`、`write_fin`、`write_synack`）均直接调用 `transport_->async_write_some()`。当前因单 io_context 单线程安全，但设计意图明确需要 strand。

---

### [LOW] M9.1 — AnyTLS padding 使用 `std::mt19937` 而非 CSPRNG

**位置**: `src/prism/stealth/anytls/padding.cpp`

`std::mt19937` 是确定性伪随机数生成器，输出可预测。用于 TLS padding 长度生成时，攻击者可能通过已知 seed 状态推断填充模式，降低流量分析抵抗能力。

**修复**: 使用 `RAND_bytes()` 或 `std::random_device` 作为随机源。

---

### [LOW] M10 — `stats::account` 遍历接口缺失

**位置**: `include/prism/stats/account.hpp:43`

```cpp
// TODO: 需要在 account::directory 中添加 for_each 遍历接口
```

stats 模块需要遍历所有账户进行指标聚合，但 `account::directory` 未提供遍历接口。

---

### [MEDIUM] M11 — Reality deadline timer 捕获 `&inbound`，inbound 被 move 后 timer 回调悬挂

**位置**: `src/prism/stealth/reality/handshake.cpp:390-398, 613`

```cpp
auto &inbound_ref = inbound;  // 引用
timer.async_wait([&inbound_ref, ...](auto ec) {
    if (!ec) inbound_ref.cancel();  // 悬挂
});
// ... 后续 inbound 被 std::move
```

deadline timer 按引用捕获 `inbound`。timer 还在挂起时 `inbound` 被 `std::move` 到其他变量。timer 触发时通过悬挂引用调用 `cancel()`，是 UB。

**修复**: timer 回调使用 shared_ptr 或在 move 前取消 timer。

---

### [MEDIUM] M12 — Restls cmd_close 和 command_type::response 冲突

**位置**: `src/prism/stealth/restls/transport.hpp`、`src/prism/stealth/restls/common.hpp`

`cmd_close` 值（0x0004）与 Restls 协议中 `command_type::response` 碰撞。接收端无法区分"关闭连接"和"随机响应"命令，可能导致连接被意外关闭或关闭被忽略。

**修复**: 重新分配命令值或添加显式类型区分逻辑。

---

### [MEDIUM] M13 — Restls 读取无超时保护

**位置**: `src/prism/stealth/restls/transport.cpp:read_restls_frame`

`read_restls_frame` 在 `co_await net::async_read` 时无 deadline。若对端发送部分 TLS 记录后停止发送，协程永远挂起。

**修复**: 为每次读取添加可配置超时（如 30s）。

---

### [MEDIUM] M14 — Stats on_connect 不在失败时回滚

**位置**: `src/prism/stats/traffic.cpp`

`broadcast_on_connect()` 在连接建立时调用，但若后续 tunnel forward 失败，`on_disconnect()` 可能不被调用。活跃连接计数只增不减，长期运行后计数器饱和。

**修复**: 确保所有退出路径（正常关闭、错误、取消）都调用 `on_disconnect()`。

---

### [MEDIUM] M15 — Restls read 递归调用可能导致栈溢出

**位置**: `src/prism/stealth/restls/transport.cpp:234`

```cpp
if (cmd == cmd_random_response)
{
    // ...
    co_return co_await read_restls_frame(ec);  // 递归
}
```

收到随机响应时递归调用 `read_restls_frame`。若对端持续发送随机响应帧，递归深度无限制。虽然是协程（`co_await`），但每次递归仍分配新协程帧。

**修复**: 改为循环结构处理连续的随机响应。

---

### [MEDIUM] M16 — h2mux craft 析构时未停止 nghttp2 session

**位置**: `src/prism/multiplex/h2mux/craft.cpp`

craft 析构时未调用 `nghttp2_session_del()`。nghttp2 session 内部分配的内存泄漏。同时未停止 detached frame_loop 协程。

**修复**: 析构函数中调用 `nghttp2_session_del()` 并停止 frame_loop。

---

### [MEDIUM] M17 — Connect pool::async_acquire 连接建立失败时不回收

**位置**: `src/prism/connect/pool/pool.cpp:190-270`

`async_acquire()` 创建新连接并 `async_connect`。若连接成功但随后的健康检查失败，socket 被关闭但连接计数未更新。多次重试可能创建大量临时 socket。

**修复**: 添加重试次数限制和临时 socket 计数。

---

### [LOW] M18 — ShadowTLS v3 fallback 目标连接失败未回退

**位置**: `src/prism/stealth/shadowtls/handshake.cpp`

当 fallback TLS 服务器不可达时，整个握手失败。应考虑缓存 fallback 结果或允许无 fallback 模式。

---

### [LOW] M19 — Trojan command byte 未严格校验范围

**位置**: `src/prism/protocol/trojan/conn.cpp`

Trojan 命令字节仅检查 `connect/udp_associate`，其他值被静默忽略。应回复错误响应。

---

### [LOW] M20 — VLESS UUID 使用字符串比较而非常量时间

**位置**: `src/prism/protocol/vless/process.cpp`

VLESS UUID 认证使用 `std::string_view::operator==`，非常量时间。攻击者可能通过时序推断有效 UUID。

**修复**: 使用 `CRYPTO_memcmp()`。

---

### [LOW] M21 — SOCKS5 UDP associate 不验证客户端地址

**位置**: `src/prism/protocol/socks5/conn.cpp`

UDP associate 模式下不验证 UDP 数据报的源地址是否匹配 BIND 地址。任何发送到 UDP 端口的数据报都被转发。

---

## 12. 第六轮审计新增问题（2026/05/25）

> 本轮审计专注于**性能优化、未实现功能、逻辑问题**三类，安全漏洞已在上轮覆盖。

### [CRITICAL] N1 — hkdf_expand 栈缓冲区溢出

**位置**: `src/prism/crypto/hkdf.cpp:110-121`

`max_hmac_input_size = 289`，但 `hkdf_expand_label` 可构造约 514 字节的 info 传入 `hkdf_expand`。第二轮迭代时 `hmac_size` 可达 547，远超 289 字节的 `hmac_buf` 栈数组。`memcpy` 写越界。

当前因 Reality 密钥调度中 info 很短未触发，但 API 无 info 长度校验。

**修复**: 添加 `info.size()` 上限校验，或改用 PMR vector 作 HMAC 输入缓冲。

---

### [CRITICAL] N2 — Reality authenticate_client decoded_privkey span 悬挂

**位置**: `src/prism/stealth/reality/handshake.cpp:430-452`

`decoded_key_str` 是局部 `std::string`，`out.decoded_privkey` 指向其 `data()`。`co_return out` 后 `decoded_key_str` 被析构，span 悬挂。当前不触发 UAF（认证结果内已使用完毕），但 `auth_stage_result` 结构保留此悬挂 span。

**修复**: 将 `decoded_key_str` 移入 `auth_stage_result` 结构体。

---

### [HIGH] N3 — AES-ECB 每次堆分配 EVP_CIPHER_CTX

**位置**: `src/prism/crypto/block.cpp:22, 69`

`EVP_CIPHER_CTX_new()` 每次调用堆分配。SS2022 UDP datagram 加解密热路径每个包触发 1-2 次。

**修复**: 改用栈上 `EVP_CIPHER_CTX` + init/cleanup。

---

### [HIGH] N4 — dispatch_push 每帧 co_spawn 协程

**位置**: `src/prism/multiplex/smux/craft.cpp:231-255`, `yamux/craft.cpp:276-299`

每个 PSH 帧通过 `co_spawn` 创建新协程调用 `on_mux_data()`。高吞吐下数百帧/秒 = 数百次协程帧分配。

**修复**: duct 路径直接 push 到 write_channel_，去掉 co_spawn。

---

### [HIGH] N5 — 隧道 partial write 静默丢数据

**位置**: `src/prism/connect/tunnel/tunnel.cpp:58-73`

`write_policy::partial` 模式下 `async_write_some` 只写了部分数据时不重发剩余数据，直接进入下次迭代。

**修复**: 为 partial 模式添加循环重试直到全部写入。

---

### [HIGH] N6 — SOCKS5 UDP 仅绑 IPv4 socket

**位置**: `src/prism/protocol/socks5/conn.cpp:579`

`bind_datagram_port()` 硬编码 `udp::v4()`。IPv6 控制连接发起 UDP ASSOCIATE 时返回 IPv4 地址，客户端无法使用。

**修复**: 根据控制连接对端地址族选择 IPv4/IPv6。

---

### [HIGH] N7 — DNS CNAME 规则匹配后未实际应用

**位置**: `src/prism/resolve/dns/resolver.cpp:186-254`

`rules_engine::match()` 正确检测 CNAME 并填充字段，但 `query_pipeline` 只处理 blocked/negative/addresses，对 cname 完全无处理。配置中的 CNAME 重定向规则是死代码。

**修复**: 添加 CNAME 重写逻辑，用目标域名重新走查询管道。

---

### [HIGH] N8 — total_active 在协议识别失败连接上从不递减

**位置**: `src/prism/instance/session/session.cpp:103-105`

`on_disconnect()` 只在 `detected_protocol != unknown` 时调用。识别失败/超时的连接 `total_active_` 只增不减，永久泄漏计数。

**修复**: 移除 `detected_protocol != unknown` 前置条件，或为识别失败路径单独处理。

---

### [HIGH] N9 — launch::start() 异常路径不回滚 on_connect

**位置**: `src/prism/instance/worker/launch.cpp:74-76 vs 125-130`

`traffic_state::on_connect()` 在 try 块之前调用，catch 块只回滚了 `session_close`，未回滚 `on_connect`。`total_active_` 永久虚高。

**修复**: catch 块中增加 `on_disconnect` 回滚。

---

### [HIGH] N10 — Restls write_frame 并发写入无保护

**位置**: `src/prism/stealth/anytls/session.cpp:389-422`（已知 S15 的深层问题）

`write_frame()` 无串行化保护。`recv_loop` 的 `on_settings()`、`on_syn()` 回调和多个 stream 的 `write_psh()` 可并发调用 write_frame，数据帧交错。

**修复**: 所有 write_frame 调用通过 write_strand_ 串行化。

---

### [HIGH] N11 — Reality fetch_dest_cert() 定义但从未调用

**位置**: `src/prism/stealth/reality/handshake.cpp:155-224`

完整实现了获取目标服务器证书功能，但 `handshake()` 传入空 `span{}`。证书生成失败时 fallback 到空证书链。

**修复**: 在 `negotiate_tls()` 中调用 `fetch_dest_cert()` 获取真实证书。

---

### [MEDIUM] N12 — smux/yamux send_loop 伪 scatter-gather

**位置**: `smux/craft.cpp:526-533`, `yamux/craft.cpp:920-928`

每帧分配 combined vector + 两次 memcpy。Boost.Asio 支持 scatter-gather `async_write`，零分配零拷贝。

**修复**: 使用 buffer sequence 重载的 `net::async_write`。

---

### [MEDIUM] N13 — h2mux send_loop 每帧两次堆分配

**位置**: `src/prism/multiplex/h2mux/craft.cpp:638-646`

每个 DATA 帧创建 `shared_ptr<payload>` + `unique_ptr<data_source>`，但 payload 在同栈帧 `send_pending()` 内同步使用完毕。

**修复**: payload 和 data_source 放在栈上作局部变量。

---

### [MEDIUM] N14 — yamux send_data 窗口等待无超时

**位置**: `src/prism/multiplex/yamux/craft.cpp:753-800`

`signal->expires_at(time_point::max())` 无限等待 WindowUpdate。恶意客户端停发 WindowUpdate 可挂起无限 duct 协程。

**修复**: 添加 30s 超时，超时后关闭对应流。

---

### [MEDIUM] N15 — system_state::mark_started 从未被调用

**位置**: `src/main.cpp`（全文无调用）

`mark_started()` 在整个代码库从未被调用。`snapshot()` 永远返回空快照。`runtime_snapshot` 是死代码。

**修复**: 在 main.cpp 的 worker 创建后调用 `mark_started(workers_count)`。

---

### [MEDIUM] N16 — counter/gauge/memory_tracker 原语全部未接入

**位置**: `stats/counter.hpp`, `stats/gauge.hpp`, `stats/memory.hpp`

counter、gauge、memory_tracker 在整个项目中无任何使用者。traffic_state 直接用 `std::atomic`。observe 用局部变量做 EMA。

**修复**: 要么让模块使用这些原语，要么移除死代码。

---

### [MEDIUM] N17 — exception::deviant 缺少显式虚析构函数

**位置**: `include/prism/exception/deviant.hpp:38`

多态基类声明了 `virtual dump()` 和纯虚 `type_name()`，但未声明虚析构函数。依赖基类隐式虚化。

**修复**: 添加 `~deviant() override = default;`。

---

### [MEDIUM] N18 — loader::load 配置文件无大小上限

**位置**: `include/prism/loader/load.hpp:40-44`

`file.tellg()` 获取大小后直接分配 `memory::string`。大文件导致 OOM。`file.read()` 结果未校验。

**修复**: 添加 10MB 上限检查 + gcount 校验。

---

### [MEDIUM] N19 — observe 协程无最大漂移保护

**位置**: `src/prism/stats/runtime.cpp:58-65`

`expected_time += 250ms` 累加模式。io_context 繁忙时 expected_time 严重落后，后续循环空转浪费 CPU。

**修复**: 每次循环检查 expected_time 是否严重落后于当前时间，是则重置。

---

### [MEDIUM] N20 — ed25519_keypair 缺少生成函数

**位置**: `include/prism/crypto/x25519.hpp:92-96`

`ed25519_keypair` 已声明但无 `generate_ed25519_keypair()` 函数。Reality 直接调用 BoringSSL `ED25519_keypair()`，绕过封装。

**修复**: 在 x25519.hpp 中添加 ed25519 生成/签名函数。

---

### [MEDIUM] N21 — pooled_object 基类从未被使用

**位置**: `include/prism/memory/pool.hpp:130-211`

`pooled_object<T>` CRTP 基类完整实现 operator new/delete 重载，但无任何类继承。所有热路径对象仍用 `make_shared` 默认堆分配。

**修复**: 要么让核心对象继承使用，要么删除。

---

### [MEDIUM] N22 — hkdf_expand 返回 std::vector 而非 PMR

**位置**: `src/prism/crypto/hkdf.cpp:82/97/127`

Reality 密钥调度中一次握手调用 9 次 `hkdf_expand_label`，每次产生一个非 PMR 堆分配 vector。

**修复**: 改用 `memory::vector` 或接受输出 span 的重载。

---

### [MEDIUM] N23 — aead_context 堆分配 EVP_AEAD_CTX

**位置**: `src/prism/crypto/aead.cpp:55`

`new EVP_AEAD_CTX`（~400 字节）每次构造堆分配。可内联嵌入避免 new/delete。

**修复**: 将 EVP_AEAD_CTX 作为成员变量嵌入。

---

### [MEDIUM] N24 — 所有 stealth scheme 的 hs_timeout 配置被忽略

**位置**: 所有 config.hpp 中的 `hs_timeout` 字段

Reality 用硬编码 30s、ShadowTLS/Restls 用 500ms、AnyTLS/TrustTunnel 无超时控制。用户配置的 `hs_timeout` 完全被忽略。

**修复**: 用配置中的 `hs_timeout` 替换硬编码值，或移除配置字段。

---

### [MEDIUM] N25 — HTTP 不剥离 hop-by-hop 头

**位置**: `src/prism/protocol/http/conn.cpp:70-92`

除已知 F10（Proxy-Authorization 泄漏）外，其他 hop-by-hop 头（Connection, Keep-Alive, Transfer-Encoding, Upgrade）也原封不动转发，可能导致双重分块编码。

**修复**: 在 forward() 中过滤已知 hop-by-hop 头。

---

### [MEDIUM] N26 — 隧道 relay_loop 每次迭代双重定时器重置

**位置**: `src/prism/connect/tunnel/tunnel.cpp:55-56 和 80-82`

每次迭代在读取后和写入后各调用一次 `expires_after + async_wait`，千兆流量下产生数十万次额外定时器操作。

**修复**: 仅在写入完成后重置一次。

---

### [MEDIUM] N27 — Restls script_engine 使用 std::rand()

**位置**: `src/prism/stealth/restls/script.cpp:45, 108, 146`

`std::rand()` 全局共享状态，多线程数据竞争。应改用 `thread_local std::mt19937` 或 `crypto::random_bytes()`。

---

### [MEDIUM] N28 — Restls write_pending 缓冲只保留最后一批

**位置**: `src/prism/stealth/restls/transport.cpp:269-272`

多次写入被缓冲时合并为一个巨大帧。返回成功但数据未实际发送，连接断开时数据丢失。

**修复**: 缓冲改为队列结构。

---

### [MEDIUM] N29 — Restls version_hint 配置被解析但从未使用

**位置**: `include/prism/stealth/restls/config.hpp:38`

handshake.cpp 通过 `is_tls13_server_hello()` 动态检测，完全忽略此字段。

---

### [MEDIUM] N30 — AnyTLS send_waste_frame 不检查负数 size

**位置**: `src/prism/stealth/anytls/session.cpp:439`

`generate_sizes()` 可能返回负数（parse 失败时），`std::vector<uint8_t>(size, 0)` 将负数转为极大 size_t，OOM 或崩溃。

**修复**: 添加 `size <= 0` 检查。

---

### [MEDIUM] N31 — DNS upstream SNI arg 传空字符串

**位置**: `src/prism/resolve/dns/upstream.cpp:55-60`

hostname 为空时条件取 address，但传给 SSL 的 SNI arg 仍是 `server.hostname.c_str()`（空串），导致不携带 SNI 扩展。

**修复**: 改为 `hostname.c_str()` 并确保生命周期正确。

---

### [MEDIUM] N32 — bootstrap negotiate 未校验 protocol 值范围

**位置**: `src/prism/multiplex/bootstrap.cpp:37`

`static_cast<protocol_type>(header[1])` 对非法值（>2）不报错，静默降级为 smux，导致后续帧解析失败但难以定位。

**修复**: switch 前校验 protocol 值范围。

---

### [LOW] N33 — base64_decode reserve 计算偏小

**位置**: `include/prism/crypto/base64.hpp:98`

`valid_count` 不含 padding，含 padding 输入 reserve 为 0，后续 push_back 触发不必要重分配。

### [LOW] N34 — sha256 空数据传入可能的 UB

**位置**: `src/prism/crypto/hkdf.cpp:207`

空 span 的 `data()` 返回 nullptr，`SHA256(nullptr, 0, ...)` 语义上 UB。

### [LOW] N35 — derive_key 返回 std::vector 而非 PMR

**位置**: `src/prism/crypto/blake3.cpp:25-31`

SS2022 每次新连接调用一次，非 PMR 堆分配。

### [LOW] N36 — peel_to_raw 多次 dynamic_cast

**位置**: `include/prism/connect/util.hpp:74-91`

对每个装饰层一次 `dynamic_cast`，O(n) RTTI 开销。

### [LOW] N37 — reliable/unreliable 无用 enable_shared_from_this

**位置**: `transport/reliable.hpp:48`, `transport/unreliable.hpp:37`

两个类继承但从未调用 `shared_from_this()`，每实例增加 16 字节 weak_ptr。

### [LOW] N38 — 三个 conn 类无用 enable_shared_from_this

**位置**: `protocol/socks5/conn.hpp:80`, `trojan/conn.hpp:48`, `vless/conn.hpp:40`

socks5/trojan/vless conn 继承但从未调用 `shared_from_this()`。

### [LOW] N39 — h2mux on_data payload 未用 PMR allocator

**位置**: `src/prism/multiplex/h2mux/craft.cpp:482-484`

迭代器构造 vector 时未传 `mr_`，回退到默认 new/delete。

### [LOW] N40 — parcel downlink_loop 每包三次分配

**位置**: `src/prism/multiplex/parcel.cpp:305-318`

`to_string()` + PMR string 拷贝 + encoded vector，高频 DNS 下开销不可忽略。

### [LOW] N41 — traffic_state 未显式 delete 拷贝/移动

**位置**: `include/prism/stats/traffic.hpp:51`

包含 atomic 成员（不可拷贝），但未显式 delete，移动后 registry 指针悬挂。

### [LOW] N42 — loader::load 文件打开失败用 security 异常

**位置**: `include/prism/loader/load.hpp:38`

文件打开失败属配置错误，非安全问题。应使用 `exception::network`。

### [LOW] N43 — ShadowTLS transport write_key_ 从不使用

**位置**: `stealth/shadowtls/transport.hpp:122`

构造时计算存储，传输阶段和握手阶段都不使用。32 字节无用占用。

### [LOW] N44 — Restls tls_version_ 和 tls13_ 冗余存储

**位置**: `stealth/restls/transport.hpp:135`

两个成员表达同一信息，且都未被任何代码使用。

### [LOW] N45 — TrustTunnel/AnyTLS 配置字段 network/congestion/idle_timeout 声明未使用

**位置**: `trusttunnel/config.hpp:74-79`, `anytls/config.hpp:59`

序列化注册但代码中完全未引用，误导用户。

---

## 13. 第七轮审计新增问题（2026/05/25）

> 本轮审计由 5 个并行 agent 覆盖全模块：crypto/security、stealth/transport、protocol/connect、multiplex/memory/stats、instance/resolve/recognition/loader。

### [CRITICAL] O1 — Executor pipeline 误判 TrustTunnel/AnyTLS 成功为"未匹配"

**位置**: `src/prism/stealth/executor.cpp:89-123`

TrustTunnel 和 AnyTLS 握手成功后返回 `detected = protocol_type::tls`、`error = success`、`transport = nullptr`。executor pipeline 将 `detected == tls` 解释为"不是我的方案"，调用 `try_rewind()`/`pass_through()` 后继续执行下一个方案。后续方案（如 `native`）尝试对已消耗的连接做 SSL 握手必然失败，pipeline 返回错误给 session，**已成功建立的连接被拆除**。

**影响**: TrustTunnel 和 AnyTLS 在生产环境中完全不工作。后台运行的 craft/session 被意外终止。

**修复**: 引入 `protocol_type::consumed` 或在 `handshake_result` 添加 `bool consumed` 字段，executor 遇到时立即返回成功。

---

### [HIGH] O2 — SOCKS5 recv_impl 使用 async_read_some 读定长协议字段

**位置**: `src/prism/protocol/socks5/conn.cpp:470-474`

所有 SOCKS5 定长字段读取（request_header 4 字节、auth 2 字节、domain 长度等）使用 `async_read_some`，后者可能只返回部分字节。调用方直接解析 buffer，假设数据完整。网络分片/TLS 记录边界场景下解析使用零填充残留数据，产生协议错误。

对比 Trojan/VLESS 用 `read_at_least`、SS2022 用 `transport::async_read` 保证精确读取。

**修复**: 将 `recv_impl` 改为循环读取直到填满，或改用 `transport::async_read`。

---

### [HIGH] O3 — 密钥材料析构时未安全清零

**位置**: `include/prism/crypto/x25519.hpp:47-51,92-96`、`reality/util/keygen.hpp:34-46`

`x25519_keypair::private_key`、`ed25519_keypair::private_key`、`key_material` 所有字段均为 `std::array<uint8_t, N>`，析构函数不清零。敏感密钥材料残留在栈/堆上，可被核心转储或内存泄露攻击读取。项目无任何 `OPENSSL_cleanse` 调用。

**修复**: 为密钥结构体添加析构函数调用 `OPENSSL_cleanse`，或实现 `secure_array` 包装器。

---

### [HIGH] O4 — DNS query_via 成功路径读取 moved-from 对象，TC 截断回退完全失效

**位置**: `src/prism/resolve/dns/upstream.cpp:734-740`

```cpp
tr.result = std::move(result);     // result 被整体搬移
tr.response = result.response;     // 读取 moved-from 对象 → 空 message
```

`tr.response` 获得 `tc` 默认值 `false`。后续 `query_udp()` 检查 `resp->tc` 永远不触发 TCP 重试。大 DNS 响应被截断后客户端收到不完整结果，无感知。

**修复**: 先拷贝 `tr.response = result.response`，再搬移 `tr.result = std::move(result)`。

---

### [MEDIUM] O5 — Trojan/VLESS close()/cancel() 在 release() 后空指针解引用

**位置**: `src/prism/protocol/trojan/conn.cpp:116-124`、`src/prism/protocol/vless/conn.cpp:71-78`

`release()` 将 `next_layer_` 置空，但 `close()` 和 `cancel()` 不检查空指针直接调用 `next_layer_->close()`。SOCKS5 和 SS2022 都有空指针保护。

**修复**: 添加 `if (next_layer_)` 检查。

---

### [MEDIUM] O6 — SS2022 fetch_chunk 不校验 SIP022 最大分片大小 0x3FFF

**位置**: `src/prism/protocol/shadowsocks/conn.cpp:489-497`

`cur_payload_len_` 从解密后的长度字段读取但未校验是否超过 `max_chunk_size = 0x3FFF`。持有 PSK 的恶意客户端可发送 65535 字节分片，违反规范且增加内存压力。

**修复**: 在赋值后添加 `if (cur_payload_len_ > max_chunk_size)` 范围校验。

---

### [MEDIUM] O7 — yamux activate_stream 缓冲区交换导致入站数据丢失

**位置**: `src/prism/multiplex/yamux/craft.cpp:538-587`

`activate_stream` 将 `entry.buffer` swap 到局部变量后执行 `co_await send_data` 等。期间 `frame_loop` 交错运行，新到达的 PSH 帧追加到已清空的 `entry.buffer`。`activate_stream` 最终 `pending_.erase(stream_id)` 销毁所有新追加的数据。

smux 通过直接从 `entry.buffer` 读取避免了此问题。

**修复**: 不进行 swap，直接从 `entry.buffer` 提取剩余数据。

---

### [MEDIUM] O8 — h2mux on_stream_close 未完全关闭 duct 管道

**位置**: `src/prism/multiplex/h2mux/craft.cpp:544-565`

`on_stream_close` 只调用 `duct->on_fin()`（半关闭），不从 `ducts_` 移除 duct。`target_readloop` 继续运行但 `nghttp2_submit_data` 返回错误。长连接目标下 duct 和连接无限期打开，traffic 永不刷新。

**修复**: 调用 `duct->close()` 或在 `on_fin()` 后显式 `remove_duct()`。

---

### [MEDIUM] O9 — DNS 负缓存 put_negative 无 LRU 淘汰

**位置**: `src/prism/resolve/dns/detail/cache.cpp:157-197`

正向缓存 `put()` 有 LRU 淘汰，但 `put_negative()` 完全缺失。DNS 放大攻击或上游故障时大量不同域名产生负缓存条目，绕过 `max_entries_` 限制无限增长。

**修复**: 在 `put_negative()` 添加与 `put()` 相同的 LRU 淘汰代码。

---

### [MEDIUM] O10 — DNS DoH Content-Length 无上限校验

**位置**: `src/prism/resolve/dns/upstream.cpp:557-585`

`content_length` 从 HTTP 头解析后直接 `body_buf.resize()`，无上限校验。恶意 DNS 服务器可返回极大值触发 OOM。

**修复**: 添加 `if (content_length > 65535)` 上限（DNS 报文最大 65535 字节）。

---

### [MEDIUM] O11 — DNS unpack 未限制记录总数

**位置**: `src/prism/resolve/dns/detail/format.cpp:402-405`

报文头四个计数合计可达 262140 条记录。精心构造的响应可触发大量 PMR 小对象分配。

**修复**: 添加总记录数限制（如 1024）。

---

### [MEDIUM] O12 — RAND_bytes 返回值未检查

**位置**: `src/prism/crypto/x25519.cpp:17`、`src/prism/stealth/reality/util/response.cpp:84`

两处 `RAND_bytes` 调用均未检查返回值。系统熵不足时使用未定义数据作为密钥。同项目 `shadowsocks/conn.cpp:246` 正确检查了返回值。

**修复**: 检查 `RAND_bytes` 返回值，失败时返回错误。

---

### [MEDIUM] O13 — Reality 空 SNI 绕过白名单验证

**位置**: `src/prism/stealth/reality/util/auth.cpp:58-64`

```cpp
if (!client_hello.server_name.empty() &&
    !match_server_name(...))
```

客户端不发送 SNI 扩展时 `server_name` 为空，整个条件短路为 `false`，白名单验证被跳过。TLS 1.3 不强制 SNI，攻击者可构造无 SNI 的 ClientHello 绕过。

**修复**: 当 `cfg.server_names` 非空时，要求客户端必须提供 SNI 且匹配。

---

### [LOW] O14 — Trojan/VLESS UDP traffic_context 异常路径泄漏

**位置**: `src/prism/protocol/trojan/conn.cpp:320-324`、`src/prism/protocol/vless/conn.cpp:310-314`

裸 `new traffic_context` 仅通过 `udp_frame_loop` 退出时的回调释放。协程异常退出时泄漏。已知 S16 记录了同类问题。

---

### [LOW] O15 — h2mux closed_ 标志从未设置（死代码）

**位置**: `include/prism/multiplex/h2mux/craft.hpp:256`

`closed_` 声明并检查但从未被设置为 `true`。`frame_loop` 完全通过 `active_` 退出。

---

### [LOW] O16 — parcel uplink_loop 非 timeout 退出时误导日志

**位置**: `src/prism/multiplex/parcel.cpp:75`

`close()` 触发退出时仍打印 "UDP idle timeout"。

---

### [LOW] O17 — yamux activate_stream 与 FIN/RST 竞态

**位置**: `src/prism/multiplex/yamux/craft.cpp:585-646`

`co_await send_data` 期间客户端发送 FIN/RST 可能在 `activate_stream` 创建 duct 前擦除 pending。已关闭的流上创建 duct 导致 `target_readloop` 卡在窗口等待。

---

### [LOW] O18 — DNS match_short_id 前缀匹配降低有效熵

**位置**: `src/prism/stealth/reality/util/auth.cpp:44`

服务端配置 4 字节 short_id 时只需匹配前 4 字节，有效熵从 64 位降至 32 位。

---

### [LOW] O19 — config.hpp 直接 include Glaze 破坏分离设计

**位置**: `include/prism/config.hpp:40-43`

`serialize.hpp` 设计意图是分离 Glaze 依赖，但 `config.hpp` 直接 include 所有序列化头和 glaze 本身，分离设计被完全架空。

---

## 统计（第七轮全面审计）

| 严重程度 | 数量 | 变化（vs 第六轮 165 项） |
|----------|------|------------------------|
| CRITICAL | 20 | +1 |
| HIGH | 44 | +3 |
| MEDIUM | 77 | +9 |
| LOW | 43 | +6 |
| **合计** | **184** | **+19** |

**第七轮新增 CRITICAL 问题**：
- O1: Executor pipeline 误判 TrustTunnel/AnyTLS 成功（影响：两个协议生产完全不工作）

**第七轮新增 HIGH 问题**：
- O2: SOCKS5 recv_impl 不保证定长读取
- O3: 密钥材料析构未清零
- O4: DNS query_via moved-from 读取致 TC 回退失效

**第七轮新增 MEDIUM 问题**：
- O5-O13: 共 9 项（空指针、缓冲区交换、负缓存无淘汰、DoH 无上限、记录数无限制、RAND_bytes 未检查、空 SNI 绕过等）

**第七轮新增 LOW 问题**：
- O14-O19: 共 6 项

**建议优先处理顺序**：
1. **CRITICAL 管道错误**: O1 (executor 误判) → S7/F1 (Restls 死代码) → S5 (open_output_size 下溢) → N1 (hkdf_expand 溢出)
2. **CRITICAL 并发/所有权**: S7.2 (SYN collision) → L2.C (send_pending) → S6 (SSL_CTX ALPN) → L2.A (AnyTLS close)
3. **CRITICAL 数据完整性**: D1.1 (HTTP EOF) → N5 (partial write) → D1.2 (Trojan overconsume) → L2.B (preread 双发)
4. **HIGH 协议正确性**: O2 (SOCKS5 定长读取) → O4 (DNS TC 回退) → O3 (密钥清零) → N3 (AES-ECB) → N4 (dispatch_push)
5. **HIGH 性能热点**: P1 (隧道缓冲) → N12 (scatter-gather) → P2/P2.1 (mux buffer) → P4 (SS2022 堆分配)
6. **HIGH 统计/功能**: N8 (total_active) → N9 (异常回滚) → N15 (mark_started) → N7 (DNS CNAME) → N11 (Reality 证书)
