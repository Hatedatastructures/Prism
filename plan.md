# Prism 代理服务器 — 开发计划（第五版）

> **编制日期**: 2026/05/01
> **修订日期**: 2026/05/24
> **时间跨度**: 2026/05/24 — 2026/08/07 (共 10 周)
>
> **修订说明** (2026/05/24 第五轮):
> - 基于第五轮全项目 220+ 文件逐行深度审计（14 个并行 agent）
> - CRITICAL bug 从 9 个激增至 17 个，新增 8 个：BLAKE3 初始化、smux/yamux SYN collision、config.json 明文凭据、HTTP EOF 忙循环、Trojan overconsume、AnyTLS close() null 解引用、AnyTLS preread 双发、TrustTunnel send_pending 并发、Restls write blocking 无界缓冲、worker unregister use-after-free
> - HIGH 问题从 24 个增至 32 个：新增 write_strand 未使用、deadline timer 未取消、detected=tls 误判、MAX_CONCURRENT_STREAMS 缺失、200 OK 时序错误、register_instance CAS 缺失等
> - 总问题从 84 项增至 123 项
> - Phase A 扩展至 13 个任务，需要扩展至 3 周

---

## 一、项目现状总览

### 1.1 架构重构完成度

15 步实施进度：

| # | 重构内容 | 状态 |
|---|---------|------|
| 1 | 提取 `protocol/types.hpp` + `protocol/common/target.hpp` | ✅ |
| 2 | 移动 TLS 解析到 `recognition/tls/` | ✅ |
| 3 | 清理 reality 重复代码 | ✅ |
| 4 | 移动 `analysis::resolve()` 和 `detect_tls()` | ✅ |
| 5 | 创建 connect 模块骨架 | ✅ |
| 6 | 创建 stats 顶层模块 | ✅ |
| 7 | 创建 account 顶层模块 | ✅ |
| 8 | channel → transport | ✅ |
| 9 | pipeline/primitives 拆分 | ✅ |
| 10 | resolve/router 拆分 | ✅ |
| 11 | dispatch/table.hpp 移除 | ✅ |
| 12 | agent → instance | ✅ |
| 13 | 更新聚合头文件 | ✅ |
| 14 | 更新 CMakeLists.txt | ✅ |
| 15 | 更新测试文件 | ✅ |

**状态**: 架构重构 100% 完成。所有 15 步已完成。

### 1.2 已完成模块

| 模块 | 状态 | 路径 |
|------|------|------|
| HTTP 代理 | ✅ 完成 | `src/prism/protocol/http/` |
| SOCKS5 (TCP+UDP) | ✅ 完成 | `src/prism/protocol/socks5/` |
| Trojan (TCP+UDP+MUX) | ✅ 完成 | `src/prism/protocol/trojan/` |
| VLESS (TCP+UDP+MUX) | ✅ 完成 | `src/prism/protocol/vless/` |
| SS2022 AEAD (TCP+UDP) | ✅ 完成 | `src/prism/protocol/shadowsocks/` |
| Reality TLS 伪装 | ✅ 完成 | `src/prism/stealth/reality/` |
| ShadowTLS v3 | ✅ 完成 | `src/prism/stealth/shadowtls/` |
| **Restls 握手** | ✅ 完成 | `src/prism/stealth/restls/` |
| **AnyTLS 握手** | ✅ 完成 | `src/prism/stealth/anytls/` |
| **TrustTunnel 握手** | ✅ 完成 | `src/prism/stealth/trusttunnel/` |
| smux v1 多路复用 | ✅ 完成 | `src/prism/multiplex/smux/` |
| yamux 多路复用 | ✅ 完成 | `src/prism/multiplex/yamux/` |
| **h2mux 多路复用** | ✅ 完成 | `src/prism/multiplex/h2mux/` |
| 七阶段 DNS 解析 | ✅ 完成 | `src/prism/resolve/dns/` |
| Happy Eyeballs (RFC 8305) | ✅ 完成 | `src/prism/connect/dial/racer.hpp` |
| 连接池 + 健康检查 | ✅ 完成 | `src/prism/connect/pool/` |
| 加权负载均衡 | ✅ 完成 | `src/prism/instance/front/balancer.cpp` |
| PMR 内存管理 | ✅ 完成 | `include/prism/memory/` |
| 协议识别 | ✅ 完成 | `src/prism/recognition/` |
| 方案注册管道 | ✅ 完成 | `include/prism/stealth/registry.hpp` |
| **优雅关机** | ✅ 完成 | `src/main.cpp` (signal_set + graceful stop) |
| **CI 修复** | ✅ 完成 | `.github/workflows/build.yml` |
| **Stats 指标系统** | ✅ 完成 | `src/prism/stats/` |

### 1.3 活跃 TODO 桩（2 个）

| # | 文件位置 | 问题描述 | 优先级 |
|---|---------|---------|--------|
| 1 | `src/prism/stealth/ech/util/decrypt.cpp:39` | ECH HPKE 解密返回 `not_supported` | MEDIUM |
| 2 | `src/prism/multiplex/h2mux/craft.cpp:478` | sing-mux DATA 帧 StreamRequest 解析 | HIGH |

### 1.4 CRITICAL 已知 Bug（需立即修复，17 个）

| # | 文件位置 | 问题描述 |
|---|---------|---------|
| 1 | `src/prism/stealth/restls/transport.cpp:131-135` | 无条件错误返回块，Restls 完全不可用 |
| 2 | `include/prism/crypto/aead.hpp:197` | `open_output_size` 无符号下溢（ciphertext < 16 时） |
| 3 | `src/prism/stealth/trusttunnel/scheme.cpp:136` | 修改共享 SSL_CTX ALPN 影响同 worker 其他会话 |
| 4 | `src/prism/crypto/aead.cpp:116` | nonce 溢出检测在密文已生成之后 |
| 5 | `src/prism/protocol/socks5/conn.cpp:249` | Password Auth 过度读取破坏流 |
| 6 | `src/prism/stealth/anytls/scheme.cpp:361-365` | SOCKS 解析失败未关闭 session，recv_loop 泄漏 |
| 7 | `src/prism/stealth/shadowtls/handshake.cpp:550` | detached 协程引用捕获局部变量（restls 同） |
| 8 | `src/prism/stealth/trusttunnel/scheme.cpp:222-228` | no-CONNECT 路径 craft 与 session 双重持有 transport |
| 9 | `src/prism/resolve/dns/upstream.cpp:55-57` | SNI arg 悬挂引用（set_servers 替换 vector 后） |
| 10 | `src/prism/crypto/blake3.cpp:40,48` | BLAKE3 keyed_hasher 初始化错误 + 无 key 长度校验 |
| 11 | `src/prism/multiplex/smux/craft.cpp:182-189` | handle_syn 不检查 stream_id 冲突 → 流劫持 |
| 12 | `src/configuration.json` | git 跟踪的明文凭据 |
| 13 | `src/prism/protocol/http/conn.cpp:125-130` | EOF (n==0) 无限忙循环 |
| 14 | `src/prism/protocol/trojan/conn.cpp:150` | overconsume 预读数据 |
| 15 | `src/prism/stealth/anytls/mux/transport.hpp:112-130` | close() null 解引用 |
| 16 | `src/prism/stealth/anytls/session.cpp:223-230` | preread 数据双重投递 |
| 17 | `src/prism/stealth/restls/transport.cpp:273-277` | write blocking 无界 send_buf_ |

**附加 CRITICAL 级并发/统计问题**:
| # | 文件位置 | 问题描述 |
|---|---------|---------|
| 18 | `src/prism/multiplex/h2mux/craft.cpp` | send_pending() 并发帧交错 |
| 19 | `src/prism/stats/traffic.cpp:110-140` | worker 从未 unregister → use-after-free |

### 1.5 测试覆盖现状

**已有**: 55 个测试文件 + 2 个并发测试 = 57 个文件

**新增测试**（第三轮后）:
- `GracefulShutdown.cpp` — 优雅关机测试
- `HandshakeTimeout.cpp` — 握手超时测试
- `H2muxCraft.cpp` — h2mux 帧编解码
- `H2mux.cpp` — h2mux 集成
- `MuxBootstrap.cpp` — mux 引导测试
- `MuxParcel.cpp` — mux 包传输
- `MuxStressTest.cpp` — mux 压力测试
- `MuxMaxStreams.cpp` — mux 最大流数
- `MuxLifecycle.cpp` — mux 生命周期
- `YamuxWindow.cpp` — yamux 窗口管理
- `TransportLayer.cpp` — 传输层测试
- `SchemeRouteTable.cpp` — 方案路由表

**零覆盖模块**: `loader/`、`outbound/`、`transport/encrypted`、`instance/worker`、`instance/listener`

### 1.6 安全性评估（6.5/10，较第四轮 7.5/10 下降）

| 方面 | 现状 | 改善 |
|------|------|------|
| 用户认证 | 统一模型，SHA224 哈希 | — |
| SS2022 salt | `RAND_bytes` | ✅ 修复 |
| AEAD nonce | 溢出检测（但时机需改进） | ⚠️ 部分修复 |
| TLS 配置 | `SSL_OP_NO_RENEGOTIATION` | ✅ 修复 |
| 优雅关机 | signal_set + graceful stop | ✅ 修复 |
| CI 完整性 | 无 continue-on-error，URL_HASH 校验 | ✅ 修复 |
| Restls MAC | `CRYPTO_memcmp` | ✅ 修复 |
| 证书泄露 | `cert.pem`/`key.pem` 仍在仓库 | ❌ 未修复 |
| 连接数限制 | 无全局/每端点最大连接数 | ❌ 缺失 |
| BLAKE3 keyed | 初始化错误 + 无 key 长度校验 | ❌ 新发现 |
| mux 流劫持 | SYN stream_id 无冲突检测 | ❌ 新发现 |
| config 凭据 | `configuration.json` 含明文密码 | ❌ 新发现 |
| AnyTLS close | null 解引用 crash | ❌ 新发现 |
| TrustTunnel 并发 | send_pending 帧交错 | ❌ 新发现 |

### 1.7 协议完整性

| 协议 | 完整度 | 关键缺失 |
|------|--------|----------|
| SOCKS5 | 85% | GSSAPI、BIND、UDP 分片、**Password Auth 过读** |
| HTTP Proxy | 75% | Keep-Alive、Chunked、**Proxy-Auth 泄漏** |
| Trojan | 90% | WebSocket 传输 |
| VLESS | 85% | XTLS/Vision |
| SS2022 | 90% | EIH、多 PSK |
| **Restls** | **90%** | **transport 层死代码需修复**、write blocking 无界缓冲、无超时、递归读 |
| **AnyTLS** | **80%** | **close() crash**、**preread 双发**、write_strand 未使用、padding 非CSPRNG |
| **TrustTunnel** | **75%** | **SSL_CTX ALPN 变异**、**send_pending 并发**、先200后连接、无MAX_CONCURRENT_STREAMS |
| WebSocket | 0% | 完全未实现 |
| gRPC | 0% | 未计划 |

---

## 二、性能目标（Before → After）

| 指标 | Before | 当前值 | 最终目标 |
|------|--------|--------|---------|
| AES-256-GCM | 205 Mi/s | **13.7 Gi/s ✅** | 13.7 Gi/s |
| AES-128-GCM | 245 Mi/s | **16.9 Gi/s ✅** | 16.9 Gi/s |
| X25519 交换 | 81.5 us | **21.4 us ✅** | 21.4 us |
| 全局池 4T | 3530 ns | 3530 ns | <100 ns |
| 连接 P50 | 95 us | 95 us | 85 us |
| 连接 P99 | 336 us | 336 us | <200 us |
| TCP 64B | 20.1 us | 20.1 us | 10 us |
| 活跃 TODO | 5 个 | **2 个** | 0 |
| 测试文件 | 47 个 | **57 个** | 60+ |
| Prism 编译优化 | -O1 ❌ | -O1 ❌ | -O3 |

---

## 三、Phase A (第 1-3 周): CRITICAL Bug 修复

> **目标**: 修复 17+ 个 CRITICAL bug，消除生产阻塞项。
> **原则**: 这些问题影响核心功能正确性，必须优先于所有其他工作。
> **注意**: Phase A 从 2 周扩展至 3 周，因 CRITICAL 数量翻倍。

### 任务 A.1: 修复 Restls transport 死代码

**文件**: `src/prism/stealth/restls/transport.cpp:138-142`

**问题**: 无条件错误返回块导致 Restls 协议完全不工作。

**步骤**:
1. 删除 line 139-142 的无条件 `{ ec = ...; co_return std::nullopt; }` 块
2. 恢复 `record_length` 解析和后续读取逻辑
3. 添加 TLS 记录长度上限校验（16384 + AEAD tag）
4. 补充 `tests/Restls.cpp` 传输层测试

---

### 任务 A.2: 修复 AEAD `open_output_size` 无符号下溢

**文件**: `include/prism/crypto/aead.hpp:194-198`

**步骤**:
```cpp
[[nodiscard]] static constexpr auto open_output_size(std::size_t ciphertext_len) noexcept
    -> std::size_t
{
    if (ciphertext_len < tag_length()) return 0;
    return ciphertext_len - tag_length();
}
```

同时修复 `seal()` 中 nonce 溢出检测时机（`src/prism/crypto/aead.cpp:104-121`）——在 `EVP_AEAD_CTX_seal` 之前检查 nonce。

---

### 任务 A.3: 修复 TrustTunnel SSL_CTX ALPN 变异

**文件**: `src/prism/stealth/trusttunnel/scheme.cpp:136-137`

**步骤**:
```cpp
// 替换 SSL_CTX_set_alpn_protos 为 per-SSL 设置
// 在 SSL* 上设置 ALPN，而非修改共享 SSL_CTX
SSL_set_alpn_protos(ssl_handle, reinterpret_cast<const uint8_t *>("\x2h2"), 3);
```

---

### 任务 A.4: 修复 SOCKS5 Password Auth 过度读取

**文件**: `src/prism/protocol/socks5/conn.cpp:249`

**步骤**:
1. 将 `const auto remaining = static_cast<std::size_t>(ulen + 1 + 255)` 改为分两步读取
2. 先读取 `ulen + 1` 字节（用户名 + plen 字段）
3. 根据 `auth_buffer[2 + ulen]`（即 plen）读取精确长度
4. 补充边界测试：超长用户名、超长密码、空密码

---

### 任务 A.5: 修复 TrustTunnel no-CONNECT 双重所有权 + 认证失败未停止 craft

**文件**: `src/prism/stealth/trusttunnel/scheme.cpp:222-243`

**问题 1**: 无 CONNECT 请求时，`encrypted_trans` 被移交给 result 同时 craft 的 frame_loop 仍持有该 transport。

**问题 2**: 认证失败后 co_return 但 craft 的 frame_loop 继续运行。

**步骤**:
1. 无 CONNECT 路径：先调用 `craft->stop()` 停止 frame_loop，再移交 transport
2. 认证失败路径：在 co_return 前调用 `craft->stop()` 或确保析构函数停止 frame_loop

---

### 任务 A.6: 修复 AnyTLS SOCKS 解析泄漏 + DNS SNI 悬挂

**文件**: `src/prism/stealth/anytls/scheme.cpp:361-365`、`src/prism/resolve/dns/upstream.cpp:55-57`

**AnyTLS**: SOCKS 解析失败路径缺少 `session->close()` 调用，detached recv_loop 持续运行。

**DNS**: `set_servers()` 替换 `servers_` vector 后，已有 SSL context 的 SNI arg 指针悬挂。

**步骤**:
1. AnyTLS: 在 SOCKS 解析失败的 `co_return` 前添加 `session->close()`
2. DNS: `set_servers()` 中保留旧 vector 或使用 `shared_ptr<string>` 存储 hostname

---

### 任务 A.7: 修复 detached 协程悬挂引用 + Listener 退避 + TLS 证书校验

**文件**:
- `src/prism/stealth/shadowtls/handshake.cpp:550`
- `src/prism/stealth/restls/handshake.cpp:346`
- `src/prism/instance/front/listener.cpp:119`
- `src/prism/instance/worker/tls.cpp:8-29`

**步骤**:
1. ShadowTLS/Restls: lambda 按值（shared_ptr）捕获 `client_sock`、`backend_sock`、`client_finished`
2. Listener: accept 成功后重置 `delay = min_delay`
3. TLS: 加载证书后调用 `SSL_CTX_check_private_key(native)` 验证匹配

---

### 任务 A.8: 修复热路径异常

**文件**: `include/prism/transport/snapshot.hpp:79-83`

将 `throw std::runtime_error(...)` 替换为错误码返回或默认 executor。

同时修复 `handshake_result::detected` 未初始化问题（`include/prism/stealth/scheme.hpp:109`），添加默认值 `protocol_type::unknown`。

---

### 任务 A.9: 修复 BLAKE3 keyed_hasher 初始化 + key 长度校验

**文件**: `src/prism/crypto/blake3.cpp:40, 48`

**问题**: `keyed_hasher()` 调用 `blake3_hasher_init` 而非 `blake3_hasher_init_keyed`，keyed 模式完全失效。同时无 key 长度校验，短 key 导致 OOB 读。

**步骤**:
1. 校验 `key.size() == 32`，不匹配则返回错误
2. 使用 `blake3_hasher_init_keyed(&hasher, key.data())` 替代 `blake3_hasher_init` + `blake3_hasher_update`

---

### 任务 A.10: 修复 smux/yamux SYN stream_id 冲突

**文件**: `src/prism/multiplex/smux/craft.cpp:182-189`、`src/prism/multiplex/yamux/craft.cpp`

**问题**: `handle_syn()` 不检查 stream_id 是否已存在，恶意客户端可劫持现有流。

**步骤**:
1. 在 `streams_` 中检查 stream_id 是否已存在
2. 已存在时发送 RST 帧拒绝并跳过
3. 补充 stream_id 冲突测试

---

### 任务 A.11: 修复 HTTP EOF 无限忙循环 + Trojan overconsume

**文件**:
- `src/prism/protocol/http/conn.cpp:125-130`
- `src/prism/protocol/trojan/conn.cpp:150`

**HTTP**: 读取循环不检查 `n == 0`（EOF），无限循环。

**Trojan**: 握手阶段消耗全部预读数据而非精确 Trojan 请求长度。

**步骤**:
1. HTTP: 在 read 循环中添加 `if (n == 0) break;`
2. Trojan: 根据 Trojan 请求格式精确消耗字节

---

### 任务 A.12: 修复 AnyTLS close() crash + preread 双发

**文件**:
- `src/prism/stealth/anytls/mux/transport.hpp:112-130`
- `src/prism/stealth/anytls/session.cpp:223-230`

**close()**: `channel_.reset()` 后调用 `session_->executor()` 可能返回无效引用。

**preread**: 第一个 stream 数据同时写入 `first_stream_preread_` 和 channel，导致双重投递。

**步骤**:
1. close(): 先保存 executor 再 reset channel
2. preread: 仅发送到 `first_stream_preread_`，不同时写入 channel

---

### 任务 A.13: 修复 TrustTunnel/h2mux 并发 send_pending + worker unregister

**文件**:
- `src/prism/multiplex/h2mux/craft.cpp`
- `src/prism/stats/traffic.cpp:110-140`

**send_pending**: nghttp2 session 非线程安全，并发提交帧可能交错。

**unregister**: worker 销毁后全局 registry 持有裸指针，broadcast 遍历时 use-after-free。

**步骤**:
1. h2mux: 使用 strand 序列化所有 nghttp2 操作
2. stats: 在 worker 析构时调用 `unregister_instance()`，添加 CAS 保护 register

---

### 任务 A.14: 修复 Restls write blocking 无界缓冲 + 递归读

**文件**: `src/prism/stealth/restls/transport.cpp`

**send_buf_**: `write_pending_` 时数据无限追加，无大小上限。

**递归**: `cmd_random_response` 通过递归调用 `read_restls_frame` 处理，可能栈溢出。

**步骤**:
1. 添加 `max_pending_write_size` 限制，超出返回错误
2. 将递归改为循环处理连续随机响应

---

### 任务 A.15: 移除 git 跟踪的凭据文件

**文件**: `cert.pem`、`key.pem`、`src/configuration.json`

**步骤**:
1. `git rm --cached cert.pem key.pem`
2. `.gitignore` 添加 `*.pem`、`configuration.json`
3. 创建 `configuration.example.json` 模板（脱敏）

---

### 任务 A.16: 修复 yamux CAS（已验证为误报，降级为审查）

**文件**: `src/prism/multiplex/yamux/craft.cpp:735-792`

**状态**: 第四轮审计确认为误报。CAS 循环在 `old_val < payload_size` 时退出外层循环，通过 `co_await signal->async_wait()`（line 766）正确挂起。窗口恢复时 `handle_window_update` 取消 timer 唤醒协程。无需修复。

---

## 四、Phase B (第 4-5 周): 安全加固 + 性能修复

> **目标**: 消除安全漏洞，修复性能瓶颈，补全配置校验。

### 任务 B.1: 安全加固

**涉及文件**: 多处

1. **移除证书泄露** (`cert.pem`/`key.pem`): `git rm --cached` + `.gitignore` 添加 `*.pem`
2. **Reality seal 悬挂 executor** (`seal.cpp:25-28`): 返回错误码而非临时 io_context
3. **TLS 记录长度校验** (`seal.cpp:120-123`): 添加 `> 16384 + tag` 检查
4. **TrustTunnel Basic Auth 常量时间** (`trusttunnel/scheme.cpp:96`): `CRYPTO_memcmp`
5. **Reality auth 常量时间** (`reality/util/auth.cpp:14-50`): `CRYPTO_memcmp`
6. **Reality handshake socket 泄漏** (`reality/handshake.cpp:134,172`): 使用 RAII 保护

---

### 任务 B.2: 修复 ShadowTLS/Restls 握手 detached 协程悬挂引用

**文件**:
- `src/prism/stealth/shadowtls/handshake.cpp:550`
- `src/prism/stealth/restls/handshake.cpp:346`

将 lambda 中对局部变量（`client_sock`、`backend_sock`、`client_finished`）的引用捕获改为 shared_ptr 值捕获。

> **注**: 此任务与 A.7 合并执行，实际工作量较小。

---

### 任务 B.2.1: Worker 优雅关机

**文件**: `src/prism/instance/worker/worker.cpp:64-67`

`io_context::stop()` 立即中断 run()，不等待挂起协程完成。改为排空当前批次或添加 drain 期限。

---

### 任务 B.3: 隧道缓冲区修复

**文件**: `src/prism/connect/tunnel/tunnel.cpp:26-28`

**步骤**: 将 `buffer.size() / 2` 改为分配两个独立向量，每方向完整 `buffer_size`。

---

### 任务 B.4: 移除 Prism 可执行文件的 `-O1` 编译选项

**文件**: `src/CMakeLists.txt:57-60`

删除 `target_compile_options(${PROJECT_NAME} PRIVATE -g1 -O1)` 块。

---

### 任务 B.5: 配置语义校验

**文件**: `include/prism/loader/load.hpp`

添加 `validate()` 函数，在反序列化后校验：
- `buffer.size >= 1024`
- `addressable.port` 在 1-65535 范围
- `dns.ttl_min <= dns.ttl_max`
- `pool.connect_timeout_ms > 0`
- `shadowsocks.timestamp_window > 0`
- 非空 `addressable.host`

---

### 任务 B.6: smux pending buffer 上限

**文件**: `src/prism/multiplex/smux/craft.cpp`

添加 `max_pending_buffer_size` 配置，超出则关闭 stream。

---

## 五、Phase C (第 6-7 周): 性能优化 + 功能补全

> **目标**: 完成性能优化目标，实现正向代理和 h2mux sing-mux。

### 任务 C.1: 全局内存池分片化

**文件**: `include/prism/memory/pool.hpp`

新增 `sharded_pool` 类，8-16 个分片，替换 `synchronized_pool`。

**预期**: 4T 下 3530 ns → <150 ns。

---

### 任务 C.2: SS2022 热路径优化

**文件**: `src/prism/protocol/shadowsocks/conn.cpp:559`

将 `send_chunk` 中的每包堆分配（`chunk_combined` 向量）替换为预分配的合并缓冲区或 scatter-gather write。

---

### 任务 C.3: 正向代理模式

**文件**: `src/prism/connect/dial/router.cpp`

实现 HTTP CONNECT 正向代理路径：
1. 通过连接池获取上游代理连接
2. 发送 CONNECT 请求
3. 解析响应，成功则返回连接

---

### 任务 C.4: h2mux sing-mux StreamRequest 解析

**文件**: `src/prism/multiplex/h2mux/craft.cpp:478`

实现 sing-mux 模式下首个 DATA 帧的 StreamRequest 解析，提取目标地址并建立 duct。

---

### 任务 C.5: P99 尾延迟优化

快速路径跳过健康检查、预创建连接、Eyeballs 竞态取消优化。

---

### 任务 C.6: smux/yamux 默认 buffer 提升

默认 `buffer_size` 从 4096 提升至 32768-65536。

---

## 六、Phase D (第 8-9 周): 测试补全 + 质量提升

> **目标**: 补全关键模块测试，消除代码重复，添加 CI 保护。

### 任务 D.1: 补全缺失测试

| 文件 | 测试内容 | 优先级 |
|------|---------|--------|
| `tests/RestlsTransport.cpp` | Restls 传输层（验证死代码修复） | P0 |
| `tests/Loader.cpp` | 配置加载 + 语义校验 | P0 |
| `tests/AeadBoundary.cpp` | AEAD nonce 溢出、open_output_size 边界 | P0 |
| `tests/Blake3Keyed.cpp` | BLAKE3 keyed hash key 长度校验 | P0 |
| `tests/MuxSynCollision.cpp` | smux/yamux stream_id 冲突拒绝 | P0 |
| `tests/HttpEof.cpp` | HTTP EOF 处理、Trojan overconsume | P1 |
| `tests/TrustTunnelScheme.cpp` | TrustTunnel 握手 + ALPN 隔离 | P1 |
| `tests/AnyTlsSession.cpp` | AnyTLS 会话泄漏、多 stream、preread | P1 |
| `tests/DnsUpstream.cpp` | UDP/TCP 查询、请求合并 | P1 |
| `tests/ConnectPool.cpp` | max_cache 上限、超时、并发 | P1 |
| `tests/Socks5Auth.cpp` | 密码认证边界、过读修复验证 | P1 |
| `tests/HttpForward.cpp` | Proxy-Auth 过滤、端口校验 | P1 |
| `tests/EyeballRacer.cpp` | 单/多端点竞态、超时 | P2 |

**目标**: 测试文件 57 → 70+。

---

### 任务 D.2: CI 增强

1. 添加 `push: branches: [main]` 和 `pull_request:` 触发器
2. 添加 `-Wall -Wextra -Wpedantic` 编译警告
3. 添加 Sanitizer 构建矩阵（ASan + UBSan）
4. 添加性能回归基准检测

---

### 任务 D.3: 协议处理器去重

提取 `protocol/common/` 下的共享函数：
- `verify_account()` — Trojan/VLESS 验证器
- `try_mux_bootstrap()` — mux 引导
- `resolve_target()` — 目标地址解析

---

### 任务 D.4: 消除 dynamic_cast（4 处）

**文件**: `src/prism/stealth/native.cpp`、`src/prism/stealth/executor.cpp`

在 `transmission` 基类添加 `raw_socket()` 虚方法，替换 `dynamic_cast`。

---

## 七、Phase E (第 10 周): 生产加固 + 运维完善

> **目标**: 完善运维工具链，实现剩余功能。

### 任务 E.1: 连接速率限制 + 全局连接上限

per-IP 令牌桶 + 全局 `max_total_connections` 硬限制。

---

### 任务 E.2: 监控指标系统

**已有基础**: `stats/` 模块实现了 runtime/traffic/account 统计。
- 添加 Prometheus 格式导出端点
- 添加 HTTP `/metrics` 管理端点
- 添加 `/health` 健康检查

---

### 任务 E.3: WebSocket 传输

实现 WebSocket 帧编解码（RFC 6455）。

---

### 任务 E.4: Dockerfile / 容器化

多阶段构建 + HEALTHCHECK + `.dockerignore`。

---

### 任务 E.5: 热重载配置

基于已有 `swap_config()` 添加 SIGHUP 触发。

---

### 任务 E.6: 文档更新

更新 README.md、模块文档、配置指南，反映新模块名和新增协议。

---

## 八、依赖关系图

```
Phase A (第 1-3 周): CRITICAL Bug 修复
  ├─ A.1 Restls transport 死代码 ──────────────┐
  ├─ A.2 AEAD open_output_size + nonce 时机 ────┤
  ├─ A.3 TrustTunnel SSL_CTX ALPN ──────────────┤
  ├─ A.4 SOCKS5 Password Auth 过读 ─────────────┤
  ├─ A.5 TrustTunnel 双重所有权 + craft 泄漏 ──┤
  ├─ A.6 AnyTLS SOCKS 泄漏 + DNS SNI 悬挂 ────┤
  ├─ A.7 detached 引用 + listener 退避 + TLS ──┤ 可并行
  ├─ A.8 热路径异常 + detected 初始化 ─────────┤
  ├─ A.9 BLAKE3 keyed_hasher 初始化 ───────────┤
  ├─ A.10 smux/yamux SYN collision ─────────────┤
  ├─ A.11 HTTP EOF + Trojan overconsume ────────┤
  ├─ A.12 AnyTLS close() crash + preread 双发 ─┤
  ├─ A.13 h2mux 并发 send + worker unregister ─┤
  ├─ A.14 Restls write blocking + 递归读 ──────┤
  ├─ A.15 移除 git 跟踪凭据 ───────────────────┤
  └─ A.16 Yamux CAS 审查（已确认为误报）───────┘

Phase B (第 4-5 周): 安全加固 + 性能修复
  ├─ B.1 安全加固 (证书/时序/悬挂) ─────────────┐
  ├─ B.2 detached 协程悬挂引用（与 A.7 合并）──┤ 可并行
  ├─ B.2.1 Worker 优雅关机 ────────────────────┤
  ├─ B.3 隧道缓冲区修复 ────────────────────────┤
  ├─ B.4 移除 -O1 编译选项 ─────────────────────┤
  ├─ B.5 配置语义校验 ──────────────────────────┤
  └─ B.6 smux pending buffer 上限 ──────────────┘

Phase C (第 6-7 周): 性能优化 + 功能补全
  ├─ C.1 内存池分片化 ──────────────────────────┐
  ├─ C.2 SS2022 热路径优化 ─────────────────────┤ 可并行
  ├─ C.3 正向代理模式 ──────────────────────────┤
  ├─ C.4 h2mux sing-mux StreamRequest ──────────┤
  ├─ C.5 P99 尾延迟优化 ────────────────────────┤
  └─ C.6 smux/yamux buffer 提升 ────────────────┘

Phase D (第 8-9 周): 测试补全 + 质量提升
  ├─ D.1 补全缺失测试 (10 个新测试) ────────────┐
  ├─ D.2 CI 增强 (警告/Sanitizer/性能回归) ─────┤ 可并行
  ├─ D.3 协议处理器去重 ────────────────────────┤
  └─ D.4 消除 dynamic_cast ─────────────────────┘

Phase E (第 10 周): 生产加固 + 运维完善
  ├─ E.1 速率限制 + 连接上限 ───────────────────┐
  ├─ E.2 监控指标导出 ──────────────────────────┤ 可并行
  ├─ E.3 WebSocket 传输 ────────────────────────┤
  ├─ E.4 Dockerfile ────────────────────────────┤
  ├─ E.5 热重载配置 ────────────────────────────┤
  └─ E.6 文档更新 ──────────────────────────────┘
```

---

## 九、风险评估与缓解

| 任务 | 风险等级 | 具体风险 | 缓解措施 |
|------|---------|---------|---------|
| A.1 Restls transport | 低 | 删除死代码可能暴露更多问题 | 完整传输层测试覆盖 |
| A.3 SSL_CTX ALPN | 低 | per-SSL ALPN 设置可能需要 BoringSSL 特定 API | 验证 `SSL_set_alpn_protos` 在 BoringSSL 上可用 |
| A.5 TrustTunnel 双重所有权 | 低 | 需确认 craft stop 机制 | 检查 craft 析构函数 |
| A.6 AnyTLS/DNS 泄漏 | 低 | 两处修复独立 | 分别验证 |
| A.7 detached 引用 | 中 | 修改 lambda 捕获可能影响握手时序 | 保留现有超时逻辑 |
| A.9 BLAKE3 keyed | 低 | 修复简单 | 单元测试验证 |
| A.10 SYN collision | 中 | 需验证 stream_id 分配策略 | 检查客户端行为规范 |
| A.12 AnyTLS close/preread | 高 | close 时序敏感，修复可能引入新竞态 | 使用 strand 保护，详细测试 |
| A.13 h2mux 并发 | 高 | nghttp2 线程安全需仔细处理 | strand 序列化 + 压力测试 |
| A.14 Restls write blocking | 中 | 需确保 flush 逻辑不丢数据 | 循环 flush 直到清空 |
| B.2.1 Worker 优雅关机 | 中 | 需设计 drain 期限 | 参考信号处理模式 |
| C.1 内存池分片 | 低 | 分片间碎片化 | 分片数 8-16，fallback 到 synchronized_pool |
| C.3 正向代理 | 中 | HTTP CONNECT 解析可复用 HTTP parser | 提取通用 HTTP 响应解析 |
| C.4 h2mux sing-mux | 中 | StreamRequest 格式需从客户端规范获取 | 参考sing-box实现 |

---

## 十、完成后状态

本计划完成后的预期状态：

| 维度 | 当前 | 目标 |
|------|------|------|
| CRITICAL Bug | 17+ 个 | 0 个 |
| HIGH 问题 | 32 个 | <5 个 |
| 活跃 TODO | 2 个 | 0 个 |
| `dynamic_cast` | 4 处 (connect/util.hpp + transmission.hpp) | 0 处 |
| Prism 编译优化 | -O1 | -O3 |
| 优雅关闭 | ✅ | ✅ |
| 监控指标 | 内部统计 | Prometheus 导出 |
| 测试文件 | 57 个 | 70+ 个 |
| CI | 基础构建 | 警告+Sanitizer+性能回归 |
| 正向代理 | 死代码 | HTTP CONNECT 实现 |
| h2mux sing-mux | 丢帧 | 完整实现 |
| WebSocket | 0% | 完整实现 |
| 速率限制 | 缺失 | per-IP + 全局上限 |
| Dockerfile | 缺失 | 多阶段构建 |
| 安全评分 | 6.5/10 | 9/10 |

---

## 十一、与上层架构计划的关系

本 10 周计划聚焦于 **CRITICAL Bug 修复 + 安全加固 + 性能优化 + 功能补全**，不涉及以下更大规模的架构变更：

| 上层功能 | 与本计划关系 |
|----------|-------------|
| Outbound 出站代理抽象 | 独立，可在本计划完成后启动 |
| Traffic Controller 流量调度器 | 独立 |
| Rule 规则引擎 | 独立 |
| Proxy Group 代理组 | 依赖 Outbound 抽象 |
| QUIC / Hysteria2 / TUIC | 独立大工程 |
| REST API | E.2 指标系统为其打基础 |
| TUN / WireGuard / VMess | 独立大工程 |
| ECH HPKE | 低优先级，可延后 |
| VLESS XTLS/Vision | 独立 |

本计划完成后的状态：CRITICAL Bug 清零、性能达标、安全加固、核心功能补全，为后续大规模架构变更奠定坚实基础。
