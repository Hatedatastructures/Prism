# ShadowTLS v3 协议文档

> **未启用**：当前 `is_enabled()` 硬编码返回 `false`。ShadowTLS v3 尚未调通，文档为设计稿，实际功能不可用。

## 1. 协议概述

### 1.1 规范参考

ShadowTLS 是由 @ihciah 提出的 TLS 伪装方案，通过将代理流量包装为正常的 TLS 连接来对抗深度包检测（DPI）。Prism 实现的是 ShadowTLS **v3** 版本，完全参照 [sing-shadowtls](https://github.com/sagernet/sing-shadowtls) 的 `v3_server.go` 逻辑。

ShadowTLS 规范并非 IETF 标准，而是社区协议。主要参考来源：

- **ShadowTLS v3 协议说明**：[github.com/ihciah/shadowtls](https://github.com/ihciah/shadowtls)
- **sing-shadowtls 实现**：[github.com/sagernet/sing-shadowtls](https://github.com/sagernet/sing-shadowtls)
- **RFC 8446** — TLS 1.3 协议（ShadowTLS 利用标准 TLS 格式承载认证信息）
- **RFC 2104** — HMAC（认证机制的基础）

### 1.2 与 v1/v2 的对比

| 特性 | v1 | v2 | v3 (Prism 实现) |
|------|----|----|------------------|
| 认证阶段 | 无（任意客户端可用） | TLS 握手阶段 | TLS 握手阶段 |
| 认证方式 | 无 | HMAC-SHA1 (SessionID) | HMAC-SHA1 (SessionID, 多用户) |
| 后端连接 | 每次握手都连接 | 每次握手都连接 | 握手阶段连接，完成后断开 |
| 数据传输 | TLS 透传 | XOR 加密 + HMAC | XOR 加密 + HMAC |
| 用户支持 | 单用户 | 单用户 | **多用户**（每用户独立密码） |
| 安全性 | 低 | 中 | 高 |

### 1.3 核心设计思想

ShadowTLS 的核心思想是**两层 TLS 连接**：

1. **外层**：与服务端建立标准 TLS 连接，外观与正常 HTTPS 完全一致
2. **内层**：通过 HMAC-SHA1 认证和 XOR 加密，在 TLS 通道内嵌入代理协议

关键创新在于**认证发生在 TLS 握手阶段**，通过篡改 ClientHello 的 SessionID 字段来嵌入 4 字节 HMAC 标签。合法客户端知道如何构造带 HMAC 的 SessionID，非法客户端（或检测器）看到的是标准 TLS 连接。

### 1.4 密码学原语

| 原语 | 算法 | 规范 | 用途 |
|------|------|------|------|
| 认证标签 | HMAC-SHA1 | RFC 2104 | ClientHello SessionID 认证 + 数据帧认证 |
| 数据加密 | SHA256 循环 XOR | FIPS 180-4 | Application Data 载荷混淆 |
| 哈希 | SHA-256 | FIPS 180-4 | WriteKey 派生 |

**注意**：ShadowTLS 不使用 AEAD 加密。数据帧的 XOR 加密仅提供基本的混淆，真正的安全性依赖于外层 TLS 通道的加密。HMAC 用于认证而非加密。

### 1.5 与 Reality 的区别

| 特性 | Reality | ShadowTLS v3 |
|------|---------|--------------|
| TLS 实现 | 自定义 TLS 1.3 握手 | 标准 TLS（后端提供） |
| 证书 | 目标网站真实证书 / 合成证书 | 后端服务器证书（标准 CA 签发） |
| 认证位置 | X25519 + short_id (session_id) | HMAC-SHA1 (session_id) |
| 认证强度 | X25519 ECDH + short_id | HMAC-SHA1 4 字节标签 |
| 回退行为 | 透明代理到 dest | 认证失败则拒绝连接 |
| 后端连接 | 仅在回退时连接 | 握手阶段必须连接 |
| 数据加密 | TLS 1.3 AEAD | XOR + 外层 TLS |
| 多用户 | 不支持 | 支持 |

## 2. 二进制协议格式

### 2.1 TLS 记录层格式

ShadowTLS 使用标准 TLS 记录格式，所有数据都封装在 TLS 记录中：

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+---------------+---------------+
|  ContentType  |    Version    |           Length              |
|    (1 byte)   |    (2 bytes)  |          (2 bytes)            |
+---------------+---------------+---------------+---------------+
|                         Payload (Length bytes)                |
|                                                               |
+---------------+---------------+---------------+---------------+
```

### 2.2 ClientHello 认证格式（SessionID 嵌入 HMAC）

ShadowTLS v3 在 TLS ClientHello 的 SessionID 字段中嵌入 4 字节 HMAC 标签：

```text
ClientHello SessionID (固定 32 字节):
+---------------------------------------------------------------+
|              前 28 字节              |    HMAC (4 bytes)       |
|  (ClientHello[10:hmac_index] 的      |  HMAC-SHA1(password,   |
|   部分 + 零填充)                     |  ClientHello 去 HMAC)  |
|                                      |  [:4]                  |
+---------------------------------------------------------------+
```

**HMAC 计算方式**（完全参照 sing-shadowtls `verifyClientHello`）：

```text
1. 取完整 ClientHello 帧（含 5 字节 TLS 记录头）
2. 去掉 TLS 记录头（前 5 字节），得到 handshake 消息
3. 将 SessionID 中 HMAC 位置（最后 4 字节）填零
4. 计算: HMAC = HMAC-SHA1(password, modified_client_hello)[:4]
5. 将 HMAC 写入 SessionID 的最后 4 字节
```

**关键偏移量**（定义在 `constants.hpp`）：

```text
TLS Header(5) + Handshake Header(4) + Version(2) + Random(32) + SessionID_Len(1) = 44
SessionID 32 字节，HMAC 在最后 4 字节:
  - SessionID 长度字节偏移: session_id_length_index = 43
  - HMAC 在 SessionID 中的偏移: hmac_index = 43 + 1 + 32 - 4 = 72
  - HMAC 在完整帧中的偏移: 72
```

### 2.3 握手阶段数据帧格式

握手完成后（ServerHello 返回后），客户端和服务端之间的数据传输使用带 HMAC 认证的帧格式：

**客户端 -> 服务端（认证方向）**：

```text
+---------------------------------------------------------------+
|    TLS Record Header    |    HMAC (4B)    |     Payload        |
|    (5 bytes)            |  HMAC-SHA1(     |  (TLS Application |
|  Type=0x17, Ver, Len    |   password,     |   Data)           |
|                         |   serverRandom  |                   |
|                         |   + "C"         |                   |
|                         |   + payload)    |                   |
|                         |   [:4]          |                   |
+---------------------------------------------------------------+
```

**服务端 -> 客户端（加密 + 认证方向）**：

```text
+---------------------------------------------------------------+
|    TLS Record Header    |    HMAC (4B)    |   XOR Payload      |
|    (5 bytes)            |  HMAC-SHA1(     |  SHA256(password   |
|  Type=0x17, Ver, Len    |   password,     |   + serverRandom)  |
|  (更新后的长度)          |   serverRandom  |   XOR original    |
|                         |   + "S"         |   payload         |
|                         |   + modified)   |                   |
|                         |   [:4]          |                   |
+---------------------------------------------------------------+
```

### 2.4 完整握手帧结构

```text
Step 1: Client -> Server
+---------------------------------------------------------------+
| TLS ClientHello (含 HMAC SessionID)                           |
| [TLS Header 5B] [Handshake ~200B]                             |
+---------------------------------------------------------------+

Step 2: Server -> Backend
+---------------------------------------------------------------+
| TLS ClientHello (原样转发)                                    |
+---------------------------------------------------------------+

Step 3: Backend -> Server
+---------------------------------------------------------------+
| TLS ServerHello (后端证书握手响应)                            |
+---------------------------------------------------------------+

Step 4: Server -> Client
+---------------------------------------------------------------+
| TLS ServerHello (原样转发)                                    |
+---------------------------------------------------------------+

Step 5: 握手阶段数据交换（双工）
+---------------------------------------------------------------+
| Client -> Backend: 非认证帧原样转发                           |
| Client -> Server:  认证帧（HMAC 匹配）                         |
| Backend -> Client: 修改帧（XOR + HMAC）                        |
+---------------------------------------------------------------+
```

### 2.5 TLS 常量

| 常量 | 值 | 描述 |
|------|-----|------|
| `tls_header_size` | 5 | TLS 记录头长度 |
| `tls_random_size` | 32 | TLS Random 长度 |
| `tls_session_id_size` | 32 | ShadowTLS 要求的 SessionID 长度 |
| `hmac_size` | 4 | HMAC 标签长度 |
| `tls_hmac_header_size` | 9 | TLS Header (5) + HMAC (4) |
| `content_type_handshake` | 0x16 | TLS 握手记录类型 |
| `content_type_application_data` | 0x17 | TLS 应用数据记录类型 |
| `content_type_alert` | 0x15 | TLS Alert 记录类型 |
| `content_type_change_cipher_spec` | 0x14 | TLS CCS 记录类型 |
| `handshake_type_client_hello` | 0x01 | ClientHello 握手类型 |
| `handshake_type_server_hello` | 0x02 | ServerHello 握手类型 |
| `tls_version_1_3` | 0x0304 | TLS 1.3 版本号 |
| `extension_supported_versions` | 43 | Supported Versions 扩展类型 |
| `session_id_length_index` | 43 | ClientHello 中 SessionID 长度字节偏移 |
| `hmac_index` | 71 | HMAC 在 ClientHello 帧中的偏移 |

## 3. Prism 架构

### 3.1 协议检测与接入

ShadowTLS 作为 stealth scheme 接入 Prism 的协议检测流程：

```text
TCP 连接进入
    |
    v
预读数据
    |
    v
detect_tls()?
  (0x16 0x03 0x01/0x03)
    |
    v
+-------------------+
| ShadowTLS Scheme  |
| (stealth layer)   |
+-------------------+
    |
    +-- shadowtls::handshake(ctx, cfg)
    |     |
    |     +-- 读取 ClientHello
    |     +-- 验证 HMAC (多用户匹配)
    |     +-- 认证成功:
    |     |     +-- 连接后端
    |     |     +-- 转发 ClientHello
    |     |     +-- 返回 ServerHello
    |     |     +-- 双工握手阶段
    |     |     +-- 提取首帧
    |     +-- 认证失败: 返回 error
    |
    +-- 认证成功:
    |     +-- 内层协议检测 (首帧)
    |     +-- 创建 preview 对象
    |
    +-- 认证失败:
          +-- 返回 tls 协议类型
          +-- 交给下一个 scheme 处理
```

### 3.2 Prism 架构中的位置

```text
  Front Layer
  listener -> balancer
       |
       v
  Worker Layer
  worker -> launch
       |
       v
  Session Layer
  session -> probe (预读数据 -> TLS 检测)
       |
       +-- detect_tls() == true
       |      |
       |      v
       |   stealth::shadowtls::scheme::execute()
       |      |
       |      +-- stealth::shadowtls::handshake(ctx, cfg)
       |             |
       |             +-- [authenticated] -> 内层协议检测
       |             |                       preview(transport, first_frame)
       |             |                       -> dispatch handler
       |             |
       |             +-- [not authenticated] -> protocol_type::tls
       |                                        -> 下一个 scheme
       |
       +-- detect_tls() == false -> 非 TLS 协议
```

### 3.3 当前状态

**注意**：ShadowTLS scheme 当前被**显式禁用**：

```cpp
// scheme.cpp:14-17
auto scheme::is_enabled([[maybe_unused]] const psm::config &cfg) const noexcept -> bool
{
    // 暂时禁用：ShadowTLS v3 尚未调通，后续完善
    return false;
}
```

虽然 handshake 和 auth 模块已完整实现，但 scheme 的 `is_enabled()` 始终返回 `false`，因此实际运行中 ShadowTLS 不会被触发。

## 4. 调用层次结构

### 4.1 完整握手调用链

```text
session::run()
  |
  +-- session::sniff_protocol()
  |     +-- protocol::analysis::detect_tls()
  |
  +-- stealth::shadowtls::scheme::execute()
        |
        +-- stealth::shadowtls::handshake(ctx, cfg)
              |
              +-- [Step 1] read_tls_frame(client_sock)
              |     +-- async_read(5 bytes)  // TLS 记录头
              |     +-- 解析 length 字段
              |     +-- async_read(length bytes)  // payload
              |     +-- 返回完整 TLS 帧
              |
              +-- [Step 2] 多用户 HMAC 验证
              |     +-- if cfg.version == 3:
              |     |     +-- for user in cfg.users:
              |     |           +-- verify_client_hello(frame, user.password)
              |     |                 +-- 最小长度检查 (>= 76 bytes)
              |     |                 +-- content_type == 0x16?
              |     |                 +-- handshake_type == 0x01?
              |     |                 +-- session_id_len == 32?
              |     |                 +-- 构建 hmac_data (去掉 TLS header, HMAC 位填零)
              |     |                 +-- compute_hmac(password, hmac_data)
              |     |                 +-- CRYPTO_memcmp(client_tag, expected, 4)
              |     |                 +-- 匹配 -> 记录 matched_user, break
              |     |     +-- 无匹配 -> 返回 permission_denied
              |     +-- else (v2 兼容):
              |           +-- verify_client_hello(frame, cfg.password)
              |
              +-- [Step 3] 建立后端连接
              |     +-- parse handshake_dest (host:port)
              |     +-- resolver.async_resolve(host, port)
              |     +-- async_connect(backend_sock, endpoints)
              |     +-- 连接失败 -> 返回 connection_refused
              |
              +-- [Step 4] 转发 ClientHello 到后端
              |     +-- async_write(backend_sock, client_hello_frame)
              |
              +-- [Step 5] 读取后端 ServerHello
              |     +-- read_tls_frame(backend_sock)
              |     +-- 读取失败 -> 返回 connection_aborted
              |
              +-- [Step 6] 转发 ServerHello 到客户端
              |     +-- async_write(client_sock, server_hello_frame)
              |
              +-- [Step 7] 提取 ServerRandom
              |     +-- extract_server_random(server_hello_frame)
              |     |     +-- 验证 TLS header + handshake header
              |     |     +-- 偏移 5+1+3+2 = 11 字节处读取 32 字节
              |     +-- 提取失败 -> 返回 protocol_error
              |
              +-- [Step 7b] TLS 1.3 版本检查 (严格模式)
              |     +-- if cfg.strict_mode:
              |     |     +-- is_server_hello_tls13(server_hello_frame)
              |     |           +-- 遍历 ServerHello 扩展
              |     |           +-- 查找 supported_versions (ext_type=43)
              |     |           +-- 检查 version == 0x0304
              |     |     +-- 不支持 TLS 1.3 -> 返回 protocol_not_supported
              |
              +-- [Step 8] 双工握手阶段
              |     |
              |     +-- 后台协程: relay_backend_to_client_modified()
              |     |     +-- compute_write_key(password, server_random)
              |     |     |     +-- SHA256(password + server_random)
              |     |     |
              |     |     +-- while true:
              |     |           +-- read_tls_frame(backend_sock)
              |     |           +-- if content_type == application_data:
              |     |           |     +-- xor_with_key(payload, write_key)
              |     |           |     +-- compute_write_hmac(password, server_random, modified_payload)
              |     |           |     +-- 构建新帧: [TLS header][HMAC 4B][XOR payload]
              |     |           |     +-- async_write(client_sock, 3-part scatter)
              |     |           +-- else:
              |     |                 +-- async_write(client_sock, 原样转发)
              |     |
              |     +-- 前台: read_until_hmac_match()
              |           +-- while true:
              |           |     +-- read_tls_frame(client_sock)
              |           |     +-- if content_type == application_data
              |           |        && frame.size() > tls_hmac_header_size:
              |           |           +-- 提取客户端 HMAC (TLS header 后 4 字节)
              |           |           +-- payload = frame[tls_hmac_header_size:]
              |           |           +-- verify_frame_hmac(password, server_random, payload, client_hmac)
              |           |           |     +-- HMAC-SHA1(password, serverRandom + "C" + payload)[:4]
              |           |           +-- 匹配:
              |           |           |     +-- 剥离 HMAC 头，返回帧
              |           |           +-- 不匹配:
              |           |                 +-- async_write(backend_sock, 原样转发)
              |
              +-- [Step 9] 清理后端连接
              |     +-- backend_sock.shutdown(shutdown_both)
              |     +-- backend_sock.close()
              |
              +-- 返回 handshake_result {
                    authenticated = true,
                    client_first_frame = 首帧数据,
                    matched_user = 用户名,
                    error = success
                  }
```

### 4.2 Scheme 执行调用链

```text
scheme::execute(ctx)
  |
  +-- stealth::shadowtls::handshake(*ctx.session, cfg)
  |
  +-- if hs.authenticated:
  |     +-- first_frame = hs.client_first_frame
  |     +-- if !first_frame.empty():
  |     |     +-- inner_view = string_view(first_frame)
  |     |     +-- result.detected = protocol::analysis::detect_tls(inner_view)
  |     |           +-- 检查内层协议是否为 TLS
  |     |     +-- if result.detected != unknown:
  |     |           +-- result.transport = preview(inbound, first_frame)
  |     |           +-- result.preread = first_frame
  |     |     +-- else:
  |     |           +-- result.preread = first_frame
  |     +-- trace::debug("Authenticated (user: {}), inner protocol: {}", ...)
  |
  +-- else:
  |     +-- result.detected = protocol_type::tls
  |     +-- trace::debug("Not ShadowTLS, pass to next scheme")
```

### 4.3 认证函数调用链

```text
verify_client_hello(client_hello_span, password)
  |
  +-- 最小长度检查: >= tls_header_size(5) + 1 + 3 + 2 + 32 + 1 + 32 = 76
  +-- content_type == 0x16?
  +-- handshake_type == 0x01?
  +-- session_id_len == 32?
  +-- 构建 hmac_data:
  |     +-- 拷贝 client_hello[tls_header_size:] 到 hmac_data
  |     +-- 计算 hmac_offset = session_id_length_index + 1 + 32 - 4 - 5 = 67
  |     +-- memset(hmac_data[hmac_offset:], 0, 4)
  +-- expected = compute_hmac(password, hmac_data)
  |     +-- HMAC(EVP_sha1(), password, data, result, &len)
  |     +-- 返回前 4 字节
  +-- client_tag = raw[client_hmac_offset:client_hmac_offset+4]
  |     +-- client_hmac_offset = session_id_length_index + 1 + 32 - 4 = 72
  +-- CRYPTO_memcmp(expected, client_tag, 4) == 0?
```

## 5. 生命周期时序图

### 5.1 认证成功完整时序

```text
Client                  Prism Server              Backend Server
  |                         |                          |
  |-- TLS ClientHello ---->|                          |
  |  (SessionID w/ HMAC)   |                          |
  |                         | [verify_client_hello]    |
  |                         |  遍历用户, 匹配 HMAC     |
  |                         |  -> 用户 "alice" 匹配    |
  |                         |                          |
  |                         | [connect backend]        |
  |                         |------------------------->|
  |                         |  TCP CONNECT             |
  |                         |<-------------------------|
  |                         |  Connected               |
  |                         |                          |
  |                         | [forward ClientHello]    |
  |                         |------------------------->|
  |                         |  TLS ClientHello         |
  |                         |                          |
  |                         | [read ServerHello]       |
  |                         |<-------------------------|
  |                         |  TLS ServerHello         |
  |                         |                          |
  |<-- TLS ServerHello ---- |                          |
  |                         |                          |
  |=== 握手阶段数据交换 (双工) ===|                          |
  |                         |                          |
  |-- App Data (no HMAC) ->|---- App Data ----------->|
  |-- App Data (no HMAC) ->|---- App Data ----------->|
  |                         |                          |
  |<-- App Data (XOR+HMAC)- |<--- App Data -----------|
  |<-- App Data (XOR+HMAC)- |<--- App Data -----------|
  |                         |                          |
  |-- App Data (w/ HMAC) ->|                          |
  |  [HMAC 匹配!]           |                          |
  |                         | [close backend]          |
  |                         |------------------------->|
  |                         |  shutdown + close        |
  |                         |                          |
  |<-- handshake_result ----|                          |
  |  authenticated=true     |                          |
  |  first_frame=内层协议    |                          |
  |                         |                          |
  |  <== 内层代理协议 =====>|                          |
```

### 5.2 认证失败时序

```text
Client                  Prism Server
  |                         |
  |-- TLS ClientHello ---->|
  |  (无 HMAC 或错误密码)    |
  |                         |
  |                         | [verify_client_hello]
  |                         |  遍历所有用户
  |                         |  -> 无匹配
  |                         |
  |<-- error: permission    |
  |     denied              |
  |                         |
  |  [连接关闭]              |
```

### 5.3 HMAC 匹配循环时序

```text
Client                  Prism Server              Backend
  |                         |                          |
  |-- App Data Frame 1 --->|                          |
  |  (no HMAC)             |  [verify_frame_hmac]      |
  |                         |  -> 不匹配                |
  |                         |---- App Data Frame 1 --->|
  |                         |                          |
  |-- App Data Frame 2 --->|                          |
  |  (no HMAC)             |  [verify_frame_hmac]      |
  |                         |  -> 不匹配                |
  |                         |---- App Data Frame 2 --->|
  |                         |                          |
  |-- App Data Frame 3 --->|                          |
  |  (w/ HMAC)             |  [verify_frame_hmac]      |
  |                         |  -> 匹配!                 |
  |                         |  [关闭后端]               |
  |                         |---- FIN ---------------->|
  |                         |                          |
  |<-- handshake complete --|                          |
  |  first_frame = Frame 3  |                          |
  |  (stripped HMAC)        |                          |
```

## 6. 十六进制帧示例

### 6.1 ClientHello 认证帧（v3）

```text
假设:
  Password: "my_secret_password"
  SessionID: 32 bytes (前 28 字节随机 + 后 4 字节 HMAC)

Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
------  -----------------------------------------------
0000    16 03 01 01 2C                                   <- TLS Record Header
        ^^ ^^ ^^ ^^^^ ^^^^
        |  |  |  |    +-- Length: 0x012C (300 bytes)
        |  |  |  +-- Version: 0x01 (TLS 1.0 in record)
        |  |  +-- ContentType high byte
        |  +-- ContentType: 0x16 (Handshake)
0005    01 00 01 28                                      <- Handshake: ClientHello, len=296
0009    03 03                                            <- Version: TLS 1.2 (0x0303)
000B    [32 bytes Client Random]                         <- 随机数
002B    20                                               <- SessionID Length: 32
002C    AA BB CC DD EE FF 00 11 22 33 44 55 66 77 88 99  <- SessionID (前 28 字节)
003C    AA BB CC DD EE FF 00 11 22 33 44 55 66 77
004C    DE AD BE EF                                      <- HMAC (4 bytes)
        ^^^^^^^^^^^^
        HMAC-SHA1(password, ClientHello with HMAC zeroed)[:4]
0050    00 04                                            <- Cipher Suites Length
0052    13 01 13 02                                      <- TLS_AES_128_GCM, TLS_AES_256_GCM
0056    01 00                                            <- Compression Methods
0058    [Extensions]
        +-- SNI, Key Share, Supported Versions, etc.
```

**HMAC 计算过程**（十六进制步骤）：

```text
1. 取完整帧 [0000..004F] (76 bytes 最小)
2. 去掉 TLS header (前 5 字节): [0005..004F]
3. 将 HMAC 位置 (偏移 72-75) 填零:
   [..., 0x66, 0x77, 0x00, 0x00, 0x00, 0x00]
4. HMAC-SHA1("my_secret_password", modified_data)
5. 取结果前 4 字节: 0xDE 0xAD 0xBE 0xEF
6. 写入 SessionID 最后 4 字节
```

### 6.2 握手阶段数据帧（客户端 -> 服务端，HMAC 认证）

```text
Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
------  -----------------------------------------------
0000    17 03 03 00 20                                   <- TLS Record Header
        ^^ ^^ ^^ ^^^^ ^^^^
        |  |  |  |    +-- Length: 0x0020 (32 bytes)
        |  |  |  +-- Version: 0x0303
        |  |  +-- ContentType high
        |  +-- ContentType: 0x17 (Application Data)
0005    AB CD EF 01                                      <- HMAC (4 bytes)
        ^^^^^^^^^^^^
        HMAC-SHA1(password, serverRandom + "C" + payload)[:4]
0009    [27 bytes TLS Application Data payload]          <- 实际代理数据
        (可能是内层 TLS ClientHello 或其他协议数据)
```

### 6.3 握手阶段数据帧（服务端 -> 客户端，XOR + HMAC）

```text
Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
------  -----------------------------------------------
0000    17 03 03 00 24                                   <- TLS Record Header
        ^^ ^^ ^^ ^^^^ ^^^^
        |  |  |  |    +-- Length: 0x0024 (36 = 4 HMAC + 32 payload)
        |  |  |  +-- Version: 0x0303
        |  |  +-- ContentType high
        |  +-- ContentType: 0x17 (Application Data)
0005    12 34 56 78                                      <- HMAC (4 bytes)
        ^^^^^^^^^^^^
        HMAC-SHA1(password, serverRandom + "S" + XOR_payload)[:4]
0009    XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX     <- XOR 加密的 payload
        (原始 payload XOR SHA256(password + serverRandom))
        [16 bytes 示例]
0019    XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX
        [16 bytes 示例]
```

### 6.4 ServerRandom 提取示意

```text
ServerHello 帧:
0000    16 03 03 00 50                                   <- TLS Record Header
0005    02 00 00 4C                                      <- Handshake: ServerHello, len=76
0009    03 03                                            <- Version: TLS 1.2
000B    AA BB CC DD EE FF ...                            <- ServerRandom (32 bytes)
        ^^^^^^^^^^^^^^^^
        偏移 = 5(record) + 1(hs_type) + 3(hs_len) + 2(ver) = 11
        ServerRandom = frame[11:43]
002B    20                                               <- SessionID Length
002C    ...                                              <- SessionID
```

## 7. 配置参数

### 7.1 JSON 配置结构

```json
{
  "stealth": {
    "shadowtls": {
      "version": 3,
      "password": "legacy_v2_password",
      "users": [
        { "name": "alice", "password": "alice_secret" },
        { "name": "bob", "password": "bob_secret" }
      ],
      "handshake_dest": "www.google.com:443",
      "strict_mode": true,
      "handshake_timeout_ms": 5000
    }
  }
}
```

### 7.2 参数详解

| 参数 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `version` | int | `3` | 协议版本。3 为 v3（多用户），2 为 v2 兼容模式（单密码） |
| `password` | string | 空 | v2 兼容模式密码。version=2 时使用，version=3 时忽略 |
| `users` | user[] | 空 | v3 多用户列表。每个用户有 name 和 password。至少配置一个用户 |
| `handshake_dest` | string | 必填 | 握手后端目标（`host:port` 格式）。握手阶段连接的 TLS 服务器 |
| `strict_mode` | bool | `true` | 严格模式。启用时要求后端必须支持 TLS 1.3（检查 supported_versions 扩展） |
| `handshake_timeout_ms` | uint32 | `5000` | 握手超时（毫秒）。整个握手阶段的最大允许时间 |

### 7.3 用户结构

```cpp
struct user
{
    std::string name;     // 用户名称（日志和匹配用）
    std::string password; // 认证密码（HMAC 密钥）
};
```

每个用户独立的 HMAC 密钥。客户端使用对应用户的 password 计算 HMAC，服务端遍历用户列表尝试匹配。

## 8. 认证算法详解

### 8.1 ClientHello HMAC 验证

```text
verify_client_hello(client_hello, password):

  1. 长度检查: len >= 76 (最小 ClientHello)
  2. 类型检查: content_type == 0x16, handshake_type == 0x01
  3. SessionID 检查: session_id_len == 32

  4. 构建待 HMAC 数据:
     a. 拷贝 client_hello[5:] 到 buffer (去掉 TLS header)
     b. 计算 HMAC 在 buffer 中的偏移:
        hmac_offset = session_id_length_index + 1 + 32 - 4 - 5
                    = 43 + 1 + 32 - 4 - 5
                    = 67
     c. 将 buffer[hmac_offset:hmac_offset+4] 填零

  5. 计算 HMAC:
     expected = HMAC-SHA1(password, buffer)[:4]

  6. 提取客户端 HMAC:
     client_tag = client_hello[72:76]

  7. 恒定时间比较:
     return CRYPTO_memcmp(expected, client_tag, 4) == 0
```

### 8.2 数据帧 HMAC 验证

```text
verify_frame_hmac(password, server_random, payload, client_hmac):

  1. 初始化 HMAC-SHA1 上下文:
     HMAC_Init_ex(ctx, password, EVP_sha1())

  2. 分步更新:
     HMAC_Update(ctx, server_random)    // 32 bytes
     HMAC_Update(ctx, "C")              // 1 byte (客户端方向标记)
     HMAC_Update(ctx, payload)          // 可变长度

  3. 完成计算:
     md = HMAC_Final(ctx)[:4]

  4. 恒定时间比较:
     return CRYPTO_memcmp(md, client_hmac, 4) == 0
```

### 8.3 服务端写入 HMAC

```text
compute_write_hmac(password, server_random, payload):

  1. 初始化 HMAC-SHA1 上下文

  2. 分步更新:
     HMAC_Update(ctx, server_random)    // 32 bytes
     HMAC_Update(ctx, "S")              // 1 byte (服务端方向标记)
     HMAC_Update(ctx, payload)          // XOR 加密后的 payload

  3. 完成计算:
     return HMAC_Final(ctx)[:4]
```

### 8.4 写入密钥派生

```text
compute_write_key(password, server_random):

  1. 初始化 SHA-256 上下文

  2. 分步更新:
     SHA256_Update(ctx, password)       // 密码
     SHA256_Update(ctx, server_random)  // 32 bytes

  3. 完成计算:
     return SHA256_Final()              // 32 bytes

注意: 常量名为 write_key_size = 64，但 SHA256 输出实际为 32 字节。
     XOR 操作使用 key[i % key.size()] 循环，因此 32 字节密钥
     可以对任意长度的 payload 进行 XOR 加密。
```

## 9. 边缘情况与错误处理

### 9.1 客户端 HMAC 验证失败

```text
情况: 所有用户的 HMAC 都不匹配
条件: 遍历 users 列表，verify_client_hello 全部返回 false
处理: 返回 std::errc::permission_denied
影响: 连接被拒绝，客户端无响应
安全: 不返回具体哪个用户不匹配，防止枚举攻击
```

### 9.2 后端连接失败

```text
情况: handshake_dest 不可达
条件: async_connect 返回错误
处理: 返回 std::errc::connection_refused
影响: 客户端连接被断开
缓解: 配置可靠的后端服务器
```

### 9.3 ServerRandom 提取失败

```text
情况: ServerHello 帧格式异常
条件: extract_server_random 检测到帧太短或类型不匹配
处理: 返回 std::errc::protocol_error
影响: 握手终止
原因: 后端服务器返回非标准 ServerHello
```

### 9.4 TLS 1.3 严格模式检查失败

```text
情况: strict_mode=true 但后端不支持 TLS 1.3
条件: is_server_hello_tls13() 返回 false
处理: 返回 std::errc::protocol_not_supported
影响: 握手终止
缓解: 使用支持 TLS 1.3 的后端服务器
```

### 9.5 HMAC 匹配超时

```text
情况: read_until_hmac_match() 循环中客户端持续发送非认证帧
条件: 客户端不断发送不带 HMAC 的 Application Data
处理: 后端连接断开后循环终止
影响: 握手阶段无限延长
缓解: 配置 handshake_timeout_ms 超时
```

### 9.6 后端连接过早断开

```text
情况: relay_backend_to_client_modified 循环中后端断开
条件: read_tls_frame(backend_sock) 返回 nullopt
处理: 后台协程退出
影响: 后续后端帧不再转发到客户端
备注: 前端协程（read_until_hmac_match）仍继续运行
```

### 9.7 空用户列表

```text
情况: version=3 但 users 列表为空
条件: for user in cfg.users 不执行任何迭代
处理: matched_user 保持空 -> permission_denied
影响: 所有连接被拒绝
缓解: 至少配置一个用户
```

### 9.8 v2 兼容模式

```text
情况: version=2
处理: 使用 cfg.password 而不是 users 列表
认证: verify_client_hello(frame, cfg.password)
用户: matched_user = "default"
备注: v2 不区分多用户，所有客户端共享同一密码
```

### 9.9 并发安全

```text
Handshake: 每个连接独立执行，无共享状态
Backend sock: 每个连接独立的后端 socket
Background coroutine: co_spawn(detached) 启动，生命周期独立
HMAC 计算: 使用 OpenSSL 的 HMAC_CTX，每个调用独立上下文
无全局状态: 所有数据都在函数局部变量或连接上下文
```

## 10. 性能特征

### 10.1 后端连接开销

ShadowTLS v3 在握手阶段**必须**建立到后端服务器的 TCP 连接：

```text
握手阶段:
  1. Client -> Server: 读取 ClientHello (1 RTT)
  2. Server -> Backend: CONNECT (1 RTT)
  3. Backend -> Server: 连接确认 (0 RTT)
  4. Server -> Backend: 转发 ClientHello (0 RTT)
  5. Backend -> Server: 返回 ServerHello (1 RTT)
  6. Server -> Client: 转发 ServerHello (0 RTT)
  7. 握手阶段数据交换 (N RTT, 直到 HMAC 匹配)
  8. Server -> Backend: 关闭连接

总计: ~3-5 RTT + 握手阶段数据交换
```

握手完成后，后端连接被关闭，后续代理流量不再经过后端。

### 10.2 XOR 加密开销

数据帧的 XOR 加密使用 SHA256 派生的 32 字节密钥循环异或：

```text
XOR 加密:
  write_key = SHA256(password + server_random)  // 32 bytes
  for i in 0..payload_len:
      encrypted[i] = payload[i] ^ write_key[i % 32]

时间复杂度: O(n)，n 为 payload 长度
空间复杂度: O(1)，无需额外缓冲区
```

注意：XOR 加密不提供密码学安全性。真正的安全性由外层 TLS 通道保证。

### 10.3 Scatter-Gather 写入

服务端到客户端的修改帧使用 scatter-gather I/O：

```text
async_write(client_sock, [
  [TLS header] (5 bytes),
  [HMAC tag] (4 bytes),
  [XOR payload] (variable)
])
```

减少内存拷贝和系统调用次数。

## 11. 与其他协议的交互

### 11.1 与内层协议的关系

ShadowTLS 认证成功后，首帧数据交给内层协议分析器：

```text
ShadowTLS handshake -> first_frame
    |
    v
protocol::analysis::detect_tls(first_frame)
    |
    +-- TLS -> 内层也是 TLS（可能是嵌套代理）
    +-- 其他 -> 未知协议
    |
    v
创建 preview(transport, first_frame)
    |
    v
dispatch handler (HTTP/SOCKS5/etc.)
```

### 11.2 与标准 TLS 的关系

ShadowTLS 认证失败时，流量被标记为标准 TLS 协议类型，交由下一个 stealth scheme 处理：

```text
ShadowTLS handshake -> not authenticated
    |
    v
result.detected = protocol_type::tls
    |
    v
下一个 scheme (如 Reality)
```

### 11.3 与后端服务器的关系

后端服务器对 ShadowTLS 完全透明：

- 后端只看到标准的 TLS ClientHello 和 ServerHello
- 后端不知道自己是 ShadowTLS 的后端
- 后端证书由标准 CA 签发，无特殊标记
- 握手完成后后端连接被关闭，不参与后续代理

这使得任何标准 HTTPS 服务器都可以作为 ShadowTLS 的后端。
