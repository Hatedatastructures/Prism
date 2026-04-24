# Shadowsocks 2022 (SS2022) 协议文档

## 1. 协议概述

### 1.1 规范参考

Shadowsocks 2022 协议基于 [SIP022 规范](https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-specification.md) 实现。SIP022 是 Shadowsocks 协议的重大修订版，引入以下关键改进：

- **AEAD 加密**：取代早期流密码，提供认证加密（Encrypt-then-MAC）
- **BLAKE3 密钥派生**：使用 BLAKE3 HKDF 替代 HKDF-SHA1，更安全高效
- **SessionID 机制**：8 字节会话标识符，用于 UDP 关联和 TCP 连接追踪
- **时间戳防重放**：固定头中包含 Unix 时间戳，服务端执行时间窗口校验
- **Salt 唯一性**：每个连接使用唯一 salt，服务端维护 salt 池拒绝重放

### 1.2 与 SIP023/SIP024 的关系

- **SIP023**：UDP over TCP 规范，定义 UDP 数据报如何通过 TCP 传输
- **SIP024**：UDP over UDP 规范，定义独立 UDP 会话

Prism 目前实现 SIP022 TCP 部分，UDP 通过独立的 datagram 层处理。

### 1.3 支持的加密算法

| 算法标识 | AEAD 算法 | 密钥长度 | Salt 长度 | 安全级别 |
|----------|-----------|----------|-----------|----------|
| `2022-blake3-aes-128-gcm` | AES-128-GCM | 16 字节 | 16 字节 | 128 位 |
| `2022-blake3-aes-256-gcm` | AES-256-GCM | 32 字节 | 32 字节 | 256 位 |
| `2022-blake3-chacha20-poly1305` | ChaCha20-Poly1305 | 32 字节 | 32 字节 | 256 位 |

加密方法由 PSK 长度自动推断：16 字节 PSK 对应 AES-128-GCM，32 字节 PSK 对应 AES-256-GCM（默认）或 ChaCha20-Poly1305（需显式配置 `method` 字段）。

### 1.4 密码学原语

- **AEAD 加密**：AES-128/256-GCM（NIST SP 800-38D）或 ChaCha20-Poly1305（RFC 8439）
- **密钥派生**：BLAKE3 HKDF（RFC 5869 变体），context 字符串固定为 `"shadowsocks 2022 session subkey"`
- **Base64 编码**：PSK 在配置中以标准 Base64 存储，运行时解码
- **时间戳**：Unix 纪元以来的秒数（64 位有符号整数），用于防重放

## 2. 二进制协议格式

### 2.1 TCP 帧结构

SS2022 TCP 连接的完整帧结构如下：

```
+------------------+-------------------+-------------------+
|   SessionID      |       Salt        |   Fixed Header    |
|   (8 bytes)      |   (16/32 bytes)   |   (27 bytes)      |
+------------------+-------------------+-------------------+
| Variable Header  |    AEAD Chunk 1   |    AEAD Chunk 2   |
|  (var length)    |   (len+tag+n)     |   (len+tag+n)     |
+------------------+-------------------+-------------------+
```

### 2.2 SessionID（仅 UDP）

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------------------------------------------------------+
|                        SessionID (8 bytes)                     |
+---------------------------------------------------------------+
```

TCP 模式下，SessionID 不显式传输，而是由服务端内部生成用于追踪连接状态。

### 2.3 Salt

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------------------------------------------------------+
|                          Salt (16/32 bytes)                     |
|                                                               |
+---------------------------------------------------------------+
```

Salt 长度由加密方法决定：
- AES-128-GCM: 16 字节
- AES-256-GCM: 32 字节
- ChaCha20-Poly1305: 32 字节

### 2.4 固定头（Fixed Header）—— AEAD 加密

固定头使用会话密钥（由 PSK + Salt 通过 BLAKE3 HKDF 派生）进行 AEAD 加密：

```
+---------------------------------------------------------------+
|                    AEAD Encrypted Fixed Header                 |
|  +----------------+----------------+----------------------+    |
|  | Type (1 byte)  | Timestamp (8B) | VarHeaderLen (2B)    |    |
|  |     0x00       |   Unix seconds |  variable header     |    |
|  +----------------+----------------+----------------------+    |
|  +--------------------------------------------------------+    |
|  |                  AEAD Tag (16 bytes)                      |    |
|  +--------------------------------------------------------+    |
+---------------------------------------------------------------+
```

**解密前**：27 字节密文（11 字节明文 + 16 字节 AEAD Tag）
**解密后**：11 字节明文
  - `Type` (1 字节)：请求类型固定为 `0x00`，响应类型固定为 `0x01`
  - `Timestamp` (8 字节)：大端序 Unix 时间戳（秒）
  - `VarHeaderLen` (2 字节)：大端序变长头长度

### 2.5 变长头（Variable Header）—— AEAD 加密

变长头包含目标地址、填充和可选的初始 payload：

```
+---------------------------------------------------------------+
|                    AEAD Encrypted Variable Header              |
|  +----------------+----------------+----------------------+    |
|  | ATYP (1 byte)  |    Address     |    Port (2 bytes)    |    |
|  | 0x01/0x03/0x04 |  (var length)  |    big-endian        |    |
|  +----------------+----------------+----------------------+    |
|  +----------------+----------------+----------------------+    |
|  |   Padding      | Initial Payload (optional)             |    |
|  |  (var length)  |   from handshake                     |    |
|  +----------------+----------------+----------------------+    |
|  +--------------------------------------------------------+    |
|  |                  AEAD Tag (16 bytes)                      |    |
|  +--------------------------------------------------------+    |
+---------------------------------------------------------------+
```

**地址类型（ATYP）**：
- `0x01`：IPv4（地址长度 4 字节）
- `0x03`：域名（1 字节长度 + 域名字节）
- `0x04`：IPv6（地址长度 16 字节）

**端口**：2 字节大端序

**填充**：可变长度，用于对齐或混淆

### 2.6 AEAD 数据块（Chunk）

SS2022 使用分块传输，每个 AEAD Chunk 由加密的长度字段和加密的 payload 组成：

```
+---------------------------------------+
|        AEAD Chunk (repeated)          |
|  +-------------------------------+    |
|  |  Encrypted Length (2+16 bytes) |    |
|  |  +--------------------------+  |    |
|  |  | PayloadLen (2B, LE)      |  |    |
|  |  | AEAD Tag (16 bytes)      |  |    |
|  |  +--------------------------+  |    |
|  +-------------------------------+    |
|  +-------------------------------+    |
|  |  Encrypted Payload            |    |
|  |  +--------------------------+  |    |
|  |  | Data (PayloadLen bytes)  |  |    |
|  |  | AEAD Tag (16 bytes)      |  |    |
|  |  +--------------------------+  |    |
|  +-------------------------------+    |
+---------------------------------------+
```

**长度字段**：
- 2 字节小端序（LE）payload 长度
- 最大值为 `0x3FFF`（16383 字节），遵循 SIP022 规范
- 长度字段本身也被 AEAD 加密并附加 16 字节 Tag
- 总长度块大小：`2 + 16 = 18` 字节

**Payload**：
- 实际传输数据
- 每个块最多 16383 字节
- 数据被 AEAD 加密并附加 16 字节 Tag

### 2.7 完整 TCP 握手帧（ASCII 十六进制示意）

```
Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII
------  -----------------------------------------------  -----
000000  SS SS SS SS SS SS SS SS  SL SL SL SL SL SL SL SL  SSSSSSSSSLLLLLLL
000010  SL SL SL SL SL SL SL SL  SL SL SL SL SL SL SL SL  LLLLLLLLLLLLLLLL  <- Salt (16/32B)
000020  SL SL SL SL SL SL SL SL                          LLLLLLLL
000020/ A0 B1 C2 D3 E4 F5 A6 B7  C8 D9 EA FB 0C 1D 2E 3F  ................  <- Fixed Header (enc)
000030  40 51 62 73 84 95 A6 B7  C8 D9                    @Qbs........
00003B  V0 V1 A0 B1 C2 D3 E4 F5  A6 B7 01 00 50 00 00 00  V0..............P...  <- Var Header (enc)
00004B  P1 P2 P3 P4 ...          PP PP PP PP              PPPP....
```

### 2.8 UDP 数据报格式

```
+------------------+-------------------+-------------------+
|   SessionID      |       Salt        |   Fixed Header    |
|   (8 bytes)      |   (16/32 bytes)   |   (27 bytes)      |
+------------------+-------------------+-------------------+
| Variable Header  |   PacketID (8B)   |    Payload        |
|  (var length)    |   big-endian      |   (AEAD enc)      |
+------------------+-------------------+-------------------+
```

UDP 使用 PacketID 进行重放保护，采用 WireGuard 风格的滑动窗口（64 位位图）。

### 2.9 服务端响应格式

服务端在握手成功后发送响应（可在拨号成功后延迟发送）：

```
+-------------------+-------------------+-------------------+
|       Salt        |   Fixed Header    |   AEAD Tag        |
|   (16/32 bytes)   |   (11 bytes enc)  |   (16 bytes)      |
+-------------------+-------------------+-------------------+
```

响应固定头中 `Type` 字段为 `0x01`，其余结构与请求类似。

## 3. Prism 架构

### 3.2 协议检测流程（排除法）

Shadowsocks 2022 是**无正特征协议**——其首字节是随机化的 salt，没有可识别的魔数或固定模式。因此 Prism 采用排除法（fallback）检测：

```
+----------------------------------------------------------+
|                    Session 启动                           |
|  预读 24 字节 -> 传给协议分析器                            |
+----------------------------------------------------------+
                           |
                           v
              +------------------------+
              |  detect_http()?        |
              |  检查: "GET ", "POST",  |
              |  "CONNECT", "PUT",      |
              |  "DELETE", "OPTIONS",   |
              |  "PATCH", "HEAD"        |
              +------------------------+
                 | 否            | 是
                 v               v
                 |          [HTTP Handler]
                 v
              +------------------------+
              |  detect_socks5()?      |
              |  检查: 首字节 == 0x05   |
              +------------------------+
                 | 否            | 是
                 v               v
                 |          [SOCKS5 Handler]
                 v
              +------------------------+
              |  detect_trojan()?      |
              |  检查: TLS ClientHello  |
              |  + cmd == 0x01/0x02    |
              +------------------------+
                 | 否            | 是
                 v               v
                 |          [Trojan Handler]
                 v
              +------------------------+
              |  detect_vless()?       |
              |  检查: TLS ClientHello  |
              |  + VLESS 特征          |
              +------------------------+
                 | 否            | 是
                 v               v
                 |          [VLESS Handler]
                 v
              +------------------------+
              |  detect_tls()?         |
              |  检查: TLS Handshake   |
              |  (0x16 0x03 0x01/0x03) |
              +------------------------+
                 | 否            | 是
                 v               v
                 |          [TLS/Reality]
                 v
              +------------------------+
              |  [Shadowsocks Handler] | <-- 排除法 fallback
              |  SS2022 无正特征        |
              +------------------------+
```

**关键代码路径**：
1. `src/prism/agent/launch.cpp` —— 创建 session 并启动协议检测
2. `src/prism/agent/session.cpp` —— session 生命周期管理，预读 24 字节
3. `include/prism/protocol/analysis.hpp` —— 协议分析器，逐个调用 detect_* 函数
4. `src/prism/pipeline/protocols/shadowsocks.cpp` —— SS2022 pipeline 实现

### 3.3 Prism 架构中的位置

```
  Front Layer
  listener -> balancer
       |
       v
  Worker Layer
  worker -> launch
       |
       v
  Session Layer
  session -> probe (预读 24 字节 -> 协议分析)
       |  外层 detect(): SOCKS5 → TLS → HTTP → SS2022(fallback)
       |  TLS 剥离后 detect_tls(): Trojan → VLESS → SS2022(fallback)
       v
  Dispatch Layer
  registry -> shadowsocks_handler
       |
       v
  Pipeline Layer
  shadowsocks.cpp:
    1. wrap_with_preview (重放预读数据)
    2. make_relay (创建 SS2022 加解密层)
    3. agent->handshake() (解密请求、验证时间戳、解析地址)
    4. agent->acknowledge() (发送响应)
    5. primitives::forward (隧道转发，relay 作为 inbound)
       |
       v
  Resolve Layer
  router -> 上游连接
```

### 3.4 内存模型

SS2022 热路径全部使用 PMR 分配器：

```
memory::vector<std::byte> decrypted_      // 解密缓冲区（使用帧竞技场）
memory::vector<std::byte> chunk_buf_      // chunk payload 缓冲区
memory::vector<std::uint8_t> payload_enc_buf_  // 发送加密缓冲区
memory::vector<std::byte> initial_payload_     // 握手初始 payload
```

Salt 池使用 `thread_local` 保证每个 worker 线程独立实例，无需锁：

```cpp
thread_local auto worker_salt_pool = std::make_shared<salt_pool>(ttl);
```

## 4. 调用层次结构

### 4.1 握手调用链

```
session::run()
  |
  +-- session::sniff_protocol()
  |     +-- protocol::analysis::detect_http()
  |     +-- protocol::analysis::detect_socks5()
  |     +-- protocol::analysis::detect_trojan()
  |     +-- protocol::analysis::detect_vless()
  |     +-- protocol::analysis::detect_tls()
  |     +-- fallback -> protocol_type::shadowsocks
  |
  +-- registry::global().create(protocol_type::shadowsocks)
  |
  +-- pipeline::shadowsocks(ctx, preview_data)
        |
        +-- primitives::wrap_with_preview(ctx, data, true)
        |     +-- 返回 preview 对象，包含预读的 24 字节
        |
        +-- make_relay(inbound, config, salt_pool)
        |     +-- 创建 relay 对象（继承 transmission）
        |
        +-- relay::handshake()
        |     +-- async_read(client_salt) -> 获取 salt
        |     +-- derive_aead_context(salt)
        |     |     +-- blake3_hkdf(psk, salt, kdf_context)
        |     |           +-- 返回 session_key (16/32 字节)
        |     |
        |     +-- read_fixed_header()
        |     |     +-- async_read_some(27 bytes)  // AEAD 加密固定头
        |     |     +-- aead_open(ciphertext, tag, session_key)
        |     |     |     +-- 解密出 type + timestamp + varHeaderLen
        |     |     +-- validate_timestamp(timestamp)
        |     |     |     +-- abs(now - timestamp) <= timestamp_window
        |     |     +-- salt_pool->check_and_insert(salt)
        |     |           +-- 拒绝重复 salt（防重放）
        |     |
        |     +-- read_variable_header(var_header_len, req)
        |     |     +-- async_read_some(var_header_len + 16)
        |     |     +-- aead_open(...)
        |     |     |     +-- 解密出 ATYP + Address + Port + Padding
        |     |     +-- format::parse_address_port(buffer)
        |     |     |     +-- 解析 SOCKS5 风格地址
        |     |     +-- 填充 req.method, req.port, req.destination_address
        |     |
        |     +-- 返回 {fault::code::success, req}
        |
        +-- relay::acknowledge()
        |     +-- send_response(client_salt, server_timestamp)
        |           +-- blake3_hkdf(psk, client_salt, kdf_context)
        |           +-- 构造响应固定头 (type=0x01, timestamp)
        |           +-- aead_seal(plaintext, session_key)
        |                 +-- async_write_some()
        |
        +-- primitives::forward(ctx, "SS2022", target, relay)
              +-- tunnel(inbound=relay, outbound=dest_conn)
                    +-- async_read(relay) -> 自动 AEAD 解密
                    +-- async_write(dest) -> 明文转发
```

### 4.2 数据转发调用链（握手完成后）

```
primitives::tunnel(relay, dest_conn)
  |
  +-- 正向: relay -> dest
  |     +-- relay::async_read_some(buffer, ec)
  |     |     +-- fetch_chunk(ec)
  |     |           +-- 状态机: READ_LENGTH_HEADER -> READ_PAYLOAD
  |     |           |
  |     |           +-- READ_LENGTH_HEADER:
  |     |           |     +-- async_read_some(18 bytes)  // 2B len + 16B tag
  |     |           |     +-- aead_open(length_block, session_key)
  |     |           |     +-- 解析 payload_len (LE 16 位)
  |     |           |
  |     |           +-- READ_PAYLOAD:
  |     |                 +-- async_read_some(payload_len + 16 bytes)
  |     |                 +-- aead_open(payload_block, session_key)
  |     |                 +-- 解密后数据写入 decrypted_
  |     |
  |     +-- 从 decrypted_ 拷贝明文到 tunnel 缓冲区
  |     +-- dest_conn::async_write_some(明文)
  |
  +-- 反向: dest -> relay
        +-- dest_conn::async_read_some(buffer, ec)
        +-- relay::async_write_some(明文, ec)
              +-- send_chunk(明文, ec)
                    +-- 将明文分块（每块 <= 0x3FFF）
                    +-- 构造长度块 (LE payload_len + AEAD seal)
                    +-- aead_seal(payload, session_key)
                    +-- scatter-gather write:
                          [length_block][encrypted_payload]
```

## 5. 生命周期时序图

### 5.1 完整握手时序

```
Client                  Prism Server               Upstream
  |                         |                         |
  |-- Salt + FixedHeader -->|                         |
  |  + VarHeader + Chunk -->|                         |
  |                         |                         |
  |                         | [relay::handshake()]    |
  |                         |  1. 读取 Salt            |
  |                         |  2. BLAKE3 HKDF 派生密钥  |
  |                         |  3. 解密固定头            |
  |                         |  4. 验证时间戳            |
  |                         |  5. salt_pool 查重        |
  |                         |  6. 解密变长头            |
  |                         |  7. 解析目标地址          |
  |                         |                         |
  |<-- Response (Salt + --- |                         |
  |     FixedHeader)        |                         |
  |                         |                         |
  |-- AEAD Chunk --------->|                         |
  |  (encrypted data)      |  [relay::async_read]     |
  |                         |  解密 chunk -> 明文        |
  |                         |                         |
  |                         |-- CONNECT ------------->|
  |                         |  (明文目标地址)           |
  |                         |<-- Connected ------------|
  |                         |                         |
  |<-- ACK (可选) --------- |                         |
  |                         |                         |
  |<======================>|<========================>|
  |     AEAD 加密转发         |       明文转发            |
  |<======================>|<========================>|
```

### 5.2 重放攻击防御时序

```
Attacker                Prism Server
  |                         |
  |-- [Captured SS2022] -->|
  |   Frame (replay)       |  salt_pool->check_and_insert(salt)
  |                         |  -> salt 已存在 -> 拒绝
  |                         |  返回 error，关闭连接
  |                         |
  |-- [Modified TS] ------>|
  |   Frame (new salt)     |  timestamp validation
  |                         |  abs(now - ts) > 30s -> 拒绝
  |                         |  返回 error，关闭连接
```

## 6. 十六进制帧示例

### 6.1 TCP 握手请求帧（AES-128-GCM）

```
假设:
  PSK (16 bytes, hex): 000102030405060708090a0b0c0d0e0f
  Salt (16 bytes):       101112131415161718191a1b1c1d1e1f
  目标地址:               example.com:443 (域名模式)
  时间戳:                 0x0000000065A1B2C3 (Unix 秒)

完整帧（十六进制）:

Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
------  -----------------------------------------------
0000    10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F  <- Salt (16B)
0010    [AEAD Encrypted Fixed Header - 27 bytes]           <- Type+TS+VarLen+Tag
0010    7A 8B 9C AD BE CF D0 E1 F2 03 14 25 36 47 58 69
0020    7A 8B 9C AD BE CF D0 E1 F2 03 14
002B    [AEAD Encrypted Variable Header - N bytes]         <- ATYP+Addr+Port+Pad+Tag
002B    3C 4D 5E 6F 70 81 92 A3 B4 C5 D6 E7 F8 09 1A 2B
003B    3C 4D 5E 6F 70 81 92 A3 B4 C5
0045    [AEAD Chunk 1 - Length Block]                      <- 2B len + 16B tag
0045    10 00 [16 bytes AEAD tag]
0057    [AEAD Chunk 1 - Payload]                           <- 16B data + 16B tag
0057    XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX
        [16 bytes AEAD tag]
```

**解密后的固定头明文**：

```
Offset  00 01 02 03 04 05 06 07 08 09 0A
------  ---------------------------------
0000    00 00 00 00 65 A1 B2 C3 00 1E     <- Type=0x00, TS=0x65A1B2C3, VarLen=0x001E(30)
```

**解密后的变长头明文**（30 字节 + 16 字节 Tag）：

```
Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
------  -----------------------------------------------
0000    03 0B 65 78 61 6D 70 6C 65 2E 63 6F 6D 01 BB     <- ATYP=0x03(Domain),
        ^^ ^^                                           |    Len=11("example.com"),
        |  +---- 11 bytes: "example.com"                 |    Port=0x01BB(443)
        +-- ATYP=0x03 (Domain Name)
0010    00 00 00 00 00 00 00 00 00 00 00 00 00 00       <- Padding (14 bytes)
001E    [16 bytes AEAD Tag]
```

### 6.2 UDP 数据报帧

```
Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
------  -----------------------------------------------
0000    AA BB CC DD EE FF 00 11                           <- SessionID (8B)
0008    20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F  <- Salt (16B)
0010    30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F  <- Salt (续)
0018    [AEAD Encrypted Fixed Header - 27 bytes]
0033    [AEAD Encrypted Variable Header - N bytes]
00XX    PP PP PP PP PP PP PP PP                           <- PacketID (8B, big-endian)
00XX+8  [AEAD Encrypted Payload + Tag]
```

## 7. 配置参数

### 7.1 JSON 配置结构

```json
{
  "protocol": {
    "shadowsocks": {
      "psk": "<Base64-encoded PSK>",
      "method": "2022-blake3-aes-256-gcm",
      "enable_tcp": true,
      "enable_udp": false,
      "timestamp_window": 30,
      "salt_pool_ttl": 60,
      "udp_idle_timeout": 60
    }
  }
}
```

### 7.2 参数详解

| 参数 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `psk` | string (Base64) | 必填 | 预共享密钥。16 字节 Base64 = AES-128-GCM，32 字节 = AES-256-GCM/ChaCha20 |
| `method` | string | 自动推断 | 加密方法名。32 字节 PSK 时默认推断 AES-256-GCM，显式设置 `"2022-blake3-chacha20-poly1305"` 可切换 |
| `enable_tcp` | bool | `true` | 是否启用 TCP 代理 |
| `enable_udp` | bool | `false` | 是否启用 UDP 代理 |
| `timestamp_window` | int64 | `30` | 时间戳重放窗口（秒）。客户端时间戳与服务器时间差超过此值则拒绝 |
| `salt_pool_ttl` | int64 | `60` | Salt 池条目 TTL（秒）。过期 salt 自动清理，用于防重放 |
| `udp_idle_timeout` | uint32 | `60` | UDP 会话空闲超时（秒）。无数据传输超过此值则关闭会话 |

### 7.3 生成 PSK

使用 OpenSSL 生成随机 PSK：

```bash
# AES-128-GCM (16 字节)
openssl rand -base64 16

# AES-256-GCM / ChaCha20 (32 字节)
openssl rand -base64 32
```

或使用 Prism 自带的密钥生成脚本。

## 8. 密钥派生

### 8.1 BLAKE3 HKDF 流程

SS2022 使用 BLAKE3 作为 HKDF 的基础，派生会话密钥：

```
                    PSK (16/32 bytes)
                         |
                         v
              +-----------------------+
              |  BLAKE3 HKDF-Extract  |
              |  salt = connection    |
              |       salt (16/32B)   |
              +-----------------------+
                         |
                         v
                   PRK (32 bytes)
                         |
                         v
              +-----------------------+
              |  BLAKE3 HKDF-Expand   |
              |  info = "shadowsocks  |
              |        2022 session   |
              |        subkey"        |
              |  length = 16 or 32    |
              +-----------------------+
                         |
                         v
              Session Key (16/32 bytes)
              (用于 AEAD 加解密)
```

**代码路径**：`crypto::blake3_hkdf(psk, salt, kdf_context)` -> 返回会话密钥

### 8.2 密钥生命周期

```
连接建立
    |
    +-- 读取 Salt
    +-- PSK + Salt --BLAKE3 HKDF--> Session Key (加密方向)
    +-- PSK + Salt --BLAKE3 HKDF--> Session Key (解密方向)
    |       (注意：SIP022 规范中加解密使用不同 context 派生)
    |
    +-- 使用 Session Key 解密 Fixed Header
    +-- 使用 Session Key 解密 Variable Header
    +-- 使用 Session Key 解密/加密所有 AEAD Chunks
    |
    +-- 连接关闭 -> Session Key 丢弃
```

## 9. 边缘情况与错误处理

### 9.1 时间戳校验

```
情况: 客户端时间戳超出窗口
条件: abs(server_time - client_timestamp) > timestamp_window
处理: 返回 fault::code::replay_attack_detected，关闭连接
影响: 客户端与服务器时钟偏差过大时连接被拒绝
缓解: 增大 timestamp_window（降低安全性）或同步系统时钟
```

### 9.2 Salt 重放

```
情况: 重复的 salt 被检测到
条件: salt_pool->check_and_insert(salt) 返回 false
处理: 返回 fault::code::replay_attack_detected，关闭连接
影响: 同一 salt 在 TTL 内只能使用一次
缓解: 客户端应使用随机 salt；增大 salt_pool_ttl
```

### 9.3 AEAD 解密失败

```
情况: AEAD tag 验证失败
条件: aead_context::open() 返回错误
处理: 返回 fault::code::aead_authentication_failed，关闭连接
影响: 数据被篡改或密钥不正确
```

### 9.4 地址解析失败

```
情况: 变长头中地址格式非法
条件: format::parse_address_port() 返回错误
处理: 返回 fault::code::invalid_address，关闭连接
```

### 9.5 PSK 长度不匹配

```
情况: 解码后的 PSK 长度既不是 16 也不是 32
条件: format::decode_psk() 验证失败
处理: 启动时配置加载阶段拒绝，不进入运行态
```

### 9.6 分块边界情况

```
情况: Payload 长度为零
处理: 跳过该 chunk，继续读取下一个
情况: Payload 长度超过 0x3FFF
处理: 返回 fault::code::chunk_too_large，关闭连接
情况: 连接在 chunk 中间断开
处理: 返回 fault::code::io_error，关闭连接
```

### 9.7 UDP 重放窗口溢出

```
情况: PacketID 远大于当前窗口右侧
条件: packet_id >= base_ + window_size + window_size
处理: 完全重置位图（WireGuard 规范）
影响: 允许大跳跃，但中间所有旧包将被拒绝
```

### 9.8 内存压力

```
情况: 大量并发 SS2022 连接
影响: salt_pool 持续增长
缓解: 每 1 秒触发一次 cleanup()，清理过期条目
     配置较小的 salt_pool_ttl 减少内存占用
```

### 9.9 并发安全

```
Salt 池: thread_local 实例，每个 worker 线程独立
         无需互斥锁，天然线程安全
UDP 会话: 每个会话独立持有 replay_window
          无共享状态
Relay 对象: 每个连接独立实例
            shared_from_this 保活
```

## 10. 性能特征

### 10.1 热路径分配

- `relay` 对象内部复用 `payload_enc_buf_` 避免重复分配
- `decrypted_` 缓冲区使用 PMR 竞技场分配
- `salt_pool` 使用异构查找（`string_view` 键），避免 `std::string` 构造
- `thread_local` salt 池，无锁设计

### 10.2 Scatter-Gather 写入

`send_chunk()` 使用 scatter-gather I/O 将长度块和加密 payload 合并为单次系统调用：

```
scatter-gather write:
  [iov 0]  length_block (18 bytes)
  [iov 1]  encrypted_payload (payload_len + 16 bytes)
```

减少系统调用次数，提高吞吐量。

### 10.3 延迟响应优化

`acknowledge()` 支持延迟发送——先拨号上游，成功后再发送响应。这避免了拨号失败时客户端收到误导性成功响应，与 Mihomo 行为一致。

## 11. 与其他协议的交互

### 11.1 与 TLS/Reality 的关系

当配置了 Reality 时，流量先经过 Reality 握手解密，然后内层协议可能是 SS2022。此时检测流程为：

```
TCP -> Reality 握手 -> 解密内层 -> 预读内层数据 -> 协议分析 -> SS2022 (排除法)
```

### 11.2 与多路复用的关系

SS2022 连接可以承载 smux/yamux 多路复用流。在 pipeline 中，relay 作为传输层传递给 tunnel，上层协议可协商多路复用。
