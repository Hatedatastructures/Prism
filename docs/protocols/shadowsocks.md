# Shadowsocks 2022 (SIP022) 协议文档

本文档包含 Shadowsocks 2022 (SIP022) 协议的完整规范以及 Prism 内的实现细节。

---

## 第一部分：协议规范

### 1. 协议概述

Shadowsocks 2022（SIP022）是 Shadowsocks 协议的最新版本，采用 AEAD（Authenticated Encryption with Associated Data）加密，使用 BLAKE3 进行密钥派生，内置时间戳重放保护和 salt 池检测。与 Trojan/VLESS 等依赖外层 TLS 的协议不同，SS2022 自身提供完整的数据加密层，所有数据（包括握手和数据传输）都经过 AEAD 加密。

**核心特点**：
- **自加密**：协议自身提供 AEAD 加密，不依赖外层 TLS
- **BLAKE3 密钥派生**：PSK + salt 通过 BLAKE3 派生会话密钥
- **重放保护**：时间戳窗口 + salt 池双重防护
- **AEAD 加密**：支持 AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305 三种 AEAD 加密算法
- **持续加密**：relay 在整个会话生命周期内保持活跃，所有数据持续加解密

**协议参数**：
- **加密算法**：2022-blake3-aes-128-gcm / 2022-blake3-aes-256-gcm / 2022-blake3-chacha20-poly1305
- **密钥长度**：16 字节（AES-128）或 32 字节（AES-256 或 ChaCha20-Poly1305，通过 method 字段区分）
- **认证方式**：预共享密钥（PSK），Base64 编码
- **Salt 长度**：与 PSK 长度一致（16 或 32 字节）
- **AEAD Tag**：16 字节

**与 Trojan/VLESS 的关键差异**：

| 特性 | Trojan | VLESS | SS2022 |
|------|--------|-------|--------|
| 加密 | 无，依赖 TLS | 无，依赖 TLS/REALITY | 自身 AEAD 加密 |
| 认证 | SHA224 哈希 | UUID | PSK + AEAD 解密验证 |
| Relay 生命周期 | 握手后释放 | 握手后释放 | 全程活跃（AEAD 加解密） |
| 重放保护 | 无 | 无 | 时间戳 + Salt 池 |
| 头部格式 | 文本 + CRLF | 纯二进制 | AEAD 加密二进制 |

### 2. 完整会话流程

```
阶段 1: TCP 连接建立
    客户端 -> TCP SYN -> 服务端
    客户端 <- TCP SYN+ACK <- 服务端
    客户端 -> TCP ACK -> 服务端

阶段 2: SS2022 握手
    客户端 -> [ClientSalt] -> 服务端
    服务端: Salt 重放检查（salt_pool::check_and_insert）
    服务端: 派生解密上下文 (PSK + ClientSalt → BLAKE3 → AEAD key)
    客户端 -> [加密固定头 + 加密变长头] -> 服务端
    服务端: AEAD 解密固定头 (type + timestamp + varHeaderLen)
    服务端: 时间戳窗口验证（默认 30 秒）
    服务端: AEAD 解密变长头 (地址 + padding + 初始 payload)
    服务端 -> [ServerSalt + 加密响应头 + 加密空payload] -> 客户端

阶段 3: AEAD 分帧数据传输
    客户端 <==> AEAD 加密流 <==> 服务端 <==> 目标服务器

阶段 4: 连接关闭
    任一方 -> TCP FIN -> 对方
```

### 3. 二进制头部格式

#### 3.1 请求格式

```
+-------------+-----------------------+---------------------------+
| ClientSalt  | EncryptedFixedHeader  | EncryptedVariableHeader   |
| 16/32 bytes | 27 bytes (11+16 tag)  | varHeaderLen+16 bytes     |
+-------------+-----------------------+---------------------------+

ClientSalt:
    长度由 PSK 决定（16 或 32 字节），随机生成，用于密钥派生

EncryptedFixedHeader（27 字节 = 11 明文 + 16 tag）:
    AEAD 解密后:
    +------+-----------+-------------+
    | type | timestamp | varHeaderLen|
    | 1B   | 8B        | 2B          |
    +------+-----------+-------------+
    type:         1字节, 0x00 = request
    timestamp:    8字节, Unix 时间戳（大端序）
    varHeaderLen: 2字节, 变长头明文长度（大端序）

EncryptedVariableHeader（varHeaderLen + 16 字节）:
    AEAD 解密后:
    +------+--------+------+-----------+--------+
    | ATYP | ADDR   | PORT | paddingLen| padding| initialPayload |
    | 1B   | 变长   | 2B   | 2B        | NB     | 剩余字节       |
    +------+--------+------+-----------+--------+
    ATYP:         1字节, 地址类型
    ADDR:         变长, 目标地址（长度由 ATYP 决定）
    PORT:         2字节, 目标端口（大端序）
    paddingLen:   2字节, 填充长度（大端序）
    padding:      NB, 随机填充字节
    initialPayload: 剩余字节, 首批用户数据（可能为空）
```

#### 3.2 响应格式

```
+-------------+-------------------------------+---------------------+
| ServerSalt  | EncryptedResponseFixedHeader  | EncryptedEmptyPayload|
| 16/32 bytes | 1+8+key_salt_len+2+16 bytes   | 16 bytes (tag only) |
+-------------+-------------------------------+---------------------+

ServerSalt:
    服务端随机生成，用于派生加密上下文

EncryptedResponseFixedHeader:
    AEAD 加密前:
    +------+-----------+--------------+-----------+
    | type | timestamp | requestSalt  | paddingLen|
    | 1B   | 8B        | 16/32B       | 2B (=0)   |
    +------+-----------+--------------+-----------+
    type:        1字节, 0x01 = response
    timestamp:   8字节, 服务端时间戳（大端序）
    requestSalt: 16/32字节, 客户端 salt 原样回传
    paddingLen:  2字节, 固定为 0

EncryptedEmptyPayload:
    16 字节 AEAD tag（加密空数据），SIP022 规范要求响应固定头后
    必须跟一个 AEAD 块
```

#### 3.3 AEAD 分帧格式（数据传输阶段）

```
读取流程:
    +---------------------+----------------------+
    | EncryptedLengthBlock| EncryptedPayloadBlock|
    | 18 bytes (2+16 tag) | payloadLen+16 bytes  |
    +---------------------+----------------------+

    EncryptedLengthBlock（18 字节 = 2 明文 + 16 tag）:
        AEAD 解密后: payloadLength(2B, 大端序)

    EncryptedPayloadBlock（payloadLength + 16 字节）:
        AEAD 解密后: payload(payloadLength B)

写入流程:
    1. 明文 payloadLength(2B) → AEAD seal → 18B 密文
    2. 明文 payloadData → AEAD seal → payloadLen+16B 密文
    3. scatter-gather 写入两个密文块
```

### 4. 地址类型（与 SOCKS5/Trojan 相同）

| 值 | 名称 | 地址长度 | 说明 |
|----|------|----------|------|
| 0x01 | IPv4 | 4 字节 | IPv4 地址 |
| 0x03 | Domain | 1 + N 字节 | 域名地址（1 字节长度前缀 + 域名） |
| 0x04 | IPv6 | 16 字节 | IPv6 地址 |

#### 4.1 IPv4 地址 (ATYP=0x01)

```
格式:
+--------+---------------+
| ATYP   | IPv4 Address  |
|  01    |    4 bytes    |
+--------+---------------+

示例: 连接 8.8.8.8
    0x01 0x08 0x08 0x08 0x08
    ATYP=IPv4, ADDR=8.8.8.8
```

#### 4.2 域名地址 (ATYP=0x03)

```
格式:
+--------+--------+------------+
| ATYP   | Length | Domain     |
|  03    | 1 byte | N bytes    |
+--------+--------+------------+

示例: 连接 example.com
    0x03 0x0B "example.com"
    ATYP=Domain, Length=11, Domain="example.com"

注意:
- Length 最大为 255
- 域名不包含 NULL 终止符
- 域名不含端口号
```

#### 4.3 IPv6 地址 (ATYP=0x04)

```
格式:
+--------+---------------+
| ATYP   | IPv6 Address  |
|  04    |   16 bytes    |
+--------+---------------+

示例: 连接 2001:db8::1
    0x04 0x20 0x01 0x0D 0xB8 0x00 0x00 0x00 0x00
         0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01
    ATYP=IPv6, ADDR=2001:db8::1
```

### 5. 密钥派生

```
输入:
    PSK: 预共享密钥（16 或 32 字节）
    salt: ClientSalt 或 ServerSalt（与 PSK 等长）

过程:
    key_material = PSK || salt
    key = BLAKE3-derive-key(
        context = "shadowsocks 2022 session subkey",
        key_material,
        output_length = key_salt_length
    )

结果:
    AES-128-GCM: 16 字节 AEAD key
    AES-256-GCM: 32 字节 AEAD key

Prism 实现:
    // relay.cpp - derive_aead_context()
    std::vector<std::uint8_t> material(psk_.size() + salt.size());
    std::memcpy(material.data(), psk_.data(), psk_.size());
    std::memcpy(material.data() + psk_.size(), salt.data(), salt.size());
    const auto key = crypto::derive_key(kdf_context, material, key_salt_length_);

密钥使用:
    解密上下文: 使用 ClientSalt 派生，用于解密请求和数据
    加密上下文: 使用 ServerSalt 派生，用于加密响应和数据
    Nonce 管理: BoringSSL EVP_AEAD 内部自动递增（大端序），初始为全零
```

### 6. 端口格式

```
端口始终使用大端序 (高字节在前)

示例:
    端口 80:   0x00 0x50  (0x00*256 + 0x50 = 80)
    端口 443:  0x01 0xBB  (0x01*256 + 0xBB = 443)
    端口 53:   0x00 0x35  (0x00*256 + 0x35 = 53)
```

---

## 第二部分：UDP

SS2022 UDP 代理使用独立的 AEAD 分帧和重放保护机制，与 TCP relay 共享 PSK 和密钥派生逻辑，
但采用无状态逐包加解密架构，每个 UDP 数据包独立加密。

### UDP 中继架构

核心组件：
- **udp_relay** (`protocol/shadowsocks/datagram.hpp`)：无状态逐包 AEAD 加解密器，处理入站（客户端→服务端）解密和出站（服务端→客户端）加密
- **session_tracker** (`protocol/shadowsocks/tracker.hpp`)：基于 SessionID 的 UDP 会话管理，支持 TTL 过期、AEAD 上下文缓存、滑动窗口重放过滤

### 加密方案

根据加密算法不同，UDP 使用两种加密方案：

**AES-GCM 方案（AES-128-GCM / AES-256-GCM）**：
- 双层加密：AES-ECB 加密 SeparateHeader（16 字节）+ AES-GCM 加密数据体
- SeparateHeader 包含 SessionID(8B) + PacketID(8B)
- 每个 UDP 会话通过 BLAKE3 派生独立的 AEAD 上下文（与 TCP 类似，使用 SessionID 作为 salt）

**ChaCha20 方案（ChaCha20-Poly1305）**：
- 单层加密：XChaCha20-Poly1305 直接加密整个数据包
- 使用 PSK 直接作为密钥，无需额外 AEAD 上下文派生

### 重放保护

- **PacketID**：每个数据包包含 8 字节 PacketID（时间戳 + 计数器）
- **replay_window** (`protocol/shadowsocks/replay.hpp`)：滑动窗口过滤器，检测重放数据包
- 每个会话独立维护重放窗口

### 相关源码

| 文件 | 职责 |
|------|------|
| `datagram.hpp` / `datagram.cpp` | UDP 逐包 AEAD 加解密 |
| `tracker.hpp` | UDP 会话管理、AEAD 上下文缓存、TTL 过期 |
| `replay.hpp` | PacketID 滑动窗口重放过滤器 |
| `block.hpp` / `block.cpp` | AES-ECB 单块加解密（SeparateHeader） |

---

## 第三部分：Mux

**不适用。** SS2022 自身是加密传输层装饰器，不提供多路复用功能。SS2022 relay 在整个会话生命周期内保持活跃，持续处理 AEAD 加解密，因此无法在 relay 之上叠加 mux 层。

---

## 第四部分：Prism 实现

### 7. 总体入口链路

1. **连接接收**：`listener` 监听端口并接受连接，`balancer` 选择 worker 分发 socket，worker 调用 `dispatch_socket` 创建 `session`
   入口：`include/prism/agent/front/listener.hpp`，`psm::agent::front::listener` 的 accept 逻辑

2. **协议探测**：`analysis::detect()` 排除 SOCKS5(0x05)、TLS(0x16)、HTTP 后，fallback 到 `protocol_type::shadowsocks`
   入口：`src/prism/protocol/analysis.cpp`

3. **SS2022 处理器**：创建 SS2022 relay（全局 salt_pool 跨会话共享），执行 AEAD 握手
   入口：`include/prism/agent/dispatch/handlers.hpp`，`psm::agent::dispatch::Shadowsocks`

4. **协议握手**：`protocol::shadowsocks::relay::handshake` 解密请求头、验证时间戳、解析地址
   入口：`src/prism/protocol/shadowsocks/relay.cpp`

5. **Pipeline 处理**：relay 握手成功后，relay 本身作为 inbound 传给 `primitives::tunnel`
   入口：`src/prism/pipeline/protocols/shadowsocks.cpp`

6. **路由决策**：`router::async_forward` 建立上游连接
   入口：`src/prism/resolve/router.cpp`

7. **隧道转发**：`primitives::tunnel` 双向透明转发（relay 负责 AEAD 加解密）
   入口：`src/prism/pipeline/primitives.cpp`

### 8. SS2022 协议探测

SS2022 没有正特征，所有在线缆上传输的数据都是 AEAD 加密后的随机字节。Prism 采用排除法进行探测：

```cpp
// analysis.cpp - detect() 中的 SS2022 fallback
// 检测顺序:
//   1. SOCKS5 (首字节 0x05)
//   2. TLS (首字节 0x16)
//   3. HTTP (方法前缀匹配)
//   4. SS2022 fallback（排除以上后）
// SS2022 数据全是 AEAD 加密随机字节，无特征可识别。
// relay 的 handshake() 会通过 AEAD 解密验证来确认是否为合法 SS2022 连接。
return protocol_type::shadowsocks;
```

在 TLS 内层（`detect_tls`）中，探测顺序为：HTTP > VLESS > Trojan > SS2022 fallback。

**探测风险**：由于 SS2022 无正特征，排除法可能产生误判。Prism 的容错策略是：如果 relay 的 `handshake()` 中 AEAD 解密失败（密钥不匹配），则视为非 SS2022 连接并关闭。

### 9. 握手实现

#### 9.1 源文件结构

| 文件 | 说明 |
|------|------|
| `include/prism/protocol/shadowsocks/constants.hpp` | 协议常量定义（cipher_method、类型值、尺寸） |
| `include/prism/protocol/shadowsocks/message.hpp` | 地址结构和请求消息结构定义 |
| `include/prism/protocol/shadowsocks/config.hpp` | 配置结构（PSK、时间戳窗口、salt 池 TTL） |
| `include/prism/protocol/shadowsocks/format.hpp` | 地址解析、PSK 解码声明 |
| `src/prism/protocol/shadowsocks/format.cpp` | 地址解析、PSK Base64 解码实现 |
| `include/prism/protocol/shadowsocks/salt_pool.hpp` | Salt 重放检测池（线程安全，精确匹配） |
| `include/prism/protocol/shadowsocks/relay.hpp` | AEAD 中继器声明 |
| `src/prism/protocol/shadowsocks/relay.cpp` | AEAD 中继器实现（握手 + 分帧） |
| `include/prism/pipeline/protocols/shadowsocks.hpp` | Pipeline 入口声明 |
| `src/prism/pipeline/protocols/shadowsocks.cpp` | Pipeline 入口实现 |
| `include/prism/crypto/aead.hpp` | AEAD 加解密抽象（BoringSSL EVP_AEAD 封装） |
| `src/prism/crypto/aead.cpp` | AEAD 实现 |
| `include/prism/crypto/blake3.hpp` | BLAKE3 密钥派生 |
| `src/prism/crypto/blake3.cpp` | BLAKE3 实现 |

#### 9.2 握手流程 (relay::handshake)

```cpp
auto relay::handshake() -> net::awaitable<std::pair<fault::code, request>>
{
    request req;
    req.method = method_;

    // 1. PSK 校验
    if (psk_.empty())
        co_return std::pair{fault::code::invalid_psk, req};

    // 2. 读取 client salt（key_salt_length_ 字节）
    // 3. Salt 重放检查（salt_pool::check_and_insert）
    // 4. 派生解密上下文（derive_aead_context）

    // 5. read_fixed_header()
    //    - 读取 27 字节加密固定头
    //    - AEAD 解密 → type(1B) + timestamp(8B) + varHeaderLen(2B)
    //    - 验证 request_type == 0x00
    //    - 时间戳窗口验证（|client_ts - now| <= timestamp_window）

    // 6. read_variable_header(var_header_len)
    //    - 读取加密变长头
    //    - AEAD 解密 → ATYP + ADDR + PORT + padding + initialPayload
    //    - 解析目标地址和端口
    //    - 提取初始 payload（可能为空）

    // 7. send_response(client_salt, server_ts)
    //    - 生成随机 server salt
    //    - 派生加密上下文
    //    - 构建响应固定头（type=0x01 + timestamp + requestSalt + paddingLen=0）
    //    - AEAD 加密响应固定头
    //    - AEAD 加密空 payload（仅 16 字节 tag）
    //    - scatter-gather 写入: server_salt + 加密固定头 + 加密空 payload

    co_return std::pair{fault::code::success, req};
}
```

#### 9.3 关键实现细节

**relay 作为 transmission**：

relay 继承 `channel::transport::transmission`，握手后继续作为传输层提供 AEAD 分帧的读写操作。与 Trojan/VLESS 的 relay 在握手后即释放不同，SS2022 relay 在整个会话生命周期内保持活跃。

```
读取状态机:
    read_phase::header → 读取 18B 加密长度块 → AEAD 解密得到 payloadLength
    read_phase::payload → 读取 payloadLength+16B 加密 payload 块 → AEAD 解密
    → 返回数据 → 回到 header 阶段

写入:
    将数据按 max_chunk_size (16383) 分块
    → 加密 2B 长度 → 18B 密文
    → 加密 payload → payloadLen+16B 密文
    → scatter-gather 写入两个密文块
```

**relay 全程活跃的 Pipeline 集成**：

```cpp
// shadowsocks.cpp - pipeline::shadowsocks
// 关键：relay 本身作为 inbound（不 release），AEAD 加解密持续进行
co_await primitives::tunnel(
    std::static_pointer_cast<channel::transport::transmission>(agent),
    std::move(outbound), ctx);
```

relay 不调用 `agent->release()`，而是将 relay 自身的 shared_ptr 直接作为 inbound 传给 `tunnel()`。这是因为 tunnel 的所有读写操作都需要经过 relay 的 AEAD 加解密。

**匿名命名空间 helper**：

```cpp
// relay.cpp - 消除 reinterpret_cast 的类型安全 helper
namespace {
    auto as_u8(std::span<const std::byte> s) -> std::span<const std::uint8_t>;
    auto as_u8_mut(std::vector<std::byte> &v) -> std::span<std::uint8_t>;
    auto to_bytes(const auto &c) -> std::span<const std::byte>;
}
```

### 10. 错误处理

#### 10.1 错误码映射

| 场景 | fault::code | 值 | 说明 |
|------|-------------|-----|------|
| PSK 未配置或无效 | invalid_psk | 46 | PSK 为空、Base64 解码失败或长度不合法 |
| AEAD 解密固定头失败 | auth_failed | 15 | PSK 不匹配导致解密失败 |
| 请求类型错误 | bad_message | 6 | 固定头 type 不为 0x00 |
| 时间戳超出窗口 | timestamp_expired | 47 | 客户端与服务端时间差超过阈值 |
| Salt 重放 | replay_detected | 48 | ClientSalt 在 TTL 内重复使用 |
| AEAD 加密失败 | crypto_error | 45 | BoringSSL seal 操作失败 |
| AEAD 解密变长头失败 | auth_failed | 15 | 变长头解密失败 |
| 地址解析失败 | bad_message / unsupported_address | 6/20 | ATYP 无效或长度不足 |
| 网络读写失败 | connection_reset | 24 | 底层连接断开 |

#### 10.2 错误处理原则

```
协议级错误:
- 直接关闭连接（不发送错误响应，协议无错误响应格式）
- AEAD 解密失败表示 PSK 不匹配或数据被篡改，无法继续
- 记录详细日志用于诊断

安全错误:
- Salt 重放检测触发时记录安全日志 (trace::warn)
- 时间戳过期记录客户端和服务端时间戳差值
- 不向客户端泄露具体错误原因

网络级错误:
- 优雅关闭连接
- 释放 AEAD 上下文和缓冲区资源
```

---

## 第五部分：协议常量

### 11. 请求/响应类型

| 常量 | 值 | 说明 |
|------|-----|------|
| request_type | 0x00 | 请求固定头类型字节 |
| response_type | 0x01 | 响应固定头类型字节 |

### 12. 尺寸常量

| 常量 | 值 | 说明 |
|------|-----|------|
| aead_tag_len | 16 | AES-GCM 认证 tag 长度 |
| nonce_len | 12 | AES-GCM nonce 长度 |
| fixed_header_plain | 11 | 固定头明文长度 (type:1 + timestamp:8 + varHeaderLen:2) |
| fixed_header_size | 27 | 固定头密文长度 (fixed_header_plain + aead_tag_len) |
| length_block_size | 18 | 加密长度块大小 (2 + aead_tag_len) |
| max_chunk_size | 0x3FFF (16383) | 数据块最大 payload 长度 |
| session_id_len | 8 | UDP 会话 ID 长度 |
| packet_id_len | 8 | UDP 数据包 ID 长度 |
| separate_header_len | 16 | UDP SeparateHeader 长度（SessionID + PacketID） |
| method_name_chacha20 | "2022-blake3-chacha20-poly1305" | ChaCha20 加密方法名 |

### 13. 地址类型

| 常量 | 值 | 地址长度 | 说明 |
|------|-----|----------|------|
| atyp_ipv4 | 0x01 | 4 字节 | IPv4 地址 |
| atyp_domain | 0x03 | 1 + N 字节 | 域名地址 |
| atyp_ipv6 | 0x04 | 16 字节 | IPv6 地址 |

### 14. 加密算法

| cipher_method | 密钥/Salt 长度 | KDF 上下文 |
|---------------|----------------|------------|
| aes_128_gcm | 16 字节 | "shadowsocks 2022 session subkey" |
| aes_256_gcm | 32 字节 | "shadowsocks 2022 session subkey" |
| chacha20_poly1305 | 32 字节 | "shadowsocks 2022 session subkey" |

### 15. 安全参数

| 常量 | 默认值 | 说明 |
|------|--------|------|
| timestamp_window | 30 | 时间戳验证窗口（秒） |
| salt_pool_ttl | 60 | Salt 池条目生存时间（秒） |

### 16. 配置参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| psk | string | "" | Base64 编码的预共享密钥 (16B=AES-128, 32B=AES-256 或 ChaCha20) |
| method | string | "" | 加密方法名（可选，32B PSK 时用于区分 AES-256-GCM 与 ChaCha20-Poly1305） |
| enable_tcp | bool | true | 启用 TCP 代理 |
| enable_udp | bool | false | 启用 UDP 代理 |
| timestamp_window | int64 | 30 | 时间戳验证窗口（秒） |
| salt_pool_ttl | int64 | 60 | Salt 池 TTL（秒） |
| udp_idle_timeout | uint32 | 60 | UDP 会话空闲超时（秒） |

```cpp
// config.hpp
struct config
{
    memory::string psk;              // Base64 编码的 PSK
    memory::string method;           // 加密方法名（可选）
    bool enable_tcp = true;          // 是否启用 TCP 代理
    bool enable_udp = false;         // 是否启用 UDP 代理
    std::int64_t timestamp_window = 30;  // 时间戳重放窗口（秒）
    std::int64_t salt_pool_ttl = 60;     // Salt 池 TTL（秒）
    std::uint32_t udp_idle_timeout = 60; // UDP 会话空闲超时（秒）
};
```

---

## 第六部分：实现备注

### 17. 安全

#### 17.1 Salt 重放检测

```
SIP022 规范要求精确匹配的 salt 重放检测（禁止 Bloom filter）:

实现:
- salt_pool 维护精确的 salt 集合，配合 TTL 自动过期清理
- 线程安全（std::mutex 保护），可跨多个 relay 会话共享
- Pipeline 层创建全局 salt_pool 实例（static 局部变量）
- check_and_insert 原子操作：首次出现返回 true，重放返回 false

清理策略:
- 每次 check_and_insert 时顺带清理过期条目
- TTL 默认 60 秒（是 timestamp_window 30 秒的 2 倍）
```

#### 17.2 时间戳验证

```
时间戳窗口机制:
- 固定头中包含 8 字节大端序 Unix 时间戳
- 服务端计算 |client_ts - server_ts|，超过 timestamp_window 则拒绝
- 默认窗口 30 秒，防止截获的握手数据被延迟重放
- 窗口过大会增加重放攻击风险，过小会导致时钟偏移大的客户端被拒绝
```

#### 17.3 BLAKE3 密钥派生

```
密钥派生安全:
- PSK + salt 作为密钥材料，通过 BLAKE3 derive_key 派生会话密钥
- 每个 salt（客户端和服务端各一个）产生独立的 AEAD 上下文
- 解密上下文（ClientSalt 派生）和加密上下文（ServerSalt 派生）完全独立
- Nonce 由 BoringSSL EVP_AEAD 内部管理，每次 seal/open 后自动递增
```

### 18. 性能

#### 18.1 scatter-gather 写入

```
SS2022 的 AEAD 分帧产生多个不连续的密文块:
- 握手响应: server_salt + 加密固定头 + 加密空 payload（3 个块）
- 数据写入: 加密长度块 + 加密 payload 块（2 个块）

Prism 使用 scatter-gather 写入（async_write_scatter）将多个密文块
合并为一次系统调用发送，避免 Nagle 延迟和多次 write 系统调用开销。
```

#### 18.2 Salt 池清理

```
过期清理策略:
- 在每次 check_and_insert 时顺带执行 cleanup_locked()
- 避免定时器或独立清理线程的开销
- 互斥锁粒度：仅在操作期间持有，清理完成后立即释放
```

### 19. 兼容性

| 客户端 | TCP | UDP | 备注 |
|--------|-----|-----|------|
| shadowsocks-rust | ✓ | ✓ | SS2022 原生实现 |
| sing-box | ✓ | ✓ | 完整兼容 |
| Clash Meta (Mihomo) | ✓ | ✓ | 完整兼容 |
| outline | ✓ | ✓ | 完整兼容 |

### 20. 限制

```
当前不支持:
- 多路复用（SS2022 是加密传输层，无法叠加 mux）
- Shadowsocks 旧版（stream cipher / AEAD 2022 之前的版本）

协议探测局限:
- SS2022 无正特征，采用排除法探测
- 如果服务端同时启用 SS2022 和其他协议，存在误判风险
- 误判后由 relay::handshake() 的 AEAD 解密失败来纠正
```

### 21. 参考资料

- SIP022 规范: https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md
- shadowsocks-rust: https://github.com/shadowsocks/shadowsocks-rust
- sing-box 文档: https://sing-box.sagernet.org/
- Mihomo 文档: https://wiki.metacubex.one/
- BLAKE3: https://github.com/BLAKE3-team/BLAKE3
- RFC 5116: AEAD 加密接口规范
