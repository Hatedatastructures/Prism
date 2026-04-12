# VLESS 协议文档

本文档包含 VLESS 协议的完整规范以及 Prism 内的实现细节。

---

## 第一部分：协议规范

### 1. 协议概述

VLESS 是由 Xray 项目设计的一种轻量级代理协议，设计目标是极简、高效、无多余特征。它本身不提供加密，依赖外层 TLS 或 REALITY 传输保障安全。用户认证通过 UUID 实现，协议头部采用纯二进制格式，无文本分隔符，解析开销极低。

**核心特点**：
- **无加密层**：协议本身不加密，依赖 TLS/REALITY 传输层提供安全性
- **UUID 认证**：使用 16 字节原始 UUID 作为用户标识
- **二进制头部**：纯二进制协议，无 CRLF 分隔符，无十六进制编码
- **极简响应**：服务端仅回复 2 字节响应（版本 + 附加信息长度）
- **多协议支持**：TCP 隧道、UDP 代理、多路复用

**协议参数**：
- **默认端口**：443（随 TLS 传输）
- **认证方式**：UUID（16 字节原始二进制，传输时以标准 UUID 字符串存储）
- **传输层**：TLS 1.2+ / REALITY（必须，VLESS 不提供自身加密）

**与 Trojan 的关键差异**：

| 特性 | Trojan | VLESS |
|------|--------|-------|
| 认证凭据 | SHA224 哈希 (56 字节十六进制) | UUID (16 字节原始二进制) |
| 头部格式 | 文本 + CRLF 分隔 | 纯二进制 |
| 响应大小 | 无响应 | 2 字节 (Version + Addons Length) |
| ATYP 值 | IPv4=0x01, Domain=0x03, IPv6=0x04 | IPv4=0x01, Domain=0x02, IPv6=0x03 |
| 加密 | 不提供，依赖 TLS | 不提供，依赖 TLS/REALITY |

### 2. 完整会话流程

```
阶段 1: TCP 连接建立
    客户端 -> TCP SYN -> 服务端
    客户端 <- TCP SYN+ACK <- 服务端
    客户端 -> TCP ACK -> 服务端

阶段 2: TLS 握手（或 REALITY）
    客户端 <-> ClientHello/ServerHello <-> 服务端
    客户端 <-> 证书验证/密钥交换 <-> 服务端
    客户端 <-> Finished <-> 服务端

阶段 3: VLESS 协议握手
    客户端 -> [Version][UUID][AddnlLen][CMD][Port][ATYP][Addr] -> 服务端
    服务端: 校验版本号 (必须为 0x00)
    服务端: 提取 UUID 并验证
    服务端: 解析命令、目标地址
    服务端 -> [0x00][0x00] -> 客户端

阶段 4: 数据传输
    客户端 <==> TLS 隧道 <==> 服务端 <==> 目标服务器

阶段 5: 连接关闭
    客户端 -> TLS close_notify -> 服务端
    客户端 -> TCP FIN -> 服务端
```

### 3. VLESS 协议头格式

#### 3.1 请求头格式

```
+---------+---------+----------+-------+------+--------+----------+----------+
| Version |  UUID   | AddnlLen |  CMD  | Port | ATYP   | DST.ADDR | AddnlInfo|
| 1 byte  | 16 bytes| 1 byte   | 1 byte| 2B   | 1 byte | Variable | Variable |
+---------+---------+----------+-------+------+--------+----------+----------+

字段说明:
    Version:   1字节, 协议版本号，固定为 0x00 (plain VLESS)
    UUID:     16字节, 用户标识，原始二进制格式（非字符串）
    AddnlLen:  1字节, 附加信息长度，plain VLESS 必须为 0x00
    CMD:       1字节, 命令类型
    Port:      2字节, 目标端口 (大端序)
    ATYP:      1字节, 地址类型
    DST.ADDR:  变长, 目标地址（长度由 ATYP 决定）
    AddnlInfo: 变长, 附加信息（plain VLESS 中不存在，AddnlLen=0）
```

#### 3.2 响应格式

```
+---------+----------+
| Version | AddonsLen |
| 1 byte  | 1 byte   |
+---------+----------+

字段说明:
    Version:   1字节, 协议版本号，固定为 0x00
    AddonsLen: 1字节, 附加信息长度，固定为 0x00

注意:
    Prism 发送 2 字节响应 [0x00][0x00]，而非仅 1 字节。
    原因：主流客户端 (mihomo/Xray/sing-box) 期望读取 2 字节响应，
    仅发送 1 字节会导致客户端将后续数据（如 smux ACK）误读为
    Addons Length，造成流偏移和解析错误。
```

#### 3.3 最小请求长度

```
最小请求长度计算 (IPv4):
    Version:   1 字节
    UUID:     16 字节
    AddnlLen:  1 字节
    CMD:       1 字节
    Port:      2 字节
    ATYP:      1 字节
    IPv4:      4 字节
    -------------------
    最小总计: 26 字节

最大请求长度计算 (域名):
    Version:   1 字节
    UUID:     16 字节
    AddnlLen:  1 字节
    CMD:       1 字节
    Port:      2 字节
    ATYP:      1 字节
    DomainLen: 1 字节
    Domain:  255 字节
    -------------------
    最大总计: 278 字节
```

### 4. 命令类型 (CMD)

| 值 | 名称 | 说明 | Prism 支持 |
|----|------|------|-----------|
| 0x01 | TCP | TCP 代理连接 | ✓ |
| 0x02 | UDP | UDP 代理 | ✗ (未实现) |
| 0x7F | MUX | 多路复用（smux/yamux） | ✓ |

### 5. 地址类型 (ATYP)

> **重要**：VLESS 的地址类型值与 Trojan/SOCKS5 不同！

| 值 | 名称 | 地址长度 | 说明 |
|----|------|----------|------|
| 0x01 | IPv4 | 4 字节 | IPv4 地址 |
| 0x02 | Domain | 1 + N 字节 | 域名地址 |
| 0x03 | IPv6 | 16 字节 | IPv6 地址 |

**对比表**：

| 地址类型 | VLESS 值 | Trojan/SOCKS5 值 |
|----------|----------|------------------|
| IPv4     | 0x01     | 0x01             |
| Domain   | 0x02     | 0x03             |
| IPv6     | 0x03     | 0x04             |

### 6. 地址格式详解

#### 6.1 IPv4 地址 (ATYP=0x01)

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

#### 6.2 域名地址 (ATYP=0x02)

```
格式:
+--------+--------+------------+
| ATYP   | Length | Domain     |
|  02    | 1 byte | N bytes    |
+--------+--------+------------+

示例: 连接 example.com
    0x02 0x0B "example.com"
    ATYP=Domain, Length=11, Domain="example.com"

注意:
- Length 最大为 255
- 域名不包含 NULL 终止符
- 域名不含端口号
```

#### 6.3 IPv6 地址 (ATYP=0x03)

```
格式:
+--------+---------------+
| ATYP   | IPv6 Address  |
|  03    |   16 bytes    |
+--------+---------------+

示例: 连接 2001:db8::1
    0x03 0x20 0x01 0x0D 0xB8 0x00 0x00 0x00 0x00
         0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01
    ATYP=IPv6, ADDR=2001:db8::1
```

### 7. 端口格式

```
端口始终使用大端序 (高字节在前)

示例:
    端口 80:   0x00 0x50  (0x00*256 + 0x50 = 80)
    端口 443:  0x01 0xBB  (0x01*256 + 0xBB = 443)
    端口 53:   0x00 0x35  (0x00*256 + 0x35 = 53)
```

### 8. 完整请求示例

#### 8.1 TCP IPv4 示例

```
连接 8.8.8.8:53，UUID = 00112233-4455-6677-8899-aabbccddeeff

请求头:
  0x00 [UUID 16B] 0x00 0x01 0x00 0x35 0x01 0x08 0x08 0x08 0x08
  |----| |--------| |---| |---| |------| |---| |-----------------|
  Ver    UUID      Addnl  TCP   53      IPv4      8.8.8.8
         16 bytes   Len

十六进制表示:
  00 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 01 00 35 01 08 08 08 08

响应:
  00 00
  |--| |--|
  Ver  AddnlLen
```

#### 8.2 TCP 域名示例

```
连接 example.com:443，UUID = 00112233-4455-6677-8899-aabbccddeeff

请求头:
  0x00 [UUID 16B] 0x00 0x01 0x01 0xBB 0x02 0x0B "example.com"
  |----| |--------| |---| |---| |------| |---| |--| |-----------|
  Ver    UUID      Addnl  TCP   443     Domain Len  "example.com"
         16 bytes   Len

十六进制表示:
  00 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF 00 01 01 BB 02 0B 65 78 61 6D 70 6C 65 2E 63 6F 6D

响应:
  00 00
```

#### 8.3 MUX 示例

```
多路复用请求，目标为 mux 标记地址

请求头:
  0x00 [UUID 16B] 0x00 0x7F 0x00 0x00 0x02 0x18 "abc123.mux.sing-box.arpa"
  |----| |--------| |---| |---| |------| |---| |--| |-----------------------|
  Ver    UUID      Addnl  MUX   0      Domain Len  "abc123.mux.sing-box.arpa"
         16 bytes   Len

注意:
    MUX 命令的端口通常为 0，地址为虚假的 mux 标记地址。
    Prism 检测到 ".mux.sing-box.arpa" 后缀后进入多路复用模式。
```

### 9. UUID 格式与认证

#### 9.1 UUID 二进制表示

```
UUID 标准格式: 00112233-4455-6677-8899-aabbccddeeff

在线缆上传输为 16 字节原始二进制（非字符串）:
  00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF

分组结构:
  time_low (4B):         00 11 22 33
  time_mid (2B):         44 55
  time_hi_and_ver (2B):  66 77
  clock_seq (2B):        88 99
  node (6B):             AA BB CC DD EE FF

Prism 内部转换:
  接收 16 字节原始二进制 -> 转为标准 UUID 字符串 -> 查询 account::directory
  格式: %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x
```

#### 9.2 UUID 验证流程

```
服务端验证流程:
1. 从请求头偏移 1-16 提取 16 字节 UUID
2. 将 UUID 字节数组转换为标准字符串格式 (8-4-4-4-12)
3. 通过 verifier 回调查询 account::directory
4. 尝试获取账户租约 (try_acquire)
5. 通过则发送响应并继续，失败则关闭连接

Prism 实现:
- 使用 account::directory 管理用户 UUID
- 支持连接数限制和流量统计
- 凭据验证失败记录日志
```

---

## 第二部分：多路复用 (Mux)

### 10. MUX 命令 (0x7F)

MUX 命令用于建立多路复用会话，允许在单个 TLS 连接上承载多个 TCP/UDP 流。

#### 10.1 MUX 触发方式

VLESS 支持两种方式触发多路复用：

```
方式 1: MUX 命令 (CMD=0x7F)
    客户端发送 CMD=0x7F 的请求，服务端识别后进入多路复用模式。

方式 2: mux 标记地址检测
    客户端发送 TCP 命令 (CMD=0x01)，但目标地址为特殊域名:
    "<random>.mux.sing-box.arpa"
    服务端检测到此后缀后进入多路复用模式。

示例:
    CMD=0x01, ATYP=0x02, Domain="abc123.mux.sing-box.arpa"
    Prism 检测: target.host.size() >= 18 &&
                target.host.substr(target.host.size() - 18) == ".mux.sing-box.arpa"
```

#### 10.2 MUX 握手流程

```
客户端发送 MUX 请求:
    0x00 [UUID 16B] 0x00 0x7F 0x00 0x00 ATYP ADDR
    或
    0x00 [UUID 16B] 0x00 0x01 0x00 0x00 0x02 0x18 "<random>.mux.sing-box.arpa"

服务端检测到 mux 标记后:
    1. 清除 session 流关闭回调（transport 生命周期由 multiplexer 接管）
    2. 通过 sing-mux 协商层确定协议（smux 或 yamux）
    3. 创建对应的多路复用会话
    4. 进入帧循环处理多路复用流
```

> smux/yamux 帧格式和完整交互流程详见 [smux 协议文档](../multiplex/smux.md) 和 [yamux 协议文档](../multiplex/yamux.md)。

---

## 第三部分：Prism 实现

### 11. 总体入口链路

1. **连接接收**：`listener` 监听端口并接受连接，`balancer` 选择 worker 分发 socket，worker 调用 `dispatch_socket` 创建 `session`
   入口：`include/prism/agent/front/listener.hpp`，`psm::agent::front::listener` 的 accept 逻辑

2. **外层协议识别**：`session::diversion` 检测到 TLS（`0x16`），执行 TLS 握手
   入口：`src/prism/agent/session/session.cpp`

3. **内层协议探测**：Session 层增量读取内层数据，调用 `analysis::detect_inner` 识别为 VLESS
   入口：`src/prism/protocol/analysis.cpp`，`psm::protocol::analysis::detect_tls`

4. **VLESS 处理器**：创建 VLESS 中继器并执行握手（TLS 已在 Session 层剥离）
   入口：`include/prism/agent/dispatch/handlers.hpp`，`psm::agent::dispatch::Vless`

5. **协议握手**：`protocol::vless::relay::handshake` 解析协议头
   入口：`src/prism/protocol/vless/relay.cpp`

6. **UUID 验证**：通过 `account::directory` 验证用户
   入口：`include/prism/agent/account/directory.hpp`

7. **路由决策**：`router::async_forward` 建立上游连接
   入口：`src/prism/resolve/router.cpp`

8. **隧道转发**：`primitives::tunnel` 双向透明转发
   入口：`src/prism/pipeline/primitives.cpp`

### 12. VLESS 协议探测

VLESS 在 TLS 内层的探测逻辑位于 `analysis::detect_tls`，在 Trojan 探测之前执行：

```cpp
// analysis.cpp - detect_tls 中的 VLESS 探测
// 检测条件 (最小 22 字节):
//   byte[0]  == 0x00 (version)
//   byte[17] == 0x00 (no additional info)
//   byte[18] in {0x01, 0x02, 0x7F} (valid command)
//   byte[21] in {0x01, 0x02, 0x03} (valid address type)
if (peek_data.size() >= 22)
{
    const auto b0  = static_cast<unsigned char>(peek_data[0]);
    const auto b17 = static_cast<unsigned char>(peek_data[17]);
    const auto b18 = static_cast<unsigned char>(peek_data[18]);
    const auto b21 = static_cast<unsigned char>(peek_data[21]);

    if (b0 == 0x00 && b17 == 0x00 &&
        (b18 == 0x01 || b18 == 0x02 || b18 == 0x7F) &&
        (b21 == 0x01 || b21 == 0x02 || b21 == 0x03))
    {
        return protocol_type::vless;
    }
}
```

**探测优先级**：HTTP > VLESS > Trojan > unknown。VLESS 探测在 Trojan 之前，因为 VLESS 的 version=0x00 不是有效的十六进制字符，不会与 Trojan 的凭据格式冲突。

### 13. VLESS 握手实现

#### 13.1 源文件结构

| 文件 | 说明 |
|------|------|
| `include/prism/protocol/vless/constants.hpp` | 版本号、命令字、地址类型枚举定义 |
| `include/prism/protocol/vless/message.hpp` | 地址结构和请求消息结构定义 |
| `include/prism/protocol/vless/format.hpp` | 协议格式编解码声明 |
| `src/prism/protocol/vless/format.cpp` | 协议格式编解码实现 |
| `include/prism/protocol/vless/config.hpp` | VLESS 配置结构（空结构体，认证已统一） |
| `include/prism/protocol/vless/relay.hpp` | VLESS 中继器声明 |
| `src/prism/protocol/vless/relay.cpp` | VLESS 中继器实现 |
| `include/prism/pipeline/protocols/vless.hpp` | VLESS 协议处理管道声明 |
| `src/prism/pipeline/protocols/vless.cpp` | VLESS 协议处理管道实现 |

#### 13.2 最小读取长度

```
最小请求长度计算:
    Version:   1 字节
    UUID:     16 字节
    AddnlLen:  1 字节
    CMD:       1 字节
    Port:      2 字节
    ATYP:      1 字节
    IPv4:      4 字节
    -------------------
    最小总计: 26 字节

实际实现分两层:
    1. relay.cpp 首次读取至少 26 字节 (k_min_request_size)
    2. 根据 ATYP 计算完整长度后补读剩余字节
       - IPv4: 26 字节 (首次读取即足够)
       - Domain: 22 + 1 + domain_len 字节
       - IPv6: 22 + 16 = 38 字节
```

#### 13.3 握手流程 (relay.cpp)

```cpp
auto relay::handshake()
    -> net::awaitable<std::pair<fault::code, request>>
{
    // 1. 分配 320 字节缓冲区（足够容纳最大 VLESS 请求 278 字节）
    std::array<std::uint8_t, 320> buffer{};

    // 2. 首次读取至少 26 字节（最小请求长度）
    //    使用受限 span 防止从 preview transport 过度消费：
    //    preview 可能包含 inner probe 的多余字节（如 sing-mux 握手 + smux 帧），
    //    限制读取量确保多余字节留在 preview 中，供后续 mux bootstrap 读取
    auto [read_ec, total] = co_await read_at_least(
        *next_layer_, byte_span.first(k_min_request_size), k_min_request_size);

    // 3. 校验版本号 (offset 0)，必须为 0x00
    if (buffer[0] != version)
        co_return std::pair{fault::code::bad_message, request{}};

    // 4. 提取 UUID (offset 1-16)
    std::memcpy(uuid.data(), buffer.data() + 1, 16);

    // 5. 校验附加信息长度 (offset 17)，plain VLESS 必须为 0
    if (buffer[17] != 0)
        co_return std::pair{fault::code::bad_message, request{}};

    // 6. 解析命令 (offset 18)
    // 7. 解析端口 (offset 19-20, 大端序)
    // 8. 解析地址类型 (offset 21)
    // 9. 根据 ATYP 计算完整请求长度并补读
    // 10. 解析目标地址

    // 11. 通过 verifier 回调验证 UUID
    if (verifier_)
    {
        const auto uuid_str = uuid_to_string(uuid);
        if (!verifier_(uuid_str))
            co_return std::pair{fault::code::auth_failed, request{}};
    }

    // 12. 发送 2 字节响应 [0x00][0x00]
    const auto response = format::make_response();
    co_await next_layer_->async_write({response.data(), response.size()}, write_ec);

    co_return std::pair{fault::code::success, std::move(req)};
}
```

#### 13.4 关键实现细节

```
缓冲区读取策略:
    首次读取: read_at_least 限制 span 为 k_min_request_size (26) 字节
    补读操作: read_remaining 限制 span 为 required_total 字节

    限制 span 的原因:
    preview transport 可能包含多个字节数据（VLESS 头 + mux 握手帧），
    如果不限制 span，会一次性消费所有数据，导致 mux bootstrap 的
    negotiate() 无法读到正确的 smux/yamux 握手帧。

    因此，每次读取都使用 byte_span.first(required) 限制读取范围，
    确保多余字节留在 preview 中供后续使用。
```

### 14. UUID 验证与统一认证

#### 14.1 UUID 转字符串

```cpp
// relay.cpp - uuid_to_string
// 将 16 字节原始 UUID 转换为标准格式: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
static auto uuid_to_string(const std::array<uint8_t, 16> &uuid) -> std::string
{
    std::array<char, 37> buf;
    static constexpr int groups[] = {4, 2, 2, 2, 6};
    // 依次将每组字节转为十六进制，组间插入 '-'
    // 结果示例: "00112233-4455-6677-8899-aabbccddeeff"
    return std::string(buf.data());
}
```

#### 14.2 统一认证流程

```cpp
// vless.cpp - pipeline::vless 中的 verifier 回调
auto verifier = [&ctx](const std::string_view credential) -> bool
{
    if (!ctx.account_directory_ptr)
    {
        trace::warn("{} account directory not configured", VlessStr);
        return false;
    }

    // 尝试获取账户租约
    // credential 为标准 UUID 字符串格式
    auto lease = account::try_acquire(*ctx.account_directory_ptr, credential);
    if (!lease)
    {
        trace::warn("{} credential verification failed", VlessStr);
        return false;
    }

    ctx.account_lease = std::move(lease);
    return true;
};
```

**统一认证架构**：
- VLESS、Trojan、HTTP、SOCKS5 共享 `account::directory` 认证体系
- VLESS 使用 UUID 字符串作为查询键
- Trojan 使用 SHA224 哈希字符串作为查询键
- 均通过 `account::try_acquire` 获取连接租约
- 租约 RAII 管理，析构时自动递减活跃连接数

### 15. 命令处理

#### 15.1 TCP 命令 (CMD=0x01)

```cpp
case protocol::vless::command::tcp:
{
    // 1. 解析目标地址
    protocol::analysis::target target(ctx.frame_arena.get());
    target.host = protocol::vless::to_string(req.destination_address, ctx.frame_arena.get());
    target.port = std::to_string(static_cast<unsigned int>(req.port));

    // 2. 检查 mux 标记（即使 CMD=TCP，地址也可能为 mux 标记地址）
    if (ctx.server.cfg.mux.enabled &&
        target.host.size() >= 18 &&
        target.host.substr(target.host.size() - 18) == ".mux.sing-box.arpa")
    {
        // 进入 smux 多路复用模式
        ctx.active_stream_close = nullptr;
        ctx.active_stream_cancel = nullptr;
        auto muxprotocol = co_await multiplex::bootstrap(agent->release(), ctx.worker.router, ctx.server.cfg.mux);
        if (muxprotocol)
            muxprotocol->start();
        co_return;
    }

    // 3. 设置正向代理标记并建立上游连接
    target.positive = true;
    trace::info("{} CONNECT -> {}:{}", VlessStr, target.host, target.port);
    auto [dial_ec, outbound] = co_await primitives::dial(router_ptr, "Vless", target, true, true);

    // 4. 进入隧道转发
    auto raw_trans = agent->release();
    co_await primitives::tunnel(std::move(raw_trans), std::move(outbound), ctx);
    break;
}
```

#### 15.2 MUX 命令 (CMD=0x7F)

```cpp
case protocol::vless::command::mux:
{
    // 处理方式与 TCP 相同
    // MUX 命令的地址通常为 mux 标记地址或任意地址
    // 进入多路复用模式后，transport 生命周期由 multiplexer 接管
    // 与 TCP 命令共享同一处理分支
    break;
}
```

#### 15.3 UDP 命令 (CMD=0x02)

```cpp
case protocol::vless::command::udp:
{
    trace::warn("{} UDP not yet supported", VlessStr);
    break;
}
```

### 16. 格式解析实现

#### 16.1 format::parse_request

```cpp
// format.cpp - 解析 VLESS 请求头
auto parse_request(std::span<const std::uint8_t> buffer) -> std::optional<request>
{
    // 1. 最小长度校验 (26 字节)
    // 2. 版本号校验 (必须为 0x00)
    // 3. 提取 UUID (offset 1, 16 字节)
    // 4. 校验附加信息长度 (必须为 0)
    // 5. 解析命令字 (TCP/UDP/MUX)
    // 6. 解析端口 (2 字节大端序)
    // 7. 根据 ATYP 解析目标地址:
    //    - 0x01: IPv4, 4 字节
    //    - 0x02: Domain, 1 + N 字节
    //    - 0x03: IPv6, 16 字节
    // 8. 设置传输形式 (UDP=datagram, 其他=stream)
    return req;
}
```

#### 16.2 format::make_response

```cpp
// format.hpp - 构建 VLESS 响应
[[nodiscard]] constexpr auto make_response() -> std::array<std::byte, 2>
{
    // 返回 [Version 0x00][Addons Length 0x00]
    // 2 字节响应确保客户端不会误读后续数据
    return {static_cast<std::byte>(version), std::byte{0x00}};
}
```

---

## 第四部分：错误处理

### 17. 错误处理

#### 17.1 错误码映射

| 场景 | fault::code | 说明 |
|------|-------------|------|
| TLS 握手失败 | tls_handshake_failed | 证书无效、协议不匹配 |
| 版本号错误 | bad_message | Version 不为 0x00 |
| 附加信息不为空 | bad_message | AddnlLen 不为 0x00（不支持 XTLS Vision） |
| UUID 验证失败 | auth_failed | UUID 未注册或账户禁用 |
| 命令不支持 | unsupported_command | 未知 CMD 值 |
| 地址不支持 | unsupported_address | 未知 ATYP 值 |
| 格式错误 | bad_message | 长度不足、解析失败 |
| 网络错误 | io_error | 连接断开、超时 |
| EOF | eof | 连接提前关闭 |

#### 17.2 错误处理原则

```
协议级错误:
- 直接关闭 TLS 连接
- 不发送错误响应（协议无错误响应格式）
- 记录详细日志

网络级错误:
- 优雅关闭连接
- 释放资源
- 通知上层

认证错误:
- 记录安全日志 (trace::warn)
- UUID 验证失败时不泄露具体原因
- 连接租约获取失败自动清理
```

---

## 第五部分：协议常量

### 18. 版本号

| 常量 | 值 | 说明 |
|------|-----|------|
| version | 0x00 | Plain VLESS，无附加功能 |

### 19. 命令类型

| 常量 | 值 | 说明 | Prism 支持 |
|------|-----|------|-----------|
| command::tcp | 0x01 | TCP 代理 | ✓ |
| command::udp | 0x02 | UDP 代理 | ✗ (未实现) |
| command::mux | 0x7F | smux/yamux 多路复用 | ✓ |

### 20. 地址类型

| 常量 | 值 | 地址长度 | 说明 |
|------|-----|----------|------|
| address_type::ipv4 | 0x01 | 4 字节 | IPv4 地址 |
| address_type::domain | 0x02 | 1 + N 字节 | 域名地址 |
| address_type::ipv6 | 0x03 | 16 字节 | IPv6 地址 |

### 21. 配置参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| config | struct | {} (空) | 认证已统一到 account::directory |

```cpp
// config.hpp
struct config
{
    // 空：用户认证已统一到 agent::authentication 中
    // VLESS 通过 account::directory 查询 UUID 凭证
};
```

---

## 第六部分：实现注意事项

### 22. 安全考虑

#### 22.1 TLS/REALITY 依赖

```
安全前提:
- VLESS 本身不加密，必须运行在 TLS 或 REALITY 之上
- 无 TLS 时 UUID 以明文传输，可被窃听和伪造
- Prism 在 Session 层完成 TLS 剥离，VLESS handler 接收已解密数据

推荐配置:
- TLS 1.3 优先
- 强密码套件: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
- 启用 OCSP Stapling

REALITY 配置:
- 无需域名和证书
- 基于 TLS 1.3 和临时密钥
- 抗主动探测
```

#### 22.2 UUID 安全

```
UUID 安全策略:
- UUID 应使用强随机生成 (版本 4)
- 不同用户使用不同 UUID
- 定期更换 UUID
- UUID 不可预测（128 位随机空间）

存储安全:
- account::directory 以 UUID 字符串为键
- 连接租约限制并发数
- 配置文件权限限制
- 日志不记录完整 UUID
```

#### 22.3 访问控制

```
连接限制 (通过 account::directory 统一管理):
- 单用户最大连接数 (entry::max_connections)
- 活跃连接原子计数 (entry::active_connections)
- RAII 租约自动释放

流量限制:
- 上传/下载流量统计 (entry::uplink_bytes / downlink_bytes)
- 原子计数，线程安全
```

### 23. 与 Trojan 的实现差异

#### 23.1 协议格式差异

```
Trojan:
    [56字节十六进制凭据] [CRLF] [CMD] [ATYP] [ADDR] [PORT] [CRLF]
    文本格式，使用 CRLF 分隔符

VLESS:
    [Version 1B] [UUID 16B] [AddnlLen 1B] [CMD 1B] [Port 2B] [ATYP 1B] [ADDR]
    纯二进制格式，无分隔符，无需 CRLF 解析

解析效率:
    VLESS 无需验证 CRLF、无需十六进制解码，解析更快
    VLESS 最小头部仅 26 字节 (vs Trojan 68 字节)
```

#### 23.2 ATYP 值差异

```
重要提醒:
    VLESS 的 ATYP 值与 Trojan/SOCKS5 不同！
    VLESS:        IPv4=0x01, Domain=0x02, IPv6=0x03
    Trojan/SOCKS5: IPv4=0x01, Domain=0x03, IPv6=0x04

    混用会导致地址解析错误，实现时需特别注意。
    Prism 中各协议有独立的 address_type 枚举定义。
```

#### 23.3 响应格式差异

```
Trojan:
    无协议响应，握手成功后直接开始数据传输

VLESS:
    必须发送 2 字节响应 [Version][AddonsLen]
    Prism 发送 [0x00][0x00]
    客户端必须读取这 2 字节后才开始发送数据
```

### 24. 兼容性

#### 24.1 客户端兼容

| 客户端 | TCP | UDP | Mux | 备注 |
|--------|-----|-----|-----|------|
| Xray-core | ✓ | ✓ | ✓ | VLESS 原生实现 |
| sing-box | ✓ | ✓ | ✓ | 完整兼容 |
| Clash Meta (Mihomo) | ✓ | ✓ | ✓ | 完整兼容 |
| v2ray (V2Fly) | ✓ | ✓ | ✗ | 部分兼容 |

#### 24.2 Mux 兼容

```
Prism smux/yamux 实现:
- 兼容 sing-box (smux/yamux 协商)
- 兼容 Mihomo / Clash Meta
- 兼容 xtaci/smux v1

MUX 标记地址检测:
- Prism 检测: <random>.mux.sing-box.arpa
- 支持 CMD=0x7F 和 CMD=0x01 + mux 标记地址两种触发方式
- 与 Trojan 共享同一套 mux bootstrap 逻辑
```

#### 24.3 限制

```
当前不支持:
- XTLS Vision (AddnlLen 必须为 0，非 0 请求直接拒绝)
- XTLS Direct / Splice
- VLESS UDP 代理 (command::udp)
- VLESS over WebSocket
- VLESS over gRPC

计划支持:
- UDP 代理 (command::udp)
```

### 25. 参考资料

- VLESS 协议设计: https://github.com/XTLS/Xray-core/blob/main/infra/conf/vless.go
- Xray-core 文档: https://xtls.github.io/
- sing-box 文档: https://sing-box.sagernet.org/
- Mihomo 文档: https://wiki.metacubex.one/
- smux 协议: https://github.com/xtaci/smux
- RFC 4122: UUID 规范
- RFC 5246: TLS 1.2
- RFC 8446: TLS 1.3
