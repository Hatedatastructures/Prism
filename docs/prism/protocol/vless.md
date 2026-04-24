# VLESS 协议规范

> Prism 代理服务器 — 协议层文档

## 1. 概述

VLESS 是 Xray 项目引入的无状态轻量级代理协议。与 VMess 不同，VLESS 不提供内置加密能力，仅定义了一个极简的二进制请求头格式，依赖外层传输（通常为 TLS）保障通信安全。Prism 中的 VLESS 实现运行在 TLS 内层，通过 UUID 进行用户认证，支持 TCP、UDP over TLS 以及多路复用三种命令模式。

### 1.1 设计原则

| 原则 | 说明 |
|------|------|
| **零附加信息** | Prism 仅支持 plain VLESS，`AddnlInfoLen` 必须为 `0x00` |
| **无 CRLF 分隔** | 与 HTTP/Trojan 不同，VLESS 是纯二进制协议，没有任何文本分隔符 |
| **零拷贝友好** | 请求结构使用 `std::variant` 地址类型，内存布局紧凑 |
| **统一认证** | UUID 验证通过 `account::directory` 统一管理，与其他协议共享连接数限制和租约机制 |

### 1.2 协议版本

当前 Prism 实现的 VLESS 协议版本固定为 `0x00`。该版本号在协议设计之初即确定为永久版本，后续不会变更。

### 1.3 与其他协议的对比

| 特性 | VLESS | Trojan | SOCKS5 |
|------|-------|--------|--------|
| 认证方式 | UUID (16B) | SHA22256(password) | None/USER-PASS |
| 请求格式 | 纯二进制 | 二进制 + CRLF | 纯二进制 |
| ATYP IPv4 | `0x01` | `0x01` | `0x01` |
| ATYP Domain | `0x02` | `0x03` | `0x03` |
| ATYP IPv6 | `0x03` | `0x04` | `0x04` |
| 响应格式 | `[0x00, 0x00]` (2B) | `HTTP/1.1 ...` + CRLF | `[0x05, 0x00, ...]` |
| UDP 封装 | ATYP+ADDR+PORT+Payload | Length+ATYP+ADDR+PORT+Payload+CRLF | FRSV+ATYP+ADDR+PORT+Payload |
| MUX 命令 | `0x7F` | `0x7F` (cmd=0x7F) | 不支持 |

---

## 2. 协议栈与分层架构

### 2.1 完整协议栈

```
+----------------------------------------------------------+
|  Application Layer (目标服务器)                              |
+----------------------------------------------------------+
|  TCP Stream / UDP Datagram                                |
+----------------------------------------------------------+
|  VLESS Protocol (TCP: 中继 | UDP: 帧封装)                    |
+----------------------------------------------------------+
|  TLS 1.3 (Reality / 标准 TLS)                              |
+----------------------------------------------------------+
|  TCP Transport (Boost.Asio ip::tcp::socket)                |
+----------------------------------------------------------+
|  Boost.Asio io_context (Worker 线程)                       |
+----------------------------------------------------------+
```

### 2.2 Prism 内部处理链路

```
  client
    |
    v
  [listener] -- 接受 TCP 连接
    |
    v
  [balancer] -- 亲和性哈希 -> 选择 worker
    |
    v
  [worker] -- io_context 投递
    |
    v
  [launch] -- 创建 session
    |
    v
  [session] -- 预读 24 字节 -> 嗅探协议
    |              TLS 握手透明剥离
    |              二次探测内层协议
    |              -> 匹配 VLESS (VER=0x00 + UUID)
    |
    v
  [dispatch::handler_table] -- handler_table[protocol_type::vless] -> vless_handler
    |
    v
  [pipeline::vless] -- wrap_with_preview (重放预读数据)
    |                     make_relay (创建中继器)
    |                     agent->handshake() (解析 + UUID 验证 + 响应)
    |
    |-- cmd=TCP  -> forward(ctx, "Vless", target, agent->release())
    |-- cmd=UDP  -> agent->async_associate(router)
    +-- cmd=MUX  -> multiplex::bootstrap(agent->release(), ...)
```

### 2.3 数据流示意

```
  Client                              Prism Server
  ------                              --------------
  TLS ClientHello                  -->
                                    <-- TLS ServerHello
  TLS Handshake (finished)       -->
  VLESS Request Header           -->  [parse_request]
                                    [uuid verification]
  [wait]                         <-- VLESS Response [0x00, 0x00]
  Application Data (TCP stream)  <---> [transparent forward]
  ...                               ...
  FIN                            -->
```

---

## 3. 二进制帧格式

### 3.1 请求头完整布局

VLESS 请求头由固定部分和可变地址部分组成，总长度取决于地址类型和域名长度。

```
+--------+--------+--------+--------+--------+--------+
| Offset | Field            | Size   | Value          |
+--------+--------+--------+--------+--------+--------+
| 0x00   | VER      | 1B   | 0x00 (固定)              |
| 0x01   | UUID     | 16B  | 用户 UUID (原始字节)      |
| 0x11   | AddnlLen | 1B   | 0x00 (Prism 仅支持 plain) |
| 0x12   | CMD      | 1B   | 0x01/0x02/0x7F           |
| 0x13   | PORT     | 2B   | 目标端口 (大端序)         |
| 0x15   | ATYP     | 1B   | 0x01/0x02/0x03           |
| 0x16   | DST.ADDR | var  | 目标地址 (见地址类型)      |
+--------+--------+--------+--------+--------+--------+
```

### 3.2 最小请求大小

```
VER(1) + UUID(16) + AddnlLen(1) + CMD(1) + PORT(2) + ATYP(1) + IPv4(4) = 26 字节
```

这是 `relay::handshake()` 中首次 `read_at_least` 的最小读取量，定义于 `relay.cpp` 第 89 行。

### 3.3 最大请求大小

```
VER(1) + UUID(16) + AddnlLen(1) + CMD(1) + PORT(2) + ATYP(1) + DomainLen(1) + Domain(255) = 278 字节
```

握手缓冲区大小为 320 字节 (`relay.cpp` 第 84 行)，留有安全余量。

### 3.4 字段详细说明

#### 3.4.1 VER -- 版本号 (1 字节)

| 偏移 | 长度 | 值 | 说明 |
|------|------|-----|------|
| 0 | 1 | `0x00` | VLESS 协议版本，固定值 |

如果客户端发送的版本号不为 `0x00`，服务端将返回 `fault::code::bad_message` 并关闭连接。

#### 3.4.2 UUID -- 用户标识 (16 字节)

| 偏移 | 长度 | 值 | 说明 |
|------|------|-----|------|
| 1 | 16 | 原始字节 | 标准 UUID-4，按 8-4-4-4-12 格式编码 |

UUID 在 wire 上以 16 字节原始二进制形式传输，不使用十六进制文本字符串。解析后通过 `uuid_to_string()` 转换为标准格式用于认证。

**UUID 字符串转换示例：**

```
原始字节 (16B):
  c3 28 f0 e5 - b1 a7 - 4c d2 - 9f 3e - 1a 8b 4c 7d 6e 2f

标准字符串:
  c328f0e5-b1a7-4cd2-9f3e-1a8b4c7d6e2f
  |----| |--| |--| |--| |------|
   4B    2B  2B  2B   6B     (8-4-4-4-12)
```

转换逻辑位于 `relay.cpp` 第 23-44 行，使用 `snprintf("%02x")` 逐字节格式化，按 `groups[] = {4, 2, 2, 2, 6}` 分组插入连字符。

#### 3.4.3 AddnlInfoLen -- 附加信息长度 (1 字节)

| 偏移 | 长度 | 值 | 说明 |
|------|------|-----|------|
| 17 | 1 | `0x00` | Prism 仅支持 plain VLESS，此值必须为 0 |

如果此值不为 `0`，`parse_request()` 和 `handshake()` 均会返回 `std::nullopt` / `bad_message`。Prism 不支持 Flow、XTLS 等带附加信息的 VLESS 变体。

#### 3.4.4 CMD -- 命令字 (1 字节)

| 值 | 枚举 | 含义 | 传输形式 |
|----|------|------|----------|
| `0x01` | `command::tcp` | TCP 代理 | `form::stream` |
| `0x02` | `command::udp` | UDP 代理 | `form::datagram` |
| `0x7F` | `command::mux` | 多路复用 | `form::stream` |

未知命令值返回 `fault::code::unsupported_command`。

#### 3.4.5 PORT -- 目标端口 (2 字节)

| 偏移 | 长度 | 编码 | 说明 |
|------|------|------|------|
| 19 | 2 | 大端序 (Network Byte Order) | 目标服务器端口号，范围 0-65535 |

解析方式：
```cpp
req.port = static_cast<uint16_t>(buffer[19]) << 8 |
           static_cast<uint16_t>(buffer[20]);
```

#### 3.4.6 ATYP -- 地址类型 (1 字节)

| 值 | 枚举 | 含义 | 地址长度 |
|----|------|------|----------|
| `0x01` | `address_type::ipv4` | IPv4 地址 | 4 字节 |
| `0x02` | `address_type::domain` | 域名 | 1B 长度 + N 字节域名 |
| `0x03` | `address_type::ipv6` | IPv6 地址 | 16 字节 |

未知地址类型返回 `fault::code::unsupported_address`。

### 3.5 地址编码详解

#### 3.5.1 IPv4 (ATYP = 0x01)

```
+------+------+------+------+
| B0   | B1   | B2   | B3   |
+------+------+------+------+
  原始字节，网络字节序 (大端)

示例: 192.168.1.100 = C0 A8 01 64
```

占用 4 字节，直接存储 IPv4 地址的四个八位组。

#### 3.5.2 域名 (ATYP = 0x02)

```
+------+--------+--------+--------+--------+
| Len  | Byte 0 | Byte 1 | ...    | Byte N |
+------+--------+--------+--------+--------+
  1B    N 字节域名内容 (ASCII/UTF-8)

示例: "example.com" (11 字符)
  0B 65 78 61 6D 70 6C 65 2E 63 6F 6D
  |-| |-------------------------------|
  Len  "example.com"
```

长度字段为 1 字节，因此域名最大长度为 255 字符。长度不能为 0，否则解析失败。

#### 3.5.3 IPv6 (ATYP = 0x03)

```
+------+------+ ... +------+
| B0   | B1   |     | B15  |
+------+------+ ... +------+
  原始字节，16 字节

示例: ::1 (loopback)
  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
```

占用 16 字节，直接存储 IPv6 地址的十六个八位组。

### 3.6 响应格式

VLESS 服务端响应固定为 2 字节：

```
+------+------+
| 0x00 | 0x00 |
+------+------+
  VER  AddonsLen
```

**为什么是 2 字节而不是 1 字节？**

如果只发送 1 字节 `[0x00]`，客户端（mihomo/Xray/sing-box）在读取期望的 2 字节响应时，会将后续的多路复用 ACK 帧数据误读为 Addons Length 字段，导致流偏移和协议解析失败。这在 smux 场景下是致命问题。

代码实现 (`format.hpp` 第 40-43 行)：
```cpp
[[nodiscard]] constexpr auto make_response() -> std::array<std::byte, 2>
{
    return {static_cast<std::byte>(version), std::byte{0x00}};
}
```

### 3.7 完整 Hex Dump 示例

#### 示例 1: TCP 连接到 93.184.216.34:80

```text
完整请求 (30 字节):

00000000: 00 c3 28 f0 e5 b1 a7 4c d2 9f 3e 1a 8b 4c 7d 6e  .(....L..>..L}n
00000010: 2f 00 01 00 50 01 5d b8 d8 22                    /...P.].."

字段拆解:
  Offset 0x00: VER       = 0x00
  Offset 0x01: UUID      = c328f0e5-b1a7-4cd2-9f3e-1a8b4c7d6e2f
  Offset 0x11: AddnlLen  = 0x00
  Offset 0x12: CMD       = 0x01 (TCP)
  Offset 0x13: PORT      = 0x0050 (80, HTTP)
  Offset 0x15: ATYP      = 0x01 (IPv4)
  Offset 0x16: ADDR      = 5d.b8.d8.22 (93.184.216.34)

响应 (2 字节):
00000000: 00 00                                            ..
```

#### 示例 2: TCP 连接到 example.com:443 (域名)

```text
完整请求 (38 字节):

00000000: 00 c3 28 f0 e5 b1 a7 4c d2 9f 3e 1a 8b 4c 7d 6e  .(....L..>..L}n
00000010: 2f 00 01 01 bb 02 0b 65 78 61 6d 70 6c 65 2e 63  /......example.c
00000020: 6f 6d                                            om

字段拆解:
  Offset 0x00: VER       = 0x00
  Offset 0x01: UUID      = c328f0e5-b1a7-4cd2-9f3e-1a8b4c7d6e2f
  Offset 0x11: AddnlLen  = 0x00
  Offset 0x12: CMD       = 0x01 (TCP)
  Offset 0x13: PORT      = 0x01BB (443, HTTPS)
  Offset 0x15: ATYP      = 0x02 (Domain)
  Offset 0x16: DomainLen = 0x0B (11)
  Offset 0x17: Domain    = "example.com"

响应 (2 字节):
00000000: 00 00                                            ..
```

#### 示例 3: UDP 到 [2001:db8::1]:53

```text
完整请求 (42 字节):

00000000: 00 c3 28 f0 e5 b1 a7 4c d2 9f 3e 1a 8b 4c 7d 6e  .(....L..>..L}n
00000010: 2f 00 02 00 35 03 20 01 0d b8 00 00 00 00 00 00  /...5. . ........
00000020: 00 00 00 00 00 00 00 01                          ........

字段拆解:
  Offset 0x00: VER       = 0x00
  Offset 0x01: UUID      = c328f0e5-b1a7-4cd2-9f3e-1a8b4c7d6e2f
  Offset 0x11: AddnlLen  = 0x00
  Offset 0x12: CMD       = 0x02 (UDP)
  Offset 0x13: PORT      = 0x0035 (53, DNS)
  Offset 0x15: ATYP      = 0x03 (IPv6)
  Offset 0x16: ADDR      = 2001:0db8:0000:0000:0000:0000:0000:0001

响应 (2 字节):
00000000: 00 00                                            ..
```

#### 示例 4: MUX 命令

```text
完整请求 (26 字节，最小尺寸):

00000000: 00 c3 28 f0 e5 b1 a7 4c d2 9f 3e 1a 8b 4c 7d 6e  .(....L..>..L}n
00000010: 2f 00 7f 00 00 01 00 00 00 00                    /.........

字段拆解:
  Offset 0x00: VER       = 0x00
  Offset 0x01: UUID      = c328f0e5-b1a7-4cd2-9f3e-1a8b4c7d6e2f
  Offset 0x11: AddnlLen  = 0x00
  Offset 0x12: CMD       = 0x7F (MUX)
  Offset 0x13: PORT      = 0x0000 (MUX 不使用)
  Offset 0x15: ATYP      = 0x01 (IPv4)
  Offset 0x16: ADDR      = 00.00.00.00 (占位符)

响应 (2 字节):
00000000: 00 00                                            ..
```

---

## 4. 地址类型详解

### 4.1 ATYP 值映射表

这是 VLESS 与 Trojan/SOCKS5 协议的关键差异点。在 Prism 内部，不同协议的处理器使用不同的 ATYP 映射。

```
                VLESS        Trojan       SOCKS5
                -----        ------       ------
  IPv4          0x01         0x01         0x01
  Domain        0x02         0x03         0x03
  IPv6          0x03         0x04         0x04
```

**重要：** VLESS 的 Domain = `0x02`、IPv6 = `0x03`，而 Trojan 的 Domain = `0x03`、IPv6 = `0x04`。在 Prism 的代码中，每个协议有自己的 `address_type` 枚举，互不干扰。但如果在代码中错误地混用协议的 ATYP 常量，将导致严重的解析错误。

### 4.2 内部地址表示

Prism 使用 `protocol::common::address` 作为统一的地址变体类型，底层为 `std::variant<ipv4_address, ipv6_address, domain_address>`。

```cpp
// ipv4_address
struct ipv4_address {
    std::array<std::uint8_t, 4> bytes;
};

// ipv6_address
struct ipv6_address {
    std::array<std::uint8_t, 16> bytes;
};

// domain_address
struct domain_address {
    std::uint8_t length;
    std::array<char, 255> value;
};

// address 变体
using address = std::variant<ipv4_address, ipv6_address, domain_address>;
```

这种设计使得地址在内存中的布局与 wire 格式高度对应，解析时可直接 `memcpy` 到结构体中，避免中间转换。

### 4.3 地址解析决策树

```
读取 ATYP (1B)
  |
  +-- 0x01 (IPv4)
  |     +-- 需要额外 4 字节
  |           +-- 缓冲区不足 -> read_remaining -> 解析为 ipv4_address
  |
  +-- 0x02 (Domain)
  |     +-- 先读 1 字节 domain_len
  |           +-- domain_len == 0 -> bad_message
  |           +-- 需要额外 domain_len 字节
  |                 +-- 解析为 domain_address (length + value)
  |
  +-- 0x03 (IPv6)
  |     +-- 需要额外 16 字节
  |           +-- 缓冲区不足 -> read_remaining -> 解析为 ipv6_address
  |
  +-- 其他值 -> unsupported_address
```

### 4.4 分步读取策略

VLESS 握手采用分步读取策略，这与其他协议一次性读取完整请求的方式不同。原因是 VLESS 运行在 TLS 内层，`preview` transport 可能包含后续的 mux 帧数据，过度消费会导致流偏移。

```
第 1 步: read_at_least(26 字节)
         读取 VER + UUID + AddnlLen + CMD + PORT + ATYP + IPv4
         |
         +-- 解析 VER -> 校验 0x00
         +-- 解析 UUID -> 保存用于认证
         +-- 解析 AddnlLen -> 必须为 0
         +-- 解析 CMD -> 验证命令字
         +-- 解析 PORT -> 大端序转主机序
         +-- 解析 ATYP -> 确定地址类型
               |
               +-- IPv4: 已在 26 字节中，无需补读
               +-- IPv6: 需要补读 16 字节 (offset 22-37)
               +-- Domain: 先补读 1 字节 (domain_len)
                     再补读 domain_len 字节
```

代码实现 (`relay.cpp` 第 89-179 行) 使用 `read_at_least` 和 `read_remaining` 两个辅助函数，均限制读取的 span 大小以防止过度消费。

---

## 5. 握手生命周期

### 5.1 完整时序图

```
  Client                    Prism Session                  Prism VLESS Relay
  ------                    -------------                  -----------------
  [TLS Handshake]
       |
       |------- VLESS Request Header ------->
       |                                         |
       |                                         |-- wrap_with_preview(ctx, data)
       |                                         |-- make_relay(transmission, cfg, verifier)
       |                                         |
       |                                         |   agent->handshake()
       |                                         |     |
       |                                         |     |-- read_at_least(26B)
       |                                         |     |   从 transmission 读取
       |                                         |     |   (包含 preview 重放数据)
       |                                         |     |
       |                                         |     |-- parse_request(buffer)
       |                                         |     |   解析 VER/UUID/CMD/PORT/ATYP/ADDR
       |                                         |     |
       |                                         |     |-- verifier(uuid_string)
       |                                         |     |   +-- account::try_acquire(directory, uuid)
       |                                         |     |         |-- 查找 UUID 是否注册用户
       |                                         |     |         |-- 检查连接数限制
       |                                         |     |         +-- 返回 account_lease
       |                                         |     |
       |                                         |     |-- make_response() -> [0x00, 0x00]
       |                                         |     |
       |       <--- VLESS Response [0x00,0x00] ---|
       |                                         |     +-- return {success, request}
       |                                         |
       |                                         |-- switch (req.cmd)
       |                                         |
       |                                         |-- TCP/MUX:
       |                                         |   |-- to_string(addr) -> host
       |                                         |   |-- to_chars(port) -> port
       |                                         |   |-- is_mux_target(host) ?
       |                                         |   |   |-- YES -> multiplex::bootstrap
       |                                         |   |   |   +-- muxprotocol->start()
       |                                         |   |   |   +-- co_return (结束)
       |                                         |   |   +-- NO -> forward(ctx, "Vless", target)
       |                                         |   |       +-- 建立上游连接 -> 双向隧道
       |                                         |   |
       |                                         +-- UDP:
       |                                               +-- async_associate(router)
       |                                                   +-- udp_frame_loop
       |
       |------- Application Data Stream ------->
       |   (TCP) 或 UDP Frames                   |
       |                                         |
       <----------- Response / Relay -------------|
```

### 5.2 握手状态机

```
  +--------------+
  |   INITIAL    |  连接已接受，等待 VLESS 请求
  +------+-------+
         |
         | co_await read_at_least(26B)
         v
  +--------------+
  |   READING    |  读取请求头 (可能分多次)
  +------+-------+
         |
         | buffer 解析完成
         v
  +--------------+
  |   PARSING    |  解析各字段，验证格式
  +------+-------+
         |
         | 解析成功
         v
  +--------------+
  |  VERIFYING   |  verifier_(uuid_string)
  +------+-------+
         |
    +----+----+
    |         |
    v         v
  PASS      FAIL
    |         |
    |         +---> fault::code::auth_failed -> co_return
    |
    | co_await async_write([0x00, 0x00])
    v
  +--------------+
  |  RESPONDING  |  发送 2 字节响应
  +------+-------+
         |
         | 响应发送成功
         v
  +--------------+
  |  DISPATCHING |  根据 CMD 分发处理路径
  +------+-------+
         |
    +----+----+
    |    |    |
    v    v    v
  TCP  UDP  MUX
```

### 5.3 UUID 认证流程

```
  pipeline::vless()
       |
       | 创建 verifier lambda
       v
  verifier(uuid_string)
       |
       | ctx.account_directory_ptr 存在?
       +-- NO -> trace::warn -> return false
       |
       | account::try_acquire(*directory, credential)
       v
  +----------------------+
  |  account::directory   |
  |  +----------------+  |
  |  | account 表      |  |  查找 UUID 是否注册
  |  | connection 计数  |  |  当前连接数 < 最大连接数?
  |  +----------------+  |
  +----------+-----------+
             |
        +----+----+
        |         |
        v         v
     找到且      未找到或
     有额度      超限
        |         |
        |         +---> return false -> handshake 失败
        |
        | 返回 account_lease (RAII 连接数 +1)
        v
  ctx.account_lease = std::move(lease)
  return true
```

认证失败场景：
- UUID 未注册用户表中
- 该 UUID 连接数已达上限
- `account_directory_ptr` 为空（未配置认证）

### 5.4 Preview 重放机制

VLESS 管道启动时，`session` 层已经预读了部分数据（通常 24 字节用于协议嗅探）。这些数据通过 `primitives::wrap_with_preview` 包装到 `transmission` 中，使得 `relay` 读取时能先消费 preview 缓冲区的数据，再回退到底层 socket 读取。

```
  session pre-read buffer (24 bytes)
       |
       v
  +-------------------------+
  |  preview_transmission   |  装饰器模式
  |  +-------------------+  |
  |  | preview buffer    |  |  包含预读的 VLESS 请求头
  |  +-------------------+  |
  |         |               |
  |         v               |
  |  underlying TLS socket  |
  +-------------------------+
       |
       | read_at_least(26B) 调用
       v
  1. 先从 preview buffer 消费 (可能有 24B)
  2. 不够则从 TLS socket 补读 (至少 2B)
  3. 拼接到统一 buffer 中解析
```

关键：`read_at_least` 和 `read_remaining` 的 span 参数被严格限制，以防止从 preview transport 过度消费。因为 preview 缓冲区可能包含 sing-mux 握手或 smux 帧等后续数据，这些数据需要留给后续的 `multiplex::bootstrap` 中的 `negotiate()` 阶段读取。

### 5.5 TCP 转发流程

握手成功后，TCP 命令的处理路径：

```
  relay.release()
       |
       | 释放底层 transmission 所有权
       v
  protocol::analysis::target (arena 分配)
       |
       | target.host = to_string(req.destination_address, arena)
       | target.port = to_chars(req.port)
       | target.positive = true
       v
  primitives::is_mux_target(host, mux_enabled)
       |
       +-- YES (MUX 标记)
       |     |
       |     +-- trace::info("mux session started")
       |     +-- multiplex::bootstrap(released_transmission, router, mux_config)
       |     +-- muxprotocol->start()
       |     +-- co_return
       |
       +-- NO (标准 TCP)
             |
             +-- trace::info("CONNECT -> {host}:{port}")
             +-- primitives::forward(ctx, "Vless", target, released_transmission)
             |     |
             |     +-- router 解析目标地址
             |     +-- 建立上游连接 (eyeball / connection pool)
             |     +-- 双向透明隧道 (client <-> upstream)
             +-- 隧道结束 -> session 清理
```

### 5.6 域名请求的分步读取示例

当客户端发送域名请求时，26 字节的初始读取不足以包含完整地址。以下是完整交互过程：

```
  客户端发送 (假设 "api.example.com":443):

  [VER][UUID...][00][01][01][BB][02][0F][api.example.com]
   1B   16B      1B   1B   2B    1B   1B   15B

  总长度: 1 + 16 + 1 + 1 + 2 + 1 + 1 + 15 = 38 字节

  Prism 读取过程:

  步骤 1: read_at_least(26B)
          +----------------------------------------------+
          | 00 | UUID(16B) | 00 | 01 | 01 BB |           |
          | 02 |                                    |
          +----------------------------------------------+
          读到: VER + UUID + AddnlLen + CMD + PORT + ATYP
          offset = 22, ATYP = 0x02 (Domain)

  步骤 2: 需要 domain_len，read_remaining(offset+1=23B)
          +----------------------------------------------+
          | ... 已读取 22B ... | 0F                       |
          +----------------------------------------------+
          domain_len = 15

  步骤 3: required_total = 22 + 1 + 15 = 38
          total(23) < required_total(38)
          read_remaining(38B)

          +----------------------------------------------+
          | ... 已读取 23B ... | api.example.com          |
          +----------------------------------------------+

  步骤 4: 完整解析 -> 发送响应 -> 建立 TCP 隧道
```

---

## 6. UDP 关联模式

### 6.1 概述

VLESS UDP 模式通过 `CMD = 0x02` 触发。与标准 VLESS TCP 不同，UDP 流量不建立透明隧道，而是采用逐帧解析-路由-转发的模式。客户端和服务端之间的所有 UDP 数据都封装在 TLS 流中传输。

### 6.2 UDP 帧格式

VLESS UDP 帧是纯二进制格式，与 Trojan 的 UDP 帧有显著差异。

```
VLESS UDP 帧:
+------+------+------+------+------+------+
| ATYP | ADDR | PORT |          Payload    |
|  1B  | var  |  2B  |         ...         |
+------+------+------+------+------+------+

Trojan UDP 帧 (对比):
+------+------+------+------+------+------+------+
| Len  | CR   | ATYP | ADDR | PORT | Payload | CR |
|  4B  | 2B  |  1B  | var  |  2B  |   ...   | 2B |
+------+------+------+------+------+------+------+
```

**关键差异：** VLESS UDP 帧不含 Length 字段和 CRLF 分隔符，直接是 ATYP + ADDR + PORT + Payload。

### 6.3 最小有效帧

```
ATYP(1) + IPv4(4) + PORT(2) = 7 字节
```

少于 7 字节的数据包被判定为 `fault::code::bad_message` 并丢弃。

### 6.4 UDP 帧 Hex Dump 示例

#### 示例: DNS 查询发往 8.8.8.8:53

```text
UDP 帧 (假设 DNS query payload 为 32 字节):

00000000: 01 08 08 08 08 00 35 1a 2b 3c 4d 5e 6f 7a 8b 9c  ......5.+<M^oz..
00000010: ad be cf d0 e1 f2 03 14 25 36 47 58 69 7a 8b 9c  ........%6GXiz..
00000020: ad be                                            ..

字段拆解:
  Offset 0x00: ATYP      = 0x01 (IPv4)
  Offset 0x01: ADDR      = 08.08.08.08 (8.8.8.8)
  Offset 0x05: PORT      = 0x0035 (53)
  Offset 0x07: Payload   = 1a 2b ... (32 字节 DNS 查询)

总长度: 7 + 32 = 39 字节
```

#### 示例: 域名目标

```text
00000000: 02 0e 64 6e 73 2e 67 6f 6f 67 6c 65 2e 63 6f 6d  ..dns.google.com
00000010: 00 35 1a 2b 3c 4d 5e 6f 7a 8b 9c                 .5.+<M^oz..

字段拆解:
  Offset 0x00: ATYP      = 0x02 (Domain)
  Offset 0x01: DomainLen = 0x0E (14, "dns.google.com")
  Offset 0x02: Domain    = "dns.google.com"
  Offset 0x10: PORT      = 0x0035 (53)
  Offset 0x12: Payload   = 1a 2b ... (DNS query)
```

### 6.5 UDP 响应帧格式

服务端将 DNS/UDP 响应封装回 TLS 流，格式为：

```
+------+------+------+------+--------+------+
| ATYP | ADDR | PORT |    Response    |
|  1B  | var  |  2B  |    Payload     |
+------+------+------+------+--------+------+
```

其中 ADDR 为发送者的源地址（客户端 endpoint），用于客户端识别响应归属。

构建逻辑 (`relay.cpp` 第 280-307 行 `send_vless_udp_response`)：
```cpp
// 从 sender_ep 提取地址
if (sender_ep.address().is_v4()) {
    frame.destination_address = ipv4_address{...};
} else {
    frame.destination_address = ipv6_address{...};
}
frame.destination_port = sender_ep.port();
// 构建帧: ATYP + ADDR + PORT + Payload
format::build_udp_packet(frame, {response_data}, buf.send);
```

### 6.6 UDP 帧处理循环

```
  relay::udp_frame_loop()
       |
       | 创建 udp_socket (复用, 避免每包 open/close)
       | 创建 idle_timer (默认 60s)
       v
  +--------------------------+
  |        WHILE TRUE        |
  +------------+-------------+
               |
               | idle_timer.expires_after(60s)
               |
               | co_await (do_read() || idle_timer.async_wait())
               |                            |
               |                     +------+------ +
               |                     |             |
               |                     v             v
               |               数据到达        超时
               |                     |             |
               |                     |             +---> co_return (结束)
               |                     |
               |                     v
               |               n = read bytes
               |                     |
               |                     | n == 0? -> co_return (EOF/error)
               |                     |
               |                     v
               |               format::parse_udp_packet(buffer)
               |                     |
               |                     | 解析失败? -> continue
               |                     |
               |                     v
               |               route_cb(host, port)
               |                     |
               |                     | 路由失败? -> continue
               |                     |
               |                     v
               |               protocol::common::relay_udp_packet(
               |                   udp_socket, target_ep, payload)
               |                     |
               |                     | 中继失败? -> continue
               |                     |
               |                     v
               |               send_vless_udp_response(
               |                   transport, sender_ep, response)
               |                     |
               |                     | 发送失败? -> co_return
               |                     |
               |                     v
               |               ---- 回到循环开头 ----
               |
               v
  +--------------------------+
  |       CO_RETURN          |  关闭 idle_timer，退出循环
  +--------------------------+
```

### 6.7 UDP 空闲超时

```
  +----------------------------------------------+
  |  udp_idle_timeout: 60 秒 (默认, 可配置)       |
  +----------------------------------------------+

  时间线:

  T=0s     收到 UDP 帧 -> 转发 -> 重置定时器 (60s)
  T=10s    收到 UDP 帧 -> 转发 -> 重置定时器 (60s)
  T=25s    收到 UDP 帧 -> 转发 -> 重置定时器 (60s)
  T=85s    无数据 -> 定时器到期 -> co_return (UDP 关联结束)
```

超时触发后，`udp_frame_loop` 正常退出，`async_associate` 返回 `fault::code::success`。客户端需要重新发起 UDP 命令来建立新的关联。

### 6.8 UDP 配置参数

| 参数 | 默认值 | 说明 | 代码位置 |
|------|--------|------|----------|
| `enable_udp` | `false` | 是否允许 UDP 命令 | `config.hpp:22` |
| `udp_idle_timeout` | `60` | UDP 会话空闲超时 (秒) | `config.hpp:23` |
| `udp_max_datagram` | `65535` | UDP 数据报最大长度 | `config.hpp:24` |

当 `enable_udp = false` 时，`async_associate` 直接返回 `fault::code::not_supported`，不进入帧处理循环。

### 6.9 UDP 数据包构建详情

`build_udp_packet` 函数 (`format.cpp` 第 200-240 行) 负责将响应数据封装为 VLESS UDP 帧：

```
输入:
  frame.destination_address (address 变体)
  frame.destination_port (uint16_t)
  payload (span<const byte>)

输出:
  out (memory::vector<std::byte>)

步骤:
  1. out.reserve(size + 19 + payload.size())  // 预分配: 最大地址(1+16) + port(2) + payload
  2. std::visit 写入地址:
     +-- IPv4:  [0x01][4B address]
     +-- IPv6:  [0x03][16B address]
     +-- Domain: [0x02][1B length][N bytes domain]
  3. 写入端口 (2B 大端):
     out.push_back(port >> 8 & 0xFF)
     out.push_back(port & 0xFF)
  4. 写入 Payload:
     out.insert(end, payload.begin(), payload.end())
```

---

## 7. 多路复用 (MUX)

### 7.1 概述

VLESS 支持通过 `CMD = 0x7F` 触发多路复用会话。这是 sing-box/mihomo 等客户端常用的优化手段，允许在单个 TLS 连接上建立多个逻辑子流，减少连接建立开销。

Prism 的 VLESS MUX 实现兼容 Mihomo smux v1 协议。

### 7.2 触发条件

MUX 会话在以下任一条件下触发：

1. **命令字为 MUX**: `CMD = 0x7F`
2. **目标地址为 MUX 标记**: `primitives::is_mux_target(target.host)` 返回 true

第二种情况允许客户端使用标准 TCP 命令 (`CMD = 0x01`) 但连接到一个特殊标记的"虚假地址"来触发 MUX，这是某些客户端的兼容策略。

### 7.3 MUX 握手流程

```
  Client                          Prism
  ------                          -----
  VLESS Request [CMD=0x7F]    -->
                                [parse: cmd = mux]
                                [verifier: UUID check]
  <-- VLESS Response [0x00,0x00]
                                [release relay]
                                [multiplex::bootstrap]
                                  |
                                  |-- negotiate() (读取 preview 中残留的 smux 帧)
                                  |-- 读取 smux SYN 帧
                                  |-- 发送 smux ACK 帧
                                  +-- start() (进入多路复用循环)

  此后所有流量均为 smux 帧:
  +-------+-------+-------+-------+
  | Ver   | Cmd   | Len   | SID   |  8 字节 smux 帧头
  +-------+-------+-------+-------+
  |         Payload ...           |
  +-------------------------------+
```

### 7.4 smux 帧格式

```
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |    Version    |     Cmd       |           Length (LE)         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           StreamID (LE)       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  Version (1B): 固定 0x01
  Cmd     (1B): SYN=0x00, FIN=0x01, PSH=0x02, NOP=0x03
  Length  (2B): payload 长度，小端序
  StreamID(2B): 逻辑流标识，小端序
```

### 7.5 MUX 代码路径

`vless.cpp` 第 52-75 行：

```
  switch (req.cmd)
  +-- TCP (0x01) / MUX (0x7F) 共享路径
  |     |
  |     +-- 解析 target.host / target.port
  |     +-- is_mux_target(host) ?
  |     |     +-- YES -> trace::info("mux session started")
  |     |     |         ctx.active_stream_close = nullptr
  |     |     |         ctx.active_stream_cancel = nullptr
  |     |     |         multiplex::bootstrap(agent->release(), router, mux_config)
  |     |     |         muxprotocol->start()
  |     |     |         co_return  <-- 不进入标准转发
  |     |     |
  |     |     +-- NO -> target.positive = true
  |     |              primitives::forward(ctx, "Vless", target, agent->release())
  |     |
  +-- UDP (0x02) -> async_associate(router)
```

### 7.6 Preview 残留数据处理

MUX 场景的一个关键技术细节：当 `session` 层进行协议嗅探时，预读的 24 字节缓冲区可能不仅包含 VLESS 请求头，还可能包含后续的 smux 握手帧（如 sing-mux 协商数据）。

```
  Preview Buffer (24 bytes):

  [VLESS Header: 22B] [smux SYN: 8B] [smux PSH: ...]
  +------ 完整 ------+ +---- 残留 ----+

  处理:
  1. relay::handshake() 只读取 VLESS 请求所需的字节数
     - read_at_least(26B) 限制 span 防止过度消费
     - 域名场景分步读取，每次限制到刚好需要的字节数

  2. 握手完成后，preview buffer 中剩余的 smux 帧数据
     仍然保留在 transmission 中

  3. multiplex::bootstrap() 的 negotiate() 阶段
     从 transmission 读取这些残留帧

  关键: 如果 handshake 过度消费了 preview buffer，
        negotiate() 将无法读取正确的 smux 帧，
        导致流偏移和多路复用失败
```

---

## 8. 错误码与故障处理

### 8.1 错误码汇总

| 错误码 | 值 | 触发条件 | 处理方式 |
|--------|-----|----------|----------|
| `fault::code::success` | 0 | 操作成功 | 继续处理 |
| `fault::code::bad_message` | -- | 版本号错误 / AddnlInfoLen != 0 / 缓冲区不足 / UDP 帧太短 / 域名长度为 0 | 关闭连接 |
| `fault::code::unsupported_command` | -- | CMD 值不为 0x01/0x02/0x7F | 关闭连接 |
| `fault::code::unsupported_address` | -- | ATYP 值不为 0x01/0x02/0x03 | 关闭连接 |
| `fault::code::auth_failed` | -- | UUID 未注册 / 连接数超限 / account_directory 未配置 | 关闭连接 |
| `fault::code::not_supported` | -- | UDP 未启用 (`enable_udp = false`) | 返回错误，不进入 UDP 循环 |

### 8.2 错误传播路径

```
  relay::handshake()
       |
       +-- read_at_least 失败 -> {read_ec, request{}}
       |     +-- fault::failed(read_ec) -> vless.cpp 中 trace::warn -> co_return
       |
       +-- VER != 0x00 -> {bad_message, request{}}
       +-- AddnlLen != 0 -> {bad_message, request{}}
       +-- CMD 无效 -> {unsupported_command, request{}}
       +-- ATYP 无效 -> {unsupported_address, request{}}
       |
       +-- verifier_(uuid) 失败 -> {auth_failed, request{}}
       |     +-- trace::warn("[Vless] UUID verification failed")
       |
       +-- async_write 失败 -> {to_code(write_ec), request{}}
       |
       +-- 全部通过 -> {success, request}
             +-- vless.cpp 中 switch (req.cmd) 分发
```

### 8.3 日志事件汇总

| 日志级别 | 消息模板 | 触发条件 | 代码位置 |
|----------|----------|----------|----------|
| `warn` | `[Pipeline.Vless] account directory not configured` | account_directory_ptr 为空 | `vless.cpp:27` |
| `warn` | `[Pipeline.Vless] credential verification failed` | account::try_acquire 返回空 | `vless.cpp:33` |
| `warn` | `[Pipeline.Vless] handshake failed: {error}` | 握手返回失败错误码 | `vless.cpp:46` |
| `info` | `[Pipeline.Vless] mux session started` | MUX 会话建立 | `vless.cpp:66` |
| `info` | `[Pipeline.Vless] CONNECT -> {host}:{port}` | TCP 连接建立 | `vless.cpp:78` |
| `info` | `[Pipeline.Vless] UDP associate started` | UDP 命令开始处理 | `vless.cpp:86` |
| `warn` | `[Pipeline.Vless] UDP associate failed: {error}` | UDP 关联失败 | `vless.cpp:93` |
| `info` | `[Pipeline.Vless] UDP associate completed` | UDP 关联正常结束 | `vless.cpp:97` |
| `warn` | `[Pipeline.Vless] unknown command: {n}` | CMD 值不在枚举范围内 | `vless.cpp:102` |
| `debug` | `[Vless.UDP] Idle timeout` | UDP 空闲超时 | `relay.cpp:342` |
| `debug` | `[Vless.UDP] Read error or EOF` | UDP 读取错误或 EOF | `relay.cpp:352` |
| `warn` | `[Vless.UDP] Packet parse failed` | UDP 帧解析失败 | `relay.cpp:359` |
| `debug` | `[Vless.UDP] Route failed` | 目标地址路由失败 | `relay.cpp:371` |
| `debug` | `[Vless.UDP] Write response failed` | UDP 响应写入失败 | `relay.cpp:303` |

### 8.4 故障恢复策略

| 故障类型 | 恢复策略 | 影响范围 |
|----------|----------|----------|
| 握手失败 | 关闭连接，释放资源 | 单个 session |
| UUID 认证失败 | 关闭连接，租约不创建 | 单个 session |
| UDP 解析失败 | continue (跳过此包) | 单个 UDP 包 |
| UDP 路由失败 | continue (跳过此包) | 单个 UDP 包 |
| UDP 写入失败 | co_return (结束关联) | UDP 关联 |
| UDP 空闲超时 | co_return (正常退出) | UDP 关联 |
| TCP 隧道断开 | 清理资源，session 结束 | 单个 session |

