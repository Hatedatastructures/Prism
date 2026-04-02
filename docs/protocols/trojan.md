# Trojan 协议文档

本文档包含 Trojan 协议的完整规范以及 Prism 内的实现细节。

---

## 第一部分：协议规范

### 1. 协议概述

Trojan 是一种轻量级的代理协议，设计目标是简单、高效、难以检测。它通过 TLS 加密通道传输数据，使用预共享密钥进行认证，流量特征与普通 HTTPS 流量几乎无法区分。

**核心特点**：
- **TLS 加密**：所有流量通过 TLS 加密，无需额外加密层
- **密码认证**：使用 SHA224 哈希的密码作为凭据
- **流量伪装**：协议头部设计为类似 HTTP 请求的格式
- **多协议支持**：TCP 隧道、UDP over TLS、多路复用

**协议参数**：
- **默认端口**：443（伪装 HTTPS）
- **认证方式**：SHA224(password) = 56 字节十六进制字符串
- **传输层**：TLS 1.2+（推荐 TLS 1.3）

### 2. 完整会话流程

```
阶段 1: TCP 连接建立
    客户端 -> TCP SYN -> 服务端
    客户端 <- TCP SYN+ACK <- 服务端
    客户端 -> TCP ACK -> 服务端

阶段 2: TLS 握手
    客户端 <-> ClientHello/ServerHello <-> 服务端
    客户端 <-> 证书验证/密钥交换 <-> 服务端
    客户端 <-> Finished <-> 服务端

阶段 3: Trojan 协议握手
    客户端 -> CREDENTIAL + CRLF + CMD + ATYP + ADDR + PORT + CRLF -> 服务端
    服务端: 验证凭据
    服务端: 解析目标地址

阶段 4: 数据传输
    客户端 <==> 加密隧道 <==> 服务端 <==> 目标服务器

阶段 5: 连接关闭
    客户端 -> TLS close_notify -> 服务端
    客户端 -> TCP FIN -> 服务端
```

### 3. TLS 握手要求

Trojan 协议依赖 TLS 提供加密和身份验证：

#### 3.1 TLS 版本

- **最低版本**：TLS 1.2
- **推荐版本**：TLS 1.3
- **禁止版本**：SSLv3、TLS 1.0、TLS 1.1（已不安全）

#### 3.2 证书要求

```
服务端证书要求:
1. 证书必须有效（未过期）
2. 证书域名与 SNI 匹配（或使用通配符证书）
3. 证书链完整
4. 推荐使用 Let's Encrypt 等权威机构签发

客户端验证:
1. 可选择跳过证书验证（skip-cert-verify: true）
2. 可指定自定义 CA 证书
3. 生产环境应启用证书验证
```

#### 3.3 TLS 扩展

```
关键扩展:
- SNI (Server Name Indication): 指定服务器域名
- ALPN: 可选，推荐 "h2,http/1.1" 伪装 HTTP/2
- Session Ticket: 支持会话恢复，减少握手延迟
```

### 4. Trojan 协议头格式

#### 4.1 请求头格式

```
+-------------------+-------+------+--------+----------+----------+-------+
|   Credential      | CRLF  | CMD  | ATYP   | DST.ADDR | DST.PORT | CRLF  |
|   (56 bytes)      | 2 bytes| 1 byte| 1 byte| Variable | 2 bytes  | 2 bytes|
+-------------------+-------+------+--------+----------+----------+-------+

字段说明:
    Credential: 56字节, SHA224(密码) 的十六进制表示
    CRLF: 2字节, 固定为 \r\n (0x0D 0x0A)
    CMD: 1字节, 命令类型
    ATYP: 1字节, 地址类型
    DST.ADDR: 变长, 目标地址
    DST.PORT: 2字节, 目标端口 (大端序)
    CRLF: 2字节, 固定为 \r\n (0x0D 0x0A)
```

#### 4.2 命令类型 (CMD)

| 值 | 名称 | 说明 |
|----|------|------|
| 0x01 | CONNECT | TCP 隧道连接 |
| 0x03 | UDP_ASSOCIATE | UDP over TLS |
| 0x7F | MUX | Mihomo smux 多路复用 |

#### 4.3 地址类型 (ATYP)

| 值 | 名称 | 地址长度 |
|----|------|----------|
| 0x01 | IPv4 | 4 字节 |
| 0x03 | Domain | 1 + N 字节 |
| 0x04 | IPv6 | 16 字节 |

### 5. 地址格式详解

#### 5.1 IPv4 地址 (ATYP=0x01)

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

#### 5.2 IPv6 地址 (ATYP=0x04)

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

#### 5.3 域名地址 (ATYP=0x03)

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

### 6. 端口格式

```
端口始终使用大端序 (高字节在前)

示例:
    端口 80:   0x00 0x50  (0x00*256 + 0x50 = 80)
    端口 443:  0x01 0xBB  (0x01*256 + 0xBB = 443)
    端口 53:   0x00 0x35  (0x00*256 + 0x35 = 53)
```

### 7. 完整请求示例

#### 7.1 CONNECT IPv4 示例

```
连接 8.8.8.8:53

请求头:
  [56字节凭据] 0x0D 0x0A 0x01 0x01 0x08 0x08 0x08 0x08 0x00 0x35 0x0D 0x0A
  |-----------| |------| |---| |---| |-----------------| |------| |------|
  SHA224(密码)   CRLF    CONNECT IPv4     8.8.8.8          53      CRLF

十六进制表示 (假设密码 SHA224 全为 'a'):
  61 61 61 61 ... (56 bytes) 0D 0A 01 01 08 08 08 08 00 35 0D 0A
```

#### 7.2 CONNECT 域名示例

```
连接 example.com:443

请求头:
  [56字节凭据] 0x0D 0x0A 0x01 0x03 0x0B "example.com" 0x01 0xBB 0x0D 0x0A
  |-----------| |------| |---| |---| |--| |-----------| |------| |------|
  SHA224(密码)   CRLF    CONNECT Domain Len  "example.com"  443     CRLF

十六进制表示:
  61 61 ... (56 bytes) 0D 0A 01 03 0B 65 78 61 6D 70 6C 65 2E 63 6F 6D 01 BB 0D 0A
```

#### 7.3 UDP_ASSOCIATE 示例

```
请求 UDP 关联

请求头:
  [56字节凭据] 0x0D 0x0A 0x03 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x0D 0x0A
  |-----------| |------| |---| |---| |-----------------| |------| |------|
  SHA224(密码)   CRLF    UDP   IPv4     0.0.0.0            0      CRLF

注意: UDP_ASSOCIATE 的目标地址通常为 0
```

### 8. 凭据计算

#### 8.1 SHA224 哈希计算

```
密码: "prism"

计算过程:
    SHA224("prism") = 56 字节十六进制字符串

Python 示例:
    import hashlib
    password = "prism"
    credential = hashlib.sha224(password.encode()).hexdigest()
    # 结果: 32 字节二进制 = 64 字符十六进制
    # 但 Trojan 使用前 56 字符

重要:
- Trojan 使用 SHA224，输出 28 字节 = 56 字符十六进制
- 凭据大小写敏感，通常使用小写
```

#### 8.2 凭据验证流程

```
服务端验证流程:
1. 读取 56 字节凭据
2. 验证每个字符都是有效的十六进制字符 (0-9, a-f)
3. 与预存的凭据哈希值比对
4. 通过则继续，失败则关闭连接

Prism 实现:
- 使用 account::directory 管理用户凭据
- 支持连接数限制和流量统计
- 凭据验证失败记录日志
```

---

## 第二部分：UDP over TLS

### 9. UDP_ASSOCIATE 命令

UDP_ASSOCIATE 建立 UDP over TLS 隧道，允许客户端通过 TLS 连接发送和接收 UDP 数据报。

#### 9.1 UDP 会话建立

```
阶段 1: TLS 连接已建立

阶段 2: 发送 UDP_ASSOCIATE 请求
    客户端 -> [CREDENTIAL] CRLF 0x03 ATYP ADDR PORT CRLF -> 服务端
    注意: ADDR 和 PORT 通常为 0

阶段 3: 服务端接受请求
    服务端: 创建 UDP 中继
    服务端: 无需发送响应，直接进入 UDP 帧循环

阶段 4: UDP 数据传输
    客户端 -> UDP 封装包 -> 服务端 -> 解封装 -> 目标
    客户端 <- UDP 封装包 <- 服务端 <- 封装 <- 目标

阶段 5: 会话终止
    TCP/TLS 连接关闭 -> UDP 会话自动终止
```

#### 9.2 UDP 数据报封装格式

Trojan UDP 封装格式兼容 SOCKS5 UDP：

```
+------+------+------+----------+----------+--------+--------+-------+
| ATYP | DST.ADDR | DST.PORT |   Length |   CRLF   |  DATA  |
| 1    | Variable |    2     |    2     |   2      | Variable|
+------+------+------+----------+----------+--------+--------+-------+

字段说明:
    ATYP: 1字节, 地址类型 (0x01=IPv4, 0x03=Domain, 0x04=IPv6)
    DST.ADDR: 变长, 目标地址
    DST.PORT: 2字节, 目标端口 (大端序)
    Length: 2字节, DATA 字段长度 (大端序)
    CRLF: 2字节, 固定为 \r\n (0x0D 0x0A)
    DATA: 变长, UDP 载荷数据
```

#### 9.3 UDP 数据报示例

```
发送 DNS 查询到 8.8.8.8:53:

UDP 封装包:
    0x01 0x08 0x08 0x08 0x08 0x00 0x35 0x00 0x1C 0x0D 0x0A [28字节DNS查询]
    |---| |-----------------| |------| |------| |------| |-----------|
    IPv4       8.8.8.8          53      28字节   CRLF    DNS数据

发送到域名 example.com:443:
    0x03 0x0B "example.com" 0x01 0xBB 0x00 0x20 0x0D 0x0A [32字节数据]
    |---| |--| |-----------| |------| |------| |------| |----------|
    Domain Len  "example.com"  443    32字节   CRLF    数据
```

#### 9.4 UDP 多路复用

```
单一 TLS 连接承载多个 UDP 流:

客户端 TLS 连接
    |
    +-- UDP 帧 1 -> 8.8.8.8:53 (DNS)
    +-- UDP 帧 2 -> 1.1.1.1:53 (DNS)
    +-- UDP 帧 3 -> time.nist.gov:123 (NTP)
    |
    v
服务端 UDP Relay
    |
    +-- 路由到 -> 8.8.8.8:53
    +-- 路由到 -> 1.1.1.1:53
    +-- 路由到 -> time.nist.gov:123

响应:
    服务端接收 UDP 响应后，封装源地址信息返回客户端
    客户端根据地址信息区分不同目标的响应
```

---

## 第三部分：多路复用 (Mux)

### 10. MUX 命令 (0x7F)

MUX 命令用于建立 smux 多路复用会话，允许在单个 TLS 连接上承载多个 TCP/UDP 流。

#### 10.1 MUX 握手

```
客户端发送 MUX 请求:
    [56字节凭据] CRLF 0x7F ATYP ADDR PORT CRLF

MUX 标记地址 (Mihomo/sing-box 兼容):
    目标地址: "<random>.mux.sing-box.arpa"
    目标端口: 任意

示例:
    0x7F 0x03 0x12 "abc123.mux.sing-box.arpa" 0x00 0x00

服务端检测到 mux 标记地址后:
    1. 不建立上游连接
    2. 创建 smux 会话
    3. 进入帧循环处理多路复用流
```

#### 10.2 smux 帧格式

smux 是一个简单的多路复用协议，帧格式如下：

```
+---------+-----+--------+----------+
| Version | Cmd | Length | StreamID |
|  1 byte | 1 b | 2 bytes| 4 bytes  |
+---------+-----+--------+----------+
|            Data (if any)          |
+-----------------------------------+

字段说明:
    Version: 1字节, 版本号，固定为 0x00
    Cmd: 1字节, 命令类型
        0x00: SYN - 新建流
        0x01: FIN - 关闭流
        0x02: PSH - 数据帧
        0x03: NOP - 心跳
    Length: 2字节, 数据长度 (小端序)
    StreamID: 4字节, 流标识符 (小端序)
```

#### 10.3 smux 流程

```
客户端                              服务端
   |                                   |
   |------ SYN (StreamID=1) --------->|  创建新流
   |<----- SYN (StreamID=1) ---------|  确认创建
   |                                   |
   |------ PSH (StreamID=1, data) --->|  发送数据
   |<----- PSH (StreamID=1, data) ----|  接收数据
   |                                   |
   |------ FIN (StreamID=1) --------->|  关闭流
   |<----- FIN (StreamID=1) ---------|  确认关闭
   |                                   |
   |------ NOP ---------------------->|  心跳保活
   |<----- NOP -----------------------|  心跳响应
```

---

## 第四部分：Prism 实现

### 11. 总体入口链路

1. **连接接收**：`worker` 监听端口并接收连接
   入口：`include/prism/agent/worker/worker.hpp`，`worker::do_accept`

2. **协议识别**：`session::diversion` 识别为 Trojan 协议
   入口：`include/prism/agent/session/session.hpp`，`session::diversion`

3. **TLS 握手**：`primitives::ssl_handshake` 执行 TLS 握手
   入口：`src/prism/agent/pipeline/primitives.cpp`

4. **Trojan 处理器**：创建 Trojan 中继器并执行握手
   入口：`include/prism/agent/dispatch/handler.hpp`

5. **协议握手**：`protocol::trojan::relay::handshake` 解析协议头
   入口：`src/prism/protocol/trojan/relay.cpp`

6. **凭据验证**：通过 `account::directory` 验证用户
   入口：`include/prism/agent/account/directory.hpp`

7. **路由决策**：`router::async_forward` 建立上游连接
   入口：`src/prism/resolve/router.cpp`

8. **隧道转发**：`primitives::tunnel` 双向透明转发
   入口：`src/prism/agent/pipeline/primitives.cpp`

### 12. TLS 握手实现

```cpp
// primitives.cpp - ssl_handshake
auto [handshake_ec, ssl_stream] = co_await primitives::ssl_handshake(ctx, data);
if (fault::failed(handshake_ec) || !ssl_stream)
{
    trace::warn("{} TLS handshake failed: {}", TrojanStr, fault::describe(handshake_ec));
    co_return;
}

// 注册流关闭回调
ctx.active_stream_cancel = [ssl_stream]() noexcept
{
    ssl_stream->lowest_layer().transmission().cancel();
};
ctx.active_stream_close = [ssl_stream]() noexcept
{
    ssl_stream->lowest_layer().transmission().close();
};
```

### 13. Trojan 握手实现

#### 13.1 最小读取长度

```
最小请求长度计算:
    凭据: 56 字节
    CRLF: 2 字节
    CMD: 1 字节
    ATYP: 1 字节
    最小地址: 4 字节 (IPv4)
    端口: 2 字节
    CRLF: 2 字节
    -------------------
    最小总计: 68 字节

实际实现分两层：
    1. protocols.cpp 预读 60 字节（凭据 56 + CRLF 2 + CMD 1 + ATYP 1）
    2. relay.cpp 读取至少 68 字节，根据 ATYP 计算完整长度后补读
```

#### 13.2 握手流程 (relay.cpp)

```cpp
auto relay::handshake() const -> net::awaitable<std::pair<fault::code, request>>
{
    // 1. 读取至少 68 字节（最小请求长度）
    auto [read_ec, total] = co_await read_at_least(*next_layer_, byte_span, k_min_request_size);

    // 2. 解析凭据 (0-55)
    auto [cred_ec, credential] = format::parse_credential(data_span.subspan(0, 56));

    // 3. 验证凭据
    if (verifier_ && !verifier_(cred_view))
    {
        co_return std::pair{fault::code::auth_failed, request{}};
    }

    // 4. 验证 CRLF (56-57)
    auto crlf1_ec = format::parse_crlf(data_span.subspan(56, 2));

    // 5. 解析命令和地址类型 (58-59)
    auto [header_ec, header] = format::parse_cmd_atyp(data_span.subspan(58, 2));

    // 6. 根据地址类型计算完整长度
    // 7. 补读剩余字节
    // 8. 解析目标地址和端口
    // 9. 验证结束 CRLF
    // 10. 验证命令权限

    co_return std::pair{fault::code::success, req};
}
```

### 14. 凭据验证

#### 14.1 account::entry 结构

```cpp
// 账户运行时状态 (entry.hpp)
struct entry
{
    std::uint32_t max_connections{0};           // 最大连接数
    std::atomic_uint64_t uplink_bytes{0};       // 上行流量
    std::atomic_uint64_t downlink_bytes{0};     // 下行流量
    std::atomic_uint32_t active_connections{0}; // 活跃连接数
};

// 账户连接租约 (RAII 封装)
class lease
{
    // 构造时持有 entry 的共享所有权
    // 析构时自动递减活跃连接数
    std::shared_ptr<entry> state_;
};
```

#### 14.2 验证流程

```cpp
// protocols.cpp - trojan
auto verifier = [&ctx](const std::string_view credential) -> bool
{
    if (!ctx.account_directory_ptr)
    {
        trace::warn("{} account directory not configured", TrojanStr);
        return false;
    }

    // 尝试获取账户租约
    auto lease = account::try_acquire(*ctx.account_directory_ptr, credential);
    if (!lease)
    {
        trace::warn("{} credential verification failed", TrojanStr);
        return false;
    }

    ctx.account_lease = std::move(lease);
    return true;
};
```

### 15. 命令处理

#### 15.1 CONNECT 命令

```cpp
case protocol::trojan::command::connect:
{
    // 1. 解析目标地址
    target.host = protocol::trojan::to_string(req.destination_address, mr);
    target.port = std::to_string(req.port);

    // 2. 检查 mux 标记
    if (ctx.server.cfg.mux.enabled &&
        target.host.ends_with(".mux.sing-box.arpa"))
    {
        // 进入 smux 多路复用模式
        auto smux_craft = std::make_shared<multiplex::smux::craft>(...);
        smux_craft->start();
        co_return;
    }

    // 3. 建立上游连接
    auto [dial_ec, outbound] = co_await primitives::dial(router_ptr, "Trojan", target, true, true);

    // 4. 进入隧道转发
    co_await primitives::tunnel(agent->release(), std::move(outbound), ctx);
    break;
}
```

#### 15.2 UDP_ASSOCIATE 命令

```cpp
case protocol::trojan::command::udp_associate:
{
    trace::info("{} UDP_ASSOCIATE started", TrojanStr);

    // 创建路由回调
    auto route_callback = [router_ptr](std::string_view host, std::string_view port)
        -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>
    {
        co_return co_await router_ptr->resolve_datagram_target(host, port);
    };

    // 进入 UDP 帧循环
    const auto associate_ec = co_await agent->async_associate(std::move(route_callback));
    break;
}
```

### 16. UDP 帧循环实现

```cpp
// relay.cpp - udp_frame_loop
auto relay::udp_frame_loop(route_callback &route_cb, net::steady_timer &idle_timer) const
    -> net::awaitable<void>
{
    udp_buffers buf(config_.udp_max_datagram);

    while (true)
    {
        // 重置空闲超时
        idle_timer.expires_after(std::chrono::seconds(config_.udp_idle_timeout));

        // 1. 从 TLS 流读取 UDP 帧
        const auto n = co_await next_layer_->async_read_some({buf.recv.data(), buf.recv.size()}, read_ec);

        // 2. 解析 UDP 帧
        auto [parse_ec, parsed] = format::parse_udp_packet({buf.recv.data(), n});

        // 3. 解析目标地址
        const auto target_host = to_string(parsed.destination_address);
        const auto target_port = std::to_string(parsed.destination_port);

        // 4. 路由到目标
        auto [route_ec, target_ep] = co_await route_cb(target_host, target_port);

        // 5. 创建 UDP socket 发送数据
        net::ip::udp::socket udp_socket(executor);
        co_await udp_socket.async_send_to(..., target_ep);

        // 6. 接收响应
        const auto resp_n = co_await udp_socket.async_receive_from(..., sender_ep);

        // 7. 封装响应并写回 TLS 流
        format::build_udp_packet(frame, payload, buf.send);
        co_await transport.async_write({buf.send.data(), buf.send.size()});
    }
}
```

### 17. 错误处理

#### 17.1 错误码映射

| 场景 | fault::code | 说明 |
|------|-------------|------|
| TLS 握手失败 | tls_handshake_failed | 证书无效、协议不匹配 |
| 凭据格式错误 | protocol_error | 非十六进制字符 |
| 凭据验证失败 | auth_failed | 密码错误、账户禁用 |
| 命令不支持 | unsupported_command | 未知 CMD 值 |
| 地址不支持 | unsupported_address | 未知 ATYP 值 |
| 格式错误 | bad_message | 长度不足、CRLF 错误 |
| 网络错误 | io_error | 连接断开、超时 |

#### 17.2 错误处理原则

```
协议级错误:
- 直接关闭 TLS 连接
- 不发送错误响应（协议无响应格式）
- 记录详细日志

网络级错误:
- 优雅关闭连接
- 释放资源
- 通知上层

认证错误:
- 记录安全日志
- 可选: 延迟响应防止暴力破解
```

---

## 第五部分：协议常量

### 18. 命令类型

| 常量 | 值 | 说明 | Prism 支持 |
|------|-----|------|-----------|
| CONNECT | 0x01 | TCP 隧道 | ✓ |
| UDP_ASSOCIATE | 0x03 | UDP over TLS | ✓ |
| MUX | 0x7F | smux 多路复用 | ✓ |

### 19. 地址类型

| 常量 | 值 | 地址长度 | 说明 |
|------|-----|----------|------|
| IPv4 | 0x01 | 4 字节 | IPv4 地址 |
| Domain | 0x03 | 1 + N 字节 | 域名地址 |
| IPv6 | 0x04 | 16 字节 | IPv6 地址 |

### 20. 配置参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| enable_tcp | bool | true | 允许 CONNECT 命令 |
| enable_udp | bool | false | 允许 UDP_ASSOCIATE 命令 |
| udp_idle_timeout | uint32 | 60 | UDP 空闲超时 (秒) |
| udp_max_datagram | uint32 | 65535 | UDP 数据报最大长度 |

---

## 第六部分：实现注意事项

### 21. 安全考虑

#### 21.1 TLS 配置

```
推荐配置:
- TLS 1.3 优先
- 强密码套件: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
- 启用 OCSP Stapling
- 启用 HSTS

禁止配置:
- TLS 1.0, TLS 1.1
- 弱密码套件: RC4, DES, 3DES
- 空密码套件
```

#### 21.2 凭据安全

```
密码策略:
- 密码长度 >= 8 字符
- 使用强随机密码
- 定期更换密码
- 不同用户使用不同密码

存储安全:
- 存储 SHA224 哈希，不存明文
- 配置文件权限限制
- 日志不记录凭据
```

#### 21.3 访问控制

```
连接限制:
- 单用户最大连接数
- 单 IP 最大连接数
- 连接速率限制

流量限制:
- 上传/下载流量配额
- 速率限制
```

### 22. 性能考虑

#### 22.1 TLS 优化

```
会话复用:
- 启用 Session Ticket
- 设置合理的 Ticket 生命周期

连接池:
- 复用 TLS 连接
- 设置合理的空闲超时

ALPN:
- 伪装为 HTTP/2 流量
- 支持 h2, http/1.1
```

#### 22.2 UDP 优化

```
缓冲区管理:
- 预分配缓冲区
- 避免 UDP 帧循环中分配内存

超时管理:
- 合理的空闲超时
- 及时清理不活跃会话
```

### 23. 兼容性

#### 23.1 客户端兼容

| 客户端 | TCP | UDP | Mux | 备注 |
|--------|-----|-----|-----|------|
| Trojan-Go | ✓ | ✓ | ✓ | 完整兼容 |
| Clash Meta | ✓ | ✓ | ✓ | 完整兼容 |
| v2ray | ✓ | ✓ | ✗ | 不支持 mux |
| sing-box | ✓ | ✓ | ✓ | 完整兼容 |

#### 23.2 Mux 兼容

```
Prism smux 实现:
- 兼容 Mihomo/Clash Meta
- 兼容 sing-box
- 兼容 xtaci/smux v1

MUX 标记地址:
- Mihomo: <random>.mux.trojan.arpa
- sing-box: <random>.mux.sing-box.arpa
- Prism 同时支持两种格式
```

### 24. 参考资料

- Trojan 官方文档: https://trojan-gfw.github.io/trojan/protocol
- Trojan-Go 文档: https://p4gefau1t.github.io/trojan-go/
- Mihomo 文档: https://wiki.metacubex.one/
- smux 协议: https://github.com/xtaci/smux
- RFC 5246: TLS 1.2
- RFC 8446: TLS 1.3