# Prism 中的 SOCKS5 协议（RFC 1928）

## 1. 协议背景

### 1.1 规范参考

| 规范 | 描述 |
|---|---|
| RFC 1928 | SOCKS 协议版本 5 |
| RFC 1929 | SOCKS V5 的用户名/密码认证 |
| RFC 2617 | HTTP 认证（用于认证比较参考） |
| Draft-Leopold-SOCKS5-IPv6 | SOCKS5 IPv6 扩展（非标准，广泛使用） |

### 1.2 为什么存在 SOCKS5

SOCKS5 是一种通用代理协议，运行在传输层（OSI 模型第 4 层）。与仅理解 HTTP 请求的 HTTP 代理不同，SOCKS5 可以代理任何 TCP 或 UDP 流量：

- **TCP 代理（CONNECT）**：建立到任意目标主机和端口的双向 TCP 隧道。用于网页浏览（HTTP/HTTPS）、SSH、数据库连接以及任何基于 TCP 的协议。
- **UDP 代理（UDP ASSOCIATE）**：中继 UDP 数据报到任意目标。对 DNS 查询、VoIP、在线游戏和基于 QUIC 的协议至关重要。
- **BIND（已弃用）**：允许服务器接受传入连接并将其回传给客户端。由于 NAT 穿透问题，在现代部署中很少使用。

SOCKS5 是最通用的代理协议，因为它**与应用程序无关**——它不解析或修改被代理的数据，使其与任何协议兼容。

### 1.3 协议特征

- **二进制协议**：所有消息均为二进制格式，具有定长头部和可变长度地址字段
- **多阶段握手**：方法协商 ->（可选）认证 -> 命令请求 -> 响应
- **三种命令**：CONNECT（TCP 隧道）、BIND（反向连接）、UDP ASSOCIATE（UDP 中继）
- **三种地址类型**：IPv4（4 字节）、IPv6（16 字节）、域名（1 字节长度前缀 + 可变长度）
- **有状态**：服务器在连接持续期间维护会话状态
- **端口 1080**：SOCKS5 默认端口，Prism 监听可配置的端口

### 1.4 Prism 架构中的 SOCKS5

Prism 将 SOCKS5 实现为**管道协议**，在 `protocol::socks5::relay` 中具有完整的中继状态机。`relay` 类继承自 `transport::transmission`，使其可在隧道层中多态使用。关键特性：

- 完整兼容 RFC 1928，支持所有三种命令
- RFC 1929 用户名/密码认证（可选）
- 支持 IPv4、IPv6 和域名
- 逐数据报路由的 UDP 中继
- 可配置的能力标志（启用/禁用特定命令）
- 基于 `account::lease` 的账户连接跟踪

---

## 2. 协议规范

### 2.1 协议栈

```
应用层:  任意协议（HTTP、DNS、SSH 等）
传输层:    SOCKS5（CONNECT 隧道 / UDP ASSOCIATE 中继）
网络层:      IP（IPv4 或 IPv6）
链路层:      以太网 / WiFi / 等
```

### 2.2 阶段 1：方法协商

客户端通过发送方法协商请求启动 SOCKS5 握手。

#### 客户端 -> 服务器：方法请求

```
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1..255   |
+----+----------+----------+
```

| 字段 | 大小 | 描述 |
|---|---|---|
| VER | 1 字节 | 协议版本，始终为 `0x05` |
| NMETHODS | 1 字节 | 提供的认证方法数量 |
| METHODS | 1..255 字节 | 认证方法 ID 列表 |

#### 服务器 -> 客户端：方法响应

```
+----+--------+
|VER | METHOD |
+----+--------+
| 1  |   1    |
+----+--------+
```

| 字段 | 大小 | 描述 |
|---|---|---|
| VER | 1 字节 | 协议版本，始终为 `0x05` |
| METHOD | 1 字节 | 选定的认证方法 |

#### 认证方法

| 值 | 名称 | 描述 |
|---|---|---|
| `0x00` | 无需认证 | 不需要认证 |
| `0x01` | GSSAPI | GSS-API 认证 |
| `0x02` | 用户名/密码 | RFC 1929 用户名/密码 |
| `0x03` - `0x7E` | IANA 分配 | 保留供将来使用 |
| `0x7F` - `0xFE` | 私有方法保留 | 私有使用 |
| `0xFF` | 无可接受的方法 | 服务器拒绝所有提供的方法 |

### 2.3 阶段 2：用户名/密码认证（RFC 1929，可选）

仅当协商期间选择了 METHOD `0x02` 时执行。

#### 客户端 -> 服务器：认证请求

```
+----+------+----------+------+----------+
|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
+----+------+----------+------+----------+
| 1  |  1   | 1..255   |  1   | 1..255   |
+----+------+----------+------+----------+
```

| 字段 | 大小 | 描述 |
|---|---|---|
| VER | 1 字节 | 认证子协商版本，始终为 `0x01` |
| ULEN | 1 字节 | 用户名长度（1-255） |
| UNAME | ULEN 字节 | 用户名字符串 |
| PLEN | 1 字节 | 密码长度（1-255） |
| PASSWD | PLEN 字节 | 密码字符串 |

最大总大小：1 + 1 + 255 + 1 + 255 = **513 字节**

#### 服务器 -> 客户端：认证响应

```
+----+--------+
|VER | STATUS |
+----+--------+
| 1  |   1    |
+----+--------+
```

| 字段 | 大小 | 描述 |
|---|---|---|
| VER | 1 字节 | 认证版本，始终为 `0x01` |
| STATUS | 1 字节 | `0x00` = 成功，`0x01` = 失败 |

### 2.4 阶段 3：命令请求

认证完成后（或如果不需要认证），客户端发送命令请求。

#### 客户端 -> 服务器：请求

```
+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  |   1   |  1   | 可变长度 |    2     |
+----+-----+-------+------+----------+----------+
```

| 字段 | 大小 | 描述 |
|---|---|---|
| VER | 1 字节 | 协议版本，始终为 `0x05` |
| CMD | 1 字节 | 命令代码 |
| RSV | 1 字节 | 保留，必须为 `0x00` |
| ATYP | 1 字节 | 地址类型 |
| DST.ADDR | 可变长度 | 目标地址 |
| DST.PORT | 2 字节 | 目标端口（网络字节序，大端序） |

#### 命令

| 值 | 名称 | 描述 |
|---|---|---|
| `0x01` | CONNECT | 建立 TCP 隧道 |
| `0x02` | BIND | 监听传入连接（反向代理） |
| `0x03` | UDP ASSOCIATE | 建立 UDP 中继关联 |

#### 地址类型

| 值 | ATYP | DST.ADDR 大小 | 格式 |
|---|---|---|---|
| `0x01` | IPv4 | 4 字节 | 网络字节序的 IPv4 地址 |
| `0x03` | 域名 | 1 + N 字节 | 1 字节域名长度，后跟 N 字节域名字符串 |
| `0x04` | IPv6 | 16 字节 | 网络字节序的 IPv6 地址 |

#### 服务器 -> 客户端：响应

```
+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  |   1   |  1   | 可变长度 |    2     |
+----+-----+-------+------+----------+----------+
```

| 字段 | 大小 | 描述 |
|---|---|---|
| VER | 1 字节 | 协议版本，始终为 `0x05` |
| REP | 1 字节 | 回复代码（见下文） |
| RSV | 1 字节 | 保留，必须为 `0x00` |
| ATYP | 1 字节 | 服务器绑定地址类型 |
| BND.ADDR | 可变长度 | 服务器绑定地址 |
| BND.PORT | 2 字节 | 服务器绑定端口（网络字节序） |

#### 回复代码

| 值 | 名称 | 描述 |
|---|---|---|
| `0x00` | 成功 | 请求已授予 |
| `0x01` | 通用服务器故障 | 通用故障 |
| `0x02` | 连接不允许 | 规则集拒绝连接 |
| `0x03` | 网络不可达 | 网络层错误 |
| `0x04` | 主机不可达 | 目标主机不可达 |
| `0x05` | 连接被拒绝 | 来自目标的 TCP RST |
| `0x06` | TTL 过期 | 生存时间超时 |
| `0x07` | 命令不支持 | CMD 未实现 |
| `0x08` | 地址类型不支持 | ATYP 不支持 |

### 2.5 阶段 4：数据转发

#### CONNECT：TCP 隧道

成功响应后，连接成为透明 TCP 隧道。数据在客户端和目标之间双向流动。

```
客户端 <-> Prism 代理 <-> 目标服务器
  [原始字节]    [拷贝]     [原始字节]
```

#### UDP ASSOCIATE：UDP 中继

代理绑定一个独立的 UDP 套接字。客户端向该套接字发送 SOCKS5 包装的 UDP 数据报。

UDP 数据报格式（RFC 1928 第 7 节）：

```
+----+------+------+----------+----------+----------+
|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
+----+------+------+----------+----------+----------+
| 2  |  1   |  1   | 可变长度 |    2     | 可变长度 |
+----+------+------+----------+----------+----------+
```

| 字段 | 大小 | 描述 |
|---|---|---|
| RSV | 2 字节 | 保留，必须为 `0x0000` |
| FRAG | 1 字节 | 分片编号（`0x00` = 不分片） |
| ATYP | 1 字节 | 地址类型 |
| DST.ADDR | 可变长度 | 目标地址 |
| DST.PORT | 2 字节 | 目标端口 |
| DATA | 可变长度 | 载荷数据 |

---

## 3. Prism 架构

### 3.2 协议检测

检测位于 `psm::protocol::analysis::detect()`（analysis.cpp 第 98-129 行）：

```cpp
// 首先检查：SOCKS5
if (peek_data[0] == 0x05)
{
    return protocol_type::socks5;
}
```

SOCKS5 在 HTTP 和 TLS **之前**检查，因为 `0x05` 是唯一签名——没有其他受支持的协议以该字节开头。检测仅需 **1 字节**的预读数据。

### 3.3 处理器分派

`protocol_type::socks5`（枚举索引 2）在编译期处理器表中映射到 `pipeline::socks5`（table.hpp 第 52 行）。

### 3.4 类层次结构

```
transport::transmission（抽象接口）
    |
    +-- socks5::relay（继承 transmission）
            |
            +-- next_layer_: shared_transmission（装饰的传输层）
            +-- config_: socks5::config（只读设置）
            +-- account_directory_: 裸指针（凭据查找）
            +-- account_lease_: account::lease（RAII 连接跟踪）
```

`relay` 类实现 `transmission` 接口（`async_read_some`、`async_write_some`、`close`、`cancel`），使其可在任何期望 transmission 的地方使用。调用 `release()` 后，`next_layer_` 被转移到隧道。

### 3.5 UDP 中继架构

```
                    +---------------------+
  控制通道          |  socks5::relay      |
  (TCP)             |                     |
  客户端 ---------> |  async_associate()  |
                    |       |             |
                    |  +----v------+      |
                    |  |ingress_socket|   |
                    |  +----+------+      |
                    +-------|-------------+
                            | UDP
                            v
                    +-------+------+
                    | route_callback|
                    | (数据报      |
                    |  路由器)      |
                    +-------+------+
                            |
                            v
                    +-------+------+
                    |egress_socket |
                    | (到目标)      |
                    +--------------+
```

UDP 中继在 `associate_loop()` 中运行，该函数并发等待：
1. `ingress_socket` 上的 UDP 数据报
2. 通过 `net::steady_timer` 的空闲超时
3. 通过 `wait_control_close()` 的控制通道关闭

循环在定时器触发或控制 TCP 连接关闭时退出。

---

## 4. 调用层次结构

### 4.1 完整调用链（自上而下）

```
listener (io_context::accept)
  |
  v
balancer::select_worker
  |
  v
worker::launch
  |
  v
session::start()
  |
  v
session::diversion()
  |
  +-- 步骤 1: protocol::probe(inbound, 24)
  |       +-- async_read_some (24 字节)
  |       +-- peek_view[0] == 0x05?
  |           是 -> protocol_type::socks5
  |
  +-- 步骤 2: 伪装管道（SOCKS5 跳过）
  |
  +-- 步骤 3: dispatch::dispatch(ctx, protocol_type::socks5, span)
              |
              +-- handler_table[2] -> pipeline::socks5(ctx, span)
                  |
                  +-- wrap_with_preview(ctx, span) -> inbound
                  +-- protocol::socks5::make_relay(inbound, config, account_dir)
                  +-- relay->handshake()
                  |   |
                  |   +-- negotiated_authentication()
                  |   |   +-- async_read_impl(2 字节) -> VER + NMETHODS
                  |   |   +-- 验证 VER == 0x05
                  |   |   +-- async_read_impl(NMETHODS 字节) -> METHODS
                  |   |   +-- 扫描 METHODS 查找 no_auth (0x00) 和 password (0x02)
                  |   |   +-- [如果 enable_auth && account_dir && password_supported]
                  |   |   |   +-- 写入响应 {0x05, 0x02}（密码）
                  |   |   |   +-- perform_password_auth()
                  |   |   |       +-- async_read_impl(2 字节) -> VER + ULEN
                  |   |   |       +-- async_read_impl(ulen + 1 + 255 字节)
                  |   |   |       +-- wire::parse_password_auth()
                  |   |   |       +-- crypto::sha224(password)
                  |   |   |       +-- account::try_acquire(directory, credential)
                  |   |   |       +-- write_password_auth_response(success)
                  |   |   |
                  |   |   +-- [如果 no_auth_supported && !enable_auth]
                  |   |   |   +-- 写入响应 {0x05, 0x00}（无需认证）
                  |   |   |
                  |   |   +-- [否则] -> 写入响应 {0x05, 0xFF}（无方法）
                  |   |
                  |   +-- read_request_header()
                  |   |   +-- async_read_impl(4 字节) -> VER + CMD + RSV + ATYP
                  |   |   +-- wire::parse_header() -> header_parse
                  |   |
                  |   +-- [根据 header.cmd 切换]
                  |   |   +-- connect:    检查 enable_tcp，设置 form=stream
                  |   |   +-- udp_associate: 检查 enable_udp，设置 form=datagram
                  |   |   +-- bind:       检查 enable_bind，设置 form=stream
                  |   |   +-- default:    写入 command_not_supported 响应
                  |   |
                  |   +-- [根据 header.atyp 切换]
                  |       +-- ipv4:  read_address<4>(parse_ipv4)
                  |       |          +-- async_read_impl(6 字节) -> 地址(4) + 端口(2)
                  |       |          +-- wire::parse_ipv4() + wire::decode_port()
                  |       |
                  |       +-- ipv6:  read_address<16>(parse_ipv6)
                  |       |          +-- async_read_impl(18 字节) -> 地址(16) + 端口(2)
                  |       |          +-- wire::parse_ipv6() + wire::decode_port()
                  |       |
                  |       +-- domain: read_domain_address()
                  |                  +-- async_read_impl(1 字节) -> 域名长度
                  |                  +-- async_read_impl(len + 2 字节) -> 域名 + 端口
                  |                  +-- wire::parse_domain() + wire::decode_port()
                  |
                  +-- [根据 pipeline::socks5 中的 request.cmd 切换]
                      |
                      +-- CONNECT (0x01)
                      |   +-- protocol::analysis::resolve -> 目标 {主机, 端口}
                      |   +-- primitives::dial(router, "SOCKS5", target, ...)
                      |   +-- [如果拨号失败]
                      |   |   +-- async_write_error(host_unreachable)
                      |   |   +-- co_return
                      |   |
                      |   +-- async_write_success(request)
                      |   +-- primitives::tunnel(relay->release(), outbound, ctx)
                      |
                      +-- UDP_ASSOCIATE (0x03)
                      |   +-- primitives::make_datagram_router()
                      |   +-- relay->async_associate(request, datagram_router)
                      |       +-- bind_datagram_port()
                      |       +-- async_write_associate_success(request, local_endpoint)
                      |       +-- associate_loop() || wait_control_close()
                      |
                      +-- BIND (0x02)
                          +-- async_write_error(command_not_supported)
```

### 4.2 关键函数签名

```cpp
// 管道入口点
auto pipeline::socks5(session_context &ctx, std::span<const std::byte> data)
    -> net::awaitable<void>;

// 中继器工厂
auto protocol::socks5::make_relay(
    shared_transmission next_layer,
    const config &cfg = {},
    agent::account::directory *account_dir = nullptr)
    -> shared_relay;

// 握手（完整协议协商）
auto relay::handshake()
    -> net::awaitable<std::pair<fault::code, request>>;

// 线路级解析
auto wire::parse_header(std::span<const std::uint8_t> buffer)
    -> std::pair<fault::code, header_parse>;

auto wire::parse_ipv4(std::span<const std::uint8_t> buffer)
    -> std::pair<fault::code, ipv4_address>;

auto wire::parse_domain(std::span<const std::uint8_t> buffer)
    -> std::pair<fault::code, domain_address>;

auto wire::decode_port(std::span<const std::uint8_t> buffer)
    -> std::pair<fault::code, uint16_t>;

auto wire::decode_udp_header(std::span<const std::uint8_t> buffer)
    -> std::pair<fault::code, udp_header_parse>;

auto wire::encode_udp_header(const udp_header &header, memory::vector<std::uint8_t> &out)
    -> fault::code;

auto wire::parse_password_auth(std::span<const std::uint8_t> data)
    -> std::pair<fault::code, password_auth_request>;

auto wire::build_password_auth_response(bool success)
    -> std::array<std::uint8_t, 2>;

// 响应写入
auto relay::async_write_success(const request &info)
    -> net::awaitable<fault::code>;

auto relay::async_write_error(reply_code code)
    -> net::awaitable<fault::code>;

// UDP 中继
auto relay::async_associate(const request &request_info, route_callback route_callback) const
    -> net::awaitable<fault::code>;
```

---

## 5. 完整生命周期

### 5.1 CONNECT 命令生命周期（无认证）

```
  客户端                Prism 代理                  目标服务器
    |                        |                            |
    |  SYN                   |                            |
    |----------------------->|                            |
    |                        |  probe(24 字节)            |
    |                        |  detect: VER=0x05 -> socks5|
    |                        |                            |
    |  协商:                  |                            |
    |  \x05\x01\x00          |                            |
    |----------------------->|                            |
    |                        |  negotiated_authentication()
    |                        |  VER=0x05, NMETHODS=1, METHOD=[0x00]
    |                        |  -> 选择 no_auth
    |                        |                            |
    |  方法响应:              |                            |
    |  \x05\x00              |                            |
    |<-----------------------|                            |
    |                        |                            |
    |  命令请求:              |                            |
    |  \x05\x01\x00\x01      |                            |
    |  \xC0\xA8\x01\x01      |                            |
    |  \x00\x50              |                            |
    |  (CONNECT 192.168.1.1:80)                          |
    |----------------------->|                            |
    |                        |  handshake()               |
    |                        |  read_request_header()     |
    |                        |  -> CMD=0x01, ATYP=0x01    |
    |                        |  read_address<4>()         |
    |                        |  -> 地址=192.168.1.1, 端口=80
    |                        |                            |
    |                        |  primitives::dial()        |
    |                        |  TCP 连接 192.168.1.1:80   |
    |                        |--------------------------->|
    |                        |         SYN-ACK            |
    |                        |<---------------------------|
    |                        |                            |
    |  响应:                  |                            |
    |  \x05\x00\x00\x01      |                            |
    |  \x00\x00\x00\x00      |                            |
    |  \x00\x00              |                            |
    |  (成功, BND=0.0.0.0:0)                             |
    |<-----------------------|                            |
    |                        |                            |
    |  HTTP GET / ...        |                            |
    |----------------------->|                            |
    |                        |  primitives::tunnel()      |
    |                        |  双向透明转发               |
    |                        |--------------------------->|
    |                        |         HTTP GET /         |
    |                        |                            |
    |  HTTP 200 OK ...       |                            |
    |<-----------------------|                            |
    |                        |         HTTP 200 OK ...    |
    |                        |<---------------------------|
    |                        |                            |
    |  ... 数据 ...           |                            |
    |<======================>|===========================>|
    |                        |                            |
    |  FIN                   |  FIN                       |
    |----------------------->|--------------------------->|
    |                        |                     FIN-ACK|
    |                        |<---------------------------|
    |  FIN-ACK               |                            |
    |<-----------------------|                            |
    |                        |  session::release_resources()
```

### 5.2 带密码认证的 CONNECT 命令（RFC 1929）

```
  客户端                Prism 代理
    |                        |
    |  协商:                  |
    |  \x05\x02\x00\x02      |
    |  (VER=5, NMETHODS=2,   |
    |   METHODS=[无需认证,    |
    |            密码])       |
    |----------------------->|
    |                        |  negotiated_authentication()
    |                        |  enable_auth=true, password_supported=true
    |                        |  -> 选择密码认证 (0x02)
    |                        |
    |  方法响应:              |
    |  \x05\x02              |
    |<-----------------------|
    |                        |
    |  认证请求:              |
    |  \x01\x04              |
    |  user\x08              |
    |  password              |
    |  (VER=1, ULEN=4,       |
    |   UNAME="user",        |
    |   PLEN=8,              |
    |   PASSWD="password")   |
    |----------------------->|
    |                        |  perform_password_auth()
    |                        |  parse_password_auth()
    |                        |  -> 用户名="user", 密码="password"
    |                        |  sha224("password") -> 凭据哈希
    |                        |  account::try_acquire(directory, credential)
    |                        |  -> 获取租约
    |                        |
    |  认证响应:              |
    |  \x01\x00              |
    |  (VER=1, STATUS=0x00)  |
    |<-----------------------|
    |                        |
    |  命令请求:              |
    |  \x05\x01\x00\x03      |
    |  \x0A                  |
    |  example.com           |
    |  \x01\xBB              |
    |  (CONNECT example.com:443)
    |----------------------->|
    |                        |  继续标准 CONNECT 流程...
```

### 5.3 UDP ASSOCIATE 生命周期

```
  客户端                Prism 代理                  目标（DNS 服务器）
    |                        |                            |
    |  协商:                  |                            |
    |  \x05\x01\x00          |                            |
    |----------------------->|                            |
    |  方法响应:              |                            |
    |  \x05\x00              |                            |
    |<-----------------------|                            |
    |                        |                            |
    |  UDP_ASSOCIATE:        |                            |
    |  \x05\x03\x00\x01      |                            |
    |  \x00\x00\x00\x00      |                            |
    |  \x00\x00              |                            |
    |  (CMD=0x03, DST=0.0.0.0:0)                         |
    |----------------------->|                            |
    |                        |  handshake()               |
    |                        |  -> CMD=0x03, form=datagram|
    |                        |                            |
    |                        |  bind_datagram_port()      |
    |                        |  UDP 套接字绑定至 :10800   |
    |                        |                            |
    |  响应:                  |                            |
    |  \x05\x00\x00\x01      |                            |
    |  \x0A\x00\x00\x01      |                            |
    |  \x2A\x30              |                            |
    |  (成功, BND=10.0.0.1:10800)                         |
    |<-----------------------|                            |
    |                        |                            |
    |  UDP 数据报到          |                            |
    |  代理:10800:           |                            |
    |  \x00\x00\x00\x01      |                            |
    |  \x08\x08\x08\x08      |                            |
    |  \x00\x35              |                            |
    |  <DNS 查询>            |                            |
    |=======================>|                            |
    |                        |  decode_udp_header()       |
    |                        |  -> DST=8.8.8.8:53         |
    |                        |  route_callback()          |
    |                        |  egress_socket.send()      |
    |                        |--------------------------->|
    |                        |         DNS 查询           |
    |                        |                            |
    |                        |         DNS 响应           |
    |                        |<---------------------------|
    |                        |  encode_udp_datagram()     |
    |                        |  -> 包装 SOCKS5 头部       |
    |  UDP 响应:              |                            |
    |  \x00\x00\x00\x01      |                            |
    |  \x08\x08\x08\x08      |                            |
    |  \x00\x35              |                            |
    |  <DNS 响应>            |                            |
    |<=======================|                            |
    |                        |                            |
    |  [继续 UDP 中继]       |                            |
    |<======================>|===========================>|
    |                        |                            |
    |  [空闲超时 60s]        |                            |
    |                        |  idle_timer 触发           |
    |                        |  associate_loop 退出       |
    |                        |  ingress_socket 关闭       |
```

### 5.4 BIND 命令（被拒绝）

```
  客户端                Prism 代理
    |                        |
    |  协商:                  |
    |  \x05\x01\x00          |
    |----------------------->|
    |  \x05\x00              |
    |<-----------------------|
    |                        |
    |  BIND 请求:             |
    |  \x05\x02\x00\x01      |
    |  \x00\x00\x00\x00      |
    |  \x00\x00              |
    |  (CMD=0x02, DST=0.0.0.0:0)
    |----------------------->|
    |                        |  handshake()
    |                        |  -> CMD=0x02
    |                        |  -> enable_bind=false（默认）
    |                        |  -> 写入 command_not_supported
    |                        |
    |  错误响应:              |
    |  \x05\x07\x00\x01      |
    |  \x00\x00\x00\x00      |
    |  \x00\x00              |
    |  (REP=命令不支持)
    |<-----------------------|
    |                        |  管道返回
    |                        |  session 释放资源
```

---

## 6. 二进制格式示例

### 6.1 方法协商（完整交换）

#### 客户端请求
```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  05 02 00 02                                       ....
```
- `0x05`: VER（SOCKS5）
- `0x02`: NMETHODS（提供 2 种方法）
- `0x00`: METHOD[0] = 无需认证
- `0x02`: METHOD[1] = 用户名/密码

#### 服务器响应（选择密码认证）
```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  05 02                                             ..
```
- `0x05`: VER
- `0x02`: METHOD（用户名/密码）

#### 服务器响应（选择无需认证）
```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  05 00                                             ..
```
- `0x05`: VER
- `0x00`: METHOD（无需认证）

### 6.2 密码认证（RFC 1929）

#### 客户端认证请求（用户名="admin"，密码="secret123"）
```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  01 05 61 64 6D 69 6E 09 73 65 63 72 65 74 31 32   ..admin..secret12
000010  33                                                  3
```
- `0x01`: VER（认证子协商版本）
- `0x05`: ULEN（5 字节）
- `61 64 6D 69 6E`: UNAME（"admin"）
- `0x09`: PLEN（9 字节）
- `73 65 63 72 65 74 31 32 33`: PASSWD（"secret123"）

总计：18 字节

#### 服务器认证响应（成功）
```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  01 00                                             ..
```
- `0x01`: VER
- `0x00`: STATUS（成功）

#### 服务器认证响应（失败）
```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  01 01                                             ..
```
- `0x01`: VER
- `0x01`: STATUS（失败）

### 6.3 CONNECT 请求（IPv4）

```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  05 01 00 01 C0 A8 01 01 00 50                    .........P
```
- `0x05`: VER
- `0x01`: CMD（CONNECT）
- `0x00`: RSV
- `0x01`: ATYP（IPv4）
- `C0 A8 01 01`: DST.ADDR（192.168.1.1）
- `00 50`: DST.PORT（80，大端序）

总计：10 字节

### 6.4 CONNECT 请求（域名）

```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  05 01 00 03 0B 65 78 61 6D 70 6C 65 2E 63 6F 6D   .....example.com
000010  01 BB                                             ..
```
- `0x05`: VER
- `0x01`: CMD（CONNECT）
- `0x00`: RSV
- `0x03`: ATYP（域名）
- `0x0B`: 域名长度（11 字节）
- `65 78 61 6D 70 6C 65 2E 63 6F 6D`: "example.com"
- `01 BB`: DST.PORT（443，大端序）

总计：17 字节

### 6.5 CONNECT 请求（IPv6）

```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  05 01 00 04 20 01 0D B8 00 00 00 00 00 00 00 00   .... ...........
000010  00 00 00 01 00 50                                 .....P
```
- `0x05`: VER
- `0x01`: CMD（CONNECT）
- `0x00`: RSV
- `0x04`: ATYP（IPv6）
- `20 01 0D B8 ... 00 01`: DST.ADDR（2001:db8::1）
- `00 50`: DST.PORT（80）

总计：22 字节

### 6.6 CONNECT 成功响应

```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  05 00 00 01 00 00 00 00 00 00                    ..........
```
- `0x05`: VER
- `0x00`: REP（成功）
- `0x00`: RSV
- `0x01`: ATYP（IPv4）
- `00 00 00 00`: BND.ADDR（0.0.0.0）
- `00 00`: BND.PORT（0）

总计：10 字节

### 6.7 错误响应

#### 主机不可达（拨号失败）
```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  05 04 00 01 00 00 00 00 00 00                    ..........
```
- `0x05`: VER
- `0x04`: REP（host_unreachable）

#### 命令不支持（BIND 被拒绝）
```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  05 07 00 01 00 00 00 00 00 00                    ..........
```
- `0x05`: VER
- `0x07`: REP（command_not_supported）

### 6.8 UDP 数据报

#### 客户端 -> 代理：通过 SOCKS5 UDP 的 DNS 查询
```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  00 00 00 01 08 08 08 08 00 35 12 34 01 00 00 01   .........5.4....
000010  00 00 00 00 00 00 06 67 6F 6F 67 6C 65 03 63 6F   .......google.co
000020  6D 00 00 01 00 01                                  m.....
```
- `00 00`: RSV（保留）
- `00`: FRAG（不分片）
- `01`: ATYP（IPv4）
- `08 08 08 08`: DST.ADDR（8.8.8.8）
- `00 35`: DST.PORT（53）
- `12 34 ...`: DNS 查询载荷

### 6.9 无可接受方法响应

```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  05 FF                                             ..
```
- `0x05`: VER
- `0xFF`: METHOD（NO_ACCEPTABLE_METHODS）

---

## 7. 配置参数

### 7.1 JSON 配置

SOCKS5 在 `configuration.json` 的 `protocol.socks5` 部分中配置：

```json
{
    "addressable": ["0.0.0.0:1080"],
    "protocol": {
        "socks5": {
            "enable_tcp": true,
            "enable_udp": true,
            "enable_bind": false,
            "udp_bind_port": 0,
            "udp_idle_timeout": 60,
            "udp_max_datagram": 65535,
            "enable_auth": false
        }
    },
    "authentication": {
        "users": [
            { "password": "mysecretpassword" }
        ]
    }
}
```

### 7.2 配置参数

| 参数 | 类型 | 默认值 | 描述 |
|---|---|---|---|
| `enable_tcp` | `bool` | `true` | 启用 CONNECT 命令（TCP 隧道） |
| `enable_udp` | `bool` | `true` | 启用 UDP_ASSOCIATE 命令（UDP 中继） |
| `enable_bind` | `bool` | `false` | 启用 BIND 命令（出于安全考虑默认禁用） |
| `udp_bind_port` | `uint16` | `0` | 固定的 UDP 中继端口。`0` 表示操作系统自动分配端口 |
| `udp_idle_timeout` | `uint32` | `60` | 关闭 UDP 关联前的无活动秒数 |
| `udp_max_datagram` | `uint32` | `65535` | 最大 UDP 数据报大小（最大 IP 包大小） |
| `enable_auth` | `bool` | `false` | 启用 RFC 1929 用户名/密码认证 |

### 7.3 配置行为

| 设置 | 效果 |
|---|---|
| `enable_tcp=false` | CONNECT 请求被拒绝，返回 `connection_not_allowed` (0x02) |
| `enable_udp=false` | UDP_ASSOCIATE 请求被拒绝，返回 `connection_not_allowed` (0x02) |
| `enable_bind=true` | BIND 请求被接受（Prism 管道中尚未完全实现） |
| `udp_bind_port=0` | 系统分配临时端口，在 UDP_ASSOCIATE 响应的 BND.PORT 中返回 |
| `udp_idle_timeout=0` | 无空闲超时（仅在控制连接关闭时终止） |
| `enable_auth=true` | 方法协商选择密码认证（如果客户端支持）；如果客户端仅提供 no_auth 则拒绝 |

### 7.4 配置结构体（源码）

```cpp
// include/prism/protocol/socks5/config.hpp
struct config
{
    bool enable_tcp = true;              // TCP CONNECT 默认启用
    bool enable_udp = true;              // UDP 中继默认启用
    bool enable_bind = false;            // BIND 默认禁用
    std::uint16_t udp_bind_port = 0;     // 0 = 自动分配
    std::uint32_t udp_idle_timeout = 60; // 60 秒空闲超时
    std::uint32_t udp_max_datagram = 65535; // 最大 UDP 包大小
    bool enable_auth = false;            // 默认禁用认证
};
```

---

## 8. 边缘情况与错误处理

### 8.1 错误码映射

| 场景 | fault::code | 发送的 SOCKS5 REP | 源 |
|---|---|---|---|
| 协商期间读取错误 | `io_error` | 无（静默关闭） | `stream.hpp` 第 612 行 |
| 协议版本错误 | `protocol_error` | 无 | `stream.hpp` 第 618 行 |
| 无可接受的认证方法 | `not_supported` | `0xFF`（写入后返回错误） | `stream.hpp` 第 681 行 |
| 认证解析错误 | `bad_message` | `0x01 0x01`（认证失败） | `stream.hpp` 第 707-709 行 |
| 认证凭据不匹配 | `success`（认证失败但无错误） | `0x01 0x01`（认证失败） | `stream.hpp` 第 736-739 行 |
| 命令被配置禁用 | `not_supported` | `connection_not_allowed` (0x02) | `stream.hpp` 第 237-238 行 |
| BIND 未启用 | `unsupported_command` | `command_not_supported` (0x07) | `stream.hpp` 第 253-254 行 |
| 未知命令 | `unsupported_command` | `command_not_supported` (0x07) | `stream.hpp` 第 259-260 行 |
| 不支持的地址类型 | `unsupported_address` | 无 | `stream.hpp` 第 299 行 |
| IPv6 禁用 | `ipv6_disabled` | `network_unreachable` (0x03) | `socks5.cpp` 第 58-60 行 |
| 拨号失败（通用） | `*` | `host_unreachable` (0x04) | `socks5.cpp` 第 64-65 行 |
| UDP 关联失败 | `*` | 已记录，无响应（已发送成功） | `socks5.cpp` 第 94-97 行 |
| UDP FRAG != 0 | `not_supported` | 无（数据报丢弃） | `wire.hpp` 第 266-269 行 |
| UDP RSV != 0x0000 | `protocol_error` | 无（数据报丢弃） | `wire.hpp` 第 260-263 行 |

### 8.2 认证边缘情况

| 场景 | 行为 | 源 |
|---|---|---|
| `enable_auth=true` 但客户端仅提供 `0x00`（无需认证） | 服务器响应 `0xFF`（无可接受的方法） | `stream.hpp` 第 675-681 行 |
| `enable_auth=true` 但 `account_directory_` 为空 | 如果客户端支持则回退到 no_auth | `stream.hpp` 第 645 行（条件失败） |
| 认证请求中 ULEN = 0 | 发送认证失败响应 | `stream.hpp` 第 705-709 行 |
| 认证请求中 PLEN = 0 | `wire::parse_password_auth` 返回 `bad_message` | `wire.hpp` 第 418-420 行 |
| 用户名 > 255 字节 | 不可能（ULEN 为 1 字节，最大 255） | 协议限制 |
| 认证请求总大小 > 513 字节 | 缓冲区为 513 字节，不可能溢出 | `stream.hpp` 第 695 行 |

### 8.3 协议错误处理

| 场景 | 检测 | 行为 |
|---|---|---|
| 协商中 VER != 0x05 | `methods_buffer[0] != 0x05` | 返回 `protocol_error`，不发送响应 |
| 请求中 VER != 0x05 | `wire::parse_header()` 返回 `protocol_error` | 返回 `protocol_error`，不发送响应 |
| 请求中 RSV != 0x00 | 不验证（根据 RFC 1928 忽略） | 无操作 |
| UDP 数据报中 RSV != 0x0000 | `buffer[0] != 0x00 || buffer[1] != 0x00` | 返回 `protocol_error`，丢弃数据报 |
| UDP 数据报中 FRAG != 0 | `frag != 0` | 返回 `not_supported`，丢弃数据报 |
| 缓冲区不足以容纳头 | `buffer.size() < 4` | 返回 `bad_message` |
| 域名长度超过缓冲区 | `len > addr.value.size()` | 返回 `bad_message` |
| 地址数据不完整 | 每个解析器中的缓冲区大小检查 | 返回 `bad_message` |

### 8.4 UDP 中继边缘情况

| 场景 | 行为 | 源 |
|---|---|---|
| 入口数据报无载荷（仅头部） | `parsed.header_size >= ingress_packet.size()` -> 丢弃 | `stream.hpp` 第 513-516 行 |
| 路由回调失败 | 数据报静默丢弃 | `stream.hpp` 第 508-511 行 |
| 出口套接字打开失败 | 数据报静默丢弃 | `stream.hpp` 第 522-525 行 |
| 发送到目标失败 | 数据报静默丢弃 | `stream.hpp` 第 528-532 行 |
| 从目标接收失败 | 数据报静默丢弃 | `stream.hpp` 第 537-540 行 |
| UDP 中继期间控制连接关闭 | `wait_control_close` 取消入口套接字 | `stream.hpp` 第 567-576 行 |
| 空闲超时触发 | `associate_loop` 通过 `co_return` 退出 | `stream.hpp` 第 457-460 行 |
| 操作已中止（取消） | `associate_loop` 通过 `co_return` 退出 | `stream.hpp` 第 465-467 行 |
| UDP 竞态：控制关闭 + 空闲超时 | `||` 运算符：先完成者获胜 | `stream.hpp` 第 191 行 |

### 8.5 网络错误场景

| 场景 | 影响 | 清理 |
|---|---|---|
| 方法协商期间客户端断开 | `async_read_impl` 返回错误码 | `handshake()` 返回错误，会话关闭 |
| 认证期间客户端断开 | `async_read_impl` 返回错误码 | `perform_password_auth()` 返回错误 |
| 命令请求期间客户端断开 | `async_read_impl` 返回错误码 | `read_request_header()` 返回错误 |
| UDP 中继期间客户端断开 | 检测到控制通道 EOF | `wait_control_close` 取消 UDP 套接字 |
| 目标服务器不可达 | `primitives::dial` 返回错误 | 发送 `async_write_error(host_unreachable)` |
| 目标服务器拒绝连接 | 拨号期间 TCP RST | `host_unreachable` 响应 |
| 网络接口断开 | `bind_datagram_port` 失败 | `server_failure` 响应，UDP 关联中止 |

### 8.6 内存和缓冲区约束

| 约束 | 值 | 源 |
|---|---|---|
| 方法缓冲区 | 258 字节（栈分配） | `stream.hpp` 第 607 行 |
| 认证缓冲区 | 513 字节（栈分配） | `stream.hpp` 第 695 行 |
| 请求头缓冲区 | 4 字节（栈分配） | `stream.hpp` 第 766 行 |
| IPv4 读取缓冲区 | 6 字节（栈分配） | `stream.hpp` 第 797 行（N=4） |
| IPv6 读取缓冲区 | 18 字节（栈分配） | `stream.hpp` 第 797 行（N=16） |
| 域名读取缓冲区 | 258 字节（栈分配） | `stream.hpp` 第 838 行 |
| 成功响应缓冲区 | 262 字节（栈分配） | `stream.hpp` 第 315 行 |
| 错误响应 | 10 字节（栈分配常量） | `stream.hpp` 第 332 行 |
| UDP 最大数据报 | 可配置，默认 65535 | `config.hpp` 第 43 行 |
| UDP 响应数据报 | PMR 分配自 `memory::current_resource()` | `stream.hpp` 第 547 行 |

### 8.7 竞态条件与并发

| 关注点 | 缓解措施 |
|---|---|
| `relay` 被多个协程访问 | 设计上非线程安全；在单个工作线程内使用 |
| 认证期间读取 `account_directory_` | 写时复制目录确保无锁读取 |
| 认证后更新 `account_lease_` | 在握手协程内单线程执行 |
| UDP 中继并发数据报 | `associate_loop` 中顺序处理（一次一个） |
| 控制关闭与空闲超时竞态 | `awaitable_operators::||` 解析为第一个完成的操作 |

### 8.8 最小预读数据要求

| 协议 | 最小字节数 | 检测方法 |
|---|---|---|
| SOCKS5 | 1 字节 | `peek_data[0] == 0x05` |
| HTTP | 4 字节（最短方法 "GET "） | 与 9 种方法前缀匹配 |
| TLS | 2 字节（`0x16 0x03`） | 前两字节检查 |

SOCKS5 检测所需数据**最少**（1 字节），使其识别速度最快。

### 8.9 合规性说明

| RFC 要求 | Prism 合规性 | 备注 |
|---|---|---|
| RFC 1928: 方法协商 | 完全合规 | 支持 0x00 和 0x02 方法 |
| RFC 1928: CONNECT 命令 | 完全合规 | TCP 隧道与透明转发 |
| RFC 1928: BIND 命令 | 部分合规 | 返回正确错误，但管道中未完全实现 |
| RFC 1928: UDP ASSOCIATE | 完全合规 | 逐数据报路由与空闲超时 |
| RFC 1928: 地址类型 | 完全合规 | IPv4、IPv6、域名 |
| RFC 1928: 回复代码 | 完全合规 | 实现所有 9 个回复代码 |
| RFC 1929: 密码认证 | 完全合规 | VER=0x01，ULEN/PLEN 格式 |
| RFC 1928: 请求中的 RSV 字段 | 忽略（接受任何值） | RFC 规定"保留，必须为 0x00"但未验证 |
| RFC 1928: UDP 分片（FRAG） | 不支持 | FRAG != 0 的数据报被丢弃 |
