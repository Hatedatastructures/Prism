# Prism 中的 Trojan 协议

> Prism 代理服务器中 Trojan 代理协议的完整参考文档。

---

## 1. 协议背景

### 1.1 起源与历史

Trojan 协议最初由 **GreaterFire** 于 2018 年设计和发布，该开发者专注于规避网络审查。该项目首次在 GitHub 上以 `trojan-gfw/trojan` 仓库发布，并迅速在网络受限地区获得采用。

原始设计的动机来自一个关键观察：大多数深度包检测（DPI）系统通过查找已知代理软件特有的协议签名来识别代理流量（例如 SOCKS5 版本字节 `0x05`、特定的 HTTP 头部或 Shadowsocks 加密模式）。Trojan 采取了完全不同的方法——它使代理流量对任何外部观察者来说**与合法的 TLS 流量无法区分**。

### 1.2 设计理念

Trojan 的设计理念可以概括为一个原则：**流量模仿**。它不是用自定义密码加密流量并希望密文看起来随机，而是将代理命令封装在标准的 TLS 1.2+ 隧道内。对于任何不拥有正确密码的 DPI 系统，该连接看起来与到 Web 服务器的正常 HTTPS 连接完全一样。

关键设计决策：

- **TLS 作为传输层，而非协议**：TLS 提供加密和流量整形。Trojan 协议在 TLS 隧道内的应用层运行。
- **固定格式头部**：TLS 握手完成后，客户端发送固定格式的头部，包含 56 字节的凭据（密码的 SHA224 十六进制摘要），后跟 CRLF、命令字节、地址类型字节、目标地址、目标端口和最终的 CRLF。
- **凭据作为认证**：56 字节凭据是共享密码的 SHA224 十六进制摘要。服务器将此与已知凭据进行比较。如果匹配，服务器继续代理行为。如果不匹配，服务器可以将连接转发到合法的 Web 服务器（诱饵模式）或直接关闭。
- **不对未授权客户端响应**：与 SOCKS5 或 HTTP 代理不同，Trojan 在认证后不向客户端发送任何协议级响应。服务器要么打开到目标的隧道（静默成功），要么关闭连接（静默失败）。

### 1.3 为什么存在 Trojan

Trojan 解决了早期代理协议无法充分解决的几个问题：

1. **主动探测**：审查者可以连接到疑似代理服务器并发送探测包以确定它们是否运行代理软件。标准 TLS 包装的 SOCKS5 在 TLS 握手后仍会暴露 SOCKS5 版本字节（`0x05`）。Trojan 通过将凭据放在首位来避免此问题，如果凭据不匹配，凭据看起来像随机的 HTTP POST 数据。

2. **统计指纹识别**：Shadowsocks 流量虽然加密，但在包大小和时序方面具有可识别的统计模式。TLS 内的 Trojan 流量与普通 HTTPS 无法区分，因为它实际上使用相同的 TLS 记录层。

3. **基于证书的检测**：一些 DPI 系统维护已知代理服务器证书的列表。Prism 中的 Reality 集成生成的证书看起来像合法的网站证书，使得基于证书的检测无效。

4. **简单性与兼容性**：协议足够简单，可以正确实现，TLS 基础意味着它可与任何标准 TLS 库一起工作。Prism 为此使用了 BoringSSL。

### 1.4 原始规范参考

原始 Trojan 协议规范可在以下位置获取：

- **原始仓库**：https://github.com/trojan-gfw/trojan
- **协议文档**：https://trojan-gfw.github.io/trojan/protocol
- **维基百科条目**：https://en.wikipedia.org/wiki/Trojan_(software)

Prism 的实现遵循原始规范，并进行了以下扩展：

- **MUX 命令（0x7F）**：Prism 支持兼容 Mihomo 的 smux 扩展，其中 `cmd=0x7F` 信号通知多路复用会话。这是 Prism 特有的扩展，不在原始 Trojan 规范中。
- **UDP over TLS**：原始规范定义了具有特定帧格式的 UDP_ASSOCIATE。Prism 实现了此功能，包含兼容 mihomo 的 UDP 帧编码，包括 `Length` 字段和 `CRLF` 终止符。
- **Reality 集成**：Prism 在伪装层集成了 Reality TLS 伪装系统，允许 Trojan 使用伪造的 TLS 证书运行，这些证书模仿合法网站。

---

## 2. 协议规范

### 2.1 整体架构

Trojan 作为分层协议运行：

```
+-------------------------------------------+
|         应用数据（载荷）                     |
+-------------------------------------------+
|     Trojan 应用层（命令）                   |
|  [凭据 | CMD | ATYP | 地址 | 端口]         |
+-------------------------------------------+
|          TLS 记录层（加密）                  |
|  [TLS 内容类型 | 版本 | 长度]               |
+-------------------------------------------+
|          TCP 传输层                        |
+-------------------------------------------+
```

### 2.2 TLS 层

Trojan 要求在交换任何 Trojan 特定数据之前建立完全建立的 TLS 1.2+ 连接。TLS 握手与标准 HTTPS 握手完全相同地进行：

1. 客户端发送 `ClientHello`，包含支持的密码套件、扩展和 SNI。
2. 服务器响应 `ServerHello`、证书、`ServerKeyExchange` 和 `ServerHelloDone`。
3. 客户端验证证书并发送 `ClientKeyExchange`、`ChangeCipherSpec` 和加密的 `Finished`。
4. 服务器发送自己的 `ChangeCipherSpec` 和加密的 `Finished`。

TLS 握手完成后，双方切换到加密的应用数据。客户端的第一个应用层字节构成 Trojan 握手。

在 Prism 中，TLS 握手在**伪装方案管道**（会话层）中执行，而不是在 Trojan 管道本身中。流程为：

```
Session::diversion()
  --> probe() 检测到 protocol_type::tls
  --> 伪装方案管道：
        Reality 方案 --> ShadowTLS 方案 --> 原生 TLS 方案
  --> TLS 建立后，读取 TLS 后数据
  --> detect_tls() 确定内层协议
        (Trojan 与 HTTPS 与 VLESS)
  --> 分派到 pipeline::trojan
```

### 2.3 Trojan 握手二进制格式

TLS 握手完成后，客户端发送 Trojan 握手。二进制格式为：

```
+--------+--------+--------+--------+--------+--------+--------+--------+
| 字节 0                                                                  |
|   ...   （共 56 字节：密码的 SHA224 十六进制摘要，ASCII）               |
| 字节 55                                                                 |
+--------+--------+--------+--------+--------+--------+--------+--------+
| 字节 56  | 字节 57  | 字节 58  | 字节 59  | 字节 60+ ...
|   '\r'   |   '\n'   |   CMD    |   ATYP   |  目标地址
+----------+----------+----------+----------+---------------------------+
```

目标地址字段根据 ATYP 而变化：

**IPv4（ATYP=0x01）：**
```
+--------+--------+--------+--------+--------+--------+
| 字节 N   | 字节 N+1  | 字节 N+2  | 字节 N+3  |
|  IPv4 字节 0  |  IPv4 字节 1  |  IPv4 字节 2  |  IPv4 字节 3  |
+-------------+-------------+-------------+-------------+
| 字节 N+4  | 字节 N+5  | 字节 N+6  | 字节 N+7  |
|  端口高位   |  端口低位    |   '\r'      |   '\n'      |
+-------------+-------------+-------------+-------------+
```

**域名（ATYP=0x03）：**
```
+--------+--------+------------------------+--------+--------+
| 长度   | 域名字节（长度字节）               | 端口高 | 端口低 |
+--------+----------------------------------+--------+--------+
| '\r'   | '\n'                             |
+--------+----------------------------------+
```

**IPv6（ATYP=0x04）：**
```
+--------+--------+--------+--------+--------+--------+--------+--------+
| IPv6 字节 0-3（4 字节）                                                 |
+--------+--------+--------+--------+--------+--------+--------+--------+
| IPv6 字节 4-7（4 字节）                                                 |
+--------+--------+--------+--------+--------+--------+--------+--------+
| IPv6 字节 8-11（4 字节）                                                |
+--------+--------+--------+--------+--------+--------+--------+--------+
| IPv6 字节 12-15（4 字节）                                               |
+--------+--------+--------+--------+--------+--------+--------+--------+
| 端口高位 | 端口低位 | '\r'      | '\n'      |
+----------+----------+-----------+-----------+
```

### 2.4 命令值（CMD）

偏移 58 处的 CMD 字节指示客户端请求的操作类型：

| 值    | 名称            | 描述                                  | Prism 支持 |
|--------|-----------------|---------------------------------------|------------|
| `0x01` | `CONNECT`       | 建立到目标的 TCP 隧道                  | 是         |
| `0x03` | `UDP_ASSOCIATE` | 建立 UDP over TLS 关联                 | 是         |
| `0x7F` | `MUX`           | 兼容 Mihomo 的 smux 多路复用会话       | 是（Prism 扩展）|

命令值定义在 `constants.hpp` 中：

```cpp
enum class command : std::uint8_t
{
    connect       = 0x01,
    udp_associate = 0x03,
    mux           = 0x7f
};
```

### 2.5 地址类型值（ATYP）

偏移 59 处的 ATYP 字节指示目标地址的格式：

| 值    | 名称   | 地址长度      | 描述                            |
|--------|--------|---------------|---------------------------------|
| `0x01` | `IPv4` | 4 字节        | 网络字节序的 IPv4 地址          |
| `0x03` | `Domain` | 1 + 长度字节 | 长度前缀的域名（最大 255）       |
| `0x04` | `IPv6` | 16 字节       | 网络字节序的 IPv6 地址          |

地址类型值定义在 `constants.hpp` 中：

```cpp
enum class address_type : std::uint8_t
{
    ipv4   = 0x01,
    domain = 0x03,
    ipv6   = 0x04
};
```

### 2.6 TCP 请求布局

完整的 TCP CONNECT 请求（IPv4）具有以下字节布局：

```
偏移   长度   字段
------ ------ -----
  0      56    凭据（SHA224 十六进制字符串，例如 "a1b2c3..."）
 56       2    CRLF（"\r\n"）
 58       1    CMD（0x01 = CONNECT）
 59       1    ATYP（0x01 = IPv4，0x03 = 域名，0x04 = IPv6）
 60      4/1+长度  地址（IPv4: 4 字节，域名: 1+长度，IPv6: 16 字节）
 60+N     2    目标端口（网络字节序，大端序）
 60+N+2   2    CRLF（"\r\n"）
```

**最小请求大小**：68 字节（无域名的 IPv4）。

**最大请求大小**：320 字节（255 字符名称的域名）。

Prism 分配一个 320 字节的栈缓冲区（`std::array<std::uint8_t, 320>`）以在单次读取操作中容纳最大可能的请求。

### 2.7 UDP 帧格式

Trojan UDP 帧在成功的 `UDP_ASSOCIATE` 握手后在 TLS 隧道内发送。格式兼容 mihomo，包含 `Length` 字段和 `CRLF`：

```
+--------+--------+------------------------+--------+--------+--------+--------+
| ATYP   | 地址（可变）                     | 端口高 | 端口低 | 长度高 | 长度低 |
+--------+---------------------------------+--------+--------+---------+---------+
| '\r'   | '\n'                           | 载荷（长度字节）                      |
+--------+--------------------------------+-------------------------------------+
```

**UDP 帧字段：**

| 字段    | 长度         | 描述                                     |
|----------|--------------|------------------------------------------|
| ATYP     | 1 字节       | 地址类型（0x01=IPv4，0x03=域名，0x04=IPv6）|
| 地址     | 可变         | 基于 ATYP 的目标地址                      |
| 端口     | 2 字节大端序 | 目标端口号                                |
| 长度     | 2 字节大端序 | 载荷字节数                                |
| CRLF     | 2 字节       | 分隔符：`\r\n`（0x0D 0x0A）              |
| 载荷     | 长度字节     | 实际 UDP 数据报内容                       |

**最小 UDP 帧大小**：11 字节（ATYP + IPv4 + 端口 + 长度 + CRLF，零载荷）。

**UDP 帧解析**验证：
1. 缓冲区至少有 11 字节
2. ATYP 是可识别的值
3. 存在给定 ATYP 的地址数据
4. 端口字节可用
5. 长度字节可用
6. CRLF 恰好是 `\r\n`
7. 存在指定长度的载荷

UDP 响应帧（服务器到客户端）反转方向：它编码**发送者**的地址和端口，后跟响应载荷。这允许客户端将响应路由到正确的本地应用程序。

### 2.8 MUX 命令扩展

Prism 使用 **MUX 命令（0x7F）** 扩展了原始 Trojan 协议以支持多路复用会话。有两种方式可以启动 mux 会话：

1. **原生 MUX（cmd=0x7F）**：客户端直接在 Trojan 握手中发送 `cmd=0x7F`。Prism 识别此并立即进入多路复用模式，调用 `multiplex::bootstrap()` 在 TLS 连接上协商 smux/yamux。

2. **兼容 Mihomo 的 MUX（cmd=0x01 + 虚假地址）**：客户端发送正常的 `CONNECT` 请求（`cmd=0x01`），但目标地址以 `.mux.sing-box.arpa` 结尾。Prism 的 `primitives::is_mux_target()` 检测此特殊后缀并将连接路由到多路复用模式，而不是常规隧道。

两种路径导致相同的结果：TLS 连接成为多路复用会话的传输层，在单个物理连接上承载多个逻辑流。

---

## 3. Prism 架构

### 3.2 检测流程

Prism 中的 Trojan 检测是一个**两阶段过程**：

**阶段 1：外层协议检测**（会话层）

```
入站 socket --> probe(*inbound, 24)
                  |
                  +-- 首字节 0x05 --> protocol_type::socks5
                  +-- 首字节 0x16 && 第二字节 0x03 --> protocol_type::tls
                  +-- 以 HTTP 方法开头 --> protocol_type::http
                  +-- 否则 --> protocol_type::shadowsocks（排除法）
```

**阶段 2：TLS 剥离 + 内层协议检测**（伪装层）

```
protocol_type::tls --> 伪装方案管道
                        |
                        +-- Reality 方案（如果配置）
                        |     使用伪造证书进行 TLS 握手 --> 内层数据
                        |
                        +-- ShadowTLS 方案（如果配置）
                        |
                        +-- 原生 TLS 方案
                              标准 TLS 握手 --> 解密流
                              |
                              读取 TLS 后数据（至少 60 字节）
                              |
                              detect_tls(peek_data):
                                1. HTTP 检查：以 GET/POST/...开头？ --> http
                                2. VLESS 检查：byte[0]=0x00, byte[17]=0x00,
                                   byte[18] in {0x01,0x02,0x7F},
                                   byte[21] in {0x01,0x02,0x03}? --> vless
                                3. Trojan 检查：
                                   bytes[0..55] 全部为十六进制数字？且
                                   bytes[56..57] == CRLF？且
                                   byte[58] in {0x01,0x03,0x7F}？且
                                   byte[59] in {0x01,0x03,0x04}？
                                   --> trojan
                                4. 60+ 字节，以上都不匹配？ --> shadowsocks
                                5. <60 字节？ --> unknown（读取更多）
```

**关键检测细节**：`detect_tls()` 函数执行严格验证：

1. **字节 0-55**：每个字节必须是 ASCII 十六进制数字（`0-9`、`a-f`、`A-F`）。这检查 56 字节 SHA224 凭据格式。
2. **字节 56-57**：必须恰好是 `\r\n`（0x0D 0x0A）。这是第一个 CRLF 分隔符。
3. **字节 58**：必须是有效命令（`0x01`、`0x03` 或 `0x7F`）。
4. **字节 59**：必须是有效 ATYP（`0x01`、`0x03` 或 `0x04`）。

只有满足所有四个条件时，流量才被分类为 Trojan。如果有 60+ 字节但模式不匹配，流量回退到 Shadowsocks（基于排除法的检测）。

### 3.3 核心组件关系图

```
+------------------------------------------------------------------+
|                        会话层                                     |
|                                                                   |
|  +-------------------------------------------------------------+  |
|  |  session::diversion()                                        |  |
|  |                                                              |  |
|  |  1. probe() -- 外层检测（24 字节）                           |  |
|  |  2. 如果 TLS: 伪装管道                                      |  |
|  |       Reality --> ShadowTLS --> 原生 TLS                    |  |
|  |  3. detect_tls() -- 内层协议检测                             |  |
|  |  4. dispatch::dispatch(ctx, type, span)                     |  |
|  +-------------------------------------------------------------+  |
|                              |                                     |
|                              v                                     |
|  +-------------------------------------------------------------+  |
|  |  dispatch::handler_table[protocol_type::trojan]              |  |
|  |       --> pipeline::trojan(ctx, data)                        |  |
|  +-------------------------------------------------------------+  |
+------------------------------------------------------------------+
                              |
                              v
+------------------------------------------------------------------+
|                       管道层                                      |
|                                                                   |
|  +-------------------------------------------------------------+  |
|  |  pipeline::trojan(ctx, data)                                  |  |
|  |  [src/prism/pipeline/protocols/trojan.cpp]                   |  |
|  |                                                              |  |
|  |  1. wrap_with_preview(ctx, data, true) -- 重放预读数据（use_global_mr）|  |
|  |  2. 创建凭据验证器 lambda                                    |  |
|  |  3. protocol::trojan::make_relay(inbound, config, verifier)  |  |
|  |  4. co_await agent->handshake()                             |  |
|  |  5. switch (req.cmd):                                       |  |
|  |     case CONNECT  --> forward(ctx, "Trojan", target, conn)  |  |
|  |     case UDP_ASSOC --> async_associate(datagram_router)     |  |
|  |     case MUX      --> multiplex::bootstrap()                |  |
|  +-------------------------------------------------------------+  |
+------------------------------------------------------------------+
                              |
                              v
+------------------------------------------------------------------+
|                     协议层（Trojan）                               |
|                                                                   |
|  +-------------------------------------------------------------+  |
|  |  relay::handshake()                                           |  |
|  |  [src/prism/protocol/trojan/relay.cpp]                       |  |
|  |                                                              |  |
|  |  1. read_at_least(*next_layer, buffer, 68) -- 批量读取       |  |
|  |  2. parse_credential(buffer[0..55]) -- 十六进制验证          |  |
|  |  3. verifier(credential) -- 账户目录检查                     |  |
|  |  4. parse_crlf(buffer[56..57]) -- CRLF 检查                 |  |
|  |  5. parse_cmd_atyp(buffer[58..59]) -- CMD + ATYP            |  |
|  |  6. 根据 ATYP 计算 required_total                             |  |
|  |  7. read_remaining() -- 如果需要则补读                       |  |
|  |  8. parse_address_from_buffer() -- IPv4/域名/IPv6            |  |
|  |  9. parse_port() -- 大端序端口解码                           |  |
|  |  10. parse_crlf() -- 最终 CRLF 检查                         |  |
|  |  11. validate_command() -- 配置能力检查                      |  |
|  |  12. 返回 request 结构体                                     |  |
|  +-------------------------------------------------------------+  |
|                                                                   |
|  +-------------------------------------------------------------+  |
|  |  relay::async_associate()                                     |  |
|  |  [src/prism/protocol/trojan/relay.cpp]                       |  |
|  |                                                              |  |
|  |  1. 创建带有 config_.udp_idle_timeout 的 idle_timer           |  |
|  |  2. 进入 udp_frame_loop()                                    |  |
|  |  3. 并行等待：读取 || 定时器（先完成者获胜）                  |  |
|  |  4. parse_udp_packet() -- ATYP/地址/端口/长度/CRLF/载荷      |  |
|  |  5. route_cb(target_host, target_port) -- DNS 解析           |  |
|  |  6. relay_udp_packet() -- 发送到目标，获取响应               |  |
|  |  7. send_udp_response() -- 编码 + 写回 TLS                  |  |
|  +-------------------------------------------------------------+  |
+------------------------------------------------------------------+
                              |
                              v
+------------------------------------------------------------------+
|                     传输层                                        |
|                                                                   |
|  +-------------------------------------------------------------+  |
|  |  transmission 接口（shared_transmission）                     |  |
|  |  - async_read_some / async_write_some                        |  |
|  |  - async_write（完整写入）                                    |  |
|  |  - close / cancel                                            |  |
|  |  - is_reliable                                               |  |
|  +-------------------------------------------------------------+  |
|                                                                   |
|  具体实现：                                                        |
|  - ssl_stream（TLS 包装连接器）                                   |
|  - preview（预读数据重放）                                        |
|  - reliable（原始 TCP 套接字）                                    |
|  - encrypted（AEAD 加密）                                         |
+------------------------------------------------------------------+
```

### 3.4 模块分层

Trojan 实现跨越四个架构层：

```
层 1: Agent（会话 + 分派）
  - session.cpp: diversion() 编排检测 + 分派
  - table.hpp: 编译期 handler_table 映射 trojan --> pipeline::trojan

层 2: Pipeline（协议处理器）
  - trojan.cpp: 高级会话生命周期
  - primitives.hpp: preview、forward、tunnel、wrap_with_preview

层 3: Protocol（Trojan 状态机）
  - relay.hpp/cpp: relay 类、handshake()、async_associate()、udp_frame_loop()
  - format.hpp/cpp: 底层二进制解析
  - constants.hpp: command、address_type 枚举
  - message.hpp: request 结构体
  - config.hpp: 能力开关

层 4: Transmission（I/O 抽象）
  - transmission.hpp: 抽象基类
  - ssl_stream: TLS 传输
  - preview: 预读数据重放
```

---

## 4. 调用层次结构

### 4.1 完整调用树

```
listener::accept_connection()
  |
  +-> balancer::select_worker()
        |
        +-> net::co_spawn(worker.io_context, launch())
              |
              +-> launch::operator()()
                    |
                    +-> make_session(std::move(params))
                    |     +-> session(params) -- 用入站连接构造会话
                    |
                    +-> session->start()
                          |
                          +-> net::co_spawn(ctx_.worker.io_context, process())
                                |
                                +-> session::diversion()
                                      |
                                      +-> psm::protocol::probe(*ctx_.inbound, 24)
                                      |     +-> async_read_some(24 字节)
                                      |     +-> analysis::detect(peek_data)
                                      |           +-- 0x05 --> socks5
                                      |           +-- 0x16 0x03 --> tls
                                      |           +-- HTTP 方法 --> http
                                      |           +-- 否则 --> shadowsocks
                                      |
                                      +-- [如果 tls] --> 伪装方案管道
                                      |     +-> Reality 方案
                                      |     |     +-> TLS 握手（伪造证书）
                                      |     |     +-> 读取 TLS 后数据
                                      |     +-> ShadowTLS 方案
                                      |     |     +-> 转发到诱饵或处理
                                      |     +-> 原生 TLS 方案
                                      |           +-> TLS 握手（标准）
                                      |           +-> 读取 TLS 后数据
                                      |
                                      +-- [伪装管道之后]
                                      +-> analysis::detect_tls(peek_data)
                                      |     +-- HTTP 检查（>=4 字节）
                                      |     +-- VLESS 检查（>=22 字节）
                                      |     +-- Trojan 检查（>=60 字节）
                                      |           +-- bytes[0..55] 全部为十六进制数字？
                                      |           +-- bytes[56..57] == CRLF？
                                      |           +-- byte[58] in {0x01,0x03,0x7F}？
                                      |           +-- byte[59] in {0x01,0x03,0x04}？
                                      |           +-- 是 --> protocol_type::trojan
                                      |           +-- 否  --> protocol_type::shadowsocks
                                      |
                                      +-> dispatch::dispatch(ctx, protocol_type::trojan, span)
                                            |
                                            +-> handler_table[idx](ctx, span)
                                                  |
                                                  +-> pipeline::trojan(ctx, span)
                                                        |
                                                        +-> wrap_with_preview(ctx, data, true)
                                                        |     +-> 用预读数据创建 preview 包装器
                                                        |
                                                        +-> 创建凭据验证器 lambda
                                                        |     +-> account::try_acquire(directory, credential)
                                                        |     +-> 检查连接数限制
                                                        |
                                                        +-> protocol::trojan::make_relay(inbound, config, verifier)
                                                        |     +-> std::make_shared<relay>(next_layer, config, verifier)
                                                        |
                                                        +-> co_await agent->handshake()
                                                        |     |
                                                        |     +-> read_at_least(*next_layer, buffer, 68)
                                                        |     |     +-> async_read_some(至少 68 字节)
                                                        |     |
                                                        |     +-> format::parse_credential(buffer[0..55])
                                                        |     |     +-> 验证每个字节为十六进制数字
                                                        |     |
                                                        |     +-> verifier_(credential_view)
                                                        |     |     +-> 账户目录查找
                                                        |     |     +-> 连接数限制检查
                                                        |     |
                                                        |     +-> format::parse_crlf(buffer[56..57])
                                                        |     |     +-> 验证 "\r\n"
                                                        |     |
                                                        |     +-> format::parse_cmd_atyp(buffer[58..59])
                                                        |     |     +-> 解码 CMD 字节
                                                        |     |     +-> 解码 ATYP 字节
                                                        |     |
                                                        |     +-> 根据 ATYP 计算 required_total
                                                        |     |     +-- IPv4: 60 + 4 + 2 + 2 = 68
                                                        |     |     +-- 域名: 60 + 1 + domain_len + 2 + 2
                                                        |     |     +-- IPv6: 60 + 16 + 2 + 2 = 80
                                                        |     |
                                                        |     +-> read_remaining(*next_layer, total, required_total)
                                                        |     |     +-> 如果初始读取不足则补读
                                                        |     |
                                                        |     +-> parse_address_from_buffer(offset, atyp)
                                                        |     |     +-> format::parse_ipv4() / parse_domain() / parse_ipv6()
                                                        |     |
                                                        |     +-> format::parse_port(port_bytes)
                                                        |     |     +-> 大端序 uint16 解码
                                                        |     |
                                                        |     +-> format::parse_crlf(final_crlf_bytes)
                                                        |     |     +-> 验证 "\r\n"
                                                        |     |
                                                        |     +-> validate_command(cmd, config)
                                                        |     |     +-> 检查 enable_tcp / enable_udp
                                                        |     |
                                                        |     +-> 返回 {fault::code::success, request}
                                                        |
                                                        +-- switch (req.cmd)
                                                              |
                                                              +-> case CONNECT (0x01)
                                                              |     +-> protocol::analysis::target（竞技场分配）
                                                              |     +-> protocol::trojan::to_string(address)
                                                              |     +-> std::to_chars(port)
                                                              |     +-> is_mux_target(host, mux_enabled)?
                                                              |     |     +-- 是: multiplex::bootstrap()
                                                              |     |            +-> smux_craft 构造
                                                              |     |            +-> muxprotocol->start()
                                                              |     |     +-- 否: primitives::forward(ctx, "Trojan", target, conn)
                                                              |     |            +-> primitives::dial(router, label, target, ...)
                                                              |     |            |     +-> router::forward_route(host, port, executor)
                                                              |     |            |     +-> 将原始套接字包装为 reliable transmission
                                                              |     |            +-> primitives::tunnel(inbound, outbound, ctx)
                                                              |     |                  +-> 并行读/写循环
                                                              |     |                  +-> co_await (read_a || read_b)
                                                              |     |                  +-> 向相反方向写入
                                                              |     |                  +-> 遇到 EOF: shut_close 两端
                                                              |
                                                              +-> case UDP_ASSOCIATE (0x03)
                                                              |     +-> 创建 datagram_router
                                                              |     +-> co_await agent->async_associate(router)
                                                              |           +-> relay::async_associate()
                                                              |                 +-> 创建 idle_timer
                                                              |                 +-> udp_frame_loop()
                                                              |                       +-> common_udp_buffers（池分配）
                                                              |                       +-> net::ip::udp::socket（复用）
                                                              |                       +-> while(true):
                                                              |                             +-> idle_timer.reset()
                                                              |                             +-> co_await (do_read() || timer.async_wait())
                                                              |                             +-- 超时: co_return
                                                              |                             +-- 读取 0: co_return
                                                              |                             +-> format::parse_udp_packet(buffer)
                                                              |                             +-> route_cb(host, port)
                                                              |                             +-> protocol::common::relay_udp_packet()
                                                              |                             +-> send_udp_response()
                                                              |                                   +-> format::build_udp_packet()
                                                              |                                   +-> transport.async_write()
                                                              |
                                                              +-> case MUX (0x7F)
                                                              |     +-> 清除会话流回调
                                                              |     +-> multiplex::bootstrap(agent->release(), router, mux_config)
                                                              |           +-> smux_craft / yamux 连接
                                                              |           +-> muxprotocol->start()
                                                              |
                                                              +-> default
                                                                    +-> trace::warn("未知命令")
```

### 4.2 处理器分派

分派机制使用**编译期函数表**而非虚函数或运行时工厂模式：

```cpp
// include/prism/agent/dispatch/table.hpp
inline constexpr std::array<handler_func *, 7> handler_table{
    /* 未知 (0)        */ handle_unknown,
    /* http (1)        */ pipeline::http,
    /* socks5 (2)      */ pipeline::socks5,
    /* trojan (3)      */ pipeline::trojan,
    /* vless (4)       */ pipeline::vless,
    /* shadowsocks (5) */ pipeline::shadowsocks,
    /* tls (6)         */ handle_unknown,  // 不应到达此处
};
```

数组索引直接对应 `protocol_type` 枚举值。此设计实现：
- **零虚函数开销**：直接函数指针调用。
- **零动态分配**：`constexpr` 数组，编译期初始化。
- **内联机会**：编译器可以内联分派。

### 4.3 协议检测管道

```
+---------------+     +----------------+     +-------------------+     +------------------+
|   probe()     |     |  伪装方案      |     |   detect_tls()    |    | dispatch::dispatch|
|  (24 字节)    |---->| Reality /      |---->| (TLS 后数据)      |---->| handler_table    |
|               |     | ShadowTLS /    |     |                   |     | [type](ctx, data)|
| tls? socks5?  |     | 原生 TLS       |     | trojan? vless?    |     |                  |
| http? ss?     |     |                |     | http? ss?         |     |                  |
+---------------+     +----------------+     +-------------------+     +------------------+
       |                      |                       |                        |
       | 检测到 TLS           | TLS 握手              | 检测到 Trojan          | pipeline::trojan
       v                      v                       v                        v
  probe_result.type      入站 = TLS 流       peek_data[0..55]        relay::handshake()
  = protocol_type::tls   （解密通道）          全部为十六进制数字？      --> 解析凭据
                                                    peek_data[56..57]       --> 验证凭据
                                                    == CRLF?                --> 解析 CMD/ATYP
                                                    peek_data[58]           --> 解析地址
                                                    in {0x01,0x03,0x7F}?    --> 解析端口
                                                    peek_data[59]           --> 验证命令
                                                    in {0x01,0x03,0x04}?    --> 返回 request
```

---

## 5. 完整生命周期

### 5.1 CONNECT 生命周期

以下时序图展示了 Trojan TCP CONNECT 请求的完整生命周期：

```
客户端              TLS 层              会话                管道              Trojan 中继器      路由器/上游
  |                    |                   |                    |                    |                    |
  | --- ClientHello -->|                   |                    |                    |                    |
  |                    |                   |                    |                    |                    |
  | <-- ServerHello -- |                   |                    |                    |                    |
  | <-- Cert+Done ---- |                   |                    |                    |                    |
  | --- KeyExchange -->|                   |                    |                    |                    |
  | <-- Finished ----- |                   |                    |                    |                    |
  |                    |                   |                    |                    |                    |
  | [TLS 已建立]       |                   |                    |                    |                    |
  |                    |                   |                    |                    |                    |
  | ===[加密数据]===>  |                   |                    |                    |                    |
  |  [凭据|CRLF|CMD|ATYP|地址|端口|CRLF]    |                    |                    |                    |
  |                    |                   |                    |                    |                    |
  |                    |=== probe(24) ===> |                    |                    |                    |
  |                    |                   |  [type=tls]        |                    |                    |
  |                    |                   |                    |                    |                    |
  |                    |== 伪装管道 ======>|                    |                    |                    |
  |                    |== TLS 解密数据    |                    |                    |                    |
  |                    |                   |                    |                    |                    |
  |                    |=== detect_tls()==>|                    |                    |                    |
  |                    |                   |  [type=trojan]     |                    |                    |
  |                    |                   |                    |                    |                    |
  |                    |                   |== 分派 ===========>|                    |                    |
  |                    |                   |                    |                    |                    |
  |                    |                   |                    | wrap_with_preview()|                    |
  |                    |                   |                    | make_relay()       |                    |
  |                    |                   |                    |                    |                    |
  |                    |                   |                    |== handshake() ====>|                    |
  |                    |                   |                    |                    | read_at_least(68)  |
  |                    |                   |                    |                    |<===================|
  |                    |                   |                    |                    | [68+ 字节]         |
  |                    |                   |                    |                    |                    |
  |                    |                   |                    |                    | parse_credential() |
  |                    |                   |                    |                    | verifier_(cred)    |
  |                    |                   |                    |                    | parse_crlf()       |
  |                    |                   |                    |                    | parse_cmd_atyp()   |
  |                    |                   |                    |                    | parse_address()    |
  |                    |                   |                    |                    | parse_port()       |
  |                    |                   |                    |                    | parse_crlf()       |
  |                    |                   |                    |                    | validate_command() |
  |                    |                   |                    |                    |                    |
  |                    |                   |                    |<== {success, req}==|                    |
  |                    |                   |                    |                    |                    |
  |                    |                   |                    | switch(req.cmd)    |                    |
  |                    |                   |                    |   case CONNECT:    |                    |
  |                    |                   |                    |                    |                    |
  |                    |                   |                    |== dial(target) =======================> |
  |                    |                   |                    |                    |<===================|
  |                    |                   |                    |                    | [出站连接]         |
  |                    |                   |                    |                    |                    |
  |                    |                   |                    |== tunnel(in, out) ====================> |
  |                    |                   |                    |                    |                    |
  |                    |                   |                    |  [双向转发循环]     |                    |
  |                    |                   |                    |                    |                    |
  |<========================= 数据 <============================== 数据 ===============================>  |
  |========================== 数据 ==============================> 数据 <===============================  |
  |                    |                   |                    |                    |                    |
  |                    |                   |                    |  [任一端 EOF]       |                    |
  |                    |                   |                    |  shut_close(in)    |                    |
  |                    |                   |                    |  shut_close(out)   |                    |
  |                    |                   |                    |                    |                    |
  | [连接关闭]         |                   |                    |                    |                    |
```

### 5.2 MUX 生命周期

MUX 生命周期在握手后与 CONNECT 分叉。存在两条启动路径：

**路径 A：原生 MUX（cmd=0x7F）**

```
客户端              会话                管道              Trojan 中继器      多路复用
  |                    |                    |                    |                    |
  | [TLS 握手]        |                    |                    |                    |
  | [cmd=0x7F|ATYP|地址|端口|CRLF]         |                    |                    |
  |                    |== 分派 ===========>|                    |                    |
  |                    |                    |                    |                    |
  |                    |                    |== handshake() ===>|                    |
  |                    |                    |<== {success, req}==| 检测到 cmd=0x7F    |
  |                    |                    |                    |                    |
  |                    |                    | 清除回调           |                    |
  |                    |                    |== bootstrap ======>|                    |
  |                    |                    |                    | release()          |
  |                    |                    |                    | [转移所有权        |
  |                    |                    |                    |  到多路复用器]      |
  |                    |                    |                    |                    |
  |                    |                    |                    |== smux/yamux =====>|
  |                    |                    |                    |  协商              |
  |                    |                    |                    |                    |
  |<============== 多路复用流 ================================================>|
  |  [流 1: 数据]      |                    |                    |  [流 1]            |
  |  [流 2: 数据]      |                    |                    |  [流 2]            |
  |  [流 N: 数据]      |                    |                    |  [流 N]            |
  |                    |                    |                    |                    |
  | [发送 FIN]        |                    |                    |  session.close()   |
  |                    |                    |                    |                    |
```

**路径 B：兼容 Mihomo 的 MUX（cmd=0x01 + .mux.sing-box.arpa）**

```
客户端              会话                管道              Trojan 中继器      多路复用
  |                    |                    |                    |                    |
  | [TLS 握手]        |                    |                    |                    |
  | [cmd=0x01|ATYP|地址(.mux.sing-box.arpa)|端口|CRLF]          |                    |
  |                    |== 分派 ===========>|                    |                    |
  |                    |                    |                    |                    |
  |                    |                    |== handshake() ===>|                    |
  |                    |                    |<== {success, req}==| cmd=0x01，         |
  |                    |                    |                    | 正常地址           |
  |                    |                    |                    |                    |
  |                    |                    | to_string(addr)    |                    |
  |                    |                    | is_mux_target()?   |                    |
  |                    |                    |  --> 是            |                    |
  |                    |                    |                    |                    |
  |                    |                    | 清除回调           |                    |
  |                    |                    |== bootstrap ======>|                    |
  |                    |                    |  [同路径 A]         |                    |
```

### 5.3 UDP_ASSOCIATE 生命周期

```
客户端              会话                管道              Trojan 中继器      DNS 路由器      UDP 目标
  |                    |                    |                    |                    |               |
  | [TLS 握手]        |                    |                    |                    |               |
  | [cmd=0x03|ATYP|地址|端口|CRLF]         |                    |                    |               |
  |                    |== 分派 ===========>|                    |                    |               |
  |                    |                    |                    |                    |               |
  |                    |                    |== handshake() ===>|                    |               |
  |                    |                    |<== {success, req}==| 检测到 cmd=0x03    |               |
  |                    |                    |                    |                    |               |
  |                    |                    | make_datagram_router()                  |               |
  |                    |                    |                    |                    |               |
  |                    |                    |== async_associate ====================>|               |
  |                    |                    |                    |                    |               |
  |                    |                    |                    | udp_frame_loop():  |               |
  |                    |                    |                    |                    |               |
  | ===[UDP 帧 1] =====>|                    |                    | parse_udp_packet() |               |
  |  [ATYP|地址|端口|长度|CRLF|载荷]         |                    |                    |               |
  |                    |                    |                    | route_cb(host,port)|==============>|
  |                    |                    |                    |                    |  [DNS 解析]   |
  |                    |                    |                    |<=====================================|
  |                    |                    |                    | relay_udp_packet() |               |
  |                    |                    |                    |===================>|  [UDP 发送]    |
  |                    |                    |                    |<===================|  [UDP 接收]    |
  |                    |                    |                    | build_udp_packet() |               |
  |                    |                    |                    | async_write()      |               |
  |<===[UDP 响应]======|                    |                    |                    |               |
  |  [ATYP|发送者地址|发送者端口|长度|CRLF|载荷]                  |                    |               |
  |                    |                    |                    |                    |               |
  | ===[UDP 帧 2] =====>|                    |  [循环重复]        |                    |               |
  | ...                |                    |                    |                    |               |
  |                    |                    |                    |                    |               |
  | [空闲: 无数据]     |                    |                    | idle_timer 到期    |               |
  |                    |                    |                    | co_return          |               |
  |                    |                    |<== success ========|                    |               |
  |                    |                    |                    |                    |               |
  | [连接关闭]         |                    |                    |                    |               |
```

---

## 6. 二进制格式示例

### 6.1 IPv4 CONNECT 请求

目标：`93.184.216.34:443`（example.com），密码 SHA224 十六进制摘要（示例）：

```text
偏移    十六进制                                          ASCII
------  ---------------------------------------------  -------------------------
0000    65 33 62 30 63 34 34 32 39 38 66 63 31 63 31   e3b0c44298fc1c1
0010    34 39 61 66 62 66 34 63 38 39 39 36 66 62 39   49afbf4c8996fb9
0020    32 34 32 37 61 65 34 31 65 34 36 34 39 62 39   2427ae41e4649b9
0030    33 34 63 61 34 39 35 39 39 31 62 37 38 35 32   34ca495991b7852
0038    62 38 35 35                                    b855          <-- 56 字节凭据
003C    0D 0A                                          ..          <-- CRLF
003E    01 01                                          ..          <-- CMD=0x01(CONNECT), ATYP=0x01(IPv4)
0040    5D B8 D8 22                                    ].."        <-- IPv4: 93.184.216.34
0044    01 BB                                          ..          <-- 端口: 443 (0x01BB)
0046    0D 0A                                          ..          <-- CRLF
```

总计：72 字节。

### 6.2 域名 CONNECT 请求

目标：`example.com:443`

```text
偏移    十六进制                                          ASCII
------  ---------------------------------------------  -------------------------
0000    65 33 62 30 63 34 34 32 39 38 66 63 31 63 31   e3b0c44298fc1c1
0010    34 39 61 66 62 66 34 63 38 39 39 36 66 62 39   49afbf4c8996fb9
0020    32 34 32 37 61 65 34 31 65 34 36 34 39 62 39   2427ae41e4649b9
0030    33 34 63 61 34 39 35 39 39 31 62 37 38 35 32   34ca495991b7852
0038    62 38 35 35                                    b855          <-- 56 字节凭据
003C    0D 0A                                          ..          <-- CRLF
003E    01 03                                          ..          <-- CMD=0x01(CONNECT), ATYP=0x03(域名)
0040    0B                                             .           <-- 域名长度: 11
0041    65 78 61 6D 70 6C 65 2E 63 6F 6D               example.com <-- 域名内容
004C    01 BB                                          ..          <-- 端口: 443
004E    0D 0A                                          ..          <-- CRLF
```

总计：80 字节。

### 6.3 IPv6 CONNECT 请求

目标：`[2001:db8::1]:443`

```text
偏移    十六进制                                          ASCII
------  ---------------------------------------------  -------------------------
0000    65 33 62 30 63 34 34 32 39 38 66 63 31 63 31   e3b0c44298fc1c1
0010    34 39 61 66 62 66 34 63 38 39 39 36 66 62 39   49afbf4c8996fb9
0020    32 34 32 37 61 65 34 31 65 34 36 34 39 62 39   2427ae41e4649b9
0030    33 34 63 61 34 39 35 39 39 31 62 37 38 35 32   34ca495991b7852
0038    62 38 35 35                                    b855          <-- 56 字节凭据
003C    0D 0A                                          ..          <-- CRLF
003E    01 04                                          ..          <-- CMD=0x01(CONNECT), ATYP=0x04(IPv6)
0040    20 01 0D B8 00 00 00 00                         ........    <-- IPv6: 2001:db8::
0048    00 00 00 00 00 00 00 01                         ........    <-- IPv6: ::1
0050    01 BB                                          ..          <-- 端口: 443
0052    0D 0A                                          ..          <-- CRLF
```

总计：84 字节。

### 6.4 UDP_ASSOCIATE 请求

目标：`8.8.8.8:53`（DNS 查询）

```text
偏移    十六进制                                          ASCII
------  ---------------------------------------------  -------------------------
0000    65 33 62 30 63 34 34 32 39 38 66 63 31 63 31   e3b0c44298fc1c1
0010    34 39 61 66 62 66 34 63 38 39 39 36 66 62 39   49afbf4c8996fb9
0020    32 34 32 37 61 65 34 31 65 34 36 34 39 62 39   2427ae41e4649b9
0030    33 34 63 61 34 39 35 39 39 31 62 37 38 35 32   34ca495991b7852
0038    62 38 35 35                                    b855          <-- 56 字节凭据
003C    0D 0A                                          ..          <-- CRLF
003E    03 01                                          ..          <-- CMD=0x03(UDP_ASSOCIATE), ATYP=0x01(IPv4)
0040    08 08 08 08                                    ....        <-- IPv4: 8.8.8.8
0044    00 35                                          .5          <-- 端口: 53
0046    0D 0A                                          ..          <-- CRLF
```

**UDP 帧**（关联后在 TLS 内发送）：

```text
偏移    十六进制                                          ASCII
------  ---------------------------------------------  -------------------------
0000    01 08 08 08 08 00 35 00 15 0D 0A               ......5.....  <-- ATYP|地址|端口|长度|CRLF
000C    00 01 00 00 00 01 00 00 00 00 00 00 07 65 78   .............ex  <-- DNS 载荷
001C    61 6D 70 6C 65 03 63 6F 6D 00 00 01 00 01      ample.com.....
```

### 6.5 MUX 请求（cmd=0x7F）

```text
偏移    十六进制                                          ASCII
------  ---------------------------------------------  -------------------------
0000    65 33 62 30 63 34 34 32 39 38 66 63 31 63 31   e3b0c44298fc1c1
0010    34 39 61 66 62 66 34 63 38 39 39 36 66 62 39   49afbf4c8996fb9
0020    32 34 32 37 61 65 34 31 65 34 36 34 39 62 39   2427ae41e4649b9
0030    33 34 63 61 34 39 35 39 39 31 62 37 38 35 32   34ca495991b7852
0038    62 38 35 35                                    b855          <-- 56 字节凭据
003C    0D 0A                                          ..          <-- CRLF
003E    7F 01                                          ..          <-- CMD=0x7F(MUX), ATYP=0x01(IPv4)
0040    00 00 00 00                                    ....        <-- IPv4: 0.0.0.0（占位符）
0044    00 00                                          ..          <-- 端口: 0（占位符）
0046    0D 0A                                          ..          <-- CRLF
```

注意：对于原生 MUX（`cmd=0x7F`），地址和端口字段通常为占位值，因为多路复用器协商自己的目标路由。

---

## 7. 配置参数

### 7.1 Trojan 专用配置

Trojan 协议配置定义在 `include/prism/protocol/trojan/config.hpp` 中：

```cpp
struct config
{
    bool enable_tcp = true;                 // 允许 CONNECT 命令（TCP 隧道）
    bool enable_udp = false;                // 允许 UDP_ASSOCIATE 命令（UDP over TLS）
    std::uint32_t udp_idle_timeout = 60;    // UDP 会话空闲超时（秒）
    std::uint32_t udp_max_datagram = 65535; // 最大 UDP 数据报大小（字节）
};
```

### 7.2 完整配置 JSON

启用所有 Trojan 功能的完整 Prism 配置：

```json
{
  "addressable": [
    {
      "host": "0.0.0.0",
      "port": 443
    }
  ],
  "authentication": {
    "users": [
      {
        "name": "user1",
        "password": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    ]
  },
  "protocol": {
    "trojan": {
      "enable_tcp": true,
      "enable_udp": true,
      "udp_idle_timeout": 120,
      "udp_max_datagram": 32768
    }
  },
  "mux": {
    "enabled": true,
    "smux": {
      "version": 1,
      "max_streams": 256,
      "keepalive": 30
    },
    "yamux": {
      "max_streams": 256,
      "keepalive_interval": 30,
      "keepalive_timeout": 30
    }
  },
  "dns": {
    "servers": [
      {
        "address": "8.8.8.8",
        "port": 53,
        "protocol": "udp"
      }
    ],
    "cache_enabled": true,
    "serve_stale": true
  },
  "pool": {
    "max_cache_per_endpoint": 32
  },
  "buffer": {
    "size": 262144
  },
  "reality": {
    "enabled": true,
    "dest": "example.com:443",
    "server_names": ["example.com"],
    "private_key": "xxx",
    "short_ids": [""]
  }
}
```

### 7.3 参数参考表

| 参数 | 类型 | 默认值 | 范围 | 描述 |
|-----------|------|---------|-------|-------------|
| `protocol.trojan.enable_tcp` | `bool` | `true` | `true`/`false` | 是否接受 `CONNECT` (0x01) 命令。禁用时 CONNECT 请求返回 `fault::code::forbidden` |
| `protocol.trojan.enable_udp` | `bool` | `false` | `true`/`false` | 是否接受 `UDP_ASSOCIATE` (0x03) 命令。禁用时 UDP 请求返回 `fault::code::forbidden` |
| `protocol.trojan.udp_idle_timeout` | `uint32` | `60` | `1`-`86400` | 关闭 UDP 关联前的无活动秒数。每个关联独立应用，每个 UDP 帧重置 |
| `protocol.trojan.udp_max_datagram` | `uint32` | `65535` | `11`-`65535` | 单个 UDP 数据报载荷的最大大小。接收缓冲区分配至此大小。最小 11 以容纳最小有效帧头 |
| `mux.enabled` | `bool` | `false` | `true`/`false` | 是否启用多路复用。通过 `.mux.sing-box.arpa` 进行兼容 Mihomo 的 MUX 检测所需 |
| `authentication.users[].password` | `string` | （无） | 56 个十六进制字符 | Trojan 密码的 SHA224 十六进制摘要。必须恰好为 56 个小写十六进制字符 |
| `reality.enabled` | `bool` | `false` | `true`/`false` | 是否激活 Reality TLS 伪装。启用时，Trojan 使用伪造证书运行 |

**重要说明：**

- 配置中的 `password` 字段必须是实际密码的 **SHA224 十六进制摘要**，而不是明文密码。客户端计算相同的哈希并将其作为 56 字节凭据发送。
- 配置在启动时读取一次并存储在 `agent::config` 中。`protocol.trojan` 子结构体传递给 `relay` 构造函数，在中继器对象的整个生命周期中不可变。
- 修改配置需要重启服务——没有热重载机制。

---

## 8. 边缘情况与错误处理

### 8.1 错误码目录

Trojan 处理期间可能返回以下错误码：

| 错误码 | 值 | 产生位置 | 条件 |
|------------|-------|----------------|-----------|
| `success` | 0 | 所有解析函数 | 操作成功完成 |
| `bad_message` | 6 | `parse_credential`、`parse_crlf`、`parse_cmd_atyp`、`parse_ipv4`、`parse_ipv6`、`parse_domain`、`parse_port`、`parse_udp_packet` | 缓冲区不足以容纳预期数据 |
| `protocol_error` | 5 | `parse_credential`、`parse_crlf`、`parse_udp_packet` | 数据格式违规（凭据中的非十六进制字节、错误的 CRLF） |
| `auth_failed` | 15 | `relay::handshake()` | 凭据与目录中的任何账户不匹配 |
| `unsupported_command` | 19 | `validate_command()` | CMD 字节不是 0x01、0x03 或 0x7F |
| `unsupported_address` | 20 | `parse_address_from_buffer()` | ATYP 字节不是 0x01、0x03 或 0x04 |
| `forbidden` | 36 | `validate_command()` | 命令有效但被配置禁用（例如 `enable_tcp=false` 时 CONNECT） |
| `not_supported` | 8 | `relay::async_associate()` | 配置中禁用了 UDP |
| `dns_failed` | 16 | UDP 帧循环中的 `route_cb()` | UDP 目标的 DNS 解析失败 |
| `upstream_unreachable` | 17 | `primitives::dial()` | 无法连接到目标服务器 |
| `connection_refused` | 18 | `primitives::dial()` | 目标服务器拒绝连接 |
| `timeout` | 11 | UDP 空闲定时器 | 在 `udp_idle_timeout` 秒内未收到 UDP 帧 |
| `udp_session_expired` | 58 | UDP 帧循环 | 触发空闲超时（记录为 debug，正常返回） |
| `tls_handshake_failed` | 13 | TLS 方案执行 | TLS 握手未完成 |

### 8.2 防御性编程措施

**每个解析步骤的缓冲区大小验证：**

`format.cpp` 中的每个解析函数在访问数据之前都验证缓冲区大小：

```cpp
// parse_credential: 至少需要 56 字节
if (buffer.size() < 56) {
    return {fault::code::bad_message, {}};
}

// parse_crlf: 至少需要 2 字节
if (buffer.size() < 2) {
    return fault::code::bad_message;
}

// parse_cmd_atyp: 至少需要 2 字节
if (buffer.size() < 2) {
    return {fault::code::bad_message, {}};
}

// parse_port: 至少需要 2 字节
if (buffer.size() < 2) {
    return {fault::code::bad_message, 0};
}

// parse_udp_packet: 至少需要 11 字节
if (buffer.size() < 11) {
    return {fault::code::bad_message, {}};
}
```

**凭据字符验证（防止注入）：**

凭据解析器验证每个字节都是 ASCII 十六进制数字。这防止：
- 凭据字段中的二进制注入尝试
- 可能利用下游字符串处理的不可打印字符
- 过长或格式错误的凭据字符串

```cpp
for (size_t i = 0; i < 56; ++i) {
    const auto c = static_cast<unsigned char>(buffer[i]);
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
        return {fault::code::protocol_error, {}};
    }
    credential[i] = static_cast<char>(buffer[i]);
}
```

**CRLF 严格验证：**

CRLF 被验证为恰好 `\r\n`（0x0D 0x0A）。独立的 `\r`、`\n`、`\n\r` 或任何其他组合都被拒绝为 `protocol_error`。这防止协议混淆攻击，客户端可能尝试注入额外行。

**CMD 和 ATYP 范围检查：**

未知的 CMD 和 ATYP 值被显式拒绝，而不是默认为安全值。这确保协议扩展是有意为之的，不会被意外接受。

**两阶段读取（批量 + 补读）：**

握手首先执行最小所需字节数（68）的批量读取。如果地址类型指示需要更多数据（例如长域名），它会计算确切所需的总数并执行有针对性的补读：

```cpp
// 根据 ATYP 计算确切所需大小
switch (header.atyp) {
case address_type::ipv4:
    required_total = 60 + 4 + 2 + 2;  // 68
    break;
case address_type::ipv6:
    required_total = 60 + 16 + 2 + 2; // 80
    break;
case address_type::domain:
    const std::uint8_t domain_len = buffer[60];
    required_total = 60 + 1 + domain_len + 2 + 2;
    break;
}

// 仅在必要时补读
if (total < required_total) {
    auto [rem_ec, new_total] = co_await read_remaining(..., total, required_total);
}
```

此方法最小化系统调用，同时处理 TCP 以小段传递数据的情况。

**UDP 帧循环：空闲超时 + 错误恢复：**

UDP 帧循环使用 `||` 运算符在读取数据和空闲定时器之间竞态：

```cpp
auto read_result = co_await (do_read() || idle_timer.async_wait(net::use_awaitable));

if (read_result.index() == 1) {  // 定时器获胜
    trace::debug("{} 空闲超时", udp_tag);
    co_return;  // 正常退出
}

if (n == 0) {  // 读取错误或 EOF
    trace::debug("{} 读取错误或 EOF", udp_tag);
    co_return;  // 正常退出
}
```

单个 UDP 帧中的解析错误**不是致命的**——循环继续处理下一帧：

```cpp
auto [parse_ec, parsed] = format::parse_udp_packet({buf.recv.data(), n});
if (fault::failed(parse_ec)) {
    trace::warn("{} 数据包解析失败", udp_tag);
    continue;  // 跳过错误数据包，继续循环
}
```

### 8.3 内存安全保证

**栈分配的握手缓冲区：**

握手使用固定的 320 字节栈缓冲区（`std::array<std::uint8_t, 320>`），它：
- 足够大以容纳任何有效的 Trojan 请求（最大：56 + 2 + 1 + 1 + 255 + 2 + 2 = 319 字节）。
- 在构造时初始化为零，防止未初始化内存的信息泄漏。
- 当握手协程返回时释放——无堆分配，无泄漏风险。

**PMR（多态内存资源）用于动态数据：**

Trojan 管道中的所有动态字符串分配使用 PMR 分配器：
- `protocol::analysis::target` 使用 `ctx.frame_arena.get()` 构造——竞技场分配，会话结束时释放。
- `to_string()` 使用 `memory::current_resource()`——线程局部内存池，自动回收。
- UDP 缓冲区使用 `common_udp_buffers(config_.udp_max_datagram)`——池分配，跨帧复用。

**MUX：smux_craft 的全局内存池：**

在 MUX 模式下，`wrap_with_preview()` 使用 `use_global_mr = true` 调用：

```cpp
auto inbound = primitives::wrap_with_preview(ctx, data, true);  // use_global_mr = true
```

这确保 preview 缓冲区使用全局内存池而非帧竞技场。原因：在 MUX 模式下，`relay` 对象及其 `smux_craft` 被移交给多路复用器，其生命周期超过会话。如果使用帧竞技场，当会话结束时竞技场将被销毁，导致多路复用器后续访问 preview 缓冲区时出现释放后使用（UAF）。

**release 时的所有权转移：**

进入 MUX 模式时，`agent->release()` 将底层传输的所有权从 `relay` 转移到多路复用器：

```cpp
auto muxprotocol = co_await multiplex::bootstrap(
    agent->release(), ctx.worker.router, ctx.server.config().mux);
```

此时 `relay` 对象实际上已失效——其 `next_layer_` 为 `nullptr`（已移动）。会话清除其流回调以防止悬空引用：

```cpp
ctx.active_stream_close = nullptr;
ctx.active_stream_cancel = nullptr;
```

### 8.4 TLS 剥离边缘情况

**误报检测：**

如果合法的 HTTP 请求恰好以 56 个十六进制字符开头，后跟 CRLF 和有效的 CMD/ATYP 字节，`detect_tls()` 函数可能产生误报。概率极低：

- 56 个十六进制数字：随机数据的概率约 (16/256)^56
- 有效的 CRLF：概率约 1/65536
- 有效的 CMD 字节：概率约 3/256
- 有效的 ATYP 字节：概率约 3/256

综合概率：对于真实 HTTP 流量实际上为零。

**数据不足：**

如果 TLS 握手后可用字节少于 60 字节，`detect_tls()` 返回 `protocol_type::unknown`。会话层不尝试解析不完整的数据。调用方（伪装方案）负责根据需要读取更多数据。

**TLS 记录分片：**

TCP 可能以分片块传递 TLS 应用数据。`read_at_least()` 函数通过发出多个 `async_read_some` 调用直到达到最小字节数来处理此问题。如果在收到足够数据之前连接关闭，则错误码向上传播。

### 8.5 凭据验证边缘情况

**缺少账户目录：**

如果 `ctx.account_directory_ptr` 为空（配置错误），验证器立即返回 `false` 并记录警告：

```cpp
if (!ctx.account_directory_ptr) {
    trace::warn("{} 未配置账户目录", TrojanStr);
    return false;
}
```

**未提供验证器：**

如果构造中继器时 `credential_verifier` 为 `nullptr`，握手将完全跳过凭据验证：

```cpp
if (verifier_) {
    const std::string_view cred_view(credential.data(), 56);
    if (!verifier_(cred_view)) {
        co_return std::pair{fault::code::auth_failed, request{}};
    }
}
```

这是安全风险——任何凭据都会被接受。Prism 在生产环境中始终提供验证器，但该设计允许无认证的测试。

**连接限制强制执行：**

`account::try_acquire()` 函数不仅验证凭据，还检查每账户连接限制。如果超过限制，`try_acquire()` 返回 `nullopt`，验证器将其视为认证失败。这防止单个账户消耗所有可用连接。

**大小写敏感性：**

凭据验证区分大小写。SHA224 十六进制摘要在客户端侧取决于大小写（客户端通常使用小写）。服务器在解析期间接受大写和小写十六进制数字（`A-F` 和 `a-f`），但实际凭据比较是逐字节匹配。凭据 `"ABC..."` 不会匹配存储的 `"abc..."`，除非存储的哈希碰巧相同（如果两者表示相同的 SHA224 值，则会是这种情况）。

---

## 附录：协议版本历史

| 版本 | 年份 | 描述 |
|---------|------|-------------|
| Trojan 1.0 | 2018 | GreaterFire 原始发布。TLS 上的 TCP CONNECT + UDP_ASSOCIATE。 |
| Trojan-Go | 2019 | Go 实现，带有 WebSocket 传输扩展。 |
| Trojan 与 Mihomo 兼容 | 2022 | 通过 `cmd=0x7F` 和 `.mux.sing-box.arpa` 寻址添加 smux 多路复用支持。 |
| Prism 实现 | 2025 | 基于 C++23 协程的实现，具有 Reality TLS 伪装、PMR 内存管理和编译期分派表。 |

## 附录：相关协议

| 协议 | 与 Trojan 的关系 |
|----------|-------------------|
| **Reality** | TLS 伪装层，使 Trojan 流量看起来像合法网站的 TLS 连接。Reality 生成与目标 SNI 匹配的伪造证书。 |
| **ShadowTLS** | 替代 TLS 伪装方案。与 Trojan 不同，ShadowTLS 不需要特定的 TLS 后协议格式——它可以将任何流量转发到诱饵服务器。 |
| **VLESS** | 来自 V2Ray 项目的下一代协议。使用基于 UUID 的认证而非 SHA224。类似的 TLS 包装架构。 |
| **Shadowsocks 2022** | 加密优先的方法。与 Trojan 的 TLS 模仿不同，SS2022 使用带有随机化 salt 的 AEAD 加密，使流量与随机噪声无法区分。 |
| **smux** | 流多路复用协议。用于 Trojan MUX 模式，在单个 TLS 连接上承载多个逻辑流。Prism 实现 smux v1（兼容 Mihomo）。 |
