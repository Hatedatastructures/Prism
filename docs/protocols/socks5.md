# SOCKS5 协议文档

本文档包含 SOCKS5 协议的完整规范（RFC 1928）以及 Prism 内的实现细节。

---

## 第一部分：协议规范

### 1. 协议概述

SOCKS5 是一种网络代理协议，定义于 RFC 1928。它支持 TCP 和 UDP 代理，提供认证机制，支持多种地址类型。

- **版本号**: 0x05
- **默认端口**: 1080

### 2. 完整会话流程

```
阶段 1: TCP 连接建立
    客户端 -> TCP SYN -> 服务端
    客户端 <- TCP SYN+ACK <- 服务端
    客户端 -> TCP ACK -> 服务端

阶段 2: 认证协商
    客户端 -> VER(5) + NMETHODS + METHODS -> 服务端
    客户端 <- VER(5) + METHOD <- 服务端

阶段 3: 认证 (如果需要)
    客户端 -> 用户名/密码 (METHOD=0x02) -> 服务端
    客户端 <- 认证结果 <- 服务端

阶段 4: 请求处理
    客户端 -> CMD + ATYP + DST.ADDR + PORT -> 服务端
    客户端 <- REP + ATYP + BND.ADDR + PORT <- 服务端

阶段 5: 数据传输
    客户端 <==> 数据双向传输 <==> 服务端

阶段 6: 连接关闭
    客户端 -> TCP FIN -> 服务端
    客户端 <- TCP FIN <- 服务端
```

### 3. 认证协商

#### 3.1 认证协商请求格式

```
客户端 -> 服务端:
+----+----------+----------+
|VER | NMETHODS | METHODS  |
| 1  |    1     | 1 to 255 |
+----+----------+----------+

字段说明:
    VER: 1字节, 协议版本, 固定为 0x05
    NMETHODS: 1字节, 客户端支持的认证方法数量
    METHODS: 1-255字节, 客户端支持的认证方法列表

认证方法值:
    0x00: 无认证 (NO AUTHENTICATION REQUIRED)
    0x01: GSSAPI (RFC 1961)
    0x02: 用户名/密码 (RFC 1929)
    0x03-0x7F: IANA 分配
    0x80-0xFE: 私有方法
    0xFF: 无可用方法
```

#### 3.2 认证协商响应格式

```
服务端 -> 客户端:
+----+--------+
|VER | METHOD |
| 1  |   1    |
+----+--------+

字段说明:
    VER: 1字节, 协议版本, 固定为 0x05
    METHOD: 1字节, 服务端选择的认证方法
        0x00-0x7F: 选中的认证方法
        0xFF: 无可用方法 (拒绝连接)
```

#### 3.3 无认证流程 (METHOD=0x00)

```
步骤 1: 发送认证协商请求
    客户端 -> 0x05 0x01 0x00 -> 服务端
    VER=0x05, NMETHODS=1, METHODS=[0x00]

步骤 2: 接收认证协商响应
    客户端 <- 0x05 0x00 <- 服务端
    VER=0x05, METHOD=0x00 (无认证)

进入请求阶段
```

#### 3.4 用户名/密码认证流程 (METHOD=0x02)

```
步骤 1: 发送认证协商请求
    客户端 -> 0x05 0x01 0x02 -> 服务端

步骤 2: 接收认证协商响应
    客户端 <- 0x05 0x02 <- 服务端
    METHOD=0x02 (用户名/密码认证)

步骤 3: 发送用户名/密码 (子协商)
    客户端 -> 0x01 + ULEN + UNAME + PLEN + PASSWD -> 服务端
    子协商版本=1, 用户名长度, 用户名, 密码长度, 密码
    示例: 0x01 0x05 "admin" 0x08 "password"

步骤 4: 接收认证结果
    客户端 <- 0x01 + STATUS <- 服务端
    STATUS: 0x00=成功, 其他=失败
```

#### 3.5 认证协商拒绝

```
步骤 1: 发送支持的认证方法
    客户端 -> 0x05 0x03 0x00 0x01 0x02 -> 服务端

步骤 2: 服务端无匹配方法
    客户端 <- 0x05 0xFF <- 服务端
    METHOD=0xFF (无可用方法)

客户端必须关闭连接
```

### 4. 请求格式

#### 4.1 通用请求格式

```
客户端 -> 服务端:
+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+

字段说明:
    VER: 1字节, 协议版本, 固定为 0x05
    CMD: 1字节, 命令类型
    RSV: 1字节, 保留字段, 固定为 0x00
    ATYP: 1字节, 地址类型
    DST.ADDR: 变长, 目标地址
    DST.PORT: 2字节, 目标端口 (大端序)

命令类型 (CMD):
    0x01: CONNECT - 建立 TCP 连接
    0x02: BIND - 绑定端口, 接收反向连接
    0x03: UDP_ASSOCIATE - 建立 UDP 中继

地址类型 (ATYP):
    0x01: IPv4 - 4 字节地址
    0x03: DOMAIN - 1字节长度 + 域名
    0x04: IPv6 - 16 字节地址
```

#### 4.2 CONNECT 命令示例

```
IPv4 示例: 连接 8.8.8.8:53
    0x05 0x01 0x00 0x01 0x08 0x08 0x08 0x08 0x00 0x35
    VER=5, CMD=CONNECT, RSV=0, ATYP=IPv4
    DST.ADDR=8.8.8.8, DST.PORT=53

域名示例: 连接 example.com:443
    0x05 0x01 0x00 0x03 0x0B "example.com" 0x01 0xBB
    VER=5, CMD=CONNECT, RSV=0, ATYP=DOMAIN
    LEN=11, DOMAIN="example.com", PORT=443
```

#### 4.3 UDP_ASSOCIATE 命令示例

```
请求 UDP 中继:
    0x05 0x03 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00
    VER=5, CMD=UDP_ASSOCIATE, RSV=0, ATYP=IPv4
    DST.ADDR=0.0.0.0, DST.PORT=0 (通常为0)

注意: DST.ADDR 和 DST.PORT 通常为 0, 因为只是请求 UDP relay
```

### 5. 响应格式

#### 5.1 响应格式

```
服务端 -> 客户端:
+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+

字段说明:
    VER: 1字节, 协议版本, 固定为 0x05
    REP: 1字节, 回复码
    RSV: 1字节, 保留字段, 固定为 0x00
    ATYP: 1字节, 地址类型
    BND.ADDR: 变长, 绑定地址
    BND.PORT: 2字节, 绑定端口 (大端序)
```

#### 5.2 回复码 (REP)

```
回复码值:
    0x00: 成功
    0x01: 一般性失败 (SOCKS服务器故障)
    0x02: 不允许的连接 (规则集拒绝)
    0x03: 网络不可达
    0x04: 主机不可达
    0x05: 连接被拒绝
    0x06: TTL 超时
    0x07: 不支持的命令
    0x08: 不支持的地址类型
    0x09-0xFF: 未分配
```

#### 5.3 响应示例

```
CONNECT 成功:
    0x05 0x00 0x00 0x01 0x7F 0x00 0x00 0x01 0x00 0x50
    VER=5, REP=成功, RSV=0, ATYP=IPv4
    BND.ADDR=127.0.0.1, BND.PORT=80

连接被拒绝:
    0x05 0x05 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00
    VER=5, REP=连接被拒绝, RSV=0, ATYP=IPv4
    BND.ADDR=0.0.0.0, BND.PORT=0
```

### 6. UDP 数据报格式

#### 6.1 UDP 数据报结构

```
+----+------+------+----------+----------+----------+
|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
| 2  |  1   |  1   | Variable |    2     | Variable |
+----+------+------+----------+----------+----------+

字段说明:
    RSV: 2字节, 保留字段, 固定为 0x0000
    FRAG: 1字节, 分片序号
    ATYP: 1字节, 地址类型 (同请求格式)
    DST.ADDR: 变长, 目标地址
    DST.PORT: 2字节, 目标端口 (大端序)
    DATA: 变长, 用户数据

FRAG 字段值:
    0x00: 独立数据报, 不分片 (最常用)
    0x01-0x7F: 分片序号
    注意: 大多数实现不支持分片, FRAG != 0x00 的数据报通常被丢弃
```

#### 6.2 UDP 数据报示例

```
发送 DNS 查询到 8.8.8.8:53:
    0x00 0x00 0x00 0x01 0x08 0x08 0x08 0x08 0x00 0x35 <DATA>
    RSV=0, FRAG=0, ATYP=IPv4, DST.ADDR=8.8.8.8, DST.PORT=53

发送数据到 example.com:443:
    0x00 0x00 0x00 0x03 0x0B "example.com" 0x01 0xBB <DATA>
    RSV=0, FRAG=0, ATYP=DOMAIN, DOMAIN="example.com", PORT=443
```

#### 6.3 UDP 多路复用原理

```
客户端 UDP Socket (单一端口)
    |
    +-- SOCKS5 UDP 数据报1 -> 目标: 8.8.8.8:53 (DNS)
    +-- SOCKS5 UDP 数据报2 -> 目标: 1.1.1.1:53 (DNS)
    +-- SOCKS5 UDP 数据报3 -> 目标: time.nist.gov:123 (NTP)
    |
    v
SOCKS5 服务端 UDP Relay (单一 UDP Socket)
    |
    +-- 路由到 -> 8.8.8.8:53
    +-- 路由到 -> 1.1.1.1:53
    +-- 路由到 -> time.nist.gov:123

关键特性:
1. 客户端使用单一 UDP socket 发送到不同目标
2. 每个数据报自带目标地址信息
3. 服务端 UDP Relay 根据数据报头部路由
4. 响应数据报包含原始来源地址，客户端可区分不同目标的响应
```

### 7. 地址格式详解

#### 7.1 IPv4 地址 (ATYP=0x01)

```
格式:
+------+----------+
| ATYP | ADDR     |
|  01  | 4 字节   |
+------+----------+

示例: 192.168.1.100
    0x01 0xC0 0xA8 0x01 0x64
    ATYP=IPv4, ADDR=192.168.1.100
```

#### 7.2 IPv6 地址 (ATYP=0x04)

```
格式:
+------+----------+
| ATYP | ADDR     |
|  04  | 16 字节  |
+------+----------+

示例: 2001:db8::1
    0x04 0x20 0x01 0x0D 0xB8 0x00 0x00 0x00 0x00
         0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01
    ATYP=IPv6, ADDR=2001:db8::1
```

#### 7.3 域名地址 (ATYP=0x03)

```
格式:
+------+----------+----------+
| ATYP | LEN      | DOMAIN   |
|  03  | 1 字节   | N 字节   |
+------+----------+----------+

示例: example.com
    0x03 0x0B "example.com"
    ATYP=DOMAIN, LEN=11, DOMAIN="example.com"

注意: 域名不以 NULL 结尾, 最大长度 255 字节
```

### 8. 端口格式

```
端口始终使用大端序 (高字节在前)

示例:
    端口 80:   0x00 0x50  (0x00*256 + 0x50 = 80)
    端口 443:  0x01 0xBB  (0x01*256 + 0xBB = 443)
    端口 53:   0x00 0x35  (0x00*256 + 0x35 = 53)
```

---

## 第二部分：命令流程详解

### 9. CONNECT 命令完整流程

```
阶段 1: 认证协商
    客户端 <==> 认证协商 <==> 服务端

阶段 2: 发送 CONNECT 请求
    客户端 -> 0x05 0x01 0x00 + ATYP + ADDR + PORT -> 服务端

阶段 3: 服务端处理
    服务端: 解析请求
    服务端: 验证权限
    服务端: DNS解析 (如果是域名)
    服务端: 连接目标服务器

阶段 4: 返回响应
    客户端 <- 0x05 0x00 0x00 + ATYP + ADDR + PORT <- 服务端

阶段 5: 数据传输
    客户端 -> 数据 -> 服务端 -> 转发 -> 目标服务器
    客户端 <- 数据 <- 服务端 <- 转发 <- 目标服务器

阶段 6: 连接关闭
    客户端 -> TCP FIN -> 服务端 -> TCP FIN -> 目标服务器
```

### 10. BIND 命令完整流程

BIND 用于 FTP 被动模式等需要反向连接的场景：

```
阶段 1: 发送 BIND 请求
    客户端 -> 0x05 0x02 0x00 + ATYP + ADDR + PORT -> 服务端

阶段 2: 服务端绑定端口
    服务端: 绑定端口, 监听连接

阶段 3: 第一次响应
    客户端 <- 0x05 0x00 0x00 + ATYP + BND.ADDR + BND.PORT <- 服务端
    返回绑定的地址和端口

阶段 4: 等待入站连接
    服务端 <- 新连接 <- 入站连接

阶段 5: 第二次响应
    客户端 <- 0x05 0x00 0x00 + ATYP + BND.ADDR + BND.PORT <- 服务端
    返回入站连接的来源地址

阶段 6: 数据传输
    客户端 <==> 双向转发 <==> 入站连接
```

### 11. UDP_ASSOCIATE 完整流程

```
控制层 (TCP):

阶段 1: TCP 控制通道建立
    客户端 -> TCP 连接 -> 服务端

阶段 2: 认证协商
    客户端 -> 0x05 0x01 0x00 -> 服务端
    客户端 <- 0x05 0x00 <- 服务端

阶段 3: UDP_ASSOCIATE 请求
    客户端 -> 0x05 0x03 0x00 + ATYP + ADDR + PORT -> 服务端
    目标地址通常为 0

阶段 4: 服务端响应
    客户端 <- 0x05 0x00 0x00 + ATYP + ADDR + PORT <- 服务端
    返回 UDP Relay 的地址和端口

转发层 (UDP):

阶段 5: UDP 数据传输
    客户端 UDP -> SOCKS5 UDP 封装 -> UDP Relay -> 目标
    客户端 UDP <- SOCKS5 UDP 解封 <- UDP Relay <- 目标

生命周期:

阶段 6: TCP 断开 -> UDP 关闭
    客户端 -> TCP 关闭 -> 服务端 -> 关闭 UDP Relay
```

---

## 第三部分：Prism 实现

### 12. 总体入口链路

1. **连接接收**：`worker` 监听端口并接收连接，创建 `session`
   入口：`include/prism/agent/worker/worker.hpp`，`psm::agent::worker::worker::do_accept`

2. **协议识别**：`session::diversion` 预读并识别协议（检查版本号 `0x05`）
   入口：`include/prism/agent/session/session.hpp`，`psm::agent::session::session::diversion`

3. **SOCKS5 处理器调用**：创建 SOCKS5 流对象并执行握手
   入口：`include/prism/agent/dispatch/handler.hpp`，`psm::agent::dispatch::socks5`

4. **协议握手执行**：`protocol::socks5::relay::handshake`
   入口：`include/prism/protocol/socks5/stream.hpp`

5. **上游连接建立**：`primitives::dial` 建立连接
   入口：`src/prism/pipeline/primitives.cpp`

6. **路由决策**：`router::async_forward` 直连或回退
   入口：`src/prism/resolve/router.cpp`

### 13. SOCKS5 握手实现

Prism 的 SOCKS5 握手分两个阶段：

#### 13.1 方法协商阶段

`negotiate_method` 处理认证协商：

1. **读取客户端请求**：异步读取 VER + NMETHODS + METHODS
2. **协议版本验证**：检查 VER 是否为 0x05
3. **方法检查**：查找支持的认证方法（当前仅支持 `0x00`）
4. **响应发送**：支持则发送 `[0x05, 0x00]`，否则 `[0x05, 0xFF]`

#### 13.2 请求读取阶段

`read_request_header` 读取请求：

1. **读取 4 字节头部**：VER、CMD、RSV、ATYP
2. **头部解码**：验证版本和保留字段
3. **地址解析分支**：根据 ATYP 选择解析函数

#### 13.3 地址解析分支

| ATYP | 函数 | 数据格式 | 最大长度 |
|------|------|----------|----------|
| IPv4 (0x01) | `read_address<4, Decoder>` | 4字节地址 + 2字节端口 | 6字节 |
| IPv6 (0x04) | `read_address<16, Decoder>` | 16字节地址 + 2字节端口 | 18字节 |
| Domain (0x03) | `read_domain_address` | 1字节长度 + 域名 + 2字节端口 | 258字节 |

### 14. 命令处理

#### 14.1 CONNECT 命令（已实现）

```
握手成功 -> 解析目标地址 -> 建立上游连接
  -> 发送成功响应 [0x05 0x00 ...]
  -> 进入 TCP 隧道转发
```

#### 14.2 UDP_ASSOCIATE 命令（已实现）

```
握手成功 -> 创建 UDP 中继 -> 返回 Relay 地址端口
  -> 进入 UDP 数据报循环
  -> TCP 断开时关闭 UDP Relay
```

#### 14.3 BIND 命令（暂不支持）

收到 BIND 命令返回 `reply_code::command_not_supported` (0x07)。

### 15. 目标解析与路由

握手成功后构造 `protocol::analysis::target`：

```cpp
target.host = protocol::socks5::to_string(request.destination_address);
target.port = std::to_string(request.destination_port);
target.positive = true;  // SOCKS5 始终是正向代理
```

路由决策流程：
1. 黑名单检查
2. DNS 解析
3. 直连尝试
4. 上游代理回退（可选）

### 16. 隧道转发

`primitives::tunnel` 进行双向 TCP 透传：

- 纯字节流转发，不进行协议升级
- 使用 PMR 内存资源分配缓冲区
- 任一方向断开即终止隧道

### 17. 错误处理映射

| 场景 | SOCKS5 回复码 | fault::code |
|------|---------------|-------------|
| BIND 命令 | 0x07 (command_not_supported) | unsupported_command |
| 不支持的认证方法 | 0xFF (no_acceptable_methods) | not_supported |
| 地址解析失败 | 0x08 (address_type_not_supported) | unsupported_address |
| 网络连接失败 | 0x03/0x04 | io_error |

---

## 第四部分：协议常量

### 18. 命令类型

| 常量 | 值 | 说明 | Prism 支持 |
|------|-----|------|-----------|
| CONNECT | 0x01 | TCP 连接 | ✓ |
| BIND | 0x02 | 反向连接 | ✗ |
| UDP_ASSOCIATE | 0x03 | UDP 中继 | ✓ |

### 19. 地址类型

| 常量 | 值 | 长度 |
|------|-----|------|
| IPv4 | 0x01 | 4 字节 |
| Domain | 0x03 | 1 + N 字节 |
| IPv6 | 0x04 | 16 字节 |

### 20. 认证方法

| 常量 | 值 | 说明 | Prism 支持 |
|------|-----|------|-----------|
| no_auth | 0x00 | 无认证 | ✓ |
| gssapi | 0x01 | GSSAPI | ✗ |
| password | 0x02 | 用户名/密码 | ✗ |
| no_acceptable_methods | 0xFF | 拒绝 | - |

### 21. 回复码

| 常量 | 值 | 说明 |
|------|-----|------|
| succeeded | 0x00 | 成功 |
| server_failure | 0x01 | 服务器失败 |
| connection_not_allowed | 0x02 | 连接不允许 |
| network_unreachable | 0x03 | 网络不可达 |
| host_unreachable | 0x04 | 主机不可达 |
| connection_refused | 0x05 | 连接被拒绝 |
| ttl_expired | 0x06 | TTL 过期 |
| command_not_supported | 0x07 | 命令不支持 |
| address_type_not_supported | 0x08 | 地址类型不支持 |

---

## 第五部分：实现注意事项

### 22. 安全考虑

- **认证**：生产环境应启用认证，避免开放代理被滥用
- **访问控制**：实现目标地址过滤，限制端口范围，防止访问内网
- **资源限制**：限制 UDP 会话数量，设置空闲超时

### 23. 性能考虑

- **UDP 中继**：使用单个 UDP socket 服务多个目标
- **内存管理**：预分配缓冲区，避免频繁分配
- **超时处理**：UDP 会话空闲超时，DNS 解析超时

### 24. 参考资料

- RFC 1928: SOCKS Protocol Version 5
- RFC 1929: Username/Password Authentication for SOCKS V5
- RFC 1961: GSS-API Authentication Method for SOCKS Version 5