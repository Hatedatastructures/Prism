# SOCKS5 协议完整文档

## 协议概述

SOCKS5 是一种网络代理协议，定义于 RFC 1928。它支持 TCP 和 UDP 代理，提供认证机制，支持多种地址类型

## 协议版本

- 版本号: 0x05 (5)
- 默认端口: 1080

---

## 完整流程图

### 总体架构

```txt
客户端 (Client)
    |
    +-- CONNECT (TCP隧道)
    |       |
    |       v
    +-- BIND (反向连接)
    |       |
    |       v
    +-- UDP_ASSOCIATE (UDP中继)
            |
            v
    SOCKS5 服务端 (Server)
            |
            +-- 目标服务器 (Target)
            +-- 入站连接 (Incoming)
            +-- UDP目标 (Targets)
```

### 完整会话流程

```txt
阶段 1: TCP 连接建立
    客户端 -> TCP SYN -> 服务端
    客户端 <- TCP SYN+ACK <- 服务端
    客户端 -> TCP ACK -> 服务端
                        |
                        v

阶段 2: 认证协商
    客户端 -> VER(5) + NMETHODS + METHODS -> 服务端
    客户端 <- VER(5) + METHOD <- 服务端
                        |
                        v

阶段 3: 认证 (如果需要)
    客户端 -> 用户名/密码 (如果METHOD=0x02) -> 服务端
    客户端 <- 认证结果 <- 服务端
                        |
                        v

阶段 4: 请求处理
    客户端 -> CMD + ATYP + DST.ADDR + PORT -> 服务端
    客户端 <- REP + ATYP + BND.ADDR + PORT <- 服务端
                        |
                        v

阶段 5: 数据传输
    客户端 <==> 数据双向传输 <==> 服务端
                        |
                        v

阶段 6: 连接关闭
    客户端 -> TCP FIN -> 服务端
    客户端 <- TCP FIN <- 服务端
```

---

## 1. 认证协商流程

### 无认证流程 (METHOD=0x00)

```txt
步骤 1: 发送认证协商请求
    客户端 -> 0x05 0x01 0x00 -> 服务端
    VER=0x05, NMETHODS=1, METHODS=[0x00]
                        |
                        v

步骤 2: 接收认证协商响应
    客户端 <- 0x05 0x00 <- 服务端
    VER=0x05, METHOD=0x00 (无认证)
                        |
                        v

进入请求阶段
```

### 用户名/密码认证流程 (METHOD=0x02)

```txt
步骤 1: 发送认证协商请求
    客户端 -> 0x05 0x01 0x02 -> 服务端
    VER=0x05, NMETHODS=1, METHODS=[0x02]
                        |
                        v

步骤 2: 接收认证协商响应
    客户端 <- 0x05 0x02 <- 服务端
    VER=0x05, METHOD=0x02 (用户名/密码认证)
                        |
                        v

步骤 3: 发送用户名/密码
    客户端 -> 0x01 + ULEN + UNAME + PLEN + PASSWD -> 服务端
    子协商版本=1, 用户名长度, 用户名, 密码长度, 密码
    示例: 0x01 0x05 "admin" 0x08 "password"
                        |
                        v

步骤 4: 接收认证结果
    客户端 <- 0x01 + STATUS <- 服务端
    STATUS: 0x00=成功, 其他=失败
    
    成功: 0x01 0x00 -> 进入请求阶段
    失败: 0x01 0x01 -> 关闭连接
```

### 认证协商拒绝流程

```txt
步骤 1: 发送支持的认证方法
    客户端 -> 0x05 0x03 0x00 0x01 0x02 -> 服务端
    支持: 无认证(0x00), GSSAPI(0x01), 用户名/密码(0x02)
                        |
                        v

步骤 2: 服务端检查无匹配方法
                        |
                        v

步骤 3: 返回拒绝
    客户端 <- 0x05 0xFF <- 服务端
    METHOD=0xFF (无可用方法)
                        |
                        v

客户端必须关闭连接
```

---

## 2. CONNECT 命令完整流程

```txt
阶段 1: 认证协商
    客户端 <==> 认证协商 <==> 服务端
                        |
                        v

阶段 2: 发送 CONNECT 请求
    客户端 -> 0x05 0x01 0x00 + ATYP + ADDR + PORT -> 服务端
    VER=5, CMD=CONNECT, RSV=0
                        |
                        v

阶段 3: 服务端处理
    服务端: 解析请求
    服务端: 验证权限
    服务端: DNS解析 (如果是域名)
    服务端: 连接目标服务器
        服务端 -> TCP SYN -> 目标服务器
        服务端 <- TCP SYN+ACK <- 目标服务器
        服务端 -> TCP ACK -> 目标服务器
                        |
                        v

阶段 4: 返回响应
    客户端 <- 0x05 0x00 0x00 + ATYP + ADDR + PORT <- 服务端
    REP=0x00 (成功)
                        |
                        v

阶段 5: 数据传输
    客户端 -> 数据 -> 服务端 -> 转发 -> 目标服务器
    客户端 <- 数据 <- 服务端 <- 转发 <- 目标服务器
                        |
                        v

阶段 6: 连接关闭
    客户端 -> TCP FIN -> 服务端 -> TCP FIN -> 目标服务器
    客户端 <- TCP FIN <- 服务端 <- TCP FIN <- 目标服务器
```

### CONNECT 错误处理流程

```txt
步骤 1: 发送 CONNECT 请求
    客户端 -> CONNECT 请求 -> 服务端
                        |
                        v

步骤 2: 服务端错误判断
    网络错误 (REP=0x03): 网络不可达
    权限错误 (REP=0x02): 规则拒绝
    目标错误 (REP=0x04): 主机不可达
    连接被拒 (REP=0x05): 连接被拒绝
                        |
                        v

步骤 3: 返回错误响应
    客户端 <- 0x05 + REP + 0x00 + ATYP + ADDR + PORT <- 服务端
    示例 (连接被拒绝): 0x05 0x05 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00
                        |
                        v

客户端处理: 分析REP值, 决定是否重试, 关闭连接或发起新请求
```

---

## 3. BIND 命令完整流程

```txt
阶段 1: 发送 BIND 请求
    客户端 -> 0x05 0x02 0x00 + ATYP + ADDR + PORT -> 服务端
    VER=5, CMD=BIND, DST.PORT=目标端口
                        |
                        v

阶段 2: 服务端绑定端口
    服务端: 绑定端口
    服务端: 监听连接
                        |
                        v

阶段 3: 第一次响应
    客户端 <- 0x05 0x00 0x00 + ATYP + BND.ADDR + BND.PORT <- 服务端
    返回绑定的地址和端口
                        |
                        v

阶段 4: 等待入站连接
    服务端: 等待外部连接
    服务端 <- 新连接 <- 入站连接
                        |
                        v

阶段 5: 第二次响应
    客户端 <- 0x05 0x00 0x00 + ATYP + BND.ADDR + BND.PORT <- 服务端
    返回入站连接的来源地址
                        |
                        v

阶段 6: 数据传输
    客户端 <==> 双向转发 <==> 入站连接
                        |
                        v

阶段 7: 连接关闭
    客户端 -> TCP FIN -> 服务端 -> TCP FIN -> 入站连接
```

### BIND 典型应用: FTP 被动模式数据连接

```txt
阶段 1: 控制连接已建立 (通过 CONNECT)
    FTP客户端 <==> SOCKS5代理 <==> FTP服务器
                        |
                        v

阶段 2: FTP PASV 命令
    FTP客户端 -> PASV -> FTP服务器
    FTP客户端 <- 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2) <- FTP服务器
                        |
                        v

阶段 3: 发送 BIND 请求
    FTP客户端 -> BIND 请求 -> SOCKS5代理
    SOCKS5代理 -> 连接数据端口 -> FTP服务器
                        |
                        v

阶段 4: BIND 第一次响应
    FTP客户端 <- 绑定地址 <- SOCKS5代理
                        |
                        v

阶段 5: 数据连接请求
    SOCKS5代理 <- 数据连接请求 <- FTP服务器
                        |
                        v

阶段 6: BIND 第二次响应
    FTP客户端 <- 连接来源 <- SOCKS5代理
                        |
                        v

阶段 7: 数据传输
    FTP客户端 <==> 文件列表/文件 <==> FTP服务器
```

---

## 4. UDP_ASSOCIATE 完整流程

```txt
控制层

阶段 1: TCP 控制通道建立
    客户端 -> TCP 连接 -> 服务端
                        |
                        v

阶段 2: 认证协商
    客户端 -> 0x05 0x01 0x00 -> 服务端
    客户端 <- 0x05 0x00 <- 服务端
    VER=5, NMETHODS=1, METHOD=0
                        |
                        v

阶段 3: UDP_ASSOCIATE 请求
    客户端 -> 0x05 0x03 0x00 + ATYP + ADDR + PORT -> 服务端
    VER=5, CMD=UDP_ASSOCIATE
    目标地址通常为 0
                        |
                        v

阶段 4: 服务端响应
    客户端 <- 0x05 0x00 0x00 + ATYP + ADDR + PORT <- 服务端
    返回 UDP Relay 的地址和端口
    例如: 0.0.0.0:12345
                        |
                        v

转发层

阶段 5: UDP 数据传输
    客户端 UDP -> SOCKS5 UDP 封装 -> UDP Relay -> 目标A
    客户端 UDP <- SOCKS5 UDP 解封 <- UDP Relay <- 目标A
    
    客户端 UDP -> SOCKS5 UDP 封装 -> UDP Relay -> 目标B
    客户端 UDP <- SOCKS5 UDP 解封 <- UDP Relay <- 目标B
                        |
                        v

生命周期

阶段 6: TCP 断开 -> UDP 关闭
    客户端 -> TCP 关闭 -> 服务端 -> 关闭 UDP Relay
```

### UDP 数据报封装流程

```txt
客户端发送

步骤 1: 原始数据
    数据: "Hello World"

步骤 2: 添加 SOCKS5 UDP 头部
    +----+------+------+----------+----------+
    |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |
    | 2  |  1   |  1   | Variable |    2     |
    +----+------+------+----------+----------+
    |          DATA                   |
    |          Variable               |
    +--------------------------------+

步骤 3: 封装后数据
    0x00 0x00 0x00 0x01 0x08 0x08 0x08 0x08 0x00 0x35 <DATA>
    |         |    |    |-----------------| |---|
    RSV=0     |    ATYP=IPv4  8.8.8.8      PORT=53
              FRAG=0 (不分片)

服务端处理

步骤 1: 解析头部
    提取目标地址: 8.8.8.8:53
    提取数据内容

步骤 2: 转发到目标
    UDP Relay -> 原始 UDP -> 8.8.8.8:53

步骤 3: 接收响应
    UDP Relay <- DNS Response <- 8.8.8.8:53

步骤 4: 封装响应
    0x00 0x00 0x00 0x01 0xC0 0xA8 0x01 0x64 0x12 0x34 <DNS Response>
    |         |    |    |-----------------| |---|
    RSV=0     |    ATYP=IPv4  192.168.1.100  PORT=1234
              FRAG=0

步骤 5: 返回客户端
    客户端 <- SOCKS5 UDP <- UDP Relay
```

### UDP 多路复用原理

```txt
客户端 UDP Socket (单一端口)
    |
    +-- SOCKS5 UDP 数据报1 -> 目标: 8.8.8.8:53 (DNS)
    |
    +-- SOCKS5 UDP 数据报2 -> 目标: 1.1.1.1:53 (DNS)
    |
    +-- SOCKS5 UDP 数据报3 -> 目标: time.nist.gov:123 (NTP)
    |
    v
SOCKS5 服务端 UDP Relay (单一 UDP Socket)
    |
    +-- 路由到 -> 8.8.8.8:53 (目标A)
    +-- 路由到 -> 1.1.1.1:53 (目标B)
    +-- 路由到 -> time.nist.gov:123 (目标C)

关键特性:
1. 客户端使用单一 UDP socket 发送到不同目标
2. 每个数据报自带目标地址信息
3. 服务端 UDP Relay 根据数据报头部的目标地址路由
4. 响应数据报包含原始来源地址，客户端可区分不同目标的响应
```

---

## 5. 协议消息格式详解

### 认证协商请求格式

```txt
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
    0x00: 无认证
    0x01: GSSAPI (RFC 1961)
    0x02: 用户名/密码 (RFC 1929)
    0x03: CHAP
    0x80-0xFE: 私有方法
    0xFF: 无可用方法

示例:
    0x05 0x01 0x00
    VER=5, NMETHODS=1, METHOD=0x00 (无认证)
```

### 认证协商响应格式

```txt
服务端 -> 客户端:
+----+--------+
|VER | METHOD |
| 1  |   1    |
+----+--------+

字段说明:
    VER: 1字节, 协议版本, 固定为 0x05
    METHOD: 1字节, 服务端选择的认证方法

示例:
    0x05 0x00 (选择无认证)
    0x05 0xFF (拒绝, 无可用方法)
```

---

## 6. 请求格式详解

### 通用请求格式

```txt
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

### CONNECT 命令示例

```txt
IPv4 示例: 连接 8.8.8.8:53
    0x05 0x01 0x00 0x01 0x08 0x08 0x08 0x08 0x00 0x35
    VER=5, CMD=CONNECT, RSV=0, ATYP=IPv4
    DST.ADDR=8.8.8.8, DST.PORT=53

域名示例: 连接 example.com:443
    0x05 0x01 0x00 0x03 0x0B "example.com" 0x01 0xBB
    VER=5, CMD=CONNECT, RSV=0, ATYP=DOMAIN
    LEN=11, DOMAIN="example.com", PORT=443
```

### UDP_ASSOCIATE 命令示例

```txt
请求 UDP 中继:
    0x05 0x03 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00
    VER=5, CMD=UDP_ASSOCIATE, RSV=0, ATYP=IPv4
    DST.ADDR=0.0.0.0, DST.PORT=0 (通常为0)

注意: DST.ADDR 和 DST.PORT 通常为 0, 因为只是请求 UDP relay
```

### BIND 命令示例

```txt
绑定端口等待反向连接:
    0x05 0x02 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x50
    VER=5, CMD=BIND, RSV=0, ATYP=IPv4
    DST.ADDR=0.0.0.0, DST.PORT=80

BIND 流程:
    1. 服务端绑定指定端口
    2. 返回绑定的地址和端口给客户端
    3. 当有连接接入时, 再次返回连接来源的地址
```

---

## 7. 响应格式详解

### 成功响应

```txt
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

示例: CONNECT 成功
    0x05 0x00 0x00 0x01 0x7F 0x00 0x00 0x01 0x00 0x50
    VER=5, REP=成功, RSV=0, ATYP=IPv4
    BND.ADDR=127.0.0.1, BND.PORT=80
```

### 错误响应

```txt
回复码 (REP):
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

示例: 连接被拒绝
    0x05 0x05 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00
    VER=5, REP=连接被拒绝, RSV=0, ATYP=IPv4
    BND.ADDR=0.0.0.0, BND.PORT=0
```

---

## 8. UDP 数据报格式

### UDP 数据报结构

```txt
+----+------+------+----------+----------+----------+
|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
| 2  |  1   |  1   | Variable |    2     | Variable |
+----+------+------+----------+----------+----------+

字段说明:
    RSV: 2字节, 保留字段, 固定为 0x0000
    FRAG: 1字节, 分片序号, 0x00 表示独立数据报
    ATYP: 1字节, 地址类型 (同请求格式)
    DST.ADDR: 变长, 目标地址
    DST.PORT: 2字节, 目标端口 (大端序)
    DATA: 变长, 用户数据
```

### UDP 数据报示例

```txt
发送 DNS 查询到 8.8.8.8:53:
    0x00 0x00 0x00 0x01 0x08 0x08 0x08 0x08 0x00 0x35 <DATA>
    RSV=0, FRAG=0, ATYP=IPv4, DST.ADDR=8.8.8.8, DST.PORT=53

发送数据到 example.com:443:
    0x00 0x00 0x00 0x03 0x0B "example.com" 0x01 0xBB <DATA>
    RSV=0, FRAG=0, ATYP=DOMAIN, DOMAIN="example.com", PORT=443
```

### UDP 分片说明

```txt
FRAG 字段值:
    0x00: 独立数据报, 不分片 (最常用)
    0x01: 第一个分片
    0x02-0x7F: 后续分片
    0x80: 最后一个分片

注意: 大多数实现不支持分片, FRAG != 0x00 的数据报通常被丢弃
```

---

## 9. 地址格式详解

### IPv4 地址 (ATYP=0x01)

```txt
格式:
+------+----------+
| ATYP | ADDR     |
|  01  | 4 字节   |
+------+----------+

示例: 192.168.1.100
    0x01 0xC0 0xA8 0x01 0x64
    ATYP=IPv4, ADDR=192.168.1.100
```

### IPv6 地址 (ATYP=0x04)

```txt
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

### 域名地址 (ATYP=0x03)

```txt
格式:
+------+----------+----------+
| ATYP | LEN      | DOMAIN   |
|  03  | 1 字节   | N 字节   |
+------+----------+----------+

示例: example.com
    0x03 0x0B 0x65 0x78 0x61 0x6D 0x70 0x6C 0x65 0x2E 0x63 0x6F 0x6D
    ATYP=DOMAIN, LEN=11, DOMAIN="example.com"

注意: 域名不以 NULL 结尾, 长度由 LEN 字段指定, 最大长度 255 字节
```

---

## 10. 端口格式

```txt
端口始终使用大端序 (高字节在前)

示例:
    端口 80:   0x00 0x50  (高字节=0x00, 低字节=0x50)
    端口 443:  0x01 0xBB  (高字节=0x01, 低字节=0xBB, 1*256+187=443)
    端口 53:   0x00 0x35  (高字节=0x00, 低字节=0x35)
```

---

## 11. 实现注意事项

### 安全考虑

```txt
认证:
    - 生产环境应启用用户名/密码认证
    - 避免开放代理被滥用

访问控制:
    - 实现目标地址过滤
    - 限制可访问的端口范围
    - 防止访问内网地址

资源限制:
    - 限制 UDP 会话数量
    - 设置空闲超时
    - 限制数据报大小
```

### 性能考虑

```txt
UDP 中继:
    - 使用单个 UDP socket 服务多个目标
    - 避免为每个目标创建新 socket

内存管理:
    - 预分配缓冲区
    - 避免频繁内存分配

超时处理:
    - UDP 会话空闲超时
    - DNS 解析超时
```

### 错误处理

```txt
协议错误:
    - 无效版本号
    - 不支持的命令
    - 无效地址格式

网络错误:
    - 连接失败
    - DNS 解析失败
    - 超时

资源错误:
    - 端口耗尽
    - 内存不足
```

---

## 12. 参考资料

- RFC 1928: SOCKS Protocol Version 5
- RFC 1929: Username/Password Authentication for SOCKS V5
- RFC 1961: GSS-API Authentication Method for SOCKS Version 5
