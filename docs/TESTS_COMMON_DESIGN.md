# tests/common 协议设计分析与 mihomo 对标

## 1. mihomo 设计模式（E:\mihomo-Meta\mihomo-Meta\transport\）

### 1.1 外部库模式
mihomo 将每个协议作为**独立外部库**：
```
transport/vmess/
  vmess.go      # 入口：Client 配置 + NewClient 工厂
  conn.go       # Conn 实现（Read/Write/sendRequest/recvResponse）
  aead.go       # AEAD 认证（纯函数）
  chunk.go      # 分块编解码（纯函数）
  header.go     # 头部编解码（纯函数）
  user.go       # 用户/ID 管理
  http.go/h2.go/tls.go/websocket.go  # 传输层适配
```

### 1.2 核心接口（Go net.Conn 抽象）
```go
type Conn struct { ... }
func (vc *Conn) Write(b []byte) (int, error)   // 加密写
func (vc *Conn) Read(b []byte) (int, error)    // 解密读
func (c *Client) StreamConn(conn net.Conn, dst *DstAddr) (net.Conn, error)  // 握手工厂
func NewClient(config Config) (*Client, error) // 配置工厂
```

**关键设计**：
- **握手在工厂内**（StreamConn 完成认证+地址协商）
- **数据面 = net.Conn 接口**（调用方无感协议差异）
- **编解码纯函数分离**（aead/chunk/header 无 IO）
- **传输适配解耦**（http/h2/tls/ws 可插拔）

## 2. Prism 设计模式（include/prism + tests/common）

### 2.1 生产库（include/prism/protocol/）
```
socks5/handler/conn.hpp   # 显式握手 + 响应控制
  handshake()              # 显式握手（返回错误码+请求）
  send_success()           # 发送成功响应
  send_error()             # 发送错误响应
  async_associate()        # UDP 关联
  is_valid()               # 状态校验
  underlying()             # 底层传输访问
```

### 2.2 测试库（tests/common/proxy/）
```
socks5/conn.hpp            # 隐式握手（工厂内部）
  write_handshake()        # 客户端握手（工厂调用）
  read_handshake()         # 服务端握手（工厂调用）
  async_read_some()        # 数据面
  async_write_some()
```

## 3. 设计差异对比

| 维度 | mihomo | Prism 生产库 | tests/common（现状） |
|---|---|---|---|
| 握手 | 工厂内隐式 | **handler 显式** | 工厂内隐式 |
| 响应控制 | 无（net.Conn） | **send_success/error** | 无 |
| 编解码 | 纯函数分离 | 纯函数分离 | codec.hpp 分离 ✓ |
| 传输抽象 | net.Conn | transmission | transmission ✓ |
| 状态校验 | 无 | **is_valid()** | 无 |
| UDP 关联 | 无 | **async_associate()** | connect_packet |

## 4. 结论

**tests/common 应补的深度接口**（对齐 Prism 生产库模式）：
1. `handshake()` 显式化（从工厂移入 conn）
2. `send_success()/send_error()` 响应控制
3. `is_valid()` 状态校验
4. `underlying()` 底层访问
5. UDP 关联显式接口

**保持 mihomo 优点**：
- 编解码纯函数分离（已有）
- 传输抽象（已有）
- 工厂模式（保留 connect/accept 入口）
