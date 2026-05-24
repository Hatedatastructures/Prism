# h2mux 协议 -- HTTP/2 CONNECT 多路复用模块

## 1. 模块概述

### 1.1 协议背景

h2mux 是 Prism 基于 HTTP/2 实现的应用层多路复用协议。它利用 HTTP/2 原生的 stream 机制，将每个代理连接映射为一个 HTTP/2 CONNECT 请求，通过标准的 HTTP/2 帧格式和流控实现高效的多连接复用。

与 smux / yamux 等自定义多路复用协议不同，h2mux 完全复用 HTTP/2 标准协议栈（由 nghttp2 库提供帧编解码），使得 h2mux 流量与任何正常的 HTTP/2 流量完全一致。流量控制由 HTTP/2 标准流控自动管理，无需应用层窗口机制。

h2mux 主要服务于 TrustTunnel 伪装方案，作为其底层多路复用传输层。TrustTunnel 负责 TLS 握手和认证，h2mux 负责 HTTP/2 帧编解码和 stream 生命周期管理。

### 1.2 核心设计思想

h2mux 的核心设计是 **nghttp2 回调到协程的桥接**：

1. **nghttp2 帧编解码**：利用 nghttp2 库处理 HTTP/2 帧的编解码，无需手动实现 HPACK、流控等复杂逻辑
2. **回调到协程桥接**：nghttp2 的同步回调通过 `concurrent_channel` 和 `co_spawn` 桥接到 Prism 的异步协程架构
3. **address_resolver 注入**：地址解析逻辑通过回调注入，支持 TrustTunnel（从 `:authority` 头解析）和 sing-mux（从 DATA 帧解析 StreamRequest）两种模式
4. **三种流类型**：TCP（duct）、UDP（parcel）和健康检查（check），由 address_resolver 返回的 `stream_type` 决定

### 1.3 与其他多路复用协议的对比

| 特性 | smux | yamux | h2mux |
|------|------|-------|-------|
| 帧格式 | 自定义 8B header | 自定义 12B header | HTTP/2 标准帧 |
| 流控 | 无 | 窗口控制 | HTTP/2 标准流控 |
| 头部压缩 | 无 | 无 | HPACK |
| 外部依赖 | 无 | 无 | nghttp2 |
| 接入方式 | sing-mux 协商 | sing-mux 协商 | 直接创建 |
| TCP 支持 | duct | duct | duct |
| UDP 支持 | parcel | parcel | parcel |
| 健康检查 | 无 | 无 | check |
| 适用场景 | Trojan/VLESS | Trojan/VLESS | TrustTunnel |

### 1.4 协议栈

```
Application (TCP/UDP proxy)
   │
   ├─ duct / parcel              TCP 流管道 / UDP 数据报管道
   │
   ├─ h2mux::craft              HTTP/2 帧编解码 + stream 调度
   │    nghttp2 session + callbacks
   │
   ├─ multiplex::core            协议无关抽象基类
   │    pending_ / ducts_ / parcels_ 流状态管理
   │
   ├─ transport                  TLS 隧道 (ALPN h2)
   │
   └─ TCP Socket
```

## 2. 架构设计

### 2.1 文件结构

```
include/prism/multiplex/h2mux/
├── config.hpp       # h2mux 配置（stream 数、帧大小、超时）
└── craft.hpp        # h2mux::craft 类定义（core 子类）

src/prism/multiplex/h2mux/
└── craft.cpp        # craft 实现（nghttp2 回调 + 帧循环 + stream 管理）
```

h2mux 依赖 `multiplex::core` 提供的协议无关基类，以及 `duct` 和 `parcel` 进行实际的数据转发。

### 2.2 组件关系

```
  craft (core 子类)
    │
    ├── run() ──────────────────── 入口协程
    │     ├── init_nghttp2()           nghttp2 session + callbacks 注册
    │     ├── send_pending()           发送 HTTP/2 SETTINGS
    │     ├── co_spawn(send_loop)      启动发送循环协程
    │     └── frame_loop()             进入帧接收循环
    │
    ├── frame_loop() ───────────── 帧接收
    │     ├── async_read_some()        从 transport 读取原始字节
    │     ├── nghttp2_session_mem_recv() 交给 nghttp2 解析
    │     └── send_pending()           发送 nghttp2 生成的响应帧
    │
    ├── nghttp2 回调 ───────────── 帧事件处理
    │     ├── on_begin_headers()       检测 CONNECT 请求
    │     ├── on_header()              收集请求头
    │     ├── on_frame_recv()          HEADERS 完成 → handle_connect()
    │     ├── on_data()                DATA 帧 → duct/parcel 分发
    │     └── on_stream_close()        stream 关闭清理
    │
    ├── handle_connect() ────────── CONNECT 处理
    │     ├── resolver_()              调用 address_resolver 回调
    │     ├── 首个 CONNECT？→ wait_first_connect 通知
    │     └── 后续 CONNECT → co_spawn(activate_stream)
    │
    ├── activate_stream() ────────── 流激活
    │     ├── check → 200 + RST_STREAM
    │     ├── udp → make_parcel() → parcel.start()
    │     └── tcp → async_forward() → make_duct() → duct.start()
    │
    ├── send_loop() ──────────────── 发送循环
    │     ├── send_channel_.async_receive() 从 channel 取数据
    │     ├── is_fin？→ nghttp2_submit_rst_stream
    │     └── else → nghttp2_submit_data + send_pending
    │
    └── 公共接口
          ├── send_data()              投递数据到 send_channel_
          ├── send_fin()               投递 FIN 到 send_channel_
          ├── wait_first_connect()     等待首个 CONNECT（供 TrustTunnel）
          ├── respond_connect()        回复 CONNECT (200/407)
          └── executor()              返回 transport executor
```

## 3. 核心组件说明

### 3.1 craft（HTTP/2 多路复用会话）

`craft` 继承 `multiplex::core`，是 h2mux 的核心类。它封装了 nghttp2 session 的完整生命周期，通过 nghttp2 的回调机制处理 HTTP/2 帧。

#### 数据结构

| 数据成员 | 类型 | 说明 |
|----------|------|------|
| `session_` | `nghttp2_session*` | nghttp2 会话句柄 |
| `resolver_` | `address_resolver` | 地址解析回调（外部注入） |
| `h2_pending_` | `unordered_map<uint32_t, h2_pending_entry>` | 等待地址解析的 stream |
| `send_channel_` | `concurrent_channel<outbound_data>` | 发送通道（串行化写入） |
| `first_connect_` | `h2_headers` | 第一个 CONNECT 的请求头 |
| `first_connect_waiter_` | `steady_timer` | 首个 CONNECT 等待定时器 |

#### h2_headers（HTTP/2 请求头收集）

```
struct h2_headers {
    int32_t stream_id;         // HTTP/2 stream ID
    memory::string authority;  // :authority 头（CONNECT 目标）
    memory::string host;       // Host 头（用于类型判断）
    memory::string user_agent; // User-Agent 头
    memory::string proxy_auth; // Proxy-Authorization 头
};
```

#### h2_pending_entry（等待中的 stream）

```
struct h2_pending_entry {
    h2_headers headers;       // 收集的请求头
    h2_stream_info info;      // resolver 返回的地址信息
    bool connecting = false;  // 是否已发起连接（防止重复）
};
```

#### outbound_data（出站数据项）

```
struct outbound_data {
    uint32_t stream_id;              // 目标 stream
    memory::vector<std::byte> payload; // 待发送数据
    bool is_fin;                     // 是否为 FIN（RST_STREAM）
};
```

### 3.2 address_resolver（地址解析回调）

address_resolver 是一个 `std::function`，由外部注入，决定如何从 CONNECT 请求提取目标地址：

```cpp
using address_resolver = std::function<h2_stream_info(
    int32_t stream_id, const h2_headers &headers)>;
```

**两种实现模式**：

| 模式 | 使用者 | resolver 行为 |
|------|--------|---------------|
| TrustTunnel | `trusttunnel::scheme` | 从 `:authority` 解析 host:port，从 Host 判断 stream 类型，直接返回 valid=true |
| sing-mux | bootstrap | 忽略 HEADERS，等待 DATA 帧的 StreamRequest，返回 valid=false |

### 3.3 stream_type（流类型路由）

| 类型 | 值 | 说明 | 处理方式 |
|------|----|------|----------|
| `tcp` | 默认 | TCP 流代理 | `make_duct()` + `connect::async_forward()` |
| `udp` | 由 resolver 判定 | UDP 数据报代理 | `make_parcel()` + `set_destination()` |
| `icmp` | 由 resolver 判定 | ICMP 代理 | 后续迭代（当前 fallback 到 TCP） |
| `check` | 由 resolver 判定 | 健康检查 | 200 OK + RST_STREAM |

### 3.4 nghttp2 回调

#### on_begin_headers

当 nghttp2 检测到新的 HEADERS 帧时触发。检查 `:method == CONNECT`，如果是则在 `h2_pending_` 中创建新条目。

#### on_header

逐个处理 HTTP/2 请求头键值对，填充 `h2_pending_entry.headers`：
- `:authority` -> `headers.authority`
- `host` / `Host` -> `headers.host`
- `user-agent` -> `headers.user_agent`
- `proxy-authorization` -> `headers.proxy_auth`

#### on_frame_recv

HEADERS 帧接收完成时触发。调用 `handle_connect()` 进行地址解析和 stream 激活。

#### on_data

接收 DATA 帧数据时触发。三路分发：
1. `h2_pending_` 中存在：sing-mux 模式首帧（等待 StreamRequest）
2. `ducts_` 中存在：TCP duct 数据 -> `duct.on_mux_data()`
3. `parcels_` 中存在：UDP parcel 数据 -> `parcel.on_mux_data()`
4. 都不存在：RST_STREAM（协议错误）

#### on_stream_close

stream 关闭时触发。清理 `h2_pending_`、`ducts_`、`parcels_` 中的对应条目。

### 3.5 send_loop（发送循环协程）

`send_loop` 是独立运行的协程，从 `send_channel_` 取出 `outbound_data`，通过 nghttp2 编码后写入 transport：

```
send_loop()
  │
  ├── send_channel_.async_receive()  等待出站数据
  │
  ├── is_fin？
  │     └── nghttp2_submit_rst_stream() + send_pending()
  │
  └── else (数据)
        ├── 构造 nghttp2_data_provider + read_callback
        ├── nghttp2_submit_data()
        └── send_pending()  同步调用 read_callback，发送编码后的帧
```

**read_callback 设计**：

```cpp
// nghttp2 的 read_callback 是同步调用
// 使用 shared_ptr<payload> 确保回调期间数据有效
auto payload = std::make_shared<memory::vector<std::byte>>(...);
nghttp2_data_provider dp;
dp.source.ptr = src.get();
dp.read_callback = [](..., nghttp2_data_source *source, ...) -> ssize_t {
    auto *ds = static_cast<data_source *>(source->ptr);
    // 拷贝数据到 nghttp2 提供的输出缓冲区
    memcpy(buf, ds->buf->data() + ds->offset, to_copy);
    ds->offset += to_copy;
    if (ds->offset >= ds->buf->size())
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return to_copy;
};
```

## 4. 数据流图

### 4.1 帧接收流程

```
Transport (TLS)
    │
    │ async_read_some()
    v
frame_loop()
    │
    ├── 读取 raw bytes
    │
    ├── nghttp2_session_mem_recv(raw_bytes)
    │     │
    │     ├── on_begin_headers()
    │     │     └── CONNECT 检测 → h2_pending_[id] = entry
    │     │
    │     ├── on_header(name, value)
    │     │     └── 填充 headers.authority/host/proxy_auth
    │     │
    │     ├── on_frame_recv()
    │     │     └── handle_connect(id)
    │     │           ├── resolver_(id, headers) → info
    │     │           ├── 首个 CONNECT → 通知 wait_first_connect
    │     │           └── 后续 CONNECT → co_spawn(activate_stream)
    │     │
    │     ├── on_data(stream_id, data)
    │     │     ├── ducts_[id] → co_spawn(duct.on_mux_data)
    │     │     └── parcels_[id] → co_spawn(parcel.on_mux_data)
    │     │
    │     └── on_stream_close(stream_id)
    │           ├── ducts_[id] → duct.on_mux_fin()
    │           └── parcels_[id] → parcel.close()
    │
    └── send_pending() → async_write(encoded_frames)
```

### 4.2 帧发送流程

```
duct / parcel
    │
    │ craft.send_data(stream_id, payload)
    v
send_channel_.async_send(outbound_data)
    │
    v
send_loop()
    │
    ├── send_channel_.async_receive()
    │
    ├── is_fin？
    │     └── nghttp2_submit_rst_stream() → send_pending()
    │
    └── data？
          ├── nghttp2_submit_data() + read_callback
          └── send_pending()
                │
                ├── nghttp2_session_mem_send() → encoded bytes
                └── async_write(transport, encoded_bytes)
```

### 4.3 stream 生命周期

```
CONNECT 请求到达
    │
    ├── on_begin_headers → 创建 h2_pending_[id]
    ├── on_header × N → 收集请求头
    ├── on_frame_recv → handle_connect()
    │     ├── resolver_() → h2_stream_info
    │     │
    │     ├── 首个 CONNECT:
    │     │     └── wait_first_connect 通知（等待外部认证）
    │     │           └── respond_connect(200/407)
    │     │           └── activate_stream()
    │     │
    │     └── 后续 CONNECT:
    │           └── co_spawn(activate_stream())
    │
    ├── activate_stream()
    │     ├── TCP: async_forward → make_duct → duct.start()
    │     ├── UDP: respond_connect(200) → make_parcel → parcel.start()
    │     └── Check: respond_connect(200) → RST_STREAM
    │
    ├── DATA 帧到达 → on_data()
    │     └── duct.on_mux_data() / parcel.on_mux_data()
    │
    ├── RST_STREAM / stream 关闭 → on_stream_close()
    │     └── duct.on_mux_fin() / parcel.close()
    │     └── erase from ducts_/parcels_
    │
    └── stream 结束
```

## 5. 配置选项

### 5.1 JSON 配置结构

h2mux 配置位于 `multiplex` 配置段的 `h2mux` 子节：

```json
{
  "multiplex": {
    "h2mux": {
      "max_streams": 256,
      "buffer_size": 4096,
      "max_frame_size": 16384,
      "idle_timeout_ms": 30000,
      "udp_idle_timeout_ms": 60000,
      "udp_max_datagram": 65535
    }
  }
}
```

### 5.2 参数详解

| 参数 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `max_streams` | uint32 | `256` | 单会话最大并发 HTTP/2 stream 数，也作为 send_channel 的容量 |
| `buffer_size` | uint32 | `4096` | 每流读取缓冲区大小（字节） |
| `max_frame_size` | uint32 | `16384` | HTTP/2 最大 DATA 帧载荷大小（字节），默认 16384 符合 HTTP/2 规范 |
| `idle_timeout_ms` | uint32 | `30000` | HTTP/2 连接空闲超时（毫秒） |
| `udp_idle_timeout_ms` | uint32 | `60000` | UDP parcel 空闲超时（毫秒），超时自动关闭 |
| `udp_max_datagram` | uint32 | `65535` | UDP 数据报最大长度（字节） |

## 6. 与其他模块的交互

### 6.1 与 multiplex::core 的关系

`h2mux::craft` 继承 `multiplex::core`，复用其提供的：
- `start()` 方法：启动 `run()` 协程
- `make_duct()` / `make_parcel()` 工厂方法：创建 TCP/UDP 管道
- `ducts_` / `parcels_` 流状态容器
- `active_` 原子标志：控制 frame_loop 退出
- `close()` 方法：关闭所有流和 transport

craft 不使用 core 的 `pending_`，而是维护独立的 `h2_pending_` 映射，因为 HTTP/2 的 pending 语义与 smux/yamux 不同。

### 6.2 与 duct / parcel 的关系

```
craft
  │
  ├── make_duct(stream_id, craft, target_transport, buffer_config)
  │     └── duct
  │           ├── start() → 读协程 + 写协程
  │           ├── on_mux_data(payload) → upstream 写入
  │           └── on_mux_fin() → upstream 半关闭
  │
  └── make_parcel(stream_id, craft, router, timeout, max_datagram)
        └── parcel
              ├── start() → 读协程
              ├── on_mux_data(payload) → UDP 转发
              └── close() → 清理
```

duct 和 parcel 通过 core 的虚函数接口（`send_data`、`send_fin`）与 craft 交互，无需感知具体的 HTTP/2 帧格式。

### 6.3 与 TrustTunnel 的关系

TrustTunnel 是 h2mux 的主要使用者：

```
trusttunnel::scheme::handshake()
  │
  ├── TLS 握手 (ALPN=h2)
  │
  ├── 创建 craft(transport, router, cfg, trusttunnel_resolver)
  │     └── trusttunnel_resolver: 从 :authority 解析 host:port
  │
  ├── craft->start()        nghttp2 初始化 + frame_loop
  ├── craft->wait_first_connect()  等待首个 CONNECT
  │
  ├── verify_basic_auth()    HTTP Basic Auth 认证
  ├── craft->respond_connect(200)  回复 200 OK
  └── craft->activate_stream()     激活首个 stream
```

### 6.4 与 connect 模块的关系

TCP stream 通过 `connect::async_forward()` 建立上游连接：

```
craft::activate_stream(stream_id)
  │
  ├── connect::async_forward(router, host, port)
  │     └── 返回 socket
  │
  ├── transport::make_reliable(socket)
  └── make_duct(stream_id, craft, reliable_transport)
```

### 6.5 与 transport 层的关系

h2mux 的 transport 层是 TLS 加密传输（`transport::encrypted`），ALPN 协商为 h2。所有 HTTP/2 帧通过 `async_read_some` / `async_write` 与 transport 交互。
