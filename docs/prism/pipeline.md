# Pipeline 模块 — 协议管道原语

## 1. 模块概述

Pipeline 模块是 Prism 的协议管道基础设施，提供通用的底层原语组件，包括上游拨号、预读回放、TLS 握手和双向隧道转发。这些原语为 HTTP、SOCKS5、Trojan、VLESS、Shadowsocks 等具体协议处理提供一致的底层支撑。

### 文件结构

```
include/prism/pipeline/
├── primitives.hpp              # 管道原语定义（header-only）
└── protocols/
    ├── http.hpp/cpp            # HTTP 协议处理
    ├── socks5.hpp/cpp          # SOCKS5 协议处理
    ├── trojan.hpp/cpp          # Trojan 协议处理
    ├── vless.hpp/cpp           # VLESS 协议处理
    └── shadowsocks.hpp/cpp     # Shadowsocks 2022 协议处理
```

---

## 2. 核心类型与函数

### 2.1 preview 类 — 预读数据回放

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/pipeline/primitives.hpp` |
| 命名空间 | `psm::pipeline::primitives` |

```
class preview final : public transmission
├── inner_                 : shared_transmission    // 被包装的内部传输
├── preread_buffer_        : memory::vector<byte>   // 预读数据缓冲区
├── offset_                : size_t                 // 当前读取偏移
├── preview(inner, preread, mr)                     // 构造函数
├── is_reliable()          : bool                   // 委托给 inner
├── executor()             : executor_type          // 委托给 inner
├── async_read_some(buf, ec): awaitable<size_t>     // 先返回预读数据
├── async_write_some(buf, ec): awaitable<size_t>    // 委托给 inner
├── async_write(buf, ec)   : awaitable<size_t>      // 委托给 inner
├── close()                : void                   // 关闭 inner
├── cancel()               : void                   // 取消 inner
└── shutdown_write()       : void                   // 委托给 inner
```

**工作原理**：

```
async_read_some 流程:
    if offset_ < preread_buffer_.size():
        从 preread_buffer_ 复制数据
        offset_ += copied
        返回 copied
    else:
        委托给 inner_->async_read_some()
```

### 2.2 dial() 函数 — 上游拨号

```
// 通过 router 拨号
dial(router, label, target, allow_reverse, require_open)
    → awaitable<pair<fault::code, shared_transmission>>

// 通过 outbound::proxy 拨号
dial(outbound_proxy, target, executor)
    → awaitable<pair<fault::code, shared_transmission>>
```

**参数说明**：

| 参数 | 说明 |
|------|------|
| `router` | DNS 路由器，负责解析和连接 |
| `label` | 协议标签，用于日志 |
| `target` | 目标地址（host, port, is_reverse） |
| `allow_reverse` | 是否允许反向路由 |
| `require_open` | 是否要求返回已打开的 socket |
| `outbound_proxy` | 出站代理接口 |
| `executor` | 执行器 |

### 2.3 ssl_handshake() 函数 — TLS 服务端握手

```
ssl_handshake(ctx)
    → awaitable<pair<fault::code, shared_ssl_stream>>
```

**流程**：

```
ssl_handshake(ctx)
    │
    ├─ 包装 ctx.inbound 为 connector
    ├─ 创建 ssl::stream<connector>
    ├─ 执行 async_handshake(server)
    └─ 返回 {error, ssl_stream}
```

### 2.4 tunnel() 函数 — 双向透明转发

```
tunnel(inbound, outbound, buffer_size)
    → awaitable<void>
```

**流程**：

```
tunnel(inbound, outbound)
    │
    ├─ co_spawn read_loop (inbound → outbound)
    │   while active:
    │       read from inbound
    │       write to outbound
    │       EOF → shutdown_write(outbound)
    │
    ├─ co_spawn write_loop (outbound → inbound)
    │   while active:
    │       read from outbound
    │       write to inbound
    │       EOF → shutdown_write(inbound)
    │
    └─ 任一端 EOF → 关闭两端
```

### 2.5 forward() 函数 — 组合拨号 + 隧道

```
forward(ctx, target)
    → awaitable<void>
```

**流程**：

```
forward(ctx, target)
    │
    ├─ dial(router, target) → outbound
    ├─ tunnel(ctx.inbound, outbound)
    └─ 完成后自动关闭
```

### 2.6 辅助函数

```
shut_close(trans*)        : void    // 关闭裸指针传输
shut_close(shared_trans)  : void    // 关闭并释放智能指针

is_mux_target(host, port) : bool    // 判断是否为 mux 地址
make_datagram_router(ctx) : function // 创建 UDP 路由回调
```

---

## 3. 协议处理器

各协议处理器位于 `src/prism/pipeline/protocols/`，实现具体协议的完整处理流程：

| 协议 | 文件 | 说明 |
|------|------|------|
| HTTP | `http.cpp` | 解析请求 → 认证 → dial → tunnel |
| SOCKS5 | `socks5.cpp` | 方法协商 → 认证 → 命令处理 → tunnel |
| Trojan | `trojan.cpp` | SHA224 认证 → 目标解析 → tunnel/mux |
| VLESS | `vless.cpp` | UUID 认证 → 目标解析 → tunnel/mux |
| SS2022 | `shadowsocks.cpp` | AEAD 解密 → 目标解析 → tunnel |

---

## 4. 与其他模块的关系

```
pipeline 模块
├── 依赖
│   ├── channel::transport::transmission (传输抽象)
│   ├── channel::adapter::connector (Socket 适配器)
│   ├── resolve::router (DNS 路由)
│   ├── outbound::proxy (出站代理接口)
│   ├── memory (PMR 容器)
│   └── fault::code (错误码)
│
└── 被依赖
    └── agent::dispatch (协议处理器注册)
    └── stealth::scheme (Reality 等伪装方案)
```