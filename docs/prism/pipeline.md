# Pipeline 模块

**源码位置**: `include/prism/pipeline/`

协议管道层，提供 primitives 原语（dial、preview、tunnel）和各协议处理器。

## 文件结构

```
pipeline/
├── primitives.hpp/cpp    # 原语：dial（连接）、preview（预读）、tunnel（隧道）、forward（转发）
└── protocols/            # 协议处理器（由各协议模块实现）
    ├── http.hpp/cpp
    ├── socks5.hpp/cpp
    ├── trojan.hpp/cpp
    ├── vless.hpp/cpp
    └── shadowsocks.hpp/cpp
```

## 核心类型

### primitives

核心原语集合，定义于 `primitives.hpp`：

- **dial()**: 通过 router 或 outbound proxy 建立上游连接，返回 transmission
- **preview()**: 包装传输层，预读指定字节后通过 `preview` 类回放
- **tunnel()**: 双向透明数据转发，连接 inbound 和 outbound 两个 transmission
- **forward()**: 组合 dial + tunnel，一键完成连接和转发
- **ssl_handshake()**: 执行 TLS 服务端握手
- **wrap_with_preview()**: 将 inbound transport 包装为带预读数据的 transmission
- **shut_close()**: 关闭 transmission
- **is_mux_target()**: 判断目标是否为 mux 多路复用地址
- **make_datagram_router()**: 创建 UDP 数据报路由回调

### preview 类

`preview` 是一个包装器，用于预读数据回放。包装 inbound transport 后，后续的 read 操作会先返回预读的字节，再回到原始 transport。

### protocols

各协议处理器实现，在 dispatch 层注册后被 session 调用：
- **http**: HTTP 代理协议处理（支持 Basic 认证）
- **socks5**: SOCKS5 代理协议处理
- **trojan**: Trojan 协议处理（支持 mux 多路复用）
- **vless**: VLESS 协议处理
- **shadowsocks**: Shadowsocks 2022 协议处理

## 与其他模块的关系

- **依赖**: resolve（router 建立连接）、channel（transmission/transport）、outbound（代理转发）
- **被依赖**: agent（session 通过 dispatch 调用各协议 handler）
