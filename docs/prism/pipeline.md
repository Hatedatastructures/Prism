# Pipeline 模块

**源码位置**: `include/prism/pipeline/`

协议管道层，提供 primitives 原语和 tunnel 隧道转发。

## 文件结构

```
pipeline/
├── primitives.hpp/cpp    # 原语：dial（连接）、preview（预读）、tunnel（隧道）
├── tunnel.hpp            # 双向透明转发隧道
└── protocols/            # 协议处理器（由各协议模块实现）
    ├── http.cpp
    ├── socks5.cpp
    ├── trojan.cpp
    ├── vless.cpp
    └── shadowsocks.cpp
```

## 核心类型

### primitives
核心原语集合：
- **dial()**: 通过 router 建立上游连接（支持旧路径和 outbound 新路径）
- **preview()**: 包装传输层，预读指定字节后放回
- **tunnel()**: 双向透明数据转发

### tunnel
双向隧道，连接 inbound 和 outbound 两个 transmission，全双工数据搬运。

## 与其他模块的关系

- **依赖**: resolve（router 建立连接）、channel（transmission）、outbound（代理转发）
- **被依赖**: agent（session 通过 dispatch 调用各协议 handler）
