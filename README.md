<div align="center">

# Prism

![C++23](https://img.shields.io/badge/Standard-C%2B%2B23-blue.svg?logo=c%2B%2B)
![Platform](https://img.shields.io/badge/Platform-Windows%2011%20|%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Build](https://img.shields.io/badge/Build-CMake-orange)
![Architecture](https://img.shields.io/badge/Architecture-Coroutine%20%2B%20PMR-success)

**现代C++高性能协程代理**

</div>

## 简介

Prism 是一个基于 **C++23 协程** 与 **Boost.Asio** 构建的高性能服务端代理，支持 `Clash` 连接。

它采用了现代 C++ 的最新特性——**纯协程架构**与**PMR 内存模型**，专为低延迟、高并发的网络转发场景打造。无论是作为代理网关、网络中间件，还是转发节点，Prism 都能提供不错的性能。

> **设计思路**：用协程避免回调的复杂性同步代码写异步并发，用内存池消除堆分配，用零拷贝减少数据搬移。

## 核心亮点

- **PMR 内存策略**：全局内存池 + 帧分配器，热路径零堆分配，避免内存碎片和分配延迟
- **透明代理**：握手后双向透传 TCP 字节流，零协议感知开销，吞吐量接近原生 socket
- **动态识别**：首包嗅探 HTTP/SOCKS5/Trojan，自动分流处理，无需端口分离
- **并发 DNS 解析**：内置 DNS 客户端，多服务器并发查询取最快响应，支持缓存、负面缓存、IPv6 过滤
- **负载均衡**：基于评分的 Worker 选择，过载检测与滞后机制，避免热点堆积
- **多路复用**：兼容 Mihomo/xtaci/smux v1，单连接承载多流，降低连接开销，增加流量行为分析难度
- **凭据认证**：SHA224 哈希验证 + 每用户连接数限制，支持多用户管理




- **HTTP/HTTPS**：HTTP 正向代理与 `CONNECT` 隧道，支持浏览器和命令行工具
- **SOCKS5**：RFC 1928 完整实现，TCP CONNECT + UDP ASSOCIATE，支持游戏和聊天软件
- **Trojan**：Trojan over TLS，TLS 握手 + 凭据验证 + 流量转发，对抗流量检测
- **smux 多路复用**：兼容 Mihomo/xtaci/smux v1，单 TCP 连接承载多个独立子流

## 当前正在实现的
- [x] DNS 解析
- [x] 负载均衡与反压
- [x] smux 多路复用
- [ ] QUIC
- [ ] WebSocket

## 依赖项

| 依赖 | 版本 | 说明 |
|------|------|------|
| **C++ 编译器** | C++23 | GCC 13+  |
| **CMake** | 3.23+ | 构建系统 |
| **Boost.Asio** | 1.85+ | 协程支持（header-only） |
| **BoringSSL** | - | TLS 实现 |
| **spdlog** | - | 日志库 |
| **glaze** | - | JSON 序列化 |
| **Google Benchmark** | - | 性能测试（自动拉取） |



## 启动与验证

程序默认读取 `src/configuration.json`，监听 `8081` 端口：

```bat
build_release/src/Prism.exe
```

验证代理功能：

```bat
curl -v -x http://127.0.0.1:8081 http://www.baidu.com
curl -v -x http://127.0.0.1:8081 https://www.baidu.com
curl -v -x socks5://127.0.0.1:8081 http://www.baidu.com
```


## 目录结构

```txt
Prism/
├── include/prism/             # 核心库头文件
│   ├── exception/             # 异常定义
│   ├── loader/                # 配置加载
│   ├── agent/                 # 代理核心逻辑
│   ├── core/                  # 核心配置
│   ├── fault/                 # 错误码与工具
│   ├── memory/                # PMR 内存管理
│   ├── multiplex/             # 多路复用模块
│   ├── protocol/              # 协议实现
│   ├── resolve/               # DNS 解析与路由
│   ├── rule/                  # 规则引擎
│   ├── trace/                 # 日志系统
│   ├── transformer/           # 数据转换
│   └── channel/               # 传输层
├── src/                       # 实现与入口
├── test/                      # 测试
├── docs/                      # 文档
│   ├── tutorial/              # 用户指南
│   ├── manual/                # 开发者指南
│   ├── protocols/             # 协议文档
│   ├── reference/             # 参考资料
│   ├── examples/              # 示例配置
│   └── project/               # 项目管理
└── CMakeLists.txt
```


## 已知限制

- SOCKS5 仅支持无认证模式，密码验证待实现
- 反向代理路由表暂不支持热更新

## 文档

详细文档位于 `docs/` 目录：

### 教程

- [快速开始](docs/tutorial/getting-started.md) - 5 分钟快速上手
- [配置详解](docs/tutorial/configuration.md) - 配置参数说明与性能调优
- [故障排除](docs/tutorial/troubleshooting.md) - 常见问题排查与解决方案
- [常见问题](docs/tutorial/faq.md) - FAQ 问答集

### 技术手册

- [架构设计](docs/manual/architecture.md) - 架构能力分析、时序链、关键实现细节
- [模块设计](docs/manual/modules.md) - front、worker、session 等模块详解
- [多路复用](docs/manual/multiplex.md) - smux 协议实现、流管理、帧格式
- [运行时流程](docs/manual/runtime.md) - Session 创建、协议检测、隧道转发流程
- [路由与分发](docs/manual/routing.md) - Registry 单例模式、Handler 工厂
- [API 参考](docs/manual/api.md) - 公开 API 入口与头文件组织

### 协议文档

- [HTTP 协议](docs/protocols/http.md) - HTTP 请求调用流程
- [SOCKS5 协议](docs/protocols/socks5.md) - SOCKS5 握手与地址解析
- [Trojan 协议](docs/protocols/trojan.md) - Trojan SSL 握手与凭据验证
- [TLS 协议](docs/protocols/tls.md) - TLS 握手（整合在 Trojan 中）

### 参考资料

- [配置结构体](docs/reference/config-structure.md) - config、server_context 等结构体详解
- [上下文结构体](docs/reference/context.md) - session_context、worker_context 详解
- [依赖关系](docs/reference/dependencies.md) - 目录依赖图与运行时调用图

### 项目管理

- [开发进度](docs/project/progress.md) - 项目概况、版本状态、路线图

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

<div align="center">

**Prism** - 为现代网络而生的高性能协程代理引擎

</div>
