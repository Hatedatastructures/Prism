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

它采用了现代 C++ 的最新特性——**纯协程架构**与**PMR 内存模型**，专为低延迟、高并发的网络转发场景打造。无论是作为代理网关、网络中间件，还是转发节点，Prism 都能提供极致的转发性能。

> **设计思路**：用协程替代回调，以同步的写法实现异步的并发；用内存池消除堆分配，用零拷贝减少数据搬移。

## 核心亮点

- **零分配热路径**：全局 PMR 内存池 + 分配器，请求处理全程零 `malloc`，消除 GC 停顿与内存碎片
- **纯协程架构**：C++23 `co_await` 全链路异步，一个连接一个协程，同步代码的 readability + 异步的性能，回调地狱不存在
- **智能协议分流**：首包嗅探自动识别 HTTP/SOCKS5/TLS，TLS 透明剥离后二次探测内层协议，一个端口搞定所有协议
- **Happy Eyeballs**：DNS 多服务器并发竞速 + 多 IP 连接竞速，首次连接延迟降到理论最低
- **多路复用**：单条 TLS 连接承载上百个子流，smux/yamux 双协议栈，握手开销降低 10x+，流量特征更难分析
- **每线程独立**：Worker 线程各持独立 `io_context`，无锁无竞争，吞吐量随 CPU 核心数线性扩展
- **凭据级管控**：SHA224 哈希验证 + 每用户并发连接数硬限制，多租户安全隔离

## 快速开始

**环境要求**：GCC 13+ / CMake 3.23+，无需安装任何第三方库只需标准库，所有依赖自动拉取。

```bash
# 克隆仓库
git clone https://github.com/Hatedatastructures/Prism.git
cd Prism

# 配置 (Release)
cmake -B build_release -DCMAKE_BUILD_TYPE=Release

# 编译 (首次会自动下载 Boost/BoringSSL/spdlog/glaze，约 10 分钟)
cmake --build build_release --config Release

# 启动代理服务器（默认监听 0.0.0.0:8081）
./build_release/src/Prism.exe

# 运行测试
ctest --test-dir build_release --output-on-failure
```

客户端连接示例（Clash 配置）：

```yaml
proxies:
  - name: "Prism"
    type: trojan
    server: 192.168.x.x # 代理服务器 IP 
    port: 8081
    password: "prism"
    udp: true
    skip-cert-verify: true
```
详细配置信息参考 [clash 配置](docs/examples/clash/reference.yaml)

## 协议支持

| 协议 | 状态 | 说明 |
|------|------|------|
| **HTTP/HTTPS** | 已完成 | 正向代理 + `CONNECT` 隧道 + Basic 认证，明文和 TLS 两种模式 |
| **SOCKS5** | 已完成 | RFC 1928 完整实现，TCP CONNECT + UDP ASSOCIATE |
| **Trojan** | 已完成 | TLS + SHA224 凭据验证 + mux 支持 |
| **TLS 透明剥离** | 已完成 | Session 层统一 TLS 握手，探测内层协议后分发，Handler 无感 TLS |
| **VLESS** | 已完成 | 轻量 TLS 内层协议，UUID 认证 + mux 支持 |
| **Shadowsocks 2022** | 已完成 | SIP022 AEAD 加密 (AES-128/256-GCM + ChaCha20-Poly1305)，BLAKE3 密钥派生，TCP/UDP 中继，抗重放 |
| **Reality** | 已完成 | TLS 指纹伪装，X25519 密钥交换，VLESS 内层协议 |
| **Hysteria2** | 计划中 | QUIC 传输，UDP 优先 |

## 多路复用

Prism 实现了多路复用协议栈，在单条 TCP/TLS 连接上承载多个独立子流，降低握手开销并增加流量特征混淆。

| 协议 | 状态 | 说明 |
|------|------|------|
| **Smux v1** | 已完成 | 兼容 Mihomo/xtaci/smux v1，TCP + UDP |
| **YAMux** | 已完成 | Hashicorp yamux 兼容，窗口流量控制 |
| **Smux v2** | 计划中 | UDP 流控命令，滑动窗口 |
| **H2Mux** | 计划中 | HTTP/2 多路复用 |

## 性能
> 当前还未测试性能，后续会补上详细信息

## 开发路线

- [x] 协议认证
    - [x] Trojan 凭据认证 (SHA224)
    - [x] HTTP 代理认证 (Basic)
    - [x] SOCKS5 用户名/密码认证 (RFC 1929)
    - [x] VLESS UUID 认证
    - [x] Shadowsocks 2022 PSK 认证 (BLAKE3)
- [x] mux 多路复用
    - [x] smux v1
    - [ ] smux v2
    - [x] yamux
    - [ ] h2mux
- [x] HTTPS 代理 (Session 层 TLS 剥离 + 二次协议探测)
- [x] Happy Eyeballs 连接竞速 (RFC 8305)
- [x] Reality (X25519 密钥交换 + TLS 指纹伪装)
- [x] Shadowsocks 2022 (AES-GCM + ChaCha20-Poly1305, TCP/UDP)
- [ ] QUIC
- [ ] WebSocket
- [ ] 优化调用延迟和性能，尽量保持零拷贝和可读性高

## 依赖项

所有依赖均通过 **CMake FetchContent** 自动拉取(比较慢，10分钟左右)，无需手动安装本地库。首次构建自动下载，后续复用缓存。

| 依赖 | 版本 | 说明 |
|------|------|------|
| **C++ 编译器** | C++23 | GCC 13+ / MinGW |
| **CMake** | 3.23+ | 构建系统 |
| **Boost.Asio** | 1.89.0 | 协程支持（header-only，自动下载） |
| **BoringSSL** | master | TLS 实现（OpenSSL API 兼容，自动下载编译） |
| **spdlog** | 1.17.0 | 日志库（自动下载） |
| **glaze** | 6.5.1 | JSON 序列化（header-only，自动下载） |
| **Google Benchmark** | v1.9.5 | 性能测试（自动拉取） |

> **编译工具链**：CMake + MinGW + VS Code，Windows 上开箱即用。Linux 支持计划中。

## 客户端兼容

> 对接 **[Mihomo](https://github.com/MetaCubeX/mihomo/tree/Meta)** API，兼容所有基于 Mihomo 内核的客户端，如 **[clash-verge-rev](https://github.com/clash-verge-rev/clash-verge-rev)**

## 目录结构

```txt
Prism/
├── include/prism/             # 核心库头文件
│   ├── agent/                 # 代理核心逻辑
│   ├── channel/               # 传输层
│   ├── crypto/                # 加密工具
│   ├── exception/             # 异常定义
│   ├── fault/                 # 错误码与工具
│   ├── loader/                # 配置加载
│   ├── memory/                # PMR 内存管理
│   ├── multiplex/             # 多路复用模块
│   ├── pipeline/              # 协议处理管道
│   ├── protocol/              # 协议实现
│   ├── resolve/               # DNS 解析与路由
│   ├── trace/                 # 日志系统
│   └── transformer/           # 数据转换
├── src/                       # 实现与入口
├── tests/                     # 测试
├── benchmarks/                # 基准测试
├── stresses/                  # 压力测试
├── scripts/                   # 工具脚本
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

- SOCKS5 认证模式默认关闭，可通过配置 `socks5.enable_auth` 开启
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
- [多路复用](docs/multiplex/overview.md) - smux/yamux 协议实现、流管理、帧格式
- [运行时流程](docs/manual/runtime.md) - Session 创建、协议检测、隧道转发流程
- [路由与分发](docs/manual/routing.md) - Registry 单例模式、Handler 工厂
- [API 参考](docs/manual/api.md) - 公开 API 入口与头文件组织

### 协议文档

- [HTTP 协议](docs/protocols/http.md) - HTTP 请求调用流程
- [SOCKS5 协议](docs/protocols/socks5.md) - SOCKS5 握手与地址解析
- [Trojan 协议](docs/protocols/trojan.md) - Trojan SSL 握手与凭据验证
- [VLESS 协议](docs/protocols/vless.md) - VLESS 二进制头部与 UUID 认证
- [Shadowsocks 2022](docs/protocols/shadowsocks.md) - SS2022 AEAD 加密与 BLAKE3 密钥派生
- [TLS 协议](docs/protocols/tls.md) - Session 层 TLS 剥离与内层协议探测
- [Reality 协议](docs/protocols/reality.md) - TLS 指纹伪装与 X25519 密钥交换

### 参考资料

- [配置与上下文结构体](docs/reference/config-structure.md) - config、server_context、worker_context、session_context 详解
- [依赖关系](docs/reference/dependencies.md) - 目录依赖图与运行时调用图

### 项目管理

- [开发进度](docs/project/progress.md) - 项目概况、版本状态、路线图

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

<div align="center">

**Prism** - 为现代网络而生的高性能协程代理引擎

</div>
