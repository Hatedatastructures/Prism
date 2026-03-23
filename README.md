# ForwardEngine

<div align="center">

![C++23](https://img.shields.io/badge/Standard-C%2B%2B23-blue.svg?logo=c%2B%2B)
![Platform](https://img.shields.io/badge/Platform-Windows%2011%20|%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Build](https://img.shields.io/badge/Build-CMake-orange)
![Architecture](https://img.shields.io/badge/Architecture-Coroutine%20%2B%20PMR-success)

**个人独立开发的现代高性能协程代理引擎**

</div>

## 📖 项目简介

ForwardEngine 是一款基于 **C++23 协程** 与 **Boost.Asio** 构建的高性能代理引擎。

它采用了现代 C++ 的最新特性——**纯协程架构**与**PMR 内存模型**，专为低延迟、高并发的网络转发场景打造。无论是作为代理网关、网络中间件，还是边缘转发节点，ForwardEngine 都能提供极致的性能与优雅的代码体验。

> 💡 **设计哲学**：用协程消灭回调地狱，用内存池消除堆分配，用零拷贝减少数据搬移。

## ✨ 核心亮点

| 特性 | 说明 |
|------|------|
| 🚀 **纯协程架构** | 核心链路全程 `co_await`，无回调地狱，代码可读性极高 |
| 💾 **PMR 内存策略** | 全局内存池 + 帧分配器，热路径零堆分配 |
| 🔌 **智能连接池** | TCP 连接复用，僵尸检测、空闲超时、端点缓存上限 |
| 🔀 **透明隧道转发** | 握手后双向透传 TCP 字节流，零协议感知开销 |
| 🔍 **动态协议识别** | 首包嗅探 HTTP/SOCKS5/TLS，自动分流处理 |
| 🌐 **内置并发 DNS 解析** | 自研 DNS 解析器，多服务器并发查询，取最快响应；支持缓存、负面缓存、IPv6 过滤 |
| ⚖️ **负载均衡与反压** | 基于评分的 Worker 选择，过载检测与滞后机制 |
| 🎯 **Clash 兼容** | 支持 Clash 客户端配置，自动切换路由 |
| 🎭 **TLS 流量伪装** | 可自定义伪装路径，将 Trojan 流量伪装为普通 HTTPS 请求，降低被识别风险 |
| 🔐 **凭据认证** | SHA224 哈希验证 + 每用户连接数限制 |

## 📦 协议支持

| 协议 | 状态 | 说明 |
|------|:----:|------|
| HTTP/HTTPS | ✅ | HTTP 正向代理与 `CONNECT` 隧道 |
| SOCKS5 | ✅ | RFC 1928，TCP CONNECT + UDP ASSOCIATE |
| Trojan | ✅ | Trojan over TLS，TLS 握手 + 凭据验证 + 流量转发 |

## 快速开始

### 环境要求

- 编译器：GCC 13+ / Clang 16+ / MSVC 2022+（支持 C++23）
- 构建系统：CMake 3.15+
- 依赖：Boost(system)、BoringSSL、spdlog、glaze

### 构建

**Windows（MinGW）**

```bat
cmake -S . -B build_release -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build_release -j
```

**Linux/macOS**

```bash
cmake -S . -B build_release -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build_release -j
```

### 启动与验证

程序默认读取 `src/configuration.json`，监听 `8081` 端口：

```bat
build_release/src/Forward.exe
```

验证代理功能：

```bat
curl -v -x http://127.0.0.1:8081 http://www.baidu.com
curl -v -x http://127.0.0.1:8081 https://www.baidu.com
curl -v -x socks5://127.0.0.1:8081 http://www.baidu.com
```

## 配置说明

配置文件位于 `src/configuration.json`，核心配置项：

| 字段 | 描述 | 默认值 |
|------|------|--------|
| `addressable` | 监听端点 | `localhost:8081` |
| `positive` | 后端服务或者上游代理（可选） | - |
| `certificate` | TLS 证书配置 | `./cert.pem`, `./key.pem` |
| `pool.max_cache_per_endpoint` | 单端点最大缓存连接数 | 32 |
| `pool.max_idle_seconds` | 空闲连接最大存活时间 | 60 |
| `authentication.credentials` | 凭据列表（SHA224 哈希） | - |
| `camouflage` | TLS 伪装路径 | - |
| `dns.servers` | DNS 服务器列表（支持并发查询） | `8.8.8.8`, `1.1.1.1` |
| `dns.mode` | DNS 解析策略（`first` 取最快响应） | `first` |
| `dns.cache_enabled` | DNS 缓存开关 | `true` |
| `dns.serve_stale` | 缓存过期后是否返回旧结果 | `true` |
| `disable_ipv6` | 禁用 IPv6 连接 | `false` |

详细配置说明请参阅 [配置详解](docs/tutorial/configuration.md)。

## 目录结构

```txt
ForwardEngine/
├── include/forward-engine/    # 核心库头文件
│   ├── exception/              # 异常定义
│   ├── loader/                # 配置加载
│   ├── agent/                 # 代理核心逻辑
│   ├── core/                  # 核心配置
│   ├── fault/                 # 错误码与工具
│   ├── memory/                # PMR 内存管理
│   ├── protocol/              # 协议实现
│   ├── rule/                  # 规则引擎
│   ├── trace/                 # 日志系统
│   ├── transformer/           # 数据转换
│   └── channel/               # 传输层
├── src/                       # 实现与入口
├── test/                      # 测试
├── docs/                      # 文档
│   ├── tutorial/            # 用户指南
│   ├── manual/                # 开发者指南
│   ├── protocols/             # 协议文档
│   ├── reference/             # 参考资料
│   ├── examples/              # 示例配置
│   └── project/               # 项目管理
└── CMakeLists.txt
```

## 测试

```bash
# 运行所有测试
ctest --test-dir build_release --output-on-failure

# 关键测试用例
./build_release/test/session_test      # 会话生命周期
./build_release/test/socks5_test       # SOCKS5 协议
./build_release/test/connection_test   # 连接池复用
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

**ForwardEngine** - 为现代网络而生的高性能协程代理引擎

</div>
