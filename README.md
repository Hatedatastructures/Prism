# ForwardEngine

<div align="center">

![C++23](https://img.shields.io/badge/Standard-C%2B%2B23-blue.svg?logo=c%2B%2B)
![Platform](https://img.shields.io/badge/Platform-Windows%2011%20|%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Build](https://img.shields.io/badge/Build-CMake-orange)
![Architecture](https://img.shields.io/badge/Architecture-Coroutine%20%2B%20PMR-success)

</div>

## 概述

ForwardEngine 是一个基于 Modern C++（C++23）与 Boost.Asio 的高性能代理引擎，采用纯协程架构设计。核心链路使用 `net::awaitable` 协程组织，配合 PMR（Polymorphic Memory Resource）内存管理，提供低延迟、高并发的网络转发能力。项目采用分层流式架构，支持 HTTP、SOCKS5、Trojan 等主流代理协议，适用于代理网关、网络中间件等场景。

## 核心特性

### 协议支持

| 协议 | 描述 | 认证方式 |
|------|------|---------|
| **HTTP/HTTPS** | 完整支持 HTTP 正向代理与 HTTPS `CONNECT` 隧道 | 无 |
| **SOCKS5** | 标准 SOCKS5 协议（RFC 1928），支持 IPv4/IPv6/域名 | 无认证 |
| **Trojan** | Trojan 协议（TLS + 类 HTTP 伪装） | 密码验证 + 流量统计 |

### 技术架构

- **纯协程驱动**：基于 Boost.Asio 的 `net::awaitable` 协程，通过线程封闭实现无锁高并发
- **PMR 内存管理**：统一 PMR 策略，支持线程本地内存池与帧分配器，热路径零分配
- **连接复用**：智能 TCP 连接池，支持僵尸检测、空闲超时与上限控制
- **协议自动识别**：基于首字节的动态协议检测，自动适配 HTTP/SOCKS5/Trojan
- **分层流式架构**：`transmission` 抽象接口 → `reliable` 传输实现 → 协议装饰器
- **错误码体系**：基于 `gist::code` 的轻量级错误码，热路径无异常

### 开发体验

- **Modern C++**：全面使用 C++23 特性
- **模块化设计**：清晰的接口边界，协议层/传输层/业务层分离
- **完整文档**：协议处理流程文档，Doxygen 注释规范
- **生产级日志**：基于 spdlog 的异步日志系统，支持文件轮转与级别控制

## 架构概览

```txt
                                ForwardEngine 架构
────────────────────────────────────────────────────────────────────────────
Agent 业务层: worker → session → handler → validator → distributor
                                        ↓
              ┌─────────────────────────┴─────────────────────────┐
              ↓                                                   ↓
Protocol 协议层: http, socks5, trojan      Transport 传输层: transmission, reliable, source
              ↓                                                   ↓
              └─────────────────────────┬─────────────────────────┘
                                        ↓
Infrastructure 基础设施: gist (错误码) → memory (内存封装) → trace (日志)
```

### 数据流

```txt
客户端 → worker → session → [协议识别] → handler → distributor
                                                      ↓
                                               连接池 (source)
                                                      ↓
                                               tunnel 双向转发
                                                      ↓
                                                  上游服务器
```

## 快速开始

### 环境要求

- **编译器**：支持 C++23 的编译器（GCC 13+、Clang 16+、MSVC 2022+）
- **构建系统**：CMake 3.15+
- **依赖库**：
  - Boost 1.82+（system）
  - OpenSSL 3.0+（CMake 依赖）
  - BoringSSL
  - spdlog 1.12+
  - glaze 2.0+

### Windows 构建（MinGW）

依赖默认从 `c:/bin` 查找，BoringSSL 路径通过 `BORINGSSL_ROOT` 指定：

```bat
# 配置项目
cmake -S . -B build_release -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo

# 编译
cmake --build build_release -j

# 运行测试
ctest --test-dir build_release --output-on-failure
```

### Linux/macOS 构建

```bash
cmake -S . -B build_release -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build_release -j
ctest --test-dir build_release --output-on-failure
```

### 运行代理服务器

程序运行时读取 `src/configuration.json`，默认监听端口 `8081`：

```bat
build_release/src/Forward.exe
```

### 验证代理功能

```bat
# HTTP/HTTPS 代理
curl -v -x http://127.0.0.1:8081 http://www.baidu.com
curl -v -x http://127.0.0.1:8081 https://www.baidu.com

# SOCKS5 代理
curl -v -x socks5://127.0.0.1:8081 http://www.baidu.com
```

## 配置说明

配置文件位于 `src/configuration.json`：

```json
{
  "agent": {
    "positive": {
      "host": "localhost",
      "port": 8080
    },
    "camouflage": "/api/notification/v1/stream?id=abcd-1234", 
    "limit": {
      "concurrences": 20,
      "blacklist": true
    },
    "addressable": {
      "host": "localhost",
      "port": 8081
    },
    "authentication": {
      "credentials": [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      ]
    },
    "certificate": {
      "key": "./key.pem",
      "cert": "./cert.pem"
    },
    "pool": {
      "max_cache_per_endpoint": 32,
      "max_idle_seconds": 60
    }
  },
  "trace": {
    "enable_console": true,
    "enable_file": true,
    "log_level": "debug",
    "pattern": "[%Y-%m-%d %H:%M:%S.%e][%l] %v",
    "trace_name": "forward_engine",
    "path_name": "./logs"
  }
}
```

### 配置项说明

| 字段 | 描述 | 默认值 |
|------|------|--------|
| `positive` | 上游代理端点（可选，用于回退） | - |
| `addressable` | 监听端点 | `localhost:8081` |
| `camouflage` | Trojan 伪装路径 | - |
| `limit.concurrences` | 最大并发连接数 | 20 |
| `limit.blacklist` | 是否启用黑名单 | `true` |
| `authentication.credentials` | Trojan 密码列表（56字符十六进制） | - |
| `certificate` | TLS 证书配置 | `./cert.pem`, `./key.pem` |
| `pool.max_cache_per_endpoint` | 单端点最大缓存连接数 | 32 |
| `pool.max_idle_seconds` | 空闲连接最大存活时间 | 60 |
| `trace.log_level` | 日志级别 | `debug` |
| `trace.max_size` | 单日志文件最大大小 | 64MB |
| `trace.max_files` | 最大日志文件数 | 8 |

## 目录结构

```txt
ForwardEngine/
├── include/forward-engine/    # 核心库头文件
│   ├── abnormal/              # 异常定义
│   ├── agent/                 # 代理核心逻辑
│   ├── gist/                  # 错误码与工具
│   ├── memory/                # PMR 内存管理
│   ├── protocol/              # 协议实现 (http/socks5/trojan)
│   ├── rule/                  # 规则引擎
│   ├── trace/                 # 日志系统
│   ├── transformer/           # 数据转换
│   └── transport/             # 传输层
├── src/                       # 实现与入口
├── test/                      # 测试
├── docs/                      # 文档
└── CMakeLists.txt
```

## 测试

### 测试套件

| 测试 | 描述 |
|------|------|
| `session_test` | 会话生命周期、双向转发、关闭传播 |
| `connection_test` | 连接池复用、正向代理回退 |
| `integration_test` | 全双工转发、传输层工厂 |
| `socks5_test` | SOCKS5 握手与数据回显 |
| `trojan_test` | Trojan 握手与密码验证 |
| `memory_bench` | 内存分配性能基准 |
| `pool_contention_stress` | 内存池竞争压力测试 |

### 运行测试

```bash
# 运行所有测试
ctest --test-dir build_release --output-on-failure

# 运行单个测试
./build_release/test/session_test
./build_release/test/connection_test
```

## 性能特征

### 设计优化

1. **热路径零分配**：协议处理器使用帧分配器，`async_read/write` 回调中严禁堆分配
2. **无锁并发**：通过线程封闭实现，连接池线程隔离
3. **去虚拟化**：所有具体实现类标记为 `final`
4. **零拷贝转发**：隧道阶段使用 `boost::asio::buffer` 引用传递
5. **连接复用**：TCP 连接池减少握手开销

## 文档

详细文档位于 `docs/` 目录：

- [技术概述与使用指南](docs/premise.md) - 快速入门、配置详解、故障排除
- [开发进度](docs/progress.md) - 模块完成度、路线图
- [协议处理流程](docs/Process/) - HTTP、SOCKS5、Trojan 详细调用链

## 已知限制

- UDP 转发支持尚未实现（`transport::unreliable` 接口已定义）
- SOCKS5 仅支持无认证模式
- 反向代理路由表需手动配置，暂不支持热更新

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

<div align="center">

**ForwardEngine** - 为现代网络而生的高性能协程代理引擎

</div>
