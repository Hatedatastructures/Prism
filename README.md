# ForwardEngine

<div align="center">

![C++23](https://img.shields.io/badge/Standard-C%2B%2B23-blue.svg?logo=c%2B%2B)
![Platform](https://img.shields.io/badge/Platform-Windows%2011%20|%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Build](https://img.shields.io/badge/Build-CMake-orange)
![Architecture](https://img.shields.io/badge/Architecture-Coroutine%20%2B%20PMR-success)

**个人独立开发的现代高性能协程代理引擎**

</div>

## 项目简介

ForwardEngine 是一个基于 **C++23 + Boost.Asio** 的高性能代理引擎，采用纯协程架构（`net::awaitable`）与 PMR 内存模型，专为低延迟、高并发的网络转发场景设计。

当前支持 HTTP/HTTPS、SOCKS5（TCP + UDP）协议，适用于代理网关、网络中间件和边缘转发节点。

## 核心亮点

- **纯协程架构**：核心链路全程使用 `co_await`，通过线程封闭实现无锁并发
- **PMR 内存策略**：全局内存池 + 帧分配器，热路径零堆分配
- **智能连接池**：TCP 连接复用，支持僵尸检测、空闲超时、端点缓存上限
- **动态协议识别**：首包嗅探 HTTP / SOCKS5 / TLS，自动分流处理
- **负载均衡与反压**：基于评分的 Worker 选择，过载检测与滞后机制
- **clash客户端**： 支持 clash 客户端配置，自动切换路由

## 协议支持

- **HTTP/HTTPS** - HTTP 正向代理与 `CONNECT` 隧道
- **SOCKS5** - RFC 1928，支持 TCP CONNECT 与 UDP ASSOCIATE
- **TLS** - 服务端 TLS 终止，解密后按 HTTP 处理
- **Trojan 协议** - 已实现但未接入运行链，待后续实现

## 架构概览

```txt
接入层
  listener -> balancer -> worker
                              |
                              v
执行层
  session -> handler -> router -> source(pool)
                |
                v
协议层
  http / socks5 / tls
```

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

详细配置说明请参阅 [config.md](docs/agent/config.md)。

## 目录结构

```txt
ForwardEngine/
├── include/forward-engine/    # 核心库头文件
│   ├── abnormal/              # 异常定义
│   ├── adapter/               # 配置加载
│   ├── agent/                 # 代理核心逻辑
│   ├── core/                  # 核心配置
│   ├── gist/                  # 错误码与工具
│   ├── memory/                # PMR 内存管理
│   ├── protocol/              # 协议实现
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
- Trojan 协议已实现但未接入运行链

## 文档

详细文档位于 `docs/` 目录：

- [技术概述与使用指南](docs/premise.md)
- [架构能力分析](docs/agent/architecture.md)
- [模块设计](docs/agent/modules.md)
- [运行时流程](docs/agent/runtime.md)
- [开发进度](docs/progress.md)

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

<div align="center">

**ForwardEngine** - 为现代网络而生的高性能协程代理引擎

</div>
