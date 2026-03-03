# ForwardEngine

<div align="center">

![C++23](https://img.shields.io/badge/Standard-C%2B%2B23-blue.svg?logo=c%2B%2B)
![Platform](https://img.shields.io/badge/Platform-Windows%2011%20|%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Build](https://img.shields.io/badge/Build-CMake-orange)
![Architecture](https://img.shields.io/badge/Architecture-Coroutine%20%2B%20PMR-success)

**为现代网络转发场景设计的高性能协程代理引擎**

</div>

## 项目简介

ForwardEngine 基于 **C++23 + Boost.Asio**，采用纯协程（`net::awaitable`）与 PMR 内存模型，面向低延迟、高并发代理转发场景。  
当前支持 HTTP/HTTPS、SOCKS5、Trojan，适用于代理网关、网络中间件和边缘转发节点。

## 核心亮点

- **纯协程架构**：核心链路使用 `co_await`，通过线程封闭实现无锁并发
- **PMR 内存策略**：线程本地池 + 帧分配器，减少热路径分配抖动
- **智能连接复用**：内置 TCP 连接池，支持空闲回收和端点缓存上限
- **动态协议识别**：首包识别 HTTP / SOCKS5 / Trojan，自动分流处理
- **可观测负载分配**：单监听器 + 分流器（粘性哈希、过载兜底、背压信号）

## 协议支持

| 协议 | 描述 | 认证 |
|------|------|------|
| HTTP/HTTPS | 支持 HTTP 正向代理与 HTTPS `CONNECT` 隧道 | 无 |
| SOCKS5 | RFC 1928，支持 IPv4/IPv6/域名 | 当前无认证 |
| Trojan | TLS + HTTP 伪装链路 | 凭据验证 |

## 架构概览

```txt
接入层
  listener (单监听器) -> distribute (分流决策)
                              |
                              v
执行层
  worker -> session -> handler -> distributor -> source(pool)
                              |
                              v
协议与基础设施
  protocol(http/socks5/trojan) + transport + memory + trace + gist
```

### 连接数据流

```txt
client
  -> listener accept
  -> distribute select(worker)
  -> worker dispatch_socket
  -> session detect protocol
  -> handler process
  -> distributor route
  -> source(pool) connect/reuse
  -> tunnel full-duplex forward
```

## 快速开始

### 环境要求

- 编译器：GCC 13+ / Clang 16+ / MSVC 2022+（支持 C++23）
- 构建系统：CMake 3.15+
- 依赖：Boost(system)、BoringSSL、spdlog、glaze

### Windows（MinGW）

项目默认从 `C:/bin` 查找依赖，BoringSSL 根目录由 `BORINGSSL_ROOT` 指定。

```bat
cmake -S . -B build_release -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build_release -j
ctest --test-dir build_release --output-on-failure
```

### Linux/macOS

```bash
cmake -S . -B build_release -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build_release -j
ctest --test-dir build_release --output-on-failure
```

### 启动与验证

程序默认读取 `src/configuration.json`，监听 `8081`：

```bat
build_release/src/Forward.exe
```

验证代理可用性：

```bat
curl -v -x http://127.0.0.1:8081 http://www.baidu.com
curl -v -x http://127.0.0.1:8081 https://www.baidu.com
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
