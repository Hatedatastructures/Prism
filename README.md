# ForwardEngine

<div align="center">

![C++23](https://img.shields.io/badge/Standard-C%2B%2B23-blue.svg?logo=c%2B%2B)
![Platform](https://img.shields.io/badge/Platform-Windows%2011%20|%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Build](https://img.shields.io/badge/Build-CMake-orange)
![Architecture](https://img.shields.io/badge/Architecture-Coroutine%20%2B%20PMR-success)

</div>

## 概述

ForwardEngine 是一个基于 Modern C++（C++23）与 Boost.Asio 的高性能代理引擎，采用纯协程架构设计。核心链路使用 `net::awaitable` 协程组织，配合 PMR（Polymorphic Memory Resource）内存管理，提供低延迟、高并发的网络转发能力。项目采用分层流式架构，支持多种代理协议，适用于代理网关、网络中间件和隐私保护等场景。

## 核心特性

### 协议支持
- **HTTP/HTTPS 代理**：完整支持 HTTP 正向代理与 HTTPS `CONNECT` 隧道
- **SOCKS5 代理**：标准 SOCKS5 协议（无认证/TCP Connect），支持 IPv4/IPv6/域名
- **Trojan 代理**：Trojan 协议（TLS + 类 HTTP 伪装），支持密码验证

### 技术架构
- **纯协程驱动**：基于 Boost.Asio 的 `net::awaitable` 协程，无回调地狱，通过线程封闭实现无锁高并发
- **PMR 内存管理**：统一 PMR 策略，支持线程本地内存池，减少堆分配碎片
- **连接复用**：智能 TCP 连接池，支持僵尸检测、空闲超时与上限控制
- **协议识别**：动态协议检测（peek-based），自动适配 HTTP/SOCKS5/Trojan
- **分层流式架构**：核心抽象接口 `core::transmission` -> 传输实现 `transport::reliable` -> 协议装饰器 `protocol::trojan::stream`
- **双向转发**：优化的隧道转发算法，支持优雅退出与资源及时回收
- **错误处理**：基于 `std::error_code` 的错误码体系，提供标准化的错误分类和追踪

### 开发体验
- **现代 C++**：全面使用 C++23 特性（`std::expected`、概念约束、协程等）
- **模块化设计**：清晰的接口边界，易于扩展新协议
- **Doxygen 文档**：严格的注释规范，完整的 API 文档
- **生产级日志**：基于 spdlog 的异步日志系统，支持文件轮转与级别控制

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
依赖默认从 `c:/bin` 查找（根目录 `CMakeLists.txt` 已配置路径），BoringSSL 路径在 `src/CMakeLists.txt` 里通过 `BORINGSSL_ROOT` 指定：

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
# 配置项目
cmake -S . -B build_release -DCMAKE_BUILD_TYPE=RelWithDebInfo

# 编译
cmake --build build_release -j

# 运行测试
ctest --test-dir build_release --output-on-failure
```

### 运行代理服务器
程序运行时会读取 `src/configuration.json`，默认监听端口为 `8081`：

```bat
build_release/src/Forward.exe
```

### 验证代理功能
使用 curl 测试代理功能：

```bat
# HTTP/HTTPS 代理
curl -v -L -x http://127.0.0.1:8081 http://www.baidu.com
curl -v -L -x http://127.0.0.1:8081 https://www.baidu.com

# SOCKS5 代理
curl -v -L -x socks5://127.0.0.1:8081 http://www.baidu.com

# 使用环境变量
set HTTP_PROXY=http://127.0.0.1:8081
curl -v http://www.baidu.com
```

## 配置说明

配置文件位于 `src/configuration.json`，主要配置项：

### 代理服务配置
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
    "clash": false
  }
}
```

配置项说明：
- `positive`：正向代理端点，定义上游代理服务器（可选）
- `addressable`：监听端点，定义服务监听的地址和端口
- `limit`：连接限制配置，控制并发数和黑名单
- `certificate`：TLS 证书配置，用于 HTTPS 和 TLS 协议
- `authentication`：身份认证配置，管理用户凭据和连接限制
- `camouflage`：伪装路径，用于抗探测
- `reverse_map`：反向代理路由表，映射主机名到后端端点
- `pool`：连接池配置，控制连接缓存和空闲超时
- `clash`：Clash 兼容模式，启用后支持 Clash 客户端特性

### 日志配置
```json
{
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

可选字段与默认值（见 `include/forward-engine/trace/config.hpp`）：
- `file_name`：`forward.log`
- `max_size`：64MB
- `max_files`：8
- `queue_size`：8192
- `thread_count`：1

### 连接池参数
连接池配置包含在 `agent` 配置中：
- `max_cache_per_endpoint`：32（单个目标端点最大缓存连接数）
- `max_idle_seconds`：60（空闲连接最大存活时间）

## 目录结构

```
ForwardEngine/
├── docs/                            # 文档
├── include/                         # 公共头文件
│   └── forward-engine/              # 核心库头文件
│       ├── abnormal/                # 异常定义（基于 std::error_code）
│       ├── agent/                   # 代理核心逻辑
│       ├── core/                    # 核心配置与管理
│       ├── gist/                    # 错误码与工具定义
│       ├── memory/                  # 内存管理（PMR）
│       ├── protocol/                # 协议实现
│       │   ├── http/                # HTTP 协议
│       │   ├── socks5/              # SOCKS5 协议
│       │   └── trojan/              # Trojan 协议
│       ├── rule/                    # 黑名单规则
│       ├── trace/                   # 日志系统
│       ├── transformer/             # 数据转换
│       └── transport/               # 传输层封装
├── src/                             # 实现与入口
│   ├── forward-engine/              # 核心库实现
│   ├── configuration.json           # 配置文件
│   └── main.cpp                     # 程序入口
├── test/                            # 测试与基准
└── CMakeLists.txt                   # 构建配置
```

## 性能特征

### 设计优化
1. **零拷贝转发**：隧道阶段使用 `boost::asio::buffer` 引用传递，避免数据复制
2. **协程栈复用**：`net::awaitable` 协程栈空间复用，减少内存分配
3. **连接复用**：TCP 连接池减少握手开销，提高响应速度
4. **内存池化**：PMR 内存管理减少堆分配碎片
5. **无锁并发**：通过线程封闭实现无锁高并发，避免互斥锁开销
6. **去虚拟化**：所有具体实现类标记为 `final`，允许编译器内联虚函数
7. **热路径优化**：热路径禁止堆分配，协议处理器使用单例模式

### 性能军规
- 严禁热路径堆分配：在 async_read/write 回调及协程切换中，严禁 new/malloc
- 严禁原子操作滥用：禁止在热路径创建临时 std::shared_ptr
- 严禁阻塞操作：IO 线程严禁调用 sleep、文件 IO 或锁等待
- 分配器透传：异步 Wrapper 必须实现 get_allocator() 钩子
- 原地修改：加密/解密必须在原 Buffer 上进行
- 去虚拟化：所有具体实现类必须标记为 final

## 文档

详细的用户指南和开发文档位于 `docs/` 目录：

- [技术概述与使用指南](docs/premise.md) - 包含快速入门、用户指南、常见问题和技术概述
- [开发进度](docs/progress.md) - 项目开发状态、贡献指南和路线图
- [协议处理流程](docs/Process/) - HTTP、SOCKS5、Trojan 协议处理详细文档

## 已知限制

### 当前版本限制
- UDP 转发支持尚未实现（`transport::unreliable` 接口已定义，实现待完成）
- 反向代理路由表配置需手动更新
- 跨线程连接池共享策略仍在完善中

### 平台兼容性
- 已在 Windows 11 + MinGW 上全面测试
- Linux/macOS 平台需要适配部分路径配置
- ARM 架构尚未验证

## 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

<div align="center">

**ForwardEngine** - 为现代网络而生的高性能协程代理引擎

</div>
