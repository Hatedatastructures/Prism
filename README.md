# ForwardEngine

<div align="center">

![C++23](https://img.shields.io/badge/Standard-C%2B%2B23-blue.svg?logo=c%2B%2B)
![Platform](https://img.shields.io/badge/Platform-Windows%2011-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Build](https://img.shields.io/badge/Build-CMake-orange)

</div>

ForwardEngine 是一个基于 Modern C++（C++23）与 Boost.Asio/Beast 的代理引擎原型，核心链路使用 `net::awaitable` 协程组织，目标是提供低延迟、高并发的网络转发能力，并支持多种代理协议。

## 功能概览
- **HTTP 代理**：支持 HTTP 正向代理与 HTTPS `CONNECT` 隧道。
- **SOCKS5 代理**：支持标准 SOCKS5 协议（无认证/TCP Connect）。
- **Trojan 代理**：支持 Trojan 协议（TLS + 类 HTTP 伪装）。
- **Obscura 隧道**：基于 WebSocket + TLS 的传输层伪装通道。

## 快速上手（Windows 11 + MinGW）
依赖默认从 `c:/bin` 查找（根目录 `CMakeLists.txt` 已配置 `CMAKE_PREFIX_PATH`、`OPENSSL_ROOT_DIR`）。

### 构建
推荐使用 `MinGW Makefiles` 生成器（已在项目中验证通过）：

```bat
cmake -S . -B build_release -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build_release -j
```

### 运行
程序运行时会读取 `src/configuration.json`。默认监听端口为 `8081`（`agent.addressable.port`）。

```bat
build_release\src\Forward.exe
```

### 验证（curl）
HTTP 站点可能会 301 跳转到 HTTPS（例如百度），建议加 `-L` 跟随跳转。

```bat
# HTTP/HTTPS 代理
curl -v -L -x http://127.0.0.1:8081 http://www.baidu.com
curl -v -L -x http://127.0.0.1:8081 https://www.baidu.com

# SOCKS5 代理
curl -v -L -x socks5://127.0.0.1:8081 http://www.baidu.com
```

### 测试
```bat
ctest --test-dir build_release --output-on-failure
```

## 配置说明（src/configuration.json）
- `agent.addressable.host/port`：对外提供代理服务的监听地址与端口（默认 `localhost:8081`）
- `agent.certificate.cert/key`：Obscura/Trojan（TLS）所需证书与私钥路径
- `trace.*`：日志开关、级别、格式与名称（建议排障时把 `log_level` 设为 `debug`）

## 目录结构
- `include/forward-engine/agent/*`：会话主链路、协议识别、路由与连接池
- `include/forward-engine/protocol/*`：具体协议实现（SOCKS5, Trojan）
- `include/forward-engine/http/*`：HTTP 类型与编解码
- `include/forward-engine/trace/*`：日志封装（基于 spdlog）
- `include/forward-engine/transformer/*`：数据转换封装（基于 glaze）
- `test/*`：回归用例（含 HTTP/SOCKS5/Trojan/Obscura 转发、连接收敛、spdlog 等）

## 已知限制
- 连接池目前仅覆盖 TCP；跨线程共享/分片池与全局淘汰策略仍在完善。
- 反向代理路由表仍在完善。

## 许可证
本项目采用 [MIT License](LICENSE)。
