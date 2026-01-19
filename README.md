# ForwardEngine

<div align="center">

![C++23](https://img.shields.io/badge/Standard-C%2B%2B23-blue.svg?logo=c%2B%2B)
![Platform](https://img.shields.io/badge/Platform-Windows%2011-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Build](https://img.shields.io/badge/Build-CMake-orange)



</div>

ForwardEngine 是一个基于 Modern C++（C++23）与 Boost.Asio/Beast 的代理引擎原型，核心链路使用 `net::awaitable` 协程组织，目标是提供低延迟、高并发的网络转发能力，并预留 Obscura（WSS）伪装通道。

## 功能概览
- 已支持：HTTP 正向代理（含 HTTPS `CONNECT` 隧道）
- 已支持：Obscura（WebSocket + TLS）隧道
- 未支持：SOCKS5（`curl -x socks5://...` 目前会被误判为 Obscura 流量而握手失败）

## 快速上手（Windows 11 + MinGW）
依赖默认从 `c:/bin` 查找（根目录 `CMakeLists.txt` 已配置 `CMAKE_PREFIX_PATH`、`OPENSSL_ROOT_DIR`）。

### 构建
```bat
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
```

### 运行
程序运行时会读取 `src/configuration.json`。默认监听端口为 `8081`（`agent.addressable.port`）。

```bat
build\src\Forward.exe
```

### 验证（curl）
HTTP 站点可能会 301 跳转到 HTTPS（例如百度），建议加 `-L` 跟随跳转。

```bat
curl -v -L -x http://127.0.0.1:8081 http://www.baidu.com
curl -v -L -x http://127.0.0.1:8081 https://www.baidu.com
```

### 测试
```bat
ctest --test-dir build --output-on-failure
```

## 配置说明（src/configuration.json）
- `agent.addressable.host/port`：对外提供代理服务的监听地址与端口（默认 `localhost:8081`）
- `agent.certificate.cert/key`：Obscura（TLS）所需证书与私钥路径
- `trace.*`：日志开关、级别、格式与名称（建议排障时把 `log_level` 设为 `debug`）

## 目录结构
- `include/forward-engine/agent/*`：会话主链路、协议识别、路由与连接池
- `include/forward-engine/http/*`：HTTP 类型与编解码
- `include/forward-engine/trace/*`：日志封装（基于 spdlog）
- `include/forward-engine/transformer/*`：数据转换封装（基于 glaze）
- `test/*`：回归用例（含 `CONNECT` 转发、连接收敛、Obscura、spdlog 等）

## 已知限制
- 连接池目前仅覆盖 TCP；跨线程共享/分片池与全局淘汰策略仍在完善。
- 反向代理路由表仍在完善。

## 许可证
本项目采用 [MIT License](LICENSE)。
