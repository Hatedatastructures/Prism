# ForwardEngine

<div align="center">

![C++23](https://img.shields.io/badge/Standard-C%2B%2B23-blue.svg?logo=c%2B%2B)
![Platform](https://img.shields.io/badge/Platform-Windows%2011-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Build](https://img.shields.io/badge/Build-CMake-orange)

</div>

`ForwardEngine` 是一个基于 C++23 与 `Boost.Asio/Beast` 的代理引擎原型工程，目标是把“接入（`accept`）→ 协议识别（`peek`）→ 路由 → 上游连接 → 双向转发（隧道）→ 退出与回收”这条主链路跑通，并保持清晰的模块边界以便后续演进。

## 核心特性
- C++23：使用 `net::awaitable` + `co_await` 组织异步流程。
- 代理会话：支持 HTTP 正向/反向代理的基本链路；支持 `CONNECT` 隧道。
- 连接复用（TCP）：按目标端点缓存空闲连接，带基础健康检查与上限控制。
- Obscura 封装：基于 Beast `WebSocket(SSL)` 的传输包装，提供 `handshake/async_read/async_write`。

## 构建环境（Windows 11 + MinGW）
- 编译器：`MinGW-w64`（支持 C++23）。
- 构建系统：`CMake 3.15+`。
- 三方依赖：除标准库外，依赖从 `c:/bin` 查找（根目录 `CMakeLists.txt` 里配置了 `CMAKE_PREFIX_PATH`、`OPENSSL_ROOT_DIR`）。

建议的依赖清单：
- `Boost`（Asio、Beast、System 等）。
- `OpenSSL`。
- `spdlog`（日志底座；项目提供 `trace/spdlog.hpp` 封装）。
- `glaze`（`JSON` 序列化/反序列化；项目提供 `transformer` 模块封装）。
  - 具体用法见 [premise.md](docs/premise.md)。

## 快速上手
- 可执行入口通常在 `src/forward-engine/*`。
- 测试在 `test/*`，其中 `session_test` 用于验证：
  - `CONNECT` 隧道的双向转发是否正确
  - 一端关闭后，另一端是否能及时收敛退出

## 目录与模块
- `include/forward-engine/agent/*`
  - `worker.hpp`：监听端口、`accept`、创建 `session`
  - `session.hpp`：会话主链路（协议识别、HTTP/Obscura 处理、隧道与收尾）
  - `analysis.hpp/.cpp`：协议识别与目标解析
  - `distributor.hpp/.cpp`：路由与连接获取
  - `connection.hpp/.cpp`：连接池（`monopolize_socket` + `deleter` 回收）
- `include/forward-engine/http/*`：HTTP 类型与编解码
- `include/forward-engine/trace/*`：日志封装（基于 `spdlog`）
- `include/forward-engine/transformer/*`：数据转换封装（基于 `glaze`）
- `test/*`：最小集成测试与回归用例

## 已知限制
- 连接池当前仅覆盖 TCP；尚未实现全局 LRU、后台定时清理、跨线程共享/分片池。
- 反向代理路由表 `reverse_map_` 仍在完善中。

## 许可证
本项目采用 [MIT License](LICENSE)。
