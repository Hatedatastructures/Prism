# psmtest 协议库规范（tests/common）

本规范定义 `tests/common/` 下所有协议测试库的统一设计标准。
参考 Go 参考实现（mihomo transport / sing 系列库）的接口模式，目标：
**可维护性与性能兼得**。所有重构必须遵守本规范。

## 1. 目录结构：一协议一目录，按职责拆分

禁止把所有代码塞进单个头文件。每个协议一个目录：

```
tests/common/<proto>/
  types.hpp     — 常量、枚举、标志位、基础结构
  codec.hpp     — 帧编解码（build/parse，纯函数，零状态）
  kdf.hpp       — 密钥派生（仅需要时）
  chunk.hpp     — 数据块编解码（流式，含状态机）
  handshake.hpp — 握手会话（仅需要时）
  client.hpp    — 客户端封装（对象，包装传输）
  server.hpp    — 服务端封装（对象，包装传输）
```

聚合头 `<proto>.hpp` 仅 re-export 子头，供旧测试过渡引用。

`tests/common/core/`：跨协议基础设施（error / crypto / flat_buffer / transport）。
`tests/common/mux/`：多路复用底层工具（smux / yamux / h2mux 统一框架）。

## 2. 接口设计：面向对象 + 协程 + 编译期约束

### 2.1 传输抽象（concept）

所有协议对象工作在统一的异步流抽象上：

```cpp
template <typename T>
concept stream = requires(T &s, std::span<std::uint8_t> buf) {
    { s.read_some(buf) } -> std::same_as<net::awaitable<std::size_t>>;
    { s.write_all(buf) } -> std::same_as<net::awaitable<std::error_code>>;
    { s.close() }        -> std::same_as<net::awaitable<void>>;
};
```

- 全部协程（`net::awaitable`），禁止阻塞 I/O
- 测试用内存管道实现（`core/transport/memory_stream.hpp`），性能测试用真实 socket

### 2.2 协议封装（对齐 Prism `transmission` + Boost.Beast/Asio）

每个协议必须提供完整的三层 API（对齐 `include/prism/net/transport/transmission.hpp`）：

**a) 会话接口（`session`，连接级）**——满足统一 concept：

```cpp
template <typename S>
concept protocol_session = requires(S &s, std::span<std::uint8_t> wbuf,
                                    std::span<const std::uint8_t> rbuf,
                                    std::chrono::milliseconds ms)
{
    { s.read_some(wbuf) } -> std::same_as<net::awaitable<std::size_t>>;   // 0 = 对端关闭
    { s.write_all(rbuf) } -> std::same_as<net::awaitable<boost::system::error_code>>;
    { s.shutdown() }      -> std::same_as<net::awaitable<void>>;          // 优雅半关（发 FIN，仍可读）
    { s.close() }         -> std::same_as<net::awaitable<void>>;
    { s.cancel() }        -> std::same_as<void>;                          // 取消挂起操作
    { s.set_timeout(ms) } -> std::same_as<void>;                          // 读超时
    { s.is_open() }       -> std::same_as<bool>;
    { s.executor() }      -> std::same_as<net::any_io_executor>;
};
```

**b) 客户端**——`connect(raw, options)` 执行完整握手（带超时）返回会话：

```cpp
class vmess::client {
public:
    struct options { uuid; security; timeout; };
    explicit client(options);
    auto connect(stream auto &raw, const address &dst)
        -> net::awaitable<std::shared_ptr<session>>;   // nullptr = 握手失败/超时
};
```

**c) 服务端**——`accept(raw, message&)` 解析握手 + 认证 + 响应，返回会话：

```cpp
class vmess::server {
public:
    struct options { uuid; timeout; };
    explicit server(options);
    auto accept(stream auto &raw, message &msg)
        -> net::awaitable<std::shared_ptr<session>>;
};
```

**d) 组合算法（自由函数，Beast/Asio 风格）**——`core/transport/algorithm.hpp`：

```cpp
auto async_read_exact(stream auto &s, std::span<std::uint8_t> buf, timeout)
    -> net::awaitable<std::error_code>;   // 读满 buf 或超时/关闭
auto async_write_exact(stream auto &s, std::span<const std::uint8_t> buf, timeout)
    -> net::awaitable<std::error_code>;
```

**e) 多路复用流**——`stream_handle` 除会话接口外补 `id()`、窗口状态查询。

### 2.3 编译期约束（模板策略）

- 帧编解码、块编解码为**无状态纯函数**，通过 concept 约束作为策略模板参数复用逻辑
- 多路复用：`template <frame_codec C> class session` 共享会话逻辑，smux/yamux/h2mux 仅提供各自的 `C`

## 3. 函数参数规则

- 普通逻辑函数参数 **≤ 2 个**
- 上限 **3 个**，超过必须收敛为 `options` / `frame` / `message` 结构体
- 构造函数参数收敛为 `options` 结构体
- 帧构造统一签名：`build(const frame_meta&, payload, out)` 或并入对象方法

## 4. 错误处理

- 编解码：`std::error_code`（`core/error.hpp`，Beast 风格），成功 = 空 code
- 增量解析：数据不足返回 `error::need_more`，消费量经出参或返回值
- 协程错误：`std::expected<T, std::error_code>` 或 `net::awaitable<std::error_code>`（无 T 时）

## 5. 命名

- 命名空间 `psmtest::<proto>`，子模块命名空间 `psmtest::<proto>::detail`
- 类 / 结构 / 枚举：snake_case；枚举成员：snake_case
- 文件：snake_case；头文件保护 `#pragma once`
- 注释：Doxygen 风格中文（`@brief` / `@param` / `@return` / `@note`）

## 6. 测试分层（每个协议必须覆盖）

```
tests/protocol/<proto>/
  <Proto>Codec.cpp     — 帧/块编解码单测（边界：半包、超长、坏数据）
  <Proto>Session.cpp   — 回环会话测试（对象全链路）
  <Proto>Perf.cpp      — 性能测试
```

### 6.1 传输完整性测试
- 100 MB 随机数据回环传输，逐块 SHA-256 校验明文一致
- 1 GB 传输（Release 构建），校验字节数与分段摘要

### 6.2 性能指标（benchmark 输出）
- **吞吐量**：MB/s（send + recv 全链路）
- **延迟**：单块 RTT 均值、p50 / p95 / p99（ms），以及波动区间（min/max）
- 报告格式：`<proto> throughput: 1234.5 MB/s | latency(ms): avg 0.12 p50 0.11 p95 0.14 p99 0.18 (min 0.10 max 0.25)`

### 6.3 互操作测试
- 保留 Go 对端（mihomo / sing 系列）验证线上协议兼容性

## 7. 多路复用框架（mux/ 底层工具）

```
tests/common/mux/
  frame.hpp    — 三套帧头常量 + 结构（smux/yamux/h2mux）
  codec.hpp    — 帧编解码策略（concept frame_codec：build/parse/header_len）
  session.hpp  — 协程会话框架：template <frame_codec> session
                 open_stream / accept_stream / close / 流窗口管理
  client.hpp   — mux 客户端（协议选择、连接管理）
  smux.hpp     — psmtest::mux::smux::codec（帧策略实现）
  yamux.hpp    — psmtest::mux::yamux::codec
  h2mux.hpp    — psmtest::mux::h2mux::codec
```

会话逻辑（流表、id 分配、窗口、FIN/RST 状态机）只实现一次，
三个协议仅提供帧策略。性能测试覆盖单会话 100 MB 传输与多流并发。

## 8. 性能原则

- 热路径零堆分配：复用缓冲区（`core/flat_buffer`）、span 切片不拷贝
- 编解码函数 `[[nodiscard]]`、`noexcept` 可行处标注
- 禁止在编解码中 throw（错误走 error_code）
- 性能测试必须 Release 构建，报告机器基础信息（CPU/构建类型）

## 9. 重构流程（逐协议）

1. 按本规范拆分目录与接口
2. 补齐三层测试（codec / session / perf）
3. 对照 Go 参考源码深度评估：逻辑正确性、性能热点、边界 bug、可维护性
4. 通过评估后进入下一协议
