# 错误处理体系

Prism 采用 **双轨错误处理策略**：热路径使用 `fault::code` 错误码（零分配、零异常开销），冷路径（启动/致命错误）使用结构化异常体系。

---

## 模块位置

| 模块 | 头文件 | 特性 |
|------|--------|------|
| `fault::code` | `include/prism/fault/code.hpp` | header-only |
| `fault::handling` | `include/prism/fault/handling.hpp` | header-only |
| `fault::compatible` | `include/prism/fault/compatible.hpp` | header-only |
| `exception::deviant` | `include/prism/exception/deviant.hpp` | header-only |
| `exception::network` | `include/prism/exception/network.hpp` | header-only |
| `exception::protocol` | `include/prism/exception/protocol.hpp` | header-only |
| `exception::security` | `include/prism/exception/security.hpp` | header-only |

聚合头文件：`include/prism/fault.hpp`、`include/prism/exception.hpp`

---

## 热路径：fault::code

`psm::fault::code` 是全局错误码枚举（`enum class code : int`），零值表示成功。

### 辅助函数

```cpp
namespace psm::fault {
    [[nodiscard]] constexpr std::string_view describe(code value) noexcept;  // 零分配，指向静态字面量
    [[nodiscard]] constexpr bool succeeded(code c) noexcept;
    [[nodiscard]] constexpr bool failed(code c) noexcept;
}
```

### 使用示例

```cpp
// 返回错误码和结果的配对
auto async_acquire(tcp::endpoint endpoint)
    -> net::awaitable<std::pair<fault::code, pooled_connection>>
{
    co_return std::make_pair(fault::code::success, pooled_connection(...));
    co_return std::make_pair(fault::code::timeout, pooled_connection{});
}

// 调用方检查
auto [ec, conn] = co_await pool.async_acquire(endpoint);
if (fault::failed(ec))
{
    trace::warn("acquire failed: {}", fault::describe(ec));
    co_return;
}
```

来源：[pool.cpp](../../src/prism/channel/connection/pool.cpp)

### Boost/std error_code 转换

```cpp
std::error_code ec;
auto n = co_await transport.async_read_some(buffer.subspan(total), ec);
if (ec)
    co_return std::pair{fault::to_code(ec), total};
```

来源：[relay.cpp](../../src/prism/protocol/vless/relay.cpp)

---

## fault::handling 适配层

位置：[handling.hpp](../../include/prism/fault/handling.hpp)

### 接口

```cpp
template <typename ErrorCode>
[[nodiscard]] constexpr bool succeeded(const ErrorCode &ec) noexcept;

template <typename ErrorCode>
[[nodiscard]] constexpr bool failed(const ErrorCode &ec) noexcept;

[[nodiscard]] code to_code(const boost::system::error_code &ec) noexcept;
[[nodiscard]] code to_code(const std::error_code &ec) noexcept;
```

### 类型分发

`succeeded()` / `failed()` 使用 `if constexpr` 编译时分发：

- **`psm::fault::code`**：直接与 `code::success` 比较
- **`std::error_code`**：使用 `!ec`
- **`boost::system::error_code`**：使用 `!ec`
- 不支持的类型触发 `static_assert`

### to_code() 映射

**Boost.Asio**:

| Boost 错误 | fault::code |
|------------|-------------|
| `eof` | `code::eof` |
| `operation_aborted` | `code::canceled` |
| `timed_out` | `code::timeout` |
| `connection_refused` / `connection_reset` / `connection_aborted` | 对应同名 |
| `host_unreachable` / `network_unreachable` | 对应同名 |
| `no_buffer_space` | `code::resource_unavailable` |
| 其他（非 fault 分类） | `code::io_error` |

**std::errc**:

| std::errc | fault::code |
|-----------|-------------|
| `connection_refused` / `connection_reset` / `connection_aborted` | 对应同名 |
| `timed_out` / `host_unreachable` / `network_unreachable` | 对应同名 |
| `operation_canceled` | `code::canceled` |
| 其他（非 fault 分类） | `code::io_error` |

两种 `to_code()` 都先检查错误码是否属于 `psm::fault` 分类，是则直接恢复原始枚举值。

---

## fault::compatible 兼容层

位置：[compatible.hpp](../../include/prism/fault/compatible.hpp)

实现 `fault::code` 与 `std::error_code`、`boost::system::error_code` 的无缝互操作。

### std::error_code 集成

通过 `std::is_error_code_enum<psm::fault::code>` 特化支持隐式转换：

```cpp
std::error_code ec = fault::code::timeout;
assert(ec.value() == 11);
assert(ec.category().name() == std::string("psm::fault"));
```

核心组件：`fault_category`（分类名称 `"psm::fault"`）、`category()`、`make_error_code(code)`、`cached_message(code)`。

### boost::system::error_code 集成

对称特化，同样支持隐式转换：

```cpp
boost::system::error_code bec = fault::code::connection_refused;
```

### 哈希支持

`std::hash<psm::fault::code>` 特化使错误码可用于无序容器。

---

## 冷路径：Exception 体系

### 继承层次

```
std::runtime_error
       |
       v
  exception::deviant (抽象基类)
       |- std::error_code ec_
       |- std::source_location location_
       |- type_name() -> 纯虚函数
       |- dump() -> 格式化诊断
       |
       +-- exception::network   -> "NETWORK"
       +-- exception::protocol  -> "PROTOCOL"
       +-- exception::security  -> "SECURITY"
```

### deviant 基类

位置：[deviant.hpp](../../include/prism/exception/deviant.hpp)

构造时通过 `std::source_location::current()` 默认参数自动捕获抛出点文件名、行号、函数名。

```cpp
explicit deviant(std::error_code ec, std::string_view desc = {},
                 const std::source_location &loc = std::source_location::current());
explicit deviant(const std::string &msg,
                 const std::source_location &loc = std::source_location::current());
template <typename... Args>
explicit deviant(const std::source_location &loc, std::format_string<Args...> fmt, Args &&...args);
```

```cpp
[[nodiscard]] const std::error_code &error_code() const noexcept;
[[nodiscard]] const std::source_location &location() const noexcept;
[[nodiscard]] std::string filename() const;
[[nodiscard]] virtual std::string dump() const;
```

### dump() 格式

```
[filename:line] [TYPE:value] description
```

### 各异常类适用场景

| 异常类 | type_name | 适用场景 | 典型错误码 |
|--------|-----------|---------|-----------|
| `exception::network` | `"NETWORK"` | 端口绑定失败、SSL 上下文初始化失败、网络地址格式错误 | `connection_refused`, `timeout`, `host_unreachable` |
| `exception::protocol` | `"PROTOCOL"` | 证书/密钥加载失败、协议版本不匹配、状态机非法转换 | `ssl_cert_load_failed`, `ssl_key_load_failed`, `protocol_error` |
| `exception::security` | `"SECURITY"` | 证书格式无效、认证凭据配置错误、安全策略验证失败 | `auth_failed`, `certificate_verification_failed` |

运行时 I/O 错误和认证失败应使用 `fault::code`，不抛异常。

```cpp
// 典型使用：tls.cpp 中证书加载失败
ctx.use_certificate_chain_file(cert_path, ec);
if (ec)
    throw exception::protocol("ssl cert load failed: {}", ec.message());
```

---

## 最佳实践

### 何时用 fault::code、何时用 Exception

| 场景 | 机制 | 理由 |
|------|------|------|
| 网络读写 / 协议解析 / 连接池 / DNS / 认证 | `fault::code` | 高频路径，零开销 |
| SSL 证书加载 / 端口绑定 / 配置解析 / 安全策略初始化 | Exception | 启动阶段，不可恢复 |

### 各层实践

**协议中继层**：使用 `std::pair<fault::code, T>` 作为协程返回类型，底层 `std::error_code` 通过 `fault::to_code()` 转换。

**Pipeline 层**：使用 `fault::failed()` 检查，`fault::describe()` 生成零分配日志。

**连接池**：连接超时返回 `fault::code::timeout`，连接失败返回 `fault::code::bad_gateway`。

**路由层**：DNS 解析失败时转换为 `fault::code::host_unreachable`。

### 日志中使用错误码

- `fault::describe(code)`：返回 `std::string_view`，零分配，适合热路径
- `fault::cached_message(code)`：返回 `const std::string&`，首次调用缓存，后续零分配

---

## 错误码速查表

### 通用错误 (0-10)

| 枚举值 | 值 | 含义 |
|--------|-----|------|
| `success` | 0 | 操作成功 |
| `generic_error` | 1 | 通用错误 |
| `parse_error` | 2 | 解析错误 |
| `eof` | 3 | 到达文件末尾 |
| `would_block` | 4 | 操作将阻塞 |
| `protocol_error` | 5 | 协议错误 |
| `bad_message` | 6 | 消息格式错误 |
| `invalid_argument` | 7 | 无效参数 |
| `not_supported` | 8 | 不支持的操作 |
| `message_too_large` | 9 | 消息过大 |
| `io_error` | 10 | I/O 错误 |

### 网络错误 (11-18)

| 枚举值 | 值 | 含义 |
|--------|-----|------|
| `timeout` | 11 | 操作超时 |
| `canceled` | 12 | 操作被取消 |
| `tls_handshake_failed` | 13 | TLS 握手失败 |
| `tls_shutdown_failed` | 14 | TLS 关闭失败 |
| `auth_failed` | 15 | 认证失败 |
| `dns_failed` | 16 | DNS 解析失败 |
| `upstream_unreachable` | 17 | 上游不可达 |
| `connection_refused` | 18 | 连接被拒绝 |

### 协议错误 (19-25)

| 枚举值 | 值 | 含义 |
|--------|-----|------|
| `unsupported_command` | 19 | 不支持的命令 |
| `unsupported_address` | 20 | 不支持的地址类型 |
| `blocked` | 21 | 请求被阻止 |
| `bad_gateway` | 22 | 网关错误 |
| `host_unreachable` | 23 | 主机不可达 |
| `connection_reset` | 24 | 连接被重置 |
| `network_unreachable` | 25 | 网络不可达 |

### 系统错误 (26-37)

| 枚举值 | 值 | 含义 |
|--------|-----|------|
| `ssl_cert_load_failed` | 26 | SSL 证书加载失败 |
| `ssl_key_load_failed` | 27 | SSL 密钥加载失败 |
| `socks5_auth_negotiation_failed` | 28 | SOCKS5 认证协商失败 |
| `file_open_failed` | 29 | 文件打开失败 |
| `config_parse_error` | 30 | 配置解析错误 |
| `port_already_in_use` | 31 | 端口已被占用 |
| `certificate_verification_failed` | 32 | 证书验证失败 |
| `connection_aborted` | 33 | 连接被中止 |
| `resource_unavailable` | 34 | 资源不可用 |
| `ttl_expired` | 35 | TTL 已过期 |
| `forbidden` | 36 | 禁止访问 |
| `ipv6_disabled` | 37 | IPv6 被禁用 |

### Mux 错误 (38-44)

| 枚举值 | 值 | 含义 |
|--------|-----|------|
| `mux_not_enabled` | 38 | Mux 未启用 |
| `mux_session_error` | 39 | Mux 会话错误 |
| `mux_stream_error` | 40 | Mux 流错误 |
| `mux_window_exceeded` | 41 | Mux 窗口超限 |
| `mux_protocol_error` | 42 | Mux 协议错误 |
| `mux_connection_limit` | 43 | Mux 连接数限制 |
| `mux_stream_limit` | 44 | Mux 流数限制 |

### SS2022 错误 (45-48)

| 枚举值 | 值 | 含义 |
|--------|-----|------|
| `crypto_error` | 45 | AEAD 加密/解密失败 |
| `invalid_psk` | 46 | PSK 无效 |
| `timestamp_expired` | 47 | 时间戳超出窗口 |
| `replay_detected` | 48 | Salt 重放检测 |

### Reality 错误 (49-57)

| 枚举值 | 值 | 含义 |
|--------|-----|------|
| `reality_not_configured` | 49 | Reality 未配置 |
| `reality_auth_failed` | 50 | Reality 认证失败 |
| `reality_sni_mismatch` | 51 | SNI 不在 server_names 中 |
| `reality_key_exchange_failed` | 52 | X25519 密钥交换失败 |
| `reality_handshake_failed` | 53 | Reality TLS 握手失败 |
| `reality_dest_unreachable` | 54 | 回退目标不可达 |
| `reality_certificate_error` | 55 | 证书获取/处理失败 |
| `reality_tls_record_error` | 56 | TLS 记录解析错误 |
| `reality_key_schedule_error` | 57 | 密钥调度错误 |

### SS2022 UDP 错误 (58-59)

| 枚举值 | 值 | 含义 |
|--------|-----|------|
| `udp_session_expired` | 58 | UDP 会话已过期 |
| `packet_replay_detected` | 59 | UDP PacketID 重放检测 |
