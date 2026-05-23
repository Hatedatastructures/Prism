---
name: coding-standards
description: Prism C++ 编码规范。所有新增和修改的 C++ 代码必须遵循此规范，包括命名、文件名、函数参数、头文件管理、函数体长度等规则。
---

# Skill: C++ 编码规范

## 触发条件

编写或修改任何 C++ 代码时必须遵循此规范。

## 1. 函数参数上限

**规则：函数参数不超过 3 个。** 超过 3 个时必须用结构体收敛。

```cpp
// 禁止：4 个参数
auto connect(const memory::string &host, std::uint16_t port,
             bool use_tls, std::uint32_t timeout) -> net::awaitable<void>;

// 正确：结构体收敛
struct connect_options
{
    memory::string host;
    std::uint16_t port = 0;
    bool use_tls = false;
    std::uint32_t timeout_ms = 5000;
};

auto connect(connect_options opts) -> net::awaitable<void>;
```

**例外**：
- nghttp2 / OpenSSL 等 C 库回调签名（无法修改）
- `main()` 函数
- 构造函数的成员初始化列表（但鼓励用结构体收敛配置参数）

**How to apply**: 审查每个新增/修改的函数声明。超过 3 个参数时，提取结构体。参考 `multiplex::stream_options`、`multiplex::bootstrap_context`、`stealth::handshake_context` 的模式。

## 2. 命名规范

**全部 snake_case**，与现有代码保持一致。

| 类型 | 风格 | 示例 |
|------|------|------|
| 类/结构体 | snake_case | `pending_entry`, `h2_stream` |
| 函数/方法 | snake_case | `activate_stream()`, `send_data()` |
| 变量/成员 | snake_case | `stream_id_`, `max_streams` |
| 枚举/枚举值 | snake_case | `stream_type::tcp`, `protocol_type::smux` |
| 命名空间 | snake_case | `psm::multiplex::h2mux` |
| 文件名 | 单词（多词用目录分层） | `craft.cpp`, `h2mux/craft.hpp` |
| 常量 | snake_case | `max_frame_payload` |
| 测试函数 | PascalCase | `TestBasicGetRequest`, `LogPass` |

**禁止**：驼峰命名、匈牙利命名。

### 2.1 标识符词数上限

**规则：标识符最多 2 个词（1 个下划线分隔）。** 超过时需重新组织命名或通过结构体/命名空间分层。

```
max_streams       → OK（2 词）
stream_type       → OK（2 词）
connect_options   → OK（2 词）
first_connect_resolved_  → 禁止（4 词），改为 connect_ctx.resolved_ 或类似分层
ssl_ctx_native_handle    → 禁止（4 词），改为 ssl.native_handle() 或类似分层
```

**例外**：
- C 库回调参数名（无法修改）
- 测试函数名（PascalCase 不受此限制）

**How to apply**: 每个新标识符检查下划线数量。超过 1 个下划线时，考虑用命名空间、结构体成员、或更短的词汇表达。

### 2.2 文件名单词规则

**规则：文件名只用单个单词，不含下划线和驼峰。** 多词含义通过目录分层表达。

```
h2mux/craft.hpp     → 正确（目录 h2mux + 单词 craft）
shadowtls/auth.cpp  → 正确（目录 shadowtls + 单词 auth）
reality/keygen.hpp  → 正确（目录 reality + 单词 keygen）
h2_bridge.hpp       → 禁止（含下划线）
h2muxCraft.hpp      → 禁止（驼峰）
packet_handler.cpp  → 禁止（含下划线），改为 handler/packet.cpp 或 handler.cpp
```

**How to apply**: 新文件命名时只用单词。如果需要多词表达，创建子目录。对现有文件，逐步迁移。

## 3. 函数体长度上限

**规则：单函数体不超过 120 行**（不含注释和空行）。超过时拆分为子函数。

```cpp
// 禁止：200 行的 run() 函数
auto run() -> net::awaitable<void>
{
    // 200 行逻辑...
}

// 正确：拆分子函数
auto run() -> net::awaitable<void>
{
    co_await init_session();
    co_spawn(executor(), send_loop(), detached);
    co_await frame_loop();
    cleanup();
}
```

**例外**：
- nghttp2 回调中的 `read_callback` lambda（nghttp2 要求同步）
- 协程中的 `co_spawn` lambda（紧耦合逻辑）

**How to apply**: 编写完函数后检查行数。超过 120 行时识别可独立的子逻辑，提取为带清晰命名的私有方法。

## 4. 头文件管理

### 4.1 头文件最小化 include

**规则：`.hpp` 文件中优先使用前向声明，`#include` 只在 `.cpp` 中引入完整定义。**

```cpp
// craft.hpp — 用前向声明，不 include
namespace psm::connect { class router; }  // 前向声明

// craft.cpp — include 完整定义
#include <prism/connect/dial/router.hpp>
```

**必须 include 的场景**（.hpp 中）：
- 基类定义（继承需要完整定义）
- 模板实现（隐式实例化需要）
- 值类型成员（`std::string`、`std::vector` 等）
- 头文件中的 inline 函数依赖的类型

### 4.2 include 排序规范

**规则：按以下顺序排列，组间用空行分隔，组内按字母序排列。**

```
// 1. 对应的头文件（仅 .cpp 文件）
#include <prism/multiplex/h2mux/craft.hpp>

// 2. 项目内头文件（<> 或 "" 均可，按项目约定）
#include <prism/multiplex/duct.hpp>
#include <prism/multiplex/parcel.hpp>
#include <prism/trace.hpp>

// 3. 第三方库头文件
#include <boost/asio/co_spawn.hpp>
#include <nghttp2/nghttp2.h>

// 4. C++ 标准库头文件
#include <algorithm>
#include <cstring>
```

### 4.3 禁止 using namespace

**规则：禁止 `using namespace std` 和 `using namespace boost`。**

```cpp
// 禁止
using namespace std;
using namespace boost::asio;

// 正确：用别名或显式限定
namespace net = boost::asio;           // 允许：命名空间别名
auto buf = std::vector<std::byte>{};   // 显式 std::
```

**允许**：命名空间别名（`namespace net = boost::asio`），这是项目现有惯例。

## 5. 注释风格

### 5.1 Doxygen 文档（仅 .hpp）

**规则：Doxygen 风格文档只写在 `.hpp` 头文件中。** 声明处的文档即为接口契约。

```cpp
// craft.hpp
/**
 * @brief 初始化 nghttp2 session
 * @return 0 成功，非 0 失败
 */
auto init_nghttp2() -> int;
```

**禁止**：`.cpp` 文件中写 Doxygen 块注释（`/** ... */`）。实现文件应自解释。

### 5.2 .cpp 行注释

**规则：`.cpp` 文件中只在复杂逻辑的 WHY 不显而易见时写 `//` 行注释。** 不写 WHAT 注释。

```cpp
// craft.cpp
auto craft::on_data(...) -> int
{
    // nghttp2 可能在单次 mem_recv 中多次回调，必须立即投递到 channel
    // 否则 coroutine 上下文切换后 send_pending 会导致帧重排
    channel_.try_send(error_code{}, item);
    return 0;
}
```

**禁止**：无意义的注释、注释掉的代码、FIXME/HACK 永久标记。

### 5.3 头文件 Doxygen 模板

```cpp
/**
 * @file craft.hpp
 * @brief h2mux 多路复用会话服务端
 * @details 继承 core，利用 nghttp2 实现 HTTP/2 服务端帧编解码。
 */
```

## 6. 返回类型

**规则：使用尾随返回类型。**

```cpp
// 正确
auto send_data(std::uint32_t stream_id, memory::vector<std::byte> payload) const
    -> net::awaitable<void> override;

// 禁止
net::awaitable<void> send_data(...) const override;
```

## 7. [[nodiscard]]

**规则：有意义的返回值必须标注 `[[nodiscard]]`。**

```cpp
[[nodiscard]] auto is_active() const noexcept -> bool;
[[nodiscard]] auto get_stream_channel(int32_t stream_id) const -> std::shared_ptr<channel_type>;
```

忽略返回值可能导致资源泄漏或逻辑错误（如未检查连接状态、未读取错误码）。

## 8. PMR 内存

**规则：热路径容器使用 PMR 分配器。**

```cpp
memory::string host;                      // std::pmr::string
memory::vector<std::byte> payload;        // std::pmr::vector
memory::unordered_map<K, V> pending_;     // std::pmr::unordered_map
```

构造函数接受 `memory::resource_pointer mr = {}`，传递给需要 PMR 的基类和成员。

## 9. 类型别名

**规则：过长的类型名用 `using` 别名缩短。** 别名放在命名空间或类内部。

```cpp
// 正确：命名空间级别名
using ssl_stream = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
using ssl_ptr = std::shared_ptr<ssl_stream>;

// 正确：类内部别名
class craft final : public core
{
    using transmit = transport::transmission;
    using awaitable_bytes = net::awaitable<memory::vector<std::byte>>;
    // ...
};

// 禁止：全局 using 污染命名空间
using namespace std;  // 已在 4.3 禁止
```

## 10. auto 使用边界

**规则：局部变量允许 `auto`，函数签名和类成员禁止。**

```cpp
// 允许：迭代器、co_await 结果、模板推导
auto it = pending_.find(stream_id);
auto [ec, protocol] = co_await negotiate();
auto buf = std::vector<std::byte>(4096);

// 禁止：函数参数（非泛型 lambda）
auto process(auto value) -> void;  // 禁止，用显式类型

// 禁止：类成员
auto payload_ = memory::vector<std::byte>{};  // 禁止
```

**允许**：泛型 lambda 的 `auto` 参数（`[](auto &&x) { ... }`）。

## 11. const 正确性

**规则：适度使用 const。** 在有明确语义的地方加 const，不过度追求。

```cpp
// 推荐加 const 的场景
[[nodiscard]] auto is_active() const noexcept -> bool;  // 不修改状态的成员函数
auto process(const memory::string &input) -> void;       // 不修改的输入参数

// 不强制 const 的场景
// - 返回值（移动语义优先）
// - 局部变量（auto 推导已足够清晰）
// - 协程中的中间状态
```

## 12. 错误处理双轨制

**规则：热路径用 `fault::code` 枚举，启动/致命错误用 `exception` 层次。**

```cpp
// 热路径：fault::code（无异常开销）
auto handshake(handshake_context ctx) -> net::awaitable<handshake_result>;
// result.error = fault::code::auth_failed;

// 启动/致命：exception
if (!ssl_context) throw exception::network("SSL context required");
```

**边界判定**：
- 函数在协程热路径中（每次请求都走） → `fault::code`
- 配置错误、初始化失败、不可恢复状态 → `exception`
- 第三方库异常 → 用 `try/catch` 在边界转换为 `fault::code`

## 13. lambda 表达式

**规则：lambda 不超过 10 行。** 超过时提取为命名函数或命名 lambda。

```cpp
// OK：短 lambda
co_spawn(executor(),
    [self](auto...) -> net::awaitable<void> { co_await self->send_loop(); },
    detached);

// 禁止：30 行 lambda
co_spawn(executor(),
    [self](auto...) -> net::awaitable<void> {
        // 30 行逻辑...  → 提取为 auto send_loop() -> net::awaitable<void>
    },
    detached);
```

**例外**：nghttp2 同步回调中的 lambda（nghttp2 API 限制）。

## 14. 头文件保护

**规则：所有 `.hpp` 文件统一使用 `#pragma once`。**

```cpp
// 正确
#pragma once
// file content...

// 禁止
#ifndef PRISM_H2MUX_CRAFT_HPP
#define PRISM_H2MUX_CRAFT_HPP
// ...
#endif
```

## 15. TODO 标记格式

**规则：TODO 格式为 `// TODO: 描述(#标签)`，禁止永久存在。**

```cpp
// 正确
// TODO: sing-mux StreamRequest 首帧解析(#h2mux)
// TODO: 移除旧 pending 兼容代码(#refactor)

// 禁止
// TODO fix this later
// FIXME: hack
// HACK: temporary workaround
```

**How to apply**: 每个 TODO 必须带标签（模块名或 issue 号），便于 grep 追踪。解决后立即删除。

## 16. 访问限定符排序

**规则：public → protected → private，先接口后实现。**

```cpp
class craft final : public core
{
public:
    craft(transport, router &, config, address_resolver, mr);
    auto start() -> void;
    [[nodiscard]] auto is_active() const noexcept -> bool;

protected:
    auto run() -> net::awaitable<void> override;

private:
    auto frame_loop() -> net::awaitable<void>;
    auto activate_stream(int32_t id, const h2_stream_info &info) -> void;

    nghttp2_session *session_ = nullptr;
    address_resolver resolver_;
};
```

## 17. 命名空间组织

**规则：源文件中用 `namespace {}` 或 `namespace detail` 封装内部实现。**

```cpp
// craft.cpp — 匿名命名空间封装文件内部函数
namespace
{
    auto verify_basic_auth(std::string_view header, const users &list) -> bool
    {
        // ...
    }
} // namespace

namespace psm::multiplex::h2mux
{
    // 公开实现...
}
```

**How to apply**: `.cpp` 中不暴露给外部的辅助函数放在匿名命名空间中。跨文件的内部函数用 `namespace detail`。

## 18. override 与 final

**规则：虚函数重写必须标注 `override`，不再被继承的类标注 `final`。**

```cpp
// 正确
class craft final : public core
{
    auto run() -> net::awaitable<void> override;  // override
    auto send_data(int32_t id, memory::vector<std::byte> data) -> void override;
};

// 禁止：重写虚函数不加 override
class craft : public core
{
    auto run() -> net::awaitable<void>;  // 缺少 override
};
```

## 19. 构造函数策略

**规则：简单构造直接 public，复杂构造用 `static create()` 工厂。**

```cpp
// 简单构造：参数可直接初始化成员，无复杂逻辑
struct h2_stream_info
{
    memory::string host;
    std::uint16_t port = 0;
};

// 工厂构造：需要 shared_from_this、异步初始化、或复杂设置
class craft final : public core, public std::enable_shared_from_this<craft>
{
public:
    [[nodiscard]] static auto create(transport t, router &r, config cfg, mr)
        -> std::shared_ptr<craft>;

private:
    craft(transport t, router &r, config cfg, mr);
};
```

## 20. 固定宽度整数类型

**规则：禁止使用 `int`、`unsigned`、`long` 等平台相关类型。** 使用 `<cstdint>` 中的固定宽度类型。

```cpp
// 正确
std::uint16_t port = 0;
std::uint32_t stream_id = 0;
std::int32_t bytes_read = 0;
std::size_t count = 0;   // std::size_t 是例外，允许

// 禁止
int port = 0;
unsigned int flags = 0;
long length = 0;
```

**例外**：`std::size_t`、`std::ptrdiff_t`（标准库约定）、`main()` 返回值。

## 21. 成员访问风格

**规则：成员函数中访问成员变量不写 `this->`，初始化列表中参数与成员同名时加 `this->`。**

```cpp
class craft
{
    auto send_data(int32_t id, memory::vector<std::byte> data) -> void
    {
        // 不加 this->（成员名本身已足够清晰）
        session_ = nullptr;
        send_channel_.try_send(error_code{}, outbound{id, std::move(data)});
    }

    // 初始化列表中用 this-> 区分参数与成员
    craft(transport trans, router &route, config cfg)
        : transport_(std::move(trans)), this->route_(route)  // 如果参数名与成员冲突
    {
    }
};
```

## 22. 类型安全规则

**规则：禁止 bool 参数、禁止单参数构造函数隐式转换。**

```cpp
// 禁止：bool 参数（调用处无法理解语义）
auto connect(const string &host, std::uint16_t port, bool use_tls) -> void;
// connect("host", 443, true);  // true 是什么意思？

// 正确：用枚举或结构体
enum class tls_mode : std::uint8_t { plain, tls };
auto connect(const string &host, std::uint16_t port, tls_mode mode) -> void;

// 禁止：隐式转换
struct timeout { std::uint32_t ms; };
void set_timeout(timeout t);
set_timeout(5000);  // 禁止：隐式转换

// 正确：显式构造
struct timeout { explicit timeout(std::uint32_t ms) : ms(ms) {} std::uint32_t ms; };
set_timeout(timeout{5000});
```

## 23. struct vs class

**规则：按语义区分。** 纯数据聚合用 `struct`，有不变量/私有成员/行为用 `class`。

```cpp
// struct：纯数据，无不变量，无私有成员
struct h2_stream_info
{
    memory::string host;
    std::uint16_t port = 0;
    stream_type type = stream_type::tcp;
    bool valid = false;
};

// class：有不变量、私有成员、或非平凡行为
class craft final : public core
{
public:
    // ...
private:
    nghttp2_session *session_ = nullptr;
    // ...
};
```

**How to apply**: 如果去掉所有成员函数后只剩下数据且没有不变量要保护，用 `struct`。否则用 `class`。

## 24. enum class + 底层类型

**规则：所有枚举必须使用 `enum class` 并指定底层类型。**

```cpp
// 正确
enum class stream_type : std::uint8_t { tcp, udp, icmp, check };
enum class protocol_type : std::uint8_t { smux, yamux, h2mux };

// 禁止：无作用域枚举
enum stream_type { tcp, udp, icmp, check };

// 禁止：未指定底层类型
enum class stream_type { tcp, udp, icmp, check };
```

**例外**：
- C 库兼容的枚举（如 nghttp2 常量映射）

## 25. 智能指针

**规则：按场景灵活选择。** 遵循以下语义指引：

- `std::unique_ptr`：独占所有权，不可复制
- `std::shared_ptr`：共享所有权，协程中按值捕获保持对象存活
- 裸指针/引用：非拥有关系（如 `this`、外部管理的对象）

协程中 `co_spawn` 的 lambda 必须按值捕获 `shared_ptr`（`self` 模式）保持对象存活。

## 26. 现有文件迁移对照表

以下是项目中含下划线的文件名及其推荐新路径：

| 现有路径 | 推荐新路径 | 说明 |
|----------|-----------|------|
| `protocol/protocol_type.hpp` | `protocol/types.hpp` | types 语义更简洁 |
| `protocol/common/udp_relay.hpp` | `protocol/common/udprelay.hpp` | 合并为单词 |
| `recognition/layered_pipeline.hpp` | `recognition/pipeline.hpp` | 目录已提供上下文 |
| `recognition/scheme_route_table.hpp` | `recognition/routes.hpp` | 缩短 |
| `recognition/tls/feature_bitmap.hpp` | `recognition/tls/features.hpp` | 目录已提供上下文 |
| `stealth/anytls/mux/stream_transport.hpp` | `stealth/anytls/mux/transport.hpp` | 目录已提供上下文 |

对应的 `.cpp` 文件同步迁移。迁移时需更新所有 `#include` 引用和 CMakeLists.txt。

## 审查清单

每次编写或修改 C++ 代码后，逐项检查：

- [ ] 函数参数 <= 3 个？
- [ ] 函数体 <= 120 行？
- [ ] 标识符最多 2 个词（1 个下划线）？
- [ ] 文件名只用单词（多词用目录分层）？
- [ ] 命名全 snake_case（测试函数除外）？
- [ ] 纯数据用 struct，有行为/不变量用 class？
- [ ] 枚举用 enum class + 底层类型？
- [ ] 类型过长时用 using 别名？
- [ ] 局部变量允许 auto，签名禁止？
- [ ] .hpp 中 Doxygen 文档，.cpp 中只用 `//` 行注释？
- [ ] .hpp 中无多余 include（优先前向声明）？
- [ ] include 按四组排序？
- [ ] 无 `using namespace std/boost`？
- [ ] 返回值用尾随返回类型？
- [ ] 有意义的返回值标注 `[[nodiscard]]`？
- [ ] 热路径容器用 PMR 类型？
- [ ] 虚函数重写标注 override？
- [ ] 使用固定宽度整数类型？
- [ ] 禁止 bool 参数，用枚举替代？
- [ ] 头文件保护用 `#pragma once`？
- [ ] TODO 格式正确且有标签？
