---
name: coding-standards
description: Prism C++ 编码规范。所有新增和修改的 C++ 代码必须遵循此规范，包括命名、文件名、函数参数、头文件管理、函数体长度等规则。
---

# Skill: C++ 编码规范

## 触发条件

编写或修改任何 C++ 代码时必须遵循此规范。

## 1. 函数参数上限

**规则：函数参数不超过 3 个。** 超过 3 个时必须用结构体收敛。，这个函数包括类里面的构造等所有函数

```cpp
// 禁止：4 个参数
auto connect(const memory::string &host, std::uint16_t port, bool use_tls, std::uint32_t timeout) 
    -> net::awaitable<void>;

// 正确：结构体收敛
struct connect_options
{
    memory::string host;
    std::uint16_t port = 0;
    bool use_tls = false;
    std::uint32_t timeout_ms = 5000;
};

auto connect(connect_options opts) 
    -> net::awaitable<void>;
```

**例外**：
- nghttp2 / OpenSSL 等 C 库回调签名（无法修改）
- `main()` 函数
- 构造函数的成员初始化列表（但鼓励用结构体收敛配置参数）

**How to apply**: 审查每个新增/修改的函数声明。超过 3 个参数时，提取结构体。参考 `multiplex::stream_options`、`multiplex::bootstrap_context`、`stealth::handshake_context` 的模式。

## 2. 命名规范

**全部 snake_case**，与现有代码保持一致，每个命名尽量不要和模块和子模块或者本命名空间的其他命名冲突，如果是其他模块的命名，建议加上模块前缀以示区分（如 `h2mux_craft`），但如果本模块已经有了 `craft` 命名，则要避免命名冲突。避免出现常用的单词（如 `handler`、`processor`、`manager`）导致的命名冲突。

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

**计数规则**：
- 常见缩写算 1 个词：`id`, `ctx`, `ssl`, `tls`, `tcp`, `udp`, `h2`, `mux`, `ptr`, `buf`
- 成员后缀 `_` 不计入词数（`stream_id_` = 2 词）
- 目录名提供上下文，不重复计入（`h2mux/craft.hpp` 中 craft 无需写成 `h2mux_craft`）

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

**How to apply**: 新文件命名时只用单词。如果需要多词表达，创建子目录。现有文件的迁移对照表见 `MIGRATION.md`。

## 3. 函数体长度上限

**规则：单函数体不超过 120 行**（不含注释和空行）。超过时拆分为子函数。

```cpp
// 禁止：200 行的 run() 函数
auto run() -> net::awaitable<void>
{
    // 200 行逻辑...
}

// 正确：拆分子函数,子函数函数名要代表其意思，并且遵守这个文件的所有规范
auto run() -> net::awaitable<void>
{
    co_await init_session();
    co_spawn(executor(), send_loop(), detached);
    co_await frame_loop();
    cleanup();
}
```

**计数规则**：
- `switch` 的 `case` 分支计入总行数；某个 `case` 分支过长时应提取为独立函数
- 宏展开不计入，但宏本身算 1 行
- 生成代码（如 protobuf 输出）不受此限制

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

**可以前向声明的场景**：
- `std::unique_ptr<T>` / `std::shared_ptr<T>` 的 T（只要析构在 .cpp 中实现）
- 指针和引用类型的函数参数
- `std::optional<T>` 的 T（C++20 起析构为平凡条件满足时可前向声明，否则需完整定义）

**注意**：如果类有 `std::unique_ptr<T>` 成员且 T 是前向声明的，析构函数必须在 .cpp 中定义（不能 `= default` 在头文件中），否则编译器无法生成正确的析构代码。

### 4.2 include 排序规范

**规则：按以下顺序排列，组间用空行分隔，组内按字母序排列。**

```
// 1. 对应的头文件（仅 .cpp 文件）
#include <prism/multiplex/h2mux/craft.hpp>

// 2. 项目内头文件（统一使用尖括号）
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

**规则：项目内头文件统一使用尖括号 `<prism/...>`。**

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

### 4.4 聚合头文件维护

**规则：新增子头文件时，必须同步更新对应模块的聚合头文件。**

```cpp
// 新增 stealth/restls/types.hpp 后，必须在 stealth.hpp 中添加：
#include <prism/stealth/restls/types.hpp>
```

每个主要模块都有根级聚合头文件（如 `stealth.hpp`、`connect.hpp`、`multiplex.hpp`）。遗漏更新会导致下游编译失败。

## 5. 注释风格

### 5.1 Doxygen 文档（仅 .hpp）

**规则：Doxygen 风格文档只写在 `.hpp` 头文件中。** 声明处的文档即为接口契约。并且禁止markdown语法，禁止英文注释，禁止写在.cpp文件中，使用常见标签

```cpp
// craft.hpp
/**
 * @brief 初始化 nghttp2 session
 * @return 0 成功，非 0 失败
 */
auto init_nghttp2() 
    -> int;
```

**禁止**：`.cpp` 文件中写 Doxygen 块注释（`/** ... */`）。实现文件应自解释。

### 5.2 .cpp 行注释

**规则：`.cpp` 文件中只在复杂逻辑的 WHY 不显而易见时写 `//` 行注释。** 不写 WHAT 注释。

```cpp
// craft.cpp
auto craft::on_data(...) 
    -> int
{
    // nghttp2 可能在单次 memc_recv 中多次回调，必须立即投递到 channel
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

**规则：使用尾随返回类型。** 尾随返回类型中的 `auto` 关键字是语法的一部分，不受 Rule 10 限制。

```cpp
// 正确：非 void 返回类型使用尾随返回
auto send_data(std::uint32_t stream_id, memory::vector<std::byte> payload) const
    -> net::awaitable<void> override;

// 正确：void 返回类型不使用尾随
void start();
void cleanup() override;
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

**规则：`auto` 仅用于以下场景。**

**允许**：
- 尾随返回类型的语法 `auto`（Rule 6）
- 局部变量的类型推导（迭代器、`co_await` 结果、模板推导）
- 泛型 lambda 的 `auto` 参数

```cpp
// 允许：迭代器、co_await 结果、模板推导
auto it = pending_.find(stream_id);
auto [ec, protocol] = co_await negotiate();
auto buf = std::vector<std::byte>(4096);

// 允许：泛型 lambda
[](auto &&x) { std::forward<decltype(x)>(x); };
```

**禁止**：
- 函数参数使用 `auto` 做类型推导（非泛型 lambda 场景）
- 类成员变量使用 `auto`
- `auto` 隐藏意图不明确的类型（如 `auto x = some_obscure_call()` 读者无法判断类型）

```cpp
// 禁止：函数参数类型推导
auto process(auto value) -> void;  // 禁止，用显式类型

// 禁止：类成员
auto payload_ = memory::vector<std::byte>{};  // 禁止，写显式类型
```

## 10.1 auto 引用推导

**规则：严格区分三种 `auto` 引用模式。**

| 用法 | 语义 | 场景 |
|------|------|------|
| `auto x` | 值语义，拷贝/移动 | `co_await` 结果、局部值 |
| `const auto &x` | 只读引用，避免拷贝 | 遍历容器、读取大对象 |
| `auto &&x` | 完美转发引用 | 仅用于泛型 lambda / 模板转发 |

```cpp
// 正确：值语义
auto result = co_await handshake(std::move(ctx));

// 正确：只读引用
for (const auto &entry : pending_) { ... }

// 正确：完美转发（仅模板/泛型 lambda）
[](auto &&stream) { co_await std::forward<decltype(stream)>(stream).read(); };

// 禁止：auto && 用于非转发场景
auto &&data = get_payload();  // 禁止，用 const auto & 或 auto
```

## 11. const 正确性

**规则：适度使用 const。** 在有明确语义的地方加 const，不过度追求。

```cpp
// 推荐加 const 的场景
[[nodiscard]] auto is_active() const noexcept 
    -> bool;  // 不修改状态的成员函数
void process(const memory::string &input);       // 不修改的输入参数

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

| 场景 | 处理方式 |
|------|----------|
| 协程热路径（每次请求都走） | `fault::code` |
| 配置错误、初始化失败、不可恢复状态 | `exception` |
| 构造函数（简单初始化） | `exception`（构造期间失败无法返回错误码） |
| 析构函数 | `fault::code` 或静默（禁止析构函数抛异常） |
| 第三方库返回错误码 | 直接用 `fault::code` 映射 |
| 第三方库抛异常 | `try/catch` 在边界转换为 `fault::code` |
| 回调边界（C 库回调） | `fault::code`（回调中禁止抛异常） |
| 适配层（协程 ↔ 回调桥接） | `fault::code`（适配层是热路径的一部分） |

## 13. lambda 表达式

**规则：lambda 提取为命名函数。

### 13.1 co_spawn 传 lambda 的方式

**规则：所有lambda 提取为命名函数，通过 `std::move` 传入。

```cpp
// OK：短 lambda 内联

auto handshake = [this, self = shared_from_this()]()
    -> net::awaitable<void>
{
    co_await self->handshake();
};

co_spawn(executor(), std::move(handshake), net::detached);

// 禁止：长 lambda 内联
co_spawn(executor(), [this, self = shared_from_this()]() -> net::awaitable<void> {
    // ... 多行逻辑
    }, net::detached);

// 正确：长 lambda 提取为命名函数，move 传入
auto send_loop = [this, self = shared_from_this()]()
    -> net::awaitable<void>
{
    // ... 多行逻辑
};

co_spawn(executor(), std::move(send_loop), net::detached);
```

### 13.2 co_await 换行

**规则：`co_await` 表达式不自然折行，不强制换行点。**

```cpp
// 短：一行
auto result = co_await handshake(std::move(ctx));

// 超 150 字符：在赋值号或参数处也不断行
auto [ec, protocol] = co_await negotiate(std::move(opts),remote_endpoint);
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
    void start();
    [[nodiscard]] auto is_active() const noexcept 
        -> bool;

protected:
    auto run() 
        -> net::awaitable<void> override;

private:
    auto frame_loop() 
        -> net::awaitable<void>;
    void activate_stream(int32_t id, const h2_stream_info &info);

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
    auto run() 
        -> net::awaitable<void> override;  // override
    void send_data(int32_t id, memory::vector<std::byte> data) override;
};

// 禁止：重写虚函数不加 override
class craft : public core
{
    auto run() 
        -> net::awaitable<void>;  // 缺少 override
};
```

## 19. 构造函数策略

**规则：简单构造直接 public，复杂构造用 `static create()` 工厂。所有构造函数标注 `explicit`。**

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
    explicit craft(transport t, router &r, config cfg, mr);
};
```

**`explicit` 规则**：所有构造函数（含多参数）必须标注 `explicit`，防止花括号隐式转换。

```cpp
// 正确
explicit craft(transport t, router &r, config cfg);

// 禁止：未标注 explicit
craft(transport t, router &r, config cfg);
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

**规则：成员函数中访问成员变量不写 `this->`。**

```cpp
class craft
{
    void send_data(int32_t id, memory::vector<std::byte> data)
    {
        // 不加 this->（成员名本身已足够清晰）
        session_ = nullptr;
        send_channel_.try_send(error_code{}, outbound{id, std::move(data)});
    }
};
```

**初始化列表中参数与成员同名时**：通过重命名参数避免冲突，而不是使用 `this->`。

```cpp
// 正确：参数名加后缀区分
craft(transport trans, router &rt, config cfg)
    : transport_(std::move(trans)), route_(rt), config_(cfg)
{
}

// 禁止：初始化列表中写 this->（非法 C++）
craft(transport trans, router &route, config cfg)
    : transport_(std::move(trans)), this->route_(route)  // 编译错误！
{
}
```

## 22. 类型安全规则

**规则：禁止 bool 函数参数；bool 成员字段允许使用。**

```cpp
// 禁止：bool 函数参数（调用处无法理解语义）
void connect(const string &host, std::uint16_t port, bool use_tls);
// connect("host", 443, true);  // true 是什么意思？

// 正确：用枚举或结构体
enum class tls_mode : std::uint8_t { plain, tls };
void connect(const string &host, std::uint16_t port, tls_mode mode);

// 允许：配置结构体中的 bool 成员（on/off 开关，JSON 兼容）
struct pool_config
{
    bool tcp_nodelay = false;   // OK：配置开关
    bool keep_alive = false;    // OK：配置开关
};

// 允许：运行时状态中的 bool 成员
class connection_pool
{
    bool started_{false};       // OK：内部状态标志
    bool closed_{false};        // OK：内部状态标志
};

// 禁止：隐式转换
struct timeout { std::uint32_t ms; };
void set_timeout(timeout t);
set_timeout(5000);  // 禁止：隐式转换

// 正确：显式构造
struct timeout { explicit timeout(std::uint32_t ms) : ms(ms) {} std::uint32_t ms; };
set_timeout(timeout{5000});
```

**例外**：
- nghttp2 / OpenSSL 等 C 库回调中的 bool 参数（无法修改）
- `std::enable_shared_from_this` 等标准库要求的 bool 参数

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

## 26. noexcept

**规则：析构函数和移动构造/移动赋值必须标注 `noexcept`。** PMR 容器的移动构造 noexcept 依赖上游分配器，按实际情况标注。

```cpp
// 正确：析构函数 noexcept（若默认则编译器自动生成）
~craft() noexcept;

// 正确：移动构造 noexcept
craft(craft &&other) noexcept;

// 注意：PMR 容器的移动构造依赖 allocator 是否 propagate_on_container_move_assignment
// 如果上游分配器不是 noexcept，不要强行标注
```

**不强制**：其他场景按需判断。

## 27. 特殊成员函数

**规则：按资源所有权和协程捕获需求决定 copy/move 策略。** PMR 容器需要特殊处理。

- PMR 容器（`memory::vector` 等）的 copy 需要显式传递 memory resource
- 持有独占资源（socket、session、`nghttp2_session*`）的类应 delete copy，提供 move
- 纯数据 struct 通常 `= default` 即可
- 如果自定义了析构函数，检查是否需要同步自定义 copy/move

## 28. nullptr

**规则：禁止使用 `NULL` 或 `0` 表示空指针。必须使用 `nullptr`。**

```cpp
// 正确
nghttp2_session *session_ = nullptr;
auto ptr = std::shared_ptr<stream>{};

// 禁止
nghttp2_session *session_ = NULL;   // 禁止
nghttp2_session *session_ = 0;      // 禁止
```

## 29. constexpr / consteval

**规则：积极使用 `constexpr`。** 编译期能计算的都应标注。

```cpp
// 正确：常量
constexpr std::uint32_t max_frame_payload = 16384;

// 正确：辅助函数
[[nodiscard]] constexpr auto to_underlying(stream_type t) noexcept -> std::uint8_t
{
    return static_cast<std::uint8_t>(t);
}

// 正确：枚举转换
[[nodiscard]] constexpr auto frame_size(std::uint8_t type) noexcept -> std::size_t
{
    switch (type)
    {
    case 0x00: return 12;
    case 0x01: return 4;
    default:   return 0;
    }
}
```

## 30. 初始化风格

**规则：混合使用 `=` 和 `{}`，按上下文选择最清晰的方式。**

```cpp
// = 初始化：简单值、类内默认值
std::uint16_t port = 0;
bool active = false;
nghttp2_session *session_ = nullptr;

// {} 初始化：容器初始化、避免 narrowing conversion
memory::vector<std::byte> buf{4096};
std::array<std::uint8_t, 4> header{0x00, 0x01, 0x00, 0x00};
```

## 31. static 成员变量

**规则：`.hpp` 中声明，`.cpp` 中定义。** 不使用 `inline static`。

```cpp
// craft.hpp
class craft final : public core
{
    static constexpr std::uint32_t max_streams = 256;
    // ...
};

// craft.cpp（如果需要取地址或 ODR 使用）
// constexpr 成员不需要额外定义，但非 constexpr static 成员需要：
// std::uint32_t craft::max_streams = 256;
```

## 32. 模板实现风格

**规则：模板实现放在 `.tpp` 文件中分离。** `.hpp` 声明，`.tpp` 实现，`.hpp` 末尾 include `.tpp`。

```cpp
// factory.hpp
#pragma once

template <typename T>
class factory
{
public:
    [[nodiscard]] auto create() const 
        -> std::shared_ptr<T>;

private:
    memory::vector<std::byte> buffer_;
};

#include <prism/factory/factory.tpp>  // 末尾 include 实现
```

```cpp
// factory.tpp
#pragma once

template <typename T>
auto factory<T>::create() const -> std::shared_ptr<T>
{
    // 实现...
}
```

**小模板**（< 20 行）可直接 inline 在 `.hpp` 中，不需要 `.tpp`。

## 33. std::move vs std::forward

**规则：严格区分 `std::move` 和 `std::forward`。**

- `std::move`：无条件右值转换，用于已知要转移所有权的场景
- `std::forward`：仅在完美转发模板参数时使用，保持值类别

```cpp
// 正确：std::move — 转移所有权
auto stream = std::move(pending_.at(id));
co_await write(std::move(payload));

// 正确：std::forward — 完美转发
template <typename T>
void emplace(T &&arg)
{
    vec_.emplace_back(std::forward<T>(arg));
}

// 禁止：用 forward 代替 move
co_await write(std::forward<memory::vector<std::byte>>(payload));  // 禁止，用 std::move

// 禁止：用 move 做完美转发
template <typename T>
void emplace(T &&arg)
{
    vec_.emplace_back(std::move(arg));  // 禁止，左值会被意外移动，用 std::forward<T>
}
```

## 34. 代码格式化

### 34.1 行宽

**规则：每行不超过 200 字，这个不是绝对的，具体看上下文来做决策来换行具备美观性。**

### 34.2 缩进

**规则：统一 4 空格缩进，禁止 Tab。**

### 34.3 花括号风格

**规则：混合风格。** 函数/类/结构体/命名空间的开括号 `{` 独占一行，控制结构（`if`/`for`/`while`/`switch`）的也是。

```cpp
// 函数：开括号独占一行
auto craft::run()
    -> net::awaitable<void>
{
    // ...
}


if (active) 
{
    process();
}

for (const auto &entry : pending_) 
{
    co_await handle(entry);
}
```

### 34.4 函数声明换行

**规则：返回类型独占一行。** 尾随返回类型换行后固定缩进 4 空格。

```cpp
// 非void：返回类型独占一行 + 尾随返回换行缩进 4 空格
auto craft::send_data(std::uint32_t stream_id, memory::vector<std::byte> payload)
    -> net::awaitable<void>
{
    // ...
}

// void：直接写 void，不换行
void craft::start()
{
    // ...
}
```

### 34.5 函数参数不换行

**规则：参数不换行。**

```cpp
auto negotiate(const memory::string &host, std::uint16_t port, tls_mode mode)
    -> net::awaitable<result>
{
    // ...
}
```

### 34.6 命名空间格式

**规则：命名空间关键字后换行，开括号独占一行。** 括号后空 1 行。

```cpp
namespace psm::multiplex::h2mux
{

auto craft::run()
    -> net::awaitable<void>
{
    // ...
}

} // namespace psm::multiplex::h2mux
```

### 34.7 空行规则

| 位置 | 空行数 |
|------|--------|
| 函数/方法之间 | 2 行 |
| 逻辑段落之间（函数内） | 1 行 |
| 访问限定符前 | 1 行 |
| `#include` 块与代码之间 | 2 行 |
| 命名空间开括号后 | 1 行 |
| 命名空间闭括号前 | 1 行 |

### 34.8 switch/case 缩进

**规则：`case` 与 `switch` 同级，不额外缩进。** `case` 内代码缩进 4 空格。

```cpp
switch (type)
{
case protocol_type::tcp:
    co_await handle_tcp(stream);
    break;
case protocol_type::udp:
    co_await handle_udp(stream);
    break;
default:
    break;
}
```

### 34.9 单行 if/else

**规则：单行 `if`/`else` 可以不加花括号。** 但多行体必须加。

```cpp
// OK：单行不加
if (!active) return;

// OK：多行必须加
if (auto it = pending_.find(id); it != pending_.end()) 
{
    co_await handle(std::move(it->second));
    pending_.erase(it);
}
```

### 34.10 const 位置

**规则：`const` 在类型左侧。** `const T&` 而非 `T const&`。

```cpp
// 正确
const auto &entry = pending_.at(id);
auto process(const memory::string &input) -> void;

// 禁止
auto &entry = const auto(pending_.at(id));  // 禁止
auto process(memory::string const &input) -> void;  // 禁止
```

### 34.11 初始化列表尾随逗号

**规则：初始化列表、枚举最后一个元素后不加尾随逗号。**

```cpp
// 正确
std::array<std::uint8_t, 3> buf{0x01, 0x02, 0x03};
enum class stream_type : std::uint8_t { tcp, udp, icmp };

// 禁止
std::array<std::uint8_t, 3> buf{0x01, 0x02, 0x03,};  // 禁止
enum class stream_type : std::uint8_t { tcp, udp, icmp, };  // 禁止
```

### 34.12 函数和函数中间是否有换行

**规则：函数和函数中间头文件空一行，源文件空两行**

```cpp
// 正确
void func1() 
{
    // ...
}

void func2() 
{
    // ...
}

// 禁止
void func1() {}
void func2() {}
```

## 35. lambda 提取为命名函数

**规则：lambda 提取为命名函数。** `co_spawn` 传 lambda 用 `std::move`。

```cpp
// 正确：lambda 提取为命名函数
auto handle = [](auto &&arg) -> net::awaitable<void>
{
    // ...
};

co_spawn(io_context_, handle(std::move(payload)), std::launch::async);

// 禁止：lambda 直接传给 co_spawn
co_spawn(io_context_, [](auto &&arg) -> net::awaitable<void>
{
    // ...
}, std::launch::async);
```

## 36. 三目运算符

**规则：禁止使用三目运算符，全部改为if判断**

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
- [ ] 尾随返回类型中 void 用直接 `void func()`，非 void 用 `auto func() -> type`？
- [ ] 局部变量允许 auto，函数参数/类成员禁止 auto 推导？
- [ ] auto 引用严格区分值语义 / const auto& 只读 / auto&& 完美转发？
- [ ] 所有构造函数标注 explicit？
- [ ] .hpp 中 Doxygen 文档，.cpp 中只用 `//` 行注释？
- [ ] .hpp 中无多余 include（优先前向声明）？
- [ ] unique_ptr 前向声明的类型，析构函数在 .cpp 中定义？
- [ ] include 按四组排序，项目内用尖括号 `<prism/...>`？
- [ ] 无 `using namespace std/boost`？
- [ ] 有意义的返回值标注 `[[nodiscard]]`？
- [ ] 热路径容器用 PMR 类型？
- [ ] 虚函数重写标注 override？
- [ ] 使用固定宽度整数类型？
- [ ] 禁止 bool 函数参数，用枚举替代（bool 成员字段允许）？
- [ ] 头文件保护用 `#pragma once`？
- [ ] TODO 格式正确且有标签？
- [ ] 析构函数和移动操作标 noexcept？
- [ ] 使用 `nullptr` 而非 `NULL`/`0`？
- [ ] 编译期能计算的用 constexpr？
- [ ] std::move 用于转移所有权，std::forward 仅用于完美转发？
- [ ] 新增头文件已同步更新聚合头文件？
- [ ] 行宽不超过 200 字符？
- [ ] 缩进 4 空格，无 Tab？
- [ ] 函数/类/命名空间开括号独占一行，控制结构同一行？
- [ ] 返回类型独占一行，尾随返回换行缩进 4 空格？
- [ ] 参数换行对齐到左括号？
- [ ] 命名空间括号独占一行，括号后空 1 行？
- [ ] 函数间 2 空行，逻辑段间 1 空行？
- [ ] switch/case 同级不缩进？
- [ ] const 在类型左侧（`const T&`）？
- [ ] 初始化列表尾随逗号？
- [ ] 函数和函数中间是否有换行?
- [ ] lambda 提取为命名函数，co_spawn 传 lambda 用 std::move？
- [ ] 代码是否有三目运算符？（禁止使用三目运算符）
