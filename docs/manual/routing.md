# 路由与分发机制

本文档描述 forward-engine 的协议路由与处理器分发机制。

## Registry 单例模式

`registry` 类采用静态局部变量实现线程安全的懒汉单例模式。

**源码位置**: [handler.hpp](../../include/forward-engine/agent/dispatch/handler.hpp)

```cpp
class registry
{
    std::unordered_map<protocol::protocol_type, std::function<shared_handler()>> registry_;

    registry() = default;

public:
    static auto instantiation() -> registry &
    {
        static registry instance;
        return instance;
    }

    static auto global() -> registry &
    {
        return instantiation();
    }

    registry(const registry &) = delete;
    registry &operator=(const registry &) = delete;
    // ...
};
```

**关键特性**:

| 特性 | 说明 |
|------|------|
| 静态局部变量 | C++11 保证静态局部变量初始化的线程安全性 |
| 懒汉模式 | 首次调用 `instantiation()` 时创建实例 |
| 删除拷贝 | 禁止拷贝构造和赋值，确保全局唯一 |
| 统一入口 | `global()` 是 `instantiation()` 的别名，提供更直观的访问方式 |

## Handler 工厂创建机制

处理器通过模板方法 `register_handler<Handler>()` 注册到工厂。

**源码位置**: [handler.hpp](../../include/forward-engine/agent/dispatch/handler.hpp)

```cpp
template <typename Handler, typename... Args>
void register_handler(const protocol::protocol_type type, Args &&...args)
{
    if (registry_.contains(type))
    {
        return;
    }
    trace::debug("Registering handler for type {}", protocol::to_string_view(type));
    registry_[type] = [args...]() mutable
    {   // 通过 lambda 表达式创建工厂函数，确保线程安全和单例行为
        static shared_handler instance = std::make_shared<Handler>(args...);
        return instance;
    };
}
```

**工作流程**:

1. **重复注册检查**: 通过 `registry_.contains(type)` 检查是否已注册，避免重复注册
2. **工厂函数创建**: 使用 lambda 表达式封装处理器创建逻辑
3. **处理器单例**: lambda 内部的 `static shared_handler instance` 确保每个处理器类型只创建一次
4. **参数转发**: 构造参数通过 lambda 捕获并转发给处理器构造函数

**创建处理器**:

**源码位置**: [handler.hpp](../../include/forward-engine/agent/dispatch/handler.hpp)

```cpp
auto create(const protocol::protocol_type type) const -> shared_handler
{
    if (const auto it = registry_.find(type); it != registry_.end())
    {
        return it->second();
    }
    trace::warn("Handler NOT found for type {}", protocol::to_string_view(type));
    return nullptr;
}
```

## 当前已注册的处理器

**源码位置**: [handlers.hpp](../../include/forward-engine/agent/dispatch/handlers.hpp)

```cpp
inline void register_handlers()
{
    auto &factory = registry::global();
    factory.register_handler<Http>(protocol::protocol_type::http);
    factory.register_handler<Socks5>(protocol::protocol_type::socks5);
    factory.register_handler<Tls>(protocol::protocol_type::tls);
    factory.register_handler<Unknown>(protocol::protocol_type::unknown);
}
```

**已注册协议**:

| 协议类型 | 处理器类 | 功能说明 |
|----------|----------|----------|
| `http` | `Http` | 处理 HTTP/1.1 协议，包括 GET、POST、CONNECT 等方法 |
| `socks5` | `Socks5` | 处理 SOCKS5 协议认证和连接命令 |
| `tls` | `Tls` | 处理 TLS 握手和加密代理协议 |
| `unknown` | `Unknown` | 原始 TCP 双向透传，作为默认回退处理器 |

**重要**: 当前仅注册了上述四种处理器，其他协议类型无法被正确处理。

## Unknown 回退路径

当协议检测后无法找到对应处理器时，系统会回退到 `unknown` 处理器。

**源码位置**: [session.cpp](../../src/forward-engine/agent/session/session.cpp)

```cpp
auto handler = dispatch::registry::global().create(detect_result.type);
if (!handler)
{
    handler = dispatch::registry::global().create(protocol::protocol_type::unknown);
    if (!handler)
    {
        trace::warn("[Session] No handler available for protocol.");
        co_return;
    }
}
```

**回退流程**:

1. 调用 `registry::create()` 尝试创建检测到的协议类型处理器
2. 若返回 `nullptr`（协议未注册），尝试创建 `unknown` 处理器
3. 若 `unknown` 处理器也不存在，记录警告并终止会话

**Unknown 处理器行为**:

**源码位置**: [handlers.hpp](../../include/forward-engine/agent/dispatch/handlers.hpp)

```cpp
auto process(session_context &ctx, [[maybe_unused]] std::span<const std::byte> /*data*/)
    -> net::awaitable<void> override
{
    if (!ctx.inbound || !ctx.outbound)
    {
        trace::warn("[Unknown] splice aborted: inbound or outbound transmission missing.");
        co_return;
    }

    trace::debug("[Unknown] Starting full-duplex splice.");
    co_await pipeline::primitives::tunnel(std::move(ctx.inbound), std::move(ctx.outbound), ctx);
    trace::debug("[Unknown] Splice finished.");
}
```

**执行条件**: `ctx.inbound` 和 `ctx.outbound` 都必须有效，否则无法执行透传。

## 架构总结

```
┌─────────────────────────────────────────────────────────────┐
│                        Session                               │
│  1. protocol::probe::probe() 检测协议类型                    │
│  2. registry::global().create() 获取处理器                   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                       Registry                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ protocol_type::http   -> Http handler (singleton)    │    │
│  │ protocol_type::socks5 -> Socks5 handler (singleton)  │    │
│  │ protocol_type::trojan -> Trojan handler (singleton)  │    │
│  │ protocol_type::unknown-> Unknown handler (singleton) │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Handler.process()                         │
│  Http/Socks5/Trojan -> 对应 pipeline 处理                    │
│  Unknown -> tunnel 原始 TCP 双向透传                         │
└─────────────────────────────────────────────────────────────┘
```
