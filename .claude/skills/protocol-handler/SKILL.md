---
name: protocol-handler
description: 新协议接入指南。在 Prism dispatch 层添加新代理协议时必须遵循此流程，涵盖协议检测、handler 注册、pipeline 实现、配置加载的完整步骤。
---

# Skill: 新协议接入指南

Prism 采用 **dispatch 层** 架构处理多种代理协议。每个协议通过统一的 handler 接口注册到工厂，由 session 层在协议探测后动态创建。添加新协议时必须遵循以下完整步骤。

## 触发条件

- 用户要求添加新的代理协议（如 SS2022、VLESS、Reality）
- 修改 `protocol_type` 枚举
- 修改协议检测逻辑（`analysis::detect`）
- 新增 handler 类

## 架构概览

```
Session 层:  session::start() → probe 24 字节 → detect() → protocol_type
Dispatch 层: registry::create(type) → handler 实例
Pipeline 层: handler::process() → parse → auth → resolve → dial → tunnel
```

关键文件关系：

| 层次 | 文件 | 职责 |
|------|------|------|
| 协议类型 | `include/prism/protocol/analysis.hpp` | `protocol_type` 枚举定义 |
| 协议检测 | `src/prism/protocol/analysis.cpp` | `detect()` 函数，嗅探首包判断协议 |
| Handler 基类 | `include/prism/agent/dispatch/handler.hpp` | 抽象基类，3 个纯虚函数 |
| 注册表 | `include/prism/agent/dispatch/registry.hpp` | 单例工厂，`register_handler<T>` + `create` |
| 全部注册 | `include/prism/agent/dispatch/handlers.hpp` | `register_handlers()` 统一注册入口 |
| Pipeline | `src/prism/pipeline/protocols/` | 各协议的具体 pipeline 实现 |

## Handler 接口

每个协议 handler 必须继承 `handler` 并实现 3 个纯虚函数：

```cpp
// include/prism/agent/dispatch/handler.hpp
class handler : public std::enable_shared_from_this<handler>
{
public:
    virtual ~handler() = default;

    // 主处理流程：解析请求 → 认证 → 解析目标 → 建立连接 → 双向转发
    virtual auto process(session_context ctx) -> net::awaitable<void> = 0;

    // 协议类型标识
    virtual auto type() const -> protocol_type = 0;

    // 协议名称（用于日志）
    virtual auto name() const -> std::string_view = 0;
};
```

## 添加新协议的完整步骤

### 步骤 1：添加协议类型枚举

文件：`include/prism/protocol/analysis.hpp`

```cpp
enum class protocol_type
{
    unknown,
    http,
    socks5,
    trojan,
    // 新增协议
    shadowsocks,
};
```

### 步骤 2：实现协议检测

文件：`src/prism/protocol/analysis.cpp`，修改 `detect()` 函数。

当前检测逻辑（首包嗅探）：
- `0x05` → SOCKS5
- `0x16` (TLS ClientHello) → Trojan（TLS 外层）
- HTTP 方法前缀 (`GET`, `POST`, `CONNECT` 等) → HTTP
- 其他 → unknown

新增协议需要确定其首包特征并在 `detect()` 中添加判断分支。注意：`detect()` 只读取首包前 24 字节，不能消耗更多数据。

### 步骤 3：定义协议配置

文件：`include/prism/loader/config.hpp`

在 `config` 结构体中添加协议专属配置字段。如果协议需要密码、密钥、头部模板等，添加对应的配置结构。

### 步骤 4：实现协议库

位置：`include/prism/protocol/<protocol_name>/`

创建协议专属的命名空间和类型：
- 帧格式解析（`frame.hpp`/`frame.cpp`）
- 加密/认证逻辑（如适用）
- 请求/响应数据结构

参考 `include/prism/protocol/trojan/` 的组织方式。

### 步骤 5：实现 Pipeline

文件：`src/prism/pipeline/protocols/<protocol_name>.cpp`

实现协议的完整处理流程：
1. 解析客户端请求（读取目标地址、命令类型）
2. 认证验证
3. 通过 `router_.async_forward()` 建立上游连接
4. 如有需要，向客户端发送连接响应
5. 调用 `tunnel` 进行双向透明转发

对于需要多路复用的协议，参考 Trojan 的 cmd=0x7F 分支触发 mux 会话。

### 步骤 6：实现 Handler

文件：`include/prism/agent/dispatch/handlers.hpp`（header-only）

```cpp
class <protocol>_handler : public handler
{
public:
    explicit <protocol>_handler(session_context ctx);
    auto process(session_context ctx) -> net::awaitable<void> override;
    auto type() const -> protocol_type override { return protocol_type::<name>; }
    auto name() const -> std::string_view override { return "<Protocol>"; }
};
```

Handler 是 header-only 的，直接调用 pipeline 函数。参考现有 handler 的实现模式。

### 步骤 7：注册 Handler

文件：`include/prism/agent/dispatch/handlers.hpp`，在 `register_handlers()` 函数中添加：

```cpp
inline void register_handlers()
{
    registry::global().register_handler<http_handler>(protocol_type::http);
    registry::global().register_handler<socks5_handler>(protocol_type::socks5);
    registry::global().register_handler<trojan_handler>(protocol_type::trojan);
    // 新增
    registry::global().register_handler<<protocol>_handler>(protocol_type::<name>);
}
```

### 步骤 8：配置加载

文件：`src/prism/loader/` 或 `src/prism/transformer/`

确保 JSON 配置文件中的新字段能被正确解析和加载到 `config` 结构体。更新 `configuration.json` schema。

### 步骤 9：更新 CMakeLists

文件：`src/CMakeLists.txt`

将新增的 `.cpp` 源文件添加到构建列表。

### 步骤 10：更新聚合头文件

确保 `include/prism/protocol.hpp`（聚合头文件）包含新增的协议子头文件。

### 步骤 11：编写测试

在 `tests/` 下添加协议的单元测试和集成测试。

## 协程安全要求

实现新协议时必须遵循 Prism 的协程规范：

1. **禁止阻塞调用**：所有 I/O 操作必须使用 `co_await` 异步完成
2. **生命周期管理**：`co_spawn` 的 lambda 必须捕获 `self`（shared_ptr）保持对象存活
3. **PMR 内存**：热路径容器使用 `memory::vector<T>` 和 `memory::string`
4. **错误处理**：热路径使用 `fault::code`，致命错误使用异常层次结构

## 协议处理生命周期

```
session::start()
  ├─ probe: 预读 24 字节首包
  ├─ detect(): 判断 protocol_type
  ├─ registry::create(type, ctx): 创建 handler
  └─ handler::process(ctx)
       ├─ 解析请求（读取完整协议头）
       ├─ 认证检查
       ├─ 解析目标地址（host:port）
       ├─ router_.async_forward(host, port): 建立上游连接
       ├─ 发送协议响应（如 SOCKS5 连接成功回复）
       └─ tunnel::run(downstream, upstream): 双向透明转发
```

## 现有协议参考

| 协议 | Handler | Pipeline | 特点 |
|------|---------|----------|------|
| HTTP | `http_handler` | `protocols/http.cpp` | CONNECT 方法代理，支持 Basic 认证 (Proxy-Authorization) |
| SOCKS5 | `socks5_handler` | `protocols/socks5.cpp` | 完整 RFC 1928/1929，支持用户名密码认证 |
| Trojan | `trojan_handler` | `protocols/trojan.cpp` | TLS 外层，支持 mux（cmd=0x7F 触发 yamux/smux） |

## 注意事项

- **首包探测限制**：`detect()` 只有 24 字节可用，新协议必须有明确的首包特征
- **复用 tunnel**：大多数协议最终都调用同一个 `tunnel::run()` 进行双向转发，不需要重复实现
- **多路复用集成**：如果新协议支持多路复用，复用 `multiplex::duct`（TCP 流）和 `multiplex::parcel`（UDP 数据报）
- **mux 会话触发**：参考 Trojan 通过 cmd 字段触发 mux 的模式
