---
name: integrate-protocol
description: 添加新代理协议时必须遵循此流程。
---

# Skill: 新协议接入指南

Prism 采用**编译期分发**架构处理多种代理协议。每个协议实现为自由函数，由会话层的 `switch` 语句静态分发。添加新协议时必须遵循以下完整步骤。

## 触发条件

- 用户要求添加新的代理协议
- 修改协议类型枚举
- 修改首包检测逻辑
- 新增协议模块目录

## 架构概览

```
会话层:     接受连接 → 读取首包 24 字节 → 协议检测
                 │
识别层:     外层探测(非 TLS) 或 TLS 内检测
                 │
会话层:     switch(protocol_type) → 协议 handler 自由函数
                 │
协议层:     包装预读 → 创建连接对象 → 握手 → 解析目标地址
                 │
连接层:     拨号建立上游连接 → 双向隧道转发
```

## Handler 接口

每个协议 handler 是一个**自由函数**，不是基类继承。统一的签名约定：

```cpp
namespace project::protocol::<name>
{
    [[nodiscard]] auto handle(context::session &ctx,
                              std::span<const std::byte> preread)
        -> net::awaitable<void>;
}
```

**核心特征**：没有抽象基类、没有动态注册表、没有工厂模式。分发是会话层中的编译期 `switch`。

## 添加新协议的完整步骤

### 步骤 1：添加协议类型枚举

在协议类型枚举中添加新值，同步更新字符串转换函数。

### 步骤 2：实现协议检测

根据协议的首包特征，在两个检测入口之一添加逻辑：

**外层检测**（非 TLS 协议）— 首包 24 字节嗅探：
- 首字节 `0x05` → SOCKS5
- 首字节 `0x16` + `0x03` → TLS
- HTTP 方法前缀 → HTTP
- 其他 → Shadowsocks（排除法）

**TLS 内检测**（运行在 TLS 隧道内的协议）— TLS 载荷分析：
- HTTP 方法检查 → HTTP
- 特定字节布局（version + 命令 + 地址类型）→ 对应协议
- Unknown → unknown

新增协议需要确定首包特征并在对应入口添加判断分支。外层检测只读取 24 字节。

### 步骤 3：创建协议模块

每个协议模块的标准文件结构：

| 文件 | 职责 |
|------|------|
| `process.hpp` / `process.cpp` | 声明和实现 `handle()` — 协议处理主流程 |
| `conn.hpp` / `conn.cpp` | 连接对象类（继承传输装饰器基类） |
| `config.hpp` | 协议专属配置结构体 |
| `constants.hpp` | 线格式常量（命令码、版本号等） |
| `packet.hpp` | 请求/响应数据结构 |
| `framing.hpp` / `framing.cpp` | 线格式编解码 |

### 步骤 4：实现 handle() 函数

所有 handler 遵循统一的处理流程：

```cpp
[[nodiscard]] auto handle(context::session &ctx,
                          std::span<const std::byte> preread)
    -> net::awaitable<void>
{
    // 1. 包装预读传输 — 重放检测阶段已消耗的预读数据
    auto transport = transport::wrap_with_preview(ctx.inbound, preread);

    // 2. 创建协议连接对象
    auto agent = make_conn(std::move(transport), ctx);

    // 3. 协议握手（解析请求、认证、获取目标地址）
    auto result = co_await agent.handshake();

    // 4. 通过连接层建立上游连接 + 双向转发
    auto opts = connect::forward_options{.label = "<name>", .target = result.target};
    co_await connect::forward(ctx, std::move(opts), std::move(agent));
}
```

**连接对象设计**：继承传输装饰器基类，使协议层成为可替换的传输装饰器。握手完成后，连接对象本身就是下游传输，可直接传给隧道转发。

### 步骤 5：接入分发 switch

在会话层的协议分发 `switch` 语句中添加新的 `case` 分支，并 include 对应的 `process.hpp`。

### 步骤 6：配置加载

在配置结构体中添加协议专属字段，更新配置文件 schema。

### 步骤 7：更新构建系统

创建新模块的 `CMakeLists.txt`，在上层 `CMakeLists.txt` 中添加 `add_subdirectory`，创建聚合头文件。

### 步骤 8：编写测试

添加协议的单元测试，覆盖正常握手、认证失败、格式错误等场景。

## 多路复用集成

如果新协议需要支持多路复用：

1. 在握手阶段识别多路复用命令
2. 调用多路复用启动函数建立会话
3. 复用 TCP 流和 UDP 数据报的传输通道

## 协程安全要求

实现新协议时必须遵循 Prism 的协程规范：

1. **禁止阻塞调用**：所有 I/O 操作必须使用 `co_await` 异步完成
2. **生命周期管理**：`co_spawn` 的 lambda 必须捕获 `self`（shared_ptr）保持对象存活
3. **PMR 内存**：热路径容器使用 PMR 类型
4. **错误处理**：热路径使用错误码枚举，致命错误使用异常层次结构
5. **co_await 后引用失效**：恢复后必须重新获取裸指针、迭代器、引用

## 常见反模式（禁止）

````cpp
// ❌ 首包检测过度读取 — 消耗超出必要的数据
auto data = co_await read_exactly(1024);

// ✅ 仅读取必要的首包字节
auto data = co_await peek(24);

// ❌ handler 中使用阻塞 DNS 解析
auto endpoints = resolver::sync_resolve(host);

// ✅ 使用异步解析
auto endpoints = co_await resolver::async_resolve(host);

// ❌ 协议状态机缺少超时保护
while (!complete)
{
    co_await read_frame();  // 无限等待
}

// ✅ 所有握手阶段有超时保护
net::steady_timer timer(executor());
timer.expires_after(std::chrono::seconds(30));

// ❌ 错误响应暴露协议细节
co_await send("ERROR: invalid command byte");

// ✅ 错误响应使用标准格式或安全回落
co_await fallback_to_dest(raw_request);

// ❌ 预读缓冲区未传递给后续阶段
auto preview = co_await peek(24);
// ... 解析协议类型后丢弃 preview
co_await agent.handshake();  // handshake 看不到 preview 数据

// ✅ 预读数据包装回传输层
auto transport = transport::wrap_with_preview(ctx.inbound, preview);
auto agent = make_conn(std::move(transport), ctx);
````

## 安全审计清单

添加新协议后，必须执行以下安全审计：

1. **`replay-audit`** — 验证协议认证的防重放机制（时间戳、nonce、AEAD）
2. **`probe-audit`** — 验证首包特征不会暴露代理身份（固定长度首包、响应行为）
3. **`dpi-audit`** — 验证协议握手不会产生可识别的 TLS 指纹
4. **`leak-audit`** — 验证协议交互中不包含软件标识字符串
5. **`traffic-audit`** — 验证协议流量的包长分布和时序特征不异常
6. **`coroutine-audit`** — 验证实现中无阻塞调用、无互斥锁、生命周期安全
