## 前置知识：读懂 ForwardEngine 需要知道什么

这份文档的目的：帮助第一次打开仓库的人，快速理解这个项目在做什么、关键概念是什么、主流程怎么走、为什么需要这些模块。

### 1. 这个项目解决什么问题

ForwardEngine 是一个基于 C++23 与 Boost.Asio 的代理引擎原型，目标是把“接入 → 协议识别 → 路由 → 上游连接 → 双向转发”这条链路跑通，并保留清晰的模块边界，便于后续演进。

你可以把它理解为一个会处理两类客户端的代理入口：

- 普通浏览器/代理客户端：走 HTTP 正向代理（明文 HTTP + HTTPS `CONNECT` 隧道）。
- 私有客户端（Obscura）：走 WebSocket(SSL) 的“传输封装”，客户端把目标信息藏在握手阶段（例如 path），服务端解析后建立到上游的连接，再进入加密的双向转发。

注意：项目当前未实现 SOCKS5 代理，因此 `curl -x socks5://...` 会被当作“非 HTTP 流量”走 Obscura 分支并导致握手失败。验证 HTTP/HTTPS 代理请使用：

```bat
curl -v -L -x http://127.0.0.1:8081 http://www.baidu.com
curl -v -L -x http://127.0.0.1:8081 https://www.baidu.com
```

### 2. 目录与模块对照

理解仓库最重要的两个目录：

- `include/forward-engine/*`：主要的对外接口与核心实现（大量 header-only）。
- `src/forward-engine/*`：部分模块的 `.cpp` 实现与可执行程序入口。

关键模块（建议按顺序看）：

- `agent/worker.hpp`：监听端口、accept 客户端连接、创建 `session`。
- `agent/session.hpp`：会话生命周期与主链路（协议识别、处理 HTTP/Obscura、建立隧道）。
- `agent/analysis.hpp/.cpp`：协议识别（peek）、目标解析（host/port/正反向判断等）。
- `agent/distributor.hpp/.cpp`：路由与连接获取（正向/反向/直连等策略入口）。
- `agent/connection.hpp/.cpp`：TCP 连接池与复用（缓存、僵尸检测、空闲超时、上限等）。
- `agent/obscura.hpp`：基于 Beast WebSocket(SSL) 的封装，提供 `handshake/async_read/async_write`。
- `agent/adaptation.hpp`：统一不同 socket/stream 的 `async_read/async_write` 适配层。
- `http/*`：HTTP request/response/header 类型与编解码。
- `trace/spdlog.hpp/.cpp`：基于 `spdlog` 的日志封装（异步文件轮转 + 可选控制台）。
- `transformer/*`：基于 `glaze` 的数据转换封装（当前以 `JSON` 为主）。

### 3. 代理相关核心概念

#### 3.1 正向代理 vs 反向代理

- `正向代理`：客户端告诉代理“我要去哪里”（例如 `CONNECT host:port` 或普通 HTTP 请求行里包含目标信息）。代理负责“帮我连上目标并转发”。
- `反向代理`：客户端认为自己在访问一个固定域名/入口，代理根据内部路由表把请求转发到真实后端（通常需要配置映射表）。

在 ForwardEngine 里，这个分支由 `analysis::resolve` 的结果驱动：会决定走 `route_forward` 还是 `route_reverse`。

#### 3.2 HTTP `CONNECT` 是什么

`CONNECT` 是 HTTPS 代理的常见方式：

- 客户端先发 `CONNECT host:port HTTP/1.1 ...`，请求代理“建立到目标的 TCP 隧道”。
- 代理如果同意，会回 `HTTP/1.1 200 Connection Established\r\n\r\n`。
- 从这之后，双方就把这条 TCP 连接当作“纯字节流隧道”使用；代理不再解析 HTTP，而是做双向搬运。

#### 3.3 “隧道/双向转发”意味着什么

隧道阶段本质就是两个方向各跑一个循环：

- 客户端 → 上游：读客户端字节流，写到上游。
- 上游 → 客户端：读上游字节流，写回客户端。

难点不是“能不能转发”，而是“怎么正确退出”：

- 一边 EOF 了，另一边不能永远卡住。
- 一边异常了，另一边要尽快停工并回收资源。
- 不应把“正常断开”（EOF/取消/连接重置）误判为业务错误。

### 4. Boost.Asio 协程与执行模型（理解代码的关键）

项目大量使用 `net::awaitable<void>` + `co_await` 组织异步流程。

你需要知道几个关键词：

- `executor`：协程恢复执行的上下文（通常来自 `io_context`）。
- `co_spawn`：把一个协程任务投递到事件循环。
- `use_awaitable`：把异步操作转换为 `co_await` 的形式。
- `redirect_error`：把异常风格的错误改为写入 `error_code`（利于区分“正常收尾”与真正错误）。

#### 4.1 隧道阶段“正确退出”的策略

在双向转发时，最常见的坑是：A 方向已经结束（例如 `EOF`/对端关闭），但 B 方向仍阻塞在 `co_await` 的读写里，导致会话迟迟不退出，上游连接也无法及时回收。

ForwardEngine 的隧道阶段采用两层策略叠加，目标是“尽快收敛、稳定回收”：

- 正确转发：每次从源读取 `n` 字节，就只把 `n` 字节写到目标（避免把未使用的缓冲区内容误写出去）。
- 退出传播：当检测到“正常收尾”（例如 `EOF`、`operation_aborted`、`connection_reset` 等）时，会主动关闭对向 socket，让对向正在等待的异步读写尽快返回，从而两条方向协程能快速收敛。

`cancellation_signal/slot` 仍然适用于需要“软取消”的场景（例如某些协议封装层或显式超时控制）；但在纯 TCP 隧道里，“关闭对向”往往是更直接、可预期的退出手段。

### 5. Obscura（传输封装）与“伪装层”要点

Obscura 的思路可以粗略理解为：

- 外层表现为 WebSocket(SSL) 的握手与帧传输（基于 Beast）。
- 在握手阶段，客户端把目标信息放到某个约定的字段里（例如 path），服务端从握手结果解析出目标，然后建立到上游的连接。
- 握手完成后，WebSocket 连接在 SSL 之上变成一条“加密的二进制通道”，后续数据以 WebSocket 帧承载，不再出现传统 HTTP 的 header/method/url。

关于“伪装层”常见的现实约束：

- 对抗/伪装通常关注握手阶段可观察信息（例如 `SNI`）与流量特征（包大小、频率、时序等）。
- SSL 建立后内容不可见，但握手阶段的一些信息仍是明文可观察的，所以需要在“握手看起来像什么”与“后续流量像不像正常业务”上做文章。

### 6. 连接池与复用（为什么需要它）

建立 TCP 连接的成本不低（握手、系统资源、延迟）。项目提供了按目标端点缓存空闲连接的复用能力：

- 连接回收：使用 `monopolize_socket` + 自定义 `deleter`，在智能指针析构时自动回收到池中。
- 健康检查：包含基础僵尸检测与空闲超时淘汰。
- 上限控制：避免单个端点无限积攒空闲连接。

#### 6.1 内存与 PMR（分配策略与使用约定）

ForwardEngine 的大部分“可变长数据”（字符串、向量、哈希表、缓冲区等）都采用 `std::pmr` 体系来做内存管理，核心目标是：

- 把“分配策略”从具体容器/业务逻辑里抽离出来，让调用方决定内存来自哪里
- 在高频路径（会话循环、HTTP 解析、序列化）中尽量复用内存，减少堆分配次数与碎片
- 为“请求级临时对象”提供更便宜的分配与回收方式（例如线性分配器一把释放）

项目对 `pmr` 的统一封装入口在 `include/forward-engine/memory/container.hpp`：

- `memory::resource`：内存资源类型别名（对应 `std::pmr::memory_resource`）
- `memory::resource_pointer`：内存资源句柄类型（用于在接口中传递）
- `memory::current_resource()`：获取当前默认内存资源
- `memory::string` / `memory::vector` / `memory::unordered_map`：项目内统一容器别名

典型用法是“谁需要分配，就接收一个 `mr`，并把它传给需要分配的容器/缓冲区”：

```cpp
#include <memory/container.hpp>

memory::string make_text(memory::resource_pointer mr = memory::current_resource())
{
    memory::string text(mr);
    text.append("hello");
    return text;
}
```

为了让项目内的资源传递保持一致性，有两条约定：

- 业务模块不直接使用 `std::pmr::get_default_resource()`；默认资源统一通过 `memory::current_resource()` 获取
- 对外接口不直接暴露 `std::pmr::memory_resource` 的原始指针写法；统一使用 `memory::resource_pointer` 作为句柄类型

另外，项目提供了两个层次的分配策略入口（`include/forward-engine/memory/pool.hpp`）：

- 全局默认资源池化：`memory::system::enable_global_pooling()` 会把默认资源切换到全局同步池资源
  - 适合：跨线程对象、生命周期不易界定的对象（例如日志、配置、路由表等）
  - 注意：应在进程启动早期调用（例如 `main` 初始化阶段），避免某些模块提前缓存了旧的默认资源句柄
- 请求级临时分配：`memory::frame_arena` 提供“线性分配 + 批量释放”的资源
  - 适合：一次请求/一次循环内的临时字符串、临时缓冲、解析中间态
  - 注意：从 `frame_arena` 分配得到的对象，不应该跨越 `reset()` 之后继续使用；也不应该被缓存到长生命周期结构中

### 7. 如何验证理解是否正确

最快的验证方式是跑测试并对照主链路：

- `session_test`：启动最小代理 + 上游回显/模拟上游断开，验证：
  - `CONNECT` 隧道是否按“读多少写多少”正确转发
  - 一端关闭后，另一端是否能及时被唤醒并收敛退出（避免卡住导致超时）
- `obscura_test`：验证 Obscura 握手、读写、关闭的基本链路。
- `connection_test`：验证连接复用是否命中，以及回收/淘汰是否符合预期。

#### 7.1 常见生命周期陷阱（回归重点）

- `io_context` 必须按 RAII 保证最后析构：任何 `socket`/连接池对象在析构时都可能触发关闭与回收逻辑，若 `io_context` 提前销毁，会出现访问违规。
- `detached` 协程禁止捕获栈引用：需要跨协程存活的对象必须放到 `std::shared_ptr`，否则主协程返回后后台协程访问悬空引用会导致崩溃。

### 8. 新增三方库：`spdlog` 与 `glaze`

#### 8.1 `spdlog` 在项目里怎么用（`trace/spdlog.hpp`）

项目没有直接散落使用 `spdlog::info(...)`，而是集中封装在 `ngx::trace` 命名空间里：

- 初始化：在进程启动时调用一次 `ngx::trace::init(cfg)`。
- 写日志：在任意线程/协程内直接调用 `ngx::trace::debug/info/warn/error/fatal(...)`。
- 关闭：退出前可调用 `ngx::trace::shutdown()` 刷盘并释放异步线程池。

配置结构体为 `ngx::trace::config`，其中字符串字段使用 `ngx::memory::string`（`std::pmr::string`），日志级别使用字符串（例如 `"info"`/`"debug"`）。

示例（与项目 `src/main.cpp` 的用法一致）：

```cpp
#include <fstream>

#include <memory.hpp>
#include <trace.hpp>
#include <transformer.hpp>
#include <core/configuration.hpp>

ngx::memory::string load_file_data(const std::string_view path)
{
    std::ifstream file(path.data(), std::ios::binary);
    if (!file.is_open())
    {
        throw ngx::abnormal::security("system error : {}", "file open failed");
    }

    file.seekg(0, std::ios::end);
    const auto size = file.tellg();
    file.seekg(0, std::ios::beg);

    ngx::memory::string content(size, '\0');
    file.read(content.data(), size);
    return content;
}

ngx::core::configuration mapping_configuration()
{
    ngx::core::configuration config;

    const ngx::memory::string config_string = load_file_data("src/configuration.json");
    (void)ngx::transformer::json::deserialize({config_string.data(), config_string.size()}, config);

    return config;
}

int main()
{
    ngx::memory::system::enable_global_pooling();

    const auto overall_situation_config = mapping_configuration();
    ngx::trace::init(overall_situation_config.trace);

    ngx::trace::info("forward_engine started");
    ngx::trace::shutdown();
    return 0;
}
```

#### 8.2 `glaze` 在项目里怎么用（`transformer/json.hpp`）

`transformer` 模块当前是对 `glaze` 的“薄封装”：统一通过项目的头文件入口引入 `glaze/json.hpp`，并预留 `ngx::transformer::json` 命名空间用于后续收敛项目侧的 `JSON` 读写策略。

在代码侧，你可以直接使用 `glz::read/glz::write`（`glaze` 的统一入口 API），并通过编译期 `opts` 指定格式为 `JSON`：

```cpp
#include <transformer/json.hpp>
#include <cstdint>
#include <string>

struct user_profile
{
    std::string name{};
    std::uint32_t age{};
};

template <>
struct glz::meta<user_profile>
{
    using T = user_profile;
    static constexpr auto value = glz::object("name", &T::name, "age", &T::age);
};

int main()
{
    constexpr glz::opts json_opts{.format = glz::JSON, .error_on_unknown_keys = false};

    user_profile profile{};
    const std::string json_text = R"({"name":"alice","age":18})";

    if (const auto ec = glz::read<json_opts>(profile, json_text))
    {
        return 1;
    }

    std::string out{};
    if (const auto ec = glz::write<json_opts>(profile, out))
    {
        return 1;
    }

    return 0;
}
```

安全与健壮性建议（处理不可信输入时尤其重要）：

- `glz::read` / `glz::write` 返回 `glz::error_ctx`，可以用 `if (ec) { ... }` 判断是否出错，避免依赖异常路径。
- 对外部输入做“上限控制”：可以自定义 `context` 继承并加入 `max_string_length/max_array_size/max_map_size` 等运行时限制，再调用 `glz::read<opts>(..., ctx)` 走受限解析，降低内存/CPU 被恶意 JSON 拖垮的风险。

