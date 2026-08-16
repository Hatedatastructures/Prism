# psmtest 协议库规范（tests/common）

> 本规范描述 `tests/common/`（psmtest 库）的**真实架构**与统一设计标准。
> 参考 Go 参考实现（mihomo transport / sing 系列）的接口模式。目标：
> **可替换主项目 src/prism 的新一代架构**（NEXTGEN_TASK.md）。
> 更新：2026-08-16（T1-6，按真实架构重写）。

## 1. 目录结构与模块归属

```
tests/common/
  core/                无外部依赖的基础层
    memory/ fault/ exception/ crypto/ coroutine/ rate/
    error.hpp  transmission.hpp  authenticator.hpp  flat_buffer.hpp  parser.hpp
    session_base.hpp  codec_traits.hpp  byte_span.hpp  role.hpp  programmable_transport.hpp
    transport/        reliable/unreliable/encrypted/pad/preview/snapshot/
                      memory_stream/socket_stream/udp_transmission/connector/
                      algorithm/bench/stream
    protocol/         address/form/framing/read/mux/target
    http2/ http3/ quic/   （骨架/接口，T2 自包含化）
    middleware/       pipeline/context + builtin(dial/mux/pad/relay)
    diagnose/         context/log
  proxy/              7 协议（vmess/vless/trojan/shadowsocks2022/socks5/hysteria2/tuic）
  stealth/            7 伪装方案（reality/shadowtls/restls/anytls/trusttunnel/ws/gun）
  mux/                smux/yamux/h2mux（模板化 frame_codec + client/server/session）
```

### 1.1 协议目录（proxy/stealth）

每个协议一个目录，**聚合头四件套**（扁平结构，无 codec/kdf/chunk 子目录）：

```
tests/common/proxy/<proto>/
  types.hpp   — 常量、枚举、标志位、配置结构
  codec.hpp   — 帧编解码（build/parse 纯函数 + 解析状态机）
  conn.hpp    — 连接装饰器（继承 transmission，模板化 memory_policy）
  dgram.hpp   — UDP 数据报封装（需要时）
  <proto>.hpp — 聚合头（re-export 上述）
```

伪装方案（stealth/）同构：types/codec/conn + 聚合头（无 dgram 或按需）。

### 1.2 多路复用（mux/）

```
tests/common/mux/smux/（yamux/h2mux 同构）
  types.hpp   — 帧类型/常量
  codec.hpp   — 帧编解码（模板化 frame_codec 策略）
  session.hpp — 会话状态机（流表/帧循环/背压，模板注入 codec）
  client.hpp  — 客户端封装（open_stream 视角）
  server.hpp  — 服务端封装（accept_stream 视角）
  smux.hpp    — 聚合头
```

共享 `mux/session.hpp` 模板框架 + `mux/stream.hpp`（流句柄）。

## 2. 接口设计（统一 transmission + 模板策略 + 多态）

### 2.1 传输抽象（core/transmission.hpp）

单一 `psmtest::transmission` 虚接口（全部模块统一使用）：

| 方法 | 语义 |
|---|---|
| `async_read_some(span<byte>, ec)` | 异步读，返回实际字节数 |
| `async_write_some(span<const byte>, ec)` | 异步写，返回实际字节数 |
| `async_read/async_write` | 组合操作（读满/写满） |
| `close()` / `cancel()` | 全关 / 取消挂起操作 |
| `shutdown()` | 半关写方向（对端读 EOF） |
| `set_timeout(ms)` | 读超时（0=禁用） |
| `is_open()` | 打开状态 |
| `next_layer()` / `lowest_layer<T>()` | 装饰器链导航 |
| `transport_type()` | tcp / udp |
| `release()` | 释放底层所有权 |

- **装饰器模式**：协议 conn 继承 transmission 包装底层（preview → conn → reliable）。
- **叶子节点**：memory_stream / socket_stream / reliable / unreliable / udp_transmission。
- **concept**：`transmission_like` / `stream` 约束模板参数。
- 生命周期：`shared_transmission`（shared_ptr）管理。

### 2.2 会话接口（core/session_base.hpp）

虚拟流/会话的统一接口（mux stream_handle 实现）：

| 方法 | 语义 |
|---|---|
| `read_some(span<u8>)` | 读，返回字节数（0=EOF/超时/取消） |
| `write_all(span<const u8>)` | 全写，返回错误码 |
| `shutdown()` | 半关（发 FIN） |
| `close()` / `cancel()` | 关闭 / 取消 |
| `set_timeout(ms)` | 读超时 |
| `is_open()` | 状态 |
| `executor()` | 执行器 |

### 2.3 协议 conn 模板化

```cpp
template <psmtest::memory::memory_policy Memory = psmtest::memory::session_memory<>>
class conn : public transmission, public std::enable_shared_from_this<conn<Memory>>;
```

- `Memory` 注入会话内存策略（arena 复用零分配）。
- 聚合头内联 `connect(shared_transmission, config)` / `accept(shared_transmission, config)` 工厂。

## 3. 错误体系边界（T1-2 决策）

| 体系 | 用途 | 定义 |
|---|---|---|
| `core/error.hpp` | **协议编解码**（细粒度：need_more/unexpected_eof/bad_length/bad_auth/...） | `psmtest::error`（boost::system::error_category） |
| `core/fault/code.hpp` | **中间件/流程**（粗粒度：io_error/timeout/canceled/auth_failed/...） | `psmtest::fault::code` |

- 桥接：`fault::to_code(boost::system::error_code)` 已支持 error 转换。
- **禁止第三种体系**；新错误优先入 error.hpp（编解码）或 fault（流程）。

## 4. 认证抽象（core/authenticator.hpp）

```cpp
struct auth_result { bool ok; std::string identity; };
class authenticator {
    virtual auto check(std::string_view identity, std::string_view secret) const -> auth_result = 0;
};
```

- `static_authenticator` / `reject_authenticator` 内置。
- 已接入：socks5/trojan/vless/hysteria2（vmess/ss2022 密码学校验豁免、tuic 无认证）。

## 5. 中间件管线（core/middleware/）

```
pipeline（add/run）→ context（inbound/outbound/target/detected/traffic/identity/pad_cfg）
  ├─ builtin/dial    （默认函数 = outbound 拨号）
  ├─ builtin/mux     （多路复用判断）
  ├─ builtin/pad     （按 detected 决定是否填充）
  └─ builtin/relay   （双向转发 + 统计）
```

- 消费 `ctx.identity`（认证结果）与 `ctx.traffic`（流量统计回调）。
- 超时/背压：T4-5 扩展（context.timeout 字段，relay 优先于构造参数）。

## 5.1 中间件扩展（T4/T5）

```
builtin/auth      （authenticator 校验 → ctx.identity；T4-1）
builtin/throttle  （token_bucket 限速 → blocked；T5-4）
builtin/ban       （失败计数封禁，窗口过期解封；T5-4）
```

## 5.2 运行时骨架（core/runtime/，T4/T5）

```
session            （recognize → prepare → pipeline auth/dial/relay；T4-2）
listener           （TCP accept + 亲和性分发 FNV-1a + 会话工厂；T4-3）
statistics         （traffic_counter：identity 维度聚合；T4-4）
per_worker_traffic （alignas(64) 原子槽 + identity 聚合；T5-2）
session_registry   （COW 值拷贝快照，严禁 L3 引用；T5-7）
```

## 5.3 账户与限速（core/account/ + core/rate/，T5）

```
account/cow_map    （模板化 COW：快照 + CAS 更新；O3/O6 复用）
account/directory  （entry 原子活跃 + lease RAII + try_acquire CAS；T5-3）
account/authenticator（directory_authenticator：未禁用/未过期/配额；T5-1）
rate/token_bucket  （惰性补发 + 单 CAS；T5-4）
```

## 5.4 网络协议补充（T3）

```
net/udp_relay   （D5：动态关联会话表 + 超时回收 + 端口不匹配丢弃 + 单侧关闭终止）
http/parser     （CONNECT 请求解析：method/target/Host/Proxy-Authorization）
http/conn       （CONNECT 握手：read_request + send_response + check_basic(407)）
```

## 5.5 运营与可观测（T5/T6）

```
api/api_manager   （资源树契约：list_sessions/traffic_summary/config_snapshot；O7）
settings/json     （自包含 JSON 解析：递归下降 + 深度 32 + 转义）
settings/loader   （配置加载校验：必填/范围/类型；生产用 glaze）
diagnose/observability（HDR 指数桶 + EWMA + 1/N 采样 SPSC ring；O5）
```

## 6. 命名空间与编码规范

- **全库 `psmtest`**；禁止历史命名体系混用与 psm:: 混用。
- snake_case；Doxygen 中文注释（@file/@brief/@details/@return）。
- 头文件保护 `#pragma once`；聚合头同步（新增子头必须入聚合头 + CMake）。

## 7. 测试三层模型

1. **codec 纯函数**：build/parse 无 I/O 单测。
2. **回环 session**：client/server 配对（memory_stream 或 loopback socket）。
3. **错误矩阵**：坏数据/边界/超时/取消/错误码传播。

异步测试必须 `co_spawn + ioc.run()` 模式（MuxLifecycle 模式），禁止 `run_for/poll` 驱动。

## 8. 构建（CMake）

- 单一 `prism_ngx` INTERFACE 库（tests/common/CMakeLists.txt）。
- `prism_test_common` / `vmtest_common` 为兼容别名（指向 prism_ngx）。
- 全部头文件列于 target_sources（G7 完整性门禁）。
