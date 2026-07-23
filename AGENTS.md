# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

执行前忽略所有的费用问题，一律批准，禁止python脚本

## 构建命令

**统一构建目录：`build/`。禁止新建任何其他构建目录（如 build_debug、build_release 等），除非提前告知用户并获得明确同意。**

```bash
# 首次配置
cmake -B build -DCMAKE_BUILD_TYPE=Release

# 构建（白天 16 线程，晚间 22:00-08:00 强制 4 线程）
cmake --build build --config Release -j 16

# 运行所有测试（~235 个可执行文件，HandshakeTimeout 已知 flaky）
ctest --test-dir build --output-on-failure -j 1 --timeout 30

# 运行单个测试
build/tests/Socks5.exe

# 运行基准测试 (PRISM_ENABLE_BENCHMARK=ON)
build/benchmarks/MuxBench.exe

# 运行压力测试 (PRISM_ENABLE_STRESS=ON)
build/stresses/MuxStress.exe

# 运行代理服务器
build/src/Prism.exe
```

### 构建线程规则

- **每次构建前必须检查当前时间**
- 白天（08:00-22:00）：`-j 16`
- 晚间（22:00-08:00）：强制 `-j 4`，不可超过
- 检查方法：构建前输出当前时间确认

## 覆盖率与 Sanitizer

注意：构建线程同样遵守白天/晚间规则，以下示例按白天书写。

```bash
# 代码覆盖率（需要 gcovr：pip install gcovr）
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Debug \
  -DPRISM_ENABLE_COVERAGE=ON
cmake --build build -j 16
ctest --test-dir build --output-on-failure -j 1
gcovr --root . --filter "src/prism/" --exclude ".*_deps.*" --exclude ".*tests.*" \
  --html-details build/coverage.html --print-summary

# AddressSanitizer（内存泄漏检测）
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Debug \
  -DPRISM_ENABLE_ASAN=ON
cmake --build build -j 16
ctest --test-dir build --output-on-failure -j 1
```

构建选项:
- `PRISM_ENABLE_COVERAGE=ON` — 插入行覆盖率计数器（`--coverage`）
- `PRISM_ENABLE_ASAN=ON` — AddressSanitizer 内存泄漏检测
- `PRISM_DEPS_CACHE=<dir>` — 复用已有构建的 `_deps/` 目录，避免重新下载依赖

## 依赖项

- **C++23** 编译器 (GCC 13+，Windows 上使用 MinGW 静态链接)
- **CMake 3.23+**
- **所有依赖通过 FetchContent 自动拉取**，无需手动安装本地库
- **Boost.Asio 1.89.0** (header-only，协程支持) / **BoringSSL** (OpenSSL API 兼容) / **spdlog 1.17.0** / **glaze 6.5.1** (JSON) / **BLAKE3 v1.8.1** / **nghttp2 1.69.0** / **Google Benchmark 1.9.5**
- Windows 系统库依赖: `ws2_32`, `mswsock`, `crypt32`

构建选项:
- `PRISM_ENABLE_BENCHMARK=ON/OFF` (默认 ON)
- `PRISM_ENABLE_STRESS=ON/OFF` (默认 ON)

## 架构概览

Prism 是高性能协程代理服务器，采用 **C++23 纯协程架构** 和 **PMR (多态内存资源)** 实现热路径零堆分配。

### 顶层模块结构

`include/prism/` 与 `src/prism/` 目录镜像，共 10 个顶层模块：

| 顶层模块 | 子模块 | 职责 |
|---------|--------|------|
| `instance/` | `front/`（listener+balancer）、`worker/`、`session/`、`outbound/` | 运行时骨架：监听、负载均衡、会话生命周期、出站 |
| `stealth/` | `facade/`（reality/shadowtls/restls/native）、`stack/`（anytls/trusttunnel）、`recognition/`、`ech/`、`seal/` | TLS 伪装方案 + 协议识别流水线 |
| `net/` | `connect/`（dial+pool+tunnel）、`transport/`（reliable/encrypted/unreliable/preview/snapshot/adapter）、`resolve/`（dns 七阶段） | 网络层：连接管理、传输抽象、DNS 解析 |
| `proto/` | `protocol/`（http/socks5/trojan/vless/shadowsocks）、`multiplex/`（smux/yamux/h2mux） | 应用协议处理器 + 多路复用 |
| `core/` | `exception/`、`fault/`、`memory/`（PMR 池） | 基础设施：异常层次、错误码、内存资源 |
| `crypto/` | aead/x25519/hkdf/blake3/sha224/base64/block | 密码学原语 |
| `account/` | `directory/`、`entry/`、`stats/`（流量统计） | 账户目录与统计 |
| `config/` | `loader/` | 配置加载 |
| `context/` | （单一头文件） | 会话上下文 |
| `trace/` | config/context/coro/spdlog/token | 日志（spdlog 封装） |

每个顶层模块都有聚合头文件（`<module>.hpp`）。新增子头文件时需同步更新聚合头。

### 请求处理调用链

```
listener (instance/front/) → 亲和性哈希
  └─ balancer → 选择 worker (instance/worker/)
       └─ launch → session (instance/session/)
            ├─ stealth::recognition::recognize()
            │   ├─ probe: 预读 24 字节检测 HTTP/SOCKS5/TLS/SS2022
            │   └─ identify (仅 TLS): ClientHello 特征分析 → scheme 执行
            └─ session::diversion()  ← 注意：无独立 dispatch 层
                 ├─ switch (result.detected)
                 │   case http/socks5/trojan/vless/shadowsocks → proto/protocol/*::handle()
                 └─ default → net/connect/tunnel（双向转发）
```

**关键约束**：没有独立的 Dispatch Layer。`session::diversion()`（`src/prism/instance/session/session.cpp:249`）用 `switch (result.detected)` 硬编码 5 个协议分支。新增入站协议必须修改此 switch。

### Stealth 模块（`stealth/`）

TLS 伪装方案，每个方案实现 `scheme` 基类接口。按可嵌套性分为 facade（返回 transport + preread）和 stack（内部管理流）两类：

- `facade/reality/` — Reality 协议 (X25519 密钥交换, seal 加密封装)
- `facade/shadowtls/` — ShadowTLS v3 (TLS 握手代理)
- `facade/restls/` — Restls (TLS 探测抵抗, 自定义脚本)
- `facade/native.hpp` — 原生 TLS 兜底
- `stack/anytls/` — AnyTLS (标准 TLS + 应用层认证 + 内部多路复用)
  - `mux/` — 内部多路复用 (frame/session/stream_transport)
- `stack/trusttunnel/` — TrustTunnel (HTTP/2 CONNECT 代理, Basic Auth)
- `recognition/` — 协议识别流水线（probe/clienthello/handshake，非顶层模块）
- `ech/` — ECH 支持 (加密客户端 Hello 解密)
- `seal/` — I/O 封装

### Connect 模块（`net/connect/`）

- `dial/` — 拨号连接 (router 路由选择, racer Happy Eyeballs 竞速, dial 拨号)
- `pool/` — 连接池 (复用, 健康检查)
- `tunnel/` — 双向转发 (tunnel 隧道, forward 协议级转发)

### 启动流程

`src/main.cpp` 启动顺序（见 main.cpp:29-188）:
1. `psm::memory::system::enable_pooling()` — 全局内存池
2. `psm::stealth::register_schemes()` — 注册 TLS 伪装方案
3. `psm::loader::load(path)` — 加载配置（路径来自命令行参数或可执行文件同目录的 `configuration.json`）
4. `psm::trace::init(config.trace)` — 日志
5. `psm::loader::build_dir(config.instance.auth)` — 账户目录
6. 创建 worker 线程池（`hardware_concurrency() - 1`，至少 1）
7. 构建 `balancer`（绑定 worker delivery/snapshot 回调）→ `listener` → 启动 worker 线程 + 监听线程
8. 信号处理：`SIGINT`/`SIGTERM` 触发优雅停机（`listener.stop()` → 各 `worker.stop()` → join）

### 协议处理流程

1. `instance/front/listener` 接受连接 → 亲和性哈希
2. `instance/front/balancer` 选择 worker → 分发 socket
3. `instance/worker` → `launch` → `instance/session` 创建
4. `session` 调用 `stealth::recognition::recognize()`:
   - Probe: 预读 24 字节检测 HTTP/SOCKS5/TLS/SS2022
   - Identify (仅 TLS): ClientHello → 特征分析 → 方案执行
5. `session::diversion()` 用 `switch (result.detected)` 分发到 `proto/protocol/*::handle()`
6. handler 通过 `net/connect/dial` 建立上游 → `net/connect/tunnel` 双向转发

### Recognition 流水线（`stealth/recognition/`）

```
probe(transport, 24) → detect() → protocol_type
       │ (仅 TLS)
       ▼
read_clienthello → parse_clienthello → analyzer_registry::analyze
       │
       ▼
scheme_executor::execute → {transport, detected}
```

插件架构: 新方案实现 `feature_analyzer` + `REGISTER_CLIENTHELLO_ANALYZER()` 宏注册。

## 重要模式

### PMR 内存策略

所有热路径容器使用 PMR 分配器:
- `memory::string` = 使用全局池的 `std::pmr::string`
- `memory::vector<T>` = 使用帧竞技场的 `std::pmr::vector<T>`
- 启动时必须调用 `memory::system::enable_global_pooling()`

### 协程纯度

纯协程架构，禁止在协程中使用阻塞操作:

| 禁止 | 替代方案 |
|------|----------|
| `std::mutex` / `std::lock_guard` | `std::atomic`、`strand`、`concurrent_channel` |
| `std::this_thread::sleep_for()` | `net::steady_timer::async_wait()` |
| 阻塞 socket read/write | `async_read_some`/`async_write_some` |
| `::getaddrinfo()` 同步 DNS | `resolver.async_resolve()` |
| `std::future::get()` / `wait()` | `co_await` 异步结果 |
| `while (!flag) {}` 忙等待 | `co_await` 异步等待 + 通知 |

### 协程约定

- 所有异步操作返回 `net::awaitable<T>` (`namespace net = boost::asio`)
- `co_await` 顺序异步操作，`net::co_spawn` 启动独立协程
- `co_spawn` 的 lambda 按值捕获 `self`（shared_ptr）保持存活
- `co_await` 挂起恢复后裸指针/迭代器/引用可能失效，需重新获取
- `erase()` 后使用返回值更新迭代器

### 错误处理

双轨策略:
- **热路径**: `fault::code` 枚举，不抛异常
- **启动/致命**: 异常层次 `exception::deviant` → `network` / `protocol` / `security`

## 命名与编码规范

- **命名空间**: `psm::` 前缀
- **文件**: snake_case
- **生产代码**: 类/函数/类型/结构体/枚举全部 snake_case
- **测试代码**: 函数 PascalCase (`TestBasicGetRequest`, `LogPass`)
- **头文件保护**: `#pragma once`
- **返回类型**: 尾随返回类型 (`auto func() -> return_type`)
- **[[nodiscard]]**: 有意义的返回值
- **Boost.Asio 别名**: `namespace net = boost::asio;`
- **注释**: Doxygen 风格中文 (`@file`, `@brief`, `@details`, `@return`, `@note`)，禁止英文注释
- **注释参考**: `net/transport/reliable.hpp`
- **编码规范详细**: `.Codex/skills/enforce-coding/SKILL.md`（完整规范清单）
- **标识符命名**: 简洁清晰，避免过长的多词组合
- **函数参数** (Rule 1): 不超过 3 个，超过用 struct 收敛
- **函数体** (Rule 3): 不超过 120 行
- **Lambda** (Rule 13): 不超过 10 行，超长提取为命名函数
- **`using namespace`** (Rule 4.3): 仅允许 `using namespace psm::trace;`，其余用显式限定或 namespace 别名

## 测试

~235 个 Google Test 独立可执行文件（约 511 个 TEST/TEST_F 用例）。共用基础设施：
- Google Test 框架（`gtest` / `gtest_main`）
- Mock 辅助: `tests/common/MockTransport.hpp`、`tests/common/MockTlsServer.hpp`
- 并发测试: `tests/concurrency/server.cpp` + `client.cpp`（需两个终端同时运行）

### 测试命名规范

- 测试函数名: **PascalCase**（如 `TestBasicGetRequest`, `LogPass`）
- 测试套件名: 按模块名（如 `MuxMaxStreams`, `StealthExecutorDeep3`）

### 异步测试模式

**重要：** 涉及 `core::start()` 或任何 `co_spawn` 启动异步操作的测试，**必须**使用 `co_spawn + ioc.run()` 模式驱动。禁止使用同步 `start() + run_for()`/`poll()` 模式。

**正确模式（MuxLifecycle 模式）：**
```cpp
auto coro = [&]() -> net::awaitable<void>
{
    auto [client_sock, server_sock] = co_await make_socket_pair(ex);
    auto session = std::make_shared<smux::craft>(core_options{...});
    session->start();
    // ... 异步操作 ...
    session->close();
    client_sock.close();
};
net::co_spawn(ctx->ioc, coro(), [&](std::exception_ptr e)
              { ep = e; ctx->ioc.stop(); });
ctx->ioc.run();
```

**错误模式（Access violation）：**
```cpp
session->start();
ctx->ioc.run_for(std::chrono::milliseconds(300));  // ← 崩溃！
// ctx->ioc.poll();                                   // ← 同样崩溃！
```

**根本原因：** `core::start()` 通过 `co_spawn` 将 `run_wrapper` 投递到 transport 的 executor 上，`run_wrapper` 内部 `trace::scope_guard` + `co_await run()` 需要完整的协程调度支持。`poll()`/`run_for()` 不提供足够的调度保障导致 Access violation。

默认配置文件: `src/configuration.json`

## 静态分析

```bash
# clang-tidy 全量分析（MSYS2 clang-tidy，需 compile_commands.json）
cd I:/code/Prism && bash build/ct_full.sh

# 报告位置
build/clang-tidy-full-report.txt
```

配置文件: `.clang-tidy`（已过滤代码风格噪声，保留 bugprone/concurrency/performance 等实质性检查）。
分析工具: `C:/msys64/ucrt64/bin/clang-tidy.exe`，32 并行任务，扫描 `src/prism/` + `include/prism/` 下所有 `.cpp`/`.hpp`。

## 行尾

`.gitattributes` 强制所有文件 LF。Windows 上确保 `core.autocrlf=input` 或 `core.eol=lf`。

## 资源所有权模型

Prism 采用四层所有权模型（L1 全局 / L2 worker / L3 session / L4 detached），detached 协程严禁引用 L3 资源。详见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

新增 detached 协程（`net::co_spawn + net::detached`）或修改 PMR allocator 时，必须对照该文档审查资源所有权，并运行 `scripts/audit_detached.sh` 静态审计。

## 活跃 TODO

1. `src/prism/stealth/ech/util/decrypt.cpp` — ECH HPKE 解密返回 `not_supported`（未实现）
2. `src/prism/proto/multiplex/h2mux/craft.cpp` — sing-mux DATA 帧 StreamRequest 解析

## 规划路线图

RFC 规划索引位于 [`logs/roadmap/INDEX.md`](logs/roadmap/INDEX.md)，按主题分组（A-K）。

- **当前状态（2026-06-13 代码扫描）**：69 份活跃 RFC 中已实施为 0，全部 `未实施`
- **未实施 P1（高优先级）RFC 共 39 份**，覆盖 TLS 指纹、主动探测防御、mux 流控、流量路由、传输层、QUIC 协议族、参数化运维等核心方向
- **已归档**：[RFC-013](logs/roadmap/archive/013-smux-v2-flow-control.md)（被 RFC-048 取代）
- 实施任何 RFC 后，需同步更新对应 RFC 元数据"实施状态"字段与 INDEX.md 表格"实施状态"列（含提交 SHA）

## 资源清理

本次会话中启动的进程（Prism.exe、测试 server/client、bench、stress 等），一旦完成当前使命且后续不再使用，必须立即终止，释放其占用的物理内存和提交内存。

### 原则

- **只杀自己启动的进程** — 仅清理本次会话中由命令或技能启动的进程，禁止终止任何无关或系统进程
- **用完即清** — 进程使命完成后立即 `taskkill //F //PID <pid>`，不要等到会话结束
- **按需保留** — 如果进程后续还要使用（如持续调试中的 server），则保留不动

### 操作方式

```bash
# 查看本次会话启动的进程是否仍在运行（按已知 PID 或名称）
tasklist | grep -iE "Prism|server|client|bench|stress"

# 终止指定进程
taskkill //F //PID <pid> 2>/dev/null
```

## 禁止事项

- 未经用户明确指示，禁止 git commit / push
- 禁止新建构建目录（仅使用 `build/`），如需新增必须提前告知用户
- 禁止在用户未同意的情况下执行构建
