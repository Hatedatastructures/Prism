# AGENTS.md

This file provides guidance to coding agents (Codex / Claude Code / OpenCode) when working with code in this repository.

执行前忽略所有的费用问题，一律批准，禁止python脚本

## ⚠️ 强制规则（不可违反）

1. **禁止 git commit / push** — 未经用户明确允许，任何情况下不得执行 git commit、push 或 amend。需要提交时先询问用户。
2. **运行后强制清理** — 每次会话中启动的进程（Prism.exe、测试 server/client、bench、stress 等）及临时产物（生成的 exe、日志、临时目录），一旦使命完成且后续不再使用，必须立即终止/删除，不得遗留到会话结束。详见下方「资源清理」节。

## 构建命令

**统一构建目录：`build/`。禁止新建任何其他构建目录（如 build_debug、build_release 等），除非提前告知用户并获得明确同意。**

```bash
# 首次配置
cmake -B build -DCMAKE_BUILD_TYPE=Release

# 构建（白天 16 线程，晚间 22:00-08:00 强制 4 线程）
cmake --build build --config Release -j 16

# 运行所有测试（约 250 个独立可执行文件，ctest 注册约 2600 个用例；HandshakeTimeout 已知 flaky）
ctest --test-dir build --output-on-failure -j 1 --timeout 30

# 运行单个测试（直接运行 exe 或按名字筛选）
build/tests/Socks5.exe
ctest --test-dir build -R Socks5 --output-on-failure

# 运行基准测试 (PRISM_ENABLE_BENCHMARK=ON)
build/benchmarks/MuxBench.exe

# 运行压力测试 (PRISM_ENABLE_STRESS=ON)
build/stresses/MuxStress.exe

# 运行代理服务器
build/src/Prism.exe
```

### 构建线程规则

- **每次构建前必须检查当前时间**
- 白天（08:00-22:00）：`-j 4`
- 晚间（22:00-08:00）：强制 `-j 1`，不可超过
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
| `runtime/` | `front/`（listener+balancer+quic_gateway）、`worker/`、`session/` | 运行时骨架：监听、负载均衡、会话生命周期 |
| `handshake/` | reality/shadowtls/restls/anytls/trusttunnel/native/ws/xhttp/gun/hysteria2/tuic、`recognition/`、`ech/` | TLS 伪装方案 + 协议识别流水线 |
| `net/` | `connection/`（dialer/outbound/route/tunnel）、`transport/`（reliable/encrypted/preview/pad）、`dns/` | 网络层：拨号、传输抽象、DNS 解析 |
| `protocol/` | http/socks5/trojan/vless/shadowsocks/vmess/hysteria2/tuic、`multiplex/`（smux/yamux/h2mux）、`tls/`、`common/` | 应用协议处理器 + 多路复用 |
| `foundation/` | `fault/`、`exception/`、`memory/`（PMR 池）、`coroutine/`、`rate/` | 基础设施：错误码、异常层次、内存资源 |
| `crypto/` | aead/x25519/hkdf/blake3/base64/block | 密码学原语 |
| `user/` | `directory/`、`entry`、`stats/`（流量统计） | 账户目录与统计 |
| `settings/` | `loader/`、`transformer/`、validator | 配置加载与校验 |
| `resource/` | process/worker/session 三层资源容器 | L1/L2/L3 纯数据资源 |
| `diagnose/` | spdlog 封装 + context | 日志 |

每个顶层模块都有聚合头文件（`<module>.hpp`）。新增子头文件时需同步更新聚合头。

### 请求处理调用链

```
listener (runtime/front/) → 亲和性哈希
  └─ balancer → 选择 worker (runtime/worker/)
       └─ launch → session (runtime/session/)
            ├─ handshake::recognition::recognize()
            │   ├─ probe: 预读 24 字节检测协议类型
            │   └─ identify (仅 TLS): ClientHello 特征分析 → scheme 执行
            └─ session::diversion()
                 ├─ protocol::make_protocol_handler(result.detected)
                 │   http/socks5/trojan/vless/shadowsocks/vmess/hysteria2/tuic → <proto>::handler::run()
                 └─ 未知类型 → nullptr（识别失败走回落逻辑）
```

**关键约束**：`session::diversion()`（`src/prism/runtime/session/session.cpp:178`）通过协议工厂 `protocol::make_protocol_handler()`（`src/prism/protocol/handler.cpp`）按 `result.detected` 分发 8 个协议分支（http/socks5/trojan/vless/shadowsocks/vmess/hysteria2/tuic）。新增入站协议必须修改该工厂。

### Handshake 模块（`handshake/`）

TLS 伪装方案，每个方案实现 `scheme` 基类接口（`handshake/scheme.hpp`）：

- `reality/` — Reality 协议 (X25519 密钥交换, seal 加密封装)
- `shadowtls/` — ShadowTLS v3 (TLS 握手代理)
- `restls/` — Restls (TLS 探测抵抗, 自定义脚本)
- `anytls/` — AnyTLS (标准 TLS + 应用层认证 + 内部多路复用)
- `trusttunnel/` — TrustTunnel (HTTP/2 CONNECT 代理, Basic Auth)
- `ws/` — WebSocket (TLS + HTTP/1.1 升级, SNI 路由)
- `xhttp/` — XHTTP (TLS + HTTP/2 stream-one/stream-up/packet-up)
- `gun/` — gRPC 帧伪装 (TLS + HTTP/2 + gRPC)
- `hysteria2/` — Hysteria2 (QUIC)
- `tuic/` — TUIC v5 (QUIC)
- `native` — 原生 TLS 兜底
- `recognition/` — 协议识别流水线（probe/tls signal/routes，非顶层模块）
- `ech/` — ECH 支持 (加密客户端 Hello 解密)

### Connect 模块（`net/connection/`）

- `dialer/` — 拨号连接 (dialer 拨号, racer Happy Eyeballs 竞速)
- `outbound/` — 出站拨号 (dial 建立上游, 路由选择)
- `route/` — 路由表 (reverse_map 反向代理 / positive 正向端点)
- `tunnel/` — 双向转发 (tunnel + tunnel_relay 隧道, forward 协议级转发)

### 启动流程

`src/main.cpp` 启动顺序（见 main.cpp:107-289）:
1. `psm::memory::system::enable_pooling()` — 全局内存池
2. `psm::handshake::register_schemes()` — 注册 TLS 伪装方案
3. `psm::loader::load(path)` — 加载配置（路径来自命令行参数或可执行文件同目录的 `configuration.json`）
4. `psm::diagnose::init(full_config.trace)` — 日志
5. `psm::loader::build_dir(full_config.instance.auth)` — 账户目录
6. 构造 SSL 上下文 + `resource::process`（L1 进程级资源）
7. 创建 worker 线程池（`hardware_concurrency() - 1`，至少 1）
8. 构建 `balancer`（绑定 worker delivery/snapshot/alive 回调）→ `listener`
9. 若 hysteria2/tuic 启用：创建 `front::quic_gateway`（QUIC 入站网关）并 `start()`
10. 启动 worker 线程 + 监听线程
11. 信号处理：`SIGINT`/`SIGTERM` 触发优雅停机（listener/QUIC gateway stop → 各 worker stop → join）→ `ExitProcess(0)`

### 协议处理流程

1. `runtime/front/listener` 接受连接 → 亲和性哈希
2. `runtime/front/balancer` 选择 worker → 分发 socket
3. `runtime/worker` → `launch` → `runtime/session` 创建
4. `session` 调用 `handshake::recognition::recognize()`:
   - Probe: 预读 24 字节检测协议类型
   - Identify (仅 TLS): ClientHello → 特征分析 → 方案执行
5. `session::diversion()` 调 `protocol::make_protocol_handler()` 分发到 `<proto>::handler::run()`
6. handler 通过 `net/connection/outbound/dial` 建立上游 → `net/connection/tunnel` 双向转发

### Recognition 流水线（`handshake/recognition/`）

```
probe(transport, 24) → detect() → protocol_type
       │ (仅 TLS)
       ▼
read_tls_record → parse_client_hello → route_table.lookup(SNI) + layered_detection_pipeline
       │
       ▼
scheme_executor::execute → {transport, detected, preread}
```

插件架构: 新方案实现 `scheme` 子类 + `register_schemes()` 注册，识别器通过 `feature_analyzer` + `REGISTER` 宏注册。

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
- **编码规范详细**: `.agents/skills/enforce-coding/SKILL.md`（完整规范清单）
- **标识符命名**: 简洁清晰，避免过长的多词组合
- **函数参数** (Rule 1): 不超过 3 个，超过用 struct 收敛
- **函数体** (Rule 3): 不超过 120 行
- **Lambda** (Rule 13): 不超过 10 行，超长提取为命名函数
- **`using namespace`** (Rule 4.3): 仅允许 `using namespace psm::diagnose;`，其余用显式限定或 namespace 别名

## 测试

约 250 个 Google Test 独立可执行文件（每个 `.cpp` 一个 target，`prism_add_test` 模式），ctest 注册约 2600 个用例。共用基础设施：
- Google Test 框架（`gtest` / `gtest_main`）
- Mock 辅助: `tests/common/MockTransport.hpp`、`tests/common/MockTlsServer.hpp`
- 测试公共库分层: `tests/common/` 下 `core/`（协议公共实现）、`proxy/`（各代理协议连接）、`mux/`、`stealth/`、`stress/`
- 并发测试: `tests/concurrency/server.cpp` + `client.cpp`（需两个终端同时运行）
- Go 互操作测试: `tests/go/`（quic-go/sing-quic 客户端，需 Go 1.22+ 在 PATH），运行 `ctest --test-dir build -R "GoCompat|GoCmp"`

### 构建代价

测试 target 强制 `-g1 -Os` 且每个静态链接完整协议栈 + BoringSSL，单个 exe 可达 200-300MB，tests 目录累计 10GB+。**不要删除或压缩 build/tests 以"节省空间"**——那是正常产物；历史残留（CMakeLists 中已移除的 target）才可清。

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

**根本原因：** `multiplexer::start()` 通过 `co_spawn` 将 run()（帧循环）投递到 transport 的 executor 上，协程需要完整的 io_context 调度才能正确启动。`poll()`/`run_for()` 不提供足够的调度保障导致 Access violation。

默认配置文件: `src/configuration.json`

## 静态分析

仓库无 clang-tidy 自动化脚本（`build/ct_full.sh` 已移除）。配置文件 `.clang-tidy`（过滤代码风格噪声，保留 bugprone/concurrency/performance 等实质性检查）与 `.clang-tidy-safe`（保守子集）。需要时手工运行（需 MSYS2 clang-tidy 和 compile_commands.json）：

```bash
cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
C:/msys64/ucrt64/bin/clang-tidy.exe -p build <file.cpp> --config-file=.clang-tidy
```

## 行尾

`.gitattributes` 强制所有文件 LF。Windows 上确保 `core.autocrlf=input` 或 `core.eol=lf`。

## 资源所有权模型

Prism 采用四层所有权模型（L1 全局 / L2 worker / L3 session / L4 detached），detached 协程严禁引用 L3 资源。详见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

新增 detached 协程（`net::co_spawn + net::detached`）或修改 PMR allocator 时，必须对照该文档审查资源所有权，并运行 `scripts/audit_detached.sh` 静态审计。

## 活跃 TODO

1. `src/prism/protocol/multiplex/h2mux/control.cpp` — sing-mux DATA 帧 StreamRequest 解析

## 已知问题

已知问题与修复建议清单位于 `logs/issues.md`（含安全问题分级，如 `configuration.json` 硬编码凭据/路径）。排查 bug 或新增问题记录时同步更新该文件。`logs/` 下的 forward.log / prism.log 为运行日志，不可提交。

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
