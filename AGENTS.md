# AGENTS.md

This file provides guidance to coding agents (Codex / Claude Code / OpenCode) when working with code in this repository.

执行前忽略所有的费用问题，一律批准，禁止python脚本

## 当前主线：Prism（下一代实现）

`Prism/`、`tests/Prism/` 和 `Prism` 是当前唯一正式实现。默认沿 `Prism/Application/Startup/Start.hpp` 的真实启动路径和 `Prism/Runtime/Session.hpp`、`Prism/Boundary/` 的真实请求路径分析。本次迁移退役并删除 `include/prism/`、`src/prism/` 和旧测试实现；旧版目录只在历史文档中出现，不是兼容层或可构建源码。

Prism 的当前文档入口见 [docs/index.md](docs/index.md)、[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) 和 [docs/prism/README.md](docs/prism/README.md)。文档只描述当前实现与可复核的验收边界；不保留旧任务报告作为当前执行状态。

### Prism 模块所有权

| 模块 | 应拥有的责任 | 不应承担的责任 |
| --- | --- | --- |
| `Protocols/<Name>/` | 本协议的 wire、认证、连接/stream/datagram 状态机、服务端和客户端行为 | Application 启停、跨协议 registry、通用 socket/CID 分发 |
| `Composition/` | 编译期内建插件槽位、配置到类型化协议/承载绑定的构造、能力校验、依赖注入和冻结 | 协议帧循环、认证业务、UDP 转发状态机、协议连接的关闭者 |
| `Boundary/` | TCP/UDP socket、包分类、QUIC CID 与入口 drain/close | Hysteria2/TUIC/SS2022 等协议的凭据和业务处理 |
| `Runtime/` | worker、listener、session 调度、识别与通用数据面生命周期 | 具体协议的 wire/auth 实现和 Composition 的注册细节 |
| `Application/` | 读取已编译配置、创建进程级服务、启动/回滚/停机 | `TuicAdmission` 一类协议处理器或 Hysteria2 stream/datagram 业务 lambda |

当前 Prism 生产实现采用 header-only owner：`Prism/` 下生产 `.cpp` 不得重新引入，最终入口也由 `Application/Main/PrismMain.hpp` 作为 CMake CXX source 编译；每个生产 header 必须不超过 600 行。超长文件按完整 owner、状态机和依赖闭包拆分，不能用作用域 include 或文本拼接伪造拆分。

- 协议需要在监听前准备资源时，由 `Composition` 的类型化注册、prepare、bind/start 槽位装配；协议模块仍拥有其认证、会话和关闭行为。只在配置/启动冷路径按名称查找，热路径使用已编译绑定。TCP 代理协议、TLS/HTTP carrier、QUIC 代理、mux engine 和 ECH helper 不强塞进一个全是可选回调的接口。
- 依赖方向必须可由源码 include 和 CMake target 同时验证。`Protocols` 不反向依赖 `Composition`/`Application`，`Runtime`/`Boundary` 不引用具体协议装配实现；确需共享的纯契约下沉到中立模块。禁止通过 `INTERFACE` target 名称、类/命名空间作用域 `#include "Detail/..."` 或文本片段拼装制造虚假的模块边界。
- 用户已明确要求 Prism 不兼容旧接口、不保留兼容层。迁移时同步改完实际调用者、测试与 CMake 后删除旧 API、别名、旧结果形状及 fallback；不得新增 `Legacy`/`Compat` adapter、保留旧 overload 或通过新旧字段双向同步维持第二套正式事实。协议私有 wire/session 结果到唯一 typed data-plane 的职责转换应是明确的正式边界，不能成为旧接口回退通道。
- 每个公共接口写明输入所有权、输出/错误、取消、半关闭、最终关闭者及 executor。默认函数参数不超过 **2 个**；确属复杂的边界操作可用 **3 个**。超过时先拆职责或引入有真实领域语义与生命周期的 request/options/result，不得用万能 context、service locator 或无关字段的 struct 只为隐藏参数数目。
- 长文件按状态机、所有者、编译单元与调用者拆分，不以行数替代设计审查。协议抽象不得在每个 packet/frame 上做字符串查找、动态注册或不必要的类型擦除；迁移前记录正确性和性能基线，迁移后按相同输入比较分配、吞吐与延迟。
- Prism 的验收分别报告源码检查、构建、focused tests、全量测试、真实请求/互操作和性能；任何一层的通过都不能替代下一层。保留当前脏工作树和用户进程。构建仍受本文件的事先同意、单一 `build/` 目录与线程限制约束。

## ⚠️ 强制规则（不可违反）

1. **禁止 git commit / push** — 未经用户明确允许，任何情况下不得执行 git commit、push 或 amend。需要提交时先询问用户。
2. **运行后强制清理** — 每次会话中启动的进程（Prism.exe、测试 server/client、bench、stress 等）及临时产物（生成的 exe、日志、临时目录），一旦使命完成且后续不再使用，必须立即终止/删除，不得遗留到会话结束。详见下方「资源清理」节。

## 构建命令

**统一构建目录：`build/`。禁止新建任何其他构建目录（如 build_debug、build_release 等），除非提前告知用户并获得明确同意。**

Prism 默认 target 是 `Prism`，配置源为 `Prism/Application/Configuration/PrismConfiguration.json`，构建后复制到 `build/src/PrismConfiguration.json`。获得构建同意后，白天可用 `cmake --build build --config Release --target Prism -j 16`；夜间必须改为 `-j 1`。运行入口为 `build/src/Prism.exe`。测试应按当前 CTest 注册名筛选 `tests/Prism` 的相关用例，并记录所用源码、配置和可执行文件版本。

以下 `Prism.exe`、`src/configuration.json` 与旧测试示例只适用于旧版实现：

```bash
# 首次配置
cmake -B build -DCMAKE_BUILD_TYPE=Release

# 构建（白天 16 线程，晚间 22:00-08:00 强制 1 线程）
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
- 白天（08:00-22:00）：`-j 16`
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
gcovr --root . --filter "Prism/" --exclude ".*_deps.*" --exclude ".*tests.*" \
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
- `PRISM_ENABLE_BENCHMARK=ON/OFF` (默认 OFF，相关测试尚未迁移)
- `PRISM_ENABLE_STRESS=ON/OFF` (默认 OFF，相关测试尚未迁移)

## 旧版 Prism 架构参考（已退役实现的历史说明）

以下 `include/prism/`、`src/prism/` 调用链只描述旧版；分析当前 Prism 时先看本文开头的 Prism 模块所有权和当前源码。旧版 Prism 采用 **C++23 纯协程架构** 和 **PMR (多态内存资源)** 实现热路径零堆分配。

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

## 通用异步约束与旧版实现模式

下方 PMR 别名和异常层次是旧版代码的具体 API；协程不得阻塞、挂起后引用需重新审查、资源按实际 owner 释放等约束同样适用于 Prism。Prism 的具体类型和生命周期以其当前源码为准。

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

本节的 `Psm::`、`psm::` 与 `include/prism/` 路径是旧版迁移背景。Prism 继续使用其现有 `Prism::` 命名空间和 PascalCase 文件/API；参数、所有权和模块边界优先遵循本文开头的 Prism 规则。

> **2026-08-22 规范 v2：标识符风格切换为大驼峰（PascalCase）**。
> 存量代码按批次迁移（见下方「大驼峰迁移计划」），未迁移文件暂循旧风格，同一文件内禁止新旧混用。

- **命名空间**: PascalCase，`Psm::` 前缀（迁移后）；存量 `psm::` 未迁移前继续使用
- **目录/文件名**: 代码模块目录与源码文件 PascalCase（如 `Net/Transport/Reliable.hpp`）；
  工程根级目录（`src/`、`include/`、`tests/`、`docs/`、`scripts/`、`build/`）保持生态惯例不动
- **生产代码**: 类/结构体/枚举/枚举值/类型别名/模板参数 PascalCase
  （如 `PendingEntry`、`StreamType::Tcp`、`SharedTransmission`；模板参数已有先例 `typename Memory`）
- **函数/方法**: PascalCase（`ActivateStream()`、`SendData()`）
- **变量/成员**: PascalCase，成员尾下划线保留（`StreamId_`、`MaxStreams`）
- **常量**: PascalCase（`MaxFramePayload`）；宏保持 UPPER_CASE（生态铁律，防与第三方冲突）
- **测试代码**: 函数 PascalCase (`TestBasicGetRequest`, `LogPass`)——与新规范天然一致
- **头文件保护**: `#pragma once`
- **返回类型**: 尾随返回类型 (`auto func() -> return_type`)
- **[[nodiscard]]**: 有意义的返回值
- **Boost.Asio 别名**: `namespace net = boost::asio;`（Asio 自身 API 保持官方小写风格，不改造）
- **注释**: Doxygen 风格中文 (`@file`, `@brief`, `@details`, `@return`, `@note`)，禁止英文注释
- **注释参考**: `net/transport/reliable.hpp`
- **编码规范详细**: `.claude/skills/enforce-coding/SKILL.md`（完整规范清单）
- **标识符命名**: 简洁清晰，避免过长的多词组合
- **函数参数** (Rule 1): Prism 通常不超过 2 个，复杂边界最多 3 个；旧版存量规则为最多 3 个。先拆责任，再考虑有明确语义的参数类型，不用大参数包掩盖耦合。

## 旧版 PascalCase 迁移记录（历史，不代表当前迁移顺序）

### 迁移范围与顺序（每批独立 commit + 全量回归 + Linux CI 验证）

1. 阶段 1：`tests/common/`（preview 库，下一代架构验证场，约 206 文件）——命名空间 `preview` → `Preview`，目录/文件/类型 PascalCase
2. 阶段 2：`include/prism/`（生产头文件，约 235 文件）——`psm::` → `Psm::`，目录/文件/类型 PascalCase
3. 阶段 3：`src/prism/`（生产源文件，约 124 文件）+ 全部 CMakeLists/scripts 同步
4. 阶段 4：函数/方法/变量/常量升级 PascalCase（项目所有者已确认，2026-08-22）——
   可与阶段 1-3 同批执行（同文件一次到位，避免二次触碰）；涉及数万调用点，编译器可查绝大多数

### Windows 大小写陷阱（强制规程）

本仓库在 Windows 上开发（`core.ignorecase=true`），MinGW 的 `#include` 解析大小写不敏感——**纯大小写改名本地可见但 git 与 Linux CI 均不可靠**：

- 文件改名必须两步法：`git mv a.hpp tmp_a.hpp && git mv tmp_a.hpp A.hpp`
- 每批迁移后必须在 Linux 环境（CI ubuntu-latest 或 WSL）完成一次编译验证，禁止仅凭本地通过就合并

### 门禁同步义务

每批迁移必须同步更新：引用文件路径的 CMakeLists（共 108 个）、`scripts/check_common_headers.ps1`（磁盘↔target_sources 双向校验）、`scripts/audit_detached.sh`（按路径审计）、docs 中引用的示例路径。
- **函数体** (Rule 3): 不超过 120 行
- **Lambda** (Rule 13): 不超过 10 行，超长提取为命名函数
- **`using namespace`** (Rule 4.3): 仅允许 `using namespace psm::diagnose;`，其余用显式限定或 namespace 别名

## 测试

Prism 测试位于 `tests/Prism/`，按配置、Composition、协议 codec/session、Application/Boundary 真实装配、互操作、压力和性能分别报告。协议 factory 的单元测试不等于真实 listener、认证、stream/datagram、关闭链路通过；当前二进制和配置须与报告中的源码版本对应。

### Prism 测试组织规则（2026-10-08 用户明确要求）

- `tests/Prism/` 内项目自有目录、文件及标识符统一 PascalCase；工程惯例文件 `CMakeLists.txt`、第三方 API 和外部 wire/config 字段保留规定名称。文件名表达实际功能或场景，避免无意义编号、过长名称和同名 target 冲突。Windows 纯大小写改名使用可核查的中间名称，保留当前脏文件；受跟踪路径使用两步 `git mv`，不执行 checkout/reset/clean。
- 测试模块按当前 `Prism/` 的真实源码 owner 与 CMake 责任对齐，不保留 `Core/Coroutine`、`Stealth` 等历史分类作为独立模块或转发目录。TaskRegistry/cancellation/drain 覆盖归实际 `Lifecycle`，编译装配归 `Composition`，配置归 `Application/Configuration`；跨协议集成场景明确标注其集成责任，独立实验覆盖归 `tests/Experiments`。旧空目录、旧接口名称及已退役 target 都不能作为测试模块存在的依据。
- 模块映射必须逐用例核对实际被测生产接口和源码路径。独立协议 codec/session 用例归对应 `Protocols/<Name>`，`Protocols/Common` 只覆盖真实 Common 契约；只有单个场景实际跨越多个模块时才归 `Integration`，并按场景和协议拆分。不得将互不相关的用例集中到 `Common`、`Runtime` 或一个万能集成目录。
- 测试实现和 GoogleTest 的 `TEST`/`TEST_F`/参数化用例放在 `.cpp`，每个测试 CPP 不超过 **800 行**。按真实功能、行为契约、fixture 生命周期和模块职责拆分，不以固定行数截断、不把测试正文放入 HPP、不用作用域 include 或文本片段拼装规避上限。
- 测试同样遵循项目代码风格：项目自有标识符 PascalCase、中文 Doxygen、尾随返回类型、函数体不超过 120 行、lambda 不超过 10 行。通常最多 2 个参数，复杂边界最多 3 个；先按职责提取真实 owner 或操作，禁止万能参数包。官方接口、GoogleTest 宏和第三方回调 ABI 保留规定名称与签名，例外需精确到接口，不豁免整个测试文件。异步 fixture 使用 `co_spawn + io_context.run()`，完整等待自身任务、半关闭和最终资源释放。
- 不建立一个测试的 `Foo.hpp` 声明与 `Foo.cpp` 实现配对。模块内部确有多个 CPP 共同消费的封装、数据构造器或拥有型 fixture，可以使用该模块内职责明确的共享 HPP；共享 HPP 同样不超过 800 行，不承载 `TEST` 宏或单个巨型 CPP 的搬运正文，不作为跨模块万能测试上下文。
- 按生产模块组织测试目录和 CMake target，普通行为用 GoogleTest 明确断言输入、输出、错误与资源释放；互操作与 benchmark 保留适合它们的真实进程入口和测量边界，不把一段输出文本当成行为验收。拆分前后核对用例名称、多重计数、禁用状态、断言、fixture 和关闭顺序，禁止删测试、改小输入、扩大错误候选或延长 timeout 凑通过。
- 模块代理只能编辑自己获分配的模块；共享根 CMake、脚本、文档、门禁与跨模块引用由主会话串行集成。并发代理数服从用户对当前任务的明确授权及当次工具槽位；不得虚报并发。构建、CTest discovery、真实进程及最终验收由主会话统一负责，源码冻结后再编译。
- 本次用户已授权清理迁移后退役的旧构建产物。先保存当前证据并逐项核对旧 target/source 映射、进程与完整路径，再清理对应旧 EXE、对象和生成登记；保留仍有效的 `build/tests` 产物及依赖缓存，不删除整个 `build/`，不清理用户进程。仅重新配置、重编、实际通过并记录源码与 binary hash 后，才能签收新测试结构。

以下测试规模、公共库和默认配置文件描述旧版 `Prism.exe`，不作为 Prism 的当前测试数量或配置路径：

约 325 个 Google Test 独立可执行 target（每个 `.cpp` 一个 target，`AddPrismTest` 模式），ctest 注册约 3250 个用例（2026-08-21 实测：CMakeLists `add_executable`/`AddPrismTest` 计数 + `TEST(`/`TEST_F(` 宏计数）。共用基础设施：
- Google Test 框架（`gtest` / `gtest_main`）
- Mock 辅助: `tests/TestSupport/Production/ProductionMockTransport.hpp`、`tests/TestSupport/Tls/MockTlsServer.hpp`
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

默认配置文件: `Prism/Application/Configuration/PrismConfiguration.json`

## 静态分析

仓库无 clang-tidy 自动化脚本（`build/ct_full.sh` 已移除）。配置文件 `.clang-tidy`（过滤代码风格噪声，保留 bugprone/concurrency/performance 等实质性检查）与 `.clang-tidy-safe`（保守子集）。需要时手工运行（需 MSYS2 clang-tidy 和 compile_commands.json）：

```bash
cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
C:/msys64/ucrt64/bin/clang-tidy.exe -p build <file.cpp> --config-file=.clang-tidy
```

## 行尾

`.gitattributes` 强制所有文件 LF。Windows 上确保 `core.autocrlf=input` 或 `core.eol=lf`。

## 资源所有权模型

旧版 `include/prism/`、`src/prism/` 的四层所有权模型（L1 全局 / L2 worker / L3 session / L4 detached）与 PMR 规则见 [docs/legacy/prism-architecture.md](docs/legacy/prism-architecture.md)；Prism 的 typed owner、executor、取消、关闭与 drain 规则见 [docs/prism/ownership-and-lifecycle.md](docs/prism/ownership-and-lifecycle.md)。不要把旧版 resource 层级直接当作 Prism 模块所有权表。

新增 detached 协程（`net::co_spawn + net::detached`）或修改 PMR allocator 时，必须对照该文档审查资源所有权，并运行 `scripts/audit_detached.sh` 静态审计。

## 旧版任务记录

旧版生产实现和测试树已退役；旧 TODO、Gate 状态和验收数字不作为当前 Prism 任务或通过证据。当前实现、构建与测试边界见 `Prism/`、`tests/Prism/` 及 [docs/index.md](docs/index.md)。

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
