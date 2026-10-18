<div align="center">
  <h1>Prism</h1>
  <p>基于 C++23 与 Boost.Asio 的异步多协议代理服务端，提供 TCP、UDP/关联流量与 QUIC 接入，以及可选的 HTTP 运维 API 和 Web 控制台。</p>
</div>

Prism 面向需要在同一服务中配置多种代理协议入口、统一处理账户认证与上游转发，并通过管理接口观察和维护运行实例的场景。生产实现位于 `Prism/`，功能测试位于 `tests/Prism/`，CMake 程序 target 为 `Prism`。旧版 `include/prism/`、`src/prism/` 和旧测试实现已经退役；历史文档仅用于理解旧实现，不代表当前接口或运行能力。

## 功能一览

### 代理协议与传输

| 接入类型 | 当前实现 | 说明 |
| --- | --- | --- |
| TCP 代理协议 | HTTP/1.1、SOCKS5、VLESS、Trojan、VMess、Shadowsocks 2022、AnyTLS、TrustTunnel | 由配置中的 protocol instance 与 `ProtocolBindings` 启用；未绑定的协议不会因为源码存在而自动开放。 |
| QUIC 代理协议 | Hysteria2、TUIC | 通过 QUIC listener 接入，当前识别绑定使用 HTTP/3 ALPN `h3`。 |
| UDP 关联 | SOCKS5、VLESS、Trojan、VMess、Shadowsocks 2022 | 必须同时满足协议实现、实例选项和 binding 配置；UDP listener 已启动不等于每个协议都启用了 UDP。 |
| TLS / HTTP 承载 | Native TLS、Reality、ShadowTLS、Restls、WebSocket、XHTTP、Gun（GunLite / gRPC） | Carrier 与代理协议分别配置；证书、密钥、路径、模式和协议组合会经过启动校验。 |
| 多路复用 | Smux、Yamux、H2Mux | 仅在对应协议和 binding 支持的组合中使用，不能把某个 mux 选项视为所有协议的通用开关。 |

Prism 会将通过认证的请求送入统一的数据面服务，按已装配的 DNS、拨号与 relay 能力建立上游连接并转发数据。TCP、UDP 关联和 QUIC 各有自己的入口与生命周期；具体可用路径由当前配置和 protocol binding 决定。

### 账户、管理和运行维护

- **账户与凭据：** 通过 `Accounts` 和 `AccountGroups` 组织账户、凭据及其协议身份范围；可用 `SecretRef` 从进程环境注入敏感值，避免把真实密码写进配置仓库。
- **策略与额度：** Account 模块提供认证、准入租约、连接/stream/byte 配额和速率策略等机制。实际执行范围取决于协议及该请求路径接入的能力，不能据此推断所有协议都执行所有预算。
- **独立管理 API：** `Operations` 使用独立 HTTP endpoint，提供管理查询与命令入口，不占用代理协议的 listener。Web 资源未构建或未配置时，管理 API 仍可独立启动。
- **可选 Web 控制台：** `Web/` 提供同源 API v2 管理界面，包含总览、入口、worker、session、账户/用户组、事件、配置和运维页面。具体操作由服务端公布的 capability 控制；不支持的操作会按不可用能力处理，不会自动切换到演示数据。
- **统计与诊断：** 可启用运行统计、管理事件查询、日志和关联信息，帮助检查 listener、worker、session 与请求状态。数据类型和保留范围以当前后端 API 与配置为准；控制台页面本身不代表历史数据已持久化。
- **显式配置更新：** 启用 `HotReload` 且开放 Operations 后，可通过管理命令先校验候选配置，再请求发布新 generation。编辑磁盘文件不会自动触发重载；需要重启的字段会返回重启要求。
- **有序停机：** 关闭入口准入后，由各协议与运行时 owner 完成取消、半关闭、资源关闭和 drain；停机预算由 `Shutdown.Timeout` 控制。

### 实现特色

- **异步 I/O：** 基于 C++23 与 Boost.Asio，将 listener、session、stream、datagram 和管理服务组织在异步执行路径中。
- **启动时编译配置：** 配置经过 schema、能力、provider 和 binding 校验后，组装为类型化 generation 与冻结的 provider catalog；不支持的实例或组合在启动阶段以错误返回。
- **清晰的数据面边界：** `Protocols/` 拥有协议 wire、认证和会话状态；`Composition/` 负责冷启动装配；`Boundary/` 管理 TCP/UDP/QUIC 入口；`Runtime/` 调度通用 session；`Application/` 编排启动、回滚和关闭。
- **面向资源生命周期：** 取消、写半关闭、最终关闭和 drain 是不同步骤，由真正拥有 I/O 的协议、transport 或入口 owner 完成，避免把“停止接收”误当成所有连接都已退出。
- **单一当前生产实现：** `Prism/` 是唯一正式生产代码；README、配置示例和测试入口均以当前 Prism 为准，不再保留旧版 API 兼容层。

## 当前能力边界

- 配置字段存在不等于功能已接线；协议、carrier、mux 和 UDP/QUIC 的可用组合以配置校验和实际 binding 为准。
- `Routes` 目前保留在配置模型中，但非空 `Routes` 会被启动 service validation 拒绝；当前 README 不宣称用户自定义路由规则已经可用。
- Operations Web 前端是可选资源。构建或配置管理静态资源目录不会自动启用 API 中尚未公布的能力。
- 功能测试、真实 listener 请求、第三方互操作、Linux/Windows 构建和性能数据是不同验收层；测试已注册、程序输出 READY 或旧报告通过，都不能替代当前 binary 的对应验收。
- Benchmark 与 stress 相关选项默认关闭；源码或 target 存在不代表本次构建包含它们，也不代表存在当前性能结论。

## 快速开始

### 环境要求

- C++23 编译器：Linux 使用 GCC 13 或更高版本；Windows 使用项目配置的 MinGW 工具链。
- CMake 3.23 或更高版本。
- Node.js 24.14.1 或更高版本及 npm。当前 CMake 配置会检查 Node/npm；Web 依赖和资源则通过单独的 `PrismWeb` target 构建。
- CMake 使用 FetchContent 获取核心依赖，包括 Boost.Asio、BoringSSL、spdlog、glaze、BLAKE3 和 nghttp2。首次配置需要可用网络；已有依赖缓存时可按项目构建说明复用。

### 配置并构建

仓库开发统一使用现有 `build/` 目录。下面示例按 Windows PowerShell 编写；每次构建前先检查上海时间，并按仓库规则选择线程数：08:00–22:00 用 `-j 16`，22:00–08:00 用 `-j 1`。

```powershell
cmake -B build -DCMAKE_BUILD_TYPE=Release
Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
# 白天：
cmake --build build --config Release --target Prism -j 16
# 夜间改用：cmake --build build --config Release --target Prism -j 1
```

程序输出为 `build/src/Prism.exe`（Windows）或 `build/src/Prism`（Linux）。构建 `Prism` 时，CMake 会把配置模板复制到程序同目录的 `PrismConfiguration.json`。

如需 Web 控制台资源，先安装前端依赖，再显式构建独立 target：

```powershell
npm ci --prefix Web
cmake --build build --config Release --target PrismWeb -j 16
```

`PrismWeb` 不属于默认 `Prism` 程序 target。把配置中的 `Operations.WebDirectory` 指向生成目录（通常为 `build/Web`），并保持目录内的 catalog 和静态资源完整；没有这项配置时，已启用的 Operations API 仍可提供管理请求。夜间构建 `PrismWeb` 时同样使用 `-j 1`。

### 启动与发起请求

不传参数时，程序从可执行文件所在目录读取 `PrismConfiguration.json`；传入的第一个位置参数用于指定配置文件。入口没有 `--config` 参数解析：

```powershell
& '.\build\src\Prism.exe' '.\build\src\PrismConfiguration.json'
```

```bash
./build/src/Prism ./build/src/PrismConfiguration.json
```

仓库模板默认把 SOCKS5 TCP 入口绑定到 `127.0.0.1:1080`，Operations endpoint 绑定到 `127.0.0.1:9090`。模板中的凭据 `local-token` 是示例值，部署前应替换；模板虽然配置了 UDP listener，但 SOCKS5 binding 默认 `UdpEnabled: false`。监听地址、账户、协议实例及 binding 应按部署需求一并核对。

为账户设置 `SecretRef` 时，可在启动进程的环境中提供对应变量。变量名由 `PRISM_SECRET_` 前缀和规范化后的 reference 组成：字母转大写、数字保留、其他字符替换为下划线。例如：

```powershell
$env:PRISM_SECRET_PROXY_PASSWORD = '替换为实际密钥'
```

启动输出中的 `Prism READY` 表示应用完成启动并发布 readiness；它不证明某个协议认证、目标拨号、UDP/QUIC 请求或管理命令已经实际通过。可按[快速开始指南](docs/tutorial/getting-started.md)发送真实请求，并检查正向/反向认证、响应内容和关闭行为。

## 测试与验收

功能测试位于 `tests/Prism/`，按生产模块和实际集成场景组织。先查看当前 CTest 注册名，再运行已构建的对应测试：

```powershell
ctest --test-dir build -N
ctest --test-dir build --output-on-failure -j 1 --timeout 30 -R '<当前测试注册名正则>'
```

全量执行入口：

```powershell
ctest --test-dir build --output-on-failure -j 1 --timeout 30
```

CTest 只运行构建目录里已有的测试程序；测试注册、源码检查或单个协议单测都不能替代全量测试、真实请求和互操作验证。需要性能或压力数据时，按专门的构建选项和测量方案单独记录，不从功能测试结果推断吞吐或延迟。

## 项目结构

```text
Prism/                  当前 C++23 生产实现
  Application/          配置、启动、重载、Operations 装配与停机
  Composition/          provider 准备、能力校验和 typed binding
  Protocols/             各代理协议与 mux 的 wire/session owner
  Boundary/              TCP、UDP、QUIC 网络入口
  Runtime/               worker、listener、session 与运行态调度
  Account/               凭据、账户准入、策略与额度
  Operations/            独立 HTTP 管理 API 与可选静态资源服务
tests/Prism/             当前功能测试
Web/                     独立构建的 Operations Web 控制台
docs/                    用户指南、当前架构与测试手册
```

Prism 的生产 owner 采用 header-only 组织，最终程序入口由 CMake 作为 C++ source 编译。模块职责、依赖方向、请求路径和资源关闭约定见[架构总览](docs/ARCHITECTURE.md)与[Prism 开发入口](docs/prism/README.md)。

## 文档

- [文档索引](docs/index.md)：用户指南与当前开发手册。
- 用户指南：[快速开始](docs/tutorial/getting-started.md)、[配置](docs/tutorial/configuration.md)、[部署](docs/tutorial/deployment.md)、[故障排查](docs/tutorial/troubleshooting.md)、[常见问题](docs/tutorial/faq.md)。
- 开发手册：[架构总览](docs/ARCHITECTURE.md)、[Prism 开发入口](docs/prism/README.md)、[配置](docs/tutorial/configuration.md)、[所有权与生命周期](docs/prism/ownership-and-lifecycle.md)、[构建与测试](docs/TESTING.md)。
- [Operations Web 控制台说明](Web/README.md)：前端 API、能力协商和独立构建边界。

目录结构和配置模型说明源码现状；某项功能是否在特定部署中可用，还要核对实际配置、启动绑定和相应运行证据。

许可证：[MIT](LICENSE)。
