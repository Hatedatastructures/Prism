<div align="center">
  <h1>Prism</h1>
  <p>基于 C++23 与 Boost.Asio 协程的多协议服务端代理。</p>
</div>

当前开发、结构审查与验收主线是 **Preview**：源码位于 `Preview/`，可执行 target 为 `PrismPreview`，测试位于 `tests/Preview/`。Preview 的协议模块拥有 wire、认证与会话状态，Composition 在启动冷路径编译和绑定配置，Runtime 调度会话，Boundary 管理入口 socket，Application 管理启动、回滚与停机。

Preview 正在进行[无兼容层重构](docs/preview-refactor/2026-10-03-preview-no-compat-execution.md)。[当前状态](docs/preview-refactor/2026-10-03-preview-no-compat-status.md)分别列出已签收范围、实施中的任务和验收缺口。旧版源码 `include/prism/`、`src/prism/`、程序 `Prism` 与 `src/configuration.json` 保留为历史实现，本文操作步骤使用 Preview。

## 构建与运行

需要 C++23 编译器、CMake 3.23+ 和 Git，依赖由 CMake 获取。仓库统一使用现有 `build/`；Windows 的 MinGW 运行环境还需能找到其运行库，当前配置并非全部静态链接。

```powershell
cmake -B build -DCMAKE_BUILD_TYPE=Release
Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
cmake --build build --config Release --target PrismPreview -j 16
```

上海时间 08:00–22:00 使用 `-j 16`，22:00–08:00 使用 `-j 1`。每次构建先检查时间。构建后的程序为 `build/src/PrismPreview.exe`（Linux 为 `build/src/PrismPreview`）。

配置模板是 [PreviewConfiguration.json](Preview/Application/Configuration/PreviewConfiguration.json)，target 构建后复制到程序同目录。首次使用先按[配置说明](docs/tutorial/configuration.md)替换示例凭据，再启动：

```powershell
.\build\src\PrismPreview.exe
# 也可以给出配置文件的第一个位置参数
.\build\src\PrismPreview.exe 'C:\Prism\PreviewConfiguration.json'
```

默认模板在 `127.0.0.1:1080` 配置 SOCKS5，Operations 地址为 `127.0.0.1:9090`。启动输出中的 `PrismPreview READY` 表示入口已发布就绪状态；端口就绪后的代理请求、认证、字节和关闭验证见[快速开始](docs/tutorial/getting-started.md)。

## 功能与边界

协议实现包括 HTTP、SOCKS5、Trojan、VLESS、VMess、Shadowsocks 2022、AnyTLS、TrustTunnel、Hysteria2 和 TUIC；承载实现包括 Native TLS、Reality、ShadowTLS、Restls、WebSocket、XHTTP 和 gRPC。配置编译会按实际能力校验协议与承载组合。

Smux、Yamux、H2Mux、AnyTLS 和 XUDP 的运行态由 `Preview/Protocols/` 下的协议 owner 持有；旧 Composition runtime wrapper 已退役，冷装配仍由 Composition/provider 边界负责。目录或 capability 中出现的能力，以及旧版测试和性能数字，各有自己的适用范围；当前构建、focused tests、全量测试、真实请求、互操作和性能分别记录在执行状态与 dated 证据中。

## 测试与文档

先确认当前注册用例，再按真实 suite 名称执行：

```powershell
ctest --test-dir build -N -R '^(ConfiguredMuxSession|ProviderAcceptPath|BindingLifetime)\.'
ctest --test-dir build --output-on-failure -j 1 --timeout 30 -R '^(ConfiguredMuxSession|ProviderAcceptPath|BindingLifetime)\.'
```

CTest 只运行已有测试程序，修改源码后须先构建对应 target。最终全量命令及各层验收规则见 [AGENTS.md](AGENTS.md) 和[执行计划](docs/preview-refactor/2026-10-03-preview-no-compat-execution.md)。

- [文档索引](docs/index.md)
- [Preview 开发入口](Preview/README.md)
- [快速开始](docs/tutorial/getting-started.md)、[配置](docs/tutorial/configuration.md)、[部署](docs/tutorial/deployment.md)
- [架构](docs/ARCHITECTURE.md)、[故障排查](docs/tutorial/troubleshooting.md)、[常见问题](docs/tutorial/faq.md)
- [当前执行状态](docs/preview-refactor/2026-10-03-preview-no-compat-status.md)

许可证：[MIT](LICENSE)。
