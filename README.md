<div align="center">
  <h1>Prism</h1>
  <p>基于 C++23 和 Boost.Asio 的异步多协议代理服务端，支持 TCP、UDP 关联流量与 QUIC 接入，并提供可选的 HTTP 运维 API 和 Web 控制台。</p>
</div>

Prism 在同一服务中配置代理协议入口、账户认证和上游转发。本文给出从源码构建、启动到发出首个 SOCKS5 请求的步骤；其他协议的配置边界见[配置与协议说明](Docs/Index.md)。

## 协议支持

| 接入类别 | 当前实现 |
| --- | --- |
| TCP 代理协议 | HTTP/1.1、SOCKS5、VLESS、Trojan、VMess、Shadowsocks 2022、AnyTLS、TrustTunnel |
| QUIC 代理协议 | Hysteria2、TUIC（当前 ALPN 为 `h3`） |
| UDP 关联 | SOCKS5、VLESS、Trojan、VMess、Shadowsocks 2022 |
| TLS / HTTP 承载 | Native TLS、Reality、ShadowTLS、Restls、WebSocket、XHTTP、Gun（GunLite / gRPC） |
| 多路复用 | Smux、Yamux、H2Mux |

这些是当前实现的协议和传输模块。实际能用的组合仍取决于 listener、协议实例及 `ProtocolBindings`；仓库默认配置只启用 SOCKS5 TCP。协议启用步骤和限制见[协议支持说明](Docs/Tutorial/Protocols.md)。当前配置模型中的 `Routes` 必须为空，非空配置会被启动校验拒绝。

### Mihomo / Clash 客户端配置参考

Prism 的互操作样例使用 Mihomo。客户端配置语法请以 [Mihomo 官方配置文档](https://wiki.metacubex.one/config/) 为准；常用的[代理节点通用字段](https://wiki.metacubex.one/en/config/proxies/)、[SOCKS5](https://wiki.metacubex.one/en/config/proxies/socks/)、[Hysteria2](https://wiki.metacubex.one/en/config/proxies/hysteria2/) 和 [TUIC](https://wiki.metacubex.one/en/config/proxies/tuic/) 参考页也可直接查看。不同 Clash 派生客户端的协议支持和字段可能不同，请同时核对所用客户端文档。

仓库根目录的 [`PrismClient.yaml`](PrismClient.yaml) 和 [`PrismConfigurationMatrix.json`](PrismConfigurationMatrix.json) 是互操作测试 fixture，不是通用生产配置；手动 runner 和验证边界见[协议支持说明](Docs/Tutorial/Protocols.md)。

## 从源码构建并发起请求

### 环境要求

- C++23 编译器：Linux 使用 GCC 13 或更高版本；Windows 使用项目支持的 MinGW 工具链。
- CMake 3.23 或更高版本。
- 首次配置需要网络以通过 CMake FetchContent 获取核心依赖。
- Node.js 和 npm 只在构建可选 Web 控制台时需要；构建 `Prism` 不需要安装前端依赖。

### 配置和构建

在仓库根目录执行：

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --target Prism
```

构建结果为 Windows 的 `build/src/Prism.exe` 或 Linux 的 `build/src/Prism`。这里的命令从源码构建服务端；仓库运行要求和测试命令见[开发构建与测试说明](Docs/Testing.md)。

### 启动并验证 SOCKS5

示例配置启用回环地址上的 SOCKS5 TCP 入口，账户名为 `local`，演示密码为 `change-me`。它只适用于本机验证，不要将演示凭据用于部署或公开监听：

```powershell
& '.\build\src\Prism.exe' '.\Docs\Tutorial\Examples\Socks5.json'
```

Linux：

```bash
./build/src/Prism ./Docs/Tutorial/Examples/Socks5.json
```

另开一个终端，通过 SOCKS5 请求外部 HTTPS 页面。请求需要本机网络和目标站点可达：

```powershell
curl.exe --proxy socks5h://127.0.0.1:1080 `
  --proxy-user 'local:change-me' `
  --head --fail --show-error https://example.com/
```

```bash
curl --proxy socks5h://127.0.0.1:1080 \
  --proxy-user 'local:change-me' \
  --head --fail --show-error https://example.com/
```

收到 HTTP 响应表示这次请求通过了 SOCKS5 认证、代理连接和上游 TLS/HTTP 往返。示例使用外部站点，因此 DNS、网络策略或目标站点不可达时，请求也会失败；这不等同于本地配置解析失败。演示凭据只允许配合回环监听；生产部署请改用 `SecretRef`，见[配置说明](Docs/Tutorial/Configuration.md)。更多诊断见[故障排查](Docs/Tutorial/Troubleshooting.md)。

### 可选 Web 控制台

Web 控制台不属于 `Prism` 默认构建目标。只有需要静态资源时才安装 Node.js/npm 并构建：

```powershell
npm ci --prefix Web
cmake --build build --config Release --target PrismWeb
```

资源生成在 `build/Web/`。要让 Operations 提供 Web 页面，还需将配置中的 `Operations.WebDirectory` 指向该目录；相对路径按配置文件位置解析。未启用 Web 资源时，Operations API 可独立使用。用户启用说明见[管理 API 与 Web 控制台指南](Docs/Tutorial/Operations.md)，前端开发和验收说明见 [Web/README.md](Web/README.md)。

## 文档

- [文档索引](Docs/Index.md)：用户指南和开发资料入口。
- [快速开始](Docs/Tutorial/GettingStarted.md)：源码构建、启动和首个请求。
- [配置](Docs/Tutorial/Configuration.md)：完整 SOCKS5 示例、账户凭据和配置边界。
- [协议支持](Docs/Tutorial/Protocols.md)：协议类别、传输方式和 binding 要求。
- [管理 API 与 Web 控制台](Docs/Tutorial/Operations.md)、[部署](Docs/Tutorial/Deployment.md)、[故障排查](Docs/Tutorial/Troubleshooting.md)、[常见问题](Docs/Tutorial/Faq.md)。
- 开发者资料：[架构](Docs/Architecture.md)、[构建与测试](Docs/Testing.md)、[异步所有权](Docs/Prism/Ownership.md)。

许可证：[MIT](LICENSE)。
