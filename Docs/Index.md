# Prism 文档

本目录包含面向使用者的操作指南和面向贡献者的开发资料。生产程序 target 为 `Prism`；公开接口位于 `Include/Prism/`，实现和私有头文件位于 `Src/Prism/`，功能测试位于 `Test/Prism/`。

## 使用 Prism

- [快速开始](Tutorial/GettingStarted.md)：从源码构建、启动 SOCKS5 示例并发起请求。
- [配置](Tutorial/Configuration.md)：完整示例、账户凭据、环境变量和当前配置限制。
- [协议支持](Tutorial/Protocols.md)：协议入口、binding、UDP/QUIC 和 Mihomo/Clash 互操作说明。
- [管理 API 与 Web 控制台](Tutorial/Operations.md)：启用静态资源、配置 endpoint 和访问范围。
- [部署](Tutorial/Deployment.md)：服务文件布局、凭据和 Linux systemd 示例。
- [故障排查](Tutorial/Troubleshooting.md)：监听、配置、认证、Web 资源和请求失败的排查步骤。
- [常见问题](Tutorial/Faq.md)：配置路径、演示凭据、UDP、Routes 和验收范围。

### 第一次使用时怎么读

如果你刚拿到 Prism，可以按这个顺序操作：

1. 先看[快速开始](Tutorial/GettingStarted.md)，确认程序能启动并完成一次 SOCKS5 请求。
2. 再看[配置说明](Tutorial/Configuration.md)，了解端口、账户和密码分别在哪里改。
3. 要连接其他协议或客户端时，查看[协议支持](Tutorial/Protocols.md)，确认服务端入口、binding 和客户端设置都匹配。
4. 部署到另一台机器前，阅读[部署](Tutorial/Deployment.md)和[故障排查](Tutorial/Troubleshooting.md)。

如果命令执行失败，先记录自己执行的完整命令、使用的配置文件路径和第一条错误，再按[故障排查](Tutorial/Troubleshooting.md)逐项检查。不要只根据配置文件里出现了某个协议名称，就判断它已经对外开放。

## 开发与验收

- [构建与测试](Testing.md)：CMake、CTest、可选互操作和性能验收边界。
- [架构与模块职责](Architecture.md)：当前实现的启动、请求和关闭路径。
- [Prism 开发入口](Prism/Readme.md)：代码入口与模块路径。
- [所有权与异步生命周期](Prism/Ownership.md)：异步 I/O、取消、半关闭、关闭和 drain 约定。

## 互操作样例的边界

根目录的 `PrismConfigurationMatrix.json` 和 `PrismClient.yaml` 是测试 fixture；互操作 runner 位于 `Test/Prism/Integration/Matrix/`。它们用于复现特定客户端组合，不等同于通用生产配置。测试记录、客户端版本、运行条件和结果必须分别核对，不能从配置可解析或测试已注册推断互操作已通过。
