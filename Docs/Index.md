# Prism 文档

本文档集描述当前唯一正式实现：公开头文件位于 `Include/Prism/`，实现和私有头文件位于 `Src/Prism/`。生产程序由 CMake target `Prism` 构建，功能测试位于 `Test/Prism/`。

## 使用指南

- [快速开始](Tutorial/GettingStarted.md)
- [配置](Tutorial/Configuration.md)
- [部署](Tutorial/Deployment.md)
- [常见问题](Tutorial/Faq.md)
- [故障排查](Tutorial/Troubleshooting.md)

## 开发资料

- [架构与模块职责](Architecture.md)
- [构建与测试](Testing.md)
- [Prism 开发入口](Prism/Readme.md)
- [所有权与异步生命周期](Prism/Ownership.md)

## 文档范围

协议的具体 wire、认证和会话行为由 `Include/Prism/Protocols/`、`Src/Prism/Protocols/` 与对应测试维护；本手册不为每个协议建立单独专题页。配置说明只描述通用配置结构和装配边界。

当前 Mihomo/Clash 互操作配置模板与对应 runner 保存在 `Test/Prism/Integration/Matrix/`，由实际测试场景维护；旧 PrismPreview 配置不再作为当前样例。

构建、测试、互操作和性能结果分层记录。源码存在、配置可以解析或测试已注册，都不单独证明真实请求或互操作已通过。
