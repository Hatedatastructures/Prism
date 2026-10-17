<div align="center">
  <h1>Prism</h1>
  <p>基于 C++23 与 Boost.Asio 的异步多协议服务端。</p>
</div>

当前开发和验收主线为 **Preview**：生产源码位于 `Preview/`，测试位于 `tests/Preview/`，程序 target 为 `PrismPreview`。旧版 `include/prism/` 与 `src/prism/` 是独立实现，不代表 Preview 的接口或验收状态。

## 开始使用

Preview 构建使用仓库现有 `build/`。详细的配置、凭据和请求步骤见[快速开始](docs/tutorial/getting-started.md)与[配置说明](docs/tutorial/configuration.md)。

```powershell
cmake -B build -DCMAKE_BUILD_TYPE=Release
Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
cmake --build build --config Release --target PrismPreview -j 16
```

上海时间 08:00–22:00 使用 `-j 16`，22:00–08:00 使用 `-j 1`。每次构建前检查时间；构建必须符合当前任务授权。程序位于 `build/src/PrismPreview.exe`（Windows）或 `build/src/PrismPreview`（Linux），默认读取同目录的 `PreviewConfiguration.json`。

## 文档入口

- [文档索引](docs/index.md)：用户指南、Preview 开发资料与历史参考。
- [快速开始](docs/tutorial/getting-started.md)、[配置](docs/tutorial/configuration.md)、[部署](docs/tutorial/deployment.md)。
- [Preview 架构](docs/ARCHITECTURE.md)与[模块手册](docs/preview/README.md)。
- [故障排查](docs/tutorial/troubleshooting.md)与[常见问题](docs/tutorial/faq.md)。

Preview 文档分别说明配置模型、启动接线和已绑定当前版本的运行证据；代码目录存在、配置能解析或测试已注册，不代表真实请求、互操作或性能通过。历史验收材料按其原日期和范围保留，不用来描述当前二进制。

许可证：[MIT](LICENSE)。
