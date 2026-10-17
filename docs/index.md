# Prism 文档索引

当前产品与源码主线为 Preview。先按你的目标进入用户指南或开发者手册；按日期保存的审计、计划和运行结果只适用于各自记录的源码快照。

## 用户指南

- [快速开始](tutorial/getting-started.md)：构建、配置路径、启动和发起一次代理请求。
- [配置说明](tutorial/configuration.md)：字段、凭据、协议绑定与 secret reference。
- [部署指南](tutorial/deployment.md)：程序、配置、日志与运行目录。
- [故障排查](tutorial/troubleshooting.md)与[常见问题](tutorial/faq.md)。

## Preview 开发者手册

- [Preview 文档总入口](preview/README.md)：模块、协议、生命周期和验收资料导航。
- [架构总览](ARCHITECTURE.md)：模块职责、依赖方向、启动与请求路径。
- [顶层模块索引](preview/modules/README.md)：13 个非构建 owner 的职责和专题页。
- [协议目录](preview/protocols/README.md)：`Preview/Protocols/` 下全部 23 个一级目录。
- [配置与装配](preview/configuration.md)、[启动与请求路径](preview/request-paths.md)、[所有权与生命周期](preview/ownership-and-lifecycle.md)。
- [构建与分层验收](preview/build-and-validation.md)。

## 历史与参考资料

以下内容保留历史上下文，不作为当前实现或验收结论：

- [`preview-refactor/`](preview-refactor/)：按日期保存的模块分析、质量审查、迁移计划、任务交接与生产交付记录。每份记录以其工作树、配置、源码和二进制范围为准。
- [2026-09-15 Preview 证据](PRISM_PREVIEW_EVIDENCE_2026-09-15.md)和[旧版性能报告](performance-report.md)：仅供对应时期结果参考。
- [旧版 Prism 架构](legacy/prism-architecture.md)：只描述 `include/prism/` 与 `src/prism/`。
- [旧版任务进度](TASK_PROGRESS.md)、[NextGen 任务资料](NEXTGEN_TASK.md)和 [NGX 对照资料](ngx-test-data/INDEX.md)：不替代 Preview 当前配置或运行状态。
- [Clash 客户端配置资料](clash/config.yaml)：字段属于客户端资料，不属于 Preview 服务端 JSON schema。
