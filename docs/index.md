# Prism 文档

当前主线为 Preview。先从用户操作或开发入口进入，构建和运行统一使用 `PrismPreview` 与 `PreviewConfiguration.json`。本文索引更新于 2026-10-08。

## 当前使用与维护

- [快速开始](tutorial/getting-started.md)：构建、默认配置、位置参数、就绪和代理请求。
- [配置说明](tutorial/configuration.md)：严格 PascalCase 字段、协议绑定与 secret 来源。
- [部署指南](tutorial/deployment.md)：程序与配置布局、进程运行库、停机与部署验证。
- [故障排查](tutorial/troubleshooting.md)、[常见问题](tutorial/faq.md)。
- [Preview 开发入口](../Preview/README.md)、[架构说明](ARCHITECTURE.md)。
- [正式 Account 模块](../Preview/Account/Account.hpp)：认证、记录与 lease 均由当前 Account owner 提供；原 Utility Account README 已随旧目录退役。
- [Diagnose 使用与实现指南](../Preview/Foundation/Utility/Diagnose/README.md)。

## 重构状态与验收

- [当前执行状态](preview-refactor/2026-10-03-preview-no-compat-status.md)：已签收卡、当前卡、剩余责任与验证层级。
- [10月5日文档同步证据](preview-refactor/2026-10-05-preview-documentation-update.md)：当前入口、教程和历史范围的实际修订与静态核对。
- [无兼容层执行计划](preview-refactor/2026-10-03-preview-no-compat-execution.md)：代码任务与文档同步卡。
- [9月28日模块分析台账](preview-refactor/2026-09-28-preview-module-refactor-analysis.md)：问题与迁移计划的历史起点。
- [10月3日会话执行质量复核](preview-refactor/2026-10-03-preview-session-execution-review.md)：当时已执行与待执行责任。

## 历史材料

以下文档记录各自当时的设计或测量结果，适用版本以文档日期、源码、配置与 executable hash 为准。当前验收从上面的执行状态进入。

- [9月26日 Diagnose 基线](preview-refactor/2026-09-26-preview-diagnose-baseline.md)与[最终阶段证据](preview-refactor/2026-09-26-preview-diagnose-final-evidence.md)。
- [9月15日 Preview 证据](PRISM_PREVIEW_EVIDENCE_2026-09-15.md)。
- [原 Next-Gen 实施计划](NEXTGEN_IMPLEMENTATION_PLAN.md)、[原任务进度](TASK_PROGRESS.md)。
- [旧版性能报告](performance-report.md)、[ngx 对照与互操作资料](ngx-test-data/INDEX.md)。
- [Clash 配置示例](clash/config.yaml)与[参考](clash/reference.yaml)：客户端资料，字段不属于 Preview 服务端 JSON schema。
