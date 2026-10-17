# Prism Preview 文档

本目录是 Preview 当前实现的集中式手册。项目级入口见仓库根目录 [README](../../README.md)，用户指南见 [文档索引](../index.md)，架构总览见 [docs/ARCHITECTURE.md](../ARCHITECTURE.md)。

## 开发者手册

- [模块索引](modules/README.md)：Preview 顶层 owner 的职责、正式入口和依赖位置。
- [协议索引](protocols/README.md)：`Preview/Protocols/` 下所有一级目录及对应说明页。
- [启动、请求和关闭路径](request-paths.md)：应用启动事务、TCP 会话、UDP/QUIC 入站边界。
- [配置与装配](configuration.md)：配置模型、校验、typed binding 和未接线能力的边界。
- [所有权与生命周期](ownership-and-lifecycle.md)：传输 I/O、executor、取消、半关闭、关闭和 drain。
- [构建与分层验收](build-and-validation.md)：构建入口、测试归属和证据口径。

## 文档事实口径

目录或配置字段存在，只能证明源码或模型中有该结构；启动路径实际装配该结构，才说明它接入生产路径；只有绑定当前源码、配置和可执行文件的记录，才能说明某一验收场景已运行。测试目录、测试名称或历史日志本身不构成当前通过结论。

Preview 当前主线由 `Preview/`、`tests/Preview/` 和 `PrismPreview` 构成。旧版 `include/prism/`、`src/prism/` 的实现和专属资源规则仅见 [legacy 参考](../legacy/prism-architecture.md)。按日期生成的重构与验收文件保留在 `docs/preview-refactor/`，由 [历史文档索引](../index.md#历史与参考资料) 导航。
