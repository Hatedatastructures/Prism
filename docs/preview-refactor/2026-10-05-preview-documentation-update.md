# Preview 文档同步：2026-10-05

本轮已更新 **44 个已有或新增 Markdown 路径**，并新增本文作为文档同步证据入口，共45个路径。修改目的为纠正旧程序、旧配置、旧目录与过时状态的误导，保持有效的模块指南与历史验收原文。完整代码重构继续执行，当前范围见[执行状态](2026-10-03-preview-no-compat-status.md)，文档任务卡见[执行计划](2026-10-03-preview-no-compat-execution.md)。本文不签整个 Task4 或整个 Preview。

## 文件范围与结果

| 范围 | 数量 | 实际改动 |
| --- | ---: | --- |
| 当前开发与模块入口 | 4 | 新增 `Preview/README.md`；Preview 架构前置，完整保留旧版资源安全正文；Account 指向真实正式 owner，说明存量目录/Runtime复用；Diagnose 保留详细指南并修正失效表述和历史证据边界 |
| 用户与代理操作入口 | 8 | 根README、文档索引、五篇tutorial与CLAUDE统一PrismPreview、严格配置、位置参数、现有build和真实运行限制 |
| tests/common历史规范 | 1 | 保留规范正文，补当前生产合同入口和历史范围 |
| 既有计划/分析/验收导航 | 21 | 补原版本快照范围与当前入口，不改旧结果、数字或当时的失败 |
| ngx测试/对拍资料导航 | 8 | 给原测试日期和原source范围加当前状态导航，保留原始数据 |
| 当前执行计划/状态 | 2 | 修正模型为5.6-luna/max、Root协调角色、当前卡状态、文档D1–D5和后续责任；合并过时状态的重复叙述，旧字节另存 |

原文件 before、隔离草稿、来源矩阵、审查与机器回执位于 `.superpowers/sdd/2026-10-03-preview-no-compat-execution/`。改动清单和最终逐文件哈希保存在该目录的 `docs-final-current-manifest.json`。所有此前脏工作树改动保留，未执行提交或推送。

## 已纠正的操作错误

- 默认路径改为 `Preview/Application/Configuration/PreviewConfiguration.json`，CMake复制到 `build/src/PreviewConfiguration.json`；可执行程序为 `PrismPreview`。
- 当前main把第一个位置参数直接用作配置路径，旧教程的 `--config <path>` 说明被移除。
- 配置按严格PascalCase和14个必填根字段解释；旧 `agent/pool/stealth/trace` 配置片段从当前教程退出。
- 账户 JSON 没有 `MaxConnections/MaxStreams` 字段，不能把真实cold账户policy测试写成JSON quota已接线。
- 非空 `Routes` 当前被启动校验以 `UnsupportedService` 拒绝；Statistics/HotReload按实际接线状态说明。
- NativeTLS相对文件路径基于配置目录，Logging相对目录基于进程工作目录；Operations Endpoint必须loopback。
- 当前main没有Windows ServiceMain，删除直接 `sc create` 安装原生服务的误导；Linux示例明确是未执行模板。
- CLAUDE通过现行AGENTS集中规则，消除旧目录、旧测试数量和夜间线程数冲突。

## 审查与静态验证

代理按用户要求使用 `gpt-5.6-luna/max`，继承上下文并按具体文件卡工作。Root逐段读实际源码与文档差异，独立确认并返修：过时handoff的“mux未构建”结论、错误物理Lifecycle路径、伪造的模板/namespace、非物理行数，以及Diagnose过度裁减。原Diagnose约53KB详细API/字段/示例保留；原ARCHITECTURE从“设计原则”起的9083个字符在归一LF后与新legacy正文完全一致。

13份拟落盘的当前文档与规范在应用前检查了 **167条非代码块本地链接**，缺失0；配置教程5个JSON片段均通过PowerShell JSON语法解析。该检查只证明文档路径和片段语法，不替代真实配置解析、curl、后台运行或平台部署测试。正式文件在代码代理全部工具退出的安全边界应用，逐文件与冻结草稿哈希比对。

文档应用时，原1927条source inventory增长为1928条：变化只有两个模块README、根README、tests/common/SPEC和新增Preview/README。没有修改任何C++、生产header、CMake或配置。随后Account文字收口在007真正代码编辑前完成并重新捕获真实before；所有既有snapshot未覆盖。

文档应用的首个回执生成曾因PowerShell布尔写法出错；13个文件已复制完成。Root保留原空回执，并按实际文件与冻结草稿重建校验回执，没有倒填成新的事前快照。细节见 `docs-root-formal-apply-receipt.json` 与 `docs-account-wording-fix.json`。

## 同期代码验收与后续

006 quota2最终版实际构建成功，同suite6/6通过，failure/error/skip均0。它证明两族真实MaxStreams=1时第二wire child被拒绝、无新dial、第一child继续literal回显，最终lease/drain/weak释放。Root对1927编译输入前后及当前hash漂移0，单元只改一个测试文件；AST最大函数体99行。XML SHA256 `225726E6B68F6006F5E348ED625D631B6071A4F81D35B4BF56F5C8CDF65319F3`，exe SHA256 `80CDE9A6FA16EF2AA4FA0C179FD2CF8F6EFA7D8EE69AB513234FD13E3467CB29`。

首轮缺少真实continuation、长函数、错误target强制构建、首次echo等待错误和后续错误断言均保留各自raw/source/退出结果，不能合成一个生产缺陷或写成全部首轮通过。007继续验证同根FIN后的真实lease释放和replacement；另一代理只读复核六个生产owner的多alias/root、关闭/drain、executor和物理边界。

Task4尚未整体冻结与签收，Task5→6A→6B→6C→7A→7B→8仍按原范围继续。最终D5在正式源码完成后再次核对本文相关接口、目录、字段和证据。当前文档静态签收不代表全量CTest、完整PrismPreview listener/互操作、性能改善或Linux编译通过。
