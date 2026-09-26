# Preview Diagnose 最终验收报告

日期：2026-09-26
仓库：I:/code/Prism
分支和基准提交：main，a4fb25e9
任务卡 G 状态：已交接验收（HANDOFF_ACCEPTED）
协调者：主任务协调者

## 验收结果

| 验收项 | 结果 | 证据 |
|---|---|---|
| 定向串行测试 | 通过，387/387 项；失败 0 项；错误 0 项 | [JUnit XML 结果](../../build/preview-diagnose-final-ctest.xml) |
| 紧凑文本性能测试 | 通过，1/1 项 | [紧凑文本性能数据](../../build/preview-diagnose-compact.json)，[输出样例](../../build/preview-diagnose-compact.json.sample.log) |
| 扩展模式性能测试 | 通过，2/2 项 | [带字段文本数据](../../build/preview-diagnose-human-with-fields.json)，[输出样例](../../build/preview-diagnose-human-with-fields.json.sample.log)；[结构化输出数据](../../build/preview-diagnose-structured.json)，[输出样例](../../build/preview-diagnose-structured.json.sample.jsonl) |
| 后端依赖边界 | 通过；PreviewApplication 是唯一私有后端所有者；业务 Preview 目标没有暴露 spdlog 编译或头文件依赖 | [目标依赖闭包报告](../../build/preview-diagnose-target-closure.txt) |
| 结构化输出脱敏检查 | 通过；样例包含 Stream 7 和密码脱敏结果，不包含 benchmark-secret 测试标记 | 上方结构化输出样例 |
| Session 关闭审计 | 通过；SessionAuditTest 验证 session_closed 记录恰好输出一次 | 上方 JUnit XML 结果 |
| 旧 API 引用检查 | 通过；最终扫描未发现已删除的 Context、Log、Logger、TraceSnapshot 或无 owner 的 TryWrite API 引用 | 最终源码扫描 |
| 资源清理 | 通过；验证后没有匹配的 Preview/Diagnose 测试进程，也没有 Diagnose 临时目录 | 最终进程和临时目录检查 |

使用的 JUnit 命令：

    ctest --test-dir build --output-junit preview-diagnose-final-ctest.xml -R "PreviewDiagnose|PreviewLogger|G2Log|PreviewApplication|PreviewTaskLoggingConfiguration|PreviewTask3Configuration|Task10|SessionOrchestration|SessionLifecycleTest|SessionRecognitionMode|TimeoutRelay|SessionAudit|MuxSession|Hysteria2Factory|TuicFactory|StartsConfiguredTuicQuicAdmission|SessionDiversionFactory.Tuic|TransportLayer|PreviewTransport|PreviewDeep|PreviewTransmission|PreviewMockTransportContract|PsmTransmission|NativeHttp3Session|XhttpErrorMatrix|Transport|Perf_CompactPathBenchmark|Perf_ExtendedPathBenchmark" --output-on-failure -j 1

运行后解析 JUnit XML：共 387 个测试项，失败元素 0 个，错误元素 0 个。这是 Preview 定向回归测试，不是整个仓库的完整 CTest 测试集。没有单独启动 PrismPreview 服务进程。

## 性能测试记录

每种情景先预热提交 10,000 次，再进行 5 轮测量，每轮提交 20,000 次，因此每种情景共有 100,000 次测量。消息大小分别为 128 字节、512 字节和 2 KiB。性能数据记录提交耗时、提交线程 CPU 时间、内存分配次数、队列最高水位、普通信息级日志丢弃数、排空耗时，以及关闭时的刷新和线程汇合耗时。

| 输出模式 | 上下文 | 消息大小 | 平均 / 95%分位 / 99%分位提交耗时（纳秒） | 每次提交分配次数 | 丢弃数（占 10 万次的比例） |
|---|---|---:|---:|---:|---:|
| 紧凑文本 | 无 | 128 字节 | 351 / 400 / 600 | 1 | 56,006（56.0%） |
| 紧凑文本 | 工作线程/会话 | 128 字节 | 364 / 400 / 700 | 1 | 55,796（55.8%） |
| 紧凑文本 | 无 | 512 字节 | 582 / 700 / 1,100 | 3 | 54,467（54.5%） |
| 紧凑文本 | 工作线程/会话 | 512 字节 | 581 / 700 / 1,100 | 3 | 54,367（54.4%） |
| 紧凑文本 | 无 | 2 KiB | 2,229 / 1,400 / 2,100 | 5 | 52,037（52.0%） |
| 紧凑文本 | 工作线程/会话 | 2 KiB | 2,104 / 1,600 / 2,600 | 5 | 51,766（51.8%） |
| 带字段文本 | 扩展字段 | 128 字节 | 560 / 600 / 1,000 | 4 | 54,435（54.4%） |
| 带字段文本 | 扩展字段 | 512 字节 | 767 / 900 / 1,500 | 6 | 52,992（53.0%） |
| 带字段文本 | 扩展字段 | 2 KiB | 1,273 / 1,400 / 6,600 | 8 | 50,902（50.9%） |
| 结构化输出 | 扩展字段 | 128 字节 | 1,428 / 1,700 / 2,900 | 9 | 17,385（17.4%） |
| 结构化输出 | 扩展字段 | 512 字节 | 1,565 / 1,700 / 3,800 | 11 | 30,967（31.0%） |
| 结构化输出 | 扩展字段 | 2 KiB | 2,101 / 2,300 / 15,400 | 13 | 42,754（42.8%） |

所有情景的队列最高水位都达到 8,192 条。压测特意让提交速度超过后端处理速度，因此出现普通信息级日志丢弃；这些丢弃属于本次过载测量结果，会保留供后续比较。此前没有旧版性能数据或明确的数值回归门槛，所以本次只能建立首轮基线，不能证明相较旧实现有所提升或退步。

这里的平均值表示所有测量样本的算术平均；95%分位和 99%分位分别表示 95% 和 99% 的提交耗时不超过该值。消息格式化发生在提交线程，因此这些数据包含提交线程的消息格式化成本，不等于磁盘写入耗时或端到端代理延迟。

## 数据完整性与清理

- 结构化输出样例每行是一条 JSON 记录，包含 Stream 7；密码显示为脱敏值；样例中没有 benchmark-secret 测试标记。
- SessionAuditTest 验证 session_closed 只输出一次；普通日志提交失败只计入观测数据，不会回滚已完成的网络操作。
- CMake 依赖闭包报告确认 spdlog 只作为 PreviewApplication 后端的私有编译依赖。PrismPreview 最终静态链接闭包中包含预期的 spdlog 链接依赖。
- 本轮只使用现有 build 目录。没有单独启动应用服务；验证后没有匹配的测试进程，也没有匹配的 Diagnose 临时目录。
- 用户提供的源计划文件保持未修改。

## SHA-256 校验值

构建和验证产物：

| 产物 | SHA-256 |
|---|---|
| build/src/PrismPreview.exe | 3E8AD8C89FE3ED7097A2B0E4BB035963870661B3A28E1AB47ED7A40573F5B367 |
| build/CMakeCache.txt | AD81B3A774985F1EC8CED63331557DC0FC72D14AF16A866A9CDEE7294D29DC1B |
| build/preview-diagnose-final-ctest.xml | D6CC29AD97CE0541880E57A6CBA8022CA8505A3F1A2BB03AAB643ACD85A16D0F |
| build/preview-diagnose-target-closure.txt | 7F68E31E889CF80E9D56E03ABE8F1529312F71275FCD18843A199507ABB2107D |
| build/preview-diagnose-compact.json | 1A2DCF01D8FB7A4B622E14ADEAB2010B6ABD3D94CB5D2A1A321E6FC50ED19DB9 |
| build/preview-diagnose-human-with-fields.json | 3DA2471558F418CE8E80E5D7FAB2D3A2FC8F4887306471BD78BD1472427CE346 |
| build/preview-diagnose-structured.json | 3BDD947472EBA3F2D4CDE86DEB297BC80E11591470C10DC441540D360A1A9180 |

源码和配置：

| 输入文件或集合 | SHA-256 |
|---|---|
| Preview、tests/Preview、tests/TestSupport 下已更改或未跟踪源码集合 | 15207AFAD8D4402E38F4425914EAE4575E28894E4B257AB1AD7789151163A61A |
| Preview/Foundation/Utility/Diagnose/Facade.hpp | D154070E5D39DF9D4B7AD9E56B2EAB45BE509ED813A84B5E94CA3D389A5F1EBC |
| Preview/Foundation/Utility/Diagnose/TraceContext.hpp | C489A661C20B09755521FA7F4C2682DCEF41294AB52989E4AAFC02A5746B0B1C |
| Preview/Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp | 34B23403982760C44711888607308B02E8F1997F1BF5F6F96A1A8A7A2BC5EA2E |
| Preview/Foundation/Utility/Diagnose/Detail/BackendLifecycle.hpp | A73DB627B6F72B8FF510975BDA49E00068E884E58A516EC46285581F37DC589C |
| Preview/Application/Application.cpp | 031AD8E197582166035360C4C7049CCCA410668A184CB74737FAC19B2E6C35BF |
| Preview/Application/Configuration/PreviewConfiguration.json | C245C56845ACC08F415F14CB372F1FABE54F541241E914880A0BE536D80E3501 |
| Preview/CMake/PreviewBoundary.cmake | 8C7283B2702972208C48AA31B8E0CB7BC34CDEA6338D3E0FCD2C677DE6957BF1 |

源码集合摘要包含按路径排序的 67 条记录。每个现存文件记录仓库相对路径、制表符和该文件的 SHA-256；已删除文件记录路径及 DELETED 标记。所有记录以换行符连接后按 UTF-8 编码计算 SHA-256。docs/preview-refactor 下的文档不计入源码集合摘要。
