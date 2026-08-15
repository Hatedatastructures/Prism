# TASK_PROGRESS

> 自动维护，勿手工编辑。每个单元结束更新。
> 无人值守：只记录事实与决策，不向用户汇报。测试数据见 docs/test-data/（主项目任务）
> 与 docs/ngx-test-data/（Next-Gen 任务）。

## 任务套件

| 套件 | 规范文件 | 数据目录 | 任务 |
|---|---|---|---|
| 主项目 | docs/LONG_TASK.md v5 | docs/test-data/ | T1-T9（主项目修复/演进） |
| Next-Gen | docs/NEXTGEN_TASK.md | docs/ngx-test-data/ | T0-T7（tests/common 新一代架构） |

> 两套任务不并行执行；本文件按当前执行中的套件维护对应总览。

## 总览（Next-Gen 套件：tests/common → 新一代架构）

| 任务 | 状态 | 进度 | 备注 |
|---|---|---|---|
| T0 传输接口补齐 | pending | 0% | D1：shutdown/set_timeout/is_open |
| T1 架构收口 | pending | 0% | M1-M10 误导清理 |
| T2 协议面补缺 | pending | 0% | xhttp/ech/native/recognition/http2（D2） |
| T3 网络层 | pending | 0% | dialer/route/dns/UDP 中继/http1.1（D4/D5） |
| T4 运行时骨架 | pending | 0% | session 编排 + 中间件完善（D9） |
| T5 运营层积木 | pending | 0% | O1-O7 + settings + stress，详设 NGX_OPS_DESIGN |
| T6 替代验证 | pending | 0% | 对拍/互操作/性能/fuzz（D6） |
| T7 质量加固 | pending | 0% | 四象限平台化 |

## 当前焦点

- 任务：T0-1 传输接口补全
- 单元：transmission 增加 shutdown/set_timeout/is_open
- 门禁：尚未开始
- 数据文件：docs/ngx-test-data/transmission.md（未创建则创建）

## 已完成单元

- 无

## 决策记录（全自动模式）

- 无

## 错误日志

- 无

## SKIP 记录

- 无

## 后续候选（行为漂移记录）

- 无

## 待提交清单（全部任务完成后生成，供用户处理）

- 无
