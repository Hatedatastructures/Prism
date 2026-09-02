---
name: tunnel-audit
description: 修改 Prism 双向转发、relay、EOF、半关闭、空闲超时或流量统计时，审查隧道生命周期和数据完整性。
---

# 双向隧道审计

## 审计流程

1. 找出下游、上游、relay 协程和所有 stop/close/cancel 入口。
2. 分别审查读方向和写方向，不把一个方向的 EOF 当作另一方向立即失败。
3. 检查 `async_read_some`、`async_write`、部分读写、零字节结果和错误码处理。
4. 检查 TCP half-close、全关闭、超时和取消时的剩余数据语义。
5. 检查 relay 退出后另一侧、统计对象、timer 和子任务的释放顺序。
6. 检查每个错误是否能到达调用者或日志，避免双重报告和静默丢失。

## 重点风险

- 读到 EOF 就立即关闭双向 socket，丢失反向剩余数据。
- `async_write` 未保证完整发送，或把部分写误判为成功。
- 两个 relay 协程同时关闭同一资源，产生竞态或重复统计。
- 空闲 timer 与真实流量更新竞争，导致过早驱逐或永不超时。
- 统计在异常路径未刷入，或关闭后仍访问 session/worker 资源。

## 验证

覆盖双向数据、单向 EOF、半关闭、部分读写、上游失败、超时、取消、重复 close 和统计刷入。优先运行 `tests` 中对应 tunnel/forward 测试，再运行受影响协议的集成测试。

## 相关 Skill

协程见 `coroutine-audit`，生命周期见 `co-lifecycle-audit`，错误链见 `error-chain-audit`，日志见 `parse-proxylog`。
