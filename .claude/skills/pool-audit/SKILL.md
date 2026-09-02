---
name: pool-audit
description: 修改实际存在的连接池、DNS ConnPool、资源复用、健康检查或驱逐策略时，审查归还和容量边界。
---

# 资源池审计

## 适用范围

先确认目标确实是资源池。当前 preview 网络代码包含 DNS `ConnPool`；生产代码不应被假定存在通用 checkout/checkin 连接池。若目标不是池化资源，应改用 `tunnel-audit`、`audit-memory` 或 `concurrency-audit`。

## 审计步骤

1. 找出资源创建、借出、使用、归还、失效和销毁的完整路径。
2. 检查成功、错误、取消、异常、超时、移动和重复关闭是否都会释放或归还资源。
3. 检查健康检查与实际使用之间的失效窗口，以及失败后的驱逐语义。
4. 检查容量、每目标限制、等待超时和空闲回收是否有真实配置或明确默认值。
5. 检查池的 executor、线程归属、统计计数和关闭时序。

## 不做的假设

- 不要求不存在的池具备 RAII checkout API。
- 不把“所有路径必须归还”套用到已经失效、应销毁而不是复用的连接。
- 不用阻塞锁或同步健康检查阻塞事件循环。
- 不凭经验添加容量和 timeout 数字；必须引用配置、测试或测量。

## 验证

覆盖池空、池满、健康检查失败、对端关闭、归还失败、取消、驱逐竞态和 worker stop。修改 preview DNS 池时运行对应 preview tests；涉及协程或资源生命周期时补充相关专项审计。

## 相关 Skill

PMR 见 `audit-memory`，并发见 `concurrency-audit`，隧道连接见 `tunnel-audit`。
