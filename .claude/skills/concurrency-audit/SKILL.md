---
name: concurrency-audit
description: 修改原子状态、CAS、strand、channel、timer 或跨 worker 同步时，审查 Prism 的并发语义和关闭竞态。
---

# 并发语义审计

## 审计流程

1. 画出状态的所有读写者、所属 executor 和线程边界。
2. 确认同一 worker 的串行假设是否真实成立，不能仅因使用同一个 `io_context` 就假定没有竞争。
3. 对每个原子操作说明可见性、顺序性和是否需要 CAS；按最小必要内存序选择 `relaxed`、`acquire`、`release` 或 `acq_rel`。
4. 检查 timer、socket、channel 和 worker stop 的竞态顺序。
5. 检查统计计数是否允许近似值，还是必须与资源状态严格一致。

## 重点问题

- `store` 不使用不存在的 `acq_rel`；发布/获取关系必须由成对操作建立。
- CAS 失败路径必须重新读取当前值，并限制重试或明确无锁进度保证。
- strand 只保护绑定其上的 handler，不会自动保护外部线程访问。
- stop、close、cancel 和析构必须幂等，重复通知不能导致 use-after-free。
- 无锁 channel 的发送失败、接收取消和生产者退出必须有处理路径。

## 禁止项

- 在协程热路径使用 `std::mutex` 或阻塞等待。
- 用忙循环观察原子 flag。
- 用日志或非原子普通变量作为跨线程同步手段。
- 未说明线程模型就把共享对象标记为线程安全。

## 验证

列出线程/executor 图、每个同步变量的状态机和关闭顺序。优先运行相关并发测试；若依赖时序，增加可控通知或测试 hook，不以延长 sleep 作为稳定性方案。

## 相关 Skill

协程约束见 `coroutine-audit`，对象存活见 `co-lifecycle-audit`，资源归还见 `audit-memory` 和 `tunnel-audit`。
