---
name: audit-memory
description: 修改 PMR 容器、memory resource、对象分配或异步资源生命周期时，审查 Prism 内存来源、释放和跨协程使用安全。
---

# PMR 与内存审计

## 当前约束

Prism 在启动阶段启用全局内存池；具体容器仍可能显式绑定 frame arena、worker 或 session resource。审计必须以目标类型和构造点为准，不能假定所有 PMR 对象都来自同一个 resource。

## 审计步骤

1. 找出容器、字符串、allocator 和 memory resource 的实际类型与来源。
2. 画出 resource 的所有者和使用期，确认它覆盖所有同步和异步使用。
3. 检查 copy、move、swap、rehash、reserve 和析构时的 allocator 语义。
4. 检查 `span`、`string_view`、迭代器和裸指针是否跨越 resource 或对象生命周期。
5. 检查分配失败、取消、异常、worker stop 和 session close 的释放路径。
6. 只在有性能证据时讨论 reserve、池大小和热路径分配；不凭经验改池策略。

## 高风险边界

- detached 协程保存 L3 resource 或引用 L3 容器。
- PMR 容器移动到不同 resource 后仍假设 allocator 不变。
- frame arena 在协程恢复前释放。
- 释放顺序反转导致 allocator、socket 或日志上下文悬空。
- 为修复分配问题引入线程不安全的全局缓存。

## 验证

修改 allocator、内存池配置或资源所有权后，运行对应 memory/lifecycle 测试和 `scripts/audit_detached.sh`。报告必须说明 resource 来源、存活范围、异常路径和测量依据。

## 相关 Skill

协程资源见 `co-lifecycle-audit`，跨线程访问见 `concurrency-audit`，性能测量见 `bench-perf`。
