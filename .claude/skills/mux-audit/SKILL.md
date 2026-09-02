---
name: mux-audit
description: 修改 Prism smux、yamux、h2mux 帧处理、流状态、窗口、读写循环或 mux 关闭逻辑时使用。
---

# 多路复用审计

## 审计范围

当前 mux 实现位于 `src/prism/protocol/multiplex/`，包含核心、smux、yamux 和 h2mux。先读取目标 codec、session、stream、control 和 transport，再判断适用协议，不混用不同 mux 的线格式。

## 审计步骤

1. 列出帧头、长度、类型、stream id 和 payload 边界，检查整数溢出和截断输入。
2. 追踪新建、激活、半关闭、重置和删除 stream 的完整状态机。
3. 检查控制帧、数据帧、窗口更新和最大 stream 限制的顺序与背压。
4. 分别检查读循环、写队列、并发写、flush、错误传播和事件循环退出。
5. 检查 session、stream、transport 和 allocator 在 `co_await` 后的生命周期。
6. 检查对端恶意输入不会造成无限分配、无限重试、死锁或未通知的 stream。

## 重点风险

- 长度字段未限制，导致越界读取或异常内存分配。
- stream 删除后仍访问引用、迭代器或待发送帧。
- 窗口更新错误导致死锁、负计数、溢出或无界发送。
- 读写协程同时修改状态但没有 strand、executor 或原子协议。
- session 关闭时遗留 stream、timer、channel 或 detached 任务。

## 验证

覆盖合法帧、截断帧、未知类型、错误 stream id、窗口边界、最大 stream、reset、半关闭、背压和完整 session close。修改 h2mux 控制帧时运行对应单测和 E2E 测试。

## 相关 Skill

协议帧安全见 `crypto-audit`，协程见 `coroutine-audit`，生命周期见 `co-lifecycle-audit`，隧道转发见 `tunnel-audit`。
