---
name: debug-cpp
description: 排查 Prism C++ 崩溃、协程挂死、协议交互错误、连接关闭异常或性能抖动时使用。
---

# C++ 运行时诊断

## 诊断流程

1. 记录可复现步骤、平台、构建类型、配置摘要和精确错误。
2. 先读取相关调用链和最近变更，再用日志、测试和最小复现验证假设。
3. 将问题分类为协议解析、异步调度、生命周期、并发、内存、网络或配置。
4. 在最近的边界处加入最小观测，不用大量日志改变时序或泄露凭据。
5. 修复根因后补回归测试，检查相邻错误路径和关闭顺序。

## Prism 入口

- 运行日志通常位于 `logs/forward.log` 和 `logs/prism.log`，先以源码实际输出格式为准。
- 连接链路从 runtime/session 进入 protocol handler，再进入 outbound 和 tunnel。
- 协程问题优先检查 executor、co_spawn completion handler、取消和 `co_await` 后引用。

## 禁止做法

- 不用无限重试、忙等待或扩大 timeout 掩盖问题。
- 不用同步 I/O、互斥锁或 `run_for()` 作为诊断性修复。
- 不打印密码、UUID、PSK、私钥、完整 token 或原始认证数据。
- 不按名称强杀系统进程；只清理本次会话启动且已确认不再需要的 PID。

## 验证

优先运行能复现问题的单个测试，再运行相邻模块测试。需要启动 server/client 时记录 PID，任务完成立即按 PID 清理。最终报告区分已证实原因、排除项、修复和未验证风险。

## 相关 Skill

协程见 `coroutine-audit`，生命周期见 `co-lifecycle-audit`，错误链见 `error-chain-audit`，日志解析见 `parse-proxylog`。
