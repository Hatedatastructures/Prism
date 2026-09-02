---
name: bench-perf
description: 编写 benchmark、分析性能结果或优化 Prism 热路径时，建立可重复的 Google Benchmark 基线。
---

# 性能基准

## 当前结构

基准代码位于 `benchmarks/`，构建选项为 `PRISM_ENABLE_BENCHMARK=ON`，默认产物位于 `build/benchmarks/`。先读取 `benchmarks/CMakeLists.txt` 和相邻 benchmark，确认 target 名称，不凭记忆运行二进制。

## 工作流程

1. 明确测量对象、输入规模、并发度、分配行为和成功标准。
2. 固定输入、预热、迭代次数和随机种子；区分 setup 成本与被测热路径。
3. 保持 benchmark 结果可重复，记录编译类型、平台、提交状态和关键配置。
4. 修改前保存基线，修改后比较吞吐、延迟、分配次数和内存占用。
5. 只有当数据支持结论时才引入缓存、reserve、PMR 或算法优化。

## 审计清单

- benchmark 没有把 I/O、日志或随机初始化误算进目标阶段。
- 编译器优化没有消除实际工作；结果有合理的 `DoNotOptimize` 或等价保护。
- 不把单机一次结果当成普遍结论，说明噪声和重复运行情况。
- 不为 benchmark 引入生产代码专用的测试分支或不现实的配置。

## 验证

构建和运行前遵守 `AGENTS.md` 的时间、线程、授权和统一 `build/` 目录规则。运行结束后清理本次启动的 benchmark 进程和临时日志，不杀其他同名进程。

## 相关 Skill

测试覆盖见 `review-test`，PMR 见 `audit-memory`，网络热路径见 `tunnel-audit` 和 `mux-audit`。
