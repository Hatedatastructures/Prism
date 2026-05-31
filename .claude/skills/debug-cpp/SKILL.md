---
name: debug-cpp
description: 排查协程死锁、内存异常、协议交互错误、性能抖动等运行时问题时触发。
---

# Skill: 调试方法论

## 触发条件

排查运行时 bug、协程挂起、内存泄漏、协议握手失败、性能异常时。

## 调试流程

### 1. 复现与分类

确定三个维度:
- **现象**: 崩溃 / 挂起 / 性能劣化 / 协议错误 / 数据错误
- **范围**: 单连接 / 并发 / 特定协议 / 特定配置
- **可复现性**: 必现 / 偶发 / 压力下才出现

### 2. 协程挂起排查

| 检查项 | 方法 |
|--------|------|
| co_await 永不完成 | 检查被等待对象是否有完成路径（定时器超时、channel 关闭） |
| io_context 被阻塞 | 检查协程中是否有阻塞操作（`sleep_for`、同步 DNS、文件 I/O） |
| strand 跨线程操作 | 确认同一对象的所有操作在同一条 strand 上 |
| 对象被提前销毁 | co_await 恢复后 `this` / 成员引用是否悬挂 |

### 3. 内存问题排查

| 现象 | 排查方向 |
|------|----------|
| PMR 内存持续增长 | 检查 `frame_arena` 是否缺少 `reset()`；检查长生命周期容器是否有淘汰 |
| 悬挂引用崩溃 | 检查 `co_await` 后是否使用了旧迭代器/引用/裸指针 |
| shared_ptr 循环 | `co_spawn` lambda 是否按值捕获 `self`（shared_ptr） |
| use-after-free | `erase()` 后是否使用返回值更新迭代器 |

### 4. 协议交互排查

| 检查项 | 方法 |
|--------|------|
| 握手失败 | 用 MockTransport 注入对端字节序列精确复现 |
| 字节序错误 | 网络字节序（大端）vs 主机字节序检查 |
| 部分读取 | `async_read_some` 可能返回部分数据，需循环读取 |
| 缓冲区残留 | 预读（preview）数据是否正确传递给下一层 |

### 5. 性能问题排查

```
1. 跑 bench 确认基线（bench-perf skill）
2. 定位热点（VTune / Windows Performance Analyzer / VerySleepy）
3. 检查 PMR 路径：是否走了系统 malloc 而非池分配
4. 检查锁竞争：是否有 mutex（应替换为 atomic/strand/post）
5. 检查内存分配频率：热路径是否频繁构造临时对象
```

## 工具链

| 工具 | 用途 | 备注 |
|------|------|------|
| spdlog 日志 | 运行时行为追踪 | `trace::config` 控制级别和格式 |
| ASAN | 内存错误检测 | `PRISM_ENABLE_ASAN=ON` 编译。MinGW ASAN 可能遗漏部分错误类别（如 stack-use-after-scope），Clang ASAN 覆盖更全 |
| Google Benchmark | 性能回归对比 | `bench-perf` skill |
| GDB (MinGW) | 断点/协程帧检查 | `gdb build/src/Prism.exe`，`info coroutines` 查看协程帧（需 GCC 12+） |
| WinDbg | Windows 原生调试 | 崩溃转储分析、线程栈检查 |
| VTune | CPU 热点分析 | Intel CPU 性能分析 |
| MockTransport | 协议交互复现 | 精确注入字节序列 + 错误注入 |

## 日志排查模式

```bash
# 调整日志级别（在 configuration.json trace 节）
"log_level": "debug"     # 开启详细日志
"pattern": "[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v"

# 过滤特定模块
# 在日志输出中 grep 模块名/连接 ID
```

## 禁止事项

1. 禁止在生产协程中加 `sleep` 调试（用 spdlog 日志代替）
2. 禁止忽略 ASAN 报告（即使看似误报也需确认）
3. 禁止用 `printf`/`cout` 调试（用 `psm::trace::info/error`）
4. 禁止用 MockTransport 做性能测量（它有 100μs 轮询延迟）
5. 禁止跳过复现直接猜测修复（必须先稳定复现）

> 相关 skill：`write-test` 提供了 MockTransport 精确注入数据的方法
> 相关 skill：`bench-perf` 提供了性能基线对比的方法
> 相关 skill：`coroutine-audit` 提供了协程纯度检查清单
> 相关 skill：`audit-memory` 提供了 PMR 内存审计清单
