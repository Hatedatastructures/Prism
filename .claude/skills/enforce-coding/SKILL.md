---
name: enforce-coding
description: 编写或修改 Prism C++ 代码时，按项目当前迁移阶段执行命名、类型、协程、内存和注释规范。
---

# Prism C++ 编码规范

## 触发条件

- 新增或修改 `.hpp`、`.cpp`、CMake 中的 C++ target
- 修改公共类型、函数签名、枚举、聚合头文件或 PMR 容器
- 修改协程、异步 I/O、资源所有权或错误传播逻辑

## 执行规则

1. 先读取目标文件、相邻头文件和所属模块的 CMake；不要按文件名猜测接口。
2. 以根目录 `AGENTS.md` 为项目级事实来源；本 skill 只补充可执行检查。
3. 存量文件遵循所在迁移阶段的风格，同一文件内不得混用新旧命名。
4. 新增代码按 PascalCase 命名空间、类型、函数、变量、成员和常量；宏保持 UPPER_CASE。
5. 代码目录和文件名遵循当前模块的实际迁移状态。大小写改名必须使用两步法，并同步 CMake、include 和脚本。

## 必查清单

- 函数参数通常不超过 3 个，更多参数收敛为 options 结构体。
- 函数体不超过 120 行；复杂 lambda 提取为命名函数。
- 返回类型使用项目约定的尾随返回类型；有意义的返回值加 `[[nodiscard]]`。
- 资源所有权使用 RAII；非拥有指针不得承担释放责任。
- 热路径容器使用项目已有的 PMR 别名和资源，不自行引入新的全局池。
- 不在协程中使用阻塞 I/O、互斥锁、同步 DNS、线程睡眠或忙等待。
- 不使用 `using namespace`；使用显式限定或 namespace 别名。
- 固定宽度整数、`nullptr`、`enum class`、`constexpr` 和 `override` 按语义使用。
- 头文件使用 `#pragma once`；新增公共头同步聚合头和 CMake source list。
- `.hpp` 的公共声明使用中文 Doxygen；`.cpp` 只添加必要的中文 `//` 说明。
- 注释描述真实职责、边界和失败行为，不复制项目级规则或虚构契约。

## 命名迁移

仓库当前处于 PascalCase 迁移期。生产代码、preview 代码和测试代码可能处于不同阶段；先观察同一目录的现状，再决定是否迁移。纯大小写改名必须检查 Linux CI 或 WSL，不能只依赖 Windows 的大小写不敏感行为。

## 验证

- 检查 include、聚合头和 CMake 是否同步。
- 对协程变更运行对应测试，测试必须使用 `co_spawn + ioc.run()`。
- 对文件迁移运行仓库已有的路径和 detached 审计脚本。
- 不因为本 skill 自动执行构建、提交、推送或删除进程。

## 相关 Skill

协程细节见 `coroutine-audit`，对象生命周期见 `co-lifecycle-audit`，PMR 见 `audit-memory`，测试见 `write-test`。
