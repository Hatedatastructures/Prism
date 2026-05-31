---
name: review-test
description: 审查代码变更的测试覆盖情况、测试深度和测试质量时触发。用于 PR review、合并前检查、或定期测试健康度评估。
---

# Skill: 测试审查

## 触发条件

审查代码变更的测试覆盖情况、测试深度和测试质量时。用于 PR review、合并前检查、或定期测试健康度评估。

## 审查维度

### 1. 变更-测试映射（最关键）

逐个检查变更涉及的每个函数/类/模块，判断测试是否存在：

```
变更项                    → 对应测试文件            → 状态
func_a() 新增逻辑         → tests/ModuleA.cpp       → ✅ 已覆盖
class_b 新增方法          → （无）                  → ❌ 缺失
config 字段新增           → tests/Config.cpp        → ⚠️ 仅默认值，未测非法输入
handler 错误路径重构      → tests/Handler.cpp       → ⚠️ 仅测 happy path
```

**判定标准**:
- **✅ 已覆盖** — 测试存在且覆盖了变更的核心逻辑
- **❌ 缺失** — 无任何测试对应此变更
- **⚠️ 不充分** — 测试存在但缺少重要场景（错误路径、边界值、并发）

### 2. 测试深度评估

对每个已有测试，逐项检查以下维度：

#### 2.1 正常路径（happy path）
- [ ] 主要功能路径是否有测试
- [ ] 输入/输出是否符合预期
- [ ] 状态变更是否正确验证

#### 2.2 边界与异常
- [ ] 空输入 / 零值 / 最大值
- [ ] 格式错误的输入（截断、多余字节、非法字段）
- [ ] 网络异常（连接中断、超时、部分读取）
- [ ] 资源耗尽（连接池满、内存压力）

#### 2.3 错误注入
- [ ] `MockTransport::set_read_error()` — 读错误路径
- [ ] `MockTransport::set_write_error()` — 写错误路径
- [ ] 意外关闭（`close()` 后操作） — eof 路径
- [ ] 取消（`cancel()` 后操作） — 取消路径

#### 2.4 并发与竞态
- [ ] 多协程同时操作同一对象
- [ ] `co_await` 恢复后状态一致性
- [ ] 跨 strand 操作（如适用）

#### 2.5 协议完整性（协议处理器相关）
- [ ] 完整握手流程
- [ ] 字节级协议解析正确性
- [ ] 大包/小包/分片传输

### 3. 覆盖率评估（定量）

```bash
# 编译覆盖率版本
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Debug -DPRISM_ENABLE_COVERAGE=ON
cmake --build build -j 16
ctest --test-dir build --output-on-failure -j 1

# 生成报告
gcovr --root . --filter "src/prism/" --exclude ".*_deps.*" --exclude ".*tests.*" \
  --html-details build/coverage.html --print-summary
```

**评估标准**:
- **≥80%** 行覆盖率 — 基本合格
- **≥60%** 分支覆盖率 — 基本合格
- 变更文件的覆盖率应 ≥ 项目平均值（不允许变更拉低整体覆盖率）

**关注重点**（非数字本身）:
- 覆盖率数字高但测试只调用函数不检查结果（假覆盖）
- 覆盖率低的热路径代码（session、tunnel、protocol handler）
- 错误处理分支未被覆盖（`if (ec)` / `catch` / `fault::failed`）

### 4. 测试质量检查

#### 4.1 断言有效性
- [ ] 测试是否验证结果 — TestRunner 模式用 `runner.Check()` / `runner.LogPass()` / `runner.LogFail()`，独立模式用匿名命名空间的 `LogPass()` / `LogFail()`
- [ ] 禁止：只调用函数不检查返回值（假通过）
- [ ] 禁止：断言条件始终为 true（如 `Check(1 == 1, "always true")`）

#### 4.2 测试独立性
- [ ] 每个测试文件独立可执行，不依赖其他测试的全局状态
- [ ] 测试间无隐式执行顺序依赖
- [ ] MockTransport 状态在测试间正确重置

#### 4.3 Mock 使用合理性
- [ ] MockTransport 用于**单元测试**（协议解析逻辑的隔离测试）
- [ ] 真实 TCP loopback 用于**集成测试**（完整协议流程，如 Socks5.cpp、Http.cpp）
- [ ] MockTransport 注入的数据是否符合协议格式
- [ ] `ioc.run()` 后所有协程是否自然退出（无挂起）
- [ ] `written_data()` 的验证是否检查了完整的协议响应

#### 4.4 命名与可读性
- [ ] 测试函数 PascalCase 命名清晰表达意图（如 `TestHandshakeWithInvalidVersion`）
- [ ] 禁止：模糊命名（如 `Test1`、`TestCase`）

## 审查流程

```
1. 收集变更范围
   git diff --name-only target_branch...HEAD
   ↓ 筛选 src/prism/ 下的变更文件

2. 识别变更内容
   对每个变更文件，提取：新增/修改的函数、类、配置字段、错误处理分支

3. 查找对应测试
   搜索 tests/ 目录中引用了变更模块的测试文件

4. 逐项评估
   按"变更-测试映射"表逐行填写状态

5. 深度检查已有测试
   对状态为 ✅ 和 ⚠️ 的测试，按"测试深度评估"清单检查

6. 生成审查报告
```

## 审查报告模板

```markdown
# 测试审查报告

## 变更范围
- 分支/commit: {ref}
- 变更文件: {count} 个

## 映射表

| 变更项 | 测试文件 | 状态 | 备注 |
|--------|----------|------|------|
| {item} | {test} | ✅/❌/⚠️ | {detail} |

## 覆盖率
- 行覆盖率: {X}%（变更文件）
- 分支覆盖率: {X}%（变更文件）

## 深度问题
1. {具体问题描述，附文件名和行号}

## 建议
- [ ] {必须修复 — ❌ 项}
- [ ] {建议补充 — ⚠️ 项}
- [ ] {可选优化}

## 结论
- 🟢 可合并 — 测试充分，无缺失
- 🟡 有风险 — 部分变更缺少测试，但非核心路径
- 🔴 需补充 — 核心变更缺少测试，必须补充后合并
```

## 常见反模式

### 假覆盖
```cpp
// ❌ 调用了函数但不检查结果 — 即使函数返回错误也 LogPass
parse_request(input, req);
runner.LogPass("parse_request works");
```
修正：检查返回值和输出字段。

### 过度 Mock
```cpp
// ❌ Mock 了被测对象本身 — 测试的是 Mock 不是真实逻辑
auto transport = std::make_shared<MockTransport>();
transport->inject_read(expected_response);  // 注入的是"期望的输出"
// 这测试的是 MockTransport 能注入数据，不是协议处理器的逻辑
```
修正：Mock 应只模拟依赖项（transport），不模拟被测对象本身。

### 忽略错误路径
```cpp
// ❌ 只测 happy path
runner.Check(ec == fault::code::ok, "success");

// 缺少：
// - 输入截断时的行为
// - 格式错误时的行为
// - 连接中断时的行为
```

### 协程挂起测试
```cpp
// ❌ ioc.run() 永远不返回 — 测试挂起
net::co_spawn(ioc, test_coro(), net::detached);
ioc.run();  // 如果 test_coro 永远不完成，这里永远阻塞
```
修正：协程必须有完成路径（设置 `closed_`、注入 eof、或使用定时器超时）。

> 相关 skill：`write-test` 提供了测试编写模板和 Mock API 速查
> 相关 skill：`bench-perf` 提供了性能回归测试的编写方法
> 相关 skill：`debug-cpp` 提供了测试失败时的排查流程
