---
name: write-test
description: 为 Prism 新增或修改 GoogleTest、MockTransport、MockTlsServer、preview 或 contract 测试时，遵循当前测试结构和协程驱动方式。
---

# Prism 测试编写

## 当前测试结构

- 生产测试公共设施：`tests/TestSupport/Production/`
- TLS 测试公共设施：`tests/TestSupport/Tls/`
- preview 公共设施：`tests/TestSupport/Preview/`
- 测试 runner：`tests/TestSupport/Runner/`
- target 注册入口：`tests/CMakeLists.txt`

当前使用 `AddProductionTest`、`AddPreviewTest` 和 `AddContractTest`，不得使用历史测试注册 helper 或未定义的 `TestSupport` target。

## 编写流程

1. 先确定测试属于 production、preview 还是 contract，并读取相邻测试和所属 CMake。
2. 先写可观察的行为断言，再选择最小的 fixture、transport 或 TLS server。
3. 正常路径之外，覆盖输入截断、格式错误、认证失败、超时、取消、上游错误、EOF 和重复关闭。
4. 异步测试使用 `net::co_spawn` 启动测试协程，并由 `ioc.run()` 驱动完整生命周期。
5. 测试协程完成后显式关闭 session、socket、timer 和 channel；completion handler 记录异常并停止事件循环。
6. 新测试文件加入正确 CMake target，测试函数使用 PascalCase。

## 协程测试硬规则

- 禁止 `start() + ioc.poll()` 或 `start() + ioc.run_for()` 驱动核心异步对象。
- 不用固定 sleep 等待事件；使用 channel、timer 或明确的完成通知。
- 不在测试中保存跨 `co_await` 的悬空引用、迭代器或临时 string_view。
- MockTransport 和 MockTlsServer 的 API 必须以当前头文件为准，不复制旧示例接口。

## 测试质量

- 断言结果和错误原因，不只断言“没有崩溃”。
- 错误路径验证资源关闭和事件循环退出，避免测试假通过或挂死。
- 并发和时序问题使用可控同步，不通过扩大超时隐藏竞态。
- 不引入真实凭据、外部网络依赖或开发者本机路径。

## 验证

构建后优先直接运行目标测试，或使用 `ctest --test-dir build -R <pattern> --output-on-failure`。需要完整回归时遵守 `AGENTS.md` 的构建授权和资源清理规则。

## 相关 Skill

覆盖审查见 `review-test`，协程测试见 `coroutine-audit`，协议测试见 `protocol-handler`。
