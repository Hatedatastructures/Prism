---
name: write-test
description: 编写或修改测试用例、添加新测试文件、MockTransport/MockTlsServer 集成时触发。
---

# Skill: 测试编写

## 触发条件

编写测试、修复测试失败、添加新测试文件、使用 MockTransport/MockTlsServer 时。

## 框架 API 速查

### TestRunner（推荐模式）

```
构造:    TestRunner("Tag")
断言:    Check(cond, "msg")       — 通过 LogPass，失败 LogFail
日志:    LogPass("msg")           — 递增 passed_
         LogFail("msg")           — 递增 failed_
退出:    Summary() → int          — 0=全通过, 1=有失败（内部调用 trace::shutdown）
```

头文件: `tests/common/TestRunner.hpp`

### MockTransport

继承 `psm::transport::transmission`，内部持有 `net::io_context`。

```
注入数据:  inject_read(vector<byte>{...})
          inject_read(byte_ptr, size)
捕获写入:  written_data() → const memory::vector<std::byte>&
清空捕获:  clear_written_data()
注入错误:  set_read_error(ec)      — 一次性，下次 async_read_some 返回
          set_write_error(ec)     — 一次性，下次 async_write_some 返回
状态查询:  is_closed() / is_cancelled()
驱动异步:  get_io_context().poll()  — 非阻塞推进
          get_io_context().run()   — 阻塞直到所有协程完成
```

头文件: `tests/common/MockTransport.hpp`

关键行为:
- 注入数据后需调用 `ioc.poll()` 或 `ioc.run()` 才能被读协程感知
- 队列为空时 `async_read_some` 通过 100μs 定时器轮询挂起
- 关闭后所有读写返回 `fault::code::eof`

### MockTlsServer

```
启动:  co_spawn(ioc, mock_tls_server::run(acceptor, max_conn), detached)
行为:  自动生成 Ed25519 自签证书，TLS 1.3 only，握手后 echo 回显
```

头文件: `tests/common/MockTlsServer.hpp`

## 测试文件模板

### main() 骨架（TestRunner 模式）

```cpp
#include "common/TestRunner.hpp"
// ... 其他 include

namespace
{
    psm::testing::TestRunner runner("ModuleName");
}

int main()
{
    SetConsoleOutputCP(CP_UTF8);          // Win32 UTF-8 输出
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    // 运行测试协程...

    return runner.Summary();
}
```

### 协程测试模式

```cpp
auto test_something(net::io_context& ioc)
    -> net::awaitable<void>
{
    // 服务端协程
    auto server = [&]()
        -> net::awaitable<void>
    {
        // accept / MockTransport / 协议处理
    };

    // 客户端协程
    auto client = [&]()
        -> net::awaitable<void>
    {
        // 发送请求 / 验证响应
    };

    net::co_spawn(ioc, server(), net::detached);
    net::co_spawn(ioc, client(), net::detached);
}
```

### main() 骨架（独立模式 — 协议集成测试常用）

约 25% 的测试（主要是协议集成测试）使用独立模式，适合需要精细控制 `ioc.run()` 生命周期的场景：

```cpp
#include "common/MockTransport.hpp"
// ... 其他 include

namespace
{
    std::int32_t passed = 0;
    std::int32_t failed = 0;
    void LogPass(std::string_view msg)
    {
        ++passed;
        psm::trace::info("PASS: {}", msg);
    }
    void LogFail(std::string_view msg)
    {
        ++failed;
        psm::trace::error("FAIL: {}", msg);
    }
}

int main()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    psm::memory::system::enable_pooling();
    psm::trace::init({});

    // 每个测试函数内部创建自己的 io_context 并 run()
    TestBasicHandshake();
    TestAuthFailure();

    psm::trace::shutdown();
    return failed > 0 ? 1 : 0;
}
```

两种模式的选择：
- **TestRunner 模式** — 纯逻辑测试（配置、序列化、解析），不需要 `io_context`
- **独立模式** — 协议集成测试（每个测试函数有自己的 `ioc.run()` 周期）

## CMake 注册

在 `tests/CMakeLists.txt` 中添加:
```
forward_add_test(TestName, TestName.cpp)
```

`forward_add_test` 自动:
- 创建独立可执行文件
- 链接 `${PROJECT_NAME}_static_library`
- MinGW 环境添加 `-static` 链接选项
- 注册为 CTest 测试

## 编写规则

1. **独立可执行** — 每个测试文件是独立的 .cpp，有自己的 main()，不共享全局状态
2. **结果传递** — 协程测试用 `shared_ptr<bool>` 传递结果，禁止全局变量
3. **驱动方式** — MockTransport 测试用 `ioc.poll()`（非阻塞单步推进）或 `ioc.run()`（完整执行）
4. **命名规范** — 测试函数 PascalCase（`TestBasicGetRequest`），与生产代码 snake_case 区分
5. **协程纯度** — 测试协程中同样禁止阻塞操作（同生产代码 `coroutine-audit` 规范）
6. **错误路径** — 必须测试错误场景（`set_read_error` / `set_write_error` / 意外关闭）
7. **资源清理** — `ioc.run()` 完成后所有协程应自然退出，不得残留挂起协程
8. **编译选项** — 测试统一 `-g1 -Os`（最小调试信息 + 体积优化）
9. **并发测试** — 需两个终端同时运行 `tests/concurrency/server` + `tests/concurrency/client`

## 常见测试模式

### 协议处理器测试

服务端: accept → 创建 transport → 协议 handler → handshake → echo
客户端: connect → 发送原始协议字节 → 验证响应字节
验证: shared_ptr 传递结果到 main() 层

### 序列化/反序列化测试

构造输入 → 调用 parse/serialize → Check 输出字段 → 验证边界（空输入、截断输入）

### 配置加载测试

构造 JSON string → deserialize → Check 各字段默认值和解析值 → 验证 enabled() 逻辑
