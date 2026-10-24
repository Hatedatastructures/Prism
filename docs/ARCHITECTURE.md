# Prism 架构

## 范围

`Include/Prism/` 保存当前公开生产接口，`Src/Prism/` 保存实现与私有头，`Test/Prism/` 保存对应功能测试。旧 `include/prism/`、`src/prism/` 和旧测试实现已退役；旧 API 不属于当前接口。

每个生产模块由自己的 CMake target 清单管理公开头、私有头和 `.cpp`。含真实 `.cpp` 的模块使用编译库，纯契约和值类型/开放模板保留 `INTERFACE` target。CMake target 和源码 include 共同表达模块依赖；不能仅凭目录名或 target 名称推断边界。

## 启动路径

进程入口是 `Src/Prism/Application/Main/PrismMain.cpp`。入口从命令行第一个参数取得配置路径；没有参数时，读取可执行文件同目录的 `PrismConfiguration.json`。入口还设置环境变量密钥解析器和默认 Web 资源目录。

公开的 `Application::Start()` 声明位于 `Include/Prism/Application/Definition.hpp`，实现位于 `Src/Prism/Application/Startup/Start.cpp`。启动流程构造并校验配置代次，准备进程服务、协议 provider 与承载绑定，启动网络入口和 Operations 服务，最后发布 readiness。`StartupTransaction` 位于 `Src/Prism/Application/Startup/StartupTransaction.hpp`，是 Application 的私有启动回滚实现；启动中途失败时由该事务回滚已创建的资源。

可执行 target 名为 `Prism`，输出到 `build/src/`。构建后默认配置会复制到可执行文件旁。

## 模块职责

| 模块 | 拥有的责任 |
| --- | --- |
| `Protocols/` | 协议 wire、认证、连接/stream/datagram 状态机及协议会话关闭行为。 |
| `Composition/` | 把配置编译成类型化协议与承载绑定，准备服务并执行能力校验。 |
| `Boundary/` | UDP/QUIC socket、包分类、QUIC CID 与入口 drain/close。 |
| `Runtime/` | worker、listener、session 调度和通用数据面生命周期；TCP acceptor 当前仍由 Runtime 实现。 |
| `Net/` | DNS、出站拨号、路由与通用 relay。 |
| `Transport/` | 统一的 typed I/O 前门、传输装饰与 activity drain。 |
| `Contract/` | 跨模块共享的 typed 请求、服务和数据面契约。 |
| `Lifecycle/` | task 注册、取消、完成通知与 drain 原语。 |
| `Application/` | 读取编译后的配置，创建进程级服务，负责启动、回滚和停机。 |
| `Operations/` | 管理 HTTP 服务、查询、命令和事件 owner。 |
| `Account/`、`Resource/`、`Statistics/`、`Foundation/` | 账户与 lease、资源池、运行统计及通用基础设施。 |

## 请求与关闭

监听入口接收连接或数据报后，Runtime/Boundary 将工作交给已编译的识别与协议绑定。协议模块处理自己的 wire 与认证；成功识别后交付唯一 typed data-plane，Runtime 和 Net 负责通用调度及出站传输。

每个资源需要有清楚的 owner、executor、取消路径、半关闭语义、最终关闭者和 drain 行为。协议代码不负责 Application 启停或跨协议 registry；Runtime 与 Boundary 不实现具体协议装配。

公共接口优先表达真实领域类型与生命周期。不得以万能 context、无关字段参数包、旧接口别名或 fallback 维持第二套正式事实。详细规则见 [所有权与生命周期](prism/ownership-and-lifecycle.md)。
