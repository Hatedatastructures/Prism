# Preview 所有权与生命周期合同

Preview 不采用旧版 `L1/L2/L3/L4` resource 模型作为当前 owner 表。当前结构以具体模块的所有权、typed lease、固定 executor、close receipt 和 drain 状态为准。

## 模块 owner

| Owner | 持有与关闭责任 |
| --- | --- |
| Application | 进程级服务、配置 generation、启动事务、回滚和有界停机。 |
| Boundary | TCP/UDP socket、datagram packet pump、QUIC admission/CID ingress 与入口 drain。 |
| Runtime | worker、listener/session 调度和通用数据面活动；不实现具体协议 wire/auth。 |
| Protocols | 协议凭据、wire/session、stream/datagram 状态机和协议 owner 关闭。 |
| Composition | 启动冷路径的协议/provider 准备、冻结、绑定与能力校验；不关闭协议连接。 |
| Account | typed identity、认证结果与 account/stream lease；租约由实际 root/session owner 持有和释放。 |
| Lifecycle / Transport | task/activity 观察、操作预约、取消与 drain 契约；不替代协议 owner 的关闭责任。 |

模块完整分工见[模块索引](modules/README.md)。实际接口的 owner 优先级由源码实现和公开合同决定。

## Transmission 前门

`Preview::Transmission` 是 Preview 的 typed I/O 前门。其公开异步操作包括 `ReadSome`、`WriteSome`、`ReadExact`、`WriteExact`、`WriteShutdown`、`Cancel` 和 `Close`；I/O 结果以 `IoResult{Bytes, Failure}` 表达，关闭/取消控制结果是 typed expected。

- I/O span 由调用方借用到该操作 completion 返回；调用方必须保证 buffer 和传输 owner 在异步完成前有效，并按方向遵守串行发起合同。
- completion 只交付一次，并在 handler 关联 executor 上异步完成；载体操作与控制状态由传输固定的 executor 域管理。
- `Cancel()` 是可重复的取消请求。取消不撤销已经完成的字节，也不证明底层已关闭。
- `WriteShutdown()` 只关闭本端写方向；对端方向仍可读。成功后调用者不得继续写。
- `Close()` 封止新准入并交付派生 close 行为；成功表示命令已接管，不自动证明底层、协议 session 或进程已退休。
- `Activity()->Drain()` 等待操作预约、handler 退出及关闭回执。只有真实 owner 的关闭/完成回执满足合同后，相关资源才可退休。

包装层可能借用下层而不拥有最终 close 权；`NextLayer()` 导航不等于所有权转移，`Release()` 才是明确的层移交操作。任何实现都需核实 `OwnsClose()`、活动预约、实际下层回执和 executor 约束，不能把 wrapper 的 `Close()` 成功写成 socket 已释放。

## 取消、半关闭、关闭与 drain

这四种操作不能互换：取消尝试中断进行中的 I/O；写半关闭保留反向读取；close 封止新操作并交付 owner close；drain 等待真实活动和异步完成全部退出。异步测试和部署流程应分别观察这些阶段，避免仅凭取消成功、listener 停止或日志输出推断资源已释放。

Detached 协程和 PMR 规则属于旧版源码时，应使用 [legacy Prism 架构参考](../legacy/prism-architecture.md)。Preview 中的新异步 owner 应按本页和具体模块页追踪真实强/弱持有、executor、operation completion 与关闭回执。
