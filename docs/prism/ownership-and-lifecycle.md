# 所有权与异步生命周期

异步操作必须说明谁持有对象、在哪个 executor 上运行、如何取消、半关闭如何传播、谁执行最终关闭，以及调用方怎样等待 drain。协议私有状态由协议模块拥有；跨模块共享的数据面使用 typed contract。

## 挂起点与借用

- `co_await` 之后，重新确认引用、指针、迭代器和 span 指向的对象仍存活。
- detached 协程只能捕获具有足够生命周期的 owner；不得借用即将离开作用域的 session 或配置引用。
- allocator/memory resource 必须比使用它的容器和对象活得更久。由 owner 提供资源，不在调用侧猜测池的生命周期。
- 一个 I/O 对象只由其规定的 executor/strand 串行访问。不得在协程里同步阻塞 socket、DNS、sleep 或等待 future。

## 关闭次序

关闭通常分成请求关闭、取消尚未完成的 I/O、传播写半关闭、等待活动任务和子流 drain、释放底层资源。收到关闭请求不等于资源已经退休；只有真实 owner 完成并报告 drain，调用方才能释放依赖它的状态。

应用启动失败由启动事务回滚已创建的 owner；运行期停机由 Application 协调 Runtime、Boundary、协议服务和 Operations 的关闭。各协议仍拥有自己的 wire/session 清理，不把协议关闭逻辑塞进 Application。

## 接口检查

新增或修改公共异步接口时，记录输入是借用还是转移、结果/错误形状、取消和半关闭行为、最终关闭者以及 executor。函数参数通常不超过两个；复杂边界参数应有真实领域语义。

详细模块边界见 [架构说明](../ARCHITECTURE.md)。旧版资源层级只作历史背景，不作为当前 Prism 的 owner 模型。
