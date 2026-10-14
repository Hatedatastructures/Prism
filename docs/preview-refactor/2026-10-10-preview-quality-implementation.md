# Preview 质量整改源码执行记录

批准计划：[2026-10-09-preview-quality-modification-plan.md](2026-10-09-preview-quality-modification-plan.md)。

原树 `I:/code/Prism` 存在其他会话的活动构建与写者，因此生产改动在管理工作树 `C:/Users/C1373/.codex/worktrees/preview-quality/Prism` 进行。工作树以原树当时的脏源码为输入，没有还原 HEAD 或覆盖用户增量。向原树集成前须重新比较每份输入。

本轮仅实施源码；不构建、不运行测试、请求、互操作或性能测量，不新增或重组测试，不提交或推送。SourceComplete 仅表示源码接口、拥有关系、调用者和登记闭合。

## 当前任务状态

|任务|状态|已形成的源码交付|仍需闭合|
|---|---|---|---|
|M00|SourceComplete|2169 文件精确字节与 hash 基线、267 缺失路径、101 问题映射、43 张完整任务 Brief、共享集成裁定|最终签收须重新捕获源码漂移|
|M01|SourceReview|Failure、typed Target/Host/DomainName、数值端口、明确 RouteKind、实际协议/拨号/装配/观察调用者、新头 CMake|统一其余正式结果中的 Failure/Native、私有 wire 双形状及整卡审查|
|M02|SourceReview|128 MiB 默认冷字节池、有界位图预约、move-only OwnedBytes、无分配归还、真实 worker 资源入口|队列节点、帧和长期 RX 消费者预算与整卡审查|
|M03/M04|InProgress|预建关闭动作、原 executor 退休、4096 共享活动槽、TaskReservation、单调任务身份、typed drain、Runtime 部分调用链|协议绑定/QUIC/Gateway、Application 停机、现有 fixture 与最终审查|
|M05|SourceReview|SHA/HMAC/HKDF/随机/X25519/Block 明确结果、调用者 span、秘密清理、两条 Reality 实际握手与既有调用者|上层旧 Error/bool 边界完整 Native 保留与整卡审查|
|M09|InProgress|DNS typed 规则、拥有型 query identity、ID 预约、地址/CNAME 有界存储正在实现|Resolver/Upstream/QueryExecutor 串行接入及审查|
|其余任务|Pending|依赖和接口政策已经固定|按批准卡顺序继续实施|

## 已确认的共享政策

- 普通失败使用 Failure/expected，不通过项目异常传递；现有 AuthFailed 和 ProtocolError 分别承担认证拒绝与非法 wire，不新增同义兼容枚举。
- task ID 仅由进程单调分配；FromParent 复制 Session/Stream/Worker/Generation 与 ParentTaskId，不复用父 task ID。
- TaskRegistry 析构只封止并发布原子取消；实际 owner 显式 Cancel/Drain，预约直到真实退栈才归还。不能在隐式 noexcept 析构中临时投递可分配命令。
- 关闭交付、I/O 退栈和资源退休分别报告；不可投递资源继续保活 context，不能跨 executor 析构或提前清零。
- DNS 纯 scanner 与生产关联检查承担不同责任；生产前门核对完整 question、ID、type、class 和 CNAME 关联。

## 已执行的源码检查

Memory 目录 10 个头、73 个函数；Crypto 目录 11 个头、52 个函数；Runtime/Session 目录 8 个头、49 个函数。当前检查均为语法解析错误 0，文件/函数/lambda/参数上限告警 0。解析器对空列表默认参数的已知限制使用保持偏移的恢复；没有调用 C++ 编译器。

工作树内 `.superpowers/sdd/2026-10-09-preview-quality-modification-plan/` 保存具体卡报告、审查、hash 和源文本基线。上述局部源码检查不表示全 Preview 规则清零，也不表示构建、运行或性能通过。
