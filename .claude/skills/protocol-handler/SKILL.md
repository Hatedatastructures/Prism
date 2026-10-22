---
name: protocol-handler
description: 在当前 Prism 中新增或修改代理协议、协议识别或类型化装配时，按模块 owner 实施并验证。
---

# 协议 Handler 接入

## 触发条件

- 新增入站代理协议或协议类型
- 修改 Runtime recognition、预读或协议 admission
- 修改 Composition 的协议/承载类型化绑定
- 修改协议配置、协议聚合头、CMake 或协议集成测试

## 当前责任边界

```text
Runtime TCP listener / Boundary UDP-QUIC ingress -> Runtime admission/session
  -> Runtime recognition -> typed protocol/carrier binding
  -> Protocol owner -> Net/Transport data plane
```

协议的 wire、认证、连接/stream/datagram 状态机和关闭行为由 `Include/Prism/Protocols/<Name>/` 与 `Src/Prism/Protocols/<Name>/` 的对应 owner 负责。`Composition` 负责配置到类型化协议/承载绑定的装配和能力校验；`Runtime` 负责 worker、listener、session 调度与通用数据面生命周期；`Boundary` 负责 UDP/QUIC socket、包分类、QUIC CID 及入口 drain/close。

不要假设存在旧版统一字符串协议工厂。配置/启动冷路径可以按名称查询 `ProtocolCatalog`；热路径使用已编译的 typed binding。不要让协议实现反向依赖 `Composition`、`Application` 或 `Runtime`。涉及识别、装配或入口时，沿当前真实调用点和 typed binding 检查职责归属。

## 接入步骤

1. 读取 `AGENTS.md`、目标协议的 `Include/Prism/Protocols/<Name>/` 公共接口、`Src/Prism/Protocols/<Name>/` 实现与 owner CMake、相邻测试。
2. 明确变更属于协议行为、识别、Composition binding，还是通用入口；只改相应 owner。识别困难时也不能过度读取或丢弃预读数据；检查 probe、replay 与 admission 的边界。
3. 保持协议规定的认证、目标解析、错误映射、取消、半关闭和最终关闭语义。
4. 若配置或能力绑定受影响，同步检查当前配置解析、校验与 Composition 装配路径。
5. 在对应模块 CMake 登记实现与私有头，并更新 `Test/Prism/Protocols/<Name>/` 或真实跨模块集成场景的测试；适用时覆盖成功、格式错误、认证失败、超时、上游失败、EOF、取消、半关闭、最终关闭顺序。

## 边界要求

- 不在 handler 中实现同步 DNS、阻塞 socket 或线程睡眠。
- 不把协议认证失败统一改成 Web 回落；回落行为必须由识别层和协议语义共同决定。
- 不把检测结果当作已认证；handler 仍必须完成协议认证和输入校验。
- 不跨 `co_await` 保存未经证明有效的引用、span、string_view 或迭代器。
- 热路径错误使用项目错误码；启动配置错误遵循异常层次。

## 验证

先运行协议单元测试，再运行对应 Runtime/Integration 测试。修改识别或 admission 时额外检查预读与回放边界；修改认证时检查失败映射、资源退休和敏感数据泄漏。构建和测试必须遵守 `AGENTS.md` 的授权、统一 `build/` 目录和线程规则。

## 相关 Skill

配置见 `map-config`，测试见 `write-test`，复用协议见 `mux-audit`，双向转发见 `tunnel-audit`。
