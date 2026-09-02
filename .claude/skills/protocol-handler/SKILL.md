---
name: protocol-handler
description: 在 Prism 中新增或修改入站代理协议、协议检测或 handler 工厂时，按当前 dispatch 流程实施并验证。
---

# 协议 Handler 接入

## 触发条件

- 新增入站代理协议或协议类型
- 修改 `handshake::recognition` 的检测、预读或回落
- 修改 `protocol::make_protocol_handler()` 或具体 handler
- 修改协议配置、协议聚合头、CMake 或协议集成测试

## 当前调用链

```text
listener -> balancer -> worker -> session
  -> handshake::recognition::recognize()
  -> session::diversion()
  -> protocol::make_protocol_handler()
  -> protocol handler::run()
  -> outbound dial -> tunnel
```

关键事实：协议工厂位于 `src/prism/protocol/handler.cpp`，接口和参数位于 `include/prism/protocol/handler.hpp`。检测代码位于 `handshake/recognition/`，应以当前目录和调用点为准。

## 接入步骤

1. 读取 `protocol_type`、recognition 结果和 session diversion 的现有定义。
2. 明确新协议首包是否可在当前预读限制内识别；不能因为识别困难而过度读取或丢弃预读数据。
3. 在 `include/prism/protocol/<name>/` 和 `src/prism/protocol/<name>/` 按邻近协议的结构实现 codec、connection、handler 和配置。
4. 实现当前 `protocol_handler` 接口，保持握手、认证、目标解析、上游拨号和响应语义与协议标准一致。
5. 在 `make_protocol_handler()` 增加工厂分支；未知类型必须保留原有失败语义。
6. 在 settings、validator、configuration 示例和相关聚合头中同步配置与 include。
7. 在对应 CMake source list 和测试 CMake 中注册文件与 target。
8. 添加成功、格式错误、认证失败、超时、上游失败、EOF 和关闭顺序测试。

## 边界要求

- 不在 handler 中实现同步 DNS、阻塞 socket 或线程睡眠。
- 不把协议认证失败统一改成 Web 回落；回落行为必须由识别层和协议语义共同决定。
- 不把检测结果当作已认证；handler 仍必须完成协议认证和输入校验。
- 不跨 `co_await` 保存未经证明有效的引用、span、string_view 或迭代器。
- 热路径错误使用项目错误码；启动配置错误遵循异常层次。

## 验证

先运行协议单元测试，再运行对应 runtime/integration 测试。修改识别或回落时额外检查 `probe-audit`；修改认证时检查 `replay-audit` 和 `leak-audit`。构建和测试必须遵守 `AGENTS.md` 的授权、统一 `build/` 目录和线程规则。

## 相关 Skill

配置见 `map-config`，测试见 `write-test`，复用协议见 `mux-audit`，双向转发见 `tunnel-audit`。
