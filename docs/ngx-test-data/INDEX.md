# Next-Gen 测试数据索引

本目录记录 `tests/common` 新架构的可重复测试基线、协议完成度和对拍材料。

## 文档

- [protocol-matrix.md](protocol-matrix.md)：协议与公共层的完成度矩阵（L1-L5 等级 + Gate A-D 证据）。
- [benchmark.md](benchmark.md)：preview 性能基线（6 个 bench，2026-08-18）。
- [coverage.md](coverage.md)：覆盖率报告（lines 91.2%，2026-08-18）。
- `transmission.md`：传输接口、关闭、取消、超时和半关闭语义（**待建**——Gate D 生命周期审查的一部分）。
- `interop/`：preview 与生产栈、外部实现的对拍记录——[psm-l4.md](interop/psm-l4.md)（L4 生产对拍，2026-08-20）。
- `vectors/`：codec、认证和坏包测试向量（**待建**——Gate D golden vector 二选一）。

## 记录规则

1. “有实现”不等于“已完成”；每个协议分别记录 codec、session、回环、生产对拍、外部互操作、性能、stress 和 fuzz。
2. 回归测试必须记录测试目标、异常路径和关闭语义，不能只记录成功样例。
3. 测试命令统一使用仓库 `build/` 目录；不在本目录存放构建产物、运行日志或凭据。
4. 每次协议行为或公共传输契约发生变化时，同步更新矩阵中的证据和下一道门禁。

## 迁移前待建材料（Gate D 清单）

| 材料 | 位置 | 内容 |
|---|---|---|
| 生产对拍记录 | `interop/psm-l4.md`（2026-08-20） | preview client ↔ 生产 Prism server；socks5/ss2022 双向 PASS，vless/trojan/vmess 认证失败路径 PASS、echo 受阻于生产识别器（`probe/analyzer.cpp`） |
| 外部互操作/golden vector | `interop/` 或 `vectors/` | mihomo/sing-box 或确定性字节向量 |
| 性能对标 | `benchmark.md` 追加 | preview vs psm 同场景对比 |
| 生命周期审查 | `transmission.md` + 结论文档 | relay/udp_service/mux 的关闭、取消、超时语义结论 |
