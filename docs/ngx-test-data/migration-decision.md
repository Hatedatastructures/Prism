# Preview 迁移决策矩阵

> 更新日期：2026-09-03
>
> 本表只记录证据驱动的迁移建议，不执行 `src/prism/` 或 `include/prism/` 迁移。
> `experimental` 表示 Preview 仍是参考实现或能力不完整；`keep-psm` 表示生产实现
> 仍是当前可用路径；`migrate` 只有在 L1-L5、生命周期和同 harness 性能证据齐全后
> 才允许使用。

| 组件 | L1/L2 | L3 | L4 生产对拍 | L5 外部互操作 | 性能 | 当前建议 | 阻塞 |
|---|---|---|---|---|---|---|---|
| HTTP / SOCKS5 | 已有 Preview 测试 | SOCKS5 TCP/UDP 已有纵向证据 | SOCKS5 双向 PASS | 全量外部矩阵待补 | 同 harness 待补 | `experimental` | Gate D L5/性能 |
| VLESS | codec/session + 非法 ATYP 已验证 | TCP/UDP 纵向 PASS | echo 受生产 analyzer 阻塞 | 待补 | 待补 | `experimental` | 生产前置、L5、性能 |
| Trojan | codec/session 已验证 | TCP/UDP 纵向 PASS | echo 受生产 analyzer 阻塞 | 待补 | 待补 | `experimental` | 单端口识别、生产前置 |
| VMess | codec/session 已验证 | TCP/UDP 纵向 PASS | echo 受生产 analyzer 阻塞 | 待补 | 待补 | `experimental` | 单端口识别、生产前置 |
| Shadowsocks 2022 | raw PSK/长度边界已验证 | TCP/UDP 纵向 PASS | 双向 PASS | sing-shadowsocks 双向 PASS | codec Contract 已输出；网络 harness 待补 | `experimental` | 完整性能对拍 |
| XHTTP / HTTP2 | 标准字段和状态负向已验证 | Stream-one 已验证 | 待补 | 待补 | 待补 | `experimental` | stream-up/packet-up、L5 |
| WebSocket / gRPC | codec/session 已验证 | 局部 E2E | 待补 | 待补 | 待补 | `experimental` | 外部全链路 |
| Reality / ShadowTLS / Restls | codec/session 已验证 | 未闭合 | 待补 | codec-vector 已通过；full E2E 待补 | 独立基线 | `keep-psm` | SNI/真实对拍 |
| AnyTLS / TrustTunnel | codec/session 已验证 | 未闭合 | 待补 | codec-vector 已通过；full E2E 待补 | 独立基线 | `keep-psm` | HTTP2/真实对拍 |
| Hysteria2 / TUIC v5 | codec + provider 接口已验证 | native ngtcp2 UDP loopback 1/1；协议认证流未闭合 | 未做 | quic-go/sing-quic 待做 | 待做 | `experimental` | Hysteria2/TUIC 真实认证流、外部 L5、性能 |

## 门禁状态

- Preview Evidence Gate：进行中；本地确定性测试、TLS/SNI 基础解析、native QUIC loopback 和 datagram provider 接口回归已通过，外部 L5 与完整网络性能仍未闭合。当前矩阵结果 52 条（8 pass、44 blocked、0 failure）。
- Production Prerequisite Gate：`blocked-production-prerequisite`；VLESS/Trojan/VMess 真实单端口 echo 需要生产 analyzer 授权变更。
- 总 Gate D：未关闭；本轮明确不修改生产代码，也不以直接 handler 对拍替代单端口证据。

机器证据入口：外部矩阵逐用例 JSON 与汇总位于 `build/interop-results/`，codec 性能
Contract 位于 `build/tests/Contract/preview-production-perf.json`；这些文件由 runner
生成，表格中的 `blocked` 只表示明确的环境或生产前置阻塞，不等同于通过。

## 结果记录格式

外部互操作和性能 runner 必须写出以下字段，文档只引用结果文件：

```json
{
  "protocol": "ss2022",
  "direction": "preview-client-to-reference-server",
  "scenario": "authenticated-echo",
  "implementation": "sing-shadowsocks@0.2.12",
  "commit": "<runner checkout commit>",
  "platform": "windows-x64",
  "status": "pass",
  "exit_code": 0,
  "command": "<reproducible command>",
  "artifacts": ["<raw log>", "<metrics json>"]
}
```

允许的 `status` 值为 `pass`、`protocol-failure`、`implementation-mismatch`、
`environment-unavailable` 和 `blocked-production-prerequisite`。任何非 `pass` 状态
都必须保留原始日志和失败原因。
