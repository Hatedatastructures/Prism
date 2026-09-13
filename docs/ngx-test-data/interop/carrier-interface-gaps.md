# Preview Carrier Interface Gaps

本文件只记录当前外部矩阵中明确为 `interface-gap` 的 carrier 缺口。
它不把 codec vector、Preview 自回环或简化握手写成标准外部互操作 PASS。

当前矩阵状态：Reality、Restls 各有两个方向 blocked，ShadowTLS 仅
`preview-client-to-reference-server` 仍 blocked，共 5 条；ShadowTLS
`reference-client-to-preview-server` 已由 Go/mihomo v3 client + Preview relay
真实 authenticated-echo 通过。native TLS codec-vector 另有一条
`environment-unavailable`，不属于本表。

## 统一入口要求

每个 carrier 必须同时提供以下四个可验证层次：

1. Preview client：连接固定版本的 reference server，完成标准 carrier 握手并 echo。
2. Preview server：接受固定版本的 reference client，完成标准 carrier 握手并 echo。
3. Candidate binding：通过 `CarrierAcceptFn` 接入 `LayeredCandidateFactory`，不能只设置 `Spec.Scheme`。
4. 关闭语义：覆盖分片、coalesced payload、EOF、half-close、timeout 和错误认证。

只有 1 和 2 都有真实 wire artifact，矩阵才允许写 `pass`。

## Reality

| 项目 | 当前状态 | 缺口 |
|---|---|---|
| Preview codec | 已有 `preview/Protocols/Reality/Codec.hpp` vector | 仅证明 SessionId/AuthKey/AEAD 字节算法 |
| Preview Conn | `Reality::Conn` 可在已装配参数后读写 | 不负责解析标准 ClientHello、TLS 1.3 ServerHello 或证书 |
| Candidate binding | `TlsCandidateFactory::MakeReality` 只接 executor/callback | 没有可接受真实 TCP ClientHello 的 server endpoint |
| Reference | mihomo `component/tls/reality` API 已固定在 Go module | 需要真实 listener 与本地 deterministic target |

解除条件：Preview server 能解析 key share/session-id，完成 Reality 认证后继续标准 TLS 1.3；
Preview client 能生成 reference 可接受的 ClientHello；两方向各保存 stdout/stderr 和 echo artifact。

## ShadowTLS

| 项目 | 当前状态 | 缺口 |
|---|---|---|
| Preview codec | 已有 HMAC/SessionId vector；`RecordProtector` 与 Go golden 对齐 C/S application-data HMAC 链 | 仍不等于完整双向 ShadowTLS TLS carrier |
| Preview Conn | `Shadowtls::Conn` 支持标准 ClientHello/ServerHello 解析、显式 record protector 和首包 wire 保留 | Preview client 仍没有完整外层 TLS socket factory |
| Preview server relay | `preview/Protocols/Shadowtls/Server.hpp`；C++ `InteropShadowtls` | 已通过 Go/mihomo v3 client→Preview server authenticated-echo；目标 TLS server 为独立 Go `crypto/tls` |
| Candidate binding | `TlsCandidateFactory::MakeShadowtls` 只保存 scheme metadata | 缺少密码、目标站点和 TLS 上下文的长期 owner |
| Reference | mihomo `transport/shadowtls` 已存在，版本固定 | 需要 pinned client/server harness，而非 codec-only tool |

解除条件：补齐 Preview client 的真实 TLS ClientHello/outer TLS 状态机，完成
Preview client→reference server 双向 wire；wrong password 必须在 server commit 前关闭连接，
不能 fallback 到 native TLS。

## Restls

| 项目 | 当前状态 | 缺口 |
|---|---|---|
| Preview codec | 已有 BLAKE3 secret、mask、auth_mac vector | 当前 `Restls::Conn` handshake 是简化状态，不是完整 TLS 1.2/1.3 record script |
| Preview Conn | 可在已知 ServerRandom 下进入透传 | 不负责真实 ClientHello/ServerHello、record script、padding 和 fallback target |
| Candidate binding | `TlsCandidateFactory::MakeRestls` 只有 callback 接口 | 没有标准 server/client carrier endpoint |
| Reference | `restls-client-go v0.1.9` 提供 `Dial` 与 `RestlsServer` | 需要固定 script、证书、target 和双向本地 echo harness |

解除条件：至少覆盖 TLS 1.3 默认 script、TLS 1.2 fallback、认证失败、record 分片和
目标站点 relay；仅通过 `restlscmp` 不足以解除此 blocker。

## 不应采取的替代

- 不把 `CarrierAcceptFn` 返回原始传输就标记成 carrier PASS。
- 不把 `realitycmp`、`shadowtlscmp`、`restlscmp` 的 vector 结果复制到 authenticated-echo 方向。
- 不让 `MixedTrial` 在 carrier 认证失败后无条件回退 native TLS。
- 不修改 `src/prism/` 或 `include/prism/` 的 analyzer 来绕过 Preview 证据门禁。

## 解锁顺序

1. 先在 Go harness 中固定 reference server/client 版本、证书、key、SNI、目标端口和 echo payload。
2. 在 Preview 新增单一 carrier endpoint 和 `CarrierAcceptFn` adapter。
3. 先跑 Preview client → reference server，再跑 reference client → Preview server。
4. 将两方向原始 artifact 注册到 `Run-Matrix.ps1`，失败分类保持 `protocol-failure` 或 `implementation-mismatch`，不能静默 skip。
5. 两方向稳定通过后，才更新 migration decision；之前保持 `experimental`/`keep-psm`。
