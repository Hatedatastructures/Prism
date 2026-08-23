# Preview 接入主项目 — 长程计划（职责分层版 v2）

> 2026-08-19 重新摸底 + 用户纠正耦合后重写。核心修正：
> **协议库不得依赖 runtime/middleware/fault**；接入缝是一个独立 adapter 模块；
> **代理协议**与**伪装/TLS 方案**是两条不同职责链，必须分开处理。

## 1. 模块职责边界（强制，违反即耦合）

| 层 | 目录 | 职责（只做这些） | 禁止依赖 |
|---|---|---|---|
| 协议-代理 | `protocols/socks5 vless trojan vmess shadowsocks2022` | 帧编解码、conn/dgram 握手与数据面、工厂 `accept`/`connect`（返回 `error + request_header + shared_conn`） | runtime、middleware、fault |
| 协议-伪装 | `protocols/anytls reality shadowtls restls ws xhttp gun trusttunnel native ech` | 把裸传输包装成 TLS/伪装传输（传输装饰器）；`accept`/`connect` 做 TLS 握手返回装饰后 `shared_conn` | runtime、middleware、fault |
| 协议-QUIC | `protocols/hysteria2 tuic quic` | QUIC 传输族（独立传输） | 同上 |
| 识别 | `core/recognition/` | probe → 协议类型；TLS 时 SNI 路由 + **scheme 应用**（缺） | — |
| 运行时 | `core/runtime/` | listener / session 编排（recognize→accept_protocol→prepare→dial/relay/udp） | 协议细节（只认 `protocol_accept_fn`） |
| 中间件 | `core/middleware/` | auth/dial/mux/pad/relay + `context`（target/identity 等共享态） | 协议细节 |
| 网络 | `core/net/` | dialer/dns/outbound/route（建连、解析） | 协议细节 |
| **接入缝（新增）** | `core/runtime/adapter/` 或 `core/integration/` | **唯一**把协议 `accept` 结果映射进 `middleware::context`（填 target/identity/is_dgram）+ `error→fault::code` 映射，产出 `protocol_accept_fn` | —（允许同时依赖 protocols + runtime + middleware） |

> 关键教训：之前把 `middleware::context`/`fault::code` 塞进 `trojan.hpp` 是越界，已撤销。
> `make_accept_vless`/`make_accept_socks5` 现在写在 E2E 测试里，必须**提进 adapter 模块**，协议库保持纯净。

## 2. 两条独立的职责链

### 链 P — 代理协议纵向（传输已建立后的应用层握手）
```
listener → recognition(识别代理类型)
  → adapter::make_accept_<proto>(cfg)  // 唯一桥：协议 accept → context
  → session(prepare 填 target / dial / relay / udp_service)
```
- 现状：SOCKS5/VLESS 已 L3（但 wiring 在测试里）；Trojan/VMess/SS2022 缺 L3。
- 做法：在 adapter 模块加 `make_accept_trojan/vmess/ss2022`，不碰协议库。

### 链 S — 伪装/TLS 方案（传输层包装，识别之前）
```
listener → recognition(probe)
  → [TLS?] scheme_executor 应用 protocols/<stealth>::accept 包装裸 socket → 装饰传输
  → 再对装饰传输跑协议识别 → 链 P
```
- 现状：preview `recognition` 只有 probe+SNI route，`recognize_result.scheme` 记了名但**无 scheme_executor 真正应用包装**。伪装协议全是 L1/L2 参考实现，**完全未接入站管线**。
- 做法：在 `core/recognition` 补 `scheme_executor`（注册表：scheme 名 → 包装函数），把 anytls/reality/... 接成传输装饰器。这是比链 P 更大的缺口，且与 `src/prism/handshake/scheme` 对应。

## 3. 接入主项目（src/prism）必须满足

1. **联通性**：链 P 全协议 L3 经统一 session 编排；链 S 至少一个伪装方案接进 recognition。
2. **测试完整**：L1→L2→L3→L4(psm 对拍)→L5(外部)；golden 全协议；coverage 分支 60%+。
3. **生产级无 Bug**：公共层并发/生命周期/错误链审计；fuzz(78)/stress(21) 替代 ASAN。
4. **零回归**：psm 原 ~2500 用例 flag off/on 双模式全过（需 prism 先能链）。
5. **可回退**：`PRISM_ENABLE_PREVIEW` 默认 OFF；adapter 隔离；不搬目录。

## 4. Backlog（按依赖，loop 逐单元；每单元只改一个正确归属处）

### 基础件
- **B0 adapter 模块**：新建 `core/runtime/adapter/protocol_adapter.hpp`，集中放
  `make_accept_socks5/vless/trojan/vmess/ss2022`（从测试内联提取），纯桥不碰协议库。
  重构 ListenerE2ETest/VlessE2ETest 改用 adapter（验证无回归）。
- **B1 fault 桥**：`error↔fault::code` 映射表（adapter 内复用）。

### 链 P（代理 L3，经 adapter）
- P1 Trojan TCP（adapter 加 `make_accept_trojan`）→ `TrojanE2ETest` ≥7
- P2 Trojan UDP（dgram 分支）
- P3 VMess TCP / P4 VMess UDP
- P5 SS2022 TCP / P6 SS2022 UDP（executor+port 风格，adapter 内薄适配）

### 链 S（伪装接线，独立大块）
- S0 `scheme_executor` + 注册表（recognize_result.scheme → 包装函数）
- S1 anytls 接管线（L3 via 伪装） / S2 reality / S3 shadowtls / S4 ws+xhttp+gun / S5 native / S6 ech / S7 trusttunnel

### 运行时补全
- R1 mux 中间件插入 session 管线 / R2 pad / R3 DNS resolver 接 dial

### 质量门禁
- Q1 golden 扩全协议 / Q2 coverage 分支 60%+ / Q3 生命周期审计文档 / Q4 回归

### 阻塞（环境）
- E1 修 prism 链接溢出 → 解锁 L4/L5/C 接入口（handler.cpp `PRISM_ENABLE_PREVIEW`）

## 5. 每单元流程（loop 单次只做一个）
读调用方 → 确认归属层 → 最小范围改 → 加回归 → 静态审（协程/生命周期/错误链）
  → 构建单测试 target（-j1 晚/-j16 昼）→ `--gtest_brief` → `taskkill` → 更新 matrix。
禁止：git commit、改协议库耦合 runtime、批量改无关代码、静默丢错。

## 6. 当前指针（2026-08-20 02:00 更新）

### 已完成（本长任务内，零耦合）
- **B0** `core/runtime/adapter/protocol_adapter.hpp` 新建：`make_accept_trojan/vmess/ss2022`（`map_*_error` + `uuid_hex`），协议库保持纯净
- **P1-P6** 链 P 全打通：`TrojanE2ETest 8/8` + `TrojanUdpE2ETest 3/3` + `VMessE2ETest 8/8` + `VMessUdpE2ETest 3/3` + `SS2022E2ETest 5/5` + `SS2022UdpE2ETest 3/3`（共 30 用例，经 adapter 缝）
- **R1-R3** 运行时补全：`MuxE2ETest 2/2`（`mux_middleware` 直通修正 + `session.hpp:152` 接入） + `PadE2ETest 2/2`（`pad_middleware` + `ctx.pad` 透传） + `DnsDialE2ETest 3/3`（`resolver` LRU/负缓存 + `dial_with_dns`）
- **Q1** golden 9→18：`GoldenVector 18/18`（新增 Trojan/VMess/SS2022 各 3+，含 credential、chunk、ipv6 二进制）
- **Q3** `LIFECYCLE_AUDIT.md` 新建：detached/引用捕获/teardown/流量时序 + 本次 3 真 bug 修复（`session` 放宽、`trojan/vmess` ipv6、`mux` 直通、`run_coro` 时序）
- **真 bug 修复**：`session.hpp:99` recognition 放宽、`trojan/vmess` ipv6 16 字节二进制、`mux.hpp:48` 直通、`Trojan half-close` 超时、`VMess BadUuid` 期望

### 进行中
- **Q2** coverage branches 44.5%→60%+（待补错误/边界分支，重采 `coverage.md`）
- **Q4** 全量回归（本次 166/166 绿，`SessionOrchestration.UnknownProtocolRejected` 仍绿）
- **S0** `scheme_executor` + 注册表（链 S 入口，独立大块）

### 下一步（按依赖串行）
- **S1-S7** 伪装方案逐个接 `scheme_executor`（anytls→reality→shadowtls→ws/xhttp/gun→native→ech→trusttunnel）
- **E1** 修 `Prism.exe` PE 重定位溢出 → 解锁 `L4/L5` 对拍、`C1-C4` 统一工厂与 `handler.cpp` 接入、`benchmark` 对标
- **C1-C4** `transmission`/`fault` 桥 + `make_accept(protocol_type)` 统一工厂
- **提纯** `ListenerE2ETest`/`VlessE2ETest` 内联 `make_accept_*` 提入 adapter（B0 收尾，`socks5/vless` 回归）
- 链 S 与链 P 已并行规划、串行执行；链 P 已闭环，链 S 为下一主战场。
