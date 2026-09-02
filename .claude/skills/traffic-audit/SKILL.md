---
name: traffic-audit
description: 修改传输 framing、padding、预览、流控或连接模式时，审查数据完整性、边界和可测量开销。
---

# 传输行为审计

## 审计范围

先明确变更属于 framing、reliable/unreliable transport、encrypted transport、preview、padding、mux 或 tunnel。审计目标是协议正确性、资源上限和可测量性能，不把未经批准的抗探测策略当成硬门禁。

## 审计步骤

1. 核对帧长度、分片、合并、padding、解密和校验的顺序。
2. 检查最大帧、最大缓冲、空帧、零长度、截断和恶意长度字段。
3. 检查读写背压、partial write、EOF、超时、取消和关闭传播。
4. 测量 padding/封装带来的 CPU、内存、带宽和延迟开销，区分配置项。
5. 检查随机性来源、可复现测试和失败时的退化行为。
6. 检查统计与日志不会泄露明文、密钥或不必要的目标信息。

## 约束

- 不使用“熵标准差 0.8”“心跳 20%”“开销 15%-60%”等无证据阈值。
- 不擅自加入 SNI 轮换、模拟浏览器或随机流量注入。
- 流量策略必须有明确配置、协议依据、测试和性能基线。
- 任何 padding 或缓冲上限都必须防止无界内存增长。

## 验证

覆盖不同 payload、边界长度、重复/丢失/截断、padding 开关、背压、半关闭和取消。性能结论使用 `bench-perf`，双向转发使用 `tunnel-audit`，协议帧使用 `mux-audit`。
