---
name: probe-audit
description: 修改协议识别、24 字节预读、TLS 信号、方案执行或回落逻辑时，审查识别正确性和数据保全。
---

# 协议识别与回落审计

## 当前流水线

Prism 的识别流程在 `handshake/recognition/`：预读、检测、TLS record/ClientHello 分析、路由和 scheme executor。`session::diversion()` 再根据识别结果创建协议 handler。先读取实际入口和 preread 所有权。

## 审计步骤

1. 记录每个检测入口、所需最小字节数、可能的误判和未知结果。
2. 检查预读数据是否完整传给后续握手，未消费数据不会丢失或重复。
3. 检查 TLS 外层和内层协议识别的边界、超时、截断和异常输入。
4. 检查 route/SNI/scheme 执行失败后的状态和资源释放。
5. 按协议语义审查回落：HTTP、SOCKS5、TLS 伪装和未知协议不能共用一个响应策略。
6. 检查识别失败不会绕过认证、错误地拨号或开放转发。

## 约束

- 当前首包探测限制必须以源码和测试为准，不能为了提高识别率无限扩读。
- 检测结果不是认证结果，handler 仍需完成认证和输入校验。
- 回落必须是显式设计的行为，不是所有认证失败的默认动作。
- 不用固定响应长度或伪造 Web 服务作为无条件安全要求。

## 验证

覆盖每种已支持协议、未知首包、最短输入、截断输入、TLS 内协议、错误 SNI、scheme 失败、认证失败和 preread 重放。修改识别器时运行 recognition、handshake 和 runtime 相关测试。

## 相关 Skill

协议接入见 `protocol-handler`，TLS 细节见 `dpi-audit`，认证重放见 `replay-audit`。
