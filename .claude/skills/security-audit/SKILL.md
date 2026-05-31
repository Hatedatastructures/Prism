---
name: security-audit
description: 修改安全相关代码后，按正确顺序编排所有安全审计 skills 的执行。
---

# Skill: 安全审计编排

当修改涉及安全相关代码时，多个专项审计 skill 可能同时需要触发。本 skill 提供**触发条件映射表**和**编排原则**，确保审计按正确的依赖顺序执行，不遗漏不重复。

## 触发条件

修改安全相关代码后，需要确定应执行哪些审计 skills。触发条件映射表按修改的代码类型组织。

## 触发条件映射表

| 修改类型 | 触发的审计 skills（按顺序） |
|----------|---------------------------|
| AEAD 加密/解密封装 | `crypto-audit` → `replay-audit` → `leak-audit` |
| HKDF/X25519/BLAKE3 密钥派生 | `crypto-audit` → `leak-audit` |
| TLS 握手/ClientHello/ServerHello | `dpi-audit` → `crypto-audit` → `probe-audit` → `leak-audit` |
| 伪装方案状态机/回落机制 | `probe-audit` → `replay-audit` → `traffic-audit` → `leak-audit` |
| 多路复用帧处理 | `mux-audit` → `traffic-audit` → `crypto-audit` |
| 协议认证/密码验证/首包处理 | `replay-audit` → `probe-audit` → `leak-audit` → `crypto-audit` |
| 填充机制/传输层读写 | `traffic-audit` → `dpi-audit` → `leak-audit` |
| 日志输出/错误响应格式 | `leak-audit` → `error-chain-audit` |
| 证书生成/TLS 库行为 | `crypto-audit` → `dpi-audit` → `leak-audit` |
| 连接池/隧道转发 | `tunnel-audit` → `pool-audit` → `error-chain-audit` |
| 协程/异步/并发原语 | `coroutine-audit` → `concurrency-audit` → `co-lifecycle-audit` |
| PMR 内存/分配器 | `audit-memory` → `co-lifecycle-audit` |

## 编排原则

### 1. 密码学基础优先

密码学是安全信道的基石。如果密钥管理有缺陷，上层的所有协议安全都失去意义。

- `crypto-audit` 必须在 `replay-audit`、`probe-audit`、`traffic-audit` 之前执行
- 密钥派生错误会级联影响所有使用派生密钥的审计结论

### 2. 协议指纹先于流量分析

TLS 指纹是审查系统的第一个检测窗口，流量统计分析是第二个窗口。

- `dpi-audit` 必须在 `traffic-audit` 之前执行
- 指纹缺陷比流量异常更容易被检测，应优先修复

### 3. 信息泄漏最后检查

泄漏风险贯穿所有变更——密码学缺陷可能导致密钥泄漏，协议缺陷可能导致行为泄漏。

- `leak-audit` 总是最后执行
- 前序审计的修复可能引入新的泄漏风险（如添加的错误日志），需要最终统一检查

### 4. 每个 skill 独立执行

- 每个审计 skill 按其内部审计流程完整执行，不跳步
- 一个 skill 的发现不影响另一个 skill 的检查项——即使 crypto-audit 发现 nonce 问题，replay-audit 仍需完整检查防重放机制
- 跨 skill 的关联发现记录在最终汇总中

## 审计结果汇总模板

所有审计 skills 执行完成后，按以下模板汇总发现：

```markdown
# 安全审计汇总

## 变更范围
- 变更文件: {files}
- 变更类型: {从映射表中选取}
- 执行的审计 skills: {列表}

## 发现汇总

### 严重（必须修复）

| # | 来源 skill | 发现描述 | 文件:行号 |
|---|-----------|----------|----------|
| 1 | {skill} | {description} | {file:line} |

### 高（建议修复）

| # | 来源 skill | 发现描述 | 文件:行号 |
|---|-----------|----------|----------|

### 中（关注）

| # | 来源 skill | 发现描述 | 文件:行号 |
|---|-----------|----------|----------|

### 低（可选优化）

| # | 来源 skill | 发现描述 | 文件:行号 |
|---|-----------|----------|----------|

## 跨 skill 关联

- {多个 skill 发现的同一根因的关联分析}

## 结论
- 可合并 — 所有严重和高优先级问题已修复
- 有风险 — 存在未修复的中优先级问题
- 需补充 — 存在未修复的严重或高优先级问题
```

## 严重程度分级标准

| 级别 | 定义 | 示例 |
|------|------|------|
| **严重** | 可被审查系统直接检测或可被主动攻击利用 | nonce 重复、明文密钥日志、固定指纹 |
| **高** | 在特定条件下可被检测，或增加被关联分析的风险 | 缺少 GREASE、固定填充长度、认证失败时间差 |
| **中** | 降低防御深度，但在其他层面仍受保护 | 单一方案缺少填充、日志时间戳精度偏高 |
| **低** | 最佳实践偏离，不影响当前安全性 | 代码风格、注释措辞、配置默认值 |

## 交叉引用

- 本 skill 是编排层，不包含具体的审计检查项
- 专项审计 skills：`crypto-audit`、`replay-audit`、`dpi-audit`、`probe-audit`、`traffic-audit`、`leak-audit`
- 工程审计 skills：`coroutine-audit`、`concurrency-audit`、`co-lifecycle-audit`、`mux-audit`、`tunnel-audit`、`pool-audit`、`audit-memory`、`error-chain-audit`
- 编码规范：`enforce-coding`
