---
name: proxylog-diagnostic
description: 解析 forward.log 日志文件，专注于错误追踪、连接池效率、多路复用状态以及流量走向的综合诊断报告。
---

# Skill: ProxyLog_Diagnostic_Analyzer

解析 `forward.log` 文件，专注于错误追踪、连接池效率、多路复用（Smux/Mux）状态以及流量走向的综合诊断报告。

## 1. 解析规则与数据提取 (Parsing Rules)

- **异常与错误 (Errors & Timeouts)**:
  - 提取所有包含 `[warning]` 或 `[error]` 的日志行。
  - 特别关注：`connect timed out` (连接超时)、`TLS handshake failed` (TLS失败)、`connect to * failed` (Smux层连接失败)。
- **流量分析 (Traffic Analysis)**:
  - 提取 `[Tunnel] [*] Transfer: Upload (\d+) B, Download (\d+) B`。
- **连接池健康度 (Pool Statistics)**:
  - 匹配定期输出的连接池状态：`[Pool] total acquires: (\d+), total hits: (\d+), total creates: (\d+), total evictions: (\d+), total recycles: (\d+), total idle: (\d+)`。
- **多路复用流分析 (Mux/Smux Streams)**:
  - 提取 `[Smux.Craft] stream \d+ pending`、`connected`、`fin while pending` 和 `[Mux.Duct] stream \d+ closed`。

## 2. 诊断计算要求 (Diagnostic Requirements)

- **错误率与分类 (Error Classification)**:
  - 统计日志中的警告/错误总数。
  - 按错误类型聚合（如：连接 Google 相关的超时总数，TLS 握手失败总数），按发生频次降序排列。
- **目标分布 (Target Domains)**:
  - 统计所有被请求的域名/IP 频次（从 `CONNECT -> <Domain>` 提取），列出 Top 10 请求目标。
- **连接池效率 (Pool Efficiency)**:
  - 提取日志最后一次/最大值的 Pool 状态。
  - 计算 **连接池命中率 (Hit Rate)** = `total hits / total acquires` * 100%。
  - 分析 `evictions` (驱逐) 和 `recycles` (回收) 的比例，判断池子大小配置是否合理。
- **流量汇总 (Total Traffic)**:
  - 累加所有的 Upload 和 Download 字节数，转换为 KB/MB 格式。

## 3. 输出格式模板 (Output Format)

请严格按照以下 Markdown 格式输出分析报告：

### 🩺 代理健康度与诊断分析报告 (Diagnostic Report)
**分析时段**: [Start Time] ~ [End Time]
**总流量传输**: Upload: [X] KB | Download: [Y] KB

#### 1. 错误与异常雷达 (Error & Anomaly Radar)
- **总异常条数**: [Count]
- **异常类型分类排版**:
  1. **连接超时 (Connect Timed Out)**: [Count] 次。**主要集中域名**: [如 googleapis.com (x次), xxx (y次)]
  2. **TLS 握手失败**: [Count] 次。**主要集中在**: [Target]
  3. **Smux 流 Fin/Failed**: [Count] 次。

#### 2. 连接池效率评估 (Connection Pool Efficiency)
- **最新状态**: Acquires: [X], Hits: [Y], Creates: [Z], Recycles: [W], Evictions: [E]
- **连接复用率 (Hit Rate)**: [计算百分比]%
- **诊断建议**: [例如：复用率为 0%，说明连接没有被有效重用，大量触发了 Creates 和 Evictions，建议检查 Pool timeout 设定或 Keep-Alive 策略。]

#### 3. 流量走向与目标 Top 10 (Traffic Top 10 Targets)
| 排名 | 目标域名 / IP | 请求频次 (Requests) | 连通成功率 (Success Rate) |
| --- | --- | --- | --- |
| 1 | www.google.com | 15 | 20% (示例) |
| 2 | ... | ... | ... |

#### 4. 多路复用健康度 (Mux/Smux Health)
- **已发起的 Stream 总数**: [Count]
- **正常 Closed 的 Stream 数**: [Count]
- **半开/异常的 Stream 数 (fin while pending 等)**: [Count]
- **状态评价**: [指出是否存在流泄漏(Stream Leak)或大量 Pending 的情况]