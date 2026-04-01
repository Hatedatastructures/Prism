---
name: proxylog-analyzer
description: 解析 forward.log 日志文件，统计 DNS 解析、连接建立、隧道传输等各阶段耗时，生成带时间窗口划分的性能报告。
---

# Skill: ProxyLog_Performance_Analyzer

解析 `forward.log` 文件，针对 DNS 解析、连接建立、数据传输等各个阶段的耗时进行深度统计，并生成带有时间窗口划分的详细性能报告。

## 1. 解析规则与数据提取 (Parsing Rules)

请读取目标日志文件，并严格按照以下正则或关键字规则提取时间戳与耗时数据：

- **DNS 解析耗时 (Resolve)**:
  - 匹配规则：`[Resolve] query to .* completed: code=success, ips=\d+, rtt=(\d+)ms`
  - 提取字段：时间戳，RTT耗时。
- **隧道传输耗时 (Tunnel Duration)**:
  - 匹配规则：`[Tunnel] \[\d+\] Transfer: Upload \d+ B, Download \d+ B, duration: (\d+) ms`
  - 提取字段：时间戳，传输持续时间 (duration)。
- **连接池耗时 (Pool Connection)**:
  - 匹配规则：从 `[Pool] new connection to <IP:Port>` 到紧随其后的 `[Smux.Craft] stream \d+ connected to <Domain:Port>` 或 `[Pipeline] * dial success`。
  - 提取字段：利用两行日志的时间戳相减（单位 ms）作为 TCP/握手建连耗时。
- **会话准备耗时 (Session Startup)**:
  - 匹配规则：从 `Session started` 到 `Dispatching to handler`，提取时间戳差值。

## 2. 统计计算要求 (Calculation Requirements)

请对提取到的数据进行以下维度的统计计算，所有时间单位统一为 ms：

- **全局统计 (Overall Metrics)**：
  - 分别计算上述 4 个阶段耗时的 **最大值 (Max)**、**最小值 (Min)**、**平均值 (Avg)** 和 **总样本数 (Count)**。
  - 找出全局耗时最大值的具体发生时间点（精确到毫秒）及对应的目标域名/IP。
- **时间窗统计 (Time Window Metrics)**：
  - 将日志按 **每 10 秒 (或每分钟，根据日志跨度自适应)** 划分为一个时间窗口（Time Window）。
  - 输出每个时间窗口内 DNS Resolve 和 Tunnel Duration 的 [Max, Min, Avg, 样本数]。
  - 指出哪个时间窗口的平均耗时最高（识别拥堵/性能劣化时段）。
- **极端值排查 (Outlier Analysis)**：
  - 列出 DNS 解析耗时 Top 5 的记录（时间、DNS服务器IP、请求域名、RTT）。
  - 列出 Tunnel 传输耗时 Top 5 的记录。

## 3. 输出格式模板 (Output Format)

请严格按照以下 Markdown 格式输出性能报告：

### 📊 代理核心阶段性能报告 (Performance Report)
**日志时间跨度**: [Start Time] ~ [End Time]
**总会话数**: [Total Sessions]

#### 1. 全局耗时统计 (Global Latency)
| 阶段 (Stage) | 平均时长 (Avg) | 最小时长 (Min) | 最大时长 (Max) | 样本量 (Count) | 极端值发生时间及目标 |
| --- | --- | --- | --- | --- | --- |
| DNS解析 (Resolve RTT) | ... | ... | ... | ... | ... |
| 隧道传输 (Tunnel) | ... | ... | ... | ... | ... |
| 建连耗时 (Connect) | ... | ... | ... | ... | ... |
| 会话准备 (Startup) | ... | ... | ... | ... | ... |

#### 2. 时间区间波动分析 (Time-Window Trend: 10s step)
| 时间窗口 (Time Window) | DNS Avg/Max (ms) | Tunnel Avg/Max (ms) | 并发请求数 (Req Count) | 性能状态 |
| --- | --- | --- | --- | --- |
| 07:44:30 - 07:44:40 | ... | ... | ... | 正常/延迟上升 |
| ... | ... | ... | ... | ... |
💡 **性能最差时间段分析**：[详细指出哪个时段的平均/最大值最高，可能的原因猜测]

#### 3. Top 5 慢请求诊断 (Top 5 Slow Requests)
- **慢 DNS**: [List 1, 2, 3, 4, 5]
- **长时隧道**: [List 1, 2, 3, 4, 5]