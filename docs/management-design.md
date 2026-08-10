# Prism 管理面设计（运营 / 治理 / 可观测性蓝图）

> 状态：设计稿（v0.1）。实施前提：账户扩展、按用户统计、会话注册表等前置模块就绪。
> 与 `docs/protocol-integration-plan.md`（协议面）互补：本文档只覆盖**数据面旁路、会话快照、管理 API** 三层。

## 设计总纲

Prism 的性能哲学（PMR 零堆分配、无锁 COW、纯协程、四层所有权）对任何新增功能是**硬约束**。
所有功能必须能对号入座到以下三层之一，并在设计阶段标注**热路径代价**：

```
热路径（每字节/每包）   : 只允许旁路式机制 —— 原子计数、采样分支、SPSC 环形缓冲
温路径（每连接级）      : 只允许 COW 快照写入 —— 值拷贝进注册表，绝不放引用
冷路径（管理面）        : 任意复杂度 —— 独立 io_context，不占 worker 线程
```

**纪律**：热路径代价必须是 O(1) 原子操作或条件分支；所有旁路缓冲"满了就丢"；任何查询型功能读 COW 快照，任何写型功能通过原子/队列投递，绝不阻塞热路径。

---

## 一、性能分层原则

| 层 | 触发频率 | 允许机制 | 禁止 |
|----|---------|---------|------|
| 热路径（数据面） | 每包/每字节 | 原子计数、采样分支、SPSC ring | 锁、分配、阻塞、系统调用 |
| 温路径（会话级） | 每连接/每事件 | COW 快照写入、值拷贝 | 引用/裸指针逃逸 L3 |
| 冷路径（管理面） | 每请求/每定时 | 任意复杂度 | 占用 worker 线程、阻塞热路径 |

---

## 二、功能蓝图

### A. 热路径旁路（代价 ≤ 1 原子 或 1 条件分支）

#### A1. HDR 延迟直方图 —— 性能分析核心数据

- 分阶段记录：`accept → DNS → 拨号 → TLS 握手 → 首字节 → 首包响应`
- 结构：每 worker 一张 HDR 直方图（~200 个 bucket 的数组），更新 = 时间戳差 + 一次 CAS
- 冷路径聚合导出 P50 / P95 / P99；**慢会话检测 = P99 超阈值触发采样**
- 价值：性能问题量化依据，比 access log 高一个维度
- 热路径代价：1 次 CAS

#### A2. 采样式追踪（sampled tracing）

- 不记录每个会话，按 1/N 采样（如 N=1024，原子计数器判断）
- 命中会话的事件序列（各阶段时间戳 + 关键参数）写入 **SPSC ring buffer**
- 缓冲满则丢弃，绝不阻塞热路径；冷路径 API 导出 ring 回放
- 价值：出问题时回放慢会话完整生命周期
- 热路径代价：1 原子 + 1 条件分支（未命中时）

#### A3. EWMA 实时速率

- 不用窗口计数（O(n) 内存 + 周期归零），改用指数加权移动平均：`rate = α×sample + (1-α)×rate`
- 每连接 / 每用户各一份，原子更新
- 价值：`/traffic` 实时速率、限速器输入
- 热路径代价：1 原子

#### A4. 溢出保护（纪律）

- 所有旁路缓冲必须"满了就丢"，禁止背压传导到热路径

### B. 温路径快照（每连接，COW 值拷贝）

#### B1. 会话注册表 —— /connections 前置

- 结构：全局 COW map（复用 `user/directory` 模式），key = session_id，value = **快照结构体**
- 快照字段：`{session_id, 协议, 用户, 目标, 已传上/下行, 开始时间, 当前阶段, 实时速率}`
- 写：session 创建/销毁/事件时更新一次（纳秒级）；读：冷路径拿 COW 快照遍历，零锁
- **所有权约束**：注册表只存值拷贝，绝不存 L3 引用（对照 `docs/ARCHITECTURE.md` 四层模型）

#### B2. 动态 SNI 路由热更新

- 伪装方案路由表改为 COW 指针交换：更新 = 构建新表 + 原子指针 swap（复用 directory upsert 模式）
- 热路径读旧表照常，**改配置不重启、不锁**
- 价值：SNI 路由、规则表、黑名单的通用更新机制

### C. 冷路径管理（独立 io_context，不影响 worker）

#### C1. 管理 API（external-controller 风格 + 机场运营需求）

资源树：

```
/api/v1/
├── /version              进程信息：version、build_sha、started_at、uptime
├── /config               配置快照：监听端口、伪装方案、SNI 路由表、mux 开关
│   └── /reload           热重载（POST，COW 指针交换落地）
├── /stats/traffic        全局流量：up/down 总量 + EWMA 实时速率
│   └── /protocols        按协议分布（stats 16 槽位已存在）
├── /stats/latency        HDR 直方图：各阶段 P50/P95/P99（A1）
├── /stats/workers        每 worker：会话数、待处理、延迟、内存池水位
├── /traces               采样追踪导出（A2）
├── /connections          实时会话列表（B1）
│   └── /{id}             单连接：协议、用户、目标、已传、速率、时长
├── /users                账户列表（依赖账户扩展）
│   ├── /{name}           状态、连接数、已用流量、预算、限速
│   ├── /{name}/traffic   按用户流量
│   └── /{name}           PUT/DELETE 创建/修改/删除
├── /rules                统一规则表（见第三章）
├── /challenge            挑战-响应状态（RFC-065）
├── /logs                 最近 access / 错误日志
└── /alerts               SSE 事件流：封禁触发、预算耗尽、过载
```

设计决策：

- 认证：Bearer token（`api.token` 配置），管理面必须认证
- 监听：单独端口（如 9090），默认本机绑定，可配置
- 传输：REST JSON（glaze 现成）+ **SSE 流**（/traffic 实时速率、/alerts 事件推送）
- 实现：复用 `protocol/http` codec + 手写最小路由（不引入 http 框架）
- **独立管理 io_context 线程池**，请求处理不占 worker 线程

#### C2. 自适应治理（从静态规则升级为负载感知防御）

- 数据源：balancer 已有的 worker 负载评分（会话/待处理/延迟）
- 行为：过载时动态收紧（新连接限速、可疑 IP 直接拒、限速降速），恢复后放松
- 全部在冷路径读负载快照，不碰热路径

#### C3. 配额预算制（quota budgeting，防超跑）

- 启动时给用户内存预算：`剩余配额 / (剩余天数 × 安全系数)`，用尽本周期内降速/停止，跨天重置
- 实时预算在内存（原子），持久化异步刷写（不进热路径）
- 与 stats 联动：预算扣减 = 流量统计，一份数据两个用途

#### C4. 多实例状态同步

- 变更事件（用户禁用、封禁、配额充值）→ 写本地 + 广播（Redis 或 UDP 组播）
- 实现为冷路径 event log + 回放，不碰热路径
- 价值：机场多台机器横向扩展

#### C5. 订阅生成器

- 冷路径从 directory 生成 Clash 订阅 YAML（节点配置聚合），URL token 认证

---

## 三、黑名单 / 规则 / 限速设计

### 统一规则表（黑名单是规则的特例）

```
规则条目：
  {id, 匹配: ip|网段|user, 动作: reject|challenge|throttle, 参数, 过期时间}
  · 静态条目 = 永不过期（手写管理的"黑名单"）
  · 动态条目 = 带过期（fail2ban 模式自动生成、自动失效）
  · 实现：COW map + 过期惰性清理（读时跳过，周期 compact）
```

### 分层防御管道

```
连接进来
  ├─ L1 静态规则    配置里的 IP/网段 黑名单 → 命中即拒
  ├─ L2 动态封禁    rate::counter 滑动窗口计数失败 → 达阈值生成 reject 条目 → 自动过期
  ├─ L3 挑战响应    可疑 IP（接近阈值）→ RFC-065 挑战 → 失败升入 L2
  └─ L4 限速        未封禁但可疑 → throttle 软惩罚而非拒绝
```

### 限速模型

- 两级令牌桶：per-user（entry 内）+ per-connection（全局）
- 参数：`{rate_bps, burst_bps}`（速率/突发）；规则表的 `throttle` 动作携带参数
- 位置：热路径 `tunnel/forward` 双向转发循环插入 token bucket（上行/下行独立桶）
- 配额联动：`daily_quota` 用尽 → 断连 + /alerts 通知 → 跨天重置或后台充值
- **ASN 匹配**：GeoLite2 mmdb 是 C 库 + 内存加载 100MB+，先不做，留接口

---

## 四、性能保障机制清单

| 机制 | 用途 | 违反代价 |
|------|------|---------|
| 原子计数 + 采样分支 | 所有热路径旁路功能只能长这样 | 热路径锁 → 全线雪崩 |
| SPSC ring buffer | 追踪/事件缓冲，满即丢 | 背压 → 热路径阻塞 |
| COW 指针交换 | 配置、规则、路由热更新，零锁 | 锁 → worker 争抢 |
| 值拷贝快照 | 会话注册表，绝不放 L3 引用 | 悬垂引用 → UAF |
| 独立管理 io_context | API/订阅/同步全在冷路径 | 管理请求挤占 worker |
| 惰性清理 | 过期条目读时跳过，不主动扫 | 周期全表扫描 → 抖动 |
| 预算内存 + 异步持久化 | 配额不阻塞热路径 | 同步刷盘 → 卡顿 |

---

## 五、依赖顺序

```
① 账户扩展（过期 / 配额 / 禁用）        ← entry 加字段 + 配置层
② 按用户统计补完（record.hpp TODO）      ← 预算扣减依赖
③ 会话注册表（新）                       ← /connections 依赖
④ 规则表 + 令牌桶限速 + 动态封禁         ← 共用 rate::counter 机制
⑤ 管理 API（含 SSE）                    ← 消费 ①-④
⑥ 后台 / 面板                           ← 消费 ⑤
```

①-④ 互不依赖可并行；⑤ 聚合一切；⑥ 是唯一外部依赖。

另有独立组件组（第七章，与 ①-④ 并行可做）：半关闭 → ACME 证书 → fuzz → 崩溃转储 → TLS 会话复用 → 节点健康自检。

---

## 六、与现有模块的映射

| 新能力 | 复用/扩展 | 新增 |
|--------|----------|------|
| HDR 直方图 | 无 | `foundation/rate/hdr.hpp`（或独立 `diagnose/hdr`） |
| 采样追踪 | A3 EWMA | `diagnose/trace/`（ring buffer） |
| 会话注册表 | user/directory 的 COW 模式 | `resource/session_registry.hpp` |
| 规则表 | 同上 COW 模式 | `foundation/rule/` |
| 令牌桶 | 无 | `foundation/rate/token_bucket.hpp` |
| 动态封禁 | `foundation/rate/counter.hpp`（滑动窗口已有） | 封禁条目生成器（冷路径定时器） |
| 管理 API | `protocol/http` codec + glaze | `runtime/api/`（独立 io_context） |
| 挑战-响应 | RFC-065 代码完备未接线（executor.hpp:75 tracker 无注入） | 接上线 |
| 配额预算 | stats（traffic.cpp） | 预算状态机 |
| 半关闭补完 | `net/connection/tunnel` 双向转发 | 隧道 EOF 状态机（见七.1） |
| ACME 自动证书 | SSL_CTX + COW 指针交换 | `resource/cert_manager.hpp`（冷路径定时器） |
| 崩溃转储 | — | `main.cpp` 异常过滤器 + MiniDump |
| TLS 会话复用 | BoringSSL session API | SSL_CTX session cache 配置 |
| fuzz 测试 | 各 codec 纯函数 | `tests/fuzz/`（libFuzzer target） |
| 节点健康自检 | dialer + resolver | `runtime/health/`（冷路径周期任务） |

---

## 七、补充组件（传输 / 运维 / 质量）

### 7.1 半关闭补完（协议正确性，最高优先级）

- **现状**：`tunnel/forward` 双向转发未见 half-close 处理（仅 restls 内部用 shutdown_both）
- **问题**：标准代理行为是"一端 EOF 后仍转发另一方向剩余数据，两端 EOF 才关闭"。直接双双 shutdown 会丢半途数据（小请求 + 大响应的经典场景）
- **实现**：隧道转发改为双阶段状态机：`{双向, 单向-A已EOF, 单向-B已EOF, 关闭}`，EOF 方向只停读不停写，对端 EOF 才 shutdown
- **验证**：interop 测试（tests/go）覆盖"请求端先关 → 响应完整送达"用例
- 热路径代价：每连接一次状态转换，无额外成本

### 7.2 ACME 自动证书（运维刚需）

- **痛点**：native TLS / WS / gun / TrustTunnel 需要证书（Reality 免证书除外），手动续期是最大运维负担
- **实现**：ACME 客户端（http-01 挑战：JWS + 两个 HTTP 端点，可手写，无需重型库）+ 续期定时器（90 天周期，提前 30 天续）
- **热更新**：新证书构建新 SSL_CTX → COW 指针交换（复用 B1 机制），连接中断零感知
- 配置：`cert: {auto: true, domains[], email, acme_dir}` 或手工 PEM 路径（降级路径）
- 冷路径，不动热路径

### 7.3 崩溃转储 + 服务化

- Windows：`SetUnhandledExceptionFilter` → `MiniDumpWriteDump`（minidump 落盘）+ 日志记录；Linux：systemd 单元 + core dump
- 自愈：崩溃后自动重启（Windows 服务恢复策略 / systemd Restart=on-failure）
- 代码量小（各 ~50 行），服务端产品形态必备

### 7.4 TLS 会话复用缓存

- BoringSSL session ticket + 服务端 session cache（内部缓存，不依赖外部票），重连握手 1.5 RTT → 1 RTT
- 收益场景：客户端频繁重连的 mux / 长连接（Prism 主力场景）
- 纯 BoringSSL API 配置（`SSL_CTX_set_session_cache_mode` + ticket key 轮换），无新依赖
- 注意：会话缓存内存上限需配置（防内存膨胀），建议 LRU + 上限

### 7.5 协议解析 fuzz 测试（质量保障）

- **背景**：vmess 指令头、sing-mux 帧、tuic 命令帧等全部是手写解析器，最易藏崩溃/越界
- **实现**：libFuzzer target 包各 codec 的 `parse` 纯函数（零 I/O 架构是理想 fuzz 目标），`-fsanitize=fuzzer,address` 一次构建跑完所有输入面
- 配合 ASAN 构建（AGENTS.md 已有 `PRISM_ENABLE_ASAN`），新增 `PRISM_ENABLE_FUZZ=ON`
- 门槛：CI 中 fuzz 每 PR 短跑（如 60s × N target）

### 7.6 节点健康自检（机场运营）

- 服务端冷路径周期任务：拨号出站目标（DNS + TCP 连通性）+ 延迟测量
- 结果经 `/health` 暴露；订阅生成器联动自动排除故障节点
- 复用 dialer + resolver，不新增传输能力

### 7.7 明确不做（已评估）

| 组件 | 结论 |
|------|------|
| outbound 连接池 | 服务端场景被 mux 聚合替代，收益小（池化价值在客户端侧） |
| io_uring / 零拷贝 | Linux 组件；Windows + IOCP 已有，等 Linux 部署再议 |
| fragment / TCP 分段 | 防封锁老手段，已有 TLS 伪装 + padding 覆盖 |
| ASN / GeoIP 匹配 | mmdb 内存 100MB+，先不做，规则表留接口 |

### 7.8 优先级

```
① 半关闭（协议正确性，零成本）      →  ② ACME 证书（运维刚需）
③ fuzz 测试（质量兜底）             →  ④ 崩溃转储 + 服务化
⑤ TLS 会话复用（性能）              →  ⑥ 节点健康自检（运营）
```

以上全部为独立组件，与主依赖顺序（①-④ 账户/统计/会话/规则）并行可做。

---

## 八、开放问题（待讨论）

1. 管理 API 端口是否复用代理端口（单端口全功能）还是独立端口？（倾向独立，代理端口保持纯代理面）
2. 持久化介质：SQLite（单机）vs Redis（多实例）？订阅生成器与用户 CRUD 的存储统一性
3. 配额跨天重置的时区定义与对齐
4. /alerts 与 /traffic SSE 的订阅鉴权方式
5. 自适应治理的过载判定阈值初始值（建议从 balancer 负载评分三分位起步）
