# Recognition 模块 — 协议智能识别

## 1. 模块概述

Recognition 模块是 Prism 的协议智能识别层，负责从传输层检测客户端协议类型并识别 TLS 伪装方案。它位于 Session 层和 Dispatch 层之间，采用三阶段流水线架构：外层探测 → 特征分析 → 方案执行。

### 文件结构

```
include/prism/recognition/
├── recognition.hpp             # 模块聚合头文件 + 统一入口 recognize()
├── confidence.hpp              # 置信度枚举（high/medium/low/none）
├── feature.hpp                 # ClientHello 特征结构
├── result.hpp                  # analysis_result 分析结果
├── probe/
│   ├── probe.hpp               # 外层协议探测（24 字节预读 + 协程）
│   └── analyzer.hpp            # detect() 纯函数检测
├── arrival/
│   ├── feature.hpp             # feature 虚基类
│   ├── registry.hpp            # 注册表（单例，插件架构）
│   ├── reality.hpp             # Reality 方案 feature
│   ├── ech.hpp                 # ECH feature（预留）
│   └── anytls.hpp              # AnyTLS feature（预留）
└── handshake/
    ├── executor.hpp            # 方案执行器
    └── priority.hpp            # 执行优先级配置

src/prism/recognition/
├── recognition.cpp             # recognize() / identify() 实现
├── probe/
│   └── analyzer.cpp            # detect() 实现
├── arrival/
│   ├── registry.cpp            # 注册表实现
│   └── reality.cpp             # Reality feature 实现
└── handshake/
    ├── executor.cpp            # 执行器实现
    └── priority.cpp            # 优先级配置
```

### 三阶段流水线

```
probe::probe(transport, 24)     → probe_result{protocol_type}
       │ (仅当 TLS)
       ▼
identify():
  read_arrival()            → raw_arrival
       │
       ▼
  parse_arrival()           → arrival_features
       │
       ▼
  registry::analyze()       → analysis_result{candidates, confidence}
       │
       ▼
  scheme_executor::execute() → scheme_result{transport, detected}
```

---

## 2. 核心类型与类

### 2.1 统一入口 recognize()

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/recognition/recognition.hpp` |
| 命名空间 | `psm::recognition` |

```
struct recognize_context              // 识别输入
├── transport              : shared_transmission   // 传输层
├── cfg                    : const config*         // 全局配置
├── router                 : router*               // DNS 路由器
├── session                : session_context*      // 会话上下文
└── frame_arena            : frame_arena*          // 帧内存池

struct recognize_result               // 识别输出
├── transport              : shared_transmission   // 最终传输层
├── detected               : protocol_type         // 检测到的协议
├── preread                : vector<byte>          // 预读数据
├── error                  : fault::code           // 错误码
├── executed_scheme        : string                // 执行的方案名称
└── success                : bool                  // 是否成功

recognize(ctx) → awaitable<recognize_result>  // 统一入口
```

**Phase 1: Probe（外层探测）**

```
probe::probe(transport, 24)
   │
   ▼
detect(peek_data) → protocol_type
   │
   ├─ 0x05 ──────────→ socks5
   ├─ 0x16 0x03 ────→ tls
   ├─ GET/POST/... ─→ http
   └─ 其他 ─────────→ shadowsocks (排除法)
```

**Phase 2: Identify（仅当 TLS）**

```
identify(ctx)
   │
   ├─ read_arrival()    → raw_arrival
   ├─ parse_arrival()   → arrival_features
   ├─ registry::analyze(features) → analysis_result
   └─ executor::execute_by_analysis() → scheme_result
```

### 2.2 置信度枚举 confidence

```
enum class confidence : uint8_t
├── high     // 特征完全匹配，可直接执行
├── medium   // 特征部分匹配，需完整验证
├── low      // 特征部分匹配但不确定
└── none     // 无特征，Native 兜底
```

### 2.3 ClientHello 特征结构

```
struct arrival_features          // 从 ClientHello 提取的特征
├── server_name           : string           // SNI
├── session_id_len        : uint8            // session_id 长度（0-32）
├── has_x25519_key_share  : bool             // 是否存在 X25519 key_share
├── x25519_public_key     : optional<array<byte,32>>
├── supported_versions    : vector<uint16>   // TLS 版本列表
├── has_ech_extension     : bool             // 是否存在 ECH 扩展
├── ech_config_id         : optional<array<byte,8>>
├── alpn_protocols        : vector<string>   // ALPN 协议列表
├── random                : array<byte,32>   // 客户端随机数
├── session_id            : vector<uint8>    // session_id 数据
├── raw_arrival           : vector<byte>     // 原始 ClientHello 记录
└── raw_handshake_message : vector<uint8>    // 原始握手消息
```

### 2.4 特征分析器 feature

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/recognition/arrival/feature.hpp` |
| 命名空间 | `psm::recognition::arrival` |

```
class feature                        // 虚基类
├── name()               : string_view        // 方案名称
├── analyze(features, cfg): confidence        // 分析置信度
└── is_enabled(cfg)      : bool               // 方案是否启用

// Reality feature 示例
class reality final : feature
├── name()               → "reality"
├── analyze(features, cfg)
│   ├─ SNI 匹配 server_names → 继续
│   ├─ session_id_len == 32 + x25519 → high
│   ├─ x25519 → medium
│   └─ SNI 匹配但无 x25519 → low
│   └─ SNI 不匹配 → none
└── is_enabled(cfg)      → cfg.stealth.reality.enabled()
```

### 2.5 注册表 registry

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/recognition/arrival/registry.hpp` |
| 命名空间 | `psm::recognition::arrival` |

```
class registry               // 单例，运行时只读
├── instance()            : registry&         // 获取单例
├── add(f)                : void              // 注册 feature
├── analyze(features, cfg): analysis_result   // 执行所有 feature，按置信度排序
└── features()            : vector<shared_feature>  // 获取所有已注册

// 注册宏
REGISTER_ARRIVAL(reality)  // 文件末尾一行注册
```

### 2.6 分析结果 analysis_result

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/recognition/result.hpp` |

```
struct analysis_result
├── candidates       : vector<string>   // 候选方案名，按置信度排序（high 在前）
├── confidence       : confidence       // 最高置信度
├── features         : arrival_features // 原始特征
└── error            : fault::code      // 错误码
```

### 2.7 方案执行器 scheme_executor

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/recognition/handshake/executor.hpp` |
| 命名空间 | `psm::recognition::handshake` |

```
class scheme_executor
├── execute_by_analysis(analysis, ctx): awaitable<scheme_result>
├── execute_by_priority(priority, ctx): awaitable<scheme_result>
├── register_scheme(scheme): void
├── create_default()      : unique_ptr<executor>
└── find_scheme(name)     : shared_scheme

// 核心管道
execute_pipeline(names[], ctx)
   │
   ├─ for name in names:
   │   ├─ find_scheme(name)
   │   ├─ is_enabled() → false 则跳过
   │   ├─ execute() → 成功则返回
   │   ├─ detected == tls → "不是我"，更新 ctx 继续下一个
   │   └─ 其他错误 → 终止执行
   └─ 全部失败 → not_supported
```

---

## 3. 架构与组件交互

### 3.1 插件架构

```
// 新伪装方案接入流程
1. 实现 feature 子类
   ├─ name() → 方案名称
   ├─ analyze() → 置信度判断
   └─ is_enabled() → 配置检查

2. 在实现文件末尾注册
   REGISTER_ARRIVAL(ech)

3. 实现 stealth::scheme 执行逻辑
   (stealth/ech/scheme.hpp)

4. 注册到执行器
   schemes.push_back(make_shared<stealth::ech::scheme>())
```

### 3.2 置信度驱动执行

```
// 分析结果按置信度排序
analysis_result
├── candidates = ["reality", "shadowtls"]  // high > medium > low
├── confidence = high
└── features = {...}

// 执行器按候选顺序尝试
execute_by_analysis()
   → reality.execute() → 成功 → 返回
   → shadowtls.execute() → （不会执行，reality 已成功）
```

### 3.3 级联重试机制

```
// 方案返回 tls 类型表示"不是我"
scheme.execute()
   │
   ├─ 成功 → detected = vless/trojan/...
   │         返回 scheme_result{transport, detected}
   │
   ├─ "不是我" → detected = tls
   │              更新 ctx.inbound（pass_through）
   │              继续下一个候选
   │
   └─ 错误 → 其他错误码
             终止执行，返回失败
```

### 3.4 executor 内部结构

```
scheme_executor
├── schemes_       : vector<shared_scheme>   // 注册的所有方案
├── create_default()                        // reality → shadowtls → restls → native
├── execute_pipeline()                      // 核心：遍历执行
├── execute_single()                        // 单个方案执行 + 写入 name
└── pass_through()                          // transport/preread 传递
```

---

## 4. 完整生命周期流程

### 4.1 Session 调用 recognize()

```
session::async_forward()
   │
   ▼
recognition::recognize({
    .transport = ctx_.inbound,
    .cfg = &ctx_.server.config(),
    .router = &ctx_.worker.router,
    .session = &ctx_,
    .frame_arena = &ctx_.frame_arena
})
   │
   ├─ Phase 1: probe::probe(transport, 24)
   │   ├─ pread 24 bytes
   │   ├─ detect(data) → protocol_type
   │   └─ 非 TLS → 返回 {success=true, detected=type}
   │
   ├─ Phase 2: identify() (仅 TLS)
   │   ├─ read_arrival() → raw
   │   ├─ parse_arrival() → features
   │   ├─ registry::analyze(features, cfg)
   │   │   ├─ reality::analyze() → confidence
   │   │   ├─ ech::analyze() → confidence
   │   │   └─ 按置信度排序 → candidates
   │   ├─ scheme_executor::execute_by_analysis()
   │   │   ├─ reality::scheme::execute() → result
   │   │   ├─ shadowtls::scheme::execute() → result
   │   │   └─ native::scheme::execute() → 兜底
   │   └─ 返回 {transport, detected, executed_scheme}
   │
   ▼
dispatch::dispatch(ctx, result.detected, result.preread)
```

---

## 5. 设计原则

### 5.1 零成本预识别

```
// 特征分析器仅解析 ClientHello 字节特征
feature::analyze()
   ├─ 无协程、无异步 I/O
   ├─ 纯内存操作
   ├─ 判断成本约 1-2 次字符串比较
   └─ 返回置信度而非执行结果
```

### 5.2 分析与执行分离

```
// 分析器负责决策（不执行）
feature::analyze() → confidence

// 执行器负责执行（调用 stealth::scheme）
scheme_executor::execute_pipeline() → scheme_result

// 分离的好处
├─ 分析器可快速判断，无副作用
├─ 执行器可灵活调整顺序
├─ 支持配置驱动和分析驱动两种模式
└─ pass_through() 保证数据在方案间无损传递
```

### 5.3 注册表只读

```
// 注册仅在静态初始化阶段
REGISTER_ARRIVAL(reality)
   └→ registry::instance().add()  // 单线程，无锁

// 运行时 analyze() 只读遍历
registry::analyze()
   └→ for f in features_ { ... }  // 无锁，只读
```

---

## 6. 依赖关系

### 6.1 Recognition 模块向外依赖

```
recognition 模块
├── channel::transport::transmission (传输层抽象)
├── stealth::scheme (方案执行接口)
├── stealth::reality (Reality ClientHello 解析)
├── protocol::protocol_type (协议枚举)
├── fault::code (错误码)
├── memory (PMR 容器)
└── config (全局配置)
```

### 6.2 外部模块对 Recognition 的依赖

```
agent::session ──────────────► recognition::recognize()
pipeline::primitives::preview ► 用于预读数据回放
stealth::scheme ─────────────► 被 executor 调用
```
