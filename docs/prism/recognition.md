# Recognition 模块 — 协议智能识别

## 1. 模块概述

Recognition 模块是 Prism 的协议智能识别层，负责从传输层检测客户端协议类型并识别 TLS 伪装方案。它位于 Session 层和 Protocol 层之间，采用两阶段架构：外层探测（Probe）→ TLS 伪装识别（Identify）。

### 文件结构

```
include/prism/recognition/
├── recognition.hpp             # 模块聚合头文件 + 统一入口 recognize() / identify()
├── confidence.hpp              # 置信度枚举（high/medium/low/none）
├── result.hpp                  # analysis_result 分析结果
├── routes.hpp                  # SNI 路由表（route_table）
├── target.hpp                  # 目标地址解析
├── pipeline.hpp                # 分层检测管道（layered_detection_pipeline）
├── probe/
│   ├── probe.hpp               # 外层协议探测（24 字节预读 + 协程）
│   └── analyzer.hpp            # detect() 纯函数检测
└── tls/
    ├── signal.hpp              # ClientHello 解析（read_tls_record / parse_client_hello）
    └── features.hpp            # 特征位图（feature_bit + build_bitmap）

src/prism/recognition/
├── recognition.cpp             # recognize() / identify() 实现
├── pipeline.cpp                # 分层检测管道实现
├── routes.cpp                  # SNI 路由表实现
├── target.cpp                  # 目标地址解析实现
├── probe/
│   └── analyzer.cpp            # detect() 实现
└── tls/
    └── signal.cpp              # ClientHello 解析实现
```

### 两阶段架构

```
Phase 1: recognize()
  probe::probe(transport, 24)   → probe_result{protocol_type}
         │
         ├─ 非 TLS → 返回 {transport, detected, preread}
         │
         └─ TLS ↓

Phase 2: identify()
  tls::read_tls_record()        → raw_record
         │
         ▼
  tls::parse_client_hello()     → hello_features
         │
         ▼
  route_table::lookup(sni)      → matched_schemes
         │
         ▼
  tls::build_bitmap(features)   → bitmap
         │
         ▼
  layered_detection_pipeline     → pipeline_result{candidates}
         │
         ▼
  stealth::scheme_executor      → handshake_result{transport, detected}
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
├── router                 : connect::router*      // 路由器（fallback 用）
├── session                : context::session*     // 会话上下文
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
   ├─ tls::read_tls_record()        → raw_record
   ├─ tls::parse_client_hello()     → hello_features
   ├─ route_table::lookup(sni)      → matched_schemes
   ├─ tls::build_bitmap(features)   → bitmap
   ├─ layered_detection_pipeline     → pipeline_result
   └─ scheme_executor::execute()    → handshake_result
```

### 2.2 置信度枚举 confidence

```
enum class confidence : uint8
├── high     // 特征完全匹配，可直接执行
├── medium   // 特征部分匹配，需完整验证
├── low      // 特征部分匹配但不确定
└── none     // 无特征，Native 兜底
```

### 2.3 ClientHello 特征结构 hello_features

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/protocol/tls/types.hpp` |
| 命名空间 | `psm::protocol::tls` |

```
struct hello_features                // 从 ClientHello 提取的特征
├── server_name           : string           // SNI
├── session_id            : vector<uint8>    // session_id 数据
├── session_id_len        : uint8            // session_id 长度（0-32）
├── has_x25519            : bool             // 是否存在 X25519 key_share
├── x25519_key            : array<uint8,32>  // X25519 公钥
├── versions              : vector<uint16>   // TLS 版本列表
├── random                : array<uint8,32>  // 客户端随机数
├── has_alpn              : bool             // ALPN 扩展存在
├── has_psk               : bool             // PSK 扩展存在
├── has_ech               : bool             // ECH 扩展存在
├── has_esni              : bool             // ESNI 扩展存在
├── greased_extensions    : bool             // GREASE 扩展存在
├── has_sig_algos         : bool             // signature_algorithms 存在
├── keyshare_multi        : bool             // key_share 含多个条目
├── early_data            : bool             // early_data 扩展存在
├── raw_msg               : vector<uint8>    // 原始握手消息（不含 record header）
└── raw_record            : vector<byte>     // 原始 ClientHello 记录（含 record header）
```

### 2.4 特征位图 feature_bit

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/recognition/tls/features.hpp` |
| 命名空间 | `psm::recognition::tls` |

```
enum class feature_bit : uint32
├── has_sni           = 1 << 0   // SNI 存在
├── sni_matched       = 1 << 1   // SNI 匹配配置
├── has_x25519        = 1 << 2   // X25519 key_share 存在
├── full_session      = 1 << 3   // session_id 长度 == 32
├── reality_marker    = 1 << 4   // session_id[0:3] == [0x01, 0x08, 0x02]
├── hmac_valid        = 1 << 5
├── nonstd_session    = 1 << 6   // session_id 长度非 0 且非 32
├── has_ech           = 1 << 7
├── has_esni          = 1 << 8
├── greased_extensions= 1 << 9
├── has_versions      = 1 << 10
├── has_alpn          = 1 << 11
├── has_psk           = 1 << 12
├── has_sigalgs       = 1 << 13
├── keyshare_multi    = 1 << 14
└── early_data        = 1 << 15

build_bitmap(features) → uint32  // 构建特征位图
has_feature(bitmap, bit) → bool  // 检查单个特征
has_all(bitmap, bits) → bool     // 检查多个特征
```

### 2.5 SNI 路由表 route_table

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/recognition/routes.hpp` |
| 实现文件 | `src/prism/recognition/routes.cpp` |
| 命名空间 | `psm::recognition` |

```
class route_table                     // SNI → 方案名称映射
├── build(cfg)            : route_table     // 从配置构建
├── lookup(sni)           : vector<string>  // 查找匹配方案
├── matches_any(sni)      : bool            // 是否匹配任意方案
├── registered_snis()     : vector<string>  // 获取所有已注册 SNI
└── empty()               : bool            // 是否为空
```

### 2.6 分层检测管道 layered_detection_pipeline

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/recognition/pipeline.hpp` |
| 实现文件 | `src/prism/recognition/pipeline.cpp` |
| 命名空间 | `psm::recognition` |

```
struct candidate_entry                // 检测候选条目
├── name                  : string   // 方案名称
├── score                 : uint16   // 评分（0-1000）
├── tier                  : uint8    // 检测层级（0-2）
└── is_deterministic      : bool     // 是否确定性命中

struct pipeline_result                // 管道检测结果
├── deterministic_hit     : bool     // 是否确定性命中
├── exclusive_scheme      : string   // 独占命中的方案名
├── candidates            : vector   // 候选列表（按评分排序）
└── reason                : string   // 检测原因

struct detect_input                   // 检测输入聚合
├── bitmap                : uint32           // 特征位图
├── features              : hello_features&  // ClientHello 特征
├── raw                   : span<byte>       // 原始字节
└── cfg                   : config&          // 全局配置

class layered_detection_pipeline
├── tier0_schemes_        : vector<shared_scheme>  // Tier 0 方案（有独占特征）
├── tier1_schemes_        : vector<shared_scheme>  // Tier 1 方案（需要 HMAC/解密）
├── tier2_schemes_        : vector<shared_scheme>  // Tier 2 方案（模糊匹配）
├── native_scheme_        : shared_scheme           // Native 兜底
├── detect(input, matched_schemes) : pipeline_result
├── detect_tier0(bitmap, features, cfg) : pipeline_result
├── detect_tier1(features, raw, cfg)    : pipeline_result
└── detect_tier2(cfg, matched_schemes)  : pipeline_result
```

### 2.7 分析结果 analysis_result

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/recognition/result.hpp` |

```
struct analysis_result
├── candidates       : vector<string>    // 候选方案名（按置信度排序）
├── score            : confidence        // 最高置信度（字段名 score，类型 confidence）
├── features         : hello_features    // 原始特征
└── error            : fault::code       // 错误码
```

### 2.8 伪装方案执行器 scheme_executor

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/stealth/executor.hpp` |
| 命名空间 | `psm::stealth` |

```
class scheme_executor                 // 伪装方案执行器
├── schemes_              : vector<shared_scheme>  // 从 registry 构建
├── execute_by_analysis(analysis, ctx) : awaitable<handshake_result>
├── execute(candidates, ctx)          : awaitable<handshake_result>
├── find_scheme(name)                 : shared_scheme
├── execute_single(scheme, ctx)       : awaitable<handshake_result>
├── pass_through(ctx, result)         : void
├── ensure_snapshot(ctx)              : void
├── try_rewind(ctx, mode)             : bool
└── execute_pipeline(order, ctx)      : awaitable<handshake_result>
```

---

## 3. 架构与组件交互

### 3.1 伪装方案接入流程

```
// 新伪装方案接入流程
1. 实现 stealth_scheme 子类
   ├─ name()   → 方案名称
   ├─ tier()   → 检测层级（0/1/2）
   ├─ unique() → 是否有独占特征
   ├─ active(cfg) → 配置是否启用
   ├─ snis(cfg)  → SNI 白名单
   ├─ sniff(bitmap, features) → sniff_result   (Tier 0)
   ├─ verify(features, raw, cfg) → verify_result (Tier 1)
   ├─ guess(cfg) → verify_result                 (Tier 2)
   └─ handshake(ctx) → handshake_result

2. 在 register_schemes() 中注册
   registry.add(make_shared<stealth::new_scheme>())

3. pipeline 自动按 tier() 分类到 tier0/tier1/tier2
```

### 3.2 分层检测流程

```
// Tier 0: 零成本字节比较（如 Reality session_id 标记）
layered_detection_pipeline.detect(input, matched)
   │
   ├─ Tier 0: sniff() → hit + solo → 确定性命中
   │   └─ 命中则直接返回，不再检测其他方案
   │
   ├─ Tier 1: verify() → score + solo_flag → 详细验证
   │   └─ 独占命中则直接返回
   │
   └─ Tier 2: guess() → score → 模糊匹配
       └─ 无独占特征，依赖 SNI 路由
```

### 3.3 级联重试机制

```
// 方案返回 tls 类型表示"不是我"
scheme.handshake()
   │
   ├─ 成功 → detected = vless/trojan/...
   │         返回 handshake_result{transport, detected}
   │
   ├─ "不是我" → detected = tls
   │              pass_through() 传递 transport/preread
   │              try_rewind() 尝试回绕传输层
   │              继续下一个候选
   │
   └─ 错误 → 其他错误码
             终止执行，返回失败
```

### 3.4 scheme_registry（stealth 模块）

```
scheme_registry                       // 伪装方案注册表（单例）
├── instance()            : registry&         // 获取单例
├── add(scheme)           : void              // 注册方案
├── all()                 : vector<shared_scheme>  // 所有已注册方案
└── find(name)            : shared_scheme     // 按名称查找

register_schemes()                    // main() 启动时调用
   ├─ add(reality)
   ├─ add(shadowtls)
   ├─ add(restls)
   ├─ add(anytls)
   ├─ add(trusttunnel)
   └─ add(native)
```

---

## 4. 完整生命周期流程

### 4.1 Session 调用 recognize()

```
session::diversion()
   │
   ▼
recognition::recognize({
    .transport = ctx_.inbound,
    .cfg = &ctx_.server_ctx.config(),
    .router = &ctx_.worker_ctx.router,
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
   │   ├─ tls::read_tls_record(transport, preread) → raw_record
   │   ├─ tls::parse_client_hello(record) → hello_features
   │   ├─ route_table::build(cfg) → table
   │   │   └─ table.lookup(sni) → matched_schemes
   │   ├─ tls::build_bitmap(features) → bitmap
   │   ├─ layered_detection_pipeline.detect(input, matched)
   │   │   ├─ Tier 0: sniff() → 确定性命中?
   │   │   ├─ Tier 1: verify() → 详细验证?
   │   │   └─ Tier 2: guess() → 模糊匹配?
   │   ├─ scheme_executor.execute_by_analysis()
   │   │   ├─ reality::handshake() → result
   │   │   ├─ shadowtls::handshake() → result
   │   │   └─ native::handshake() → 兜底
   │   └─ 返回 {transport, detected, executed_scheme}
   │
   ▼
session::diversion() switch (detected)
   → protocol::{name}::handle(ctx, preread_span)
```

---

## 5. 设计原则

### 5.1 分层检测零成本

```
// Tier 0 仅做字节比较，无协程无异步 I/O
sniff(bitmap, features) → sniff_result
   ├─ 纯内存操作
   ├─ 判断成本约 1-2 次字节比较
   └─ 独占命中则跳过所有其他方案
```

### 5.2 分析与执行分离

```
// 检测管道负责决策（不执行）
layered_detection_pipeline.detect() → pipeline_result

// 执行器负责执行（调用 stealth_scheme::handshake）
scheme_executor::execute_pipeline() → handshake_result

// 分离的好处
├─ 检测管道可快速判断，无副作用
├─ 执行器可灵活调整顺序
├─ pass_through() 保证数据在方案间无损传递
└─ try_rewind() 支持传输层回绕
```

### 5.3 注册表只读

```
// 注册仅在启动阶段
register_schemes()
   └→ registry.add()  // 单线程，无锁

// 运行时只读遍历
registry.all()
   └→ for s in schemes_ { ... }  // 无锁，只读
```

---

## 6. 依赖关系

### 6.1 Recognition 模块向外依赖

```
recognition 模块
├── transport::transmission (传输层抽象)
├── transport::preview (预读数据回放)
├── stealth::stealth_scheme (伪装方案基类 — sniff/verify/guess/handshake)
├── stealth::scheme_registry (方案注册表)
├── stealth::scheme_executor (方案执行器)
├── protocol::tls::hello_features (ClientHello 特征结构)
├── protocol::protocol_type (协议枚举)
├── fault::code (错误码)
├── memory (PMR 容器)
└── config (全局配置)
```

### 6.2 外部模块对 Recognition 的依赖

```
instance::session ─────────────► recognition::recognize()
transport::preview ────────────► 用于预读数据回放
stealth::stealth_scheme ──────► 被 pipeline 检测 + executor 执行
```
