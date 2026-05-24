# Restls 伪装方案文档

## 1. 模块概述

### 1.1 协议背景

Restls 是一种 TLS 探测抵抗协议，通过在真实 TLS 连接内部嵌入认证和加密层来隐藏代理特征。与 Reality 或 ShadowTLS 不同，Restls 不修改 TLS 握手本身，而是在 TLS 应用数据阶段通过自定义帧格式实现客户端认证和流量混淆。

Restls 采用 **Path C 代理架构**，复用 ShadowTLS 的双工转发模式：服务端作为中间人，将客户端的 TLS ClientHello 透传给后端真实 TLS 服务器，完成完整的标准 TLS 握手。握手完成后，在应用数据层注入认证信息和流量填充，使得被动检测器无法区分 Restls 流量与正常 TLS 流量。

Prism 中的 Restls 实现参考了以下规范：

- **BLAKE3** -- 密钥派生和 MAC 构造
- **RFC 5246 / RFC 8446** -- TLS 1.2 / TLS 1.3 协议格式
- **Restls 规范** -- https://github.com/3andne/restls

### 1.2 核心设计思想

Restls 的核心思想是 **TLS 内嵌认证 + 流量脚本化**：

1. **握手透明**：完整转发标准 TLS 握手，不修改 ClientHello / ServerHello，使得 TLS 指纹与正常连接一致
2. **应用层认证**：在 TLS 握手完成后，通过应用数据帧中的 `auth_mac` 验证客户端身份
3. **流量混淆**：通过 Restls Script 控制每条记录的填充长度和发送节奏，打乱代理流量的时序和大小特征

### 1.3 与其他伪装方案的对比

| 特性 | Reality | ShadowTLS | Restls |
|------|---------|-----------|--------|
| TLS 握手修改 | 修改 session_id | 无 | 无（透传） |
| 证书来源 | 目标网站合成证书 | 后端真实证书 | 后端真实证书 |
| 认证机制 | X25519 ECDH | HMAC-SHA256 | BLAKE3 keyed hash |
| 认证阶段 | 握手阶段 | 握手阶段 | 应用数据阶段 |
| 流量混淆 | 无 | 无 | Script 引擎 |
| 后端依赖 | 无需后端 | 需要 TLS 后端 | 需要 TLS 后端 |
| 检测层级 | Tier 0（独占特征） | Tier 1（HMAC） | Tier 2（SNI 匹配） |

### 1.4 密码学原语

| 原语 | 算法 | 用途 |
|------|------|------|
| 密钥派生 | BLAKE3 derive_key | 从密码派生 RestlsSecret |
| MAC（握手） | BLAKE3 keyed hash | server_auth_mask（16 字节） |
| MAC（应用数据） | BLAKE3 keyed hash | auth_mac（8 字节） |
| 掩码 | BLAKE3 keyed hash | mask（4 字节） |

## 2. 架构设计

### 2.1 文件结构

```
include/prism/stealth/restls/
├── config.hpp        # Restls 配置（SNI、后端地址、密码、脚本）
├── scheme.hpp        # stealth_scheme 子类（方案注册与握手入口）
├── crypto.hpp        # 密码学原语（BLAKE3 密钥派生 + MAC + mask）
├── script.hpp        # Restls Script 解析器 + 分配引擎
├── handshake.hpp     # 服务端握手（Path C 双工转发）
└── transport.hpp     # 应用数据传输层（帧编解码）

src/prism/stealth/restls/
├── scheme.cpp        # scheme 实现（调用 handshake + 创建 transport）
├── handshake.cpp     # 握手实现（双工转发 + server_auth_mask XOR）
├── script.cpp        # Script 解析和分配逻辑
└── transport.cpp     # 传输层实现（读/写 Restls 帧）
```

### 2.2 组件关系

```
  scheme (stealth_scheme 入口)
    │
    ├── handshake() ────────── 握手阶段
    │     ├── parse_host_port()       解析后端地址
    │     ├── connect backend         TCP 连接后端 TLS 服务器
    │     ├── relay_backend_to_client 后端→客户端（XOR 首个加密记录）
    │     ├── relay_client_to_backend 客户端→后端（捕获 clientFinished）
    │     └── compute_server_auth_mask BLAKE3 计算认证掩码
    │
    ├── restls_transport ───── 应用数据阶段
    │     ├── read_restls_frame   读取 → auth_mac 验证 → mask XOR → 提取数据
    │     ├── write_restls_frame  script 分配 → 拼接明文 → mask XOR → auth_mac → 发送
    │     └── send_random_response 随机响应帧
    │
    ├── script_engine ──────── 流量控制脚本
    │     ├── parse_line()         解析单条规则
    │     └── allocate()          根据计数器和数据量生成分配方案
    │
    └── crypto ─────────────── 密码学工具
          ├── derive_secret()          BLAKE3 derive_key
          ├── compute_server_auth_mask BLAKE3 keyed hash（16B）
          ├── compute_auth_mac         BLAKE3 keyed hash（8B）
          ├── compute_mask             BLAKE3 keyed hash（4B）
          └── xor_with_mask            循环 XOR
```

## 3. 核心组件说明

### 3.1 scheme（方案入口）

`scheme` 类继承 `stealth_scheme`，是 Restls 在 Prism 伪装方案管道中的入口。作为 **Tier 2** 方案，Restls 无 ClientHello 独占特征，依赖 SNI 匹配触发。

- `name()` 返回 `"restls"`
- `tier()` 返回 `2`
- `unique()` 返回 `false`（无独占特征）
- `guess()` 返回固定分数 100
- `handshake()` 执行完整握手流程，创建 `restls_transport`

### 3.2 handshake（握手模块）

握手采用 **Path C 双工转发架构**：

1. 从客户端接收 ClientHello，透传给后端 TLS 服务器
2. 读取 ServerHello，提取 `server_random`，判断 TLS 1.2 或 TLS 1.3
3. 计算 `server_auth_mask`，XOR 后端返回的第一个加密记录
4. 双工转发：后端到客户端（首个加密记录被 XOR），客户端到后端（捕获 clientFinished）
5. 握手完成后关闭后端连接，返回 `handshake_detail`

**握手输出 `handshake_detail`**：

| 字段 | 类型 | 说明 |
|------|------|------|
| `restls_secret` | `uint8_t[32]` | BLAKE3 派生的 RestlsSecret |
| `server_random` | `uint8_t[32]` | TLS ServerHello 的 server_random |
| `client_finished` | `vector<uint8_t>` | 客户端 Finished（完整加密 TLS record 含 header） |
| `first_frame` | `vector<byte>` | 认证后的首帧数据 |
| `tls13` | `bool` | 后端是否为 TLS 1.3 |
| `script` | `script_engine` | Restls script 引擎实例 |

### 3.3 crypto（密码学原语）

#### 密钥派生链

```
password (UTF-8)
     │
     v
BLAKE3-DeriveKey("restls-traffic-key", password) → RestlsSecret (32B)
     │
     ├──→ compute_server_auth_mask(secret, server_random) → 16B 握手认证掩码
     ├──→ compute_auth_mac(secret, server_random, direction, counter, ...) → 8B 记录认证
     └──→ compute_mask(secret, server_random, direction, counter, sample) → 4B XOR 掩码
```

#### auth_mac 计算输入序列

```
BLAKE3 keyed hash（secret 为密钥）：
  1. server_random (32B)
  2. direction_string (16B: "server-to-client" 或 "client-to-server")
  3. counter (8B big-endian)
  4. client_finished（仅首次 client→server 方向，完整加密 TLS record）
  5. tls_header (5B TLS 记录头)
  6. payload_after_mac (masked_len + masked_cmd + data + padding)
  → 截断为 8 字节
```

#### mask 计算输入序列

```
BLAKE3 keyed hash（secret 为密钥）：
  1. server_random (32B)
  2. direction_string (16B)
  3. counter (8B big-endian)
  4. plaintext_sample（明文数据，XOR 之前，最多 32 字节）
  → 截断为 4 字节
```

### 3.4 script_engine（流量控制脚本）

#### Script 语法

```
规则列表，逗号分隔：
  targetLen[?randomRange|~randomRange][<responseCount]

修饰符：
  ?N  一次性随机：解析时 resolve，后续固定
  ~N  动态随机：每次调用时重新计算 rand(N)
  <N  写阻塞：发送后阻塞后续写入，等待 N 个响应后解除

默认脚本：
  "250?100<1,350~100<1,600~100,300~200,300~100"
```

#### 分配逻辑

`allocate(counter, data_available)` 返回 `allocation` 结构：

| 字段 | 说明 |
|------|------|
| `payload_len` | 含 auth_header (12B) 的完整 payload |
| `data_len` | 实际用户数据长度 |
| `padding_len` | 填充长度 |
| `cmd` | 命令类型（noop 或 response） |
| `write_blocking` | 是否阻塞后续写入 |

### 3.5 restls_transport（应用数据传输层）

`restls_transport` 继承 `transport::transmission`，包装原始 TCP socket，持续处理 Restls 应用数据帧。

#### 应用数据帧布局

```
[TLS Header 5B][auth_mac 8B][masked_len 2B][masked_cmd 2B][data][padding]
                 │              │            │
                 │              └── XOR(mask) ┘
                 │
                 └── BLAKE3 keyed hash 验证

auth_header_len = 12 (auth_mac + mask)
app_data_offset = 12
```

#### 写阻塞机制

当 script 行包含 `<N` 时，写入该帧后进入写阻塞状态。后续写入数据被缓冲到 `send_buf_`，直到读端收到有效数据后解除阻塞并 flush。

#### 命令类型

| 命令 | 值 | 说明 |
|------|----|------|
| `cmd_data` | `0x0000` | 普通数据帧 |
| `cmd_close` | `0x0001` | 关闭连接 |
| `cmd_random_response` | `0x0002` | 随机响应帧 |

## 4. 数据流图

### 4.1 握手阶段数据流

```
Client                     Prism Server                     Backend TLS Server
  │                              │                                  │
  │── TLS ClientHello ─────────>│                                  │
  │                              │── TLS ClientHello ──────────────>│
  │                              │                                  │
  │                              │<── TLS ServerHello ──────────────│
  │<── TLS ServerHello ─────────│                                  │
  │                              │                                  │
  │                              │   extract_server_random()        │
  │                              │   compute_server_auth_mask()     │
  │                              │                                  │
  │                              │<── Encrypted Handshake ──────────│
  │<── Encrypted Handshake ─────│   (首个 record 被 XOR)           │
  │                              │                                  │
  │── CCS ─────────────────────>│── CCS ──────────────────────────>│
  │── Encrypted Finished ──────>│── Encrypted Finished ───────────>│
  │                              │   (捕获 clientFinished)           │
  │                              │                                  │
  │                              │   关闭后端连接                    │
  │                              │   创建 restls_transport          │
  │                              │                                  │
  │<== Restls 应用数据帧 ======>│                                  │
```

### 4.2 应用数据读取流程

```
async_read_some(buffer, ec)
    │
    ├── initial_buffer_ 有剩余？
    │     └── 拷贝到 buffer，返回
    │
    ├── pending_buffer_ 有剩余？
    │     └── 拷贝到 buffer，返回
    │
    └── read_restls_frame(ec)
          │
          ├── 读取 TLS header (5B)
          ├── 读取 payload
          ├── 提取 received_mac (8B)
          ├── compute_mask() → XOR 解码 masked_len/masked_cmd
          ├── compute_auth_mac() → 验证 received_mac
          │     └── 失败 → permission_denied
          │
          ├── cmd == cmd_random_response？
          │     └── send_random_response() → 递归读下一帧
          │
          └── 提取用户数据 (data_len 字节)
```

### 4.3 应用数据写入流程

```
async_write_some(data, ec)
    │
    └── write_restls_frame(data, ec)
          │
          ├── write_pending_？→ 缓冲到 send_buf_，返回
          │
          ├── script_.allocate(counter, data.size())
          ├── 构造明文 [zeros(8)][data_len(2B)][cmd(2B)][data][padding]
          ├── compute_mask() → XOR masked_len/masked_cmd
          ├── compute_auth_mac() → 写入 auth_mac
          ├── 构造 TLS record → async_write
          │
          └── alloc.write_blocking？→ 设置 write_pending_=true
```

## 5. 配置选项

### 5.1 JSON 配置结构

```json
{
  "stealth": {
    "restls": {
      "server_names": ["www.microsoft.com", "www.apple.com"],
      "host": "www.microsoft.com:443",
      "password": "your-secret-password",
      "version_hint": "tls13",
      "restls_script": "250?100<1,350~100<1,600~100,300~200,300~100",
      "handshake_timeout_ms": 5000
    }
  }
}
```

### 5.2 参数详解

| 参数 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `server_names` | string[] | 必填 | SNI 白名单，只有匹配的 ClientHello 才会执行 Restls 握手 |
| `host` | string | 必填 | 后端 TLS 服务器地址（`host:port` 格式），必须是 TLS 1.2 或 TLS 1.3 服务器 |
| `password` | string | 必填 | 认证密码，通过 BLAKE3 derive_key 派生为 RestlsSecret |
| `version_hint` | string | `"tls13"` | 版本提示：`"tls12"` 或 `"tls13"`，影响 XOR 偏移量 |
| `restls_script` | string | 内置默认 | 流量控制脚本，为空时使用默认脚本 |
| `handshake_timeout_ms` | uint32 | `5000` | 握手超时（毫秒） |

### 5.3 Script 配置示例

```
# 基础：固定长度
300<1

# 一次性随机
250?100<1

# 动态随机
350~100<1

# 无阻塞
600~100

# 完整配置
250?100<1,350~100<1,600~100,300~200,300~100
```

## 6. 与其他模块的交互

### 6.1 与 Stealth 层管道的关系

```
probe (预读 24 字节)
  └── detect_tls() → true
        └── stealth_scheme 管道
              ├── Tier 0: sniff() → Restls 不响应
              ├── Tier 1: verify() → Restls 不响应
              └── Tier 2: guess() → 返回 score=100
                    └── scheme::handshake() 执行
```

### 6.2 与内层协议的关系

Restls 认证成功后，内层协议固定为 **Shadowsocks (SS2022)**：

```
scheme::handshake()
  └── result.detected = protocol::protocol_type::shadowsocks
```

由于 Restls 无独占特征，SS2022 作为无正特征的排除法 fallback 协议，两者天然互补。

### 6.3 与 common 工具库的关系

Restls 握手复用 `stealth::common` 模块提供的 `read_raw_tls_frame()` 函数，用于从 TCP socket 逐帧读取 TLS 记录。

### 6.4 与 transport 层的关系

`scheme::handshake()` 完成后，从 `transport::reliable` 中释放底层 TCP socket（`release_socket()`），将所有权转移给 `restls_transport`。后续所有读写操作通过 `restls_transport` 完成。
