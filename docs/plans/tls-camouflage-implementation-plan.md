# TLS 伪装协议完整实现计划（v2）

本文件涵盖三个协议的服务端实现：**Restls**、**AnyTLS**、**TrustTunnel（TCP only）**。
实施顺序：Restls(1) → TrustTunnel(2) → AnyTLS(3)。UDP 部分全部暂不实现。

---

# 一、Restls

Restls 遵循 ShadowTLS 的 **代理架构**（Path C）：服务端不终结 TLS，而是代理到真实后端 TLS 服务器，
在代理过程中通过 BLAKE3-HMAC 验证客户端身份。

## 1.1 协议流程（服务端视角）

```
客户端                    Prism(服务端)                  后端TLS服务器
  │                           │                              │
  │──── ClientHello ─────────>│                              │
  │  session_id[0:16] =       │                              │
  │  BLAKE3-keyed(RestlsSecret│                              │
  │  , key_shares + psk_ids)  │                              │
  │  [:16]                    │                              │
  │                           │──── ClientHello ────────────>│
  │                           │<─── ServerHello ─────────────│
  │<─── ServerHello ──────────│  提取 server_random(32B)     │
  │                           │                              │
  │  后端→客户端方向：          │                              │
  │  第一个 encrypted record   │<─── Finished/Cert ──────────│
  │  XOR with                 │  XOR record[5:] with         │
  │  BLAKE3-keyed(Secret,     │  BLAKE3-keyed(Secret,        │
  │   serverRandom)[:16]      │   serverRandom)[:16]         │
  │<─── XOR'd record ─────────│                              │
  │                           │  尝试解密 XOR'd record       │
  │                           │  成功 → restlsAuthed=true     │
  │                           │                              │
  │  继续转发后端数据...        │  (后续 record 不再 XOR)      │
  │                           │                              │
  │  客户端→服务端方向：         │                              │
  │  首个 post-Finished record │                              │
  │  = encrypted clientFinished│  捕获完整 encrypted record   │
  │  (TLS header + ciphertext)│  → 存入 client_finished      │
  │                           │  转发到后端                   │
  │                           │                              │
  │  后续 record 使用 Restls   │                              │
  │  自定义帧格式：             │  认证成功后关闭后端连接       │
  │  [TLS Header(5)]          │                              │
  │  [auth_mac(8)]            │                              │
  │  [masked_len(2)+cmd(2)]   │                              │
  │  [data]                   │                              │
  │  [padding]                │                              │
```

## 1.2 密钥和认证机制

### RestlsSecret 派生
```
RestlsSecret = BLAKE3_DeriveKey(context="restls-traffic-key", material=password)  // 32 字节
```

### BLAKE3-HMAC 构造

Restls 使用 BLAKE3 的 **keyed mode**（`blake3_hasher_init_keyed`），不是传统 HMAC。

```
RestlsHmac(key) = blake3::init_keyed(key)   // key=RestlsSecret(32B)
                  → hasher 对象
                  → hasher.Write(data...)
                  → hasher.Sum(nil)          // 32 字节输出
```

**Prism 已有 `crypto/blake3.hpp` 仅有 `derive_key`**，需要新增 `keyed_hash` wrapper。

### 握手阶段认证
- **session_id[0:16]** = BLAKE3-keyed(RestlsSecret, group_id(2B)+key_share_data + psk_identity_labels)[:16]
- **server_auth_mask** = BLAKE3-keyed(RestlsSecret).Write(serverRandom).Sum()[:16]
  XOR 到第一个 encrypted record 的 `record[5:]`（TLS header 之后）
  如果是 TLS 1.2 GCM 且前 8 字节 nonce 为零，则 XOR 从 `record[13:]` 开始

### auth_mac 计算（应用数据阶段，per-record）

```
auth_mac = BLAKE3-keyed(RestlsSecret)           // key
           .Write(server_random)                  // 32B
           .Write(direction_string)               // "server-to-client" 或 "client-to-server" (16B)
           .Write(counter_as_big_endian_uint64)    // 8B
           .Write(clientFinished)                  // 仅首次 client→server 写入，完整加密 TLS record
           .Write(tls_header)                      // 5B (TLS 1.3)，13B (TLS 1.2 GCM)
           .Write(data_from_app_data_len_offset)   // masked_len(2) + masked_cmd(2) + data + padding
           .Sum()[:8]
```

### mask 计算（per-record，XOR 解码 masked_len + masked_cmd）

```
mask = BLAKE3-keyed(RestlsSecret)                // key
       .Write(server_random)                       // 32B
       .Write(direction_string)                    // 同 auth_mac
       .Write(counter_as_big_endian_uint64)         // 同 auth_mac
       .Write(data_from_app_data_offset[:min(32, len)]) // 明文 data（XOR 之前的原始数据）
       .Sum()[:4]
```

**关键顺序**：mask 基于明文 data 计算，在 XOR 之前。写端必须：
1. 拼好明文 data + padding
2. 用明文 data 计算 mask
3. 用 mask XOR [masked_len + masked_cmd]
4. 计算完整 auth_mac（包含已 XOR 的 len/cmd 和明文 data+padding）
5. 发送

### 应用数据帧格式
```
┌──────────────────────────────────────────────────┐
│ TLS Record Header (5 bytes)                      │
├──────────────────────────────────────────────────┤
│ auth_mac (8 bytes)                               │
├──────────────────────────────────────────────────┤
│ masked_data_len(2B BE) + masked_cmd(2B)          │ ← XOR with 4B mask
├──────────────────────────────────────────────────┤
│ data (data_len bytes)                            │
├──────────────────────────────────────────────────┤
│ padding (随机填充, 由 script 控制)                 │
└──────────────────────────────────────────────────┘
```

### 常量
```cpp
handshake_mac_len    = 16;   // 握手阶段 HMAC 截断
app_data_mac_len     = 8;    // 应用数据 HMAC 截断
cmd_len              = 2;    // 命令字段长度
mask_len             = 4;    // cmd_len + 2 (data_len 字段)
auth_header_len      = 12;   // app_data_mac_len + mask_len
app_data_offset      = 12;   // auth_header_len
app_data_len_offset  = 8;    // app_data_mac_len
max_plaintext        = 16384; // TLS 最大明文长度
random_response_magic = "restls-random-response"; // 响应帧魔数
```

### Restls Script 语法
```
"250?100<1,350~100<1,600~100,300~200,300~100"
targetLen[~randomRange|?randomRange][<responseCount]
```

- `250?100`：解析时一次性计算 `250 + rand(100)`，之后固定值
- `350~100`：每次调用时计算 `350 + rand(100)`，每次不同
- `<1`：ActResponse(1)，写端阻塞，等待读端收到 1 个响应后解锁

### Write Blocking 机制

Script 行如果有 `<N` 响应命令：
1. 写端设置 `write_pending_ = true`
2. 后续 `Write()` 调用被缓冲到 `send_buf_`
3. 读端成功提取一个应用数据帧时，清除 `write_pending_`
4. 读端调用 `Write(empty)` 触发缓冲数据 flush

这个读写协调机制意味着 `restls_transport` 需要维护一个
`write_pending_` 标志和 `send_buf_` 缓冲区。

## 1.3 新增文件

| 文件 | 用途 |
|------|------|
| `include/prism/stealth/restls/crypto.hpp` | BLAKE3 keyed mode wrapper、auth_mac/mask 计算（header-only） |
| `include/prism/stealth/restls/script.hpp` | Script 解析器和执行引擎 |
| `src/prism/stealth/restls/script.cpp` | Script 实现 |
| `include/prism/stealth/restls/handshake.hpp` | 握手流程声明 |
| `src/prism/stealth/restls/handshake.cpp` | 握手流程实现 |
| `include/prism/stealth/restls/transport.hpp` | 传输层包装器声明 |
| `src/prism/stealth/restls/transport.cpp` | 传输层包装器实现 |

修改文件：
| 文件 | 修改内容 |
|------|----------|
| `include/prism/crypto/blake3.hpp` | 新增 `keyed_hash()` 和 `hash()` wrapper |
| `src/prism/crypto/blake3.cpp` | 对应实现 |
| `src/prism/stealth/restls/scheme.cpp` | 从桩实现改为调用 handshake + 创建 transport |
| `src/CMakeLists.txt` | 添加新源文件 |

## 1.4 实施步骤

### Phase R1：BLAKE3 keyed mode 扩展 + Restls 密码学原语

**R1a. 扩展 `crypto/blake3.hpp`**

```cpp
namespace psm::crypto
{
    // 已有：derive_key()

    // 新增：BLAKE3 keyed mode（等效 Go 的 blake3.New(32, key)）
    // 初始化 hasher 为 keyed mode，调用方继续 update + finalize
    [[nodiscard]] auto keyed_hasher(std::span<const std::uint8_t> key)
        -> blake3_hasher;

    // 新增：BLAKE3 plain hash
    [[nodiscard]] auto hash(std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, 32>;

    // 新增：BLAKE3 keyed mode 便捷函数
    [[nodiscard]] auto keyed_hash(std::span<const std::uint8_t> key,
                                   std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, 32>;
}
```

`blake3_hasher` 是 C 库 `blake3.h` 中定义的结构体，直接使用即可（无需包装）。

**R1b. 创建 `restls/crypto.hpp`**

```cpp
namespace psm::stealth::restls::crypto
{
    // 派生 RestlsSecret
    [[nodiscard]] auto derive_restls_secret(std::string_view password)
        -> std::array<std::uint8_t, 32>;

    // BLAKE3-HMAC：返回已初始化的 keyed hasher
    // 等效 Go 的 RestlsHmac(key) = blake3.New(32, key)
    [[nodiscard]] auto init_hmac(std::span<const std::uint8_t> key)
        -> blake3_hasher;

    // 初始化 per-record auth hasher
    // 写入: secret(keyed) + server_random + direction + counter
    [[nodiscard]] auto init_record_hasher(
        std::span<const std::uint8_t> restls_secret,
        std::span<const std::uint8_t> server_random,
        bool to_client,
        std::uint64_t counter) -> blake3_hasher;

    // 计算 auth_mac（8 字节）
    [[nodiscard]] auto compute_auth_mac(
        std::span<const std::uint8_t> restls_secret,
        std::span<const std::uint8_t> server_random,
        bool to_client,
        std::uint64_t counter,
        std::span<const std::byte> client_finished,  // 首次 c2s 时非空
        std::span<const std::byte> tls_header,
        std::span<const std::byte> payload_after_mac) // masked_len+cmd+data+padding
        -> std::array<std::uint8_t, 8>;

    // 计算 mask（4 字节）
    // data_after_header 是 XOR 之前的明文 data（最多取前 32 字节）
    [[nodiscard]] auto compute_mask(
        std::span<const std::uint8_t> restls_secret,
        std::span<const std::uint8_t> server_random,
        bool to_client,
        std::uint64_t counter,
        std::span<const std::byte> data_after_header) -> std::array<std::uint8_t, 4>;

    // XOR data with mask（循环）
    void xor_with_mask(std::span<std::byte> data, std::span<const std::uint8_t> mask);
}
```

### Phase R2：Script 解析器（`script.hpp` / `script.cpp`）

```cpp
namespace psm::stealth::restls
{
    enum class command_type : std::uint8_t { noop = 0x00, response = 0x01 };

    struct script_line
    {
        std::int16_t target_base{0};
        std::int16_t target_random{0};
        bool random_is_fixed{false};   // true = ?语法（解析时已 resolve）
        command_type cmd{command_type::noop};
        std::uint8_t response_count{0};

        // 获取本次目标长度
        [[nodiscard]] auto target_length() const -> std::int16_t;
    };

    class script_engine
    {
    public:
        explicit script_engine(std::string_view script);

        struct allocation
        {
            std::int16_t payload_len;    // 含 auth_header 的完整 payload
            std::int16_t data_len;       // 实际数据长度
            std::int16_t padding_len;    // 填充长度
            command_type cmd;
            std::uint8_t response_count;
            bool write_blocking;         // 是否阻塞后续写入
        };

        // 根据 counter 和可用数据量计算分配方案
        [[nodiscard]] auto allocate(std::uint64_t counter, std::size_t data_available) const
            -> allocation;

        static constexpr std::string_view default_script =
            "250?100<1,350~100<1,600~100,300~200,300~100";

    private:
        memory::vector<script_line> lines_;
    };
}
```

**Script 解析规则**（对应 Go `parseRecordScript`）：
- 逗号分隔，每个段格式 `targetLen[~rand|?rand][<count]`
- `?`：解析时 `target_base = base + rand(range)`，`target_random = 0`
- `~`：保留 `target_base = base`，`target_random = range`，每次调用时动态计算
- `<N`：`cmd = response`，`response_count = N`，`write_blocking = true`
- 无 `<N`：`cmd = noop`，`write_blocking = false`

**allocate() 规则**（对应 Go `actAccordingToScript`）：
- `counter < lines_.size()` → 使用对应行的 target_length
- 否则 → `data_len = data_available`，无 padding
- `data_len == 0` → 随机 padding `19 + rand(100)`
- `data_available < data_len` → `padding_len = data_len - data_available`
- 最终 payload_len 不超过 `max_plaintext` (16384)

### Phase R3：握手流程（`handshake.hpp` / `handshake.cpp`）

```cpp
struct handshake_detail
{
    memory::vector<std::byte> client_first_data;       // 首帧 data（不含 TLS header）
    std::array<std::uint8_t, 32> restls_secret{};      // 派生后的密钥
    std::array<std::uint8_t, 32> server_random{};      // ServerHello 的 random
    memory::vector<std::byte> client_finished;          // 完整加密 TLS record（含 header）
    std::uint64_t initial_read_counter{0};              // 握手结束时的读取计数器
    std::uint64_t initial_write_counter{0};             // 握手结束时的写入计数器
};

auto handshake(net::ip::tcp::socket &client_sock,
               const config &cfg,
               memory::vector<std::byte> client_hello,
               handshake_detail &detail)
    -> net::awaitable<stealth::handshake_result>;
```

**握手流程**（参照 `shadowtls/handshake.cpp` 的双工转发架构）：

1. 派生 `RestlsSecret = BLAKE3_DeriveKey("restls-traffic-key", password)`
2. 解析后端地址 `cfg.host`，建立 TCP 连接
3. 转发 ClientHello 到后端
4. 读取后端 ServerHello，提取 `server_random`（复用 `common::extract_server_random` 模式）
5. 转发 ServerHello 给客户端
6. 启动双工转发（`net::co_spawn` + `cancellation_signal`）：
   - **后端→客户端方向**（spawn 为独立协程）：
     - 逐帧读取（`common::read_raw_tls_frame`）
     - 第一个 encrypted record（content_type == 0x17）：XOR `record[5:]` with `HMAC(Secret, serverRandom)[:16]`
     - 后续 record 直接转发
   - **客户端→后端方向**（前景协程）：
     - 逐帧读取
     - 捕获第一个客户端 encrypted record（clientFinished）→ 存入 `detail.client_finished`
     - 转发到后端
     - 继续转发直到后端→客户端方向确认 restlsAuthed
7. 认证成功：
   - 取消双工转发协程
   - 关闭后端连接
   - 填充 `handshake_detail`
   - 返回 `handshake_result{transport = 原始 transport, detected = tls}`

**注意**：握手阶段 Prism 不解析 Restls 自定义帧。握手只做 TLS 代理 + XOR 第一个 encrypted record +
捕获 clientFinished。Restls 帧解析留给 `restls_transport`。

### Phase R4：传输层包装器（`transport.hpp` / `transport.cpp`）

```cpp
class restls_transport final : public transport::transmission
{
public:
    explicit restls_transport(net::ip::tcp::socket socket,
                               std::span<const std::uint8_t> restls_secret,
                               std::span<const std::uint8_t> server_random,
                               std::span<const std::byte> initial_data,
                               std::span<const std::byte> client_finished,
                               std::uint64_t initial_read_counter,
                               std::uint64_t initial_write_counter,
                               script_engine script);

    [[nodiscard]] auto transport_type() const noexcept -> type override { return type::tcp; }
    [[nodiscard]] transmission *next_layer() noexcept override { return nullptr; }
    [[nodiscard]] const transmission *next_layer() const noexcept override { return nullptr; }
    [[nodiscard]] executor_type executor() const override;

    auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override;
    auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override;

    void close() override;
    void cancel() override;
    void shutdown_write();

private:
    // 读取一个完整的 Restls 帧，验证 auth_mac，XOR mask 解码，返回 data
    auto read_restls_frame(std::error_code &ec)
        -> net::awaitable<std::optional<memory::vector<std::byte>>>;

    // 写入一个 Restls 帧：script 分配 → 拼接 → mask → auth_mac → TLS record → 发送
    auto write_restls_frame(std::span<const std::byte> data, std::error_code &ec)
        -> net::awaitable<std::size_t>;

    // 刷新 write pending 缓冲区
    auto flush_pending(std::error_code &ec)
        -> net::awaitable<void>;

    net::ip::tcp::socket socket_;

    // 密钥材料
    std::array<std::uint8_t, 32> restls_secret_;
    std::array<std::uint8_t, 32> server_random_;
    memory::vector<std::byte> client_finished_;  // 首次 c2s 写入时注入 auth_mac

    // Script 引擎
    script_engine script_;

    // 计数器（读写方向独立）
    std::uint64_t read_counter_;
    std::uint64_t write_counter_;
    bool first_write_{true};  // 首次写入需要注入 client_finished

    // 缓冲区
    memory::vector<std::byte> initial_buffer_;
    std::size_t initial_offset_{0};
    memory::vector<std::byte> pending_buffer_;
    std::size_t pending_offset_{0};

    // Write blocking 机制
    bool write_pending_{false};
    memory::vector<std::byte> send_buf_;
};
```

**读取方向**：
1. 读 5B TLS header → 获取 record 长度
2. 读 record body（`app_data_mac_len` + `mask_len` + data + padding）
3. 提取 `auth_mac`（前 8B）和 `masked_len + masked_cmd`（接下来的 4B）
4. 用明文 data（offset 12 开始）计算 mask → XOR 解码 `masked_len + masked_cmd`
5. 提取 `data_len` 和 `cmd`
6. 计算完整 auth_mac 验证
7. 如果 `write_pending_` 且收到了数据帧 → 清除 blocking，flush send_buf_
8. 返回 data 部分

**写入方向**：
1. `script_.allocate(write_counter_, data.size())` 获取分配方案
2. 如果 `write_pending_` → 缓冲到 `send_buf_`，返回 data.size()（假装写入成功）
3. 拼接明文：`[zeros(8)][data(data_len)][padding(padding_len)]`
4. 用明文 data 计算 mask → XOR `[data_len(2B) + cmd(2B)]` 写入 offset 8-11
5. 构造 TLS header `[0x17, 0x03, 0x03, len(BE16)]`
6. 计算完整 auth_mac（首次写入包含 client_finished）→ 写入 offset 0-7
7. 通过 `net::async_write` 发送完整 TLS record
8. `++write_counter_`
9. 如果 `allocation.write_blocking` → 设置 `write_pending_ = true`

### Phase R5：Scheme 整合

修改 `src/prism/stealth/restls/scheme.cpp`（参照 `shadowtls/scheme.cpp` 模式）：
1. 获取底层 `reliable` transport → `release_socket()`
2. 调用 `restls::handshake(socket, cfg, preread, detail)`
3. 认证成功 → 创建 `restls_transport`
4. 检测内层协议（`recognition::probe::detect_tls` + shadowsocks fallback）
5. 返回 `handshake_result`

### Phase R6：构建系统

- `src/CMakeLists.txt` 添加 `restls/script.cpp`、`restls/handshake.cpp`、`restls/transport.cpp`
- 无新依赖（BLAKE3 已有）

---

# 二、AnyTLS

AnyTLS 走 **Path A**（ssl::stream 黑盒）：服务端用配置的 TLS 证书终结 TLS 握手，
然后在 TLS 隧道内做应用层认证 + 自定义多路复用。

与 Restls/ShadowTLS 的本质区别：**AnyTLS 服务端是 TLS 终结者**，不代理到后端 TLS 服务器。

## 2.1 协议流程（服务端视角，TCP only）

```
客户端                    Prism(服务端)
  │                           │
  │──── TLS ClientHello ─────>│  (标准 TLS 握手)
  │<─── TLS ServerHello ──────│
  │    ... TLS handshake ...  │
  │<─── TLS Finished ────────│  (TLS 隧道建立)
  │                           │
  │─── sha256(password)(32B)─>│  SHA-256 完整 32 字节
  │─── padding_len(2B BE) ───>│
  │─── padding(N) ───────────>│  零填充
  │                           │
  │                           │  查找 userMap[hash] → username
  │                           │  失败 → 静默关闭连接
  │                           │
  │─── cmdSettings ──────────>│  [cmd=4][sid=0][len][v=2\nclient=...\npadding-md5=...]
  │                           │  如果 padding-md5 不匹配 → 发 cmdUpdatePaddingScheme
  │                           │  如果 v>=2 → 发 cmdServerSettings(v=2)
  │                           │
  │─── cmdSYN(sid=1) ────────>│  [cmd=1][sid=1][len=0]
  │                           │  创建 Stream(sid=1)
  │─── SOCKS 地址 (PSH,sid=1)>│  [cmd=2][sid=1][len][addr_data]
  │                           │  解析目标地址
  │<─── cmdSYNACK(sid=1) ────│  [cmd=7][sid=1][len=0]（v2+）
  │                           │
  │─── 数据 (PSH,sid=1) ─────>│  双向转发
  │<─── 数据 (PSH,sid=1) ────│
```

### 帧格式（7 字节 header）
```
┌────────┬────────────┬──────────┐
│ cmd(1) │  sid(4 BE) │ len(2BE) │
├────────┴────────────┴──────────┤
│ data (len bytes)               │
└────────────────────────────────┘
```
最大帧 payload = 65535 字节（uint16 最大值）。

### 命令类型
| cmd | 名称 | 方向 | 有数据 | 含义 |
|-----|------|------|--------|------|
| 0 | cmdWaste | 双向 | 是（padding） | 丢弃 |
| 1 | cmdSYN | C→S | 否 | 打开流 |
| 2 | cmdPSH | 双向 | 是 | 数据推送 |
| 3 | cmdFIN | 双向 | 否 | 关闭流 |
| 4 | cmdSettings | C→S | 是 | key=value 文本 |
| 5 | cmdAlert | 双向 | 是 | 告警/错误 |
| 6 | cmdUpdatePadding | S→C | 是 | raw scheme bytes |
| 7 | cmdSYNACK | S→C | 可选 | 流打开确认（v2+） |
| 8 | cmdHeartReq | 双向 | 否 | 心跳请求 |
| 9 | cmdHeartResp | 双向 | 否 | 心跳响应 |
| 10 | cmdServerSettings | S→C | 是 | key=value 文本（v2+） |

### Padding 方案
```
stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000
```
- `stop=N`：前 N 个包做 padding，之后停止
- `pktNum=min-max`：生成 [min, max] 范围的随机大小帧
- `c`（CheckMark = -1）：此位置放实际 payload

### 认证机制
- 客户端发送 `SHA-256(password)` 的完整 32 字节
- 服务端预计算所有用户的 `SHA-256(password)`，构建 `unordered_map<array<uint8_t,32>, string>`
- 查表匹配 O(1)

### Settings 格式
key=value 换行分隔文本：
```
v=2
client=mihomo/v1.19.0
padding-md5=a1b2c3d4e5f6...
```

## 2.2 架构设计：多路复用与 Prism 集成

### 核心问题

Prism 当前架构是 **1 connection = 1 session = 1 protocol handler**。
AnyTLS 是多路复用协议：1 TLS 连接承载 N 个 Stream，每个 Stream 对应一个独立的代理连接。

### 设计决策：AnyTLS 作为 multiplex 协议处理

AnyTLS 不走 stealth scheme 的 `handshake()` 返回单条流的模式。
而是复用 Prism 已有的 **multiplex 架构**（smux/yamux）。

**方案**：AnyTLS 的 `scheme::handshake()` 做完 TLS + 认证后，
将结果交给 `protocol::anytls::handle()` 处理，
后者复用 Prism 的 multiplex 框架（`multiplex::core`）。

```
AnyTLS 在 Prism 中的位置：

recognition::recognize()
  → probe: TLS
  → identify: SNI 匹配 anytls
  → scheme::handshake()
      1. peel_to_raw → wrap_with_preview
      2. encrypted::ssl_handshake() → TLS 终结
      3. 读 32B SHA-256(password) + padding → 验证身份
      4. 启动 recv_loop（独立协程）
      5. 等待 cmdSettings + cmdSYN + 第一个 PSH(SOCKS 地址)
      6. 返回 handshake_result {
           detected = protocol_type::anytls,   // 新增枚举值
           transport = anytls_stream_transport(stream_id=1),
           preread = SOCKS 地址数据
         }

session::diversion()
  → switch (anytls):
    → protocol::anytls::handle(ctx, preread)
        // 第一个 Stream：正常走 pipeline
        // 后续 Stream：recv_loop 收到 cmdSYN 时，
        //   通过 callback 创建新的 outbound 连接 + tunnel
```

### 新增 protocol_type 枚举值

`protocol/protocol_type.hpp` 添加 `anytls`。

### Stream pipe 设计：boost::asio::experimental::concurrent_channel

Prism 是纯协程架构，禁止 mutex。AnyTLS 的 Stream pipe 使用
`boost::asio::experimental::concurrent_channel<void(error_code, memory::vector<std::byte>)>`
作为异步队列：

- **recv_loop**（读协程）：收到 cmdPSH(sid=N) → `channel.try_send(data)`
- **stream_transport::async_read_some**：`co_await channel.async_receive(data)`
- 这保证协程安全，无 mutex，且能跨 strand（recv_loop 和 stream_read 可能不同 strand）

### 后续 Stream 的处理

`anytls_session` 的 `recv_loop` 收到 `cmdSYN(sid=N)` 时：
1. 创建新的 pipe channel
2. 创建 `anytls_stream_transport(session, sid=N, channel)`
3. 通过回调通知上层：`on_new_stream(sid, transport)`
4. 回调中解析 SOCKS 地址，建立 outbound 连接，启动 tunnel

**回调集成**：需要一种机制让 `recv_loop` 能创建新的代理连接。
方案：`anytls_session` 构造时接收一个 `on_new_stream` 回调函数，
该回调由 `protocol::anytls::handle()` 提供，内部调用 `connect::tunnel()` 启动新的双向转发。

```
recv_loop() → cmdSYN(sid=2)
  → on_new_stream(sid=2, transport)
    → 读取 SOCKS 地址
    → router.resolve(target) → outbound connect
    → net::co_spawn(tunnel(inbound=stream_transport, outbound, ctx))
```

每个后续 Stream 在独立协程中运行，共享同一个 AnyTLS session（即同一个 TLS 连接）。

## 2.3 新增文件

| 文件 | 用途 |
|------|------|
| `include/prism/stealth/anytls/frame.hpp` | 帧格式定义（7 字节 header）+ 命令常量 |
| `include/prism/stealth/anytls/padding.hpp` | Padding 方案解析器 |
| `src/prism/stealth/anytls/padding.cpp` | Padding 实现 |
| `include/prism/stealth/anytls/session.hpp` | AnyTLS session 管理（多流多路复用） |
| `src/prism/stealth/anytls/session.cpp` | Session 实现（recv_loop、帧收发） |
| `include/prism/stealth/anytls/stream_transport.hpp` | 单个 Stream 的 transmission 适配器 |
| `include/prism/protocol/anytls/conn.hpp` | 协议 handler（注册到 dispatch） |
| `src/prism/protocol/anytls/process.cpp` | 协议处理入口 |

修改文件：
| 文件 | 修改内容 |
|------|----------|
| `include/prism/protocol/protocol_type.hpp` | 添加 `anytls` 枚举值 |
| `src/prism/stealth/anytls/scheme.cpp` | 从桩实现改为 TLS 握手 + 认证 + session 创建 |
| `src/prism/instance/session/session.cpp` | switch 添加 `anytls` case |
| `src/prism/stealth/CMakeLists.txt` | 添加新源文件 |
| `src/CMakeLists.txt` | 添加协议处理源文件 |

## 2.4 实施步骤

### Phase A1：帧格式和常量（`frame.hpp`）

```cpp
namespace psm::stealth::anytls
{
    enum class cmd : std::uint8_t {
        waste = 0, syn = 1, psh = 2, fin = 3,
        settings = 4, alert = 5, update_padding = 6,
        synack = 7, heart_req = 8, heart_resp = 9,
        server_settings = 10
    };

    constexpr std::size_t header_size = 7;
    constexpr std::uint16_t max_frame_payload = 65535;

    struct frame_header {
        cmd command;
        std::uint32_t stream_id;
        std::uint16_t length;

        void parse(std::span<const std::byte, header_size> raw);
        void serialize(std::span<std::byte, header_size> out) const;
    };
}
```

### Phase A2：Padding 方案（`padding.hpp` / `padding.cpp`）

```cpp
class padding_factory
{
public:
    explicit padding_factory(std::string_view raw_scheme);

    // 生成第 pkt 个包的 payload 大小列表
    // -1 (CheckMark) 表示"此位置放实际 payload"
    [[nodiscard]] auto generate_sizes(std::uint32_t pkt) const
        -> memory::vector<int>;

    std::uint32_t stop{0};
    memory::string md5;   // MD5(raw_scheme_bytes)，用于 Settings 交换比对

private:
    memory::unordered_map<int, memory::string> scheme_;
    memory::vector<std::byte> raw_scheme_;
};
```

MD5 计算使用 BoringSSL 的 `MD5()` 函数。

### Phase A3：Session 管理（`session.hpp` / `session.cpp`）

```cpp
class anytls_session final : public std::enable_shared_from_this<anytls_session>
{
public:
    using stream_callback = std::function<void(
        std::uint32_t stream_id,
        std::shared_ptr<transport::transmission> stream_transport)>;

    explicit anytls_session(
        transport::shared_transmission tls_transport,
        const memory::unordered_map<std::array<std::uint8_t, 32>, memory::string> &user_map,
        std::shared_ptr<padding_factory> padding,
        stream_callback on_new_stream);

    // 启动 recv loop（在独立协程中运行）
    auto start() -> void;

    // 等待第一个 Stream 的 cmdSYN + SOCKS 地址
    auto wait_first_stream()
        -> net::awaitable<std::pair<fault::code,
            std::tuple<std::uint32_t, memory::vector<std::byte>>>>;

    // 写 PSH 帧到指定 stream
    auto write_psh(std::uint32_t stream_id, std::span<const std::byte> data,
                   std::error_code &ec) -> net::awaitable<std::size_t>;

    // 写 FIN 帧关闭指定 stream
    auto write_fin(std::uint32_t stream_id) -> net::awaitable<void>;

    // 写 SYNACK 帧（v2+）
    auto write_synack(std::uint32_t stream_id) -> net::awaitable<void>;

    // 关闭 session
    void close();

private:
    auto recv_loop() -> net::awaitable<void>;
    auto write_frame(cmd command, std::uint32_t stream_id,
                     std::span<const std::byte> data) -> net::awaitable<void>;
    auto send_padding(std::uint32_t pkt_num) -> net::awaitable<void>;

    transport::shared_transmission transport_;
    stream_callback on_new_stream_;

    // 每个 stream 有一个 channel 用于缓冲接收的数据
    memory::unordered_map<std::uint32_t,
        std::shared_ptr<boost::asio::experimental::concurrent_channel<
            void(std::error_code, memory::vector<std::byte>)>>> streams_;

    std::shared_ptr<padding_factory> padding_;
    std::uint32_t pkt_counter_{0};
    bool received_settings_{false};
    std::uint32_t peer_version_{1};
};
```

### Phase A4：Stream Transport 适配器（`stream_transport.hpp`）

```cpp
class anytls_stream_transport final : public transport::transmission
{
public:
    using channel_type = boost::asio::experimental::concurrent_channel<
        void(std::error_code, memory::vector<std::byte>)>;

    explicit anytls_stream_transport(
        std::shared_ptr<anytls_session> session,
        std::uint32_t stream_id,
        std::shared_ptr<channel_type> read_channel);

    [[nodiscard]] auto transport_type() const noexcept -> type override { return type::tcp; }
    [[nodiscard]] transmission *next_layer() noexcept override { return nullptr; }
    [[nodiscard]] const transmission *next_layer() const noexcept override { return nullptr; }
    [[nodiscard]] executor_type executor() const override;

    auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override;
    auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override;

    void close() override;
    void cancel() override;

private:
    std::shared_ptr<anytls_session> session_;
    std::uint32_t stream_id_;
    std::shared_ptr<channel_type> read_channel_;

    // 缓冲区
    memory::vector<std::byte> pending_;
    std::size_t pending_offset_{0};
};
```

**async_read_some**：
1. 如果 `pending_` 有数据 → 切片返回
2. 否则 `co_await read_channel_->async_receive()` → 缓存到 `pending_` → 切片返回

**async_write_some**：
1. `co_await session_->write_psh(stream_id_, buffer, ec)`

### Phase A5：协议 Handler + Scheme 整合

**`protocol/anytls/conn.hpp` + `process.cpp`**：

```cpp
namespace psm::protocol::anytls
{
    auto handle(context::session &ctx, std::span<const std::byte> preread)
        -> net::awaitable<void>;
}
```

流程：
1. 从 `ctx.inbound`（实际是 `anytls_stream_transport`）读取 SOCKS 地址
2. `router.resolve(target)` → 建立上游连接
3. `connect::tunnel(ctx.inbound, outbound, ctx)` 双向转发
4. 后续 Stream 由 `anytls_session::on_new_stream` 回调自动处理

**Scheme 整合**（`src/prism/stealth/anytls/scheme.cpp`）：

```cpp
auto scheme::handshake(stealth::handshake_context ctx)
    -> net::awaitable<stealth::handshake_result>
{
    // 1. 解包到原始 transport（参照 native.cpp）
    auto raw = connect::peel_to_raw(std::move(ctx.inbound));
    auto clean = transport::wrap_with_preview(std::move(raw), preread, arena);

    // 2. TLS 握手（使用配置的证书）
    auto [ssl_ec, ssl_stream, recovered] = co_await transport::encrypted::ssl_handshake(
        std::move(clean), *ctx.session->server_ctx.ssl_ctx);
    // 错误处理...

    auto encrypted_trans = std::make_shared<transport::encrypted>(ssl_stream);

    // 3. 读取 32B password hash
    std::array<std::byte, 32> hash_buf{};
    // async_read_exact(encrypted_trans, hash_buf)

    // 4. 查找 user_map
    auto it = user_map.find(hash_buf);
    if (it == user_map.end()) co_return error_result;

    // 5. 读取 padding
    std::array<std::byte, 2> pad_len_buf{};
    // async_read_exact + skip padding

    // 6. 创建 anytls_session，启动 recv_loop
    auto session = std::make_shared<anytls_session>(
        encrypted_trans, user_map, padding,
        on_new_stream_callback);
    session->start();  // 启动 recv_loop 协程

    // 7. 等待第一个 Stream
    auto [ec, stream_info] = co_await session->wait_first_stream();
    auto [stream_id, preread_data] = stream_info;

    // 8. 创建 stream_transport
    auto stream_transport = /* 获取第一个 stream 的 transport */;

    // 9. 返回
    co_return handshake_result{
        .transport = stream_transport,
        .detected = protocol::protocol_type::anytls,
        .preread = preread_data,
        .scheme = "anytls"
    };
}
```

**Session::diversion() 修改**：
```cpp
case protocol::protocol_type::anytls:
    co_await protocol::anytls::handle(ctx_, preread_span);
    break;
```

---

# 三、TrustTunnel（TCP only）

TrustTunnel 走 **Path A**（ssl::stream 黑盒），本质是 **TLS + HTTP/2 CONNECT 代理**。
这是三个协议中最简单的一个——标准 HTTP/2 反向代理，不需要自定义帧格式。

## 3.1 协议流程（服务端视角，TCP only）

```
客户端                    Prism(服务端)
  │                           │
  │──── TLS ClientHello ─────>│  (标准 TLS 握手, ALPN=h2)
  │<─── TLS ServerHello ──────│
  │    ... TLS handshake ...  │
  │<─── TLS Finished ────────│  (TLS 隧道建立)
  │                           │
  │─── HTTP/2 CONNECT ──────>│
  │    :method = CONNECT       │
  │    :authority = target:port│
  │    Host = target:port      │
  │    Proxy-Authorization:    │
  │      Basic base64(user:pw) │
  │    User-Agent: <OS> <app>  │
  │                           │
  │                           │  验证 Basic auth
  │                           │  解析 Host 获取目标地址
  │                           │
  │<── HTTP/2 200 OK ────────│
  │                           │
  │─── 原始 TCP 数据 ────────>│  H2 stream body = TCP payload
  │<── 原始 TCP 数据 ─────────│  双向透明转发
```

HTTP/2 stream body 直接承载 TCP payload，无额外帧格式（不像 gRPC/gun 有 protobuf 封装）。

### 特殊 Host 值（暂不实现）
| Host | 含义 | 实现状态 |
|------|------|----------|
| `target:port` | TCP 代理 | **本次实现** |
| `_udp2` | UDP 多路复用 | 暂不实现 |
| `_icmp` | ICMP 隧道 | 暂不实现 |
| `_check` | 健康检查 | 暂不实现 |

### 认证机制
```
Proxy-Authorization: Basic base64(username:password)
```
标准 HTTP Basic Auth，明文密码比对。

### 服务端响应
- 认证成功：HTTP 200 OK + Flush
- 认证失败：HTTP 407 Proxy Authentication Required

## 3.2 架构设计：nghttp2 与协程桥接

### nghttp2 回调模型

nghttp2 是 callback-based C 库。服务端需要：
1. 创建 `nghttp2_session`（server mode）
2. 注册回调：
   - `on_begin_headers`：检测 CONNECT 方法
   - `on_header`：收集 `:authority`/`Host`、`proxy-authorization`、`user-agent`
   - `on_data`：接收客户端 TCP payload
   - `send_data`：发送数据到客户端（通过 `nghttp2_session_mem_send`）
3. 通过 `nghttp2_session_mem_recv` 喂入 TLS 解密后的数据
4. 通过 `nghttp2_session_mem_send` 获取待发送的数据

### 协程桥接方案

nghttp2 的回调在 `nghttp2_session_mem_recv` 调用栈中同步执行。
需要桥接到 Prism 的异步传输：

```cpp
class h2_bridge
{
public:
    explicit h2_bridge(transport::shared_transmission tls_transport);

    // 喂入 TLS 解密后的数据，触发 nghttp2 回调
    auto feed(std::span<const std::byte> data) -> void;

    // 获取 nghttp2 想要发送的数据（由 send_data 回调产生）
    [[nodiscard]] auto pending_output() const -> std::span<const std::byte>;

    // 清空已发送的输出
    void clear_output();

    // 主循环：读 TLS → feed → send output → 循环
    auto run() -> net::awaitable<void>;

    // 发送 CONNECT 200 OK 响应
    auto submit_response(int32_t stream_id) -> void;

    // 发送数据到指定 H2 stream
    auto submit_data(int32_t stream_id, std::span<const std::byte> data) -> void;

    // CONNECT 请求回调（由 on_header 触发）
    using connect_callback = std::function<void(
        int32_t stream_id,
        memory::string target_host,
        std::uint16_t target_port,
        memory::string username)>;
    void set_connect_handler(connect_callback cb);

    // 数据到达回调（由 on_data 触发）
    using data_callback = std::function<void(int32_t stream_id, std::span<const std::byte> data)>;
    void set_data_handler(data_callback cb);

private:
    transport::shared_transmission transport_;
    nghttp2_session *session_;

    // 输出缓冲区（send_data 回调写入）
    memory::vector<std::byte> output_buf_;

    // CONNECT 请求解析状态
    struct connect_request {
        memory::string authority;
        memory::string auth_header;
        memory::string user_agent;
    };
    std::unordered_map<int32_t, connect_request> pending_connects_;

    connect_callback on_connect_;
    data_callback on_data_;
};
```

**H2 stream → transmission 适配器**：

```cpp
class h2_stream_transport final : public transport::transmission
{
public:
    using channel_type = boost::asio::experimental::concurrent_channel<
        void(std::error_code, memory::vector<std::byte>)>;

    explicit h2_stream_transport(
        std::shared_ptr<h2_bridge> bridge,
        int32_t stream_id,
        std::shared_ptr<channel_type> read_channel);

    auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override;
    auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override;
    // ... transport_type, next_layer, close, cancel, executor
};
```

**数据流**：
```
客户端 TLS data → TLS decrypt → h2_bridge::feed() → nghttp2 回调:
  on_data(stream_id, data) → channel.try_send(data)
                                            ↓
h2_stream_transport::async_read_some ← channel.async_receive()

h2_stream_transport::async_write_some → h2_bridge::submit_data(stream_id, data)
  → nghttp2 生成 H2 DATA frame → h2_bridge::pending_output()
  → TLS encrypt → 发送到客户端
```

## 3.3 新增文件

| 文件 | 用途 |
|------|------|
| `include/prism/stealth/trusttunnel/h2_bridge.hpp` | nghttp2 会话管理 + 回调桥接 |
| `src/prism/stealth/trusttunnel/h2_bridge.cpp` | 桥接实现 |
| `include/prism/stealth/trusttunnel/h2_stream.hpp` | H2 stream → transmission 适配器 |
| `src/prism/stealth/trusttunnel/h2_stream.cpp` | 适配器实现 |

修改文件：
| 文件 | 修改内容 |
|------|----------|
| `src/prism/stealth/trusttunnel/scheme.cpp` | 从桩实现改为调用 h2_bridge |
| `CMakeLists.txt`（根） | 添加 nghttp2 FetchContent |
| `src/CMakeLists.txt` | 添加新源文件，链接 nghttp2 |

## 3.4 实施步骤

### Phase T1：引入 nghttp2

根 `CMakeLists.txt` 添加：
```cmake
FetchContent_Declare(nghttp2
    GIT_REPOSITORY https://github.com/nghttp2/nghttp2.git
    GIT_TAG v1.62.0
)
set(NGHTTP2_ENABLE_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(nghttp2)
```
`src/CMakeLists.txt` 链接 `nghttp2::nghttp2_static`。

### Phase T2：H2 bridge（`h2_bridge.hpp` / `h2_bridge.cpp`）

实现上面描述的 `h2_bridge` 类，核心：
1. `nghttp2_session_server_new()` 创建服务端 session
2. 注册 `nghttp2_session_callbacks`：
   - `on_begin_headers_callback`：检测 CONNECT
   - `on_header_callback`：收集 header
   - `on_data_callback`：接收数据 → channel
   - `send_data_callback`：输出到 output_buf_
3. `run()` 循环：`async_read_some` → `nghttp2_session_mem_recv` → `nghttp2_session_mem_send` → `async_write`
4. HTTP/2 server connection preface：`nghttp2_submit_settings()`

### Phase T3：H2 stream 适配器（`h2_stream.hpp` / `h2_stream.cpp`）

实现 `h2_stream_transport`，与 AnyTLS 的 `anytls_stream_transport` 结构相同：
- `async_read_some` 从 channel 读取
- `async_write_some` 通过 `h2_bridge::submit_data` 发送

### Phase T4：Scheme 整合

修改 `src/prism/stealth/trusttunnel/scheme.cpp`：

```cpp
auto scheme::handshake(stealth::handshake_context ctx)
    -> net::awaitable<stealth::handshake_result>
{
    // 1. 解包 + TLS 握手（ALPN=h2，使用配置的证书）
    //    参照 native.cpp，但 ssl_context 需要设置 ALPN h2
    auto raw = connect::peel_to_raw(std::move(ctx.inbound));
    auto clean = transport::wrap_with_preview(std::move(raw), preread, arena);

    // 配置 ALPN
    SSL_CTX_set_alpn_select_cb(ssl_ctx, select_h2, nullptr);

    auto [ssl_ec, ssl_stream, recovered] = co_await transport::encrypted::ssl_handshake(
        std::move(clean), *ssl_ctx);

    auto encrypted_trans = std::make_shared<transport::encrypted>(ssl_stream);

    // 2. 创建 h2_bridge
    auto bridge = std::make_shared<h2_bridge>(encrypted_trans);

    // 3. 设置 CONNECT handler（promise/future 模式等待第一个 CONNECT）
    // 4. 启动 bridge run 协程
    // 5. 等待 CONNECT 请求
    // 6. 验证 Basic auth
    // 7. 解析 Host 获取目标地址
    // 8. 发送 200 OK
    // 9. 创建 h2_stream_transport
    // 10. 返回 handshake_result
}
```

---

# 四、构建系统变更汇总

## 依赖引入

| 依赖 | 用途 | 协议 | 状态 |
|------|------|------|------|
| blake3 (已有) | BLAKE3 keyed mode + derive_key | Restls | 需扩展 keyed_hasher |
| BoringSSL (已有) | TLS 握手 | AnyTLS, TrustTunnel | 已有 |
| BoringSSL MD5 | padding MD5 计算 | AnyTLS | 已有 |
| nghttp2 (新增) | HTTP/2 frame 解析 | TrustTunnel | 新增 FetchContent |
| Boost.Asio concurrent_channel | 异步 pipe | AnyTLS, TrustTunnel | 已有（experimental） |

## 新增源文件

```
Restls:
  include/prism/crypto/blake3.hpp            (修改：添加 keyed_hasher/hash)
  src/prism/crypto/blake3.cpp                (修改：对应实现)
  include/prism/stealth/restls/crypto.hpp    (新增：header-only)
  include/prism/stealth/restls/script.hpp    (新增)
  src/prism/stealth/restls/script.cpp        (新增)
  include/prism/stealth/restls/handshake.hpp (新增)
  src/prism/stealth/restls/handshake.cpp     (新增)
  include/prism/stealth/restls/transport.hpp (新增)
  src/prism/stealth/restls/transport.cpp     (新增)

AnyTLS:
  include/prism/stealth/anytls/frame.hpp           (新增：header-only)
  include/prism/stealth/anytls/padding.hpp         (新增)
  src/prism/stealth/anytls/padding.cpp             (新增)
  include/prism/stealth/anytls/session.hpp         (新增)
  src/prism/stealth/anytls/session.cpp             (新增)
  include/prism/stealth/anytls/stream_transport.hpp(新增)
  include/prism/protocol/anytls/conn.hpp           (新增)
  src/prism/protocol/anytls/process.cpp            (新增)

TrustTunnel:
  include/prism/stealth/trusttunnel/h2_bridge.hpp  (新增)
  src/prism/stealth/trusttunnel/h2_bridge.cpp      (新增)
  include/prism/stealth/trusttunnel/h2_stream.hpp  (新增)
  src/prism/stealth/trusttunnel/h2_stream.cpp      (新增)
```

## 修改文件

```
Restls:
  src/prism/stealth/restls/scheme.cpp    (从桩改为调用 handshake + transport)

AnyTLS:
  include/prism/protocol/protocol_type.hpp  (添加 anytls 枚举值)
  src/prism/stealth/anytls/scheme.cpp       (从桩改为 TLS + 认证 + session)
  src/prism/instance/session/session.cpp    (switch 添加 anytls case)

TrustTunnel:
  src/prism/stealth/trusttunnel/scheme.cpp  (从桩改为 TLS + h2_bridge)
  CMakeLists.txt（根）                       (添加 nghttp2 FetchContent)

通用:
  src/prism/stealth/CMakeLists.txt          (添加所有新源文件)
  src/CMakeLists.txt                        (添加协议处理源文件)
```

---

# 五、三种协议的对比

| 方面 | Restls | AnyTLS | TrustTunnel |
|------|--------|--------|-------------|
| 架构路径 | Path C (代理) | Path A (TLS 终结) | Path A (TLS 终结) |
| TLS 握手 | 代理到后端 | 自己终结 (BoringSSL) | 自己终结 (BoringSSL, ALPN=h2) |
| 后端连接 | 需要真实 TLS 服务器 | 不需要 | 不需要 |
| 认证方式 | BLAKE3 keyed HMAC | SHA-256(password) 查表 | HTTP Basic Auth |
| 帧格式 | 自定义 (auth_mac + mask + data) | 自定义 (7B header + data) | HTTP/2 标准 |
| 多路复用 | 无 (单流) | 有 (多 Stream via concurrent_channel) | 有 (H2 stream via nghttp2) |
| 流量控制 | Script 驱动 padding + write blocking | Padding 方案 + CheckMark | HTTP/2 内建 |
| TLS 版本 | TLS 1.3（TLS 1.2 暂跳过） | TLS 1.3 | TLS 1.3 |
| 复杂度 | 高（双工代理 + BLAKE3 + script） | 中高（多路复用架构适配） | 中（nghttp2 桥接） |
| 新依赖 | 无 | 无 | nghttp2 |
| Prism 集成点 | scheme + transport | scheme + protocol handler + session 修改 | scheme + h2_bridge |

---

# 六、实施顺序和依赖关系

```
R1 (BLAKE3 keyed) ─→ R2 (script) ─→ R3 (handshake) ─→ R4 (transport) ─→ R5 (scheme) ─→ R6 (build)
                                                                            │
T1 (nghttp2) ─→ T2 (h2_bridge) ─→ T3 (h2_stream) ─→ T4 (scheme)         │
                                                                            │
A1 (frame) ─→ A2 (padding) ─→ A3 (session) ─→ A4 (stream_transport) ─→ A5 (protocol handler + scheme)
```

Restls 和 TrustTunnel 可以并行（无依赖）。
AnyTLS 需要 `concurrent_channel` 和 `protocol_type::anytls` 提前就绪。

---

# 七、风险和注意事项

## Restls
- BLAKE3 keyed mode (`blake3_hasher_init_keyed`) 是新增 API，需要验证 blake3 C 库版本
- clientFinished 是**完整加密 TLS record**（含 TLS header），不仅仅是 Finished 消息
- mask 计算使用 XOR 之前的明文 data（最多 32 字节）
- write blocking 要求读写方向协调，需要在 transport 内部实现
- TLS 1.2 GCM 模式的 8 字节 explicit nonce 处理复杂，初始版本跳过
- `"restls-random-response"` 魔数字符串用于响应帧

## AnyTLS
- 多路复用与 Prism "一个连接=一个会话" 模型冲突
  解决方案：`anytls_session` 管理多个 stream，每个 stream 通过回调创建独立的 outbound + tunnel 协程
- recv_loop 和 stream_transport 通过 `concurrent_channel` 协调（协程安全，无 mutex）
- padding 方案的 CheckMark (`c` = -1) 标记 payload 分段点
- padding MD5 需要用 BoringSSL 的 `MD5()` 计算原始 scheme 的哈希
- Settings 交换中 `v>=2` 才发 cmdServerSettings 和 cmdSYNACK
- 后续 Stream 的 `on_new_stream` 回调需要访问 `router` 和 `io_context`

## TrustTunnel
- nghttp2 引入增加构建复杂度，需要 FetchContent 配置
- nghttp2 回调在 `nghttp2_session_mem_recv` 调用栈中同步执行，
  需要在回调中把数据写入 `concurrent_channel`，不能直接 `co_await`
- HTTP/2 server 端需要处理 SETTINGS、PING、GOAWAY 等控制帧
- ALPN 必须协商 h2，否则连接无法工作
- HTTP/2 server connection preface 必须先发送 SETTINGS 帧
- 初始版本只支持 TCP CONNECT，不支持 `_udp2` / `_icmp` / `_check`
