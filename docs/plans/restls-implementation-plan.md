# Restls 服务端实现计划

## 核心思路

Restls 遵循 ShadowTLS 的 **代理架构**（Path C）：
- 服务端不终结 TLS，而是将客户端流量代理到真实后端 TLS 服务器
- 在代理过程中，通过 HMAC 验证客户端身份
- 认证成功后，使用自定义帧格式包装应用数据

与 ShadowTLS 的区别：
- ShadowTLS 认证在 session_id（TLS 层），Restls 认证在 first encrypted record（record 层）
- ShadowTLS 用 HMAC-SHA1 + XOR，Restls 用 BLAKE3-HMAC + XOR
- ShadowTLS 传输层用累积 HMAC，Restls 用 per-record HMAC + script 驱动 padding
- Restls 支持 TLS 1.2 和 TLS 1.3 两种模式

## 协议流程（服务端视角）

```
                客户端                    Prism(服务端)                  后端TLS服务器
                  │                           │                              │
                  │──── ClientHello ──────────>│                              │
                  │  session_id = BLAKE3-HMAC  │                              │
                  │  (RestlsSecret, key_shares  │                              │
                  │   + psk_identities)[:16]    │                              │
                  │                           │──── ClientHello ─────────────>│
                  │                           │<─── ServerHello ─────────────│
                  │<─── ServerHello ──────────│                              │
                  │                           │                              │
    ─ ─ ─ 握手阶段双向转发 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
                  │                           │                              │
                  │  后端→客户端方向：          │                              │
                  │  第一个 encrypted record   │<─── Finished/Cert ──────────│
                  │  XOR with BLAKE3-HMAC     │  XOR record with             │
                  │  (RestlsSecret,           │  HMAC(Secret, serverRandom)  │
                  │   serverRandom)[:16]      │  [:16]                       │
                  │<─── XOR'd record ─────────│                              │
                  │                           │                              │
                  │  客户端→后端方向：          │                              │
                  │  携带 clientFinished 的    │                              │
                  │  第一个 post-Finished      │── ── 转发到后端 ─ ─ ─ ─ ─ ─ >│
                  │  record（带 auth header）  │  验证 auth_mac               │
                  │                           │  验证成功 → restlsAuthed=true │
                  │                           │                              │
    ─ ─ ─ 认证完成，进入应用数据阶段 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
                  │                           │                              │
                  │  自定义帧格式：             │                              │
                  │  [TLS Header(5)]           │                              │
                  │  [auth_mac(8)]             │                              │
                  │  [masked_len+cmd(4)]       │                              │
                  │  [data]                    │                              │
                  │  [padding]                 │                              │
                  │                           │                              │
                  │  后端服务器正常关闭         │                              │
```

## 密钥和认证机制

### 1. RestlsSecret 派生
```
RestlsSecret = BLAKE3_DeriveKey("restls-traffic-key", password)  // 32 字节
```

### 2. 握手阶段认证

**客户端→服务端（session_id HMAC）：**
```
session_id = BLAKE3-HMAC(RestlsSecret, key_share_data_1 + ... + key_share_data_N
                          + psk_identity_1 + ... + psk_identity_M)[:16]
```

**服务端→客户端（第一个 encrypted record XOR）：**
```
server_auth_mask = BLAKE3-HMAC(RestlsSecret, server_random)[:16]
XOR first_encrypted_record[5:] with server_auth_mask
```
- 客户端用同样的 XOR 还原后，用 TLS 的正常流程解密
- 如果 XOR 后解密失败，则用原始 record 解密（fallback = 不是 Restls 客户端）

**客户端→服务端（auth header，首个 post-Finished record）：**
```
auth_mac = BLAKE3-HMAC(RestlsSecret, server_random, "client-to-server",
                        counter(8B), clientFinished?, tls_header, data_after_mac)[:8]
mask = BLAKE3-HMAC(RestlsSecret, server_random, "client-to-server",
                    counter(8B), data_sample[:32])[:4]
XOR [data_len(2B) + cmd(2B)] with mask
```

### 3. 应用数据阶段帧格式

```
Record Layout:
┌──────────────────────────────────────────────────────┐
│ TLS Record Header (5 bytes)                          │
│   [0x17] [0x03 0x03] [payload_len(2B BE)]           │
├──────────────────────────────────────────────────────┤
│ auth_mac (8 bytes)                                   │
│   = BLAKE3-HMAC(RestlsSecret, SR, direction,        │
│     counter(8B), [clientFinished?], header,          │
│     data_after_mac)[:8]                              │
├──────────────────────────────────────────────────────┤
│ masked_len + cmd (4 bytes)                           │
│   data_len(2B BE) XOR mask[:2]                      │
│   cmd(2B)           XOR mask[2:4]                   │
├──────────────────────────────────────────────────────┤
│ data (data_len bytes, 可以为空)                       │
├──────────────────────────────────────────────────────┤
│ padding (随机填充)                                    │
└──────────────────────────────────────────────────────┘

mask = BLAKE3-HMAC(RestlsSecret, SR, direction, counter(8B),
                    data_sample[:32])[:4]

cmd 类型:
  [0x00, 0x00] = NoOp（不需要响应）
  [0x01, N]    = Response（请求 N 个随机响应）
```

### 4. Restls Script 语法

```
"250?100<1,350~100<1,600~100,300~200,300~100"

每条规则格式: targetLen[~randomRange|?randomRange][<responseCount]
- targetLen: 目标总 payload 长度
- ~randomRange: 加上 0~randomRange 的随机值
- ?randomRange: 取 0~randomRange 的随机值作为固定 targetLen
- <responseCount: 需要等待 responseCount 个服务器响应后才继续发送
```

## 新增文件清单

| 文件 | 用途 |
|------|------|
| `include/prism/stealth/restls/handshake.hpp` | 握手流程声明 |
| `src/prism/stealth/restls/handshake.cpp` | 握手流程实现 |
| `include/prism/stealth/restls/transport.hpp` | 传输层包装器声明 |
| `src/prism/stealth/restls/transport.cpp` | 传输层包装器实现 |
| `include/prism/stealth/restls/script.hpp` | Restls Script 解析器和执行引擎 |
| `src/prism/stealth/restls/script.cpp` | Restls Script 实现 |
| `include/prism/stealth/restls/crypto.hpp` | Restls 密码学原语（BLAKE3-HMAC、XOR mask） |

修改文件：
| 文件 | 修改内容 |
|------|----------|
| `src/prism/stealth/restls/scheme.cpp` | 从桩实现改为调用 handshake + 创建 transport |
| `src/prism/stealth/stealth.hpp`（聚合头文件） | 添加新子头文件 |
| `src/CMakeLists.txt` | 添加新源文件 |

---

## 实施步骤

### Phase 1：密码学原语（`crypto.hpp`）

创建 header-only 密码学工具，复用已有的 `crypto/blake3.hpp`。

```cpp
// include/prism/stealth/restls/crypto.hpp

namespace psm::stealth::restls::crypto
{
    // 常量
    constexpr std::size_t handshake_mac_len = 16;   // 握手阶段 HMAC 截断长度
    constexpr std::size_t app_data_mac_len = 8;     // 应用数据 HMAC 截断长度
    constexpr std::size_t mask_len = 4;             // XOR mask 长度（= cmd_len + len_len）
    constexpr std::size_t auth_header_len = app_data_mac_len + mask_len; // = 12
    constexpr std::size_t app_data_offset = auth_header_len;             // = 12
    constexpr std::size_t app_data_len_offset = app_data_mac_len;        // = 8

    /// 派生 RestlsSecret：BLAKE3_DeriveKey("restls-traffic-key", password)
    [[nodiscard]] auto derive_restls_secret(std::string_view password)
        -> std::array<std::uint8_t, 32>;

    /// BLAKE3-HMAC：BLAKE3::New(32, key) → Write(data...) → Sum(nil)
    /// 等效于 Go 的 RestlsHmac(key)
    [[nodiscard]] auto blake3_hmac(std::span<const std::uint8_t> key,
                                    std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, 32>;

    /// 生成认证头 HMAC（per-record）
    /// direction: "server-to-client" 或 "client-to-server"
    [[nodiscard]] auto auth_header_hash(std::span<const std::uint8_t> restls_secret,
                                         std::span<const std::uint8_t> server_random,
                                         bool to_client,
                                         std::uint64_t counter)
        -> blake3_hasher; // 返回已初始化的 hasher，调用方继续 Write

    /// XOR data with key（循环）
    void xor_with_mask(std::span<std::uint8_t> data, std::span<const std::uint8_t> mask);

    /// 生成随机填充
    void random_padding(std::span<std::byte> padding);
}
```

**关键实现**：
- `blake3_hmac` 使用 BLAKE3 的 keyed mode（`blake3::New(32, key)`），等效于 Go 的 `RestlsHmac(key)` 返回的 `hash.Hash`
- `auth_header_hash` 初始化 hasher：keyed(restls_secret) → Write(server_random) → Write(direction) → Write(counter_8B)，返回 hasher 供调用方继续写入
- `xor_with_mask` 复用 `stealth::common::xor_with_key` 的逻辑，但操作 `uint8_t` span

### Phase 2：Script 解析器（`script.hpp` / `script.cpp`）

```cpp
// include/prism/stealth/restls/script.hpp

namespace psm::stealth::restls
{
    /// Restls 命令类型
    enum class command_type : std::uint8_t
    {
        noop = 0x00,     // 不需要响应
        response = 0x01  // 请求 N 个随机响应
    };

    /// 单条 script 规则
    struct script_line
    {
        std::int16_t target_base{0};  // 基础目标长度
        std::int16_t target_random{0}; // 随机范围（~和?语法）
        bool random_is_fixed{false};   // true = ?语法（一次性随机）
        command_type cmd{command_type::noop};
        std::uint8_t response_count{0};
    };

    /// Script 解析和执行引擎
    class script_engine
    {
    public:
        /// 解析 Restls Script 字符串
        explicit script_engine(const std::string_view script);

        /// 获取当前 counter 对应的 script line
        auto line_at(std::uint64_t counter) const
            -> const script_line&;

        /// 计算 targetLen（含随机化）
        [[nodiscard]] auto compute_target_len(const script_line &line) const
            -> std::int16_t;

        /// 根据 script 计算 payload 分配
        struct allocation { std::int16_t payload_len; std::int16_t data_len; std::int16_t padding_len; command_type cmd; std::uint8_t response_count; };
        [[nodiscard]] auto allocate(std::uint64_t counter, std::size_t data_available) const
            -> allocation;

    private:
        memory::vector<script_line> lines_;
        script_line default_line_;
    };
}
```

Script 解析逻辑（参照 mihomo `parseRecordScript`）：
1. 按逗号分割
2. 解析 `targetLen`（数字）
3. 解析可选的 `~randomRange` 或 `?randomRange`
4. 解析可选的 `<responseCount`

### Phase 3：握手流程（`handshake.hpp` / `handshake.cpp`）

```cpp
// include/prism/stealth/restls/handshake.hpp

namespace psm::stealth::restls
{
    struct handshake_detail
    {
        memory::vector<std::byte> client_first_data;  // 首帧实际数据（剥离 TLS header 和 auth header）
        std::array<std::uint8_t, 32> restls_secret{}; // 派生的 RestlsSecret
        std::array<std::uint8_t, 32> server_random{};  // ServerHello 的 ServerRandom
        std::uint64_t initial_read_counter{0};         // 读取方向初始 counter
        std::uint64_t initial_write_counter{0};        // 写入方向初始 counter
        memory::vector<std::byte> client_finished;     // 客户端 Finished record（用于首帧 auth_mac 验证）
        bool is_tls13{true};                           // 后端是否 TLS 1.3
    };

    auto handshake(net::ip::tcp::socket &client_sock,
                   const config &cfg,
                   memory::vector<std::byte> client_hello,
                   handshake_detail &detail)
        -> net::awaitable<stealth::handshake_result>;
}
```

**握手流程实现**（参照 ShadowTLS 的 `handshake.cpp` 架构 + mihomo 的 Restls 逻辑）：

#### Step 1：验证 session_id HMAC
```cpp
// 从 ClientHello 解析 session_id
// 计算 BLAKE3-HMAC(RestlsSecret, key_shares + psk_identities)[:16]
// 与 session_id 比较
// 注意：Prism 不修改 ClientHello，只是验证 session_id 中的 HMAC 是否匹配
```

**关键问题**：Prism 需要解析 ClientHello 中的 key_share 和 psk_identity 来验证 HMAC。
- mihomo 的客户端在 session_id 中写入 HMAC，服务端需要从 ClientHello 的 extensions 中提取 key_share 和 psk_identity
- 这些字段的位置：ClientHello → extensions → key_share extension → key_share_entry[] → group(2B) + length(2B) + data

#### Step 2：建立后端连接，转发 ClientHello
```cpp
// 与 ShadowTLS 相同：解析 host:port，DNS 解析，TCP connect
// 将原始 ClientHello 转发给后端
```

#### Step 3：读取后端 ServerHello，转发给客户端
```cpp
// 读取后端 ServerHello
// 提取 server_random
// 转发给客户端
```

#### Step 4：双向转发握手阶段数据
```cpp
// 后端→客户端方向：
//   读取后端 TLS 记录
//   对于第一个 encrypted record（ApplicationData 类型）：
//     计算 server_auth_mask = BLAKE3-HMAC(RestlsSecret, server_random)[:16]
//     XOR record[5:] with server_auth_mask（TLS 1.3 模式）
//     发送给客户端
//   后续记录原样转发
//
// 客户端→后端方向：
//   原样转发所有客户端记录到后端
//   直到检测到第一个带 auth header 的 record
```

#### Step 5：认证客户端首帧
```cpp
// 客户端发送的第一个 post-handshake record 包含 auth header
// 读取该 record，验证 auth_mac
// 验证成功 → restlsAuthed = true
// 提取实际数据
// 关闭后端连接
```

**实现细节 — 双工转发的状态机**：

与 ShadowTLS 类似，使用两个并发协程：
1. `backend_to_client_relay` — 转发后端数据，对第一个 encrypted record 做 XOR
2. `client_to_backend_read` — 转发客户端数据，等待 auth header

但 Restls 的特殊之处在于：
- 后端连接在**握手完成、客户端认证通过后关闭**（不像 ShadowTLS 继续使用后端连接）
- 客户端认证的首帧不是普通的 TLS ApplicationData，而是 Restls 自定义帧格式
- 需要区分"握手阶段"和"应用数据阶段"

**简化的状态机设计**：

```
状态 1: HANDSHAKE_RELAY
  - 后端→客户端：原样转发（但第一个 encrypted record 要 XOR server_auth_mask）
  - 客户端→后端：原样转发
  - 退出条件：检测到后端的 ChangeCipherSpec（TLS 1.2）或 encrypted extensions 完成（TLS 1.3）

状态 2: WAIT_AUTH
  - 客户端→方向：读取下一个 record，尝试验证 auth header
  - 后端→方向：继续转发（后端可能还有 NewSessionTicket 等）
  - 退出条件：auth_mac 验证成功

状态 3: AUTHENTICATED
  - 关闭后端连接
  - 返回 client_first_data
  - 创建 restls_transport
```

**实际上更简洁的做法**（参照 mihomo 的实现方式）：

mihomo 的 Restls 不是在握手阶段做双工转发状态机，而是：
1. 完整代理整个 TLS 握手（客户端↔后端双向转发所有记录）
2. 在转发过程中，对**第一个从后端收到的 encrypted record** 做 XOR
3. 握手完成后，客户端发送的第一个带 auth header 的 record 进行验证
4. 验证成功后，关闭后端连接，切换到 restls_transport

这意味着我们不需要复杂的状态机。流程是：

```
1. 建立 TCP 连接到后端
2. 转发 ClientHello
3. 启动双工转发协程：
   a. backend→client: 逐帧转发，对第一个 encrypted record 做 XOR
   b. client→backend: 逐帧转发，同时监听第一个带 auth header 的 record
4. 等待客户端认证成功
5. 关闭后端连接
6. 创建 restls_transport
```

### Phase 4：传输层包装器（`transport.hpp` / `transport.cpp`）

```cpp
// include/prism/stealth/restls/transport.hpp

namespace psm::stealth::restls
{
    class restls_transport final : public transport::transmission
    {
    public:
        explicit restls_transport(net::ip::tcp::socket socket,
                                   std::span<const std::uint8_t> restls_secret,
                                   std::span<const std::uint8_t> server_random,
                                   std::span<const std::byte> initial_data,
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

    private:
        /// 读取一个 Restls 帧（含 auth header 验证 + mask 解码）
        auto read_restls_frame(std::error_code &ec)
            -> net::awaitable<std::optional<memory::vector<std::byte>>>;

        /// 写入一个 Restls 帧（含 auth header + mask + padding + script）
        auto write_restls_frame(std::span<const std::byte> data, std::error_code &ec)
            -> net::awaitable<std::size_t>;

        /// 处理 script 命令（发送随机响应）
        auto handle_command(command_type cmd, std::uint8_t count, bool data_sent)
            -> void;

        net::ip::tcp::socket socket_;
        std::array<std::uint8_t, 32> restls_secret_;
        std::array<std::uint8_t, 32> server_random_;
        script_engine script_;

        // 计数器
        std::uint64_t read_counter_{0};   // server-to-client 方向
        std::uint64_t write_counter_{0};  // client-to-server 方向

        // 缓冲区
        memory::vector<std::byte> initial_buffer_;
        std::size_t initial_offset_{0};
        memory::vector<std::byte> pending_buffer_;
        std::size_t pending_offset_{0};

        // 写入缓冲（script 驱动的 pending 数据）
        memory::vector<std::byte> write_pending_buf_;
        bool write_blocked_{false};

        // 首帧 clientFinished（仅第一次写入时需要）
        memory::vector<std::byte> client_finished_;
    };
}
```

**读取方向 (`read_restls_frame`)**：
```
1. 读取 TLS Record Header (5 bytes)
2. 读取 TLS Record Body (record_len bytes)
3. 提取 header = record[0:5], body = record[5:]
4. 初始化 auth_hasher = auth_header_hash(secret, SR, to_client=true, read_counter)
5. auth_hasher.Write(header)
6. auth_hasher.Write(body[app_data_len_offset:])  // mask+cmd + data + padding
7. expected_mac = auth_hasher.Sum()[:8]
8. 比较 body[0:8] == expected_mac，失败则 protocol_error
9. 初始化 mask_hasher = auth_header_hash(secret, SR, to_client=true, read_counter)
10. mask_hasher.Write(body[app_data_offset:app_data_offset+min(32, remaining)])
11. mask = mask_hasher.Sum()[:4]
12. XOR body[app_data_len_offset:app_data_len_offset+4] with mask
13. data_len = BigEndian.Uint16(body[app_data_len_offset:])
14. cmd = parse_command(body[app_data_len_offset+2:])
15. data = body[app_data_offset : app_data_offset + data_len]
16. read_counter++
17. return data, cmd
```

**写入方向 (`write_restls_frame`)**：
```
1. 获取当前 counter 对应的 script line
2. 计算 payload_len, data_len, padding_len, cmd = script.allocate(counter, data.size())
3. 构建缓冲区：
   - TLS Header (5 bytes): [0x17][0x03][0x03][payload_len BE]
   - auth_mac (8 bytes): 稍后填充
   - data_len (2 bytes BE) + cmd (2 bytes): 稍后 XOR
   - data[:data_len]
   - padding(padding_len): 随机
4. 计算 mask：
   - mask_hasher = auth_header_hash(secret, SR, to_client=false, write_counter)
   - mask_hasher.Write(buf[app_data_offset:app_data_offset+min(32, remaining)])
   - mask = mask_hasher.Sum()[:4]
5. 填充 data_len + cmd 并 XOR with mask
6. 计算 auth_mac：
   - auth_hasher = auth_header_hash(secret, SR, to_client=false, write_counter)
   - if (write_counter == 0 && client_finished 不为空): auth_hasher.Write(client_finished)
   - auth_hasher.Write(tls_header)
   - auth_hasher.Write(buf[app_data_len_offset:])
   - auth_mac = auth_hasher.Sum()[:8]
7. 填充 auth_mac 到 buf[0:8]
8. 通过 socket 发送整个 buf
9. write_counter++
10. 处理 script 命令：
    - 如果 cmd.needInterrupt() && data 还有剩余：设置 write_blocked_ = true
    - 如果 cmd == Response(N)：发送 N 个随机响应帧
```

### Phase 5：Scheme 整合（修改 `scheme.cpp`）

```cpp
auto scheme::handshake(stealth::handshake_context ctx)
    -> net::awaitable<stealth::handshake_result>
{
    // 1. 获取底层 reliable transport 的 raw socket
    auto *rel = ctx.inbound->lowest_layer<transport::reliable>();
    if (!rel) {
        result.detected = protocol::protocol_type::tls;
        result.transport = std::move(ctx.inbound);
        co_return result;
    }

    // 2. 调用 restls::handshake()
    handshake_detail detail;
    auto hs_result = co_await restls::handshake(
        rel->native_socket(),
        ctx.cfg->stealth.restls,
        std::move(ctx.preread),
        detail);

    if (fault::succeeded(hs_result.error))
    {
        // 3. 释放 socket
        auto raw_socket_opt = rel->release_socket();
        if (!raw_socket_opt) { /* fallback */ }

        // 4. 解析 script
        auto script = script_engine(ctx.cfg->stealth.restls.restls_script);

        // 5. 创建 restls_transport
        auto transport = std::make_shared<restls_transport>(
            std::move(*raw_socket_opt),
            detail.restls_secret,
            detail.server_random,
            detail.client_first_data,
            detail.initial_read_counter,
            detail.initial_write_counter,
            std::move(script));

        result.transport = transport;
        result.scheme = "restls";
        // 检测内层协议（同 ShadowTLS）
    }
    else
    {
        result.detected = protocol::protocol_type::tls;
    }

    co_return result;
}
```

### Phase 6：构建系统更新

`src/CMakeLists.txt` 添加：
```cmake
src/prism/stealth/restls/handshake.cpp
src/prism/stealth/restls/transport.cpp
src/prism/stealth/restls/script.cpp
```

### Phase 7：聚合头文件更新

`include/prism/stealth.hpp` 添加：
```cpp
#include <prism/stealth/restls/handshake.hpp>
#include <prism/stealth/restls/transport.hpp>
#include <prism/stealth/restls/script.hpp>
#include <prism/stealth/restls/crypto.hpp>
```

---

## 关键设计决策

### Q1：为什么不在 Restls 的 `verify()` 阶段做 session_id HMAC 验证？

**可以但不必要**。原因：
- Restls 是 Tier 2 方案（无独占特征），依赖 SNI 路由匹配
- session_id 的 HMAC 验证需要解析 ClientHello 的 key_share extension，复杂度高
- 即使验证失败，handshake 阶段会自然 fallback（返回 `tls` → 下一个 scheme）
- 如果性能需要，可以后续作为 Tier 1 优化加入

### Q2：如何处理 TLS 1.2 vs TLS 1.3 的差异？

TLS 1.3 模式（`version_hint = "tls13"`）：
- 标准握手：ClientHello → ServerHello → EncryptedExtensions → Certificate → Finished
- 服务端 XOR 第一个 encrypted record
- 客户端首帧包含 auth header

TLS 1.2 模式（`version_hint = "tls12"`）：
- 握手包含 ChangeCipherSpec
- 服务端 XOR 第一个 encrypted record（跳过 GCM nonce 8 字节如果 nonce==0）
- 客户端 Finished 在 auth_mac 计算中的位置不同

**实现策略**：先完整实现 TLS 1.3 模式（更常见），TLS 1.2 作为后续扩展。
初始版本只支持 `version_hint = "tls13"`。

### Q3：如何处理 script 驱动的 write blocking？

mihomo 的 `writeRestlsApplicationRecord` 有一个 `restlsWritePending` 状态：
- 当 script 规则包含 `<N`（需要等待响应）时，设置 `write_blocked_ = true`
- 后续的 `Write` 调用将数据追加到 `write_pending_buf_`
- 当收到服务器的响应（`extractRestlsAppData` 成功）时，取消 block 并 flush pending 数据

这需要读取和写入方向之间有协调机制。实现方式：
- `write_blocked_` 使用 `std::atomic<bool>`
- 读取方向解包成功后，如果 `write_blocked_` 为 true，调用内部的 `flush_pending()` 方法

### Q4：restls_transport 直接持有 socket 还是持有 transmission？

与 shadowtls_transport 一致，**直接持有 `net::ip::tcp::socket`**。
原因：Restls 握手完成后关闭后端连接，不再需要 transmission 的分层语义。
直接操作 socket 性能更好，避免虚函数开销。

### Q5：ClientHello 中 key_share 的解析

需要从 ClientHello 中提取 key_share extension 的数据来验证 session_id HMAC。
ClientHello 结构：
```
TLS Record Header (5)
Handshake Header (4: type(1) + length(3))
ClientVersion (2)
Random (32)
SessionID (1 + len)
CipherSuites (2 + len*2)
CompressionMethods (2)
Extensions Length (2)
Extensions...
  └─ key_share (type=0x0033)
       └─ key_share_entry[]: group(2) + length(2) + data
  └─ pre_shared_key (type=0x0029)
       └─ psk_identity[]: identity(2+len) + obfuscated_ticket_age(4)
```

需要实现一个轻量的 ClientHello key_share/psk 解析器。

---

## 与 ShadowTLS 的对比

| 方面 | ShadowTLS | Restls |
|------|-----------|--------|
| 认证位置 | session_id 中 HMAC-SHA1 | first encrypted record 中 XOR + auth header |
| 密码学原语 | HMAC-SHA1, SHA256, XOR | BLAKE3-HMAC, XOR |
| 传输层帧格式 | HMAC(4) + payload | auth_mac(8) + masked(4) + data + padding |
| 流量控制 | 无（固定帧格式） | script 驱动（padding + response） |
| 后端连接生命周期 | 握手期间保持，完成后关闭 | 握手期间保持，认证后关闭 |
| TLS 版本支持 | 仅 TLS 1.3 | TLS 1.2 和 TLS 1.3 |
| transport 类 | `shadowtls_transport` | `restls_transport` |

---

## 测试策略

1. **单元测试**：Script 解析、密码学原语（BLAKE3-HMAC、XOR mask）
2. **集成测试**：用 mihomo 的 Restls 客户端连接 Prism 服务端
3. **回归测试**：确保不影响现有 ShadowTLS/Reality/Native 方案
4. **并发测试**：Restls 客户端通过 Clash (mihomo) 连接 Prism 代理

---

## 风险和注意事项

1. **BLAKE3-HMAC 与 HMAC-SHA256 的区别**：
   - BLAKE3-HMAC 使用 BLAKE3 的 keyed mode (`blake3::New(32, key)`)，
     不是传统的 HMAC-SHA256 构造
   - Go 代码 `RestlsHmac(key)` = `blake3.New(32, key)` = BLAKE3 keyed hash
   - 这意味着不需要 HMAC 框架，直接用 BLAKE3 的 keyed mode

2. **clientFinished 的处理**：
   - 仅在第一次写入时，auth_mac 计算需要包含 clientFinished
   - 这需要在 handshake 阶段捕获客户端的 Finished record
   - 服务端无法直接解密客户端的 Finished，但可以通过帧拦截捕获 TLS record

3. **TLS 1.2 兼容性**：
   - TLS 1.2 的 ChangeCipherSpec 处理不同
   - GCM nonce 处理不同（需要检查 nonce==0）
   - 初始版本跳过 TLS 1.2 支持

4. **Script 默认值**：
   - 默认 script: `"250?100<1,350~100<1,600~100,300~200,300~100"`
   - 空 script 时使用默认值
