# Crypto 模块

**源码位置**: `include/prism/crypto/` · `src/prism/crypto/`

加密算法组件，通过 BoringSSL 提供底层密码学能力。所有上层函数以 C++ 封装，返回 `fault::code` 错误码，不抛异常（热路径约定）。

## 文件结构

```
crypto/
├── sha224.hpp        # SHA-224 哈希（header-only，Trojan 密码哈希）
├── base64.hpp        # Base64 编码/解码（header-only，RFC 4648）
├── aead.hpp/cpp      # AES-GCM / ChaCha20-Poly1305 AEAD 加解密
├── blake3.hpp/cpp    # BLAKE3 哈希（SS2022 密钥派生）
├── hkdf.hpp/cpp      # HKDF 密钥派生（RFC 5869 / TLS 1.3）
├── x25519.hpp/cpp    # X25519 密钥交换（Reality）
└── block.hpp/cpp     # AES-ECB 单块加解密（ShadowTLS / SS2022 UDP）
```

> 注：`sha224` 和 `base64` 是 header-only，没有对应的 `.cpp` 文件。`common.hpp` 不存在。

## 组件详情

### 1. SHA-224

| 属性 | 值 |
|------|------|
| **源文件** | `include/prism/crypto/sha224.hpp` |
| **类型** | Header-only |
| **底层** | OpenSSL `SHA224()` |
| **输出** | 28 字节（56 字符十六进制字符串） |

**用途**: Trojan 协议将用户密码哈希化为 SHA-224 十六进制字符串作为认证凭据。

#### `sha224(input) -> std::string`

```cpp
[[nodiscard]] inline auto sha224(std::string_view input) -> std::string;
```

计算输入字符串的 SHA-224 哈希，返回 56 字符十六进制小写字符串。

实现：调用 OpenSSL `SHA224()` 得到 28 字节摘要，逐字节转换为十六进制（查表法 `"0123456789abcdef"`）。

#### `normalize_credential(credential) -> std::string`

```cpp
[[nodiscard]] inline auto normalize_credential(std::string_view credential) -> std::string;
```

智能判断凭据格式：如果输入已经是 56 字符且全是十六进制数字，则直接返回（假设已哈希）；否则计算 `sha224(input)`。

**设计原因**: 配置文件中的 `authentication.users[].password` 可以是明文密码，也可以是预先计算的 SHA-224 哈希值。此函数统一处理两种情况。

#### `is_hex_string(str) -> bool`

检查字符串是否全部由十六进制字符组成。

#### 使用示例

```cpp
// Trojan 密码哈希
auto hash = psm::crypto::sha224("my_password");
// hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// 规范化凭据（自动判断是否已哈希）
auto cred = psm::crypto::normalize_credential(config_password);
```

---

### 2. Base64

| 属性 | 值 |
|------|------|
| **源文件** | `include/prism/crypto/base64.hpp` |
| **类型** | Header-only |
| **标准** | RFC 4648 |

**用途**: SS2022 PSK 解码、HTTP Basic Auth。

#### `base64_encode(input) -> std::string`

```cpp
[[nodiscard]] inline auto base64_encode(std::span<const std::uint8_t> input) -> std::string;
```

将原始字节编码为标准 Base64 字符串（含 `+`/`/` 和 `=` 填充）。

**算法**: 每 3 字节 → 4 个 Base64 字符。剩余 1 字节补 `==`，剩余 2 字节补 `=`。

#### `base64_decode(input) -> std::string`

```cpp
[[nodiscard]] inline auto base64_decode(std::string_view input) -> std::string;
```

解码 Base64 字符串为原始字节。支持：
- 标准 Base64（`+`/`/`）
- URL-safe Base64（`-`/`_` 自动转换）
- 自动跳过空白字符

**验证规则**:
- 填充字符数 ≤ 2
- 总长度必须是 4 的倍数
- 无效字符返回空字符串

**内部实现**: 使用 256 项查找表 `base64_decode_table` 将 ASCII 映射到 6-bit 值，非法字符映射为 255。

---

### 3. AEAD（认证加密）

| 属性 | 值 |
|------|------|
| **源文件** | `include/prism/crypto/aead.hpp` · `src/prism/crypto/aead.cpp` |
| **底层** | BoringSSL `EVP_AEAD_CTX` |
| **资源管理** | `std::unique_ptr` + 自定义删除器 |
| **Tag 长度** | 固定 16 字节 |

**用途**: Shadowsocks 2022 加密隧道、TLS 1.3 记录层。

#### 支持的算法

| 算法 | 枚举值 | 密钥长度 | Nonce 长度 |
|------|--------|----------|-----------|
| AES-128-GCM | `aead_cipher::aes_128_gcm` | 16 字节 | 12 字节 |
| AES-256-GCM | `aead_cipher::aes_256_gcm` | 32 字节 | 12 字节 |
| ChaCha20-Poly1305 | `aead_cipher::chacha20_poly1305` | 32 字节 | 12 字节 |
| XChaCha20-Poly1305 | `aead_cipher::xchacha20_poly1305` | 32 字节 | 24 字节 |

#### `aead_context` 类

**不可拷贝，可移动**。构造时根据算法类型初始化 BoringSSL 上下文，nonce 初始化为全零。

```cpp
psm::crypto::aead_context ctx(psm::crypto::aead_cipher::aes_256_gcm, key_span);
```

#### 加密/解密接口

```cpp
// 自动递增 nonce（状态模式，适用于 TCP 流）
auto seal(out, plaintext, ad = {})      -> fault::code;
auto open(out, ciphertext, ad = {})     -> fault::code;

// 显式 nonce（无状态，适用于 UDP 逐包）
auto seal(out, plaintext, nonce, ad)    -> fault::code;
auto open(out, ciphertext, nonce, ad)   -> fault::code;
```

#### Nonce 递增

自动 nonce 模式下，每次 `seal`/`open` 成功后 nonce **小端序递增**（从 byte[0] 开始加 1，溢出进位）。这是 SS2022 (SIP022) 规范要求的递增方式。

```cpp
// 小端序递增示例:
// [00, 00, 00, ..., 00] → [01, 00, 00, ..., 00] → [02, 00, 00, ..., 00]
// [FF, FF, 00, ..., 00] → [00, 00, 01, ..., 00]
```

#### 缓冲区大小计算

```cpp
// 加密输出大小 = 明文大小 + 16（认证标签）
constexpr auto out_size = aead_context::seal_output_size(plaintext_len);

// 解密输出大小 = 密文大小 - 16（认证标签）
constexpr auto out_size = aead_context::open_output_size(ciphertext_len);
```

#### 生命周期管理

```
构造: new EVP_AEAD_CTX → EVP_AEAD_CTX_init()
移动: unique_ptr 转移所有权，源对象 nonce 清零
析构: EVP_AEAD_CTX_cleanup() → delete（自动）
```

#### 使用示例

```cpp
// TCP 流模式（自动 nonce）
psm::crypto::aead_context ctx(cipher, key);
std::array<std::uint8_t, 100> out;
ctx.seal(out, plaintext);  // nonce = 0
ctx.seal(out, plaintext);  // nonce = 1（自动递增）

// UDP 逐包模式（显式 nonce）
std::array<std::uint8_t, 12> packet_nonce = {/* per-packet nonce */};
ctx.seal(out, plaintext, packet_nonce, aad);  // 不修改内部状态
```

---

### 4. BLAKE3

| 属性 | 值 |
|------|------|
| **源文件** | `include/prism/crypto/blake3.hpp` · `src/prism/crypto/blake3.cpp` |
| **底层** | BLAKE3 C 库（FetchContent 自动拉取编译） |
| **模式** | `derive_key`（域分离密钥派生） |

**用途**: Shadowsocks 2022 会话子密钥派生。替代 HKDF，速度更快。

#### `derive_key(context, material, out_len) -> std::vector<uint8_t>`

```cpp
[[nodiscard]] auto derive_key(std::string_view context,
                              std::span<const std::uint8_t> material,
                              std::size_t out_len) -> std::vector<std::uint8_t>;

void derive_key(std::string_view context,
                std::span<const std::uint8_t> material,
                std::size_t out_len,
                std::span<std::uint8_t> out);  // 预分配缓冲区版本
```

**算法流程**:
1. `blake3_hasher_init_derive_key_raw(ctx, context.data(), context.size())` — 使用上下文字符串初始化哈希器（域分离）
2. `blake3_hasher_update(ctx, material.data(), material.size())` — 输入密钥材料
3. `blake3_hasher_finalize(ctx, out.data(), out_len)` — 输出指定长度的派生密钥

**与普通哈希的区别**: `derive_key` 模式内置域分离机制，相同输入在不同上下文中产生不同输出。

#### SS2022 中的使用

```cpp
// Shadowsocks 2022 会话子密钥派生
auto subkey = psm::crypto::derive_key(
    "shadowsocks 2022 session subkey",  // 域分离上下文
    master_key,                         // 主密钥
    16                                  // AES-128 需要 16 字节
);
```

> **性能对比**: BLAKE3 derive_key 比 HKDF-SHA256 快约 3 倍，且无需 extract + expand 两步。

---

### 5. HKDF（密钥派生函数）

| 属性 | 值 |
|------|------|
| **源文件** | `include/prism/crypto/hkdf.hpp` · `src/prism/crypto/hkdf.cpp` |
| **底层** | BoringSSL `HMAC()`, `SHA256()`, `EVP_MD_CTX` |
| **标准** | RFC 5869（HKDF）+ RFC 8446（TLS 1.3） |

**用途**: TLS 1.3 密钥调度、Reality 协议 Ed25519 证书签名。

#### 基础函数

| 函数 | 签名 | 说明 |
|------|------|------|
| `hmac_sha256` | `(key, data) -> array[32]` | 计算 HMAC-SHA256 |
| `hmac_sha512` | `(key, data) -> array[64]` | 计算 HMAC-SHA512（Ed25519 证书签名） |
| `sha256`（单块）| `(data) -> array[32]` | 单次 SHA-256 哈希 |
| `sha256`（两块）| `(data1, data2) -> array[32]` | 流式 SHA-256，避免内存分配 |
| `sha256`（三块）| `(data1, data2, data3) -> array[32]` | 三块流式 SHA-256 |

#### HKDF-Extract（RFC 5869 Step 1）

```cpp
[[nodiscard]] auto hkdf_extract(std::span<const std::uint8_t> salt,
                                std::span<const std::uint8_t> ikm)
    -> std::array<std::uint8_t, 32>;
```

从输入密钥材料（IKM）提取伪随机密钥（PRK）：`PRK = HMAC-SHA256(salt, IKM)`。

**空盐处理**: 如果 `salt` 为空，使用 32 字节全零（符合 RFC 5869 规范）。

#### HKDF-Expand（RFC 5869 Step 2）

```cpp
[[nodiscard]] auto hkdf_expand(std::span<const std::uint8_t> prk,
                               std::span<const std::uint8_t> info,
                               std::size_t length)
    -> std::pair<fault::code, std::vector<std::uint8_t>>;
```

将 PRK 扩展为所需长度的输出密钥材料（OKM）：
```
T(1) = HMAC-SHA256(PRK, info || 0x01)
T(2) = HMAC-SHA256(PRK, T(1) || info || 0x02)
...
OKM = T(1) || T(2) || ... （截断到 length）
```

**限制**:
- 最大输出长度: 255 × 32 = 8160 字节
- PRK 长度必须 ≥ 32 字节
- 超限返回 `fault::code::invalid_argument`

#### HKDF-Expand-Label（TLS 1.3, RFC 8446 Section 7.1）

```cpp
[[nodiscard]] auto hkdf_expand_label(std::span<const std::uint8_t> secret,
                                     std::string_view label,
                                     std::span<const std::uint8_t> context,
                                     std::size_t length)
    -> std::pair<fault::code, std::vector<std::uint8_t>>;
```

TLS 1.3 密钥派生标准方法。内部构建 `HkdfLabel` 结构：

```
struct {
    uint16 length;                    // 大端序，期望输出长度
    opaque label<7..255>;             // "tls13 " + label
    opaque context<0..255>;           // 上下文数据
} HkdfLabel;
```

**自动前缀**: 函数自动在 label 前添加 `"tls13 "` 前缀。

**常用 TLS 1.3 标签**:

| 标签 | 用途 |
|------|------|
| `"key"` | 导出客户端/服务端流量密钥 |
| `"iv"` | 导出初始化向量 |
| `"finished"` | 导出 Finished 消息密钥 |
| `"c hs traffic"` | 客户端握手流量密钥 |
| `"s hs traffic"` | 服务端握手流量密钥 |
| `"c ap traffic"` | 客户端应用流量密钥 |
| `"s ap traffic"` | 服务端应用流量密钥 |

**限制**: label 总长度（含前缀）≤ 255 字节，context ≤ 255 字节。

#### 流式 SHA-256 重载

两块和三块版本的 `sha256` 使用 `EVP_MD_CTX` 流式 API，避免创建临时缓冲区拼接数据：

```cpp
// TLS 1.3 转录哈希：SHA-256(ClientHello || ServerHello)
auto transcript = psm::crypto::sha256(client_hello_bytes, server_hello_bytes);

// 多块流式处理
auto hash = psm::crypto::sha256(header, body, trailer);
```

#### 使用示例

```cpp
// TLS 1.3 密钥调度
auto [ec, client_key] = psm::crypto::hkdf_expand_label(
    handshake_secret,
    "key",
    client_handshake_traffic_hash,
    16  // AES-128 key size
);

if (psm::fault::failed(ec)) {
    // 处理错误
}
```

---

### 6. X25519（椭圆曲线密钥交换）

| 属性 | 值 |
|------|------|
| **源文件** | `include/prism/crypto/x25519.hpp` · `src/prism/crypto/x25519.cpp` |
| **底层** | BoringSSL `EVP_PKEY_X25519` / `curve25519.h` |
| **曲线** | Curve25519 |

**用途**: Reality 协议 ECDH 密钥交换。

#### 常量

| 常量 | 值 | 说明 |
|------|------|------|
| `X25519_KEY_LEN` | 32 | X25519 公私钥长度（字节） |
| `X25519_SHARED_LEN` | 32 | 共享密钥长度（字节） |
| `ED25519_KEY_LEN` | 32 | Ed25519 公钥长度 |
| `ED25519_PRIVATE_KEY_LEN` | 64 | Ed25519 私钥长度（种子 + 公钥） |

#### 数据结构

```cpp
struct x25519_keypair {
    std::array<std::uint8_t, 32> private_key;  // X25519 标量
    std::array<std::uint8_t, 32> public_key;   // Curve25519 点
};

struct ed25519_keypair {
    std::array<std::uint8_t, 64> private_key;  // 种子(32) + 公钥(32)
    std::array<std::uint8_t, 32> public_key;
};
```

#### `generate_x25519_keypair() -> x25519_keypair`

```cpp
[[nodiscard]] auto generate_x25519_keypair() -> x25519_keypair;
```

生成随机 X25519 密钥对：
1. `RAND_bytes()` 生成 32 字节随机私钥
2. `derive_x25519_public_key()` 从私钥推导公钥

#### `x25519(private_key, peer_public_key) -> pair<fault::code, shared_secret>`

```cpp
auto x25519(std::span<const std::uint8_t> private_key,
            std::span<const std::uint8_t> peer_public_key)
    -> std::pair<fault::code, std::array<std::uint8_t, 32>>;
```

执行 X25519 ECDH 密钥交换：`shared_secret = X25519(sk, pk_peer)`。

**实现步骤**:
1. `EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, ...)` — 从私钥创建 EVP_PKEY
2. `EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, ...)` — 从对端公钥创建 EVP_PKEY
3. `EVP_PKEY_CTX_new(local_pkey)` — 创建派生上下文
4. `EVP_PKEY_derive_set_peer(ctx, peer_pkey)` — 设置对端公钥
5. `EVP_PKEY_derive(ctx, shared_secret)` — 推导共享密钥

**错误码**:

| 错误码 | 触发条件 |
|--------|----------|
| `invalid_argument` | 密钥长度不是 32 字节 |
| `reality_key_exchange_failed` | EVP API 调用失败 |

**安全警告**: 调用者应检查输出是否全零（低阶点攻击防御）。Reality 协议在认证层处理此检查。

---

### 7. AES-ECB（单块加密）

| 属性 | 值 |
|------|------|
| **源文件** | `include/prism/crypto/block.hpp` · `src/prism/crypto/block.cpp` |
| **底层** | BoringSSL `EVP_CIPHER_CTX` |
| **限制** | 仅支持单块（16 字节） |
| **模式** | ECB（无填充） |

**用途**: ShadowTLS 流量伪装、SS2022 UDP SeparateHeader 加密。

> **警告**: ECB 模式对多块数据不安全。此实现故意限制为单块操作，仅用于需要确定性加密的场景。

#### `aes_ecb_encrypt(input, key) -> array[16]`

```cpp
[[nodiscard]] auto aes_ecb_encrypt(std::span<const std::uint8_t, 16> input,
                                   std::span<const std::uint8_t> key)
    -> std::array<std::uint8_t, 16>;
```

使用 AES-ECB 加密单个 16 字节块：
- 密钥 16 字节 → `AES-128-ECB`
- 密钥 32 字节 → `AES-256-ECB`
- 禁用填充：`EVP_CIPHER_CTX_set_padding(ctx, 0)`
- 失败返回全零数组

#### `aes_ecb_decrypt(input, key) -> array[16]`

解密单个 16 字节块，实现与加密对称。

#### 实现细节

```
EVP_CIPHER_CTX_new()
  → EVP_EncryptInit_ex(ctx, cipher, nullptr, key, nullptr)
  → EVP_CIPHER_CTX_set_padding(ctx, 0)  // 无填充
  → EVP_EncryptUpdate(ctx, out, &len, input, 16)
  → EVP_EncryptFinal_ex(ctx, out+len, &final_len)  // 单块无额外输出
  → EVP_CIPHER_CTX_free(ctx)
```

#### 使用示例

```cpp
// SS2022 UDP SeparateHeader 加密
std::array<std::uint8_t, 16> header = {/* ... */};
auto encrypted = psm::crypto::aes_ecb_encrypt(header, salt);
```

---

## 组件关系图

```
prism::crypto
│
├── SHA-224 ──────────────────────────→ Trojan 密码哈希
│   OpenSSL SHA224() + hex 编码
│
├── Base64 ───────────────────────────→ HTTP Basic Auth
│   RFC 4648 标准编码/解码
│
├── AEAD ─────────────────────────────→ SS2022 加密隧道 / TLS 1.3
│   ├── AES-128-GCM  ───┐
│   ├── AES-256-GCM  ───┤  BoringSSL EVP_AEAD_CTX
│   ├── ChaCha20-Poly ──┤  自动 nonce 递增（小端序）
│   └── XChaCha20-Poly ─┘  显式 nonce 重载（UDP 模式）
│
├── BLAKE3 ───────────────────────────→ SS2022 子密钥派生
│   derive_key 模式（域分离）
│   比 HKDF 快约 3 倍
│
├── HKDF ─────────────────────────────→ TLS 1.3 密钥调度 / Reality
│   ├── HMAC-SHA256/512
│   ├── HKDF-Extract（RFC 5869 Step 1）
│   ├── HKDF-Expand（RFC 5869 Step 2）
│   ├── HKDF-Expand-Label（RFC 8446 TLS 1.3）
│   └── 流式 SHA-256（2/3 块）
│
├── X25519 ───────────────────────────→ Reality ECDH 密钥交换
│   ├── generate_x25519_keypair()
│   ├── derive_x25519_public_key()
│   └── x25519 ECDH 共享密钥
│
└── AES-ECB ──────────────────────────→ ShadowTLS / SS2022 UDP
    仅单块 16 字节，ECB 模式
```

## 使用约定

1. **热路径不抛异常**: 所有操作返回 `fault::code`，不依赖异常处理
2. **内存安全**: AEAD 上下文使用 `unique_ptr` 管理，析构时自动清理敏感数据
3. **Nonce 管理**: AEAD 自动模式管理 nonce 状态，手动模式不修改内部状态
4. **缓冲区大小**: 使用 `seal_output_size`/`open_output_size` 静态方法计算所需大小
5. **启动要求**: 无特殊初始化要求（与 memory 模块不同，crypto 不需要全局初始化）

## 依赖

| 依赖 | 来源 | 用途 |
|------|------|------|
| **BoringSSL** | FetchContent（commit `beafe3db15`） | AES, ChaCha20, HMAC, SHA, X25519, EVP_AEAD |
| **BLAKE3** | FetchContent（v1.8.1） | BLAKE3 哈希和密钥派生 |

Windows 系统库: `ws2_32`, `mswsock`, `crypt32`（通过 CMake 自动链接）。
