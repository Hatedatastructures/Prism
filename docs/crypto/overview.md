# Crypto 模块文档

`psm::crypto` 命名空间封装 Prism 代理协议栈所需的全部密码学原语，隔离 BoringSSL/BLAKE3 C API，使协议层仅依赖类型安全的 C++ 接口。

---

## 子组件一览

| 组件 | 头文件 | 源文件 | 核心用途 |
|------|--------|--------|----------|
| SHA224 | [sha224.hpp](../../include/prism/crypto/sha224.hpp) | header-only | Trojan 凭据哈希 |
| Base64 | [base64.hpp](../../include/prism/crypto/base64.hpp) | header-only | PSK 解码、HTTP Basic 认证 |
| AEAD | [aead.hpp](../../include/prism/crypto/aead.hpp) | [aead.cpp](../../src/prism/crypto/aead.cpp) | SS2022 流加密、Reality session_id 解密 |
| BLAKE3 | [blake3.hpp](../../include/prism/crypto/blake3.hpp) | [blake3.cpp](../../src/prism/crypto/blake3.cpp) | SS2022 会话密钥派生 |
| Block | [block.hpp](../../include/prism/crypto/block.hpp) | [block.cpp](../../src/prism/crypto/block.cpp) | SS2022 UDP SeparateHeader 加密 |
| HKDF | [hkdf.hpp](../../include/prism/crypto/hkdf.hpp) | [hkdf.cpp](../../src/prism/crypto/hkdf.cpp) | Reality TLS 1.3 密钥调度 |
| X25519 | [x25519.hpp](../../include/prism/crypto/x25519.hpp) | [x25519.cpp](../../src/prism/crypto/x25519.cpp) | Reality ECDH 密钥交换 |

### 组件依赖关系

```
                +----------+
                |  SHA224  |        +----------+
                | (header) |        |  Base64  |
                +----+-----+        | (header) |
                     |              +----+-----+
                     v                   v
                Trojan 凭据        SS2022 PSK 解码 / HTTP Basic
                哈希验证

+----------+     +----------+     +----------+
|  BLAKE3  +---->|   AEAD   |<----+   HKDF   |
| (KDF)    |     | (stream  |     | (TLS 1.3 |
+----+-----+     |  cipher) |     |  KDF)    |
     |           +-----+----+     +----+-----+
     v                 v               v
SS2022 会话密钥    SS2022 分帧     Reality 密钥调度
派生 (derive_key)  加解密          (hkdf_expand_label)
                  Reality 认证
                  (显式 nonce)

+----------+     +----------+
|  Block   |     |  X25519  |
| (AES-ECB)|     | (ECDH)   |
+----+-----+     +----+-----+
     v                v
SS2022 UDP        Reality 认证
SeparateHeader    密钥交换
```

**关键依赖链**：

- SS2022 TCP：`Base64` -> `BLAKE3` -> `AEAD`
- SS2022 UDP：上述 + `Block`
- Reality 认证：`X25519` -> `HKDF` -> `AEAD`
- Reality TLS 1.3：`HKDF` -> `AEAD`
- Trojan 凭据：`SHA224`

---

## SHA224

Trojan 协议凭据哈希，输出 56 字符小写十六进制字符串。

```cpp
namespace psm::crypto {

/// 计算 SHA224 哈希，返回 56 字符小写十六进制字符串
[[nodiscard]] auto sha224(std::string_view input) -> std::string;

/// 检查字符串是否仅含十六进制字符
[[nodiscard]] auto is_hex_string(std::string_view str) -> bool;

/// 凭据规范化：56 字符十六进制串原样返回，否则计算 SHA224
[[nodiscard]] auto normalize_credential(std::string_view credential) -> std::string;

} // namespace psm::crypto
```

Trojan 握手头格式为 `<credential>\r\n<command>`，`normalize_credential` 允许配置文件中填写明文密码或哈希值，服务端统一转为哈希后比较。

安全注意：SHA224 仅用于凭据匹配，不用于密钥派生。生产环境建议直接填写哈希值避免明文泄露。

| 文件 | 说明 |
|------|------|
| [sha224.hpp](../../include/prism/crypto/sha224.hpp) | 全部实现（header-only），依赖 OpenSSL `SHA224()` |

---

## Base64

RFC 4648 Base64 编解码，用于 SS2022 PSK 配置解码和 HTTP Proxy Basic 认证头解析。

```cpp
namespace psm::crypto {

/// Base64 编码（含 padding）
[[nodiscard]] auto base64_encode(std::span<const std::uint8_t> input) -> std::string;

/// Base64 解码（自动忽略空白，支持 URL-safe 变体）
[[nodiscard]] auto base64_decode(std::string_view input) -> std::string;

} // namespace psm::crypto
```

| 场景 | 说明 |
|------|------|
| SS2022 PSK 解码 | `psk` 字段为 Base64 编码的 16/32 字节密钥 |
| HTTP Basic 认证 | 解析 `Proxy-Authorization: Basic <base64>` |
| Reality 密钥配置 | 解码 `private_key` 和 `short_id` |

实现使用 `constexpr` 解码查找表，零运行时开销。自动处理 URL-safe 变体和 padding。

| 文件 | 说明 |
|------|------|
| [base64.hpp](../../include/prism/crypto/base64.hpp) | 全部实现（header-only），无外部依赖 |

---

## AEAD

封装 BoringSSL `EVP_AEAD_CTX`，提供类型安全的 AEAD 加解密接口，管理 nonce 状态和密钥生命周期。

### 支持的算法

| 算法 | 枚举值 | 密钥长度 | Nonce 长度 | Tag 长度 |
|------|--------|----------|------------|----------|
| AES-128-GCM | `aead_cipher::aes_128_gcm` | 16 字节 | 12 字节 | 16 字节 |
| AES-256-GCM | `aead_cipher::aes_256_gcm` | 32 字节 | 12 字节 | 16 字节 |
| ChaCha20-Poly1305 | `aead_cipher::chacha20_poly1305` | 32 字节 | 12 字节 | 16 字节 |
| XChaCha20-Poly1305 | `aead_cipher::xchacha20_poly1305` | 32 字节 | 24 字节 | 16 字节 |

### 接口

```cpp
namespace psm::crypto {

class aead_context {
public:
    explicit aead_context(aead_cipher cipher, std::span<const std::uint8_t> key);
    ~aead_context();
    aead_context(const aead_context&) = delete;
    aead_context(aead_context&& other) noexcept;
    auto operator=(aead_context&& other) noexcept -> aead_context&;

    // 自动 nonce 版本（内部递增） -- SS2022 流加密
    auto seal(std::span<std::uint8_t> out,
              std::span<const std::uint8_t> plaintext,
              std::span<const std::uint8_t> ad = {}) -> fault::code;

    auto open(std::span<std::uint8_t> out,
              std::span<const std::uint8_t> ciphertext,
              std::span<const std::uint8_t> ad = {}) -> fault::code;

    // 显式 nonce 版本（不修改内部状态） -- Reality 认证 / TLS 1.3
    auto seal(std::span<std::uint8_t> out,
              std::span<const std::uint8_t> plaintext,
              std::span<const std::uint8_t> nonce,
              std::span<const std::uint8_t> ad) -> fault::code;

    auto open(std::span<std::uint8_t> out,
              std::span<const std::uint8_t> ciphertext,
              std::span<const std::uint8_t> nonce,
              std::span<const std::uint8_t> ad) -> fault::code;

    [[nodiscard]] auto key_length() const noexcept -> std::size_t;
    [[nodiscard]] static constexpr auto tag_length() noexcept -> std::size_t;  // 固定 16
    [[nodiscard]] auto nonce_length() const noexcept -> std::size_t;
    [[nodiscard]] auto nonce() const noexcept -> const std::array<std::uint8_t, 24>&;
    [[nodiscard]] static constexpr auto seal_output_size(std::size_t plaintext_len) noexcept -> std::size_t;
    [[nodiscard]] static constexpr auto open_output_size(std::size_t ciphertext_len) noexcept -> std::size_t;
};

[[nodiscard]] constexpr auto aead_key_length(aead_cipher cipher) noexcept -> std::size_t;

} // namespace psm::crypto
```

### Nonce 递增与两组重载

自动 nonce 版本内部维护 24 字节 nonce 缓冲区，每次 seal/open 后**小端序**递增（SS2022/SIP022 规范要求）。显式 nonce 版本由调用方传入 nonce，不修改内部状态，适用于 Reality TLS 1.3（nonce = `iv XOR sequence_number`）。

```
seal: plaintext[N] + ad[M] -> ciphertext[N+16]
open: ciphertext[N+16] + ad[M] -> plaintext[N]，失败返回 fault::code::crypto_error
```

`aead_context` 不可拷贝，可移动。析构时调用 `EVP_AEAD_CTX_cleanup` 清理敏感数据。

| 文件 | 说明 |
|------|------|
| [aead.hpp](../../include/prism/crypto/aead.hpp) | 类声明、算法枚举 |
| [aead.cpp](../../src/prism/crypto/aead.cpp) | BoringSSL EVP_AEAD 封装 |

---

## BLAKE3

BLAKE3 密钥派生，用于 SS2022 (SIP022) 会话密钥派生：PSK + salt -> AEAD key。

```cpp
namespace psm::crypto {

/// BLAKE3 密钥派生（输出到调用方缓冲区）
auto derive_key(std::string_view context,
                std::span<const std::uint8_t> material,
                std::size_t out_len,
                std::span<std::uint8_t> out) -> void;

/// BLAKE3 密钥派生（返回 vector）
[[nodiscard]] auto derive_key(std::string_view context,
                              std::span<const std::uint8_t> material,
                              std::size_t out_len) -> std::vector<std::uint8_t>;

} // namespace psm::crypto
```

### SS2022 密钥派生流程

```
material = PSK || salt
key = BLAKE3-derive-key(context="shadowsocks 2022 session subkey", key_material=material, output_length=len(PSK))
```

实现位置：[relay.cpp](../../src/prism/protocol/shadowsocks/relay.cpp) `relay::derive_aead_context()`。

函数命名为 `derive_key`（而非 `blake3_derive_key`）以避免与 BLAKE3 C API 命名冲突。

| 文件 | 说明 |
|------|------|
| [blake3.hpp](../../include/prism/crypto/blake3.hpp) | 函数声明 |
| [blake3.cpp](../../src/prism/crypto/blake3.cpp) | BLAKE3 C API 封装 |

---

## Block (AES-ECB)

AES-ECB 单块加解密，固定 16 字节输入输出。仅用于 SS2022 UDP SeparateHeader 加密（隐藏会话元数据）。

```cpp
namespace psm::crypto {

/// AES-ECB 单块加密（16 -> 16 字节）
[[nodiscard]] auto aes_ecb_encrypt(std::span<const std::uint8_t, 16> input,
                                   std::span<const std::uint8_t> key)
    -> std::array<std::uint8_t, 16>;

/// AES-ECB 单块解密（16 -> 16 字节）
[[nodiscard]] auto aes_ecb_decrypt(std::span<const std::uint8_t, 16> input,
                                   std::span<const std::uint8_t> key)
    -> std::array<std::uint8_t, 16>;

} // namespace psm::crypto
```

安全限制：ECB 模式不提供语义安全性，相同明文块产生相同密文，不提供认证。仅限 SS2022 UDP 规范明确要求的场景。根据密钥长度自动选择 AES-128/256-ECB，禁用 PKCS#7 填充。

| 文件 | 说明 |
|------|------|
| [block.hpp](../../include/prism/crypto/block.hpp) | 函数声明 |
| [block.cpp](../../src/prism/crypto/block.cpp) | BoringSSL EVP 封装 |

---

## HKDF

HKDF-SHA256（RFC 5869）及 TLS 1.3 专用的 `hkdf_expand_label`。Reality TLS 1.3 密钥调度的核心组件。

```cpp
namespace psm::crypto {

constexpr std::size_t SHA256_LEN = 32;
constexpr std::size_t SHA512_LEN = 64;

// 基础原语
[[nodiscard]] auto hmac_sha256(std::span<const std::uint8_t> key,
                               std::span<const std::uint8_t> data)
    -> std::array<std::uint8_t, SHA256_LEN>;

[[nodiscard]] auto hmac_sha512(std::span<const std::uint8_t> key,
                               std::span<const std::uint8_t> data)
    -> std::array<std::uint8_t, SHA512_LEN>;

[[nodiscard]] auto sha256(std::span<const std::uint8_t> data)
    -> std::array<std::uint8_t, SHA256_LEN>;
[[nodiscard]] auto sha256(std::span<const std::uint8_t> data1,
                          std::span<const std::uint8_t> data2)
    -> std::array<std::uint8_t, SHA256_LEN>;
[[nodiscard]] auto sha256(std::span<const std::uint8_t> data1,
                          std::span<const std::uint8_t> data2,
                          std::span<const std::uint8_t> data3)
    -> std::array<std::uint8_t, SHA256_LEN>;

// HKDF
[[nodiscard]] auto hkdf_extract(std::span<const std::uint8_t> salt,
                                std::span<const std::uint8_t> ikm)
    -> std::array<std::uint8_t, SHA256_LEN>;

[[nodiscard]] auto hkdf_expand(std::span<const std::uint8_t> prk,
                               std::span<const std::uint8_t> info,
                               std::size_t length)
    -> std::pair<fault::code, std::vector<std::uint8_t>>;

// TLS 1.3 专用
[[nodiscard]] auto hkdf_expand_label(std::span<const std::uint8_t> secret,
                                     std::string_view label,
                                     std::span<const std::uint8_t> context,
                                     std::size_t length)
    -> std::pair<fault::code, std::vector<std::uint8_t>>;

} // namespace psm::crypto
```

### hkdf_expand_label

构造 RFC 8446 Section 7.1 的 `HkdfLabel` 结构，自动添加 `"tls13 "` 前缀。Reality 密钥调度中使用的 label：

| Label | 输出长度 | 用途 |
|-------|----------|------|
| `"derived"` | 32 | 派生下一阶段 derived_secret |
| `"c hs traffic"` / `"s hs traffic"` | 32 | 客户端/服务端握手流量密钥 |
| `"key"` | 16 | AEAD 加密密钥 |
| `"iv"` | 12 | AEAD nonce 基础值 |
| `"finished"` | 32 | Finished 消息 verify_key |
| `"s ap traffic"` / `"c ap traffic"` | 32 | 服务端/客户端应用流量密钥 |

### sha256 多数据块重载

1/2/3 数据块拼接版本用于 TLS 1.3 transcript hash 计算，使用 `EVP_DigestUpdate` 分段输入避免额外内存分配。

### Reality 认证中的 HKDF 使用

```
salt = ClientHello.random[0:20], IKM = X25519 shared_secret
PRK = HKDF-Extract(salt, IKM)
auth_key = HKDF-Expand(PRK, "REALITY", 32)
```

| 文件 | 说明 |
|------|------|
| [hkdf.hpp](../../include/prism/crypto/hkdf.hpp) | 函数声明 |
| [hkdf.cpp](../../src/prism/crypto/hkdf.cpp) | BoringSSL HMAC/SHA256 实现 |

---

## X25519

Curve25519 ECDH 密钥交换（128 位安全强度），用于 Reality 协议密钥交换。同时提供 Ed25519 密钥对用于自签名证书签名。

```cpp
namespace psm::crypto {

constexpr std::size_t X25519_KEY_LEN = 32;
constexpr std::size_t X25519_SHARED_LEN = 32;
constexpr std::size_t ED25519_KEY_LEN = 32;
constexpr std::size_t ED25519_PRIVATE_KEY_LEN = 64;

struct x25519_keypair {
    std::array<std::uint8_t, X25519_KEY_LEN> private_key{};
    std::array<std::uint8_t, X25519_KEY_LEN> public_key{};
};

struct ed25519_keypair {
    std::array<std::uint8_t, ED25519_PRIVATE_KEY_LEN> private_key{};
    std::array<std::uint8_t, ED25519_KEY_LEN> public_key{};
};

[[nodiscard]] auto generate_x25519_keypair() -> x25519_keypair;
[[nodiscard]] auto derive_x25519_public_key(std::span<const std::uint8_t> private_key)
    -> std::array<std::uint8_t, X25519_KEY_LEN>;
auto x25519(std::span<const std::uint8_t> private_key,
            std::span<const std::uint8_t> peer_public_key)
    -> std::pair<fault::code, std::array<std::uint8_t, X25519_SHARED_LEN>>;

} // namespace psm::crypto
```

### Reality 协议中的两个使用点

1. **认证阶段**（[auth.cpp](../../src/prism/protocol/reality/auth.cpp)）：服务端长期私钥与客户端 key_share 公钥 ECDH -> 共享密钥 -> HKDF 派生 auth_key -> AES-256-GCM 解密 session_id
2. **TLS 1.3 密钥调度**（[keygen.cpp](../../src/prism/protocol/reality/keygen.cpp)）：临时密钥对（`generate_x25519_keypair`）用于 ECDHE，共享密钥作为 `hkdf_extract` 的 IKM

安全注意：X25519 对低阶公钥返回全零共享密钥，Reality 认证代码在 ECDH 后检查全零以拒绝低阶点攻击。每次握手生成全新临时密钥对，提供前向安全性。

| 文件 | 说明 |
|------|------|
| [x25519.hpp](../../include/prism/crypto/x25519.hpp) | 密钥对结构体、函数声明 |
| [x25519.cpp](../../src/prism/crypto/x25519.cpp) | BoringSSL EVP_PKEY 封装 |

---

## 消费方映射

```
协议模块                使用的 crypto 组件           关键调用点
─────────────────────────────────────────────────────────────────
Trojan                  SHA224                      credential 哈希验证
                        Base64                      HTTP Basic 认证头解析

SS2022 (TCP)            Base64                      PSK 解码 (format.cpp)
                        BLAKE3                      会话密钥派生 (relay.cpp)
                        AEAD                        流分帧加解密 (relay.cpp)
                            +-- 自动 nonce seal     数据写入
                            +-- 自动 nonce open     数据读取

SS2022 (UDP)            上述全部 + Block            SeparateHeader 加密

Reality (认证)          X25519                      ECDH 密钥交换 (auth.cpp)
                        HKDF                        auth_key 派生 (auth.cpp)
                        AEAD                        session_id AES-256-GCM 解密
                            +-- 显式 nonce open

Reality (TLS 1.3)       HKDF                        完整密钥调度 (keygen.cpp)
                            +-- hkdf_extract        握手/应用密钥
                            +-- hkdf_expand_label   label 派生
                            +-- sha256              transcript hash
                            +-- hmac_sha256         Finished verify_data
                        AEAD                        握手记录加解密
                            +-- 显式 nonce seal/open
```

### 典型数据流

**SS2022 TCP 连接**：

```
配置加载:  PSK (Base64) -> base64_decode() -> 16/32 字节原始密钥
握手阶段:  PSK || ClientSalt -> BLAKE3 derive_key -> AEAD key -> aead_context -> decrypt_ctx_
           密文 -> decrypt_ctx_.open() -> 明文（自动 nonce 递增）
响应:      ServerSalt -> BLAKE3 derive_key -> AEAD key -> encrypt_ctx_
数据传输:  读取: 18B 加密长度块 -> open() -> payloadLength -> payloadLength+16B -> open()
           写入: plaintext -> seal() -> 18B + payloadLen+16B
```

**Reality 握手**：

```
认证阶段:  x25519(服务端私钥, 客户端公钥) -> shared_secret
           hkdf_extract(ClientHello.random[0:20], shared_secret) -> PRK
           hkdf_expand(PRK, "REALITY", 32) -> auth_key
           aead_context(aes_256_gcm, auth_key).open(session_id, nonce=random[20:32]) -> 验证 short_id

TLS 1.3:   hkdf_extract/hkdf_expand_label 完整密钥调度
           AEAD seal/open 使用显式 nonce (iv XOR sequence_number)
```

---

## 设计要点

### 错误处理

| 场景 | 返回方式 | 说明 |
|------|----------|------|
| AEAD seal/open 失败 | `fault::code::crypto_error` | 密钥错误、密文损坏等 |
| HKDF 参数错误 | `fault::code::invalid_argument` | 长度超限、PRK 过短 |
| X25519 密钥交换失败 | `fault::code::reality_key_exchange_failed` | EVP API 错误 |
| X25519 参数错误 | `fault::code::invalid_argument` | 密钥长度不正确 |

返回 `std::pair<fault::code, ...>` 的函数（`hkdf_expand`、`hkdf_expand_label`、`x25519`）允许调用方无异常处理错误。

### 依赖隔离

头文件层（`include/prism/crypto/`）仅依赖 C++ 标准库和 `fault::code`，使用前向声明避免暴露 OpenSSL 类型。所有 BoringSSL/BLAKE3 的 `#include` 集中在 `src/prism/crypto/`，协议层不直接引用 OpenSSL 头文件。

### 测试

测试位于 `tests/Crypto` 测试目标，覆盖全部 7 个子组件的正确性和边界情况。
