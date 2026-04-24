# Crypto 模块

**源码位置**: `include/prism/crypto/`

加密算法组件，header-only + BoringSSL 绑定。

## 组件

| 组件 | 说明 |
|------|------|
| **SHA224** | Trojan 密码哈希 |
| **Base64** | SS2022 PSK 解码 |
| **AEAD** | AES-GCM / ChaCha20-Poly1305 加解密 |
| **BLAKE3** | SS2022 密钥派生（HKDF） |
| **HKDF** | 通用密钥派生 |
| **X25519** | Reality 密钥交换 |

## 依赖

BoringSSL（通过 FetchContent 自动拉取编译）。
