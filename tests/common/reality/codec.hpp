/**
 * @file codec.hpp
 * @brief Reality 密钥工具与认证编解码（纯函数）
 * @details 对齐 mihomo component/tls/reality.go 与
 * C++ src/prism/handshake/reality/util/：
 *          - base64url 编解码（RFC 4648 无填充）
 *          - X25519 密钥对生成/派生
 *          - auth_key 派生：HKDF-Extract(random[:20], shared) +
 *            HKDF-Expand("REALITY", 32)
 *          - session_id seal/open：AES-256-GCM（nonce = random[20:32]，
 *            AAD = ClientHello raw 且 session_id 区清零）
 *          - 短 ID 解析
 * @note 参考 Reality 协议规范。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/reality/types.hpp>

#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace psmtest::reality
{

    /**
     * @brief base64url 编码（RFC 4648，无填充）
     * @param data 输入
     * @return base64url 字符串
     */
    [[nodiscard]] inline auto base64url_encode(std::span<const std::uint8_t> data) -> std::string
    {
        static constexpr char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string out;
        out.reserve((data.size() + 2) / 3 * 4);
        std::size_t i = 0;
        for (; i + 2 < data.size(); i += 3)
        {
            const auto n = static_cast<std::uint32_t>(data[i]) << 16 |
                           static_cast<std::uint32_t>(data[i + 1]) << 8 | data[i + 2];
            out.push_back(table[(n >> 18) & 0x3F]);
            out.push_back(table[(n >> 12) & 0x3F]);
            out.push_back(table[(n >> 6) & 0x3F]);
            out.push_back(table[n & 0x3F]);
        }
        if (i + 1 == data.size())
        {
            const auto n = static_cast<std::uint32_t>(data[i]) << 16;
            out.push_back(table[(n >> 18) & 0x3F]);
            out.push_back(table[(n >> 12) & 0x3F]);
        }
        else if (i + 2 == data.size())
        {
            const auto n = static_cast<std::uint32_t>(data[i]) << 16 |
                           static_cast<std::uint32_t>(data[i + 1]) << 8;
            out.push_back(table[(n >> 18) & 0x3F]);
            out.push_back(table[(n >> 12) & 0x3F]);
            out.push_back(table[(n >> 6) & 0x3F]);
        }
        return out;
    }

    /**
     * @brief base64url 解码（无填充，失败返回空）
     * @param s 输入
     * @return 解码字节
     */
    [[nodiscard]] inline auto base64url_decode(std::string_view s) -> std::vector<std::uint8_t>
    {
        auto val = [](char c) -> int
        {
            if (c >= 'A' && c <= 'Z')
                return c - 'A';
            if (c >= 'a' && c <= 'z')
                return c - 'a' + 26;
            if (c >= '0' && c <= '9')
                return c - '0' + 52;
            if (c == '-')
                return 62;
            if (c == '_')
                return 63;
            return -1;
        };
        std::vector<std::uint8_t> out;
        std::uint32_t acc = 0;
        int bits = 0;
        for (const char c : s)
        {
            const int v = val(c);
            if (v < 0)
                return {};
            acc = (acc << 6) | static_cast<std::uint32_t>(v);
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                out.push_back(static_cast<std::uint8_t>((acc >> bits) & 0xFF));
            }
        }
        return out;
    }

    /**
     * @brief 生成 X25519 密钥对（BoringSSL 原生 API）
     * @param priv 输出私钥（32 字节）
     * @param pub 输出公钥（32 字节）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto generate_keypair(std::array<std::uint8_t, key_len> &priv,
                                               std::array<std::uint8_t, key_len> &pub) -> bool
    {
        if (RAND_bytes(priv.data(), static_cast<int>(key_len)) != 1)
            return true;
        X25519_public_from_private(pub.data(), priv.data());
        return false;
    }

    /**
     * @brief 由私钥派生公钥（BoringSSL 原生 API）
     * @param priv 私钥（32 字节）
     * @param pub 输出公钥（32 字节）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto derive_public_key(std::span<const std::uint8_t> priv,
                                                std::array<std::uint8_t, key_len> &pub) -> bool
    {
        if (priv.size() != key_len)
            return true;
        X25519_public_from_private(pub.data(), priv.data());
        return false;
    }

    /**
     * @brief X25519 共享密钥（BoringSSL 原生 API）
     * @param priv 私钥（32 字节）
     * @param pub 公钥（32 字节）
     * @param out 输出共享密钥（32 字节）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto x25519_shared(std::span<const std::uint8_t> priv,
                                            std::span<const std::uint8_t> pub,
                                            std::array<std::uint8_t, key_len> &out) -> bool
    {
        if (priv.size() != key_len || pub.size() != key_len)
            return true;
        if (X25519(out.data(), priv.data(), pub.data()) != 1)
            return true;
        bool all_zero = true;
        for (const auto b : out)
        {
            if (b != 0)
            {
                all_zero = false;
                break;
            }
        }
        return all_zero;
    }

    /**
     * @brief 派生认证密钥（对齐 mihomo reality.go，HMAC 实现 HKDF）
     * @param shared_secret X25519 共享密钥（32 字节）
     * @param client_random 客户端随机数（40 字节：前 20 salt，后 12 nonce）
     * @param out 输出 32 字节 auth_key
     * @return 成功返回 false
     * @details HKDF-Extract(salt=random[:20], ikm=shared) +
     * HKDF-Expand(info="REALITY", 32)，用 HMAC-SHA256 实现
     * （BoringSSL 无 EVP_PKEY HKDF 上下文）。
     */
    [[nodiscard]] inline auto derive_auth_key(std::span<const std::uint8_t> shared_secret,
                                              std::span<const std::uint8_t> client_random,
                                              std::array<std::uint8_t, key_len> &out) -> bool
    {
        if (client_random.size() < 40)
            return true;
        auto hmac_sha256 = [](std::span<const std::uint8_t> key,
                              std::span<const std::uint8_t> data) -> std::array<std::uint8_t, 32>
        {
            std::array<std::uint8_t, 32> md{};
            unsigned int len = 0;
            HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
                 data.data(), data.size(), md.data(), &len);
            return md;
        };

        // HKDF-Extract: PRK = HMAC-SHA256(salt, ikm)
        const auto prk = hmac_sha256(client_random.first(20), shared_secret);

        // HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)，32 字节单块
        std::vector<std::uint8_t> info(sizeof(reality_info) - 1 + 1);
        std::memcpy(info.data(), reality_info, sizeof(reality_info) - 1);
        info.back() = 0x01;
        const auto okm = hmac_sha256(prk, info);
        std::memcpy(out.data(), okm.data(), key_len);
        return false;
    }

    /**
     * @brief seal session_id（客户端侧，对齐 mihomo reality.go）
     * @param auth_key 32 字节认证密钥
     * @param client_random 客户端随机数（40 字节，后 12 为 nonce）
     * @param plain 明文（16 字节：version + random + short_id + padding）
     * @param hello ClientHello 原始消息（AAD，session_id 区偏移 39 清零）
     * @param out 输出 32 字节密文（16 + tag 16）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto seal_session_id(std::span<const std::uint8_t> auth_key,
                                              std::span<const std::uint8_t> client_random,
                                              std::span<const std::uint8_t> plain,
                                              std::span<const std::uint8_t> hello,
                                              std::array<std::uint8_t, session_id_auth_len> &out)
        -> bool
    {
        if (plain.size() != 16 || client_random.size() < 40)
            return true;
        // AAD：hello 且 session_id 区（偏移 39 起 32 字节）清零
        std::vector<std::uint8_t> aad(hello.begin(), hello.end());
        if (aad.size() >= 39 + 32)
            std::memset(aad.data() + 39, 0, 32);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            return true;
        int len = 0;
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, auth_key.data(),
                           client_random.data() + 20);
        EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size()));
        EVP_EncryptUpdate(ctx, out.data(), &len, plain.data(), static_cast<int>(plain.size()));
        int out_len = len;
        EVP_EncryptFinal_ex(ctx, out.data() + out_len, &len);
        out_len += len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + out_len);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    /**
     * @brief open session_id（服务端侧）
     * @param auth_key 32 字节认证密钥
     * @param client_random 客户端随机数（40 字节，后 12 为 nonce）
     * @param cipher 32 字节密文（16 + tag 16）
     * @param hello ClientHello 原始消息（AAD）
     * @param out 输出 16 字节明文
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto open_session_id(std::span<const std::uint8_t> auth_key,
                                              std::span<const std::uint8_t> client_random,
                                              std::span<const std::uint8_t> cipher,
                                              std::span<const std::uint8_t> hello,
                                              std::array<std::uint8_t, 16> &out) -> bool
    {
        if (cipher.size() != session_id_auth_len || client_random.size() < 40)
            return true;
        std::vector<std::uint8_t> aad(hello.begin(), hello.end());
        if (aad.size() >= 39 + 32)
            std::memset(aad.data() + 39, 0, 32);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            return true;
        int len = 0;
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, auth_key.data(),
                           client_random.data() + 20);
        EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size()));
        EVP_DecryptUpdate(ctx, out.data(), &len, cipher.data(), 16);
        int out_len = len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                            const_cast<std::uint8_t *>(cipher.data()) + 16);
        const auto ok = EVP_DecryptFinal_ex(ctx, out.data() + out_len, &len);
        EVP_CIPHER_CTX_free(ctx);
        return ok != 1;
    }

    /**
     * @brief 解析 base64url 私钥
     * @param encoded base64url 字符串
     * @param out 输出私钥（32 字节）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto parse_private_key(std::string_view encoded,
                                                std::array<std::uint8_t, key_len> &out) -> bool
    {
        const auto raw = base64url_decode(encoded);
        if (raw.size() != key_len)
            return true;
        std::copy(raw.begin(), raw.end(), out.begin());
        return false;
    }

    /**
     * @brief 编码公钥为 base64url
     * @param pub 公钥（32 字节）
     * @return base64url 字符串
     */
    [[nodiscard]] inline auto encode_public_key(std::span<const std::uint8_t> pub) -> std::string
    {
        return base64url_encode(pub);
    }

    /**
     * @brief 解析 16 进制短 ID（最多 8 字节）
     * @param hex 16 进制字符串
     * @param out 输出短 ID（8 字节，不足补 0）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto parse_short_id(std::string_view hex,
                                             std::array<std::uint8_t, max_short_id_len> &out)
        -> bool
    {
        if (hex.empty() || hex.size() > 16 || hex.size() % 2 != 0)
            return true;
        auto nibble = [](char c) -> int
        {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return -1;
        };
        std::size_t pos = 0;
        for (std::size_t i = 0; i < hex.size(); i += 2)
        {
            const int hi = nibble(hex[i]);
            const int lo = nibble(hex[i + 1]);
            if (hi < 0 || lo < 0)
                return true;
            out[pos++] = static_cast<std::uint8_t>((hi << 4) | lo);
        }
        return false;
    }

} // namespace psmtest::reality
