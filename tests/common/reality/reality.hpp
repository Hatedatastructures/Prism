/**
 * @file reality.hpp
 * @brief Reality 密钥原语（客户端 + 服务端）
 * @details 纯逻辑（无锁）：
 *          1. base64url（无填充）编解码——Reality 公钥/私钥格式
 *          2. X25519 密钥对生成与公钥派生
 *          3. Short ID 十六进制编解码
 *          命名空间 psm_test::reality，参考 mihomo listener/reality。
 */

#pragma once

#include <common/common.hpp>

#include <openssl/evp.h>

namespace psm_test::reality
{

    inline constexpr std::size_t key_len = 32;

    /// base64url（RFC 4648，无填充）
    [[nodiscard]] inline auto base64url_encode(const view data) -> std::string
    {
        static constexpr char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string out;
        out.reserve((data.size() + 2) / 3 * 4);
        std::size_t i = 0;
        for (; i + 2 < data.size(); i += 3)
        {
            const auto n = static_cast<std::uint32_t>(data[i]) << 16
                | static_cast<std::uint32_t>(data[i + 1]) << 8 | data[i + 2];
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
            const auto n = static_cast<std::uint32_t>(data[i]) << 16
                | static_cast<std::uint32_t>(data[i + 1]) << 8;
            out.push_back(table[(n >> 18) & 0x3F]);
            out.push_back(table[(n >> 12) & 0x3F]);
            out.push_back(table[(n >> 6) & 0x3F]);
        }
        return out;
    }

    /// base64url 解码（无填充，失败返回空）
    [[nodiscard]] inline auto base64url_decode(const std::string_view s) -> buffer
    {
        auto val = [](const char c) -> int
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
        buffer out;
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

    /// 生成 X25519 密钥对：返回 {私钥 32B, 公钥 32B}
    [[nodiscard]] inline auto generate_keypair() -> std::pair<std::array<std::uint8_t, key_len>,
                                                              std::array<std::uint8_t, key_len>>
    {
        std::array<std::uint8_t, key_len> priv{};
        std::array<std::uint8_t, key_len> pub{};
        for (auto &b : priv)
            b = static_cast<std::uint8_t>(std::rand() & 0xFF);

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        if (!ctx)
            return {};
        EVP_PKEY *pkey = nullptr;
        if (EVP_PKEY_keygen_init(ctx) > 0 && EVP_PKEY_keygen(ctx, &pkey) > 0)
        {
            // 覆盖随机私钥：用生成的密钥对
            std::size_t len = key_len;
            EVP_PKEY_get_raw_private_key(pkey, priv.data(), &len);
            len = key_len;
            EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len);
            EVP_PKEY_free(pkey);
        }
        EVP_PKEY_CTX_free(ctx);
        return {priv, pub};
    }

    /// 从私钥派生 X25519 公钥（成功返回 true，输出到 pub）
    [[nodiscard]] inline auto derive_public_key(const std::span<const std::uint8_t> priv,
                                                std::span<std::uint8_t> pub) -> bool
    {
        if (priv.size() != key_len || pub.size() < key_len)
            return false;
        EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), key_len);
        if (!pkey)
            return false;
        std::size_t len = key_len;
        const auto ok = EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) > 0;
        EVP_PKEY_free(pkey);
        return ok && len == key_len;
    }

    /// 解析配置私钥（base64url 32 字节 → 校验长度）
    [[nodiscard]] inline auto parse_private_key(const std::string_view encoded) -> buffer
    {
        auto key = base64url_decode(encoded);
        if (key.size() != key_len)
            return {};
        return key;
    }

    /// 编码公钥（base64url）
    [[nodiscard]] inline auto encode_public_key(const std::span<const std::uint8_t> pub) -> std::string
    {
        return base64url_encode(pub);
    }

    /// Short ID 十六进制 → 8 字节（不足填 0）
    [[nodiscard]] inline auto parse_short_id(const std::string_view hex) -> std::array<std::uint8_t, 8>
    {
        std::array<std::uint8_t, 8> out{};
        std::size_t n = 0;
        bool hi = true;
        std::uint8_t nibble = 0;
        for (const char c : hex)
        {
            if (n >= 8)
                break;
            std::uint8_t d = 0;
            if (c >= '0' && c <= '9')
                d = static_cast<std::uint8_t>(c - '0');
            else if (c >= 'a' && c <= 'f')
                d = static_cast<std::uint8_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                d = static_cast<std::uint8_t>(c - 'A' + 10);
            else
                continue;
            if (hi)
            {
                nibble = static_cast<std::uint8_t>(d << 4);
                hi = false;
            }
            else
            {
                out[n++] = static_cast<std::uint8_t>(nibble | d);
                hi = true;
            }
        }
        return out;
    }

} // namespace psm_test::reality
