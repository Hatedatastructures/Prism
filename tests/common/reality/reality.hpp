/**
 * @file reality.hpp
 * @brief Reality 伪装方案密钥工具（纯逻辑）
 * @details 实现 X25519 密钥对生成/派生、base64url 编解码、
 *          短 ID 解析等 Reality 方案基础工具。
 * @note 参考 Reality 协议规范与 mihomo transport/reality。
 */

#pragma once

#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace psmtest::reality
{

    /// 密钥长度（X25519 32 字节）
    inline constexpr std::size_t key_len = 32;

    /// @brief base64url 编码（RFC 4648，无填充）
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

    /// @brief base64url 解码（无填充，失败返回空）
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

    /// @brief 生成 X25519 密钥对
    /// @param priv 输出私钥（32 字节）
    /// @param pub 输出公钥（32 字节）
    /// @return 成功返回 false（对齐测试断言习惯）
    [[nodiscard]] inline auto generate_keypair(std::array<std::uint8_t, key_len> &priv,
                                               std::array<std::uint8_t, key_len> &pub) -> bool
    {
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        if (!ctx)
            return true;
        EVP_PKEY *pkey = nullptr;
        if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0)
        {
            EVP_PKEY_CTX_free(ctx);
            return true;
        }
        std::size_t priv_len = key_len, pub_len = key_len;
        EVP_PKEY_get_raw_private_key(pkey, priv.data(), &priv_len);
        EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pub_len);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    /// @brief 由私钥派生公钥
    /// @param priv 私钥（32 字节）
    /// @param pub 输出公钥（32 字节）
    /// @return 成功返回 false
    [[nodiscard]] inline auto derive_public_key(std::span<const std::uint8_t> priv,
                                                std::array<std::uint8_t, key_len> &pub) -> bool
    {
        EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                      priv.data(), priv.size());
        if (!pkey)
            return true;
        std::size_t pub_len = key_len;
        const auto ok = EVP_PKEY_get_raw_public_key(pkey, pub.data(), &pub_len) > 0;
        EVP_PKEY_free(pkey);
        return !ok;
    }

    /// @brief 解析 base64url 私钥
    /// @param encoded base64url 字符串
    /// @param out 输出私钥（32 字节）
    /// @return 成功返回 false
    [[nodiscard]] inline auto parse_private_key(std::string_view encoded,
                                                std::array<std::uint8_t, key_len> &out) -> bool
    {
        const auto raw = base64url_decode(encoded);
        if (raw.size() != key_len)
            return true;
        std::copy(raw.begin(), raw.end(), out.begin());
        return false;
    }

    /// @brief 编码公钥为 base64url
    [[nodiscard]] inline auto encode_public_key(std::span<const std::uint8_t> pub) -> std::string
    {
        return base64url_encode(pub);
    }

    /// @brief 解析 16 进制短 ID（最多 8 字节）
    /// @param hex 16 进制字符串
    /// @param out 输出短 ID（8 字节，不足补 0）
    /// @return 成功返回 false
    [[nodiscard]] inline auto parse_short_id(std::string_view hex,
                                             std::array<std::uint8_t, 8> &out) -> bool
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
