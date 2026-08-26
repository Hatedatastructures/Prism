/**
 * @file Codec.hpp
 * @brief Reality 密钥工具与认证编解码（纯函数）
 * @details 对齐 mihomo component/tls/reality.go 与
 * C++ src/prism/handshake/reality/util/：
 *          - base64url 编解码（RFC 4648 无填充）
 *          - X25519 密钥对生成/派生
 *          - AuthKey 派生：HKDF-Extract(random[:20], shared) +
 *            HKDF-Expand("REALITY", 32)
 *          - SessionId Seal/Open：AES-256-GCM（Nonce = random[20:32]，
 *            AAD = ClientHello raw 且 SessionId 区清零）
 *          - 短 ID 解析
 * @note 参考 Reality 协议规范。
 */

#pragma once

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

#include <common/Core/Error.hpp>
#include <common/Protocols/Reality/Types.hpp>

namespace Preview::Reality
{

    /**
     * @brief base64url 编码（RFC 4648，无填充）
     * @param Data 输入
     * @return base64url 字符串
     */
    [[nodiscard]] inline auto Base64urlEncode(std::span<const std::uint8_t> Data) -> std::string
    {
        static constexpr char Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string out;
        out.reserve((Data.size() + 2) / 3 * 4);
        std::size_t I = 0;
        for (; I + 2 < Data.size(); I += 3)
        {
            const auto N = static_cast<std::uint32_t>(Data[I]) << 16 |
                           static_cast<std::uint32_t>(Data[I + 1]) << 8 | Data[I + 2];
            out.push_back(Table[(N >> 18) & 0x3F]);
            out.push_back(Table[(N >> 12) & 0x3F]);
            out.push_back(Table[(N >> 6) & 0x3F]);
            out.push_back(Table[N & 0x3F]);
        }
        if (I + 1 == Data.size())
        {
            const auto N = static_cast<std::uint32_t>(Data[I]) << 16;
            out.push_back(Table[(N >> 18) & 0x3F]);
            out.push_back(Table[(N >> 12) & 0x3F]);
        }
        else if (I + 2 == Data.size())
        {
            const auto N = static_cast<std::uint32_t>(Data[I]) << 16 | static_cast<std::uint32_t>(Data[I + 1])
                                                                           << 8;
            out.push_back(Table[(N >> 18) & 0x3F]);
            out.push_back(Table[(N >> 12) & 0x3F]);
            out.push_back(Table[(N >> 6) & 0x3F]);
        }
        return out;
    }

    /**
     * @brief base64url 解码（无填充，失败返回空）
     * @param s 输入
     * @return 解码字节
     */
    [[nodiscard]] inline auto Base64urlDecode(std::string_view s) -> std::vector<std::uint8_t>
    {
        auto Val = [](char c) -> int
        {
            if (c >= 'A' && c <= 'Z')
            {
                return c - 'A';
            }
            if (c >= 'a' && c <= 'z')
            {
                return c - 'a' + 26;
            }
            if (c >= '0' && c <= '9')
            {
                return c - '0' + 52;
            }
            if (c == '-')
            {
                return 62;
            }
            if (c == '_')
            {
                return 63;
            }
            return -1;
        };
        std::vector<std::uint8_t> out;
        std::uint32_t Acc = 0;
        int Bits = 0;
        for (const char c : s)
        {
            const int V = Val(c);
            if (V < 0)
            {
                return {};
            }
            Acc = (Acc << 6) | static_cast<std::uint32_t>(V);
            Bits += 6;
            if (Bits >= 8)
            {
                Bits -= 8;
                out.push_back(static_cast<std::uint8_t>((Acc >> Bits) & 0xFF));
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
    [[nodiscard]] inline auto GenerateKeypair(std::array<std::uint8_t, KeyLen> &priv,
                                               std::array<std::uint8_t, KeyLen> &pub) -> bool
    {
        if (RAND_bytes(priv.data(), static_cast<int>(KeyLen)) != 1)
        {
            return true;
        }
        X25519_public_from_private(pub.data(), priv.data());
        return false;
    }

    /**
     * @brief 由私钥派生公钥（BoringSSL 原生 API）
     * @param priv 私钥（32 字节）
     * @param pub 输出公钥（32 字节）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto DerivePublicKey(std::span<const std::uint8_t> priv,
                                                std::array<std::uint8_t, KeyLen> &pub) -> bool
    {
        if (priv.size() != KeyLen)
        {
            return true;
        }
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
    [[nodiscard]] inline auto X25519Shared(std::span<const std::uint8_t> priv,
                                            std::span<const std::uint8_t> pub,
                                            std::array<std::uint8_t, KeyLen> &out) -> bool
    {
        if (priv.size() != KeyLen || pub.size() != KeyLen)
        {
            return true;
        }
        if (X25519(out.data(), priv.data(), pub.data()) != 1)
        {
            return true;
        }
        bool AllZero = true;
        for (const auto b : out)
        {
            if (b != 0)
            {
                AllZero = false;
                break;
            }
        }
        return AllZero;
    }

    /**
     * @brief 派生认证密钥（对齐 mihomo reality.go，HMAC 实现 HKDF）
     * @param SharedSecret X25519 共享密钥（32 字节）
     * @param ClientRandom 客户端随机数（40 字节：前 20 salt，后 12 Nonce）
     * @param out 输出 32 字节 AuthKey
     * @return 成功返回 false
     * @details HKDF-Extract(salt=random[:20], ikm=shared) +
     * HKDF-Expand(Info="REALITY", 32)，用 HMAC-SHA256 实现
     * （BoringSSL 无 EVP_PKEY HKDF 上下文）。
     */
    [[nodiscard]] inline auto DeriveAuthKey(std::span<const std::uint8_t> SharedSecret,
                                              std::span<const std::uint8_t> ClientRandom,
                                              std::array<std::uint8_t, KeyLen> &out) -> bool
    {
        if (ClientRandom.size() < 40)
        {
            return true;
        }
        auto HmacSha256 = [](std::span<const std::uint8_t> key,
                              std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, 32>
        {
            std::array<std::uint8_t, 32> md{};
            unsigned int Len = 0;
            HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), Data.data(), Data.size(), md.data(),
                 &Len);
            return md;
        };

        // HKDF-Extract: PRK = HMAC-SHA256(salt, ikm)
        const auto Prk = HmacSha256(ClientRandom.first(20), SharedSecret);

        // HKDF-Expand: OKM = HMAC-SHA256(PRK, Info || 0x01)，32 字节单块
        std::vector<std::uint8_t> Info(sizeof(RealityInfo) - 1 + 1);
        std::memcpy(Info.data(), RealityInfo, sizeof(RealityInfo) - 1);
        Info.back() = 0x01;
        const auto Okm = HmacSha256(Prk, Info);
        std::memcpy(out.data(), Okm.data(), KeyLen);
        return false;
    }

    /**
     * @brief Seal SessionId（客户端侧，对齐 mihomo reality.go）
     * @param AuthKey 32 字节认证密钥
     * @param ClientRandom 客户端随机数（40 字节，后 12 为 Nonce）
     * @param plain 明文（16 字节：version + random + ShortId + padding）
     * @param hello ClientHello 原始消息（AAD，SessionId 区偏移 39 清零）
     * @param out 输出 32 字节密文（16 + tag 16）
     * @return 成功返回 false
     */
    /// SessionId 密封输入（AuthKey + random + hello）
    struct SessionIdSealInput
    {
        std::span<const std::uint8_t> AuthKey;      ///< 32 字节认证密钥
        std::span<const std::uint8_t> ClientRandom; ///< 客户端随机数（40 字节）
        std::span<const std::uint8_t> plain;         ///< 明文（16 字节）
        std::span<const std::uint8_t> hello;         ///< ClientHello 原始消息（AAD）
    };

    /// SessionId 解析输入（AuthKey + random + hello）
    struct SessionIdOpenInput
    {
        std::span<const std::uint8_t> AuthKey;      ///< 32 字节认证密钥
        std::span<const std::uint8_t> ClientRandom; ///< 客户端随机数（40 字节）
        std::span<const std::uint8_t> cipher;        ///< 32 字节密文（16 + tag 16）
        std::span<const std::uint8_t> hello;         ///< ClientHello 原始消息（AAD）
    };

    /**
     * @brief Seal SessionId（客户端侧，对齐 mihomo reality.go）
     * @param in 密封输入
     * @param out 输出 32 字节密文（16 + tag 16）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto SealSessionId(const SessionIdSealInput &in,
                                              std::array<std::uint8_t, SessionIdAuthLen> &out) -> bool
    {
        if (in.plain.size() != 16 || in.ClientRandom.size() < 40)
        {
            return true;
        }
        // AAD：hello 且 SessionId 区（偏移 39 起 32 字节）清零
        std::vector<std::uint8_t> aad(in.hello.begin(), in.hello.end());
        if (aad.size() >= 39 + 32)
        {
            std::memset(aad.data() + 39, 0, 32);
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            return true;
        }
        int Len = 0;
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, in.AuthKey.data(), in.ClientRandom.data() + 20);
        EVP_EncryptUpdate(ctx, nullptr, &Len, aad.data(), static_cast<int>(aad.size()));
        EVP_EncryptUpdate(ctx, out.data(), &Len, in.plain.data(), static_cast<int>(in.plain.size()));
        int OutLen = Len;
        EVP_EncryptFinal_ex(ctx, out.data() + OutLen, &Len);
        OutLen += Len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + OutLen);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    /**
     * @brief Open SessionId（服务端侧）
     * @param in 解析输入
     * @param out 输出 16 字节明文
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto OpenSessionId(const SessionIdOpenInput &in,
                                              std::array<std::uint8_t, 16> &out) -> bool
    {
        if (in.cipher.size() != SessionIdAuthLen || in.ClientRandom.size() < 40)
        {
            return true;
        }
        std::vector<std::uint8_t> aad(in.hello.begin(), in.hello.end());
        if (aad.size() >= 39 + 32)
        {
            std::memset(aad.data() + 39, 0, 32);
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            return true;
        }
        int Len = 0;
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, in.AuthKey.data(), in.ClientRandom.data() + 20);
        EVP_DecryptUpdate(ctx, nullptr, &Len, aad.data(), static_cast<int>(aad.size()));
        EVP_DecryptUpdate(ctx, out.data(), &Len, in.cipher.data(), 16);
        int OutLen = Len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<std::uint8_t *>(in.cipher.data()) + 16);
        const auto Ok = EVP_DecryptFinal_ex(ctx, out.data() + OutLen, &Len);
        EVP_CIPHER_CTX_free(ctx);
        return Ok != 1;
    }

    /**
     * @brief 解析 base64url 私钥
     * @param encoded base64url 字符串
     * @param out 输出私钥（32 字节）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto ParsePrivateKey(std::string_view encoded,
                                                std::array<std::uint8_t, KeyLen> &out) -> bool
    {
        const auto Raw = Base64urlDecode(encoded);
        if (Raw.size() != KeyLen)
        {
            return true;
        }
        std::copy(Raw.begin(), Raw.end(), out.begin());
        return false;
    }

    /**
     * @brief 编码公钥为 base64url
     * @param pub 公钥（32 字节）
     * @return base64url 字符串
     */
    [[nodiscard]] inline auto EncodePublicKey(std::span<const std::uint8_t> pub) -> std::string
    {
        return Base64urlEncode(pub);
    }

    /**
     * @brief 解析 16 进制短 ID（最多 8 字节）
     * @param hex 16 进制字符串
     * @param out 输出短 ID（8 字节，不足补 0）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto ParseShortId(std::string_view hex,
                                             std::array<std::uint8_t, MaxShortIdLen> &out) -> bool
    {
        if (hex.empty() || hex.size() > 16 || hex.size() % 2 != 0)
        {
            return true;
        }
        auto Nibble = [](char c) -> int
        {
            if (c >= '0' && c <= '9')
            {
                return c - '0';
            }
            if (c >= 'a' && c <= 'f')
            {
                return c - 'a' + 10;
            }
            if (c >= 'A' && c <= 'F')
            {
                return c - 'A' + 10;
            }
            return -1;
        };
        std::size_t Pos = 0;
        for (std::size_t I = 0; I < hex.size(); I += 2)
        {
            const int Hi = Nibble(hex[I]);
            const int Lo = Nibble(hex[I + 1]);
            if (Hi < 0 || Lo < 0)
            {
                return true;
            }
            out[Pos++] = static_cast<std::uint8_t>((Hi << 4) | Lo);
        }
        return false;
    }

} // namespace Preview::Reality
