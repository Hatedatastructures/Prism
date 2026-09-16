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
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Reality/Types.hpp>

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
        std::string Output;
        Output.reserve((Data.size() + 2) / 3 * 4);
        std::size_t I = 0;
        for (; I + 2 < Data.size(); I += 3)
        {
            const auto N = static_cast<std::uint32_t>(Data[I]) << 16 |
                           static_cast<std::uint32_t>(Data[I + 1]) << 8 | Data[I + 2];
            Output.push_back(Table[(N >> 18) & 0x3F]);
            Output.push_back(Table[(N >> 12) & 0x3F]);
            Output.push_back(Table[(N >> 6) & 0x3F]);
            Output.push_back(Table[N & 0x3F]);
        }
        if (I + 1 == Data.size())
        {
            const auto N = static_cast<std::uint32_t>(Data[I]) << 16;
            Output.push_back(Table[(N >> 18) & 0x3F]);
            Output.push_back(Table[(N >> 12) & 0x3F]);
        }
        else if (I + 2 == Data.size())
        {
            const auto N = static_cast<std::uint32_t>(Data[I]) << 16 | static_cast<std::uint32_t>(Data[I + 1])
                                                                           << 8;
            Output.push_back(Table[(N >> 18) & 0x3F]);
            Output.push_back(Table[(N >> 12) & 0x3F]);
            Output.push_back(Table[(N >> 6) & 0x3F]);
        }
        return Output;
    }

    /**
     * @brief base64url 解码（无填充，失败返回空）
     * @param Input 输入
     * @return 解码字节
     */
    [[nodiscard]] inline auto Base64urlDecode(std::string_view Input) -> std::vector<std::uint8_t>
    {
        auto ValueOf = [](const char Character) -> int
        {
            if (Character >= 'A' && Character <= 'Z')
            {
                return Character - 'A';
            }
            if (Character >= 'a' && Character <= 'z')
            {
                return Character - 'a' + 26;
            }
            if (Character >= '0' && Character <= '9')
            {
                return Character - '0' + 52;
            }
            if (Character == '-')
            {
                return 62;
            }
            if (Character == '_')
            {
                return 63;
            }
            return -1;
        };
        if (Input.size() % 4 == 1)
        {
            return {};
        }
        std::vector<std::uint8_t> Output;
        std::uint32_t Acc = 0;
        int Bits = 0;
        for (const char Character : Input)
        {
            const int Value = ValueOf(Character);
            if (Value < 0)
            {
                return {};
            }
            Acc = (Acc << 6) | static_cast<std::uint32_t>(Value);
            Bits += 6;
            if (Bits >= 8)
            {
                Bits -= 8;
                Output.push_back(static_cast<std::uint8_t>((Acc >> Bits) & 0xFF));
                if (Bits == 0)
                {
                    Acc = 0;
                }
                else
                {
                    Acc &= (std::uint32_t{1} << Bits) - 1;
                }
            }
        }
        if (Bits != 0 && (Acc & ((std::uint32_t{1} << Bits) - 1)) != 0)
        {
            return {};
        }
        return Output;
    }

    /**
     * @brief 生成 X25519 密钥对（BoringSSL 原生 API）
     * @param PrivateKey 输出私钥（32 字节）
     * @param PublicKey 输出公钥（32 字节）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto GenerateKeypair(
        std::array<std::uint8_t, KeyLen> &PrivateKey,
        std::array<std::uint8_t, KeyLen> &PublicKey) -> bool
    {
        PrivateKey.fill(0);
        PublicKey.fill(0);
        if (RAND_bytes(PrivateKey.data(), static_cast<int>(KeyLen)) != 1)
        {
            return true;
        }
        X25519_public_from_private(PublicKey.data(), PrivateKey.data());
        return false;
    }

    /**
     * @brief 由私钥派生公钥（BoringSSL 原生 API）
     * @param PrivateKey 私钥（32 字节）
     * @param PublicKey 输出公钥（32 字节）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto DerivePublicKey(
        std::span<const std::uint8_t> PrivateKey,
        std::array<std::uint8_t, KeyLen> &PublicKey) -> bool
    {
        if (PrivateKey.size() != KeyLen)
        {
            return true;
        }
        X25519_public_from_private(PublicKey.data(), PrivateKey.data());
        return false;
    }

    /**
     * @brief X25519 共享密钥（BoringSSL 原生 API）
     * @param PrivateKey 私钥（32 字节）
     * @param PublicKey 公钥（32 字节）
     * @param Output 输出共享密钥（32 字节）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto X25519Shared(
        std::span<const std::uint8_t> PrivateKey,
        std::span<const std::uint8_t> PublicKey,
        std::array<std::uint8_t, KeyLen> &Output) -> bool
    {
        Output.fill(0);
        if (PrivateKey.size() != KeyLen || PublicKey.size() != KeyLen)
        {
            return true;
        }
        if (X25519(Output.data(), PrivateKey.data(), PublicKey.data()) != 1)
        {
            return true;
        }
        bool AllZero = true;
        for (const auto Byte : Output)
        {
            if (Byte != 0)
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
     * @param ClientRandom TLS ClientRandom（32 字节：前 20 salt，后 12 Nonce）
     * @param Output 输出 32 字节 AuthKey
     * @return 成功返回 false
     * @details HKDF-Extract(salt=random[:20], ikm=shared) +
     * HKDF-Expand(Info="REALITY", 32)，用 HMAC-SHA256 实现
     * （BoringSSL 无 EVP_PKEY HKDF 上下文）。
     */
    [[nodiscard]] inline auto DeriveAuthKey(std::span<const std::uint8_t> SharedSecret,
                                              std::span<const std::uint8_t> ClientRandom,
                                              std::array<std::uint8_t, KeyLen> &Output) -> bool
    {
        Output.fill(0);
        if (SharedSecret.size() != KeyLen || ClientRandom.size() != 32)
        {
            return true;
        }
        auto HmacSha256 = [](std::span<const std::uint8_t> Key,
                              std::span<const std::uint8_t> Data,
                              std::array<std::uint8_t, 32> &Digest) -> bool
        {
            unsigned int Len = 0;
            const auto *Result = HMAC(
                EVP_sha256(),
                Key.data(),
                static_cast<int>(Key.size()),
                Data.data(),
                Data.size(),
                Digest.data(),
                &Len);
            return Result != nullptr && Len == Digest.size();
        };

        // HKDF-Extract: PRK = HMAC-SHA256(salt, ikm)
        std::array<std::uint8_t, 32> Prk{};
        if (!HmacSha256(ClientRandom.first(20), SharedSecret, Prk))
        {
            return true;
        }

        // HKDF-Expand: OKM = HMAC-SHA256(PRK, Info || 0x01)，32 字节单块
        std::vector<std::uint8_t> Info(sizeof(RealityInfo) - 1 + 1);
        std::memcpy(Info.data(), RealityInfo, sizeof(RealityInfo) - 1);
        Info.back() = 0x01;
        std::array<std::uint8_t, 32> Okm{};
        if (!HmacSha256(Prk, Info, Okm))
        {
            return true;
        }
        std::memcpy(Output.data(), Okm.data(), KeyLen);
        return false;
    }

    /// SessionId 密封输入（AuthKey + random + hello）
    struct SessionIdSealInput
    {
        std::span<const std::uint8_t> AuthKey;      ///< 32 字节认证密钥
        std::span<const std::uint8_t> ClientRandom; ///< TLS ClientRandom（32 字节）
        std::span<const std::uint8_t> plain;         ///< 明文（16 字节）
        std::span<const std::uint8_t> hello;         ///< ClientHello 原始消息（AAD）
    };

    /// SessionId 解析输入（AuthKey + random + hello）
    struct SessionIdOpenInput
    {
        std::span<const std::uint8_t> AuthKey;      ///< 32 字节认证密钥
        std::span<const std::uint8_t> ClientRandom; ///< TLS ClientRandom（32 字节）
        std::span<const std::uint8_t> cipher;        ///< 32 字节密文（16 + tag 16）
        std::span<const std::uint8_t> hello;         ///< ClientHello 原始消息（AAD）
    };

    /**
     * @brief Seal SessionId（客户端侧，对齐 mihomo reality.go）
     * @param Input 密封输入
     * @param Output 输出 32 字节密文（16 + tag 16）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto SealSessionId(
        const SessionIdSealInput &Input,
        std::array<std::uint8_t, SessionIdAuthLen> &Output) -> bool
    {
        Output.fill(0);
        constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
        if (Input.AuthKey.size() != KeyLen || Input.plain.size() != 16 ||
            Input.ClientRandom.size() != 32 || Input.hello.size() < 39 + 32 ||
            Input.hello.size() > MaxInt)
        {
            return true;
        }
        // AAD：hello 且 SessionId 区（偏移 39 起 32 字节）清零
        std::vector<std::uint8_t> AAD(Input.hello.begin(), Input.hello.end());
        std::memset(AAD.data() + 39, 0, 32);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            return true;
        }
        int Len = 0;
        bool Ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, Input.AuthKey.data(),
                                     Input.ClientRandom.data() + 20) == 1;
        if (Ok && !AAD.empty())
        {
            Ok = EVP_EncryptUpdate(ctx, nullptr, &Len, AAD.data(), static_cast<int>(AAD.size())) == 1;
        }
        if (Ok)
        {
            Ok = EVP_EncryptUpdate(ctx, Output.data(), &Len, Input.plain.data(),
                                   static_cast<int>(Input.plain.size())) == 1;
        }
        int OutLen = 0;
        if (Ok)
        {
            OutLen = Len;
        }
        if (Ok)
        {
            Ok = EVP_EncryptFinal_ex(ctx, Output.data() + OutLen, &Len) == 1;
            OutLen += Len;
        }
        if (Ok && OutLen == 16)
        {
            Ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, Output.data() + OutLen) == 1;
        }
        EVP_CIPHER_CTX_free(ctx);
        if (!Ok || OutLen != 16)
        {
            Output.fill(0);
            return true;
        }
        return false;
    }

    /**
     * @brief Open SessionId（服务端侧）
     * @param Input 解析输入
     * @param Output 输出 16 字节明文
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto OpenSessionId(
        const SessionIdOpenInput &Input,
        std::array<std::uint8_t, 16> &Output) -> bool
    {
        Output.fill(0);
        constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
        if (Input.AuthKey.size() != KeyLen || Input.cipher.size() != SessionIdAuthLen ||
            Input.ClientRandom.size() != 32 || Input.hello.size() < 39 + 32 ||
            Input.hello.size() > MaxInt)
        {
            return true;
        }
        std::vector<std::uint8_t> AAD(Input.hello.begin(), Input.hello.end());
        std::memset(AAD.data() + 39, 0, 32);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            return true;
        }
        int Len = 0;
        bool Ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, Input.AuthKey.data(),
                                     Input.ClientRandom.data() + 20) == 1;
        if (Ok && !AAD.empty())
        {
            Ok = EVP_DecryptUpdate(ctx, nullptr, &Len, AAD.data(), static_cast<int>(AAD.size())) == 1;
        }
        if (Ok)
        {
            Ok = EVP_DecryptUpdate(ctx, Output.data(), &Len, Input.cipher.data(), 16) == 1;
        }
        int OutLen = 0;
        if (Ok)
        {
            OutLen = Len;
        }
        if (Ok)
        {
            Ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                     const_cast<std::uint8_t *>(Input.cipher.data()) + 16) == 1;
        }
        if (Ok)
        {
            Ok = EVP_DecryptFinal_ex(ctx, Output.data() + OutLen, &Len) == 1;
            OutLen += Len;
        }
        EVP_CIPHER_CTX_free(ctx);
        if (!Ok || OutLen != 16)
        {
            Output.fill(0);
            return true;
        }
        return false;
    }

    /**
     * @brief 解析 base64url 私钥
     * @param Encoded base64url 字符串
     * @param Output 输出私钥（32 字节）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto ParsePrivateKey(
        std::string_view Encoded,
        std::array<std::uint8_t, KeyLen> &Output) -> bool
    {
        Output.fill(0);
        const auto Raw = Base64urlDecode(Encoded);
        if (Raw.size() != KeyLen)
        {
            return true;
        }
        std::copy(Raw.begin(), Raw.end(), Output.begin());
        return false;
    }

    /**
     * @brief 编码公钥为 base64url
     * @param PublicKey 公钥（32 字节）
     * @return base64url 字符串
     */
    [[nodiscard]] inline auto EncodePublicKey(std::span<const std::uint8_t> PublicKey) -> std::string
    {
        return Base64urlEncode(PublicKey);
    }

    /**
     * @brief 解析 16 进制短 ID（最多 8 字节）
     * @param Hex 16 进制字符串
     * @param Output 输出短 ID（8 字节，不足补 0）
     * @return 成功返回 false
     */
    [[nodiscard]] inline auto ParseShortId(
        std::string_view Hex,
        std::array<std::uint8_t, MaxShortIdLen> &Output) -> bool
    {
        Output.fill(0);
        if (Hex.size() > 16 || Hex.size() % 2 != 0)
        {
            return true;
        }
        auto Nibble = [](const char Character) -> int
        {
            if (Character >= '0' && Character <= '9')
            {
                return Character - '0';
            }
            if (Character >= 'a' && Character <= 'f')
            {
                return Character - 'a' + 10;
            }
            if (Character >= 'A' && Character <= 'F')
            {
                return Character - 'A' + 10;
            }
            return -1;
        };
        std::size_t Pos = 0;
        for (std::size_t I = 0; I < Hex.size(); I += 2)
        {
            const int Hi = Nibble(Hex[I]);
            const int Lo = Nibble(Hex[I + 1]);
            if (Hi < 0 || Lo < 0)
            {
                return true;
            }
            Output[Pos++] = static_cast<std::uint8_t>((Hi << 4) | Lo);
        }
        return false;
    }

} // namespace Preview::Reality
