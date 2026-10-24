/**
 * @file KeyMaterial.hpp
 * @brief Reality base64、X25519 与 AuthKey 密钥材料编解码。
 * @details 负责配置和握手冷路径使用的密钥材料处理：
 *          - base64url 编解码（RFC 4648 无填充）
 *          - X25519 密钥对生成、公开密钥派生和共享密钥计算
 *          - AuthKey 派生（HKDF-Extract + HKDF-Expand）
 *          - 私钥解析、公钥编码
 * @note 这些函数均为无状态纯工具，调用方持有输出缓冲区所有权。
 */

#pragma once

#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <Prism/Protocols/Reality/CarrierTypes.hpp>

namespace Prism::Reality::Detail
{

    namespace KeyDetail
    {

        [[nodiscard]] inline auto Base64Value(const char Character) noexcept -> int
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
        }

        [[nodiscard]] inline auto HmacSha256(
            std::span<const std::uint8_t> Key,
            std::span<const std::uint8_t> Data,
            std::array<std::uint8_t, 32> &Digest) -> bool
        {
            unsigned int Length = 0;
            const auto *Result = HMAC(
                EVP_sha256(), Key.data(), static_cast<int>(Key.size()), Data.data(), Data.size(),
                Digest.data(), &Length);
            return Result != nullptr && Length == Digest.size();
        }

    } // namespace KeyDetail

    /**
     * @brief base64url 编码（RFC 4648，无填充）。
     * @param Data 输入字节。
     * @return 无填充 base64url 字符串。
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
            const auto N = static_cast<std::uint32_t>(Data[I]) << 16 |
                           static_cast<std::uint32_t>(Data[I + 1]) << 8;
            Output.push_back(Table[(N >> 18) & 0x3F]);
            Output.push_back(Table[(N >> 12) & 0x3F]);
            Output.push_back(Table[(N >> 6) & 0x3F]);
        }
        return Output;
    }

    /**
     * @brief base64url 解码（无填充，失败返回空）。
     * @param Input 无填充 base64url 字符串。
     * @return 解码字节；非法输入返回空向量。
     */
    [[nodiscard]] inline auto Base64urlDecode(std::string_view Input) -> std::vector<std::uint8_t>
    {
        if (Input.size() % 4 == 1)
        {
            return {};
        }
        std::vector<std::uint8_t> Output;
        std::uint32_t Acc = 0;
        int Bits = 0;
        for (const char Character : Input)
        {
            const int Value = KeyDetail::Base64Value(Character);
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
     * @brief 生成 X25519 密钥对（BoringSSL 原生 API）。
     * @param PrivateKey 输出私钥（32 字节）。
     * @param PublicKey 输出公钥（32 字节）。
     * @return 成功返回 false。
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
     * @brief 由私钥派生公钥（BoringSSL 原生 API）。
     * @param PrivateKey 私钥（32 字节）。
     * @param PublicKey 输出公钥（32 字节）。
     * @return 成功返回 false。
     */
    [[nodiscard]] inline auto DerivePublicKey(
        std::span<const std::uint8_t> PrivateKey,
        std::array<std::uint8_t, KeyLen> &PublicKey) -> bool
    {
        PublicKey.fill(0);
        if (PrivateKey.size() != KeyLen)
        {
            return true;
        }
        X25519_public_from_private(PublicKey.data(), PrivateKey.data());
        return false;
    }

    /**
     * @brief X25519 共享密钥（BoringSSL 原生 API）。
     * @param PrivateKey 私钥（32 字节）。
     * @param PublicKey 对端公钥（32 字节）。
     * @param Output 输出共享密钥（32 字节）。
     * @return 成功返回 false；输入非法、计算失败或结果为全零返回 true。
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
     * @brief 派生 Reality AuthKey。
     * @param SharedSecret X25519 共享密钥（32 字节）。
     * @param ClientRandom TLS ClientRandom（32 字节，前 20 字节为 salt）。
     * @param Output 输出 32 字节 AuthKey。
     * @return 成功返回 false。
     * @details 计算 HKDF-Extract(random[:20], shared) 后，以 "REALITY" 和
     *          单块 HKDF-Expand 派生 32 字节密钥。
     */
    [[nodiscard]] inline auto DeriveAuthKey(
        std::span<const std::uint8_t> SharedSecret,
        std::span<const std::uint8_t> ClientRandom,
        std::array<std::uint8_t, KeyLen> &Output) -> bool
    {
        Output.fill(0);
        if (SharedSecret.size() != KeyLen || ClientRandom.size() != 32)
        {
            return true;
        }
        std::array<std::uint8_t, 32> Prk{};
        if (!KeyDetail::HmacSha256(ClientRandom.first(20), SharedSecret, Prk))
        {
            return true;
        }

        std::vector<std::uint8_t> Info(sizeof(RealityInfo) - 1 + 1);
        std::memcpy(Info.data(), RealityInfo, sizeof(RealityInfo) - 1);
        Info.back() = 0x01;
        std::array<std::uint8_t, 32> Okm{};
        if (!KeyDetail::HmacSha256(Prk, Info, Okm))
        {
            return true;
        }
        std::memcpy(Output.data(), Okm.data(), KeyLen);
        return false;
    }

    /**
     * @brief 解析 base64url 私钥。
     * @param Encoded 无填充 base64url 私钥。
     * @param Output 输出私钥（32 字节）。
     * @return 成功返回 false。
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
     * @brief 编码公钥为 base64url。
     * @param PublicKey 公钥字节。
     * @return 无填充 base64url 字符串。
     */
    [[nodiscard]] inline auto EncodePublicKey(std::span<const std::uint8_t> PublicKey) -> std::string
    {
        return Base64urlEncode(PublicKey);
    }

} // namespace Prism::Reality::Detail
