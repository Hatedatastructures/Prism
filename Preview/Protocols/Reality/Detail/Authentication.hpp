/**
 * @file SessionId.hpp
 * @brief Reality SessionId 认证密封、解析与 ShortId 编解码。
 * @details 负责 SessionId 的 AES-256-GCM wire 语义：Nonce 使用
 *          ClientRandom[20:32]，AAD 为 ClientHello 且 SessionId 区清零。
 *          同时拥有 ShortId 的十六进制解析。
 * @note 明文固定为 16 字节，密文固定为 32 字节（16 字节密文加 16 字节 tag）。
 */

#pragma once

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <expected>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <string_view>
#include <vector>

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Protocols/Reality/Types.hpp>
#include <Preview/Protocols/Reality/Detail/Hello.hpp>
#include <Preview/Protocols/Reality/Detail/Key.hpp>

namespace Preview::Reality::Detail
{

    namespace AuthenticationDetail
    {

        [[nodiscard]] inline auto HexNibble(const char Character) noexcept -> int
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
        }

    } // namespace AuthenticationDetail

    /// SessionId 密封输入（AuthKey、ClientRandom、明文和 ClientHello AAD）。
    struct SessionIdSealInput
    {
        std::span<const std::uint8_t> AuthKey;      ///< 32 字节认证密钥。
        std::span<const std::uint8_t> ClientRandom; ///< TLS ClientRandom（32 字节）。
        std::span<const std::uint8_t> plain;         ///< 明文（16 字节）。
        std::span<const std::uint8_t> hello;         ///< ClientHello 原始消息（AAD）。
    };

    /// SessionId 解析输入（AuthKey、ClientRandom、密文和 ClientHello AAD）。
    struct SessionIdOpenInput
    {
        std::span<const std::uint8_t> AuthKey;      ///< 32 字节认证密钥。
        std::span<const std::uint8_t> ClientRandom; ///< TLS ClientRandom（32 字节）。
        std::span<const std::uint8_t> cipher;        ///< 32 字节密文（16 字节密文加 tag）。
        std::span<const std::uint8_t> hello;         ///< ClientHello 原始消息（AAD）。
    };

    /**
     * @brief Seal SessionId（客户端侧，对齐 mihomo reality.go）。
     * @param Input 密封输入。
     * @param Output 输出 32 字节密文（16 字节密文加 16 字节 tag）。
     * @return 成功返回 false。
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
        // AAD：hello 且 SessionId 区（偏移 39 起 32 字节）清零。
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
     * @brief Open SessionId（服务端侧）。
     * @param Input 解析输入。
     * @param Output 输出 16 字节明文。
     * @return 成功返回 false。
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
     * @brief 解析十六进制 ShortId（最多 8 字节）。
     * @param Hex 偶数长度十六进制字符串。
     * @param Output 输出 ShortId（不足 8 字节的高位补零）。
     * @return 成功返回 false。
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
        std::size_t Pos = 0;
        for (std::size_t I = 0; I < Hex.size(); I += 2)
        {
            const int Hi = AuthenticationDetail::HexNibble(Hex[I]);
            const int Lo = AuthenticationDetail::HexNibble(Hex[I + 1]);
            if (Hi < 0 || Lo < 0)
            {
                return true;
            }
            Output[Pos++] = static_cast<std::uint8_t>((Hi << 4) | Lo);
        }
        return false;
    }

        struct AuthenticatedClient final
        {
            std::array<std::uint8_t, KeyLen> AuthKey{};
            ClientHelloView Client;
        };

        /** @brief 校验 SessionId/ShortId 并构造后续 ServerHello 所需的认证材料。 */
        [[nodiscard]] inline auto AuthenticateClient(const PreparedRequest &Request)
            -> std::expected<AuthenticatedClient, Preview::Fault::Failure>
        {
            if (Request.Random.size() != 32 ||
                Request.SessionId.size() != SessionIdAuthLen ||
                Request.X25519Key.size() != KeyLen || Request.RawMessage.empty() ||
                Request.Config.ShortIds.empty())
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::BadMessage});
            }
            if (!Request.Config.ServerNames.empty() &&
                std::find(Request.Config.ServerNames.begin(), Request.Config.ServerNames.end(),
                          Request.ServerName) == Request.Config.ServerNames.end())
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Badsni});
            }

            std::array<std::uint8_t, KeyLen> AuthShared{};
            AuthenticatedClient Result;
            if (X25519Shared(Request.Config.PrivateKey, Request.X25519Key, AuthShared))
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Kexfail});
            }
            if (DeriveAuthKey(AuthShared, Request.Random, Result.AuthKey))
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Kdferr});
            }

            std::array<std::uint8_t, 16> SessionPlain{};
            if (OpenSessionId(
                    SessionIdOpenInput{
                        Result.AuthKey, Request.Random, Request.SessionId, Request.RawMessage},
                    SessionPlain) ||
                SessionPlain[0] != 0x01)
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Unauth});
            }

            std::array<std::uint8_t, MaxShortIdLen> ShortId{};
            std::copy_n(SessionPlain.data() + 8, ShortId.size(), ShortId.data());
            if (std::find(Request.Config.ShortIds.begin(), Request.Config.ShortIds.end(), ShortId) ==
                Request.Config.ShortIds.end())
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Unauth});
            }

            std::copy(Request.Random.begin(), Request.Random.end(), Result.Client.Random.begin());
            std::copy(Request.SessionId.begin(), Request.SessionId.end(), Result.Client.SessionId.begin());
            std::copy(Request.X25519Key.begin(), Request.X25519Key.end(), Result.Client.PublicKey.begin());
            return Result;
        }


} // namespace Preview::Reality::Detail
