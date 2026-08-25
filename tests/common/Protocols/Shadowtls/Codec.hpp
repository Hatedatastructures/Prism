/**
 * @file Codec.hpp
 * @brief ShadowTLS v3 认证编解码（纯函数）
 * @details 对齐 sing-shadowtls v3_client.go / v3_conn.go：
 *          - GenerateSessionId：HMAC-SHA1(password, clientHello 前段 + sessionID
 *            + clientHello 后段)[:4] 塞入 SessionId 末尾
 *          - VerifyClientHello：校验 ClientHello SessionId 内 HMAC
 *          - FrameHmac：HMAC-SHA1(password, serverRandom + tag + payload)[:4]
 *          - Kdf：SHA256(password + serverRandom)，用于流加密密钥
 * @note 参考 sing-shadowtls v3 协议规范。
 */

#pragma once

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

#include <common/Core/Error.hpp>
#include <common/Protocols/Shadowtls/Types.hpp>

namespace Preview::Shadowtls
{

    /// SessionId 生成输入（password + ClientHello + 输出 sid）
    struct SessionIdInput
    {
        std::string_view password;                             ///< 密码
        std::span<const std::uint8_t> ClientHello;            ///< 不含 TLS 头的握手数据
        std::span<std::uint8_t, TlsSessionIdSz> SessionId; ///< 输出 sid（32B）
    };

    /**
     * @brief 生成 SessionId（客户端侧）
     * @param in 生成输入
     * @return 错误码
     * @details 对齐 sing v3 generateSessionID：前 28 字节随机，
     * 后 4 字节 = HMAC-SHA1(password, hello[:sidStart] + sid + hello[sidEnd:])[:4]。
     */
    [[nodiscard]] inline auto GenerateSessionId(const SessionIdInput &in) -> Error
    {
        const auto &password = in.password;
        const auto &ClientHello = in.ClientHello;
        auto &SessionId = in.SessionId;
        if (ClientHello.size() < SessionIdStart + TlsSessionIdSz)
        {
            return Error::bad_length;
        }

        // HMAC-SHA1(password, ClientHello[:sidStart] + sessionID + ClientHello[sidEnd:])[:4]
        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx)
        {
            return Error::io_error;
        }
        HMAC_Init_ex(ctx, password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
        HMAC_Update(ctx, ClientHello.data(), SessionIdStart);
        HMAC_Update(ctx, SessionId.data(), TlsSessionIdSz);
        HMAC_Update(ctx, ClientHello.data() + SessionIdStart + TlsSessionIdSz,
                    ClientHello.size() - SessionIdStart - TlsSessionIdSz);
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t MdLen = 0;
        HMAC_Final(ctx, md.data(), &MdLen);
        HMAC_CTX_free(ctx);

        std::memcpy(SessionId.data() + TlsSessionIdSz - HmacSize, md.data(), HmacSize);
        return Error::none;
    }

    /**
     * @brief 校验 ClientHello（服务端侧）
     * @param password 密码
     * @param ClientHello 含 TLS 头的完整消息
     * @return true = SessionId HMAC 校验通过
     * @details 对齐 sing v3 / C++ VerifyClientHello：
     * HMAC-SHA1(password, hello[5:] 且 SessionId 末尾 4 字节置零)[:4] == SessionId 末尾 4 字节。
     */
    [[nodiscard]] inline auto VerifyClientHello(std::string_view password,
                                                  std::span<const std::byte> ClientHello) -> bool
    {
        constexpr std::size_t MinLen = TlsHdrsize + 1 + 3 + 2 + TlsRndSize + 1 + TlsSessionIdSz;
        if (ClientHello.size() < MinLen)
        {
            return false;
        }
        const auto *raw = reinterpret_cast<const std::uint8_t *>(ClientHello.data());
        if (raw[0] != 0x16 || raw[TlsHdrsize] != HsTypeClienthello)
        {
            return false;
        }
        const std::size_t SidLenIdx = TlsHdrsize + 1 + 3 + 2 + TlsRndSize;
        if (raw[SidLenIdx] != TlsSessionIdSz)
        {
            return false;
        }

        // 构造 HMAC 数据：hello[5:] 且 SessionId 末尾 4 字节置零
        const std::size_t DataSize = ClientHello.size() - TlsHdrsize;
        std::vector<std::uint8_t> hmac_data(DataSize);
        std::memcpy(hmac_data.data(), raw + TlsHdrsize, DataSize);
        const std::size_t HmacOffsetInData = SessionIdStart + TlsSessionIdSz - HmacSize;
        std::memset(hmac_data.data() + HmacOffsetInData, 0, HmacSize);

        // 期望 HMAC
        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx)
        {
            return false;
        }
        HMAC_Init_ex(ctx, password.data(), static_cast<int>(password.size()), EVP_sha1(), nullptr);
        HMAC_Update(ctx, hmac_data.data(), hmac_data.size());
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t MdLen = 0;
        HMAC_Final(ctx, md.data(), &MdLen);
        HMAC_CTX_free(ctx);

        // 客户端 tag
        const std::size_t ClientHmacOffset = SidLenIdx + 1 + TlsSessionIdSz - HmacSize;
        return CRYPTO_memcmp(md.data(), raw + ClientHmacOffset, HmacSize) == 0;
    }

    /// 帧 HMAC 输入（password + ServerRandom + tag + payload）
    struct FrameHmacInput
    {
        std::string_view password;                   ///< 密码
        std::span<const std::uint8_t> ServerRandom; ///< 32 字节 Server random
        char tag{'C'};                               ///< 标签（'C' 客户端 / 'S' 服务端）
        std::span<const std::uint8_t> payload;       ///< 载荷
    };

    /**
     * @brief 计算帧 HMAC（post-handshake 认证）
     * @param in 输入
     * @return 4 字节 HMAC
     */
    [[nodiscard]] inline auto FrameHmac(const FrameHmacInput &in) -> std::array<std::uint8_t, HmacSize>
    {
        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx)
        {
            return {};
        }
        HMAC_Init_ex(ctx, in.password.data(), static_cast<int>(in.password.size()), EVP_sha1(), nullptr);
        HMAC_Update(ctx, in.ServerRandom.data(), in.ServerRandom.size());
        const auto TagByte = static_cast<std::uint8_t>(in.tag);
        HMAC_Update(ctx, &TagByte, 1);
        HMAC_Update(ctx, in.payload.data(), in.payload.size());
        std::array<std::uint8_t, EVP_MAX_MD_SIZE> md{};
        std::uint32_t MdLen = 0;
        HMAC_Final(ctx, md.data(), &MdLen);
        HMAC_CTX_free(ctx);

        std::array<std::uint8_t, HmacSize> out{};
        std::memcpy(out.data(), md.data(), HmacSize);
        return out;
    }

    /**
     * @brief 派生流密钥（对齐 sing v3 Kdf）
     * @param password 密码
     * @param ServerRandom 32 字节 Server random
     * @return SHA256(password + serverRandom)
     */
    [[nodiscard]] inline auto Kdf(std::string_view password, std::span<const std::uint8_t> ServerRandom)
        -> std::array<std::uint8_t, 32>
    {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, password.data(), password.size());
        SHA256_Update(&ctx, ServerRandom.data(), ServerRandom.size());
        std::array<std::uint8_t, 32> out{};
        SHA256_Final(out.data(), &ctx);
        return out;
    }

    /**
     * @brief 字节异或（对齐 sing v3 xorSlice，用于流加密）
     * @param Data 待异或数据（原地）
     * @param key 密钥
     */
    inline auto XorSlice(std::span<std::uint8_t> Data, std::span<const std::uint8_t> key) -> void
    {
        if (key.empty())
        {
            return;
        }
        for (std::size_t i = 0; i < Data.size(); ++i)
        {
            Data[i] ^= key[i % key.size()];
        }
    }

} // namespace Preview::Shadowtls
