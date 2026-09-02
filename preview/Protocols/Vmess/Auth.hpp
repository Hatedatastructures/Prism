/**
 * @file Auth.hpp
 * @brief VMess AEAD 认证头与密钥派生
 * @details 只负责 KDF、UUID 到 cmdKey 的转换、AuthID 以及认证头的
 *          AES-128-GCM 密封/打开。请求与响应头格式位于对应的 codec 文件。
 */

#pragma once

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <cstring>
#include <functional>
#include <random>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

#include <preview/Foundation/Error.hpp>
#include <preview/Protocols/Vmess/Types.hpp>

namespace Preview::Vmess
{

    namespace detail
    {

        /**
         * @brief HMAC-SHA256 单次
         * @param key 输入密钥
         * @param Data 输入数据
         * @return 32 字节摘要
         */
        [[nodiscard]] inline auto HmacSha256(std::span<const std::uint8_t> key,
                                              std::span<const std::uint8_t> Data)
            -> std::array<std::uint8_t, 32>
        {
            std::array<std::uint8_t, 32> out{};
            unsigned int Len = 0;
            HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), Data.data(), Data.size(), out.data(),
                 &Len);
            return out;
        }

        /**
         * @brief MD5 摘要（16 字节）
         * @param Data 输入数据
         * @return 16 字节摘要
         */
        [[nodiscard]] inline auto Md5(std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, 16>
        {
            std::array<std::uint8_t, 16> out{};
            unsigned int Len = 0;
            EVP_Digest(Data.data(), Data.size(), out.data(), &Len, EVP_md5(), nullptr);
            return out;
        }

        /**
         * @brief SHA-256 摘要（32 字节）
         * @param Data 输入数据
         * @return 32 字节摘要
         */
        [[nodiscard]] inline auto Sha256(std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, 32>
        {
            std::array<std::uint8_t, 32> out{};
            unsigned int Len = 0;
            EVP_Digest(Data.data(), Data.size(), out.data(), &Len, EVP_sha256(), nullptr);
            return out;
        }

        /**
         * @brief 路径转字节视图（支持 string_view / span / array）
         * @tparam Path 路径类型
         * @param obj 路径对象
         * @return 只读字节视图
         */
        template <typename Path>
        [[nodiscard]] inline auto AsBytes(const Path &obj) -> std::span<const std::uint8_t>
        {
            if constexpr (std::is_convertible_v<Path, std::string_view>)
            {
                const std::string_view sv(obj);
                return {reinterpret_cast<const std::uint8_t *>(sv.data()), sv.size()};
            }
            else
            {
                return std::span<const std::uint8_t>(obj);
            }
        }

        /**
         * @brief 路径填充到 64 字节块
         * @param Path 路径字节
         * @param mask 异或掩码（0x36 / 0x5C）
         * @return 64 字节填充块
         */
        [[nodiscard]] inline auto XorPad(std::span<const std::uint8_t> Path, std::uint8_t mask)
            -> std::array<std::uint8_t, 64>
        {
            std::array<std::uint8_t, 64> out{};
            const auto N = std::min(Path.size(), out.size());
            std::copy(Path.begin(), Path.begin() + static_cast<std::ptrdiff_t>(N), out.begin());
            for (auto &b : out)
            {
                b ^= mask;
            }
            return out;
        }

        /**
         * @brief AES-GCM 加密输入
         */
        struct SealInput
        {
            std::span<const std::uint8_t> key;
            std::span<const std::uint8_t> Nonce;
            std::span<const std::uint8_t> Plain;
            std::span<const std::uint8_t> aad;
        };

        /**
         * @brief AES-GCM 解密输入
         */
        struct OpenInput
        {
            std::span<const std::uint8_t> key;
            std::span<const std::uint8_t> Nonce;
            std::span<const std::uint8_t> cipher;
            std::span<const std::uint8_t> aad;
        };

        /**
         * @brief AES-128-GCM 加密（带 AAD）
         * @param in 加密输入
         * @return 密文 + 16 字节 tag；失败返回空
         */
        [[nodiscard]] inline auto AesGcmSeal(const SealInput &in) -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> out(in.Plain.size() + 16);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return {};
            }
            int Len = 0;
            EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, in.key.data(), in.Nonce.data());
            if (!in.aad.empty())
            {
                EVP_EncryptUpdate(ctx, nullptr, &Len, in.aad.data(), static_cast<int>(in.aad.size()));
            }
            EVP_EncryptUpdate(ctx, out.data(), &Len, in.Plain.data(), static_cast<int>(in.Plain.size()));
            int OutLen = Len;
            EVP_EncryptFinal_ex(ctx, out.data() + OutLen, &Len);
            OutLen += Len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + OutLen);
            out.resize(static_cast<std::size_t>(OutLen) + 16);
            EVP_CIPHER_CTX_free(ctx);
            return out;
        }

        /**
         * @brief AES-128-GCM 解密（带 AAD）
         * @param in 解密输入
         * @return 明文；失败返回空
         */
        [[nodiscard]] inline auto AesGcmOpen(const OpenInput &in) -> std::vector<std::uint8_t>
        {
            if (in.cipher.size() < 16)
            {
                return {};
            }
            std::vector<std::uint8_t> out(in.cipher.size() - 16);
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx)
            {
                return {};
            }
            int Len = 0;
            EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, in.key.data(), in.Nonce.data());
            if (!in.aad.empty())
            {
                EVP_DecryptUpdate(ctx, nullptr, &Len, in.aad.data(), static_cast<int>(in.aad.size()));
            }
            EVP_DecryptUpdate(ctx, out.data(), &Len, in.cipher.data(),
                              static_cast<int>(in.cipher.size() - 16));
            int OutLen = Len;
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                const_cast<std::uint8_t *>(in.cipher.data()) + in.cipher.size() - 16);
            const auto Ok = EVP_DecryptFinal_ex(ctx, out.data() + OutLen, &Len);
            OutLen += Len;
            EVP_CIPHER_CTX_free(ctx);
            if (Ok != 1)
            {
                return {};
            }
            out.resize(static_cast<std::size_t>(OutLen));
            return out;
        }

        /**
         * @brief FNV-1a 32 位
         * @param Data 输入数据
         * @return 32 位哈希
         */
        [[nodiscard]] inline auto Fnv1a32(std::span<const std::uint8_t> Data) -> std::uint32_t
        {
            std::uint32_t H = 0x811C9DC5;
            for (const auto b : Data)
            {
                H ^= b;
                H *= 0x01000193;
            }
            return H;
        }

        /**
         * @brief 时间戳编码（大端 8 字节）
         * @param Ts 时间戳（秒）
         * @return 大端 8 字节
         */
        [[nodiscard]] inline auto EncodeTimestamp(std::int64_t Ts) -> std::array<std::uint8_t, 8>
        {
            std::array<std::uint8_t, 8> out{};
            const auto U = static_cast<std::uint64_t>(Ts);
            for (std::size_t I = 0; I < 8; ++I)
            {
                out[7 - I] = static_cast<std::uint8_t>((U >> (I * 8)) & 0xFF);
            }
            return out;
        }

    } // namespace detail

    /**
     * @brief 执行 VMess AEAD KDF 链式哈希
     * @tparam Path KDF 路径类型
     * @param key 初始密钥
     * @param paths KDF 路径列表
     * @return 32 字节派生密钥
     */
    template <typename... Path>
    [[nodiscard]] auto Kdf(std::span<const std::uint8_t> key, const Path &...paths)
        -> std::array<std::uint8_t, 32>
    {
        std::function<std::array<std::uint8_t, 32>(std::span<const std::uint8_t>)> H =
            [](std::span<const std::uint8_t> msg) -> std::array<std::uint8_t, 32>
        { return detail::HmacSha256(detail::AsBytes(KdfInnerMarker), msg); };

        auto Wrap = [&H](std::span<const std::uint8_t> PathSpan)
        {
            const auto Prev = H;
            const auto Ipad = detail::XorPad(PathSpan, 0x36);
            const auto Opad = detail::XorPad(PathSpan, 0x5C);
            H = [Prev, Ipad, Opad](std::span<const std::uint8_t> msg) -> std::array<std::uint8_t, 32>
            {
                std::vector<std::uint8_t> InnerIn(64 + msg.size());
                std::copy(Ipad.begin(), Ipad.end(), InnerIn.begin());
                std::copy(msg.begin(), msg.end(), InnerIn.begin() + 64);
                const auto Inner = Prev(InnerIn);

                std::array<std::uint8_t, 64 + 32> OuterIn{};
                std::copy(Opad.begin(), Opad.end(), OuterIn.begin());
                std::copy(Inner.begin(), Inner.end(), OuterIn.begin() + 64);
                return Prev(OuterIn);
            };
        };

        (Wrap(detail::AsBytes(paths)), ...);
        return H(key);
    }

    namespace detail
    {

        /**
         * @brief CRC32-IEEE 校验
         * @param Data 输入数据
         * @return CRC32 值
         */
        [[nodiscard]] inline auto Crc32(std::span<const std::uint8_t> Data) -> std::uint32_t
        {
            std::uint32_t Crc = 0xFFFFFFFFU;
            for (const auto Byte : Data)
            {
                Crc ^= Byte;
                for (int I = 0; I < 8; ++I)
                {
                    Crc = (Crc & 1U) != 0U ? (Crc >> 1) ^ 0xEDB88320U : Crc >> 1;
                }
            }
            return Crc ^ 0xFFFFFFFFU;
        }

        /**
         * @brief AES-128-ECB 无填充加密
         */
        [[nodiscard]] inline auto AesEcbEncrypt(std::span<const std::uint8_t, 16> Key,
                                                 std::span<const std::uint8_t, 16> Plain)
            -> std::array<std::uint8_t, 16>
        {
            std::array<std::uint8_t, 16> Out{};
            EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return {};
            }
            int Len = 0;
            int Total = 0;
            const bool Ok = EVP_EncryptInit_ex(Ctx, EVP_aes_128_ecb(), nullptr, Key.data(), nullptr) == 1 &&
                            EVP_CIPHER_CTX_set_padding(Ctx, 0) == 1 &&
                            EVP_EncryptUpdate(Ctx, Out.data(), &Len, Plain.data(), Plain.size()) == 1;
            if (Ok)
            {
                Total = Len;
                const bool FinalOk = EVP_EncryptFinal_ex(Ctx, Out.data() + Total, &Len) == 1;
                Total += Len;
                EVP_CIPHER_CTX_free(Ctx);
                if (!FinalOk || Total != static_cast<int>(Out.size()))
                {
                    return {};
                }
                return Out;
            }
            EVP_CIPHER_CTX_free(Ctx);
            return {};
        }

        /**
         * @brief AES-128-ECB 无填充解密
         */
        [[nodiscard]] inline auto AesEcbDecrypt(std::span<const std::uint8_t, 16> Key,
                                                 std::span<const std::uint8_t, 16> Cipher)
            -> std::array<std::uint8_t, 16>
        {
            std::array<std::uint8_t, 16> Out{};
            EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return {};
            }
            int Len = 0;
            int Total = 0;
            const bool Ok = EVP_DecryptInit_ex(Ctx, EVP_aes_128_ecb(), nullptr, Key.data(), nullptr) == 1 &&
                            EVP_CIPHER_CTX_set_padding(Ctx, 0) == 1 &&
                            EVP_DecryptUpdate(Ctx, Out.data(), &Len, Cipher.data(), Cipher.size()) == 1;
            if (Ok)
            {
                Total = Len;
                const bool FinalOk = EVP_DecryptFinal_ex(Ctx, Out.data() + Total, &Len) == 1;
                Total += Len;
                EVP_CIPHER_CTX_free(Ctx);
                if (!FinalOk || Total != static_cast<int>(Out.size()))
                {
                    return {};
                }
                return Out;
            }
            EVP_CIPHER_CTX_free(Ctx);
            return {};
        }

    } // namespace detail

    /**
     * @brief 由 UUID 16 字节派生 cmdKey
     * @param uuid 16 字节 UUID 原始字节
     * @return 16 字节 cmdKey
     */
    [[nodiscard]] inline auto CmdKeyFromUuid(std::span<const std::uint8_t, 16> uuid)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16 + 36> input{};
        std::copy(uuid.begin(), uuid.end(), input.begin());
        const auto Salt = detail::AsBytes(UuidSalt);
        std::copy(Salt.begin(), Salt.end(), input.begin() + 16);
        return detail::Md5(input);
    }

    /**
     * @brief 解析 36 字符 UUID 字符串为 16 字节
     * @param uuid UUID 字符串
     * @param out 输出 16 字节
     * @return 成功返回 true
     */
    [[nodiscard]] inline auto ParseUuid(std::string_view uuid, std::span<std::uint8_t, 16> out) -> bool
    {
        if (uuid.size() != 36)
        {
            return false;
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
        for (std::size_t I = 0; I < uuid.size();)
        {
            if (uuid[I] == '-')
            {
                ++I;
                continue;
            }
            if (I + 1 >= uuid.size())
            {
                return false;
            }
            const int Hi = Nibble(uuid[I]);
            const int Lo = Nibble(uuid[I + 1]);
            if (Hi < 0 || Lo < 0)
            {
                return false;
            }
            out[Pos++] = static_cast<std::uint8_t>((Hi << 4) | Lo);
            I += 2;
        }
        return Pos == 16;
    }

    /**
     * @brief 构造标准 VMess AuthID
     * @param CmdKey 16 字节 cmdKey
     * @param TimeSec UTC 秒
     * @param random 4 字节随机数
     * @return 加密后的 16 字节 AuthID
     */
    [[nodiscard]] inline auto CreateAuthId(std::span<const std::uint8_t, 16> CmdKey,
                                            std::int64_t TimeSec,
                                            std::span<const std::uint8_t, 4> random)
        -> std::array<std::uint8_t, 16>
    {
        std::array<std::uint8_t, 16> Plain{};
        const auto Ts = detail::EncodeTimestamp(TimeSec);
        std::memcpy(Plain.data(), Ts.data(), Ts.size());
        std::memcpy(Plain.data() + TimestampLen, random.data(), AuthRandomLen);
        const auto Crc = detail::Crc32(std::span<const std::uint8_t>(Plain.data(), TimestampLen + AuthRandomLen));
        for (std::size_t I = 0; I < sizeof(Crc); ++I)
        {
            Plain[TimestampLen + AuthRandomLen + I] =
                static_cast<std::uint8_t>(Crc >> (8 * (sizeof(Crc) - 1 - I)));
        }
        const auto AuthKey = Kdf(CmdKey, KdfAuthId);
        return detail::AesEcbEncrypt(
            std::span<const std::uint8_t, 16>(AuthKey.data(), 16), Plain);
    }

    /**
     * @brief 认证头密封输入
     */
    struct AuthHeaderInput
    {
        std::span<const std::uint8_t> Body;
        std::int64_t TimeSec{0};
        std::span<const std::uint8_t, 4> random;
    };

    /**
     * @brief 密封 AEAD 认证头
     * @param CmdKey 16 字节 cmdKey
     * @param in 输入（body + TimeSec + random）
     * @return 认证头字节
     */
    [[nodiscard]] inline auto SealAuthHeader(std::span<const std::uint8_t, 16> CmdKey,
                                               const AuthHeaderInput &in) -> std::vector<std::uint8_t>
    {
        const auto AuthId = CreateAuthId(CmdKey, in.TimeSec, in.random);
        std::array<std::uint8_t, 8> Nonce8{};
        if (RAND_bytes(Nonce8.data(), static_cast<int>(Nonce8.size())) != 1)
        {
            return {};
        }

        std::array<std::uint8_t, 2> LenPlain{static_cast<std::uint8_t>(in.Body.size() >> 8),
                                              static_cast<std::uint8_t>(in.Body.size() & 0xFF)};
        const auto LenKey = Kdf(CmdKey, KdfHeaderLenKey, AuthId, Nonce8);
        const auto LenIv = Kdf(CmdKey, KdfHeaderLenIv, AuthId, Nonce8);
        const auto LenEnc = detail::AesGcmSeal(
            detail::SealInput{std::span<const std::uint8_t>(LenKey.data(), 16),
                               std::span<const std::uint8_t>(LenIv.data(), 12), LenPlain, AuthId});

        const auto HdrKey = Kdf(CmdKey, KdfHeaderKey, AuthId, Nonce8);
        const auto HdrIv = Kdf(CmdKey, KdfHeaderIv, AuthId, Nonce8);
        const auto HdrEnc = detail::AesGcmSeal(
            detail::SealInput{std::span<const std::uint8_t>(HdrKey.data(), 16),
                               std::span<const std::uint8_t>(HdrIv.data(), 12), in.Body, AuthId});

        std::vector<std::uint8_t> out;
        out.reserve(16 + LenEnc.size() + 8 + HdrEnc.size());
        out.insert(out.end(), AuthId.begin(), AuthId.end());
        out.insert(out.end(), LenEnc.begin(), LenEnc.end());
        out.insert(out.end(), Nonce8.begin(), Nonce8.end());
        out.insert(out.end(), HdrEnc.begin(), HdrEnc.end());
        return out;
    }

    /**
     * @brief 打开 AEAD 认证头
     * @param CmdKey 16 字节 cmdKey
     * @param Header 认证头
     * @param out 输出明文载荷
     * @return 错误码
     */
    [[nodiscard]] inline auto OpenAuthHeader(std::span<const std::uint8_t, 16> CmdKey,
                                               std::span<const std::uint8_t> Header,
                                               std::vector<std::uint8_t> &out) -> Error
    {
        if (Header.size() < 16 + 18 + 8 + 18)
        {
            return Error::NeedMore;
        }
        const auto AuthId = Header.first(16);
        const auto AuthKey = Kdf(CmdKey, KdfAuthId);
        const auto AuthPlain = detail::AesEcbDecrypt(
            std::span<const std::uint8_t, 16>(AuthKey.data(), 16),
            std::span<const std::uint8_t, 16>(AuthId.data(), 16));
        const auto ExpectedCrc = detail::Crc32(
            std::span<const std::uint8_t>(AuthPlain.data(), TimestampLen + AuthRandomLen));
        std::uint32_t ActualCrc = 0;
        for (std::size_t I = 0; I < sizeof(ActualCrc); ++I)
        {
            ActualCrc = (ActualCrc << 8) | AuthPlain[TimestampLen + AuthRandomLen + I];
        }
        if (ActualCrc != ExpectedCrc)
        {
            return Error::BadAuth;
        }
        std::uint64_t AuthTimestamp = 0;
        for (std::size_t I = 0; I < TimestampLen; ++I)
        {
            AuthTimestamp = (AuthTimestamp << 8) | AuthPlain[I];
        }
        const auto Now = static_cast<std::int64_t>(std::time(nullptr));
        const auto Diff = Now >= static_cast<std::int64_t>(AuthTimestamp)
                              ? Now - static_cast<std::int64_t>(AuthTimestamp)
                              : static_cast<std::int64_t>(AuthTimestamp) - Now;
        if (Diff > TimeTolerance)
        {
            return Error::BadAuth;
        }
        const auto LenEnc = Header.subspan(16, 18);
        const auto Nonce8 = Header.subspan(16 + 18, 8);
        const auto LenKey = Kdf(CmdKey, KdfHeaderLenKey, AuthId, Nonce8);
        const auto LenIv = Kdf(CmdKey, KdfHeaderLenIv, AuthId, Nonce8);
        const auto LenPlain = detail::AesGcmOpen(
            detail::OpenInput{std::span<const std::uint8_t>(LenKey.data(), 16),
                               std::span<const std::uint8_t>(LenIv.data(), 12), LenEnc, AuthId});
        if (LenPlain.size() != 2)
        {
            return Error::BadAuth;
        }
        const auto length = static_cast<std::size_t>(LenPlain[0]) << 8 | LenPlain[1];
        const auto BodyOffset = 16 + 18 + 8;
        if (Header.size() < BodyOffset + length + 16)
        {
            return Error::NeedMore;
        }

        const auto HdrKey = Kdf(CmdKey, KdfHeaderKey, AuthId, Nonce8);
        const auto HdrIv = Kdf(CmdKey, KdfHeaderIv, AuthId, Nonce8);
        const auto Body = detail::AesGcmOpen(
            detail::OpenInput{std::span<const std::uint8_t>(HdrKey.data(), 16),
                               std::span<const std::uint8_t>(HdrIv.data(), 12),
                               Header.subspan(BodyOffset, length + 16), AuthId});
        if (Body.empty())
        {
            return Error::BadAuth;
        }
        out = Body;
        return Error::None;
    }

} // namespace Preview::Vmess
