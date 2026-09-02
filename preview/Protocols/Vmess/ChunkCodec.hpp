/**
 * @file ChunkCodec.hpp
 * @brief VMess 分块 AEAD 编解码与流状态机
 * @details 该文件只负责数据面分块：长度块、载荷块、Nonce 推进以及
 *          ChunkStream 的增量封装。认证头和请求/响应头由 Codec.hpp 负责。
 */

#pragma once

#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <preview/Foundation/Error.hpp>
#include <preview/Protocols/Vmess/Types.hpp>

namespace Preview::Vmess
{

    namespace detail
    {

        /**
         * @brief 单次 AES-128-GCM 加密（Nonce 由调用方控制）
         * @param Key 密钥
         * @param Nonce 12 字节 Nonce
         * @param Plain 明文
         * @param Out 输出密文（含 tag）
         */
        inline auto ChunkSeal(std::span<const std::uint8_t> Key,
                              std::span<const std::uint8_t, 12> Nonce,
                              std::span<const std::uint8_t> Plain,
                              std::span<std::uint8_t> Out) -> void
        {
            EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return;
            }
            int Len = 0;
            EVP_EncryptInit_ex(Ctx, EVP_aes_128_gcm(), nullptr, Key.data(), Nonce.data());
            EVP_EncryptUpdate(Ctx, Out.data(), &Len, Plain.data(), static_cast<int>(Plain.size()));
            EVP_EncryptFinal_ex(Ctx, Out.data() + Len, &Len);
            EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_GET_TAG, 16, Out.data() + Plain.size());
            EVP_CIPHER_CTX_free(Ctx);
        }

        /**
         * @brief 单次 AES-128-GCM 解密
         * @param Key 密钥
         * @param Nonce 12 字节 Nonce
         * @param Cipher 密文（含 tag）
         * @param Out 输出明文
         * @return 校验成功返回 true
         */
        inline auto ChunkOpen(std::span<const std::uint8_t> Key,
                              std::span<const std::uint8_t, 12> Nonce,
                              std::span<const std::uint8_t> Cipher,
                              std::span<std::uint8_t> Out) -> bool
        {
            if (Cipher.size() < 16)
            {
                return false;
            }
            EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return false;
            }
            int Len = 0;
            EVP_DecryptInit_ex(Ctx, EVP_aes_128_gcm(), nullptr, Key.data(), Nonce.data());
            EVP_DecryptUpdate(Ctx, Out.data(), &Len, Cipher.data(),
                              static_cast<int>(Cipher.size() - 16));
            EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                const_cast<std::uint8_t *>(Cipher.data()) + Cipher.size() - 16);
            const auto Ok = EVP_DecryptFinal_ex(Ctx, Out.data() + Len, &Len);
            EVP_CIPHER_CTX_free(Ctx);
            return Ok == 1;
        }

        /**
         * @brief Nonce 递增（大端 +1）
         * @param Nonce 12 字节 Nonce（原地递增）
         */
        inline auto IncNonce(std::span<std::uint8_t, 12> Nonce) -> void
        {
            for (std::size_t I = Nonce.size(); I > 0; --I)
            {
                if (++Nonce[I - 1] != 0)
                {
                    break;
                }
            }
        }

    } // namespace detail

    /**
     * @brief VMess 分块加密器（状态机）
     */
    class ChunkEncryptor
    {
    public:
        /// 分块开销：2 长度 + 16 长度 tag + 16 载荷 tag
        static constexpr std::size_t Overhead = 2 + 16 + 16;

        /**
         * @brief 构造
         * @param Key 16 字节分块密钥
         * @param Nonce 12 字节起始 Nonce
         */
        explicit ChunkEncryptor(std::span<const std::uint8_t, 16> Key,
                                std::span<const std::uint8_t, 12> Nonce)
            : Key_(), Nonce_()
        {
            std::memcpy(Key_.data(), Key.data(), 16);
            std::memcpy(Nonce_.data(), Nonce.data(), 12);
        }

        /**
         * @brief 加密一块数据
         * @param Plain 明文
         * @param Out 输出（容量至少为 Plain.size() + Overhead）
         * @return 写入字节数（含块头）
         */
        auto Seal(std::span<const std::uint8_t> Plain, std::span<std::uint8_t> Out) -> std::size_t
        {
            const auto N = Plain.size();
            if (Out.size() < N + Overhead)
            {
                return 0;
            }

            std::array<std::uint8_t, 2> LenPlain{};
            LenPlain[0] = static_cast<std::uint8_t>((N >> 8) & 0xFF);
            LenPlain[1] = static_cast<std::uint8_t>(N & 0xFF);
            std::array<std::uint8_t, 2 + 16> LenEnc{};
            detail::ChunkSeal(Key_, Nonce_, LenPlain, LenEnc);
            detail::IncNonce(Nonce_);

            std::memcpy(Out.data(), LenEnc.data(), LenEnc.size());
            detail::ChunkSeal(Key_, Nonce_, Plain, Out.subspan(LenEnc.size()));
            detail::IncNonce(Nonce_);
            return LenEnc.size() + N + 16;
        }

        /**
         * @brief 结束块（长度 0）
         * @param Out 输出（容量至少为 18）
         * @return 写入字节数
         */
        auto Finish(std::span<std::uint8_t> Out) -> std::size_t
        {
            return Seal({}, Out);
        }

    private:
        std::array<std::uint8_t, 16> Key_;
        std::array<std::uint8_t, 12> Nonce_;
    };

    /**
     * @brief VMess 分块解密器（状态机，支持增量两步解析）
     */
    class ChunkDecryptor
    {
    public:
        /**
         * @brief 构造
         * @param Key 16 字节分块密钥
         * @param Nonce 12 字节起始 Nonce
         */
        explicit ChunkDecryptor(std::span<const std::uint8_t, 16> Key,
                                std::span<const std::uint8_t, 12> Nonce)
            : Key_(), Nonce_()
        {
            std::memcpy(Key_.data(), Key.data(), 16);
            std::memcpy(Nonce_.data(), Nonce.data(), 12);
        }

        /**
         * @brief 解密长度字段（2 字节密文 + 16 tag）
         * @param Head 18 字节块头
         * @return 载荷长度或错误码
         */
        auto OpenLen(std::span<const std::uint8_t> Head) -> std::expected<std::size_t, Error>
        {
            if (Head.size() < 18)
            {
                return std::unexpected(Error::NeedMore);
            }
            std::array<std::uint8_t, 2> LenPlain{};
            if (!detail::ChunkOpen(Key_, Nonce_, Head.first(18), LenPlain))
            {
                return std::unexpected(Error::BadAuth);
            }
            detail::IncNonce(Nonce_);
            const auto N = static_cast<std::size_t>(LenPlain[0]) << 8 | LenPlain[1];
            if (N > MaxChunkLen)
            {
                return std::unexpected(Error::BadLength);
            }
            return N;
        }

        /**
         * @brief 解密载荷字段
         * @param Data 载荷密文块（长度 + 16）
         * @param Out 输出明文
         * @return 错误码
         */
        auto OpenPayload(std::span<const std::uint8_t> Data, std::span<std::uint8_t> Out) -> Error
        {
            if (Data.size() < 16 || Out.size() < Data.size() - 16)
            {
                return Error::NeedMore;
            }
            if (!detail::ChunkOpen(Key_, Nonce_, Data, Out.first(Data.size() - 16)))
            {
                return Error::BadAuth;
            }
            detail::IncNonce(Nonce_);
            return Error::None;
        }

        /**
         * @brief 解密一块完整数据
         * @param Data 完整密文块
         * @param Out 输出明文
         * @param Consumed 输出消耗字节数
         * @return 错误码；NeedMore 表示数据不足
         */
        auto Open(std::span<const std::uint8_t> Data, std::span<std::uint8_t> Out,
                  std::size_t &Consumed) -> Error
        {
            if (Data.size() < 18)
            {
                return Error::NeedMore;
            }
            auto Len = OpenLen(Data);
            if (!Len)
            {
                return Len.error();
            }
            if (*Len == 0)
            {
                Consumed = 18;
                return Error::None;
            }
            if (Data.size() < 18 + *Len + 16)
            {
                return Error::NeedMore;
            }
            const auto Ec = OpenPayload(Data.subspan(18, *Len + 16), Out);
            if (Ec != Error::None)
            {
                return Ec;
            }
            Consumed = 18 + *Len + 16;
            return Error::None;
        }

    private:
        std::array<std::uint8_t, 16> Key_;
        std::array<std::uint8_t, 12> Nonce_;
    };

    /**
     * @brief VMess 会话级分块流（Beast 风格封装）
     * @details 加密和解密方向各自维护独立 Nonce 状态。
     */
    class ChunkStream
    {
    public:
        /**
         * @brief 解密结果
         */
        struct Result
        {
            /// 错误码（Error::None 成功）
            std::error_code Ec;
            /// 已消耗 wire 字节数
            std::size_t Consumed{0};
        };

        /**
         * @brief 初始化
         * @param Key 16 字节分块密钥
         * @param Iv 16 字节分块 IV（Nonce 取前 12 字节）
         */
        auto Init(std::span<const std::uint8_t, 16> Key,
                  std::span<const std::uint8_t, 16> Iv) -> void
        {
            std::array<std::uint8_t, 12> Nonce{};
            std::memcpy(Nonce.data(), Iv.data(), 12);
            Enc_ = ChunkEncryptor(Key, Nonce);
            Dec_ = ChunkDecryptor(Key, Nonce);
        }

        /**
         * @brief 加密一块载荷
         * @param Payload 明文
         * @param Wire 输出密文
         * @return false 表示成功
         */
        auto Encrypt(std::span<const std::uint8_t> Payload, std::string &Wire) -> bool
        {
            std::vector<std::uint8_t> Out(Payload.size() + ChunkEncryptor::Overhead);
            const auto N = Enc_.Seal(Payload, Out);
            Wire.assign(reinterpret_cast<const char *>(Out.data()), N);
            return false;
        }

        /**
         * @brief 解密一块密文
         * @param Wire 密文（完整块）
         * @param Plain 输出明文
         * @return 解密结果
         */
        auto Decrypt(std::span<const std::uint8_t> Wire, std::string &Plain) -> Result
        {
            Result R;
            if (Wire.size() < 18)
            {
                R.Ec = make_error_code(Error::NeedMore);
                return R;
            }
            std::vector<std::uint8_t> Out(Wire.size());
            std::size_t Consumed = 0;
            const auto Ec = Dec_.Open(Wire, Out, Consumed);
            if (Ec != Error::None)
            {
                R.Ec = make_error_code(Ec);
                return R;
            }
            const auto PlainLen = Consumed >= 18 + 16 ? Consumed - 18 - 16 : 0;
            Plain.assign(reinterpret_cast<const char *>(Out.data()), PlainLen);
            R.Consumed = Consumed;
            return R;
        }

    private:
        ChunkEncryptor Enc_{std::array<std::uint8_t, 16>{}, std::array<std::uint8_t, 12>{}};
        ChunkDecryptor Dec_{std::array<std::uint8_t, 16>{}, std::array<std::uint8_t, 12>{}};
    };

} // namespace Preview::Vmess
