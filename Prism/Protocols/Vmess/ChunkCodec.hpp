/**
 * @file ChunkCodec.hpp
 * @brief VMess 分块 AEAD 编解码与流状态机
 * @details 该文件只负责数据面分块：长度块、载荷块、Nonce 推进以及
 *          ChunkStream 的增量封装。认证头和请求/响应头由 Codec.hpp 负责。
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Utility/Crypto/Aead.hpp>
#include <Prism/Protocols/Vmess/Types.hpp>
#include <Prism/Protocols/Vmess/ChunkMask.hpp>

namespace Prism::Vmess
{

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
            : Key_(), NonceSeed_(), LegacyNonce_(),
              Aead_(Prism::Crypto::AeadCipher::Aes128Gcm, Key),
              Options_(static_cast<std::uint8_t>(Option::AuthenticatedLength))
        {
            std::memcpy(Key_.data(), Key.data(), 16);
            std::memcpy(NonceSeed_.data(), Nonce.data(), 12);
            std::memcpy(LegacyNonce_.data(), Nonce.data(), 12);
        }

        /**
         * @brief 构造标准 VMess 数据块编码器
         * @param Key 16 字节数据层密钥
         * @param Nonce 16 字节 request/response nonce
         * @param OptionsValue 请求头 option 位
         */
        explicit ChunkEncryptor(std::span<const std::uint8_t, 16> Key,
                                std::span<const std::uint8_t, 16> Nonce,
                                std::uint8_t OptionsValue)
            : Key_(), NonceSeed_(), LegacyNonce_(),
              Aead_(Prism::Crypto::AeadCipher::Aes128Gcm, Key), Options_(OptionsValue)
        {
            std::memcpy(Key_.data(), Key.data(), 16);
            std::memcpy(NonceSeed_.data(), Nonce.data(), 16);
            std::memcpy(LegacyNonce_.data(), Nonce.data(), 12);
            if (detail::HasOption(Options_, Option::ChunkMasking))
            {
                MaskStream_.emplace(std::span<const std::uint8_t>(NonceSeed_));
            }
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
            if (N > (std::numeric_limits<std::size_t>::max)() - Overhead ||
                Out.size() < N + Overhead)
            {
                return 0;
            }

            if (!UseAuthenticatedLength())
            {
                const auto CipherLength = N + 16;
                if (CipherLength > 0xFFFF)
                {
                    return 0;
                }
                auto WireLength = static_cast<std::uint16_t>(CipherLength);
                WireLength ^= NextMask();
                Out[0] = static_cast<std::uint8_t>(WireLength >> 8);
                Out[1] = static_cast<std::uint8_t>(WireLength & 0xFF);
                const auto Nonce = detail::MakeNonce(NonceCount_, NonceSeed_);
                if (!SealChunk(Nonce, Plain, Out.subspan(2)))
                {
                    return 0;
                }
                ++NonceCount_;
                return 2 + CipherLength;
            }

            if (N > (std::numeric_limits<std::uint16_t>::max)())
            {
                return 0;
            }

            std::array<std::uint8_t, 2> LenPlain{};
            LenPlain[0] = static_cast<std::uint8_t>((N >> 8) & 0xFF);
            LenPlain[1] = static_cast<std::uint8_t>(N & 0xFF);
            std::array<std::uint8_t, 2 + 16> LenEnc{};
            auto NextNonce = LegacyNonce_;
            if (!SealChunk(NextNonce, LenPlain, LenEnc))
            {
                return 0;
            }
            detail::IncNonce(NextNonce);

            std::memcpy(Out.data(), LenEnc.data(), LenEnc.size());
            if (!SealChunk(NextNonce, Plain, Out.subspan(LenEnc.size())))
            {
                return 0;
            }
            detail::IncNonce(NextNonce);
            LegacyNonce_ = NextNonce;
            return LenEnc.size() + N + 16;
        }

        /**
         * @brief 结束块（长度 0）
         * @param Out 输出（容量至少为 18）
         * @return 写入字节数
         */
        auto Finish(std::span<std::uint8_t> Out) -> std::size_t
        {
            if (UseAuthenticatedLength())
            {
                return Seal({}, Out);
            }
            if (Out.size() < 2)
            {
                return 0;
            }
            auto WireLength = NextMask();
            Out[0] = static_cast<std::uint8_t>(WireLength >> 8);
            Out[1] = static_cast<std::uint8_t>(WireLength & 0xFF);
            return 2;
        }

    private:
        [[nodiscard]] auto SealChunk(std::span<const std::uint8_t> Nonce,
                                     std::span<const std::uint8_t> Plain,
                                     std::span<std::uint8_t> Out) -> bool
        {
            return Aead_.Seal(Prism::Crypto::SealInput{Out, Plain, Nonce, {}}) ==
                   Prism::Fault::Code::Success;
        }

        [[nodiscard]] auto UseAuthenticatedLength() const noexcept -> bool
        {
            return detail::HasOption(Options_, Option::AuthenticatedLength);
        }

        [[nodiscard]] auto NextMask() -> std::uint16_t
        {
            if (!MaskStream_)
            {
                return 0;
            }
            std::array<std::uint8_t, 2> Mask{};
            MaskStream_->Take(Mask);
            return static_cast<std::uint16_t>(Mask[0]) << 8 | Mask[1];
        }

        std::array<std::uint8_t, 16> Key_;
        std::array<std::uint8_t, 16> NonceSeed_;
        std::array<std::uint8_t, 12> LegacyNonce_;
        Prism::Crypto::AeadContext Aead_;
        std::uint8_t Options_{static_cast<std::uint8_t>(Option::AuthenticatedLength)};
        std::uint16_t NonceCount_{0};
        std::optional<ShakeStream> MaskStream_;
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
            : Key_(), NonceSeed_(), LegacyNonce_(),
              Aead_(Prism::Crypto::AeadCipher::Aes128Gcm, Key),
              Options_(static_cast<std::uint8_t>(Option::AuthenticatedLength))
        {
            std::memcpy(Key_.data(), Key.data(), 16);
            std::memcpy(NonceSeed_.data(), Nonce.data(), 12);
            std::memcpy(LegacyNonce_.data(), Nonce.data(), 12);
        }

        /**
         * @brief 构造标准 VMess 数据块解码器
         * @param Key 16 字节数据层密钥
         * @param Nonce 16 字节 request/response nonce
         * @param OptionsValue 请求头 option 位
         */
        explicit ChunkDecryptor(std::span<const std::uint8_t, 16> Key,
                                std::span<const std::uint8_t, 16> Nonce,
                                std::uint8_t OptionsValue)
            : Key_(), NonceSeed_(), LegacyNonce_(),
              Aead_(Prism::Crypto::AeadCipher::Aes128Gcm, Key), Options_(OptionsValue)
        {
            std::memcpy(Key_.data(), Key.data(), 16);
            std::memcpy(NonceSeed_.data(), Nonce.data(), 16);
            std::memcpy(LegacyNonce_.data(), Nonce.data(), 12);
            if (detail::HasOption(Options_, Option::ChunkMasking))
            {
                MaskStream_.emplace(std::span<const std::uint8_t>(NonceSeed_));
            }
        }

        /**
         * @brief 解密长度字段（2 字节密文 + 16 tag）
         * @param Head 18 字节块头
         * @return 载荷长度或错误码
         */
        auto OpenLen(std::span<const std::uint8_t> Head) -> std::expected<std::size_t, Error>
        {
            if (!UseAuthenticatedLength())
            {
                if (Head.size() < 2)
                {
                    return std::unexpected(Error::NeedMore);
                }
                std::uint16_t Length = static_cast<std::uint16_t>(Head[0]) << 8 | Head[1];
                Length ^= NextMask();
                if (Length > MaxChunkLen + 16)
                {
                    return std::unexpected(Error::BadLength);
                }
                return Length;
            }
            if (Head.size() < 18)
            {
                return std::unexpected(Error::NeedMore);
            }
            std::array<std::uint8_t, 2> LenPlain{};
            if (!OpenChunk(LegacyNonce_, Head.first(18), LenPlain))
            {
                return std::unexpected(Error::BadAuth);
            }
            detail::IncNonce(LegacyNonce_);
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
            if (UseAuthenticatedLength())
            {
                if (!OpenChunk(LegacyNonce_, Data, Out.first(Data.size() - 16)))
                {
                    return Error::BadAuth;
                }
                detail::IncNonce(LegacyNonce_);
                return Error::None;
            }
            const auto Nonce = detail::MakeNonce(NonceCount_, NonceSeed_);
            if (!OpenChunk(Nonce, Data, Out.first(Data.size() - 16)))
            {
                return Error::BadAuth;
            }
            ++NonceCount_;
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
            const bool AuthenticatedLength = UseAuthenticatedLength();
            std::size_t Minimum = 2;
            if (AuthenticatedLength)
            {
                Minimum = 18;
            }
            if (Data.size() < Minimum)
            {
                return Error::NeedMore;
            }
            const auto SavedLegacyNonce = LegacyNonce_;
            const auto SavedNonceCount = NonceCount_;
            const auto SavedMaskStream = MaskStream_;
            const auto RestoreState = [this, SavedLegacyNonce, SavedNonceCount, SavedMaskStream]() -> void
            {
                LegacyNonce_ = SavedLegacyNonce;
                NonceCount_ = SavedNonceCount;
                MaskStream_ = SavedMaskStream;
            };
            auto Len = OpenLen(Data);
            if (!Len)
            {
                RestoreState();
                return Len.error();
            }
            if (*Len == 0)
            {
                Consumed = Minimum;
                return Error::None;
            }
            const auto Prefix = Minimum;
            auto PayloadLength = *Len;
            if (AuthenticatedLength)
            {
                PayloadLength += 16;
            }
            if (Data.size() < Prefix + PayloadLength)
            {
                RestoreState();
                return Error::NeedMore;
            }
            const auto Ec = OpenPayload(Data.subspan(Prefix, PayloadLength), Out);
            if (Ec != Error::None)
            {
                RestoreState();
                return Ec;
            }
            Consumed = Prefix + PayloadLength;
            return Error::None;
        }

    private:
        [[nodiscard]] auto OpenChunk(std::span<const std::uint8_t> Nonce,
                                     std::span<const std::uint8_t> Cipher,
                                     std::span<std::uint8_t> Out) -> bool
        {
            return Aead_.Open(Prism::Crypto::OpenInput{Out, Cipher, Nonce, {}}) ==
                   Prism::Fault::Code::Success;
        }

        [[nodiscard]] auto UseAuthenticatedLength() const noexcept -> bool
        {
            return detail::HasOption(Options_, Option::AuthenticatedLength);
        }

        [[nodiscard]] auto NextMask() -> std::uint16_t
        {
            if (!MaskStream_)
            {
                return 0;
            }
            std::array<std::uint8_t, 2> Mask{};
            MaskStream_->Take(Mask);
            return static_cast<std::uint16_t>(Mask[0]) << 8 | Mask[1];
        }

        std::array<std::uint8_t, 16> Key_;
        std::array<std::uint8_t, 16> NonceSeed_;
        std::array<std::uint8_t, 12> LegacyNonce_;
        Prism::Crypto::AeadContext Aead_;
        std::uint8_t Options_{static_cast<std::uint8_t>(Option::AuthenticatedLength)};
        std::uint16_t NonceCount_{0};
        std::optional<ShakeStream> MaskStream_;
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
         * @return false 表示成功，true 表示加密失败
         */
        auto Encrypt(std::span<const std::uint8_t> Payload, std::string &Wire) -> bool
        {
            if (Payload.size() > (std::numeric_limits<std::size_t>::max)() - ChunkEncryptor::Overhead)
            {
                Wire.clear();
                return true;
            }
            std::vector<std::uint8_t> Out(Payload.size() + ChunkEncryptor::Overhead);
            const auto N = Enc_.Seal(Payload, Out);
            if (N == 0)
            {
                Wire.clear();
                return true;
            }
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
            std::size_t PlainLength = 0;
            if (Consumed >= 18 + 16)
            {
                PlainLength = Consumed - 18 - 16;
            }
            Plain.assign(reinterpret_cast<const char *>(Out.data()), PlainLength);
            R.Consumed = Consumed;
            return R;
        }

    private:
        ChunkEncryptor Enc_{std::array<std::uint8_t, 16>{}, std::array<std::uint8_t, 12>{}};
        ChunkDecryptor Dec_{std::array<std::uint8_t, 16>{}, std::array<std::uint8_t, 12>{}};
    };

} // namespace Prism::Vmess
