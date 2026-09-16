/**
 * @file ChunkCodec.hpp
 * @brief VMess 分块 AEAD 编解码与流状态机
 * @details 该文件只负责数据面分块：长度块、载荷块、Nonce 推进以及
 *          ChunkStream 的增量封装。认证头和请求/响应头由 Codec.hpp 负责。
 */

#pragma once

#include <openssl/evp.h>

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

#include <Preview/Foundation/Error.hpp>
#include <Preview/Protocols/Vmess/Types.hpp>

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
         * @return 密封成功返回 true；参数或 OpenSSL 失败返回 false
         */
        [[nodiscard]] inline auto ChunkSeal(
            std::span<const std::uint8_t> Key,
            std::span<const std::uint8_t, 12> Nonce,
            std::span<const std::uint8_t> Plain,
            std::span<std::uint8_t> Out) -> bool
        {
            constexpr auto AeadTagLength = std::size_t{16};
            constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
            if (Key.size() != 16 ||
                Plain.size() > MaxInt ||
                Plain.size() > (std::numeric_limits<std::size_t>::max)() - AeadTagLength ||
                Out.size() < Plain.size() + AeadTagLength)
            {
                return false;
            }
            EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return false;
            }
            int Len = 0;
            bool Ok = EVP_EncryptInit_ex(Ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1;
            Ok = Ok && EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1;
            Ok = Ok && EVP_EncryptInit_ex(Ctx, nullptr, nullptr, Key.data(), Nonce.data()) == 1;
            int OutputLength = 0;
            if (Ok && !Plain.empty())
            {
                Ok = EVP_EncryptUpdate(
                         Ctx, Out.data(), &Len, Plain.data(), static_cast<int>(Plain.size())) == 1;
                OutputLength = Len;
            }
            if (Ok)
            {
                Ok = EVP_EncryptFinal_ex(Ctx, Out.data() + OutputLength, &Len) == 1;
                OutputLength += Len;
            }
            if (Ok)
            {
                Ok = EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_GET_TAG, 16, Out.data() + OutputLength) == 1;
            }
            Ok = Ok && OutputLength == static_cast<int>(Plain.size());
            EVP_CIPHER_CTX_free(Ctx);
            return Ok;
        }

        /**
         * @brief 单次 AES-128-GCM 解密
         * @param Key 密钥
         * @param Nonce 12 字节 Nonce
         * @param Cipher 密文（含 tag）
         * @param Out 输出明文
         * @return 校验成功返回 true
         */
        [[nodiscard]] inline auto ChunkOpen(
            std::span<const std::uint8_t> Key,
            std::span<const std::uint8_t, 12> Nonce,
            std::span<const std::uint8_t> Cipher,
            std::span<std::uint8_t> Out) -> bool
        {
            constexpr auto AeadTagLength = std::size_t{16};
            constexpr auto MaxInt = static_cast<std::size_t>((std::numeric_limits<int>::max)());
            if (Key.size() != 16 || Cipher.size() < AeadTagLength)
            {
                return false;
            }
            const auto CipherLength = Cipher.size() - AeadTagLength;
            if (CipherLength > MaxInt || Out.size() < CipherLength)
            {
                return false;
            }
            EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return false;
            }
            int Len = 0;
            bool Ok = EVP_DecryptInit_ex(Ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1;
            Ok = Ok && EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1;
            Ok = Ok && EVP_DecryptInit_ex(Ctx, nullptr, nullptr, Key.data(), Nonce.data()) == 1;
            int OutputLength = 0;
            if (Ok && CipherLength > 0)
            {
                Ok = EVP_DecryptUpdate(
                         Ctx, Out.data(), &Len, Cipher.data(), static_cast<int>(CipherLength)) == 1;
                OutputLength = Len;
            }
            if (Ok)
            {
                Ok = EVP_CIPHER_CTX_ctrl(
                         Ctx,
                         EVP_CTRL_GCM_SET_TAG,
                         16,
                         const_cast<std::uint8_t *>(Cipher.data()) + CipherLength) == 1;
            }
            if (Ok)
            {
                std::array<std::uint8_t, 16> FinalOutput{};
                std::uint8_t *FinalData = nullptr;
                if (Out.empty())
                {
                    FinalData = FinalOutput.data();
                }
                else
                {
                    FinalData = Out.data() + OutputLength;
                }
                Ok = EVP_DecryptFinal_ex(Ctx, FinalData, &Len) == 1;
                OutputLength += Len;
            }
            EVP_CIPHER_CTX_free(Ctx);
            return Ok && OutputLength == static_cast<int>(CipherLength);
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

        [[nodiscard]] inline auto HasOption(std::uint8_t Options, Option Value) noexcept -> bool
        {
            return (Options & static_cast<std::uint8_t>(Value)) != 0;
        }

        [[nodiscard]] inline auto MakeNonce(std::uint16_t Count,
                                            std::span<const std::uint8_t, 16> Seed)
            -> std::array<std::uint8_t, 12>
        {
            std::array<std::uint8_t, 12> Nonce{};
            Nonce[0] = static_cast<std::uint8_t>(Count >> 8);
            Nonce[1] = static_cast<std::uint8_t>(Count & 0xFF);
            std::memcpy(Nonce.data() + 2, Seed.data() + 2, 10);
            return Nonce;
        }

    } // namespace detail

    /**
     * @class ShakeStream
     * @brief 与 Go sha3.Shake128 兼容的增量 XOF
     * @details VMess ChunkMasking 使用 request nonce 派生的 SHAKE128
     *          连续字节流。实现保留在 Preview codec 内，避免把生产实现
     *          作为编译依赖。
     */
    class ShakeStream
    {
    public:
        explicit ShakeStream(std::span<const std::uint8_t> Seed)
        {
            std::size_t Offset = 0;
            auto *Block = reinterpret_cast<std::uint8_t *>(State_.data());
            while (Seed.size() - Offset >= Rate)
            {
                for (std::size_t Index = 0; Index < Rate; ++Index)
                {
                    Block[Index] ^= Seed[Offset + Index];
                }
                Permute(State_);
                Offset += Rate;
            }
            const auto Remaining = Seed.size() - Offset;
            for (std::size_t Index = 0; Index < Remaining; ++Index)
            {
                Block[Index] ^= Seed[Offset + Index];
            }
            Block[Remaining] ^= 0x1F;
            Block[Rate - 1] ^= 0x80;
            Permute(State_);
        }

        auto Take(std::span<std::uint8_t> Output) -> void
        {
            std::size_t Offset = 0;
            while (Offset < Output.size())
            {
                if (Cursor_ == Rate)
                {
                    std::memcpy(Buffer_.data(), State_.data(), Rate);
                    Permute(State_);
                    Cursor_ = 0;
                }
                const auto Count = (std::min)(Rate - Cursor_, Output.size() - Offset);
                std::memcpy(Output.data() + Offset, Buffer_.data() + Cursor_, Count);
                Cursor_ += Count;
                Offset += Count;
            }
        }

    private:
        static constexpr std::size_t Rate = 168;
        static constexpr std::array<std::uint64_t, 24> RoundConstants{
            0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
            0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
            0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
            0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
            0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
            0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
            0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
            0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

        [[nodiscard]] static constexpr auto Rotate(std::uint64_t Value, int Count) noexcept
            -> std::uint64_t
        {
            if (Count == 0)
            {
                return Value;
            }
            return (Value << Count) | (Value >> (64 - Count));
        }

        static auto Permute(std::array<std::uint64_t, 25> &State) noexcept -> void
        {
            static constexpr std::array<int, 24> Piln{
                10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};
            static constexpr std::array<int, 24> Rotc{
                1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
            for (const auto RoundConstant : RoundConstants)
            {
                std::array<std::uint64_t, 5> Column{};
                for (std::size_t Index = 0; Index < 5; ++Index)
                {
                    Column[Index] = State[Index] ^ State[Index + 5] ^ State[Index + 10] ^
                                    State[Index + 15] ^ State[Index + 20];
                }
                for (std::size_t Index = 0; Index < 5; ++Index)
                {
                    const auto Delta = Column[(Index + 4) % 5] ^ Rotate(Column[(Index + 1) % 5], 1);
                    for (std::size_t Row = 0; Row < 25; Row += 5)
                    {
                        State[Row + Index] ^= Delta;
                    }
                }

                auto Temporary = State[1];
                for (std::size_t Index = 0; Index < Piln.size(); ++Index)
                {
                    const auto Position = static_cast<std::size_t>(Piln[Index]);
                    const auto Saved = State[Position];
                    State[Position] = Rotate(Temporary, Rotc[Index]);
                    Temporary = Saved;
                }

                for (std::size_t Row = 0; Row < 25; Row += 5)
                {
                    std::array<std::uint64_t, 5> Saved{};
                    for (std::size_t Index = 0; Index < 5; ++Index)
                    {
                        Saved[Index] = State[Row + Index];
                    }
                    for (std::size_t Index = 0; Index < 5; ++Index)
                    {
                        State[Row + Index] = Saved[Index] ^
                                             ((~Saved[(Index + 1) % 5]) & Saved[(Index + 2) % 5]);
                    }
                }
                State[0] ^= RoundConstant;
            }
        }

        std::array<std::uint64_t, 25> State_{};
        std::array<std::uint8_t, Rate> Buffer_{};
        std::size_t Cursor_{Rate};
    };

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
            : Key_(), NonceSeed_(), LegacyNonce_(), Options_(static_cast<std::uint8_t>(Option::AuthenticatedLength))
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
            : Key_(), NonceSeed_(), LegacyNonce_(), Options_(OptionsValue)
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
                if (!detail::ChunkSeal(Key_, Nonce, Plain, Out.subspan(2)))
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
            if (!detail::ChunkSeal(Key_, NextNonce, LenPlain, LenEnc))
            {
                return 0;
            }
            detail::IncNonce(NextNonce);

            std::memcpy(Out.data(), LenEnc.data(), LenEnc.size());
            if (!detail::ChunkSeal(Key_, NextNonce, Plain, Out.subspan(LenEnc.size())))
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
            : Key_(), NonceSeed_(), LegacyNonce_(), Options_(static_cast<std::uint8_t>(Option::AuthenticatedLength))
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
            : Key_(), NonceSeed_(), LegacyNonce_(), Options_(OptionsValue)
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
            if (!detail::ChunkOpen(Key_, LegacyNonce_, Head.first(18), LenPlain))
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
                if (!detail::ChunkOpen(Key_, LegacyNonce_, Data, Out.first(Data.size() - 16)))
                {
                    return Error::BadAuth;
                }
                detail::IncNonce(LegacyNonce_);
                return Error::None;
            }
            const auto Nonce = detail::MakeNonce(NonceCount_, NonceSeed_);
            if (!detail::ChunkOpen(Key_, Nonce, Data, Out.first(Data.size() - 16)))
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

} // namespace Preview::Vmess
