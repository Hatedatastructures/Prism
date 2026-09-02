/**
 * @file ChunkCodec.hpp
 * @brief Shadowsocks 2022 分块 AEAD 编解码状态机
 * @details 负责数据面长度块、载荷块、裸 AEAD 块和 Nonce 状态。
 *          地址/握手/UDP 数据报编解码由 Codec.hpp 负责。
 */

#pragma once

#include <openssl/evp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

#include <preview/Protocols/Shadowsocks2022/Types.hpp>

namespace Preview::Shadowsocks2022
{

    namespace detail
    {

        /**
         * @brief Nonce 小端 +1
         * @param Nonce Nonce（原地递增）
         */
        inline auto IncNonce(std::span<std::uint8_t> Nonce) -> void
        {
            for (auto &Byte : Nonce)
            {
                ++Byte;
                if (Byte != 0)
                {
                    break;
                }
            }
        }

        /**
         * @brief AEAD 加密并写入新缓冲
         * @param Key 密钥
         * @param Nonce Nonce
         * @param Plain 明文
         * @param Out 输出缓冲
         * @return 输出字节数，失败返回 0
         */
        template <typename Alloc>
        [[nodiscard]] inline auto AeadSeal(std::span<const std::uint8_t> Key,
                                           std::span<const std::uint8_t> Nonce,
                                           std::span<const std::uint8_t> Plain,
                                           std::vector<std::uint8_t, Alloc> &Out) -> std::size_t
        {
            Out.clear();
            Out.resize(Plain.size() + AeadTagLen);
            EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return 0;
            }
            int Len = 0;
            EVP_EncryptInit_ex(Ctx, EVP_aes_128_gcm(), nullptr, Key.data(), Nonce.data());
            EVP_EncryptUpdate(Ctx, Out.data(), &Len, Plain.data(), static_cast<int>(Plain.size()));
            int OutLen = Len;
            EVP_EncryptFinal_ex(Ctx, Out.data() + OutLen, &Len);
            OutLen += Len;
            EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_GET_TAG, 16, Out.data() + OutLen);
            Out.resize(static_cast<std::size_t>(OutLen) + AeadTagLen);
            EVP_CIPHER_CTX_free(Ctx);
            return Out.size();
        }

        /**
         * @brief AEAD 加密到已有缓冲的偏移处
         * @param Key 密钥
         * @param Nonce Nonce
         * @param Plain 明文
         * @param Out 输出缓冲
         * @param Offset 写入偏移
         * @return 写入字节数，失败返回 0
         */
        template <typename Alloc>
        [[nodiscard]] inline auto AeadSeal(std::span<const std::uint8_t> Key,
                                           std::span<const std::uint8_t> Nonce,
                                           std::span<const std::uint8_t> Plain,
                                           std::vector<std::uint8_t, Alloc> &Out,
                                           const std::size_t Offset) -> std::size_t
        {
            if (Out.size() < Offset + Plain.size() + AeadTagLen)
            {
                Out.resize(Offset + Plain.size() + AeadTagLen);
            }
            EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return 0;
            }
            int Len = 0;
            EVP_EncryptInit_ex(Ctx, EVP_aes_128_gcm(), nullptr, Key.data(), Nonce.data());
            EVP_EncryptUpdate(Ctx, Out.data() + Offset, &Len, Plain.data(),
                              static_cast<int>(Plain.size()));
            int OutLen = Len;
            EVP_EncryptFinal_ex(Ctx, Out.data() + Offset + OutLen, &Len);
            OutLen += Len;
            EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_GET_TAG, 16, Out.data() + Offset + OutLen);
            EVP_CIPHER_CTX_free(Ctx);
            return static_cast<std::size_t>(OutLen) + AeadTagLen;
        }

        /**
         * @brief AEAD 加密并返回独立缓冲
         */
        [[nodiscard]] inline auto AeadSeal(std::span<const std::uint8_t> Key,
                                           std::span<const std::uint8_t> Nonce,
                                           std::span<const std::uint8_t> Plain)
            -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> Out;
            (void)AeadSeal(Key, Nonce, Plain, Out);
            return Out;
        }

        /**
         * @brief AEAD 解密并返回独立缓冲
         * @param Key 密钥
         * @param Nonce Nonce
         * @param Cipher 密文（含 tag）
         * @return 明文；认证失败返回空
         */
        [[nodiscard]] inline auto AeadOpen(std::span<const std::uint8_t> Key,
                                           std::span<const std::uint8_t> Nonce,
                                           std::span<const std::uint8_t> Cipher)
            -> std::vector<std::uint8_t>
        {
            if (Cipher.size() < AeadTagLen)
            {
                return {};
            }
            std::vector<std::uint8_t> Out(Cipher.size() - AeadTagLen);
            EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return {};
            }
            int Len = 0;
            EVP_DecryptInit_ex(Ctx, EVP_aes_128_gcm(), nullptr, Key.data(), Nonce.data());
            EVP_DecryptUpdate(Ctx, Out.data(), &Len, Cipher.data(),
                              static_cast<int>(Cipher.size() - AeadTagLen));
            int OutLen = Len;
            EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(AeadTagLen),
                                const_cast<std::uint8_t *>(Cipher.data()) + Cipher.size() - AeadTagLen);
            const auto Ok = EVP_DecryptFinal_ex(Ctx, Out.data() + OutLen, &Len);
            OutLen += Len;
            EVP_CIPHER_CTX_free(Ctx);
            if (Ok != 1)
            {
                return {};
            }
            Out.resize(static_cast<std::size_t>(OutLen));
            return Out;
        }

        /**
         * @brief AEAD 解密到调用方复用缓冲
         */
        template <typename Alloc>
        [[nodiscard]] inline auto AeadOpen(std::span<const std::uint8_t> Key,
                                           std::span<const std::uint8_t> Nonce,
                                           std::span<const std::uint8_t> Cipher,
                                           std::vector<std::uint8_t, Alloc> &Out) -> bool
        {
            Out.clear();
            if (Cipher.size() < AeadTagLen)
            {
                return false;
            }
            Out.resize(Cipher.size() - AeadTagLen);
            EVP_CIPHER_CTX *Ctx = EVP_CIPHER_CTX_new();
            if (!Ctx)
            {
                return false;
            }
            int Len = 0;
            EVP_DecryptInit_ex(Ctx, EVP_aes_128_gcm(), nullptr, Key.data(), Nonce.data());
            EVP_DecryptUpdate(Ctx, Out.data(), &Len, Cipher.data(),
                              static_cast<int>(Cipher.size() - AeadTagLen));
            int OutLen = Len;
            EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(AeadTagLen),
                                const_cast<std::uint8_t *>(Cipher.data()) + Cipher.size() - AeadTagLen);
            const auto Ok = EVP_DecryptFinal_ex(Ctx, Out.data() + OutLen, &Len);
            OutLen += Len;
            EVP_CIPHER_CTX_free(Ctx);
            if (Ok != 1)
            {
                Out.clear();
                return false;
            }
            Out.resize(static_cast<std::size_t>(OutLen));
            return true;
        }

    } // namespace detail

    /**
     * @brief SS2022 AEAD 分块编解码器（状态机）
     */
    class ChunkCodec
    {
    public:
        /**
         * @brief 构造
         * @param Key 会话密钥
         * @param StartNonce 起始 Nonce 计数
         */
        explicit ChunkCodec(std::span<const std::uint8_t> Key, std::size_t StartNonce = 0)
            : Key_(Key.begin(), Key.end())
        {
            for (std::size_t I = 0; I < StartNonce; ++I)
            {
                detail::IncNonce(Nonce_);
            }
        }

        /**
         * @brief 加密单块到复用缓冲
         * @param Plain 明文
         * @param Out 输出缓冲
         * @return 写入字节数；0 = 失败
         */
        template <typename Alloc>
        [[nodiscard]] auto Seal(std::span<const std::uint8_t> Plain,
                                std::vector<std::uint8_t, Alloc> &Out) -> std::size_t
        {
            Out.clear();
            if (Plain.size() > MaxChunkSize)
            {
                return 0;
            }
            const auto StartNonce = Nonce_;
            const std::array<std::uint8_t, 2> LenPlain{
                static_cast<std::uint8_t>((Plain.size() >> 8) & 0xFF),
                static_cast<std::uint8_t>(Plain.size() & 0xFF)};
            const auto LenN = detail::AeadSeal(Key_, Nonce_, LenPlain, Out);
            if (LenN == 0)
            {
                Nonce_ = StartNonce;
                return 0;
            }
            detail::IncNonce(Nonce_);
            Out.resize(LenN + Plain.size() + AeadTagLen);
            if (detail::AeadSeal(Key_, Nonce_, Plain, Out, LenN) == 0)
            {
                Out.clear();
                Nonce_ = StartNonce;
                return 0;
            }
            detail::IncNonce(Nonce_);
            return Out.size();
        }

        /**
         * @brief 加密单块并返回独立缓冲
         */
        [[nodiscard]] auto Seal(std::span<const std::uint8_t> Plain)
            -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> Out;
            (void)Seal(Plain, Out);
            return Out;
        }

        /**
         * @brief 解密长度块
         * @return 载荷长度；认证失败返回空
         */
        [[nodiscard]] auto OpenLen(std::span<const std::uint8_t> Head)
            -> std::optional<std::size_t>
        {
            if (Head.size() < LenBlockSize)
            {
                return std::nullopt;
            }
            const auto LenPlain = detail::AeadOpen(Key_, Nonce_, Head.first(LenBlockSize));
            if (LenPlain.size() != 2)
            {
                return std::nullopt;
            }
            detail::IncNonce(Nonce_);
            const auto N = static_cast<std::size_t>(LenPlain[0]) << 8 | LenPlain[1];
            if (N > MaxChunkSize)
            {
                return std::nullopt;
            }
            return N;
        }

        /**
         * @brief 解密载荷块到复用缓冲
         */
        template <typename Alloc>
        [[nodiscard]] auto OpenPayload(std::span<const std::uint8_t> Data,
                                       std::vector<std::uint8_t, Alloc> &Out) -> std::size_t
        {
            Out.clear();
            if (Data.size() < AeadTagLen || !detail::AeadOpen(Key_, Nonce_, Data, Out))
            {
                return 0;
            }
            detail::IncNonce(Nonce_);
            return Out.size();
        }

        /**
         * @brief 解密载荷块并返回独立缓冲
         */
        [[nodiscard]] auto OpenPayload(std::span<const std::uint8_t> Data)
            -> std::vector<std::uint8_t>
        {
            std::vector<std::uint8_t> Out;
            (void)OpenPayload(Data, Out);
            return Out;
        }

        /**
         * @brief 解密单个完整分块
         * @param Data 完整块
         * @param Consumed 输出消耗字节数
         * @return 明文；失败或结束块返回空
         */
        [[nodiscard]] auto Open(std::span<const std::uint8_t> Data, std::size_t &Consumed)
            -> std::vector<std::uint8_t>
        {
            Consumed = 0;
            const auto StartNonce = Nonce_;
            auto Len = OpenLen(Data);
            if (!Len)
            {
                return {};
            }
            if (*Len == 0)
            {
                Consumed = LenBlockSize;
                return {};
            }
            if (Data.size() < LenBlockSize + *Len + AeadTagLen)
            {
                Nonce_ = StartNonce;
                return {};
            }
            auto Body = OpenPayload(Data.subspan(LenBlockSize, *Len + AeadTagLen));
            if (Body.empty())
            {
                Nonce_ = StartNonce;
                return {};
            }
            Consumed = LenBlockSize + *Len + AeadTagLen;
            return Body;
        }

        /**
         * @brief 加密裸块（握手头使用）
         */
        [[nodiscard]] auto SealRaw(std::span<const std::uint8_t> Plain)
            -> std::vector<std::uint8_t>
        {
            auto Out = detail::AeadSeal(Key_, Nonce_, Plain);
            if (!Out.empty())
            {
                detail::IncNonce(Nonce_);
            }
            return Out;
        }

        /**
         * @brief 解密裸块
         */
        [[nodiscard]] auto OpenRaw(std::span<const std::uint8_t> Data)
            -> std::vector<std::uint8_t>
        {
            auto Out = detail::AeadOpen(Key_, Nonce_, Data);
            if (!Out.empty())
            {
                detail::IncNonce(Nonce_);
            }
            return Out;
        }

        /**
         * @brief 解密裸块到复用缓冲
         */
        template <typename Alloc>
        [[nodiscard]] auto OpenRaw(std::span<const std::uint8_t> Data,
                                   std::vector<std::uint8_t, Alloc> &Out) -> bool
        {
            if (!detail::AeadOpen(Key_, Nonce_, Data, Out))
            {
                return false;
            }
            detail::IncNonce(Nonce_);
            return true;
        }

        /**
         * @brief 生成结束块
         */
        [[nodiscard]] auto Finish() -> std::vector<std::uint8_t>
        {
            return Seal({});
        }

    private:
        std::vector<std::uint8_t> Key_;
        std::array<std::uint8_t, 12> Nonce_{};
    };

} // namespace Preview::Shadowsocks2022
