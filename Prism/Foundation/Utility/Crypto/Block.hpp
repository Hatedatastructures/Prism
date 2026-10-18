/**
 * @file Block.hpp
 * @brief AES-ECB 单块加解密的显式失败值接口。
 * @details 输入与密钥只借用至返回；结果拥有一个 16 字节块。
 *          无取消、半关闭、最终连接关闭或 executor 行为。
 */
#pragma once

#include <Prism/Foundation/Utility/Crypto/Operation.hpp>
#include <openssl/evp.h>
#include <array>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>

namespace Prism::Crypto
{
    namespace Detail
    {
        /** @brief 根据完整密钥长度选择 AES-ECB 算法，非法长度不创建上下文。 */
        [[nodiscard]] inline auto EcbCipher(const std::size_t Length) noexcept -> const EVP_CIPHER *
        {
            switch (Length)
            {
            case 16: return EVP_aes_128_ecb();
            case 24: return EVP_aes_192_ecb();
            case 32: return EVP_aes_256_ecb();
            default: return nullptr;
            }
        }
    }

    /**
     * @brief 将一个完整块加密为拥有型结果；成功算法为无填充 AES-128/192/256-ECB。
     * @return 非法密钥长度返回 InvalidArgument；分配或各阶段失败保留原生错误。
     * @details 上下文由本调用释放，临时块在所有返回路径擦除。
     */
    [[nodiscard]] inline auto EcbEncrypt(const std::span<const std::uint8_t, 16> Input,
                                       const std::span<const std::uint8_t> Key)
        -> std::expected<std::array<std::uint8_t, 16>, Fault::Failure>
    {
        const auto *Cipher = Detail::EcbCipher(Key.size());
        if (!Cipher)
        {
            return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument, {}});
        }
        ERR_clear_error();
        const std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> Context{
            EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free};
        if (!Context)
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::ResourceUnavailable));
        }
        if (EVP_EncryptInit_ex(Context.get(), Cipher, nullptr, Key.data(), nullptr) != 1 ||
            EVP_CIPHER_CTX_set_padding(Context.get(), 0) != 1)
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::CryptoError));
        }
        std::array<std::uint8_t, 16> Output{};
        const SecretScope OutputCleanup{Output};
        std::array<std::uint8_t, 16> FinalBlock{};
        const SecretScope FinalCleanup{FinalBlock};
        int Length = 0;
        if (EVP_EncryptUpdate(Context.get(), Output.data(), &Length, Input.data(), 16) != 1 ||
            Length != static_cast<int>(Output.size()))
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::CryptoError));
        }
        int FinalLength = 0;
        if (EVP_EncryptFinal_ex(Context.get(), FinalBlock.data(), &FinalLength) != 1 || FinalLength != 0)
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::CryptoError));
        }
        return Output;
    }

    /**
     * @brief 解密一个完整 AES-ECB 块；借用、拥有和关闭契约同 EcbEncrypt。
     * @return 长度非法返回 InvalidArgument，各原生阶段失败立即返回 Failure。
     */
    [[nodiscard]] inline auto EcbDecrypt(const std::span<const std::uint8_t, 16> Input,
                                       const std::span<const std::uint8_t> Key)
        -> std::expected<std::array<std::uint8_t, 16>, Fault::Failure>
    {
        const auto *Cipher = Detail::EcbCipher(Key.size());
        if (!Cipher)
        {
            return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument, {}});
        }
        ERR_clear_error();
        const std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> Context{
            EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free};
        if (!Context)
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::ResourceUnavailable));
        }
        if (EVP_DecryptInit_ex(Context.get(), Cipher, nullptr, Key.data(), nullptr) != 1 ||
            EVP_CIPHER_CTX_set_padding(Context.get(), 0) != 1)
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::CryptoError));
        }
        std::array<std::uint8_t, 16> Output{};
        const SecretScope OutputCleanup{Output};
        std::array<std::uint8_t, 16> FinalBlock{};
        const SecretScope FinalCleanup{FinalBlock};
        int Length = 0;
        if (EVP_DecryptUpdate(Context.get(), Output.data(), &Length, Input.data(), 16) != 1 ||
            Length != static_cast<int>(Output.size()))
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::CryptoError));
        }
        int FinalLength = 0;
        if (EVP_DecryptFinal_ex(Context.get(), FinalBlock.data(), &FinalLength) != 1 || FinalLength != 0)
        {
            return std::unexpected(Detail::NativeFailure(Fault::Code::CryptoError));
        }
        return Output;
    }
}
