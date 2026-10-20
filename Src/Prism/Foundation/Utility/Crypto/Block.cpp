/**
 * @file Block.cpp
 * @brief AES-ECB 单块加解密实现。
 */
#include <Prism/Foundation/Utility/Crypto/Block.hpp>

#include <openssl/err.h>

#include <memory>

namespace Prism::Crypto::Detail
{
    auto EcbCipher(const std::size_t Length) noexcept -> const EVP_CIPHER *
    {
        switch (Length)
        {
        case 16: return EVP_aes_128_ecb();
        case 24: return EVP_aes_192_ecb();
        case 32: return EVP_aes_256_ecb();
        default: return nullptr;
        }
    }
} // namespace Prism::Crypto::Detail

namespace Prism::Crypto
{
    auto EcbEncrypt(const std::span<const std::uint8_t, 16> Input,
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

    auto EcbDecrypt(const std::span<const std::uint8_t, 16> Input,
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
} // namespace Prism::Crypto
