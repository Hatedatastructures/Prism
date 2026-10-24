/**
 * @file Aead.cpp
 * @brief AEAD 加密解密实现。
 */
#include <Prism/Foundation/Utility/Crypto/Aead.hpp>

#include <openssl/aead.h>
#include <openssl/evp.h>
#include <openssl/mem.h>

#include <utility>

namespace Prism::Crypto
{
    auto AeadContext::ReleaseCtx(evp_aead_ctx_st *Context) noexcept -> void
    {
        if (Context)
        {
            EVP_AEAD_CTX_cleanup(Context);
            delete Context;
        }
    }

    AeadContext::AeadContext(const AeadCipher Cipher, const std::span<const std::uint8_t> Key)
        : Ctx_(nullptr, &ReleaseCtx), KeyLength_(Key.size())
    {
        const EVP_AEAD *Aead = nullptr;
        switch (Cipher)
        {
        case AeadCipher::Aes128Gcm:
            Aead = EVP_aead_aes_128_gcm();
            NonceLen_ = 12;
            break;
        case AeadCipher::Aes256Gcm:
            Aead = EVP_aead_aes_256_gcm();
            NonceLen_ = 12;
            break;
        case AeadCipher::Chacha20Poly1305:
            Aead = EVP_aead_chacha20_poly1305();
            NonceLen_ = 12;
            break;
        case AeadCipher::Xchacha20Poly1305:
            Aead = EVP_aead_xchacha20_poly1305();
            NonceLen_ = 24;
            break;
        default: return;
        }

        if (!Aead)
        {
            return;
        }

        auto *RawCtx = new EVP_AEAD_CTX;
        EVP_AEAD_CTX_zero(RawCtx);
        if (!EVP_AEAD_CTX_init(RawCtx, Aead, Key.data(), Key.size(), EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr))
        {
            EVP_AEAD_CTX_cleanup(RawCtx);
            delete RawCtx;
            return;
        }
        Ctx_.reset(RawCtx);
    }

    AeadContext::~AeadContext() noexcept = default;

    AeadContext::AeadContext(AeadContext&& other) noexcept
        : Ctx_(std::move(other.Ctx_)), Nonce_(other.Nonce_), KeyLength_(other.KeyLength_),
          NonceLen_(other.NonceLen_)
    {
        other.Nonce_.fill(0);
    }

    auto AeadContext::operator=(AeadContext&& other) noexcept -> AeadContext&
    {
        if (this != &other)
        {
            Ctx_ = std::move(other.Ctx_);
            Nonce_ = other.Nonce_;
            KeyLength_ = other.KeyLength_;
            NonceLen_ = other.NonceLen_;
            other.Nonce_.fill(0);
        }
        return *this;
    }

    auto AeadContext::ClearOutput(const std::span<std::uint8_t> Out) noexcept -> void
    {
        if (!Out.empty())
        {
            OPENSSL_cleanse(Out.data(), Out.size());
        }
    }

    auto AeadContext::Seal(std::span<std::uint8_t> Out,
        const std::span<const std::uint8_t> Plaintext,
        const std::span<const std::uint8_t> AdditionalData) -> Fault::Code
    {
        constexpr auto MaxSize = std::numeric_limits<std::size_t>::max();
        if (!Ctx_ || IsNonceExhausted() || Plaintext.size() > MaxSize - TagLength())
        {
            return Fault::Code::CryptoError;
        }

        const auto RequiredSize = SealSize(Plaintext.size());
        if (Out.size() < RequiredSize)
        {
            return Fault::Code::CryptoError;
        }

        std::size_t OutLen = 0;
        const auto Result =
            EVP_AEAD_CTX_seal(Ctx_.get(), Out.data(), &OutLen, Out.size(), Nonce_.data(), NonceLen_,
                Plaintext.data(), Plaintext.size(), AdditionalData.data(), AdditionalData.size());

        if (!Result)
        {
            return Fault::Code::CryptoError;
        }

        if (OutLen != RequiredSize)
        {
            ClearOutput(Out);
            return Fault::Code::CryptoError;
        }

        IncrementNonce();
        return Fault::Code::Success;
    }

    auto AeadContext::Open(std::span<std::uint8_t> Out,
        const std::span<const std::uint8_t> Ciphertext,
        const std::span<const std::uint8_t> AdditionalData) -> Fault::Code
    {
        if (!Ctx_ || IsNonceExhausted() || Ciphertext.size() < TagLength())
        {
            return Fault::Code::CryptoError;
        }

        const auto RequiredSize = OpenSize(Ciphertext.size());
        if (Out.size() < RequiredSize)
        {
            return Fault::Code::CryptoError;
        }

        std::uint8_t EmptyOutput = 0;
        auto *OutputData = Out.data();
        if (Out.empty())
        {
            OutputData = &EmptyOutput;
        }
        std::size_t OutLen = 0;
        const auto Result =
            EVP_AEAD_CTX_open(Ctx_.get(), OutputData, &OutLen, Out.size(), Nonce_.data(), NonceLen_,
                Ciphertext.data(), Ciphertext.size(), AdditionalData.data(), AdditionalData.size());

        if (!Result)
        {
            return Fault::Code::CryptoError;
        }

        if (OutLen != RequiredSize)
        {
            ClearOutput(Out);
            return Fault::Code::CryptoError;
        }

        IncrementNonce();
        return Fault::Code::Success;
    }

    auto AeadContext::Seal(const SealInput Input) -> Fault::Code
    {
        constexpr auto MaxSize = std::numeric_limits<std::size_t>::max();
        if (!Ctx_ || Input.Nonce.size() != NonceLen_ || Input.Plaintext.size() > MaxSize - TagLength())
        {
            return Fault::Code::CryptoError;
        }

        const auto RequiredSize = SealSize(Input.Plaintext.size());
        if (Input.Out.size() < RequiredSize)
        {
            return Fault::Code::CryptoError;
        }

        std::size_t OutLen = 0;
        const auto Result = EVP_AEAD_CTX_seal(Ctx_.get(), Input.Out.data(), &OutLen, Input.Out.size(),
            Input.Nonce.data(), Input.Nonce.size(), Input.Plaintext.data(), Input.Plaintext.size(),
            Input.AdditionalData.data(), Input.AdditionalData.size());

        if (!Result)
        {
            return Fault::Code::CryptoError;
        }

        if (OutLen != RequiredSize)
        {
            ClearOutput(Input.Out);
            return Fault::Code::CryptoError;
        }

        return Fault::Code::Success;
    }

    auto AeadContext::Open(const OpenInput Input) -> Fault::Code
    {
        if (!Ctx_ || Input.Nonce.size() != NonceLen_ || Input.Ciphertext.size() < TagLength())
        {
            return Fault::Code::CryptoError;
        }

        const auto RequiredSize = OpenSize(Input.Ciphertext.size());
        if (Input.Out.size() < RequiredSize)
        {
            return Fault::Code::CryptoError;
        }

        std::uint8_t EmptyOutput = 0;
        auto *OutputData = Input.Out.data();
        if (Input.Out.empty())
        {
            OutputData = &EmptyOutput;
        }
        std::size_t OutLen = 0;
        const auto Result = EVP_AEAD_CTX_open(Ctx_.get(), OutputData, &OutLen, Input.Out.size(),
            Input.Nonce.data(), Input.Nonce.size(), Input.Ciphertext.data(), Input.Ciphertext.size(),
            Input.AdditionalData.data(), Input.AdditionalData.size());

        if (!Result)
        {
            return Fault::Code::CryptoError;
        }

        if (OutLen != RequiredSize)
        {
            ClearOutput(Input.Out);
            return Fault::Code::CryptoError;
        }

        return Fault::Code::Success;
    }

    auto AeadContext::IncrementNonce() noexcept -> void
    {
        for (std::size_t I = 0; I < NonceLen_; ++I)
        {
            Nonce_[I]++;
            if (Nonce_[I] != 0)
            {
                return;
            }
        }
    }

    auto AeadContext::IsNonceExhausted() const noexcept -> bool
    {
        for (std::size_t I = 0; I < NonceLen_; ++I)
        {
            if (Nonce_[I] != 0xFF)
            {
                return false;
            }
        }
        return true;
    }
} // namespace Prism::Crypto
