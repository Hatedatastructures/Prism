/**
 * @file aead.cpp
 * @brief AEAD 加密解密实现
 * @details 包装 BoringSSL EVP_AEAD API，支持 AES-128-GCM、AES-256-GCM、
 * ChaCha20-Poly1305、XChaCha20-Poly1305。
 */

#include <prism/crypto/aead.hpp>
#include <prism/trace/spdlog.hpp>
#include <openssl/evp.h>
#include <cstring>

namespace psm::crypto
{
    aead_context::aead_context(const aead_cipher cipher, const std::span<const std::uint8_t> key)
        : key_length_(key.size())
    {
        const EVP_AEAD *aead = nullptr;
        switch (cipher)
        {
        case aead_cipher::aes_128_gcm:
            aead = EVP_aead_aes_128_gcm();
            nonce_len_ = 12;
            break;
        case aead_cipher::aes_256_gcm:
            aead = EVP_aead_aes_256_gcm();
            nonce_len_ = 12;
            break;
        case aead_cipher::chacha20_poly1305:
            aead = EVP_aead_chacha20_poly1305();
            nonce_len_ = 12;
            break;
        case aead_cipher::xchacha20_poly1305:
            aead = EVP_aead_xchacha20_poly1305();
            nonce_len_ = 24;
            break;
        }

        ctx_ = new EVP_AEAD_CTX;
        EVP_AEAD_CTX_zero(ctx_);
        EVP_AEAD_CTX_init(ctx_, aead, key.data(), key.size(), EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr);
    }

    aead_context::~aead_context()
    {
        if (ctx_)
        {
            EVP_AEAD_CTX_cleanup(ctx_);
            delete ctx_;
        }
    }

    aead_context::aead_context(aead_context &&other) noexcept
        : ctx_(other.ctx_), nonce_(other.nonce_), key_length_(other.key_length_), nonce_len_(other.nonce_len_)
    {
        other.ctx_ = nullptr;
        other.nonce_.fill(0);
    }

    auto aead_context::operator=(aead_context &&other) noexcept -> aead_context &
    {
        if (this != &other)
        {
            if (ctx_)
            {
                EVP_AEAD_CTX_cleanup(ctx_);
                delete ctx_;
            }
            ctx_ = other.ctx_;
            nonce_ = other.nonce_;
            key_length_ = other.key_length_;
            nonce_len_ = other.nonce_len_;
            other.ctx_ = nullptr;
            other.nonce_.fill(0);
        }
        return *this;
    }

    // === 自动递增 nonce 版本 ===

    auto aead_context::seal(const std::span<std::uint8_t> out, const std::span<const std::uint8_t> plaintext,
                            const std::span<const std::uint8_t> ad)
        -> fault::code
    {
        std::size_t out_len = 0;
        const auto result = EVP_AEAD_CTX_seal(
            ctx_, out.data(), &out_len, out.size(),
            nonce_.data(), nonce_len_,
            plaintext.data(), plaintext.size(),
            ad.data(), ad.size());

        if (!result)
        {
            return fault::code::crypto_error;
        }

        increment_nonce();
        return fault::code::success;
    }

    auto aead_context::open(const std::span<std::uint8_t> out, const std::span<const std::uint8_t> ciphertext,
                            const std::span<const std::uint8_t> ad)
        -> fault::code
    {
        std::size_t out_len = 0;
        const auto result = EVP_AEAD_CTX_open(
            ctx_, out.data(), &out_len, out.size(),
            nonce_.data(), nonce_len_,
            ciphertext.data(), ciphertext.size(),
            ad.data(), ad.size());

        if (!result)
        {
            return fault::code::crypto_error;
        }

        increment_nonce();
        return fault::code::success;
    }

    // === 显式 nonce 版本（不修改内部状态） ===

    auto aead_context::seal(const std::span<std::uint8_t> out, const std::span<const std::uint8_t> plaintext,
                            const std::span<const std::uint8_t> nonce, const std::span<const std::uint8_t> ad)
        -> fault::code
    {
        std::size_t out_len = 0;
        const auto result = EVP_AEAD_CTX_seal(
            ctx_, out.data(), &out_len, out.size(),
            nonce.data(), nonce.size(),
            plaintext.data(), plaintext.size(),
            ad.data(), ad.size());

        if (!result)
        {
            return fault::code::crypto_error;
        }

        return fault::code::success;
    }

    auto aead_context::open(const std::span<std::uint8_t> out, const std::span<const std::uint8_t> ciphertext,
                            const std::span<const std::uint8_t> nonce, const std::span<const std::uint8_t> ad)
        -> fault::code
    {
        std::size_t out_len = 0;
        const auto result = EVP_AEAD_CTX_open(
            ctx_, out.data(), &out_len, out.size(),
            nonce.data(), nonce.size(),
            ciphertext.data(), ciphertext.size(),
            ad.data(), ad.size());

        if (!result)
        {
            return fault::code::crypto_error;
        }

        return fault::code::success;
    }

    void aead_context::increment_nonce()
    {
        // SS2022 SIP022：nonce 小端序递增（从 byte[0] 开始进位）
        for (std::size_t i = 0; i < nonce_len_; ++i)
        {
            nonce_[i]++;
            if (nonce_[i] != 0)
            {
                break;
            }
        }
    }
} // namespace psm::crypto
