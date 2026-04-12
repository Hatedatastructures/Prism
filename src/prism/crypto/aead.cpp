/**
 * @file aead.cpp
 * @brief AEAD 加密解密实现
 * @details 包装 BoringSSL EVP_AEAD API，支持 AES-128-GCM 和 AES-256-GCM。
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
            break;
        case aead_cipher::aes_256_gcm:
            aead = EVP_aead_aes_256_gcm();
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
        : ctx_(other.ctx_), nonce_(other.nonce_), key_length_(other.key_length_)
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
            other.ctx_ = nullptr;
            other.nonce_.fill(0);
        }
        return *this;
    }

    auto aead_context::seal(const std::span<std::uint8_t> out, const std::span<const std::uint8_t> plaintext,
                            const std::span<const std::uint8_t> ad)
        -> fault::code
    {
        std::size_t out_len = 0;
        const auto result = EVP_AEAD_CTX_seal(
            ctx_, out.data(), &out_len, out.size(),
            nonce_.data(), nonce_.size(),
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
            nonce_.data(), nonce_.size(),
            ciphertext.data(), ciphertext.size(),
            ad.data(), ad.size());

        if (!result)
        {
            return fault::code::crypto_error;
        }

        increment_nonce();
        return fault::code::success;
    }

    void aead_context::increment_nonce()
    {
        // SS2022 SIP022：nonce 小端序递增（sing-shadowsocks 实现从 byte[0] 开始进位）
        for (int i = 0; i < 12; ++i)
        {
            nonce_[i]++;
            if (nonce_[i] != 0)
            {
                break;
            }
        }
    }
} // namespace psm::crypto
