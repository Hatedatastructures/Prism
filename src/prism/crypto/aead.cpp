#include <prism/crypto/aead.hpp>

#include <prism/trace/spdlog.hpp>

#include <openssl/evp.h>

#include <cstring>
#include <memory>

namespace psm::crypto
{

    void aead_context::release_ctx(evp_aead_ctx_st *ctx) noexcept
    {
        if (ctx)
        {
            EVP_AEAD_CTX_cleanup(ctx);
            delete ctx;
        }
    }


    aead_context::aead_context(const aead_cipher cipher, const std::span<const std::uint8_t> key)
        : ctx_(nullptr, &release_ctx), key_length_(key.size())
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
        default:
            trace::error("[Crypto.AEAD] 未知加密算法: {}", static_cast<std::int32_t>(cipher));
            return;
        }

        if (!aead)
        {
            trace::error("[Crypto.AEAD] 获取 AEAD 算法失败");
            return;
        }

        auto *raw_ctx = new EVP_AEAD_CTX;
        EVP_AEAD_CTX_zero(raw_ctx);
        if (!EVP_AEAD_CTX_init(raw_ctx, aead, key.data(), key.size(), EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr))
        {
            trace::error("[Crypto.AEAD] EVP_AEAD_CTX_init 失败");
            EVP_AEAD_CTX_cleanup(raw_ctx);
            delete raw_ctx;
            return;
        }
        ctx_.reset(raw_ctx);
    }


    aead_context::~aead_context() = default;


    aead_context::aead_context(aead_context &&other) noexcept
        : ctx_(std::move(other.ctx_)), nonce_(other.nonce_), key_length_(other.key_length_), nonce_len_(other.nonce_len_)
    {
        other.nonce_.fill(0);
    }


    auto aead_context::operator=(aead_context &&other) noexcept
        -> aead_context &
    {
        if (this != &other)
        {
            ctx_ = std::move(other.ctx_);
            nonce_ = other.nonce_;
            key_length_ = other.key_length_;
            nonce_len_ = other.nonce_len_;
            other.nonce_.fill(0);
        }
        return *this;
    }


    auto aead_context::seal(const std::span<std::uint8_t> out, const std::span<const std::uint8_t> plaintext,
                            const std::span<const std::uint8_t> ad)
        -> fault::code
    {
        if (!ctx_)
        {
            return fault::code::crypto_error;
        }

        std::size_t out_len = 0;
        const auto result = EVP_AEAD_CTX_seal(
            ctx_.get(), out.data(), &out_len, out.size(),
            nonce_.data(), nonce_len_,
            plaintext.data(), plaintext.size(),
            ad.data(), ad.size());

        if (!result)
        {
            return fault::code::crypto_error;
        }

        if (!increment_nonce())
        {
            trace::error("[Crypto.AEAD] seal nonce 溢出");
            return fault::code::crypto_error;
        }
        return fault::code::success;
    }


    auto aead_context::open(const std::span<std::uint8_t> out, const std::span<const std::uint8_t> ciphertext,
                            const std::span<const std::uint8_t> ad)
        -> fault::code
    {
        if (!ctx_)
        {
            return fault::code::crypto_error;
        }

        std::size_t out_len = 0;
        const auto result = EVP_AEAD_CTX_open(
            ctx_.get(), out.data(), &out_len, out.size(),
            nonce_.data(), nonce_len_,
            ciphertext.data(), ciphertext.size(),
            ad.data(), ad.size());

        if (!result)
        {
            return fault::code::crypto_error;
        }

        if (!increment_nonce())
        {
            trace::error("[Crypto.AEAD] open nonce 溢出");
            return fault::code::crypto_error;
        }
        return fault::code::success;
    }


    auto aead_context::seal(seal_input input)
        -> fault::code
    {
        if (!ctx_)
        {
            return fault::code::crypto_error;
        }

        std::size_t out_len = 0;
        const auto result = EVP_AEAD_CTX_seal(
            ctx_.get(), input.out.data(), &out_len, input.out.size(),
            input.nonce.data(), input.nonce.size(),
            input.plaintext.data(), input.plaintext.size(),
            input.ad.data(), input.ad.size());

        if (!result)
        {
            return fault::code::crypto_error;
        }

        return fault::code::success;
    }


    auto aead_context::open(open_input input)
        -> fault::code
    {
        if (!ctx_)
        {
            return fault::code::crypto_error;
        }

        std::size_t out_len = 0;
        const auto result = EVP_AEAD_CTX_open(
            ctx_.get(), input.out.data(), &out_len, input.out.size(),
            input.nonce.data(), input.nonce.size(),
            input.ciphertext.data(), input.ciphertext.size(),
            input.ad.data(), input.ad.size());

        if (!result)
        {
            return fault::code::crypto_error;
        }

        return fault::code::success;
    }


    auto aead_context::increment_nonce() -> bool
    {
        for (std::size_t i = 0; i < nonce_len_; ++i)
        {
            nonce_[i]++;
            if (nonce_[i] != 0)
            {
                return true;
            }
        }
        return false;
    }

} // namespace psm::crypto
