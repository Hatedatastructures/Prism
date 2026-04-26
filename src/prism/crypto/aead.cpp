#include <prism/crypto/aead.hpp>
#include <prism/trace/spdlog.hpp>
#include <openssl/evp.h>
#include <memory>
#include <cstring>

namespace psm::crypto
{
    // 删除器实现
    void aead_context::delete_aead_ctx(evp_aead_ctx_st *ctx) noexcept
    {
        if (ctx)
        {
            EVP_AEAD_CTX_cleanup(ctx);
            delete ctx;
        }
    }

    // 构造时根据算法类型选择对应的 BoringSSL AEAD 实现，并用密钥初始化上下文。
    // AES-GCM 和 ChaCha20 的 nonce 都是 12 字节，XChaCha20 扩展到 24 字节。
    // EVP_AEAD_CTX 是 BoringSSL 的不透明结构，用 unique_ptr + 函数指针删除器管理生命周期。
    aead_context::aead_context(const aead_cipher cipher, const std::span<const std::uint8_t> key)
        : ctx_(nullptr, &delete_aead_ctx), key_length_(key.size())
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
            trace::error("[Crypto.AEAD] unknown cipher type: {}", static_cast<int>(cipher));
            return;
        }

        if (!aead)
        {
            trace::error("[Crypto.AEAD] failed to get AEAD algorithm");
            return;
        }

        auto *raw_ctx = new EVP_AEAD_CTX;
        EVP_AEAD_CTX_zero(raw_ctx);
        if (!EVP_AEAD_CTX_init(raw_ctx, aead, key.data(), key.size(), EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr))
        {
            trace::error("[Crypto.AEAD] EVP_AEAD_CTX_init failed");
            EVP_AEAD_CTX_cleanup(raw_ctx);
            delete raw_ctx;
            return;
        }
        ctx_.reset(raw_ctx);
    }

    // 析构由 unique_ptr 自动处理，无需手动清理。
    aead_context::~aead_context() = default;

    // 移动构造：转移 ctx_ 所有权后，将源对象置为安全状态（nullptr + 零 nonce），
    // 防止析构时双重释放。
    aead_context::aead_context(aead_context &&other) noexcept
        : ctx_(std::move(other.ctx_)), nonce_(other.nonce_), key_length_(other.key_length_), nonce_len_(other.nonce_len_)
    {
        other.nonce_.fill(0);
    }

    // 移动赋值：先清理自己的资源，再接管对方的，最后将对方置为安全状态。
    auto aead_context::operator=(aead_context &&other) noexcept -> aead_context &
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

    // 加密：明文 → 密文 + 认证标签。输出 buffer 大小 = 明文长度 + 标签长度（通常 16 字节）。
    // 加密成功后 nonce 自动 +1。
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

        increment_nonce();
        return fault::code::success;
    }

    // 解密：密文 + 认证标签 → 明文。如果密文被篡改或标签不匹配，解密失败。
    // 解密成功后 nonce 自动 +1（必须和加密时的 nonce 递增顺序一致）。
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

        increment_nonce();
        return fault::code::success;
    }

    auto aead_context::seal(const std::span<std::uint8_t> out, const std::span<const std::uint8_t> plaintext,
                            const std::span<const std::uint8_t> nonce, const std::span<const std::uint8_t> ad)
        -> fault::code
    {
        if (!ctx_)
        {
            return fault::code::crypto_error;
        }

        std::size_t out_len = 0;
        const auto result = EVP_AEAD_CTX_seal(
            ctx_.get(), out.data(), &out_len, out.size(),
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
        if (!ctx_)
        {
            return fault::code::crypto_error;
        }

        std::size_t out_len = 0;
        const auto result = EVP_AEAD_CTX_open(
            ctx_.get(), out.data(), &out_len, out.size(),
            nonce.data(), nonce.size(),
            ciphertext.data(), ciphertext.size(),
            ad.data(), ad.size());

        if (!result)
        {
            return fault::code::crypto_error;
        }

        return fault::code::success;
    }

    // Nonce 小端序递增：从 byte[0] 开始加 1，溢出则进位到 byte[1]，以此类推。
    // 这是 SS2022 (SIP022) 规范要求的 nonce 递增方式。
    void aead_context::increment_nonce()
    {
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
