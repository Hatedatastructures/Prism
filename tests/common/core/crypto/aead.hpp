/**
 * @file aead.hpp
 * @brief AEAD 加密解密工具
 * @details 包装 BoringSSL 的 EVP_AEAD API，提供类型安全的加解密接口。
 * 支持 AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305、XChaCha20-Poly1305。
 * 管理 nonce 状态，每次 seal/open 后自动递增 nonce。
 * 同时提供显式 nonce 重载，用于无状态的逐包加解密（如 SS2022 UDP）。
 */
#pragma once

#include <cstring>

#include <openssl/aead.h>

#include <openssl/evp.h>

#include <common/core/fault/code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

// 前向声明，避免暴露 OpenSSL 头文件
struct evp_aead_ctx_st;

namespace psm::crypto
{

    /**
     * @enum aead_cipher
     * @brief AEAD 加密算法类型
     * @details 定义支持的 AEAD 加密算法枚举，每种算法对应
     * 不同的密钥长度和 nonce 长度。
     */
    enum class aead_cipher : std::uint8_t
    {
        /** @brief AES-128-GCM，16 字节密钥，12 字节 nonce */
        aes_128_gcm,
        /** @brief AES-256-GCM，32 字节密钥，12 字节 nonce */
        aes_256_gcm,
        /** @brief ChaCha20-Poly1305，32 字节密钥，12 字节 nonce */
        chacha20_poly1305,
        /** @brief XChaCha20-Poly1305，32 字节密钥，24 字节 nonce */
        xchacha20_poly1305
    };

    /**
     * @struct seal_input
     * @brief 显式 nonce 加密参数
     * @details 收敛显式 nonce seal 调用的参数，
     * 用于无状态的逐包加密场景（如 SS2022 UDP）。
     */
    struct seal_input
    {
        std::span<std::uint8_t> out;             ///< 输出缓冲区（密文 + tag）
        std::span<const std::uint8_t> plaintext; ///< 明文
        std::span<const std::uint8_t> nonce;     ///< 显式 nonce（12 或 24 字节）
        std::span<const std::uint8_t> ad;        ///< 附加数据
    };

    /**
     * @struct open_input
     * @brief 显式 nonce 解密参数
     * @details 收敛显式 nonce open 调用的参数，
     * 用于无状态的逐包解密场景（如 SS2022 UDP）。
     */
    struct open_input
    {
        std::span<std::uint8_t> out;              ///< 输出缓冲区（明文）
        std::span<const std::uint8_t> ciphertext; ///< 密文 + tag
        std::span<const std::uint8_t> nonce;      ///< 显式 nonce（12 或 24 字节）
        std::span<const std::uint8_t> ad;         ///< 附加数据
    };

    /**
     * @class aead_context
     * @brief AEAD 加密上下文
     * @details 管理 BoringSSL EVP_AEAD_CTX 的生命周期和 nonce 状态。
     * 每次 seal/open 成功后 nonce 自动递增（小端序）。
     * 显式 nonce 重载不修改内部 nonce 状态，适用于 UDP 逐包加密。
     * 不可拷贝，可移动。
     */
    class aead_context
    {
    public:
        /**
         * @brief 构造 AEAD 上下文
         * @details 根据 cipher 类型初始化 BoringSSL EVP_AEAD_CTX，
         * 并将 nonce 初始化为零值。密钥长度必须与算法匹配。
         * @param cipher 加密算法
         * @param key 密钥（16 或 32 字节）
         */
        explicit aead_context(aead_cipher cipher, std::span<const std::uint8_t> key);

        /**
         * @brief 析构 AEAD 上下文
         * @details 释放 BoringSSL EVP_AEAD_CTX 资源。
         */
        ~aead_context() noexcept;

        /**
         * @brief 禁止拷贝构造
         * @details AEAD 上下文包含 BoringSSL 原始指针，不可拷贝。
         */
        aead_context(const aead_context &) = delete;

        /**
         * @brief 禁止拷贝赋值
         * @details AEAD 上下文包含 BoringSSL 原始指针，不可拷贝。
         * @return 不返回
         */
        auto operator=(const aead_context &) -> aead_context & = delete;

        /**
         * @brief 移动构造函数
         * @details 转移 BoringSSL 上下文和 nonce 状态的所有权。
         * 移动后源对象处于无效状态，ctx_ 为 nullptr。
         * @param other 源对象
         */
        aead_context(aead_context &&other) noexcept;

        /**
         * @brief 移动赋值运算符
         * @details 释放当前资源后转移源对象的所有权。
         * 移动后源对象处于无效状态，ctx_ 为 nullptr。
         * @param other 源对象
         * @return 当前对象的引用
         */
        auto operator=(aead_context &&other) noexcept -> aead_context &;

        /**
         * @brief AEAD 加密（自动递增 nonce）
         * @details 使用内部 nonce 加密明文，成功后 nonce 按小端序递增。
         * 输出缓冲区大小必须为 plaintext.size() + tag_length()。
         * @param out 输出缓冲区（密文 + tag），大小 = plaintext.size() + tag_length()
         * @param plaintext 明文
         * @param ad 附加数据（可选）
         * @return 成功返回 fault::code::success，失败返回 crypto_error
         */
        [[nodiscard]] auto seal(std::span<std::uint8_t> out, std::span<const std::uint8_t> plaintext,
                                std::span<const std::uint8_t> ad = {}) -> fault::code;

        /**
         * @brief AEAD 解密（自动递增 nonce）
         * @details 使用内部 nonce 解密密文，成功后 nonce 按小端序递增。
         * 输出缓冲区大小必须为 ciphertext.size() - tag_length()。
         * @param out 输出缓冲区（明文），大小 = ciphertext.size() - tag_length()
         * @param ciphertext 密文 + tag
         * @param ad 附加数据（可选）
         * @return 成功返回 fault::code::success，失败返回 crypto_error
         */
        [[nodiscard]] auto open(std::span<std::uint8_t> out, std::span<const std::uint8_t> ciphertext,
                                std::span<const std::uint8_t> ad = {}) -> fault::code;

        /**
         * @brief AEAD 加密（显式 nonce，不修改内部状态）
         * @details 使用显式 nonce 加密明文，不修改内部 nonce 状态。
         * 适用于 UDP 逐包加密等无状态场景。
         * @param input 加密参数（输出缓冲区、明文、nonce、附加数据）
         * @return 成功返回 fault::code::success，失败返回 crypto_error
         */
        [[nodiscard]] auto seal(seal_input input) -> fault::code;

        /**
         * @brief AEAD 解密（显式 nonce，不修改内部状态）
         * @details 使用显式 nonce 解密密文，不修改内部 nonce 状态。
         * 适用于 UDP 逐包解密等无状态场景。
         * @param input 解密参数（输出缓冲区、密文、nonce、附加数据）
         * @return 成功返回 fault::code::success，失败返回 crypto_error
         */
        [[nodiscard]] auto open(open_input input) -> fault::code;

        /**
         * @brief AEAD tag 长度（固定 16 字节）
         * @details 所有支持的 AEAD 算法均使用 16 字节 tag。
         * @return std::size_t 始终返回 16
         */
        [[nodiscard]] static constexpr auto tag_length() noexcept -> std::size_t
        {
            return 16;
        }

        /**
         * @brief 获取当前 nonce 长度
         * @details 返回当前算法的 nonce 长度，GCM/ChaCha20 为 12 字节，
         * XChaCha20 为 24 字节。
         * @return std::size_t nonce 长度（12 或 24 字节）
         */
        [[nodiscard]] auto nonce_length() const noexcept -> std::size_t
        {
            return nonce_len_;
        }

        /**
         * @brief 获取当前 nonce 值
         * @details 返回内部 nonce 数组的只读引用，主要用于调试。
         * @return nonce 数组的常量引用
         */
        [[nodiscard]] auto nonce() const noexcept -> const std::array<std::uint8_t, 24> &
        {
            return nonce_;
        }

        /**
         * @brief 计算 seal 输出缓冲区所需大小
         * @details 明文加密后输出长度 = 明文长度 + tag 长度。
         * @param plaintext_len 明文长度
         * @return std::size_t 输出缓冲区所需大小
         */
        [[nodiscard]] static constexpr auto seal_size(std::size_t plaintext_len) noexcept -> std::size_t
        {
            return plaintext_len + tag_length();
        }

        /**
         * @brief 计算 open 输出缓冲区所需大小
         * @details 密文解密后输出长度 = 密文长度 - tag 长度。
         * @param ciphertext_len 密文长度（含 tag）
         * @return std::size_t 输出缓冲区所需大小
         */
        [[nodiscard]] static constexpr auto open_size(std::size_t ciphertext_len) noexcept -> std::size_t
        {
            return ciphertext_len >= tag_length() ? ciphertext_len - tag_length() : 0;
        }

    private:
        /**
         * @brief 递增 nonce
         * @details 按 SS2022 规范要求，以小端序递增 nonce 值。
         * 仅在 seal/open 加解密成功后调用。
         */
        void increment_nonce() noexcept;

        /**
         * @brief 检测 nonce 是否耗尽
         * @details 检查 nonce 是否已达到最大值（所有字节均为 0xFF）。
         * 在加解密操作之前调用，防止 nonce 重用。
         * @return true nonce 已耗尽，false 仍可使用
         */
        [[nodiscard]] auto is_nonce_exhausted() const noexcept -> bool;

        static void release_ctx(evp_aead_ctx_st *ctx) noexcept;

        std::unique_ptr<evp_aead_ctx_st, void (*)(evp_aead_ctx_st *) noexcept> ctx_; // BoringSSL AEAD 上下文
        std::array<std::uint8_t, 24> nonce_{}; // 当前 nonce 值（最大 24 字节）
        std::size_t key_length_{0};            // 密钥长度
        std::size_t nonce_len_{12};            // nonce 长度（12 或 24 字节）
    };



    inline void aead_context::release_ctx(evp_aead_ctx_st *ctx) noexcept
    {
        if (ctx)
        {
            EVP_AEAD_CTX_cleanup(ctx);
            delete ctx;
        }
    }

    inline aead_context::aead_context(const aead_cipher cipher, const std::span<const std::uint8_t> key)
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
        default: return;
        }

        if (!aead)
        {
            return;
        }

        auto *raw_ctx = new EVP_AEAD_CTX;
        EVP_AEAD_CTX_zero(raw_ctx);
        if (!EVP_AEAD_CTX_init(raw_ctx, aead, key.data(), key.size(), EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr))
        {
            EVP_AEAD_CTX_cleanup(raw_ctx);
            delete raw_ctx;
            return;
        }
        ctx_.reset(raw_ctx);
    }

    inline aead_context::~aead_context() = default;

    inline aead_context::aead_context(aead_context &&other) noexcept
        : ctx_(std::move(other.ctx_)), nonce_(other.nonce_), key_length_(other.key_length_),
          nonce_len_(other.nonce_len_)
    {
        other.nonce_.fill(0);
    }

    inline auto aead_context::operator=(aead_context &&other) noexcept -> aead_context &
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

    inline auto aead_context::seal(const std::span<std::uint8_t> out, const std::span<const std::uint8_t> plaintext,
                            const std::span<const std::uint8_t> ad) -> fault::code
    {
        if (!ctx_)
        {
            return fault::code::crypto_error;
        }

        if (is_nonce_exhausted())
        {
            return fault::code::crypto_error;
        }

        std::size_t out_len = 0;
        const auto result =
            EVP_AEAD_CTX_seal(ctx_.get(), out.data(), &out_len, out.size(), nonce_.data(), nonce_len_,
                              plaintext.data(), plaintext.size(), ad.data(), ad.size());

        if (!result)
        {
            return fault::code::crypto_error;
        }

        increment_nonce();
        return fault::code::success;
    }

    inline auto aead_context::open(const std::span<std::uint8_t> out, const std::span<const std::uint8_t> ciphertext,
                            const std::span<const std::uint8_t> ad) -> fault::code
    {
        if (!ctx_)
        {
            return fault::code::crypto_error;
        }

        if (is_nonce_exhausted())
        {
            return fault::code::crypto_error;
        }

        std::size_t out_len = 0;
        const auto result =
            EVP_AEAD_CTX_open(ctx_.get(), out.data(), &out_len, out.size(), nonce_.data(), nonce_len_,
                              ciphertext.data(), ciphertext.size(), ad.data(), ad.size());

        if (!result)
        {
            return fault::code::crypto_error;
        }

        increment_nonce();
        return fault::code::success;
    }

    inline auto aead_context::seal(seal_input input) -> fault::code
    {
        if (!ctx_)
        {
            return fault::code::crypto_error;
        }

        std::size_t out_len = 0;
        const auto result = EVP_AEAD_CTX_seal(ctx_.get(), input.out.data(), &out_len, input.out.size(),
                                              input.nonce.data(), input.nonce.size(), input.plaintext.data(),
                                              input.plaintext.size(), input.ad.data(), input.ad.size());

        if (!result)
        {
            return fault::code::crypto_error;
        }

        return fault::code::success;
    }

    inline auto aead_context::open(open_input input) -> fault::code
    {
        if (!ctx_)
        {
            return fault::code::crypto_error;
        }

        std::size_t out_len = 0;
        const auto result = EVP_AEAD_CTX_open(ctx_.get(), input.out.data(), &out_len, input.out.size(),
                                              input.nonce.data(), input.nonce.size(), input.ciphertext.data(),
                                              input.ciphertext.size(), input.ad.data(), input.ad.size());

        if (!result)
        {
            return fault::code::crypto_error;
        }

        return fault::code::success;
    }

    inline void aead_context::increment_nonce() noexcept
    {
        for (std::size_t i = 0; i < nonce_len_; ++i)
        {
            nonce_[i]++;
            if (nonce_[i] != 0)
            {
                return;
            }
        }
    }

    inline auto aead_context::is_nonce_exhausted() const noexcept -> bool
    {
        for (std::size_t i = 0; i < nonce_len_; ++i)
        {
            if (nonce_[i] != 0xFF)
            {
                return false;
            }
        }
        return true;
    }


} // namespace psm::crypto
