/**
 * @file aead.hpp
 * @brief AEAD 加密解密工具
 * @details 包装 BoringSSL 的 EVP_AEAD API，提供类型安全的加解密接口。
 * 支持 AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305、XChaCha20-Poly1305。
 * 管理 nonce 状态，每次 seal/open 后自动递增 nonce。
 * 同时提供显式 nonce 重载，用于无状态的逐包加解密（如 SS2022 UDP）。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <span>
#include <prism/fault/code.hpp>

// 前向声明，避免暴露 OpenSSL 头文件
struct evp_aead_ctx_st;

namespace psm::crypto
{
    /**
     * @enum aead_cipher
     * @brief AEAD 加密算法类型
     */
    enum class aead_cipher : std::uint8_t
    {
        aes_128_gcm,          ///< AES-128-GCM，16 字节密钥，12 字节 nonce
        aes_256_gcm,          ///< AES-256-GCM，32 字节密钥，12 字节 nonce
        chacha20_poly1305,    ///< ChaCha20-Poly1305，32 字节密钥，12 字节 nonce
        xchacha20_poly1305    ///< XChaCha20-Poly1305，32 字节密钥，24 字节 nonce
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
         * @param cipher 加密算法
         * @param key 密钥（16 或 32 字节）
         */
        explicit aead_context(aead_cipher cipher, std::span<const std::uint8_t> key);

        ~aead_context();

        aead_context(const aead_context &) = delete;
        auto operator=(const aead_context &) -> aead_context & = delete;

        aead_context(aead_context &&other) noexcept;
        auto operator=(aead_context &&other) noexcept -> aead_context &;

        /**
         * @brief AEAD 加密（自动递增 nonce）
         * @param out 输出缓冲区（密文 + tag），大小 = plaintext.size() + tag_length()
         * @param plaintext 明文
         * @param ad 附加数据（可选）
         * @return 成功返回 fault::code::success，失败返回 crypto_error
         */
        auto seal(std::span<std::uint8_t> out, std::span<const std::uint8_t> plaintext,
                  std::span<const std::uint8_t> ad = {})
            -> fault::code;

        /**
         * @brief AEAD 解密（自动递增 nonce）
         * @param out 输出缓冲区（明文），大小 = ciphertext.size() - tag_length()
         * @param ciphertext 密文 + tag
         * @param ad 附加数据（可选）
         * @return 成功返回 fault::code::success，失败返回 crypto_error
         */
        auto open(std::span<std::uint8_t> out, std::span<const std::uint8_t> ciphertext,
                  std::span<const std::uint8_t> ad = {})
            -> fault::code;

        /**
         * @brief AEAD 加密（显式 nonce，不修改内部状态）
         * @param out 输出缓冲区（密文 + tag）
         * @param plaintext 明文
         * @param nonce 显式 nonce（12 或 24 字节）
         * @param ad 附加数据（可选）
         * @return 成功返回 fault::code::success，失败返回 crypto_error
         */
        auto seal(std::span<std::uint8_t> out, std::span<const std::uint8_t> plaintext,
                  std::span<const std::uint8_t> nonce, std::span<const std::uint8_t> ad)
            -> fault::code;

        /**
         * @brief AEAD 解密（显式 nonce，不修改内部状态）
         * @param out 输出缓冲区（明文）
         * @param ciphertext 密文 + tag
         * @param nonce 显式 nonce（12 或 24 字节）
         * @param ad 附加数据（可选）
         * @return 成功返回 fault::code::success，失败返回 crypto_error
         */
        auto open(std::span<std::uint8_t> out, std::span<const std::uint8_t> ciphertext,
                  std::span<const std::uint8_t> nonce, std::span<const std::uint8_t> ad)
            -> fault::code;

        /**
         * @brief 获取密钥长度
         */
        [[nodiscard]] auto key_length() const noexcept -> std::size_t { return key_length_; }

        /**
         * @brief AEAD tag 长度（固定 16 字节）
         */
        [[nodiscard]] static constexpr auto tag_length() noexcept -> std::size_t { return 16; }

        /**
         * @brief 获取当前 nonce 长度（12 或 24 字节）
         */
        [[nodiscard]] auto nonce_length() const noexcept -> std::size_t { return nonce_len_; }

        /**
         * @brief 获取当前 nonce 值（用于调试）
         */
        [[nodiscard]] auto nonce() const noexcept -> const std::array<std::uint8_t, 24> & { return nonce_; }

        /**
         * @brief 计算 seal 输出缓冲区所需大小
         */
        [[nodiscard]] static constexpr auto seal_output_size(std::size_t plaintext_len) noexcept -> std::size_t
        {
            return plaintext_len + tag_length();
        }

        /**
         * @brief 计算 open 输出缓冲区所需大小
         */
        [[nodiscard]] static constexpr auto open_output_size(std::size_t ciphertext_len) noexcept -> std::size_t
        {
            return ciphertext_len - tag_length();
        }

    private:
        /// 递增 nonce（小端序，SS2022 规范要求）
        void increment_nonce();

        evp_aead_ctx_st *ctx_{nullptr};
        std::array<std::uint8_t, 24> nonce_{};
        std::size_t key_length_{0};
        std::size_t nonce_len_{12};
    };

    /**
     * @brief 根据 AEAD 算法获取密钥长度
     */
    [[nodiscard]] constexpr auto aead_key_length(aead_cipher cipher) noexcept -> std::size_t
    {
        switch (cipher)
        {
        case aead_cipher::aes_128_gcm:
            return 16;
        case aead_cipher::aes_256_gcm:
        case aead_cipher::chacha20_poly1305:
        case aead_cipher::xchacha20_poly1305:
            return 32;
        }
        return 32;
    }
} // namespace psm::crypto
