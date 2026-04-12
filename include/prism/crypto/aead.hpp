/**
 * @file aead.hpp
 * @brief AEAD 加密解密工具
 * @details 包装 BoringSSL 的 EVP_AEAD API，提供类型安全的 AES-GCM 加解密接口。
 * 管理 nonce 状态，每次 seal/open 后自动递增 nonce。
 * 用于 SS2022 (SIP022) 协议的流加密。
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
        aes_128_gcm, ///< AES-128-GCM，16 字节密钥
        aes_256_gcm  ///< AES-256-GCM，32 字节密钥
    };

    /**
     * @class aead_context
     * @brief AEAD 加密上下文
     * @details 管理 BoringSSL EVP_AEAD_CTX 的生命周期和 nonce 状态。
     * 每次 seal/open 成功后 nonce 自动递增（大端序）。
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
         * @brief AEAD 加密（seal）
         * @param out 输出缓冲区（密文 + tag），大小 = plaintext.size() + tag_length()
         * @param plaintext 明文
         * @param ad 附加数据（可选）
         * @return 成功返回 fault::code::success，失败返回 crypto_error
         */
        auto seal(std::span<std::uint8_t> out, std::span<const std::uint8_t> plaintext,
                  std::span<const std::uint8_t> ad = {})
            -> fault::code;

        /**
         * @brief AEAD 解密（open）
         * @param out 输出缓冲区（明文），大小 = ciphertext.size() - tag_length()
         * @param ciphertext 密文 + tag
         * @param ad 附加数据（可选）
         * @return 成功返回 fault::code::success，失败返回 crypto_error
         */
        auto open(std::span<std::uint8_t> out, std::span<const std::uint8_t> ciphertext,
                  std::span<const std::uint8_t> ad = {})
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
         * @brief Nonce 长度（固定 12 字节，AES-GCM 标准）
         */
        [[nodiscard]] static constexpr auto nonce_length() noexcept -> std::size_t { return 12; }

        /**
         * @brief 获取当前 nonce 值（用于调试）
         */
        [[nodiscard]] auto nonce() const noexcept -> const std::array<std::uint8_t, 12> & { return nonce_; }

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
        /// 递增 nonce（大端序，SS2022 规范要求）
        void increment_nonce();

        evp_aead_ctx_st *ctx_{nullptr};
        std::array<std::uint8_t, 12> nonce_{};
        std::size_t key_length_{0};
    };

    /**
     * @brief 根据 AEAD 算法获取密钥长度
     */
    [[nodiscard]] constexpr auto aead_key_length(aead_cipher cipher) noexcept -> std::size_t
    {
        return cipher == aead_cipher::aes_128_gcm ? 16 : 32;
    }
} // namespace psm::crypto
