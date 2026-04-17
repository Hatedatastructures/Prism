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
        ~aead_context();

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
        auto seal(std::span<std::uint8_t> out, std::span<const std::uint8_t> plaintext,
                  std::span<const std::uint8_t> ad = {})
            -> fault::code;

        /**
         * @brief AEAD 解密（自动递增 nonce）
         * @details 使用内部 nonce 解密密文，成功后 nonce 按小端序递增。
         * 输出缓冲区大小必须为 ciphertext.size() - tag_length()。
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
         * @details 使用显式 nonce 加密明文，不修改内部 nonce 状态。
         * 适用于 UDP 逐包加密等无状态场景。
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
         * @details 使用显式 nonce 解密密文，不修改内部 nonce 状态。
         * 适用于 UDP 逐包解密等无状态场景。
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
         * @brief AEAD tag 长度（固定 16 字节）
         * @details 所有支持的 AEAD 算法均使用 16 字节 tag。
         * @return std::size_t 始终返回 16
         */
        [[nodiscard]] static constexpr auto tag_length() noexcept -> std::size_t { return 16; }

        /**
         * @brief 获取当前 nonce 长度
         * @details 返回当前算法的 nonce 长度，GCM/ChaCha20 为 12 字节，
         * XChaCha20 为 24 字节。
         * @return std::size_t nonce 长度（12 或 24 字节）
         */
        [[nodiscard]] auto nonce_length() const noexcept -> std::size_t { return nonce_len_; }

        /**
         * @brief 获取当前 nonce 值
         * @details 返回内部 nonce 数组的只读引用，主要用于调试。
         * @return nonce 数组的常量引用
         */
        [[nodiscard]] auto nonce() const noexcept -> const std::array<std::uint8_t, 24> & { return nonce_; }

        /**
         * @brief 计算 seal 输出缓冲区所需大小
         * @details 明文加密后输出长度 = 明文长度 + tag 长度。
         * @param plaintext_len 明文长度
         * @return std::size_t 输出缓冲区所需大小
         */
        [[nodiscard]] static constexpr auto seal_output_size(std::size_t plaintext_len) noexcept -> std::size_t
        {
            return plaintext_len + tag_length();
        }

        /**
         * @brief 计算 open 输出缓冲区所需大小
         * @details 密文解密后输出长度 = 密文长度 - tag 长度。
         * @param ciphertext_len 密文长度（含 tag）
         * @return std::size_t 输出缓冲区所需大小
         */
        [[nodiscard]] static constexpr auto open_output_size(std::size_t ciphertext_len) noexcept -> std::size_t
        {
            return ciphertext_len - tag_length();
        }

    private:
        /**
         * @brief 递增 nonce
         * @details 按 SS2022 规范要求，以小端序递增 nonce 值。
         */
        void increment_nonce();

        evp_aead_ctx_st *ctx_{nullptr};        // BoringSSL AEAD 上下文指针
        std::array<std::uint8_t, 24> nonce_{}; // 当前 nonce 值（最大 24 字节）
        std::size_t key_length_{0};            // 密钥长度
        std::size_t nonce_len_{12};            // nonce 长度（12 或 24 字节）
    };
} // namespace psm::crypto
