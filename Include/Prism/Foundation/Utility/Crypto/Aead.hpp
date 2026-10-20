/**
 * @file Aead.hpp
 * @brief AEAD 加密解密工具
 * @details 包装 BoringSSL 的 EVP_AEAD API，提供类型安全的加解密接口。
 * 支持 AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305、XChaCha20-Poly1305。
 * 管理 Nonce 状态，每次 Seal/Open 后自动递增 Nonce。
 * 同时提供显式 Nonce 重载，用于无状态的逐包加解密（如 SS2022 UDP）。
 */
#pragma once

#include <Prism/Foundation/Fault/Code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>

// 前向声明，避免暴露 OpenSSL 头文件（BoringSSL 真实类型名，C 结构体保持生态命名）
struct evp_aead_ctx_st;

namespace Prism::Crypto
{

    /**
     * @enum AeadCipher
     * @brief AEAD 加密算法类型
     * @details 定义支持的 AEAD 加密算法枚举，每种算法对应
     * 不同的密钥长度和 Nonce 长度。
     */
    enum class AeadCipher : std::uint8_t
    {
        /** @brief AES-128-GCM，16 字节密钥，12 字节 Nonce */
        Aes128Gcm,
        /** @brief AES-256-GCM，32 字节密钥，12 字节 Nonce */
        Aes256Gcm,
        /** @brief ChaCha20-Poly1305，32 字节密钥，12 字节 Nonce */
        Chacha20Poly1305,
        /** @brief XChaCha20-Poly1305，32 字节密钥，24 字节 Nonce */
        Xchacha20Poly1305
    };

    /**
     * @struct SealInput
     * @brief 显式 Nonce 加密参数
     * @details 收敛显式 Nonce Seal 调用的参数，
     * 用于无状态的逐包加密场景（如 SS2022 UDP）。
     */
    struct SealInput
    {
        std::span<std::uint8_t> Out;             ///< 输出缓冲区（密文 + tag）
        std::span<const std::uint8_t> Plaintext; ///< 明文
        std::span<const std::uint8_t> Nonce;     ///< 显式 Nonce（12 或 24 字节）
        std::span<const std::uint8_t> AdditionalData; ///< 附加数据
    };

    /**
     * @struct OpenInput
     * @brief 显式 Nonce 解密参数
     * @details 收敛显式 Nonce Open 调用的参数，
     * 用于无状态的逐包解密场景（如 SS2022 UDP）。
     */
    struct OpenInput
    {
        std::span<std::uint8_t> Out;              ///< 输出缓冲区（明文）
        std::span<const std::uint8_t> Ciphertext; ///< 密文 + tag
        std::span<const std::uint8_t> Nonce;      ///< 显式 Nonce（12 或 24 字节）
        std::span<const std::uint8_t> AdditionalData; ///< 附加数据
    };

    /**
     * @class AeadContext
     * @brief AEAD 加密上下文
     * @details 管理 BoringSSL EVP_AEAD_CTX 的生命周期和 Nonce 状态。
     * 每次 Seal/Open 成功后 Nonce 自动递增（小端序）。
     * 显式 Nonce 重载不修改内部 Nonce 状态，适用于 UDP 逐包加密。
     * 本地参数检查失败不触碰输出；BoringSSL 操作失败会清零整个输出容量；
     * 成功长度不符合 wire 长度时也会清零输出并返回 CryptoError。
     * 不可拷贝，可移动。
     */
    class AeadContext
    {
    public:
        /**
         * @brief 构造 AEAD 上下文
         * @details 根据 cipher 类型初始化 BoringSSL EVP_AEAD_CTX，
         * 并将 Nonce 初始化为零值。密钥长度必须与算法匹配。
         * @param cipher 加密算法
         * @param key 密钥（16 或 32 字节）
         */
        explicit AeadContext(AeadCipher Cipher, std::span<const std::uint8_t> Key);

        /**
         * @brief 析构 AEAD 上下文
         * @details 释放 BoringSSL EVP_AEAD_CTX 资源。
         */
        ~AeadContext() noexcept;

        /**
         * @brief 禁止拷贝构造
         * @details AEAD 上下文包含 BoringSSL 原始指针，不可拷贝。
         */
        AeadContext(const AeadContext &) = delete;

        /**
         * @brief 禁止拷贝赋值
         * @details AEAD 上下文包含 BoringSSL 原始指针，不可拷贝。
         * @return 不返回
         */
        auto operator=(const AeadContext &) -> AeadContext & = delete;

        /**
         * @brief 移动构造函数
         * @details 转移 BoringSSL 上下文和 Nonce 状态的所有权。
         * 移动后源对象处于无效状态，Ctx_ 为 nullptr。
         * @param other 源对象
         */
        AeadContext(AeadContext &&other) noexcept;

        /**
         * @brief 移动赋值运算符
         * @details 释放当前资源后转移源对象的所有权。
         * 移动后源对象处于无效状态，Ctx_ 为 nullptr。
         * @param other 源对象
         * @return 当前对象的引用
         */
        auto operator=(AeadContext &&other) noexcept -> AeadContext &;

        /**
         * @brief AEAD 加密（自动递增 Nonce）
         * @details 使用内部 Nonce 加密明文，成功后 Nonce 按小端序递增。
         * 输出容量至少为 plaintext.size() + TagLength()；实际 wire 输出长度为该值。
         * 仅在 BoringSSL 成功且返回长度符合 wire 长度后递增 Nonce。
         * @param out 输出缓冲区（密文 + tag），容量至少为 plaintext.size() + TagLength()
         * @param plaintext 明文
         * @param ad 附加数据（可选）
         * @return 成功返回 Fault::Code::Success，失败返回 crypto_error
         */
        [[nodiscard]] auto Seal(std::span<std::uint8_t> Out, std::span<const std::uint8_t> Plaintext,
                                std::span<const std::uint8_t> AdditionalData = {}) -> Fault::Code;

        /**
         * @brief AEAD 解密（自动递增 Nonce）
         * @details 使用内部 Nonce 解密密文，成功后 Nonce 按小端序递增。
         * 输出容量至少为 ciphertext.size() - TagLength()。
         * ciphertext 短于 tag 时在本地拒绝，且不触碰输出。
         * @param out 输出缓冲区（明文），容量至少为 ciphertext.size() - TagLength()
         * @param ciphertext 密文 + tag
         * @param ad 附加数据（可选）
         * @return 成功返回 Fault::Code::Success，失败返回 crypto_error
         */
        [[nodiscard]] auto Open(std::span<std::uint8_t> Out, std::span<const std::uint8_t> Ciphertext,
                                std::span<const std::uint8_t> AdditionalData = {}) -> Fault::Code;

        /**
         * @brief AEAD 加密（显式 Nonce，不修改内部状态）
         * @details 使用显式 Nonce 加密明文，不修改内部 Nonce 状态。
         * 适用于 UDP 逐包加密等无状态场景。
         * @param input 加密参数（输出缓冲区、明文、Nonce、附加数据）
         * @return 成功返回 Fault::Code::Success，失败返回 crypto_error
         */
        [[nodiscard]] auto Seal(SealInput Input) -> Fault::Code;

        /**
         * @brief AEAD 解密（显式 Nonce，不修改内部状态）
         * @details 使用显式 Nonce 解密密文，不修改内部 Nonce 状态。
         * 适用于 UDP 逐包解密等无状态场景。
         * @param input 解密参数（输出缓冲区、密文、Nonce、附加数据）
         * @return 成功返回 Fault::Code::Success，失败返回 crypto_error
         */
        [[nodiscard]] auto Open(OpenInput Input) -> Fault::Code;

        /**
         * @brief AEAD tag 长度（固定 16 字节）
         * @details 所有支持的 AEAD 算法均使用 16 字节 tag。
         * @return std::size_t 始终返回 16
         */
        [[nodiscard]] static constexpr auto TagLength() noexcept -> std::size_t
        {
            return 16;
        }

        /**
         * @brief 获取当前 Nonce 长度
         * @details 返回当前算法的 Nonce 长度，GCM/ChaCha20 为 12 字节，
         * XChaCha20 为 24 字节。
         * @return std::size_t Nonce 长度（12 或 24 字节）
         */
        [[nodiscard]] auto NonceLength() const noexcept -> std::size_t
        {
            return NonceLen_;
        }

        /**
         * @brief 获取当前 Nonce 值
         * @details 返回内部 Nonce 数组的只读引用，主要用于调试。
         * @return Nonce 数组的常量引用
         */
        [[nodiscard]] auto Nonce() const noexcept -> const std::array<std::uint8_t, 24> &
        {
            return Nonce_;
        }

        /**
         * @brief 计算 Seal 输出缓冲区所需大小
         * @details 明文加密后输出长度 = 明文长度 + tag 长度。若加法溢出，饱和返回
         * std::numeric_limits<std::size_t>::max()；调用方仍须处理无法容纳该长度的情况。
         * @param PlaintextLen 明文长度
         * @return std::size_t 输出缓冲区所需大小
         */
        [[nodiscard]] static constexpr auto SealSize(std::size_t PlaintextLen) noexcept -> std::size_t
        {
            constexpr auto MaxSize = std::numeric_limits<std::size_t>::max();
            if (PlaintextLen > MaxSize - TagLength())
            {
                return MaxSize;
            }
            return PlaintextLen + TagLength();
        }

        /**
         * @brief 计算 Open 输出缓冲区所需大小
         * @details 密文解密后输出长度 = 密文长度 - tag 长度。
         * @param CiphertextLen 密文长度（含 tag）
         * @return std::size_t 输出缓冲区所需大小
         */
        [[nodiscard]] static constexpr auto OpenSize(std::size_t CiphertextLen) noexcept -> std::size_t
        {
            if (CiphertextLen >= TagLength())
            {
                return CiphertextLen - TagLength();
            }
            return 0;
        }

    private:
        /**
         * @brief 安全清除输出缓冲区
         * @param Out 待清除的输出
         */
        static auto ClearOutput(std::span<std::uint8_t> Out) noexcept -> void;

        /**
         * @brief 递增 Nonce
         * @details 按 SS2022 规范要求，以小端序递增 Nonce 值。
         * 仅在 Seal/Open 加解密成功后调用。
         */
        auto IncrementNonce() noexcept -> void;

        /**
         * @brief 检测 Nonce 是否耗尽
         * @details 检查 Nonce 是否已达到最大值（所有字节均为 0xFF）。
         * 在加解密操作之前调用，防止 Nonce 重用。
         * @return true Nonce 已耗尽，false 仍可使用
         */
        [[nodiscard]] auto IsNonceExhausted() const noexcept -> bool;

        static auto ReleaseCtx(evp_aead_ctx_st *Context) noexcept -> void;

        std::unique_ptr<evp_aead_ctx_st, void (*)(evp_aead_ctx_st *) noexcept> Ctx_; // BoringSSL AEAD 上下文
        std::array<std::uint8_t, 24> Nonce_{}; // 当前 Nonce 值（最大 24 字节）
        std::size_t KeyLength_{0};            // 密钥长度
        std::size_t NonceLen_{12};            // Nonce 长度（12 或 24 字节）
    };

} // namespace Prism::Crypto
