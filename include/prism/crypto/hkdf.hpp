/**
 * @file hkdf.hpp
 * @brief HKDF-SHA256 密钥派生工具
 * @details 提供 HMAC-SHA256、HKDF-Extract、HKDF-Expand 和
 * TLS 1.3 专用的 HKDF-Expand-Label 函数。这些函数是 TLS 1.3
 * 密钥调度的核心组件，用于从 ECDHE 共享密钥派生握手和应用流量密钥。
 * 基于 BoringSSL 的 HMAC API 实现。
 * @note SHA-256 输出固定 32 字节，HKDF-Expand 输出长度可变。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>
#include <prism/fault/code.hpp>

namespace psm::crypto
{
    /**
     * @brief SHA-256 输出长度（字节）
     */
    constexpr std::size_t SHA256_LEN = 32;

    /**
     * @brief SHA-512 输出长度（字节）
     */
    constexpr std::size_t SHA512_LEN = 64;

    /**
     * @brief HMAC-SHA256
     * @param key HMAC 密钥
     * @param data 输入数据
     * @return 32 字节 HMAC-SHA256 结果
     * @details 计算 HMAC-SHA256(key, data)，用于 HKDF-Extract
     * 和 TLS 1.3 Finished 消息的 verify_data 计算。
     */
    [[nodiscard]] auto hmac_sha256(std::span<const std::uint8_t> key,
                                   std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, SHA256_LEN>;

    /**
     * @brief HMAC-SHA512
     * @param key HMAC 密钥
     * @param data 输入数据
     * @return 64 字节 HMAC-SHA512 结果
     */
    [[nodiscard]] auto hmac_sha512(std::span<const std::uint8_t> key,
                                   std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, SHA512_LEN>;

    /**
     * @brief HKDF-Extract
     * @param salt 盐值（可以为空）
     * @param ikm 输入密钥材料
     * @return 32 字节伪随机密钥 (PRK)
     * @details 计算 PRK = HMAC-SHA256(salt, IKM)。
     * 当 salt 为空时使用 32 字节全零作为盐值（RFC 5869）。
     */
    [[nodiscard]] auto hkdf_extract(std::span<const std::uint8_t> salt,
                                    std::span<const std::uint8_t> ikm)
        -> std::array<std::uint8_t, SHA256_LEN>;

    /**
     * @brief HKDF-Expand
     * @param prk 伪随机密钥（32 字节）
     * @param info 上下文信息
     * @param length 输出长度（最大 255 * 32 = 8160 字节）
     * @return 错误码和输出字节的配对
     * @details 按照 RFC 5869 实现 HKDF-Expand：
     * T(1) = HMAC-SHA256(PRK, info || 0x01)
     * T(N) = HMAC-SHA256(PRK, T(N-1) || info || N)
     * Output = T(1) || T(2) || ... || T(N)
     */
    [[nodiscard]] auto hkdf_expand(std::span<const std::uint8_t> prk,
                                   std::span<const std::uint8_t> info,
                                   std::size_t length)
        -> std::pair<fault::code, std::vector<std::uint8_t>>;

    /**
     * @brief TLS 1.3 HKDF-Expand-Label
     * @param secret 输入密钥
     * @param label 标签（如 "key", "iv", "finished", "c hs traffic"）
     * @param context 上下文数据（通常是 transcript hash）
     * @param length 输出长度
     * @return 错误码和输出字节的配对
     * @details 按照 RFC 8446 Section 7.1 实现：
     * HkdfLabel = Length(2) || label_len(1) || "tls13 " + Label || context_len(1) || Context
     * HKDF-Expand-Label(Secret, Label, Context, Length) = HKDF-Expand(Secret, HkdfLabel, Length)
     * @note TLS 1.3 自动在 label 前添加 "tls13 " 前缀。
     */
    [[nodiscard]] auto hkdf_expand_label(std::span<const std::uint8_t> secret,
                                         std::string_view label,
                                         std::span<const std::uint8_t> context,
                                         std::size_t length)
        -> std::pair<fault::code, std::vector<std::uint8_t>>;

    /**
     * @brief SHA-256 哈希
     * @param data 输入数据
     * @return 32 字节 SHA-256 哈希值
     * @details 计算 SHA-256(data)，用于 TLS 1.3 transcript hash。
     */
    [[nodiscard]] auto sha256(std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, SHA256_LEN>;

    /**
     * @brief SHA-256 哈希（两个数据块拼接）
     * @param data1 第一个数据块
     * @param data2 第二个数据块
     * @return 32 字节 SHA-256 哈希值
     * @details 计算 SHA-256(data1 || data2)，用于 TLS 1.3 transcript hash。
     * 比 concat 后再 hash 更高效，避免额外内存分配。
     */
    [[nodiscard]] auto sha256(std::span<const std::uint8_t> data1,
                              std::span<const std::uint8_t> data2)
        -> std::array<std::uint8_t, SHA256_LEN>;

    /**
     * @brief SHA-256 哈希（三个数据块拼接）
     * @param data1 第一个数据块
     * @param data2 第二个数据块
     * @param data3 第三个数据块
     * @return 32 字节 SHA-256 哈希值
     * @details 计算 SHA-256(data1 || data2 || data3)，用于 TLS 1.3 transcript hash。
     */
    [[nodiscard]] auto sha256(std::span<const std::uint8_t> data1,
                              std::span<const std::uint8_t> data2,
                              std::span<const std::uint8_t> data3)
        -> std::array<std::uint8_t, SHA256_LEN>;
} // namespace psm::crypto
