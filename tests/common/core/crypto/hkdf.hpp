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

#include <cstring>

#include <openssl/sha.h>

#include <openssl/hmac.h>

#include <openssl/evp.h>

#include <common/core/fault/code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace psmtest::crypto
{

    /**
     * @brief SHA-256 输出长度（字节）
     */
    constexpr std::size_t sha256_len = 32;

    /**
     * @brief SHA-512 输出长度（字节）
     */
    constexpr std::size_t sha512_len = 64;

    /**
     * @brief HMAC-SHA256
     * @param key HMAC 密钥
     * @param data 输入数据
     * @return 32 字节 HMAC-SHA256 结果
     * @details 计算 HMAC-SHA256(key, data)，用于 HKDF-Extract
     * 和 TLS 1.3 Finished 消息的 verify_data 计算。
     */
    [[nodiscard]] auto hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, sha256_len>;

    /**
     * @brief HMAC-SHA512
     * @param key HMAC 密钥
     * @param data 输入数据
     * @return 64 字节 HMAC-SHA512 结果
     */
    [[nodiscard]] auto hmac_sha512(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, sha512_len>;

    /**
     * @brief HKDF-Extract
     * @param salt 盐值（可以为空）
     * @param ikm 输入密钥材料
     * @return 32 字节伪随机密钥 (PRK)
     * @details 计算 PRK = HMAC-SHA256(salt, IKM)。
     * 当 salt 为空时使用 32 字节全零作为盐值（RFC 5869）。
     */
    [[nodiscard]] auto hkdf_extract(std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ikm)
        -> std::array<std::uint8_t, sha256_len>;

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
    [[nodiscard]] auto hkdf_expand(std::span<const std::uint8_t> prk, std::span<const std::uint8_t> info,
                                   std::size_t length) -> std::pair<fault::code, std::vector<std::uint8_t>>;

    /**
     * @struct expand_label_params
     * @brief HKDF-Expand-Label 参数
     * @details 组合 TLS 1.3 HKDF-Expand-Label 调用所需的全部参数。
     */
    struct expand_params
    {
        std::span<const std::uint8_t> secret;  ///< 输入密钥
        std::string_view label;                ///< 标签（如 "key", "iv", "finished"）
        std::span<const std::uint8_t> context; ///< 上下文数据（通常是 transcript hash）
        std::size_t length = 0;                ///< 输出长度
    };

    /**
     * @brief TLS 1.3 HKDF-Expand-Label
     * @param params 扩展标签参数
     * @return 错误码和输出字节的配对
     * @details 按照 RFC 8446 Section 7.1 实现：
     * HkdfLabel = Length(2) || label_len(1) || "tls13 " + Label || context_len(1) || Context
     * HKDF-Expand-Label(Secret, Label, Context, Length) = HKDF-Expand(Secret, HkdfLabel, Length)
     * @note TLS 1.3 自动在 label 前添加 "tls13 " 前缀。
     */
    [[nodiscard]] auto expand_label(expand_params params)
        -> std::pair<fault::code, std::vector<std::uint8_t>>;

    /**
     * @brief SHA-256 哈希
     * @param data 输入数据
     * @return 32 字节 SHA-256 哈希值
     * @details 计算 SHA-256(data)，用于 TLS 1.3 transcript hash。
     */
    [[nodiscard]] auto sha256(std::span<const std::uint8_t> data) -> std::array<std::uint8_t, sha256_len>;

    /**
     * @brief SHA-256 哈希（两个数据块拼接）
     * @param data1 第一个数据块
     * @param data2 第二个数据块
     * @return 32 字节 SHA-256 哈希值
     * @details 计算 SHA-256(data1 || data2)，用于 TLS 1.3 transcript hash。
     * 比 concat 后再 hash 更高效，避免额外内存分配。
     */
    [[nodiscard]] auto sha256(std::span<const std::uint8_t> data1, std::span<const std::uint8_t> data2)
        -> std::array<std::uint8_t, sha256_len>;

    /**
     * @brief SHA-256 哈希（三个数据块拼接）
     * @param data1 第一个数据块
     * @param data2 第二个数据块
     * @param data3 第三个数据块
     * @return 32 字节 SHA-256 哈希值
     * @details 计算 SHA-256(data1 || data2 || data3)，用于 TLS 1.3 transcript hash。
     */
    [[nodiscard]] auto sha256(std::span<const std::uint8_t> data1, std::span<const std::uint8_t> data2,
                              std::span<const std::uint8_t> data3) -> std::array<std::uint8_t, sha256_len>;



    auto hmac_sha256(const std::span<const std::uint8_t> key, const std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, sha256_len>
    {
        std::array<std::uint8_t, sha256_len> result{};

        std::uint32_t mac_len = 0;
        const auto *ret = HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(),
                               data.size(), result.data(), &mac_len);

        if (!ret)
        {
            result.fill(0);
        }

        return result;
    }

    auto hmac_sha512(const std::span<const std::uint8_t> key, const std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, sha512_len>
    {
        std::array<std::uint8_t, sha512_len> result{};

        std::uint32_t mac_len = 0;
        const auto *ret = HMAC(EVP_sha512(), key.data(), static_cast<int>(key.size()), data.data(),
                               data.size(), result.data(), &mac_len);

        if (!ret)
        {
            result.fill(0);
        }

        return result;
    }

    auto hkdf_extract(const std::span<const std::uint8_t> salt, const std::span<const std::uint8_t> ikm)
        -> std::array<std::uint8_t, sha256_len>
    {
        if (salt.empty())
        {
            std::array<std::uint8_t, sha256_len> zero_salt{};
            return hmac_sha256(zero_salt, ikm);
        }
        return hmac_sha256(salt, ikm);
    }

    auto hkdf_expand(const std::span<const std::uint8_t> prk, const std::span<const std::uint8_t> info,
                     const std::size_t length) -> std::pair<fault::code, std::vector<std::uint8_t>>
    {
        if (length > 255 * sha256_len)
        {
            return {fault::code::invalid_argument, {}};
        }

        if (prk.size() < sha256_len)
        {
            return {fault::code::invalid_argument, {}};
        }

        constexpr std::size_t max_info_size = 514;
        if (info.size() > max_info_size)
        {
            return {fault::code::invalid_argument, {}};
        }

        std::vector<std::uint8_t> result;
        result.reserve(length);

        std::array<std::uint8_t, sha256_len> t{};
        std::size_t t_size = 0;
        std::size_t offset = 0;
        std::uint8_t counter = 1;

        while (offset < length)
        {
            constexpr std::size_t max_hmac_buf = sha256_len + max_info_size + 1;
            std::array<std::uint8_t, max_hmac_buf> hmac_buf;
            const auto hmac_size = t_size + info.size() + 1;
            if (t_size > 0)
            {
                std::memcpy(hmac_buf.data(), t.data(), t_size);
            }
            if (!info.empty())
            {
                std::memcpy(hmac_buf.data() + t_size, info.data(), info.size());
            }
            hmac_buf[hmac_size - 1] = counter;

            const auto block = hmac_sha256(prk.first(sha256_len), {hmac_buf.data(), hmac_size});

            const auto to_copy = std::min(sha256_len, length - offset);
            result.insert(result.end(), block.begin(), block.begin() + static_cast<std::ptrdiff_t>(to_copy));
            offset += to_copy;

            t = block;
            t_size = sha256_len;
            ++counter;
        }

        return {fault::code::success, std::move(result)};
    }

    auto expand_label(const expand_params params) -> std::pair<fault::code, std::vector<std::uint8_t>>
    {
        const auto &secret = params.secret;
        const auto &label = params.label;
        const auto &context = params.context;
        const auto length = params.length;
        constexpr std::string_view tls13_prefix = "tls13 ";
        const auto full_label_len = tls13_prefix.size() + label.size();

        if (full_label_len > 255)
        {
            return {fault::code::invalid_argument, {}};
        }

        if (context.size() > 255)
        {
            return {fault::code::invalid_argument, {}};
        }

        constexpr std::size_t max_label_buf = 2 + 1 + 255 + 1 + 255;
        std::array<std::uint8_t, max_label_buf> label_buf;
        std::size_t pos = 0;

        label_buf[pos++] = static_cast<std::uint8_t>((length >> 8) & 0xFF);
        label_buf[pos++] = static_cast<std::uint8_t>(length & 0xFF);

        label_buf[pos++] = static_cast<std::uint8_t>(full_label_len);
        std::memcpy(label_buf.data() + pos, tls13_prefix.data(), tls13_prefix.size());
        pos += tls13_prefix.size();
        std::memcpy(label_buf.data() + pos, label.data(), label.size());
        pos += label.size();

        label_buf[pos++] = static_cast<std::uint8_t>(context.size());
        if (!context.empty())
        {
            std::memcpy(label_buf.data() + pos, context.data(), context.size());
            pos += context.size();
        }

        return hkdf_expand(secret, {label_buf.data(), pos}, length);
    }

    auto sha256(const std::span<const std::uint8_t> data) -> std::array<std::uint8_t, sha256_len>
    {
        std::array<std::uint8_t, sha256_len> hash{};
        ::SHA256(data.data(), data.size(), hash.data());
        return hash;
    }

    auto sha256(const std::span<const std::uint8_t> data1, const std::span<const std::uint8_t> data2)
        -> std::array<std::uint8_t, sha256_len>
    {
        std::array<std::uint8_t, sha256_len> hash{};

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx)
        {
            return hash;
        }

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
        {
            EVP_MD_CTX_free(ctx);
            return hash;
        }

        if (EVP_DigestUpdate(ctx, data1.data(), data1.size()) != 1 ||
            EVP_DigestUpdate(ctx, data2.data(), data2.size()) != 1)
        {
            EVP_MD_CTX_free(ctx);
            return hash;
        }

        std::uint32_t hash_len = 0;
        EVP_DigestFinal_ex(ctx, hash.data(), &hash_len);
        EVP_MD_CTX_free(ctx);

        return hash;
    }

    auto sha256(const std::span<const std::uint8_t> data1, const std::span<const std::uint8_t> data2,
                const std::span<const std::uint8_t> data3) -> std::array<std::uint8_t, sha256_len>
    {
        std::array<std::uint8_t, sha256_len> hash{};

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx)
        {
            return hash;
        }

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
        {
            EVP_MD_CTX_free(ctx);
            return hash;
        }

        if (EVP_DigestUpdate(ctx, data1.data(), data1.size()) != 1 ||
            EVP_DigestUpdate(ctx, data2.data(), data2.size()) != 1 ||
            EVP_DigestUpdate(ctx, data3.data(), data3.size()) != 1)
        {
            EVP_MD_CTX_free(ctx);
            return hash;
        }

        std::uint32_t hash_len = 0;
        EVP_DigestFinal_ex(ctx, hash.data(), &hash_len);
        EVP_MD_CTX_free(ctx);

        return hash;
    }


} // namespace psmtest::crypto
