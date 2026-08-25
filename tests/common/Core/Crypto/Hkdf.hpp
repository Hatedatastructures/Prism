/**
 * @file hkdf.hpp
 * @brief HKDF-SHA256 密钥派生工具
 * @details 提供 HMAC-SHA256、HKDF-Extract、HKDF-Expand 和
 * TLS 1.3 专用的 HKDF-Expand-Label 函数。这些函数是 TLS 1.3
 * 密钥调度的核心组件，用于从 ECDHE 共享密钥派生握手和应用流量密钥。
 * 基于 BoringSSL 的 HMAC API 实现。
 * @note SHA-256 输出固定 32 字节，HKDF-Expand 输出长度可变。
 * @note 已分叉，各自演进（与主库 foundation 无镜像同步约束）
 */

#pragma once

#include <cstring>

#include <openssl/sha.h>

#include <openssl/hmac.h>

#include <openssl/evp.h>

#include <common/Core/Fault/Code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace Preview::Crypto
{

    /**
     * @brief SHA-256 输出长度（字节）
     */
    constexpr std::size_t Sha256Len = 32;

    /**
     * @brief SHA-512 输出长度（字节）
     */
    constexpr std::size_t Sha512Len = 64;

    /**
     * @brief HMAC-SHA256
     * @param key HMAC 密钥
     * @param Data 输入数据
     * @return 32 字节 HMAC-SHA256 结果
     * @details 计算 HMAC-SHA256(key, Data)，用于 HKDF-Extract
     * 和 TLS 1.3 Finished 消息的 verify_data 计算。
     */
    [[nodiscard]] auto HmacSha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> Data)
        -> std::array<std::uint8_t, Sha256Len>;

    /**
     * @brief HMAC-SHA512
     * @param key HMAC 密钥
     * @param Data 输入数据
     * @return 64 字节 HMAC-SHA512 结果
     */
    [[nodiscard]] auto HmacSha512(std::span<const std::uint8_t> key, std::span<const std::uint8_t> Data)
        -> std::array<std::uint8_t, Sha512Len>;

    /**
     * @brief HKDF-Extract
     * @param salt 盐值（可以为空）
     * @param ikm 输入密钥材料
     * @return 32 字节伪随机密钥 (PRK)
     * @details 计算 PRK = HMAC-SHA256(salt, IKM)。
     * 当 salt 为空时使用 32 字节全零作为盐值（RFC 5869）。
     */
    [[nodiscard]] auto HkdfExtract(std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ikm)
        -> std::array<std::uint8_t, Sha256Len>;

    /**
     * @brief HKDF-Expand
     * @param prk 伪随机密钥（32 字节）
     * @param Info 上下文信息
     * @param length 输出长度（最大 255 * 32 = 8160 字节）
     * @return 错误码和输出字节的配对
     * @details 按照 RFC 5869 实现 HKDF-Expand：
     * T(1) = HMAC-SHA256(PRK, Info || 0x01)
     * T(N) = HMAC-SHA256(PRK, T(N-1) || Info || N)
     * Output = T(1) || T(2) || ... || T(N)
     */
    [[nodiscard]] auto HkdfExpand(std::span<const std::uint8_t> prk, std::span<const std::uint8_t> Info,
                                   std::size_t length) -> std::pair<Fault::Code, std::vector<std::uint8_t>>;

    /**
     * @struct ExpandLabelParams
     * @brief HKDF-Expand-Label 参数
     * @details 组合 TLS 1.3 HKDF-Expand-Label 调用所需的全部参数。
     */
    struct ExpandParams
    {
        std::span<const std::uint8_t> Secret;  ///< 输入密钥
        std::string_view Label;                ///< 标签（如 "key", "iv", "finished"）
        std::span<const std::uint8_t> Context; ///< 上下文数据（通常是 transcript Hash）
        std::size_t length = 0;                ///< 输出长度
    };

    /**
     * @brief TLS 1.3 HKDF-Expand-Label
     * @param params 扩展标签参数
     * @return 错误码和输出字节的配对
     * @details 按照 RFC 8446 Section 7.1 实现：
     * HkdfLabel = Length(2) || label_len(1) || "tls13 " + Label || context_len(1) || Context
     * HKDF-Expand-Label(Secret, Label, Context, Length) = HKDF-Expand(Secret, HkdfLabel, Length)
     * @note TLS 1.3 自动在 Label 前添加 "tls13 " 前缀。
     */
    [[nodiscard]] auto ExpandLabel(ExpandParams params)
        -> std::pair<Fault::Code, std::vector<std::uint8_t>>;

    /**
     * @brief SHA-256 哈希
     * @param Data 输入数据
     * @return 32 字节 SHA-256 哈希值
     * @details 计算 SHA-256(Data)，用于 TLS 1.3 transcript Hash。
     */
    [[nodiscard]] auto Sha256(std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, Sha256Len>;

    /**
     * @brief SHA-256 哈希（两个数据块拼接）
     * @param data1 第一个数据块
     * @param data2 第二个数据块
     * @return 32 字节 SHA-256 哈希值
     * @details 计算 SHA-256(data1 || data2)，用于 TLS 1.3 transcript Hash。
     * 比 concat 后再 Hash 更高效，避免额外内存分配。
     */
    [[nodiscard]] auto Sha256(std::span<const std::uint8_t> data1, std::span<const std::uint8_t> data2)
        -> std::array<std::uint8_t, Sha256Len>;

    /**
     * @brief SHA-256 哈希（三个数据块拼接）
     * @param data1 第一个数据块
     * @param data2 第二个数据块
     * @param data3 第三个数据块
     * @return 32 字节 SHA-256 哈希值
     * @details 计算 SHA-256(data1 || data2 || data3)，用于 TLS 1.3 transcript Hash。
     */
    [[nodiscard]] auto Sha256(std::span<const std::uint8_t> data1, std::span<const std::uint8_t> data2,
                              std::span<const std::uint8_t> data3) -> std::array<std::uint8_t, Sha256Len>;



    inline auto HmacSha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> Data)
        -> std::array<std::uint8_t, Sha256Len>
    {
        std::array<std::uint8_t, Sha256Len> Result{};

        std::uint32_t MacLen = 0;
        const auto *ret = HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), Data.data(),
                               Data.size(), Result.data(), &MacLen);

        if (!ret)
        {
            Result.fill(0);
        }

        return Result;
    }

    inline auto HmacSha512(std::span<const std::uint8_t> key, std::span<const std::uint8_t> Data)
        -> std::array<std::uint8_t, Sha512Len>
    {
        std::array<std::uint8_t, Sha512Len> Result{};

        std::uint32_t MacLen = 0;
        const auto *ret = HMAC(EVP_sha512(), key.data(), static_cast<int>(key.size()), Data.data(),
                               Data.size(), Result.data(), &MacLen);

        if (!ret)
        {
            Result.fill(0);
        }

        return Result;
    }

    inline auto HkdfExtract(std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ikm)
        -> std::array<std::uint8_t, Sha256Len>
    {
        if (salt.empty())
        {
            std::array<std::uint8_t, Sha256Len> zero_salt{};
            return HmacSha256(zero_salt, ikm);
        }
        return HmacSha256(salt, ikm);
    }

    inline auto HkdfExpand(std::span<const std::uint8_t> prk, std::span<const std::uint8_t> Info,
                            const std::size_t length) -> std::pair<Fault::Code, std::vector<std::uint8_t>>
    {
        if (length > 255 * Sha256Len)
        {
            return {Fault::Code::invalid_argument, {}};
        }

        if (prk.size() < Sha256Len)
        {
            return {Fault::Code::invalid_argument, {}};
        }

        constexpr std::size_t MaxInfoSize = 514;
        if (Info.size() > MaxInfoSize)
        {
            return {Fault::Code::invalid_argument, {}};
        }

        std::vector<std::uint8_t> Result;
        Result.reserve(length);

        std::array<std::uint8_t, Sha256Len> t{};
        std::size_t TSize = 0;
        std::size_t offset = 0;
        std::uint8_t counter = 1;

        while (offset < length)
        {
            constexpr std::size_t MaxHmacBuf = Sha256Len + MaxInfoSize + 1;
            std::array<std::uint8_t, MaxHmacBuf> hmac_buf;
            const auto HmacSize = TSize + Info.size() + 1;
            if (TSize > 0)
            {
                std::memcpy(hmac_buf.data(), t.data(), TSize);
            }
            if (!Info.empty())
            {
                std::memcpy(hmac_buf.data() + TSize, Info.data(), Info.size());
            }
            hmac_buf[HmacSize - 1] = counter;

            const auto block = HmacSha256(prk.first(Sha256Len), {hmac_buf.data(), HmacSize});

            const auto ToCopy = std::min(Sha256Len, length - offset);
            Result.insert(Result.end(), block.begin(), block.begin() + static_cast<std::ptrdiff_t>(ToCopy));
            offset += ToCopy;

            t = block;
            TSize = Sha256Len;
            ++counter;
        }

        return {Fault::Code::success, std::move(Result)};
    }

    inline auto ExpandLabel(const ExpandParams params)
        -> std::pair<Fault::Code, std::vector<std::uint8_t>>
    {
        const auto &Secret = params.Secret;
        const auto &Label = params.Label;
        const auto &Context = params.Context;
        const auto length = params.length;
        constexpr std::string_view Tls13Prefix = "tls13 ";
        const auto FullLabelLen = Tls13Prefix.size() + Label.size();

        if (FullLabelLen > 255)
        {
            return {Fault::Code::invalid_argument, {}};
        }

        if (Context.size() > 255)
        {
            return {Fault::Code::invalid_argument, {}};
        }

        constexpr std::size_t MaxLabelBuf = 2 + 1 + 255 + 1 + 255;
        std::array<std::uint8_t, MaxLabelBuf> label_buf;
        std::size_t pos = 0;

        label_buf[pos++] = static_cast<std::uint8_t>((length >> 8) & 0xFF);
        label_buf[pos++] = static_cast<std::uint8_t>(length & 0xFF);

        label_buf[pos++] = static_cast<std::uint8_t>(FullLabelLen);
        std::memcpy(label_buf.data() + pos, Tls13Prefix.data(), Tls13Prefix.size());
        pos += Tls13Prefix.size();
        std::memcpy(label_buf.data() + pos, Label.data(), Label.size());
        pos += Label.size();

        label_buf[pos++] = static_cast<std::uint8_t>(Context.size());
        if (!Context.empty())
        {
            std::memcpy(label_buf.data() + pos, Context.data(), Context.size());
            pos += Context.size();
        }

        return HkdfExpand(Secret, {label_buf.data(), pos}, length);
    }

    inline auto Sha256(std::span<const std::uint8_t> Data) -> std::array<std::uint8_t, Sha256Len>
    {
        std::array<std::uint8_t, Sha256Len> Hash{};
        ::SHA256(Data.data(), Data.size(), Hash.data());
        return Hash;
    }

    inline auto Sha256(std::span<const std::uint8_t> data1, std::span<const std::uint8_t> data2)
        -> std::array<std::uint8_t, Sha256Len>
    {
        std::array<std::uint8_t, Sha256Len> Hash{};

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx)
        {
            return Hash;
        }

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
        {
            EVP_MD_CTX_free(ctx);
            return Hash;
        }

        if (EVP_DigestUpdate(ctx, data1.data(), data1.size()) != 1 ||
            EVP_DigestUpdate(ctx, data2.data(), data2.size()) != 1)
        {
            EVP_MD_CTX_free(ctx);
            return Hash;
        }

        std::uint32_t HashLen = 0;
        EVP_DigestFinal_ex(ctx, Hash.data(), &HashLen);
        EVP_MD_CTX_free(ctx);

        return Hash;
    }

    inline auto Sha256(std::span<const std::uint8_t> data1, std::span<const std::uint8_t> data2,
                       const std::span<const std::uint8_t> data3) -> std::array<std::uint8_t, Sha256Len>
    {
        std::array<std::uint8_t, Sha256Len> Hash{};

        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx)
        {
            return Hash;
        }

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
        {
            EVP_MD_CTX_free(ctx);
            return Hash;
        }

        if (EVP_DigestUpdate(ctx, data1.data(), data1.size()) != 1 ||
            EVP_DigestUpdate(ctx, data2.data(), data2.size()) != 1 ||
            EVP_DigestUpdate(ctx, data3.data(), data3.size()) != 1)
        {
            EVP_MD_CTX_free(ctx);
            return Hash;
        }

        std::uint32_t HashLen = 0;
        EVP_DigestFinal_ex(ctx, Hash.data(), &HashLen);
        EVP_MD_CTX_free(ctx);

        return Hash;
    }


} // namespace Preview::Crypto
