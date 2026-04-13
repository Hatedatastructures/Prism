/**
 * @file hkdf.cpp
 * @brief HKDF-SHA256 密钥派生实现
 * @details 使用 BoringSSL 的 HMAC 和 SHA256 API 实现 HKDF。
 * HKDF-Expand-Label 遵循 RFC 8446 Section 7.1 的 HkdfLabel 格式。
 */

#include <prism/crypto/hkdf.hpp>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <cstring>
#include <prism/trace.hpp>

namespace psm::crypto
{
    constexpr std::string_view HkdfTag = "[Crypto.HKDF]";

    auto hmac_sha256(const std::span<const std::uint8_t> key, const std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, SHA256_LEN>
    {
        std::array<std::uint8_t, SHA256_LEN> result{};

        unsigned int mac_len = 0;
        HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
             data.data(), data.size(), result.data(), &mac_len);

        return result;
    }

    auto hkdf_extract(const std::span<const std::uint8_t> salt, const std::span<const std::uint8_t> ikm)
        -> std::array<std::uint8_t, SHA256_LEN>
    {
        // salt 为空时使用全零
        if (salt.empty())
        {
            std::array<std::uint8_t, SHA256_LEN> zero_salt{};
            return hmac_sha256(zero_salt, ikm);
        }
        return hmac_sha256(salt, ikm);
    }

    auto hkdf_expand(const std::span<const std::uint8_t> prk, const std::span<const std::uint8_t> info,
                     const std::size_t length)
        -> std::pair<fault::code, std::vector<std::uint8_t>>
    {
        // RFC 5869: 最大输出长度 = 255 * HashLen
        if (length > 255 * SHA256_LEN)
        {
            trace::error("{} HKDF-Expand requested length {} exceeds max {}", HkdfTag, length, 255 * SHA256_LEN);
            return {fault::code::invalid_argument, {}};
        }

        if (prk.size() < SHA256_LEN)
        {
            trace::error("{} HKDF-Expand PRK too short: {}", HkdfTag, prk.size());
            return {fault::code::invalid_argument, {}};
        }

        std::vector<std::uint8_t> result;
        result.reserve(length);

        // T(0) = empty
        // T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
        std::vector<std::uint8_t> t;
        std::size_t offset = 0;
        std::uint8_t counter = 1;

        while (offset < length)
        {
            // 构造 HMAC 输入: T(i-1) || info || counter
            std::vector<std::uint8_t> hmac_input;
            hmac_input.reserve(t.size() + info.size() + 1);
            hmac_input.insert(hmac_input.end(), t.begin(), t.end());
            hmac_input.insert(hmac_input.end(), info.begin(), info.end());
            hmac_input.push_back(counter);

            t.clear();
            const auto block = hmac_sha256(prk.first(SHA256_LEN), hmac_input);

            const auto to_copy = std::min(SHA256_LEN, length - offset);
            result.insert(result.end(), block.begin(), block.begin() + static_cast<std::ptrdiff_t>(to_copy));
            offset += to_copy;

            // T(i) = 完整的 block（不是截断后的）
            t.assign(block.begin(), block.end());
            ++counter;
        }

        return {fault::code::success, std::move(result)};
    }

    auto hkdf_expand_label(const std::span<const std::uint8_t> secret, const std::string_view label,
                           const std::span<const std::uint8_t> context, const std::size_t length)
        -> std::pair<fault::code, std::vector<std::uint8_t>>
    {
        // RFC 8446 Section 7.1:
        // struct {
        //     uint16 length = Length;
        //     opaque label<7..255> = "tls13 " + Label;
        //     opaque context<0..255> = Context;
        // } HkdfLabel;

        // "tls13 " 前缀 + 用户 label
        static constexpr std::string_view tls13_prefix = "tls13 ";
        const std::string full_label = std::string(tls13_prefix) + std::string(label);

        // 检查 label 长度
        if (full_label.size() > 255)
        {
            trace::error("{} HKDF-Expand-Label label too long: {}", HkdfTag, full_label.size());
            return {fault::code::invalid_argument, {}};
        }

        // 检查 context 长度
        if (context.size() > 255)
        {
            trace::error("{} HKDF-Expand-Label context too long: {}", HkdfTag, context.size());
            return {fault::code::invalid_argument, {}};
        }

        // 构建 HkdfLabel info
        // Length (2 bytes, big-endian) || label_len (1 byte) || label || context_len (1 byte) || context
        std::vector<std::uint8_t> hkdf_label;
        hkdf_label.reserve(2 + 1 + full_label.size() + 1 + context.size());

        // Length: 2 字节大端
        hkdf_label.push_back(static_cast<std::uint8_t>((length >> 8) & 0xFF));
        hkdf_label.push_back(static_cast<std::uint8_t>(length & 0xFF));

        // Label: 1 字节长度前缀 + 内容
        hkdf_label.push_back(static_cast<std::uint8_t>(full_label.size()));
        hkdf_label.insert(hkdf_label.end(), full_label.begin(), full_label.end());

        // Context: 1 字节长度前缀 + 内容
        hkdf_label.push_back(static_cast<std::uint8_t>(context.size()));
        hkdf_label.insert(hkdf_label.end(), context.begin(), context.end());

        return hkdf_expand(secret, hkdf_label, length);
    }

    auto sha256(const std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, SHA256_LEN>
    {
        std::array<std::uint8_t, SHA256_LEN> hash{};
        ::SHA256(data.data(), data.size(), hash.data());
        return hash;
    }

    auto sha256(const std::span<const std::uint8_t> data1, const std::span<const std::uint8_t> data2)
        -> std::array<std::uint8_t, SHA256_LEN>
    {
        std::array<std::uint8_t, SHA256_LEN> hash{};

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

        EVP_DigestUpdate(ctx, data1.data(), data1.size());
        EVP_DigestUpdate(ctx, data2.data(), data2.size());

        unsigned int hash_len = 0;
        EVP_DigestFinal_ex(ctx, hash.data(), &hash_len);
        EVP_MD_CTX_free(ctx);

        return hash;
    }

    auto sha256(const std::span<const std::uint8_t> data1, const std::span<const std::uint8_t> data2,
                const std::span<const std::uint8_t> data3)
        -> std::array<std::uint8_t, SHA256_LEN>
    {
        std::array<std::uint8_t, SHA256_LEN> hash{};

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

        EVP_DigestUpdate(ctx, data1.data(), data1.size());
        EVP_DigestUpdate(ctx, data2.data(), data2.size());
        EVP_DigestUpdate(ctx, data3.data(), data3.size());

        unsigned int hash_len = 0;
        EVP_DigestFinal_ex(ctx, hash.data(), &hash_len);
        EVP_MD_CTX_free(ctx);

        return hash;
    }
} // namespace psm::crypto
