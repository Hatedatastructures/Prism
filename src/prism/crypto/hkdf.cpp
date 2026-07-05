#include <prism/crypto/hkdf.hpp>
#include <prism/trace/trace.hpp>
#include <prism/trace/context.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <cstring>

using namespace psm::trace;

namespace psm::crypto
{


    auto hmac_sha256(const std::span<const std::uint8_t> key, const std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, sha256_len>
    {
        std::array<std::uint8_t, sha256_len> result{};

        std::uint32_t mac_len = 0;
        const auto *ret = HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
             data.data(), data.size(), result.data(), &mac_len);

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
        const auto *ret = HMAC(EVP_sha512(), key.data(), static_cast<int>(key.size()),
             data.data(), data.size(), result.data(), &mac_len);

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


    auto hkdf_expand(const std::span<const std::uint8_t> prk, const std::span<const std::uint8_t> info, const std::size_t length)
        -> std::pair<fault::code, std::vector<std::uint8_t>>
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


    auto expand_label(const expand_params params)
        -> std::pair<fault::code, std::vector<std::uint8_t>>
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


    auto sha256(const std::span<const std::uint8_t> data)
        -> std::array<std::uint8_t, sha256_len>
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


    auto sha256(const std::span<const std::uint8_t> data1, const std::span<const std::uint8_t> data2, const std::span<const std::uint8_t> data3)
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

} // namespace psm::crypto
