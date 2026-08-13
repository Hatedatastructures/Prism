/**
 * @file keygen.cpp
 * @brief ECH 密钥生成与序列化实现
 */

#include <prism/handshake/ech/util/keygen.hpp>

#include <openssl/base64.h>
#include <openssl/rand.h>

#include <cstring>

namespace psm::handshake::ech
{

    namespace
    {
        /**
         * @brief 释放 EVP_HPKE_KEY
         * @param key 待释放的 HPKE 密钥句柄
         */
        void hpke_key_free(EVP_HPKE_KEY *key)
        {
            if (key)
            {
                EVP_HPKE_KEY_free(key);
            }
        }

        using hpke_key_ptr = std::unique_ptr<EVP_HPKE_KEY, decltype(&hpke_key_free)>;

        /**
         * @brief 从私钥构造 HPKE 密钥
         * @param private_key X25519 私钥
         * @return 构造成功的 HPKE 密钥（失败时为空）
         */
        [[nodiscard]] auto make_hpke_key(std::span<const std::uint8_t, private_key_len> private_key)
            -> hpke_key_ptr
        {
            auto *key = EVP_HPKE_KEY_new();
            if (!key)
            {
                return {nullptr, &hpke_key_free};
            }
            if (!EVP_HPKE_KEY_init(key, EVP_hpke_x25519_hkdf_sha256(), private_key.data(),
                                   private_key.size()))
            {
                EVP_HPKE_KEY_free(key);
                return {nullptr, &hpke_key_free};
            }
            return {key, &hpke_key_free};
        }

        /**
         * @brief 构建 ECHConfigList（uint16 长度前缀 + ECHConfig）
         * @param ech_config 待封装的 ECHConfig 字节序列
         * @return 带长度前缀的 ECHConfigList
         */
        [[nodiscard]] auto build_config_list(std::span<const std::uint8_t> ech_config)
            -> memory::vector<std::uint8_t>
        {
            memory::vector<std::uint8_t> list;
            list.reserve(2 + ech_config.size());
            list.push_back(static_cast<std::uint8_t>(ech_config.size() >> 8));
            list.push_back(static_cast<std::uint8_t>(ech_config.size() & 0xFF));
            list.insert(list.end(), ech_config.begin(), ech_config.end());
            return list;
        }
    } // namespace

    auto generate_keypair(const std::string_view public_name, const std::size_t max_name_len,
                          ech_keypair &out) -> fault::code
    {
        // 生成 X25519 HPKE 密钥
        EVP_HPKE_KEY *raw = EVP_HPKE_KEY_new();
        if (!raw)
        {
            return fault::code::crypto_error;
        }
        if (!EVP_HPKE_KEY_generate(raw, EVP_hpke_x25519_hkdf_sha256()))
        {
            EVP_HPKE_KEY_free(raw);
            return fault::code::crypto_error;
        }
        hpke_key_ptr key(raw, &hpke_key_free);

        // 导出私钥
        std::array<std::uint8_t, private_key_len> private_key{};
        std::size_t private_len = 0;
        if (!EVP_HPKE_KEY_private_key(key.get(), private_key.data(), &private_len, private_key.size()))
        {
            return fault::code::crypto_error;
        }

        // 构造 ECHConfig
        std::uint8_t config_id = 0;
        RAND_bytes(&config_id, 1);
        std::uint8_t *config_out = nullptr;
        std::size_t config_len = 0;
        if (!SSL_marshal_ech_config(&config_out, &config_len, config_id, key.get(),
                                    std::string(public_name).c_str(), max_name_len))
        {
            return fault::code::crypto_error;
        }

        std::copy(private_key.begin(), private_key.end(), out.private_key.begin());
        out.ech_config.assign(config_out, config_out + config_len);
        OPENSSL_free(config_out);
        out.ech_config_list = build_config_list(out.ech_config);
        return fault::code::success;
    }

    auto keypair_from_private(const std::span<const std::uint8_t, private_key_len> private_key,
                              const std::string_view public_name, const std::size_t max_name_len,
                              ech_keypair &out) -> fault::code
    {
        auto key = make_hpke_key(private_key);
        if (!key)
        {
            return fault::code::crypto_error;
        }

        std::uint8_t *config_out = nullptr;
        std::size_t config_len = 0;
        if (!SSL_marshal_ech_config(&config_out, &config_len, 0, key.get(), std::string(public_name).c_str(),
                                    max_name_len))
        {
            return fault::code::crypto_error;
        }

        std::copy(private_key.begin(), private_key.end(), out.private_key.begin());
        out.ech_config.assign(config_out, config_out + config_len);
        OPENSSL_free(config_out);
        out.ech_config_list = build_config_list(out.ech_config);
        return fault::code::success;
    }

    auto make_ech_keys(const std::span<const std::uint8_t, private_key_len> private_key,
                       const std::span<const std::uint8_t> ech_config) -> SSL_ECH_KEYS *
    {
        auto key = make_hpke_key(private_key);
        if (!key)
        {
            return nullptr;
        }

        auto *keys = SSL_ECH_KEYS_new();
        if (!keys)
        {
            return nullptr;
        }

        if (!SSL_ECH_KEYS_add(keys, 1 /* retry config */, ech_config.data(), ech_config.size(), key.get()))
        {
            SSL_ECH_KEYS_free(keys);
            return nullptr;
        }
        return keys;
    }

    auto base64_encode(const std::span<const std::uint8_t> data) -> std::string
    {
        if (data.empty())
        {
            return {};
        }
        const auto encoded_len = ((data.size() + 2) / 3) * 4;
        std::string out(encoded_len, '\0');
        EVP_EncodeBlock(reinterpret_cast<std::uint8_t *>(out.data()), data.data(),
                        static_cast<int>(data.size()));
        // 移除标准 base64 的 '=' 填充（URL 安全形式）
        while (!out.empty() && out.back() == '=')
        {
            out.pop_back();
        }
        return out;
    }

    auto base64_decode(const std::string_view text, memory::vector<std::uint8_t> &out) -> bool
    {
        if (text.empty())
        {
            return false;
        }

        // 补充填充
        std::string padded(text);
        while (padded.size() % 4 != 0)
        {
            padded.push_back('=');
        }
        std::size_t pad_count = 0;
        for (auto it = padded.rbegin(); it != padded.rend() && *it == '='; ++it)
        {
            ++pad_count;
        }

        std::vector<std::uint8_t> buf(padded.size());
        const int decoded = EVP_DecodeBlock(buf.data(), reinterpret_cast<const std::uint8_t *>(padded.data()),
                                            static_cast<int>(padded.size()));
        if (decoded < 0)
        {
            return false;
        }

        out.clear();
        out.insert(out.end(), buf.begin(), buf.begin() + (decoded - static_cast<int>(pad_count)));
        return true;
    }

} // namespace psm::handshake::ech
