/**
 * @file keygen.hpp
 * @brief ECH 密钥生成与 SSL_ECH_KEYS 构造（移植自主项目 handshake/ech/util/keygen）
 * @details 基于 BoringSSL EVP_HPKE_KEY + SSL_marshal_ech_config：
 *          - generate_keypair：随机 X25519 密钥 + ECHConfig 序列化
 *          - keypair_from_private：由私钥恢复 ECHConfig
 *          - make_ech_keys：构造 SSL_ECH_KEYS（服务端 TLS 上下文注册）
 * @note 使用 psmtest::fault 错误码（与 psmtest 库一致）
 */

#pragma once

#include <common/core/fault/code.hpp>
#include <common/core/memory/container.hpp>

#include <openssl/ssl.h>

#include <array>
#include <cstdint>
#include <span>
#include <string_view>

namespace psmtest::ech
{

    /// X25519 私钥长度
    inline constexpr std::size_t private_key_len = 32;

    /**
     * @struct ech_keypair
     * @brief 生成的 ECH 密钥对
     */
    struct ech_keypair
    {
        std::array<std::uint8_t, private_key_len> private_key{}; ///< X25519 私钥
        memory::vector<std::uint8_t> ech_config;                 ///< 序列化 ECHConfig
        memory::vector<std::uint8_t> ech_config_list;            ///< ECHConfigList（含长度前缀）
    };

    /**
     * @brief 生成新的 ECH 密钥对
     * @param public_name 公开伪装域名
     * @param max_name_len 最大域名长度（影响客户端填充）
     * @param out 输出密钥对
     * @return 错误码
     */
    [[nodiscard]] auto generate_keypair(std::string_view public_name, std::size_t max_name_len,
                                        ech_keypair &out) -> psmtest::fault::code;

    /**
     * @brief 由私钥恢复 ECHConfig
     * @param private_key 32 字节 X25519 私钥
     * @param public_name 公开伪装域名
     * @param max_name_len 最大域名长度
     * @param out 输出密钥对（含 ECHConfig）
     * @return 错误码
     */
    [[nodiscard]] auto keypair_from_private(std::span<const std::uint8_t, private_key_len> private_key,
                                            std::string_view public_name, std::size_t max_name_len,
                                            ech_keypair &out) -> psmtest::fault::code;

    /**
     * @brief 由 ECHConfig 与私钥构造 SSL_ECH_KEYS（服务端注册用）
     * @param private_key 32 字节 X25519 私钥
     * @param ech_config 序列化 ECHConfig
     * @return SSL_ECH_KEYS 指针（失败返回 nullptr），调用方负责 SSL_ECH_KEYS_free
     */
    [[nodiscard]] auto make_ech_keys(std::span<const std::uint8_t, private_key_len> private_key,
                                     std::span<const std::uint8_t> ech_config) -> SSL_ECH_KEYS *;

} // namespace psmtest::ech

// ── 实现（header-only inline） ─────────────────────────────────────

#include <openssl/base64.h>
#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/rand.h>

#include <memory>
#include <string>

namespace
{
    inline void hpke_key_free(EVP_HPKE_KEY *key)
    {
        if (key)
        {
            EVP_HPKE_KEY_free(key);
        }
    }

    using hpke_key_ptr = std::unique_ptr<EVP_HPKE_KEY, decltype(&hpke_key_free)>;

    inline auto make_hpke_key(std::span<const std::uint8_t, psmtest::ech::private_key_len> private_key)
        -> hpke_key_ptr
    {
        auto *key = EVP_HPKE_KEY_new();
        if (!key)
        {
            return hpke_key_ptr(nullptr, &hpke_key_free);
        }
        if (!EVP_HPKE_KEY_init(key, EVP_hpke_x25519_hkdf_sha256(), private_key.data(), private_key.size()))
        {
            EVP_HPKE_KEY_free(key);
            return hpke_key_ptr(nullptr, &hpke_key_free);
        }
        return hpke_key_ptr(key, &hpke_key_free);
    }

    inline auto build_config_list(std::span<const std::uint8_t> ech_config)
        -> psmtest::memory::vector<std::uint8_t>
    {
        psmtest::memory::vector<std::uint8_t> list;
        list.reserve(2 + ech_config.size());
        list.push_back(static_cast<std::uint8_t>(ech_config.size() >> 8));
        list.push_back(static_cast<std::uint8_t>(ech_config.size() & 0xFF));
        list.insert(list.end(), ech_config.begin(), ech_config.end());
        return list;
    }
} // namespace

namespace psmtest::ech
{

    inline auto generate_keypair(std::string_view public_name, std::size_t max_name_len,
                                 ech_keypair &out) -> psmtest::fault::code
    {
        auto *raw = EVP_HPKE_KEY_new();
        if (!raw)
        {
            return psmtest::fault::code::crypto_error;
        }
        if (!EVP_HPKE_KEY_generate(raw, EVP_hpke_x25519_hkdf_sha256()))
        {
            EVP_HPKE_KEY_free(raw);
            return psmtest::fault::code::crypto_error;
        }
        hpke_key_ptr key(raw, &hpke_key_free);

        std::array<std::uint8_t, private_key_len> private_key{};
        std::size_t private_len = 0;
        if (!EVP_HPKE_KEY_private_key(key.get(), private_key.data(), &private_len, private_key.size()))
        {
            return psmtest::fault::code::crypto_error;
        }

        std::uint8_t config_id = 0;
        if (RAND_bytes(&config_id, 1) != 1)
        {
            return psmtest::fault::code::crypto_error;
        }
        std::uint8_t *config_out = nullptr;
        std::size_t config_len = 0;
        if (!SSL_marshal_ech_config(&config_out, &config_len, config_id, key.get(),
                                    std::string(public_name).c_str(), max_name_len))
        {
            return psmtest::fault::code::crypto_error;
        }

        std::copy(private_key.begin(), private_key.end(), out.private_key.begin());
        out.ech_config.assign(config_out, config_out + config_len);
        OPENSSL_free(config_out);
        out.ech_config_list = build_config_list(out.ech_config);
        return psmtest::fault::code::success;
    }

    inline auto keypair_from_private(std::span<const std::uint8_t, private_key_len> private_key,
                                     std::string_view public_name, std::size_t max_name_len,
                                     ech_keypair &out) -> psmtest::fault::code
    {
        auto key = make_hpke_key(private_key);
        if (!key)
        {
            return psmtest::fault::code::crypto_error;
        }

        std::uint8_t *config_out = nullptr;
        std::size_t config_len = 0;
        if (!SSL_marshal_ech_config(&config_out, &config_len, 0, key.get(), std::string(public_name).c_str(),
                                    max_name_len))
        {
            return psmtest::fault::code::crypto_error;
        }

        std::copy(private_key.begin(), private_key.end(), out.private_key.begin());
        out.ech_config.assign(config_out, config_out + config_len);
        OPENSSL_free(config_out);
        out.ech_config_list = build_config_list(out.ech_config);
        return psmtest::fault::code::success;
    }

    inline auto make_ech_keys(std::span<const std::uint8_t, private_key_len> private_key,
                              std::span<const std::uint8_t> ech_config) -> SSL_ECH_KEYS *
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
        if (!SSL_ECH_KEYS_add(keys, 1, ech_config.data(), ech_config.size(), key.get()))
        {
            SSL_ECH_KEYS_free(keys);
            return nullptr;
        }
        return keys;
    }

} // namespace psmtest::ech