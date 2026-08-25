/**
 * @file keygen.hpp
 * @brief ECH 密钥生成与 SSL_ECH_KEYS 构造（移植自主项目 handshake/ech/util/keygen）
 * @details 基于 BoringSSL EVP_HPKE_KEY + SSL_marshal_ech_config：
 *          - GenerateKeypair：随机 X25519 密钥 + ECHConfig 序列化
 *          - KeypairFromPrivate：由私钥恢复 ECHConfig
 *          - MakeEchKeys：构造 SSL_ECH_KEYS（服务端 TLS 上下文注册）
 * @note 使用 Preview::Fault 错误码（与 Preview 库一致）
 */

#pragma once

#include <common/Core/Fault/Code.hpp>
#include <common/Core/Memory/Container.hpp>

#include <openssl/ssl.h>

#include <array>
#include <cstdint>
#include <span>
#include <string_view>

namespace Preview::Ech
{

    /// X25519 私钥长度
    inline constexpr std::size_t PrivateKeyLen = 32;

    /**
     * @struct EchKeypair
     * @brief 生成的 ECH 密钥对
     */
    struct EchKeypair
    {
        std::array<std::uint8_t, PrivateKeyLen> private_key{}; ///< X25519 私钥
        std::vector<std::uint8_t> EchConfig;                 ///< 序列化 ECHConfig
        std::vector<std::uint8_t> EchConfigList;            ///< ECHConfigList（含长度前缀）
    };

    /**
     * @brief 生成新的 ECH 密钥对
     * @param public_name 公开伪装域名
     * @param max_name_len 最大域名长度（影响客户端填充）
     * @param out 输出密钥对
     * @return 错误码
     */
    [[nodiscard]] auto GenerateKeypair(std::string_view public_name, std::size_t max_name_len,
                                        EchKeypair &out) -> Preview::Fault::Code;

    /**
     * @brief 由私钥恢复 ECHConfig
     * @param private_key 32 字节 X25519 私钥
     * @param public_name 公开伪装域名
     * @param max_name_len 最大域名长度
     * @param out 输出密钥对（含 ECHConfig）
     * @return 错误码
     */
    [[nodiscard]] auto KeypairFromPrivate(std::span<const std::uint8_t, PrivateKeyLen> private_key,
                                            std::string_view public_name, std::size_t max_name_len,
                                            EchKeypair &out) -> Preview::Fault::Code;

    /**
     * @brief 由 ECHConfig 与私钥构造 SSL_ECH_KEYS（服务端注册用）
     * @param private_key 32 字节 X25519 私钥
     * @param EchConfig 序列化 ECHConfig
     * @return SSL_ECH_KEYS 指针（失败返回 nullptr），调用方负责 SSL_ECH_KEYS_free
     */
    [[nodiscard]] auto MakeEchKeys(std::span<const std::uint8_t, PrivateKeyLen> private_key,
                                     std::span<const std::uint8_t> EchConfig) -> SSL_ECH_KEYS *;

} // namespace Preview::Ech

// ── 实现（Header-only inline） ─────────────────────────────────────

#include <openssl/base64.h>
#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/rand.h>

#include <memory>
#include <string>

namespace
{
    inline void HpkeKeyFree(EVP_HPKE_KEY *key)
    {
        if (key)
        {
            EVP_HPKE_KEY_free(key);
        }
    }

    using HpkeKeyPtr = std::unique_ptr<EVP_HPKE_KEY, decltype(&HpkeKeyFree)>;

    inline auto MakeHpkeKey(std::span<const std::uint8_t, Preview::Ech::PrivateKeyLen> private_key)
        -> HpkeKeyPtr
    {
        auto *key = EVP_HPKE_KEY_new();
        if (!key)
        {
            return HpkeKeyPtr(nullptr, &HpkeKeyFree);
        }
        if (!EVP_HPKE_KEY_init(key, EVP_hpke_x25519_hkdf_sha256(), private_key.data(), private_key.size()))
        {
            EVP_HPKE_KEY_free(key);
            return HpkeKeyPtr(nullptr, &HpkeKeyFree);
        }
        return HpkeKeyPtr(key, &HpkeKeyFree);
    }

    inline auto BuildConfigList(std::span<const std::uint8_t> EchConfig)
        -> Preview::Memory::vector<std::uint8_t>
    {
        Preview::Memory::vector<std::uint8_t> List;
        List.reserve(2 + EchConfig.size());
        List.push_back(static_cast<std::uint8_t>(EchConfig.size() >> 8));
        List.push_back(static_cast<std::uint8_t>(EchConfig.size() & 0xFF));
        List.insert(List.end(), EchConfig.begin(), EchConfig.end());
        return List;
    }
} // namespace

namespace Preview::Ech
{

    inline auto GenerateKeypair(std::string_view public_name, std::size_t max_name_len,
                                 EchKeypair &out) -> Preview::Fault::Code
    {
        auto *raw = EVP_HPKE_KEY_new();
        if (!raw)
        {
            return Preview::Fault::Code::crypto_error;
        }
        if (!EVP_HPKE_KEY_generate(raw, EVP_hpke_x25519_hkdf_sha256()))
        {
            EVP_HPKE_KEY_free(raw);
            return Preview::Fault::Code::crypto_error;
        }
        HpkeKeyPtr key(raw, &HpkeKeyFree);

        std::array<std::uint8_t, PrivateKeyLen> private_key{};
        std::size_t PrivateLen = 0;
        if (!EVP_HPKE_KEY_private_key(key.get(), private_key.data(), &PrivateLen, private_key.size()))
        {
            return Preview::Fault::Code::crypto_error;
        }

        std::uint8_t ConfigId = 0;
        if (RAND_bytes(&ConfigId, 1) != 1)
        {
            return Preview::Fault::Code::crypto_error;
        }
        std::uint8_t *config_out = nullptr;
        std::size_t ConfigLen = 0;
        if (!SSL_marshal_ech_config(&config_out, &ConfigLen, ConfigId, key.get(),
                                    std::string(public_name).c_str(), max_name_len))
        {
            return Preview::Fault::Code::crypto_error;
        }

        std::copy(private_key.begin(), private_key.end(), out.private_key.begin());
        out.EchConfig.assign(config_out, config_out + ConfigLen);
        OPENSSL_free(config_out);
        out.EchConfigList = BuildConfigList(out.EchConfig);
        return Preview::Fault::Code::success;
    }

    inline auto KeypairFromPrivate(std::span<const std::uint8_t, PrivateKeyLen> private_key,
                                     std::string_view public_name, std::size_t max_name_len,
                                     EchKeypair &out) -> Preview::Fault::Code
    {
        auto key = MakeHpkeKey(private_key);
        if (!key)
        {
            return Preview::Fault::Code::crypto_error;
        }

        std::uint8_t *config_out = nullptr;
        std::size_t ConfigLen = 0;
        if (!SSL_marshal_ech_config(&config_out, &ConfigLen, 0, key.get(), std::string(public_name).c_str(),
                                    max_name_len))
        {
            return Preview::Fault::Code::crypto_error;
        }

        std::copy(private_key.begin(), private_key.end(), out.private_key.begin());
        out.EchConfig.assign(config_out, config_out + ConfigLen);
        OPENSSL_free(config_out);
        out.EchConfigList = BuildConfigList(out.EchConfig);
        return Preview::Fault::Code::success;
    }

    inline auto MakeEchKeys(std::span<const std::uint8_t, PrivateKeyLen> private_key,
                              std::span<const std::uint8_t> EchConfig) -> SSL_ECH_KEYS *
    {
        auto key = MakeHpkeKey(private_key);
        if (!key)
        {
            return nullptr;
        }
        auto *keys = SSL_ECH_KEYS_new();
        if (!keys)
        {
            return nullptr;
        }
        if (!SSL_ECH_KEYS_add(keys, 1, EchConfig.data(), EchConfig.size(), key.get()))
        {
            SSL_ECH_KEYS_free(keys);
            return nullptr;
        }
        return keys;
    }

} // namespace Preview::Ech