/**
 * @file Keygen.hpp
 * @brief ECH 密钥生成与 SSL_ECH_KEYS 构造（移植自主项目 handshake/ech/util/keygen）
 * @details 基于 BoringSSL EVP_HPKE_KEY + SSL_marshal_ech_config：
 *          - GenerateKeypair：随机 X25519 密钥 + ECHConfig 序列化
 *          - KeypairFromPrivate：由私钥恢复 ECHConfig
 *          - MakeEchKeys：构造 SSL_ECH_KEYS（服务端 TLS 上下文注册）
 * @note 使用 Preview::Fault 错误码（与 Preview 库一致）
 */

#pragma once

#include <preview/Foundation/Fault/Code.hpp>
#include <preview/Foundation/Memory/Container.hpp>

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
        std::array<std::uint8_t, PrivateKeyLen> private_key{}; ///< X25519 私钥（兼容公共字段）
        std::vector<std::uint8_t> EchConfig;                 ///< 序列化 ECHConfig
        std::vector<std::uint8_t> EchConfigList;            ///< ECHConfigList（含长度前缀）
    };

    /**
     * @brief ECH 私钥恢复参数
     * @details PrivateKey、PublicName 和 Out 均为借用对象，
     *          调用期间必须保持有效。
     */
    struct KeypairParameters
    {
        std::span<const std::uint8_t, PrivateKeyLen> PrivateKey;
        std::string_view PublicName;
        std::size_t MaxNameLen;
        EchKeypair &Out;
    };

    /**
     * @brief 生成新的 ECH 密钥对
     * @param PublicName 公开伪装域名
     * @param MaxNameLen 最大域名长度（影响客户端填充）
     * @param Output 输出密钥对
     * @return 错误码
     */
    [[nodiscard]] auto GenerateKeypair(
        std::string_view PublicName,
        std::size_t MaxNameLen,
        EchKeypair &Output) -> Preview::Fault::Code;

    /**
     * @brief 由私钥恢复 ECHConfig
     * @param Params 私钥恢复参数
     * @return 错误码
     */
    [[nodiscard]] auto KeypairFromPrivate(const KeypairParameters &Params) -> Preview::Fault::Code;

    /**
     * @brief 由 ECHConfig 与私钥构造 SSL_ECH_KEYS（服务端注册用）
     * @param PrivateKey 32 字节 X25519 私钥
     * @param EchConfig 序列化 ECHConfig
     * @return SSL_ECH_KEYS 指针（失败返回 nullptr），调用方负责 SSL_ECH_KEYS_free
     */
    [[nodiscard]] auto MakeEchKeys(
        std::span<const std::uint8_t, PrivateKeyLen> PrivateKey,
        std::span<const std::uint8_t> EchConfig) -> SSL_ECH_KEYS *;

} // namespace Preview::Ech

// ── 实现（Header-only inline） ─────────────────────────────────────

#include <openssl/base64.h>
#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/rand.h>

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

namespace
{
    inline auto HpkeKeyFree(EVP_HPKE_KEY *Key) -> void
    {
        if (Key)
        {
            EVP_HPKE_KEY_free(Key);
        }
    }

    using HpkeKeyPtr = std::unique_ptr<EVP_HPKE_KEY, decltype(&HpkeKeyFree)>;

    inline auto MakeHpkeKey(
        std::span<const std::uint8_t, Preview::Ech::PrivateKeyLen> PrivateKey)
        -> HpkeKeyPtr
    {
        auto *Key = EVP_HPKE_KEY_new();
        if (!Key)
        {
            return HpkeKeyPtr(nullptr, &HpkeKeyFree);
        }
        if (!EVP_HPKE_KEY_init(Key, EVP_hpke_x25519_hkdf_sha256(), PrivateKey.data(), PrivateKey.size()))
        {
            EVP_HPKE_KEY_free(Key);
            return HpkeKeyPtr(nullptr, &HpkeKeyFree);
        }
        return HpkeKeyPtr(Key, &HpkeKeyFree);
    }

    inline auto BuildConfigList(std::span<const std::uint8_t> EchConfig)
        -> std::vector<std::uint8_t>
    {
        if (EchConfig.size() > 0xFFFF)
        {
            return {};
        }
        std::vector<std::uint8_t> List;
        List.reserve(2 + EchConfig.size());
        List.push_back(static_cast<std::uint8_t>(EchConfig.size() >> 8));
        List.push_back(static_cast<std::uint8_t>(EchConfig.size() & 0xFF));
        List.insert(List.end(), EchConfig.begin(), EchConfig.end());
        return List;
    }
} // namespace

namespace Preview::Ech
{

    inline auto GenerateKeypair(
        std::string_view PublicName,
        std::size_t MaxNameLen,
        EchKeypair &Output) -> Preview::Fault::Code
    {
        auto *RawKey = EVP_HPKE_KEY_new();
        if (!RawKey)
        {
            return Preview::Fault::Code::CryptoError;
        }
        if (!EVP_HPKE_KEY_generate(RawKey, EVP_hpke_x25519_hkdf_sha256()))
        {
            EVP_HPKE_KEY_free(RawKey);
            return Preview::Fault::Code::CryptoError;
        }
        HpkeKeyPtr Key(RawKey, &HpkeKeyFree);

        std::array<std::uint8_t, PrivateKeyLen> PrivateKey{};
        std::size_t PrivateLen = 0;
        if (!EVP_HPKE_KEY_private_key(Key.get(), PrivateKey.data(), &PrivateLen, PrivateKey.size()))
        {
            return Preview::Fault::Code::CryptoError;
        }

        std::uint8_t ConfigId = 0;
        if (RAND_bytes(&ConfigId, 1) != 1)
        {
            return Preview::Fault::Code::CryptoError;
        }
        std::uint8_t *ConfigOut = nullptr;
        std::size_t ConfigLen = 0;
        if (!SSL_marshal_ech_config(&ConfigOut, &ConfigLen, ConfigId, Key.get(),
                                    std::string(PublicName).c_str(), MaxNameLen))
        {
            return Preview::Fault::Code::CryptoError;
        }

        std::copy(PrivateKey.begin(), PrivateKey.end(), Output.private_key.begin());
        Output.EchConfig.assign(ConfigOut, ConfigOut + ConfigLen);
        OPENSSL_free(ConfigOut);
        Output.EchConfigList = BuildConfigList(Output.EchConfig);
        if (Output.EchConfigList.empty())
        {
            Output.EchConfig.clear();
            return Preview::Fault::Code::InvalidArgument;
        }
        return Preview::Fault::Code::Success;
    }

    inline auto KeypairFromPrivate(const KeypairParameters &Params) -> Preview::Fault::Code
    {
        auto Key = MakeHpkeKey(Params.PrivateKey);
        if (!Key)
        {
            return Preview::Fault::Code::CryptoError;
        }

        std::uint8_t *ConfigOut = nullptr;
        std::size_t ConfigLen = 0;
        if (!SSL_marshal_ech_config(&ConfigOut, &ConfigLen, 0, Key.get(),
                                    std::string(Params.PublicName).c_str(), Params.MaxNameLen))
        {
            return Preview::Fault::Code::CryptoError;
        }

        std::copy(Params.PrivateKey.begin(), Params.PrivateKey.end(), Params.Out.private_key.begin());
        Params.Out.EchConfig.assign(ConfigOut, ConfigOut + ConfigLen);
        OPENSSL_free(ConfigOut);
        Params.Out.EchConfigList = BuildConfigList(Params.Out.EchConfig);
        if (Params.Out.EchConfigList.empty())
        {
            Params.Out.EchConfig.clear();
            return Preview::Fault::Code::InvalidArgument;
        }
        return Preview::Fault::Code::Success;
    }

    inline auto MakeEchKeys(
        std::span<const std::uint8_t, PrivateKeyLen> PrivateKey,
        std::span<const std::uint8_t> EchConfig) -> SSL_ECH_KEYS *
    {
        auto Key = MakeHpkeKey(PrivateKey);
        if (!Key)
        {
            return nullptr;
        }
        auto *keys = SSL_ECH_KEYS_new();
        if (!keys)
        {
            return nullptr;
        }
        if (!SSL_ECH_KEYS_add(keys, 1, EchConfig.data(), EchConfig.size(), Key.get()))
        {
            SSL_ECH_KEYS_free(keys);
            return nullptr;
        }
        return keys;
    }

} // namespace Preview::Ech
