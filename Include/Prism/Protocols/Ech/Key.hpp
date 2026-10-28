/**
 * @file Key.hpp
 * @brief ECH 私有密钥生成与 TLS key-container 构造。
 * @details 基于 BoringSSL EVP_HPKE_KEY + SSL_marshal_ech_config：
 *          - GenerateKeypair：随机 X25519 密钥 + ECHConfig 序列化
 *          - KeypairFromPrivate：由私钥恢复 ECHConfig
 *          - MakeEchKeys：构造由调用者拥有的 SSL_ECH_KEYS 句柄
 * @note 使用 Prism::Fault 错误码（与 Prism 库一致）
 */

#pragma once

#include <Prism/Foundation/Fault/Code.hpp>
#include <Prism/Foundation/Memory/Container.hpp>

#include <openssl/ssl.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace Prism::Ech::Detail
{

    /// X25519 私钥长度
    inline constexpr std::size_t PrivateKeyLen = 32;

    using EchKeys = std::unique_ptr<SSL_ECH_KEYS, decltype(&SSL_ECH_KEYS_free)>;

    /**
     * @struct EchKeypair
     * @brief 生成的 ECH 密钥对
     */
    struct EchKeypair
    {
        std::array<std::uint8_t, PrivateKeyLen> PrivateKey{}; ///< X25519 私钥
        std::vector<std::uint8_t> EchConfig;                  ///< 序列化 ECHConfig
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
        EchKeypair &Output) -> Prism::Fault::Code;

    /**
     * @brief 由私钥恢复 ECHConfig
     * @param Params 私钥恢复参数
     * @return 错误码
     */
    [[nodiscard]] auto KeypairFromPrivate(const KeypairParameters &Params) -> Prism::Fault::Code;

    /**
     * @brief 由 ECHConfig 与私钥构造 SSL_ECH_KEYS owning 句柄
     * @param PrivateKey 32 字节 X25519 私钥
     * @param EchConfig 序列化 ECHConfig
     * @return 拥有 SSL_ECH_KEYS 的句柄；调用方销毁句柄后释放其资源
     */
    [[nodiscard]] auto MakeEchKeys(
        std::span<const std::uint8_t, PrivateKeyLen> PrivateKey,
        std::span<const std::uint8_t> EchConfig) -> EchKeys;

} // namespace Prism::Ech::Detail
