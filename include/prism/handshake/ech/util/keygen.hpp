/**
 * @file keygen.hpp
 * @brief ECH 密钥生成与序列化
 * @details 基于 BoringSSL 的 EVP_HPKE_KEY 与 SSL_marshal_ech_config：
 *          生成 X25519 HPKE 密钥对 + ECHConfig（draft-18），
 *          支持私钥/公配置的 base64 编解码与往返恢复。
 */

#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/foundation/memory/container.hpp>

#include <openssl/hpke.h>
#include <openssl/ssl.h>

#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace psm::handshake::ech
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
     * @brief 生成新的 ECH 密钥对与配置
     * @param public_name 公开伪装域名
     * @param max_name_len 匿名集合中最大名称长度（影响客户端填充）
     * @param out 输出密钥对
     * @return 错误码
     */
    [[nodiscard]] auto generate_keypair(std::string_view public_name, std::size_t max_name_len,
                                        ech_keypair &out) -> fault::code;

    /**
     * @brief 从私钥恢复 ECHConfig
     * @param private_key 32 字节 X25519 私钥
     * @param public_name 公开伪装域名
     * @param max_name_len 最大名称长度
     * @param out 输出密钥对（含 ECHConfig）
     * @return 错误码
     */
    [[nodiscard]] auto keypair_from_private(std::span<const std::uint8_t, private_key_len> private_key,
                                            std::string_view public_name, std::size_t max_name_len,
                                            ech_keypair &out) -> fault::code;

    /**
     * @brief 从 ECHConfig 与私钥构造 SSL_ECH_KEYS（服务端注册用）
     * @param private_key 32 字节 X25519 私钥
     * @param ech_config 序列化 ECHConfig
     * @return SSL_ECH_KEYS 指针（失败返回 nullptr），调用方负责释放
     */
    [[nodiscard]] auto make_ech_keys(std::span<const std::uint8_t, private_key_len> private_key,
                                     std::span<const std::uint8_t> ech_config) -> SSL_ECH_KEYS *;

    /**
     * @brief Base64 编码（无填充，URL 安全）
     * @param data 输入
     * @return 编码字符串
     */
    [[nodiscard]] auto base64_encode(std::span<const std::uint8_t> data) -> std::string;

    /**
     * @brief Base64 解码（兼容标准与 URL 安全）
     * @param text 输入
     * @param out 输出
     * @return 是否成功
     */
    [[nodiscard]] auto base64_decode(std::string_view text, memory::vector<std::uint8_t> &out) -> bool;

} // namespace psm::handshake::ech
