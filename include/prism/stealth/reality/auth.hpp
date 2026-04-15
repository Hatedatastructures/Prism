/**
 * @file auth.hpp
 * @brief Reality 认证逻辑
 * @details 实现 Reality 协议的客户端认证流程：
 * 1. 检查 SNI 是否匹配 server_names
 * 2. 检查 key_share 扩展是否包含 X25519 公钥
 * 3. 计算 X25519 共享密钥
 * 4. 验证 session_id 中的 short_id 和认证数据
 * 认证成功后返回共享密钥和服务端临时密钥对。
 */

#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <utility>
#include <prism/crypto/x25519.hpp>
#include <prism/fault/code.hpp>
#include <prism/stealth/reality/config.hpp>
#include <prism/stealth/reality/request.hpp>
#include <prism/stealth/reality/constants.hpp>

namespace psm::stealth
{
    /**
     * @struct auth_result
     * @brief Reality 认证结果
     */
    struct auth_result
    {
        /// 认证是否成功
        bool authenticated = false;

        /// X25519 共享密钥
        std::array<std::uint8_t, tls::REALITY_KEY_LEN> shared_secret{};

        /// 服务端临时 X25519 密钥对（用于 ServerHello 的 key_share）
        crypto::x25519_keypair server_ephemeral_key;

        /// HKDF 派生的认证密钥（用于 Ed25519 证书签名）
        std::array<std::uint8_t, tls::REALITY_KEY_LEN> auth_key{};
    };

    /**
     * @brief 执行 Reality 认证
     * @param cfg Reality 配置
     * @param client_hello 解析后的 ClientHello 信息
     * @param decoded_private_key 已 base64 解码的 32 字节私钥
     * @return 错误码和认证结果
     */
    [[nodiscard]] auto authenticate(const config &cfg, const client_hello_info &client_hello,
                                    std::span<const std::uint8_t> decoded_private_key)
        -> std::pair<fault::code, auth_result>;

    /**
     * @brief 检查 SNI 是否匹配
     */
    [[nodiscard]] auto match_server_name(std::string_view sni,
                                         const memory::vector<memory::string> &server_names) -> bool;

    /**
     * @brief 匹配 short_id
     */
    [[nodiscard]] auto match_short_id(std::span<const std::uint8_t> short_id,
                                      const memory::vector<memory::string> &allowed_short_ids) -> bool;

    /**
     * @brief 十六进制字符串转字节
     */
    [[nodiscard]] auto hex_to_bytes(std::string_view hex) -> memory::vector<std::uint8_t>;

    /**
     * @brief 单个十六进制字符转数值
     */
    [[nodiscard]] auto hex_digit(char c) -> int;
} // namespace psm::stealth
