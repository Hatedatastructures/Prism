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
#include <prism/protocol/reality/config.hpp>
#include <prism/protocol/reality/request.hpp>
#include <prism/protocol/reality/constants.hpp>

namespace psm::protocol::reality
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
     * @details 认证流程：
     * 1. 检查 SNI 是否在 server_names 列表中
     * 2. 检查客户端是否提供了 X25519 公钥
     * 3. 计算 shared_secret = X25519(private_key, client_public_key)
     * 4. 从 session_id 提取 short_id 并匹配配置
     * 5. 生成服务端临时密钥对
     */
    [[nodiscard]] auto authenticate(const config &cfg, const client_hello_info &client_hello,
                                    std::span<const std::uint8_t> decoded_private_key)
        -> std::pair<fault::code, auth_result>;

    /**
     * @brief 检查 SNI 是否匹配
     * @param sni 客户端的 SNI
     * @param server_names 允许的 SNI 列表
     * @return 匹配返回 true
     */
    [[nodiscard]] auto match_server_name(std::string_view sni,
                                         const memory::vector<memory::string> &server_names) -> bool;

    /**
     * @brief 匹配 short_id
     * @param short_id 从 session_id 提取的 short_id
     * @param allowed_short_ids 配置中的允许 short_id 列表（hex 编码）
     * @return 匹配返回 true
     */
    [[nodiscard]] auto match_short_id(std::span<const std::uint8_t> short_id,
                                      const memory::vector<memory::string> &allowed_short_ids) -> bool;

    /**
     * @brief 十六进制字符串转字节
     * @param hex 十六进制字符串
     * @return 字节数组，无效输入返回空
     */
    [[nodiscard]] auto hex_to_bytes(std::string_view hex) -> memory::vector<std::uint8_t>;

    /**
     * @brief 单个十六进制字符转数值
     * @param c 十六进制字符
     * @return 数值 0-15，无效字符返回 -1
     */
    [[nodiscard]] auto hex_digit(char c) -> int;
} // namespace psm::protocol::reality
