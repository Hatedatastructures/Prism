/**
 * @file auth.hpp
 * @brief Reality 认证逻辑
 * @details 实现 Reality 协议的客户端认证流程：检查 SNI 是否匹配
 * server_names，检查 key_share 扩展是否包含 X25519 公钥，计算
 * X25519 共享密钥，验证 session_id 中的 short_id 和认证数据。
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
        bool authenticated = false;                                     // 认证是否成功
        std::array<std::uint8_t, tls::REALITY_KEY_LEN> shared_secret{}; // X25519 共享密钥
        crypto::x25519_keypair server_ephemeral_key;                    // 服务端临时 X25519 密钥对（用于 ServerHello 的 key_share）
        std::array<std::uint8_t, tls::REALITY_KEY_LEN> auth_key{};      // HKDF 派生的认证密钥（用于 Ed25519 证书签名）
    };

    /**
     * @brief 执行 Reality 认证
     * @details 检查 SNI 匹配、X25519 密钥交换、short_id 验证等认证步骤，
     * 认证成功返回共享密钥和服务端临时密钥对
     * @param cfg Reality 配置
     * @param client_hello 解析后的 ClientHello 信息
     * @param decoded_private_key 已 base64 解码的 32 字节私钥
     * @return std::pair<fault::code, auth_result> 错误码和认证结果
     */
    [[nodiscard]] auto authenticate(const config &cfg, const client_hello_info &client_hello,
                                    std::span<const std::uint8_t> decoded_private_key)
        -> std::pair<fault::code, auth_result>;

    /**
     * @brief 检查 SNI 是否匹配
     * @details 遍历 server_names 列表检查是否有匹配项
     * @param sni 客户端 ClientHello 中的 SNI 值
     * @param server_names 配置中允许的 SNI 列表
     * @return bool 匹配返回 true
     */
    [[nodiscard]] auto match_server_name(std::string_view sni,
                                         const memory::vector<memory::string> &server_names) -> bool;

    /**
     * @brief 匹配 short_id
     * @details 遍历 allowed_short_ids 检查是否有匹配项，
     * 空字符串表示接受任意 short_id
     * @param short_id 客户端发送的 short_id 字节
     * @param allowed_short_ids 配置中允许的 short_id 列表（hex 编码）
     * @return bool 匹配返回 true
     */
    [[nodiscard]] auto match_short_id(std::span<const std::uint8_t> short_id,
                                      const memory::vector<memory::string> &allowed_short_ids) -> bool;

    /**
     * @brief 十六进制字符串转字节
     * @details 将 hex 编码的字符串解码为原始字节序列
     * @param hex 十六进制字符串
     * @return 解码后的字节向量
     */
    [[nodiscard]] auto hex_to_bytes(std::string_view hex) -> memory::vector<std::uint8_t>;

    /**
     * @brief 单个十六进制字符转数值
     * @details 将 0-9/a-f/A-F 字符转换为对应的数值
     * @param c 十六进制字符
     * @return 对应的数值，非法字符返回 -1
     */
    [[nodiscard]] auto hex_digit(char c) -> int;
} // namespace psm::stealth
