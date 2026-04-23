/**
 * @file auth.hpp
 * @brief ShadowTLS v3 认证逻辑
 * @details 基于 HMAC-SHA1 的认证机制。ShadowTLS v3 在 TLS ClientHello
 * 的 SessionID 字段中嵌入 4 字节 HMAC 标签进行身份验证。
 *
 * 认证算法（sing-shadowtls v3_server.go verifyClientHello）：
 *   HMAC = HMAC-SHA1(password, ClientHello[10:hmac_index] + 00000000 + ClientHello[hmac_index+4:])[:4]
 *
 * 握手完成后的数据帧处理：
 *   HMAC_Verify = HMAC-SHA1(password, serverRandom + "C")
 *   HMAC_Write = HMAC-SHA1(password, serverRandom + "S")
 *   WriteKey = SHA256(password + serverRandom)
 */
#pragma once

#include <span>
#include <string_view>
#include <string>
#include <array>
#include <vector>
#include <cstdint>
#include <optional>

namespace psm::stealth::shadowtls
{
    /**
     * @brief 验证 ClientHello 中的 SessionID HMAC
     * @details 从 ClientHello 帧（含 TLS 记录头）中提取 SessionID 的
     * 后 4 字节 HMAC 标签，与本地计算结果比较。
     * @param client_hello ClientHello 帧数据（含 TLS 记录头）
     * @param password 认证密码
     * @return true 如果认证通过
     */
    [[nodiscard]] auto verify_client_hello(std::span<const std::byte> client_hello,
                                            std::string_view password) -> bool;

    /**
     * @brief 计算 HMAC-SHA1 标签
     * @details HMAC-SHA1(password, data)[:4]
     * @param key HMAC 密钥（密码）
     * @param data 要认证的数据
     * @return 4 字节 HMAC 标签
     */
    [[nodiscard]] auto compute_hmac(std::string_view key, std::span<const std::byte> data)
        -> std::array<std::uint8_t, 4>;

    /**
     * @brief 验证握手后的数据帧 HMAC
     * @details HMAC-SHA1(password, serverRandom + "C" + payload)[:4]
     * 与服务端收到的帧头 4 字节比较。
     * @param password 密码
     * @param server_random TLS ServerRandom（32 字节）
     * @param payload 数据帧 payload（不含 TLS header 和 HMAC）
     * @param client_hmac 客户端帧头中的 4 字节 HMAC
     * @return true 如果匹配
     */
    [[nodiscard]] auto verify_frame_hmac(std::string_view password,
                                          std::span<const std::byte> server_random,
                                          std::span<const std::byte> payload,
                                          std::span<const std::uint8_t, 4> client_hmac) -> bool;

    /**
     * @brief 生成数据帧的 HMAC 标签（服务端写入方向）
     * @details HMAC-SHA1(password, serverRandom + "S" + modified_payload)[:4]
     * @param password 密码
     * @param server_random TLS ServerRandom
     * @param payload 修改后的 payload
     * @return 4 字节 HMAC 标签
     */
    [[nodiscard]] auto compute_write_hmac(std::string_view password,
                                           std::span<const std::byte> server_random,
                                           std::span<const std::byte> payload)
        -> std::array<std::uint8_t, 4>;

    /**
     * @brief 生成写入密钥（XOR 加密用）
     * @details SHA256(password + serverRandom)
     * @param password 密码
     * @param server_random TLS ServerRandom
     * @return 64 字节写入密钥（SHA256 输出 32 字节，此处取实际长度）
     */
    [[nodiscard]] auto compute_write_key(std::string_view password,
                                          std::span<const std::byte> server_random)
        -> std::vector<std::uint8_t>;
} // namespace psm::stealth::shadowtls
