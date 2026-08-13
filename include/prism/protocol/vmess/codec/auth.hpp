/**
 * @file auth.hpp
 * @brief VMess AEAD 认证头编解码
 * @details 认证头 16 字节：明文 P = timestamp(8B BE) || random(4B) ||
 *          CRC32-IEEE(P[0:12])(4B BE)，经 AES-128-ECB 加密。
 *          key = KDF(cmdKey, "AES Auth ID Encryption")[:16]。
 */

#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/protocol/vmess/constants.hpp>

#include <array>
#include <cstdint>
#include <span>

namespace psm::protocol::vmess::codec
{

    /**
     * @struct auth_result
     * @brief 认证头解密结果
     */
    struct auth_result
    {
        std::int64_t timestamp{0}; ///< 时间戳（Unix 秒）
        bool valid{false};         ///< CRC32 校验是否通过
    };

    /**
     * @brief 计算 CRC32-IEEE 校验和
     * @param data 输入数据
     * @return 32 位校验和
     */
    [[nodiscard]] auto crc32_ieee(std::span<const std::uint8_t> data) -> std::uint32_t;

    /**
     * @brief 计算 FNV-1a 32 位哈希
     * @param data 输入数据
     * @return 32 位哈希
     */
    [[nodiscard]] auto fnv1a_32(std::span<const std::uint8_t> data) -> std::uint32_t;

    /**
     * @brief 构造认证头明文并加密
     * @param cmd_key 16 字节 cmdKey
     * @param timestamp 当前 Unix 时间戳（秒）
     * @param out 输出缓冲区（16 字节）
     * @return 错误码
     */
    [[nodiscard]] auto seal_auth_header(std::span<const std::uint8_t, 16> cmd_key, std::int64_t timestamp,
                                        std::span<std::uint8_t, auth_header_len> out) -> fault::code;

    /**
     * @brief 解密并校验认证头
     * @param cmd_key 16 字节 cmdKey
     * @param auth_id 16 字节认证头
     * @return 解密结果（含时间戳与校验标记）
     */
    [[nodiscard]] auto open_auth_header(std::span<const std::uint8_t, 16> cmd_key,
                                        std::span<const std::uint8_t, auth_header_len> auth_id)
        -> auth_result;

} // namespace psm::protocol::vmess::codec
