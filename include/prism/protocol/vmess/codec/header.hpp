/**
 * @file header.hpp
 * @brief VMess 指令头与响应头编解码
 * @details 指令头明文（38 + H 字节）：
 *   version(1) requestNonce(16) requestKey(16) responseHeader(1)
 *   option(1) paddingLen<<4|security(1) reserved(1) command(1)
 *   [addrType(1) port(2 BE) addr] padding FNV-1a(4)
 *   请求封装：16B authID + GCM(2B len) + 8B connNonce + GCM(header)
 */

#pragma once

#include <prism/foundation/fault/code.hpp>
#include <prism/protocol/common/address.hpp>
#include <prism/protocol/vmess/constants.hpp>

#include <array>
#include <cstdint>
#include <span>

namespace psm::protocol::vmess::codec
{

    /**
     * @struct request_header
     * @brief 解析后的 VMess 指令头
     */
    struct request_header
    {
        std::uint8_t version{0};                         ///< 版本号
        std::array<std::uint8_t, 16> request_nonce{};    ///< 请求随机数（数据 nonce 源）
        std::array<std::uint8_t, 16> request_key{};      ///< 请求密钥（数据加密密钥）
        std::uint8_t response_header{0};                 ///< 响应头回显字节
        std::uint8_t option{0};                          ///< 选项位
        std::uint8_t security{0};                        ///< 安全类型
        std::uint8_t command{0};                         ///< 命令码
        psm::protocol::common::address destination;      ///< 目标地址
        std::uint16_t port{0};                           ///< 目标端口
    };

    /**
     * @brief 密封完整请求首包（模拟客户端用）
     * @param cmd_key 16 字节 cmdKey
     * @param header 指令头明文
     * @param out 输出序列化字节
     * @return 错误码
     */
    [[nodiscard]] auto seal_request(
        std::span<const std::uint8_t, 16> cmd_key, const request_header &header,
        std::span<std::uint8_t> out) -> fault::code;

    /**
     * @brief 解开完整请求首包（服务端用）
     * @param cmd_key 16 字节 cmdKey
     * @param first_packet 首包字节（>= aead_min_header_len）
     * @param conn_nonce 输出连接随机数
     * @param header 输出指令头明文
     * @return 错误码（auth_failed / bad_message / crypto_error）
     */
    [[nodiscard]] auto open_request(
        std::span<const std::uint8_t, 16> cmd_key,
        std::span<const std::uint8_t> first_packet,
        std::array<std::uint8_t, 8> &conn_nonce, request_header &header) -> fault::code;

    /**
     * @brief 解开请求长度块（服务端精确分段读取第二步）
     * @param cmd_key 16 字节 cmdKey
     * @param auth_id 16 字节认证 ID
     * @param len_block 18 字节长度块密文
     * @param conn_nonce 连接随机数（8 字节，wire 上位于 len 块之后）
     * @param header_len 输出指令头明文长度
     * @return 错误码
     */
    [[nodiscard]] auto open_len_block(
        std::span<const std::uint8_t, 16> cmd_key,
        std::span<const std::uint8_t, 16> auth_id,
        std::span<const std::uint8_t, 18> len_block,
        std::span<const std::uint8_t, 8> conn_nonce, std::size_t &header_len) -> fault::code;

    /**
     * @brief 解开请求载荷块（服务端精确分段读取第二步）
     * @param cmd_key 16 字节 cmdKey
     * @param auth_id 16 字节认证 ID
     * @param conn_nonce 连接随机数（8 字节）
     * @param payload_block 载荷块密文（header_len + 16）
     * @param header 输出指令头明文
     * @return 错误码
     */
    [[nodiscard]] auto open_payload(
        std::span<const std::uint8_t, 16> cmd_key,
        std::span<const std::uint8_t, 16> auth_id,
        std::span<const std::uint8_t, 8> conn_nonce,
        std::span<const std::uint8_t> payload_block, request_header &header) -> fault::code;

    /**
     * @brief 构造响应头字节流（AEAD 双段 GCM 或 legacy CFB）
     * @param request_key 16 字节 requestKey
     * @param request_nonce 16 字节 requestNonce
     * @param response_header 回显字节
     * @param option 回显选项
     * @param legacy 是否 legacy 协议（CFB 模式）
     * @param out 输出缓冲区（38 字节）
     * @return 错误码
     */
    [[nodiscard]] auto build_response(
        std::span<const std::uint8_t, 16> request_key,
        std::span<const std::uint8_t, 16> request_nonce,
        std::uint8_t response_header, std::uint8_t option, bool legacy,
        std::span<std::uint8_t> out) -> fault::code;

} // namespace psm::protocol::vmess::codec
