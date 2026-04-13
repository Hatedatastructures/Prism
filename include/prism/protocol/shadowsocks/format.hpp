/**
 * @file format.hpp
 * @brief SS2022 协议格式编解码声明
 * @details 提供 SS2022 协议的地址解析、PSK 解码等底层解析函数声明。
 */

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <prism/fault/code.hpp>
#include <prism/protocol/shadowsocks/message.hpp>

namespace psm::protocol::shadowsocks::format
{
    /**
     * @struct address_parse_result
     * @brief 地址解析结果
     */
    struct address_parse_result
    {
        address addr;         ///< 目标地址
        std::uint16_t port{}; ///< 目标端口
        std::size_t offset{}; ///< 地址+端口在缓冲区中占用的总字节数
    };

    /**
     * @brief 从缓冲区解析 SOCKS5 风格地址和端口
     * @param buffer 包含 ATYP+ADDR+PORT 的缓冲区
     * @return 错误码和解析结果
     */
    [[nodiscard]] auto parse_address_port(std::span<const std::uint8_t> buffer)
        -> std::pair<fault::code, address_parse_result>;

    /**
     * @brief 解码 base64 PSK 并验证长度
     * @param base64_psk Base64 编码的 PSK 字符串
     * @return 错误码和原始 PSK 字节（16 或 32 字节）
     */
    [[nodiscard]] auto decode_psk(std::string_view base64_psk)
        -> std::pair<fault::code, std::vector<std::uint8_t>>;

    /**
     * @brief 根据加密方法获取 key/salt 长度
     */
    [[nodiscard]] constexpr auto key_salt_length(cipher_method method) noexcept -> std::size_t
    {
        return method == cipher_method::aes_128_gcm ? 16 : 32;
    }

    /**
     * @brief 根据加密方法获取 KDF 上下文字符串
     * @note SIP022 规范要求所有方法统一使用 "shadowsocks 2022 session subkey"
     */
    [[nodiscard]] constexpr auto kdf_context_for(cipher_method /*method*/) noexcept -> std::string_view
    {
        return kdf_context;
    }

    /**
     * @brief 从配置方法字符串解析加密方法
     * @param method_str 方法名字符串（可为空，自动推断）
     * @param psk_len PSK 字节长度（用于自动推断）
     * @return 加密方法枚举
     */
    [[nodiscard]] auto resolve_cipher_method(std::string_view method_str, std::size_t psk_len) noexcept
        -> cipher_method;
} // namespace psm::protocol::shadowsocks::format
