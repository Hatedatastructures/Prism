/**
 * @file types.hpp
 * @brief 协议类型枚举
 * @details 定义代理系统支持的所有应用层协议类型枚举。原位于
 *          protocol/types.hpp，下沉到 net/ 以解除 account/net → proto 的
 *          循环依赖。
 */
#pragma once

#include <cstdint>
#include <string_view>


namespace psm::connect
{

/**
 * @enum protocol_type
 * @brief 协议类型枚举
 * @details 标识当前连接所使用的应用层协议类型。使用 enum class 提供类型安全。
 */
enum class protocol_type : std::uint8_t
{
    unknown,
    http,
    socks5,
    trojan,
    vless,
    shadowsocks,
    tls
};

/**
 * @brief 将协议类型转换为字符串视图
 * @param type 协议类型枚举值
 * @return 字符串表示
 */
[[nodiscard]] inline auto to_string_view(const protocol_type type)
    -> std::string_view
{
    switch (type)
    {
    case protocol_type::unknown:
        return "unknown";
    case protocol_type::http:
        return "http";
    case protocol_type::socks5:
        return "socks5";
    case protocol_type::trojan:
        return "trojan";
    case protocol_type::vless:
        return "vless";
    case protocol_type::shadowsocks:
        return "shadowsocks";
    case protocol_type::tls:
        return "tls";
    default:
        return "unknown";
    }
}

} // namespace psm::connect
