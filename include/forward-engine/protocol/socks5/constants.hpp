#pragma once
#include <cstdint>

namespace ngx::protocol::socks5
{
    /**
     * @brief SOCKS5 命令
     */
    enum class command : uint8_t
    {
        connect = 0x01,
        bind = 0x02,
        udp_associate = 0x03
    };

    /**
     * @brief 地址类型
     */
    enum class address_type : uint8_t
    {
        ipv4 = 0x01,
        domain = 0x03,
        ipv6 = 0x04
    };

    /**
     * @brief 响应码
     * @note 每个响应码对应一个字节的值
     */
    enum class reply_code : uint8_t
    {
        succeeded = 0x00,
        server_failure = 0x01,
        connection_not_allowed = 0x02,
        network_unreachable = 0x03,
        host_unreachable = 0x04,
        connection_refused = 0x05,
        ttl_expired = 0x06,
        command_not_supported = 0x07,
        address_type_not_supported = 0x08
    };
}
