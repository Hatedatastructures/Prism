#pragma once
#include <cstdint>

namespace ngx::protocol::trojan
{
    enum class command : uint8_t
    {
        connect = 0x01,
        udp_associate = 0x03
    };

    enum class address_type : uint8_t
    {
        ipv4 = 0x01,
        domain = 0x03,
        ipv6 = 0x04
    };
}
