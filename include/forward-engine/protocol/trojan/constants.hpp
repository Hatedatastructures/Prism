#pragma once
#include <cstdint>

namespace ngx::protocol::trojan
{
    /**
     * @brief Trojan 命令
     */
    enum class command : uint8_t
    {
        /**
         * @brief 连接
         */
        connect = 0x01,

        /**
         * @brief UDP 关联
         */
        udp_associate = 0x03
    };

    /**
     * @brief Trojan 地址类型
     */
    enum class address_type : uint8_t
    {
        /**
         * @brief IPv4 地址
         */
        ipv4 = 0x01,

        /**
         * @brief 域名地址
         */
        domain = 0x03,

        /**
         * @brief IPv6 地址
         */
        ipv6 = 0x04
    };
}
