#pragma once
#include <cstdint>

/**
 * @brief SOCKS5 协议
 * @note 参考 https://blog.csdn.net/qq_40873884/article/details/123636767
 */
namespace ngx::protocol::socks5
{
    /**
     * @brief SOCKS5 命令类型
     */
    enum class command : std::uint8_t
    {
        /**
         * @brief 建立 TCP 连接
         */
        connect = 0x01,
        
        /**
         * @brief 绑定端口
         */
        bind = 0x02,
        
        /**
         * @brief 建立 UDP 关联
         */
        udp_associate = 0x03
    };

    /**
     * @brief 地址类型
     */
    enum class address_type : std::uint8_t
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

    /**
     * @brief 响应码
     * @note 每个响应码对应一个字节的值
     */
    enum class reply_code : std::uint8_t
    {
        /**
         * @brief 成功
         */
        succeeded = 0x00,

        /**
         * @brief 服务器失败
         */
        server_failure = 0x01,

        /**
         * @brief 连接不允许
         */
        connection_not_allowed = 0x02,

        /**
         * @brief 网络不可达
         */
        network_unreachable = 0x03,

        /**
         * @brief 主机不可达
         */
        host_unreachable = 0x04,

        /**
         * @brief 连接被拒绝
         */
        connection_refused = 0x05,

        /**
         * @brief TTL 过期
         */
        ttl_expired = 0x06,

        /**
         * @brief 命令不支持
         */
        command_not_supported = 0x07,

        /**
         * @brief 地址类型不支持
         */
        address_type_not_supported = 0x08
    };
}
