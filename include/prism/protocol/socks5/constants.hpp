/**
 * @file constants.hpp
 * @brief SOCKS5 协议常量定义
 * @details 定义 SOCKS5 协议的命令字、地址类型、认证方法和响应码。
 * 这些常量直接映射 RFC 1928 规范中的协议字段值，用于协议解析
 * 和响应构建。所有枚举值均为单字节无符号整数，与协议格式保持
 * 一致，可直接用于网络字节序读写。
 */
#pragma once

#include <cstdint>

namespace psm::protocol::socks5
{
    /**
     * @enum command
     * @brief SOCKS5 命令类型
     * @details 定义客户端请求的命令类型，用于指示服务端执行的操作。
     * CONNECT 用于建立 TCP 隧道，BIND 用于反向连接，UDP_ASSOCIATE
     * 用于建立 UDP 中继。命令值直接对应协议字段，无需转换。
     */
    enum class command : std::uint8_t
    {
        /** @brief 建立 TCP 连接 */
        connect = 0x01,
        /** @brief 绑定端口等待反向连接 */
        bind = 0x02,
        /** @brief 建立 UDP 关联 */
        udp_associate = 0x03
    };

    /**
     * @enum address_type
     * @brief SOCKS5 地址类型
     * @details 定义目标地址的编码格式。IPv4 使用 4 字节二进制地址，
     * IPv6 使用 16 字节二进制地址，域名使用长度前缀加域名字符串。
     * 地址类型值直接对应协议 ATYP 字段。
     */
    enum class address_type : std::uint8_t
    {
        /** @brief IPv4 地址（4 字节） */
        ipv4 = 0x01,
        /** @brief 域名地址（1 字节长度 + 域名） */
        domain = 0x03,
        /** @brief IPv6 地址（16 字节） */
        ipv6 = 0x04
    };

    /**
     * @enum auth_method
     * @brief SOCKS5 认证方法
     * @details 定义客户端和服务端协商的认证方式。无认证模式直接
     * 进入请求阶段，GSSAPI 和用户名密码需要额外的认证交互。
     * no_acceptable_methods 表示协商失败，服务端不支持客户端
     * 提供的任何认证方法。
     */
    enum class auth_method : std::uint8_t
    {
        /** @brief 无需认证 */
        no_auth = 0x00,
        /** @brief GSSAPI 认证 */
        gssapi = 0x01,
        /** @brief 用户名/密码认证 */
        password = 0x02,
        /** @brief 无可接受的认证方法 */
        no_acceptable_methods = 0xFF
    };

    /**
     * @enum reply_code
     * @brief SOCKS5 响应码
     * @details 定义服务端返回给客户端的响应状态码。succeeded 表示
     * 请求成功执行，其他值表示各类失败原因。响应码值直接对应
     * 协议 REP 字段，客户端根据响应码判断后续行为。
     * @note 每个响应码对应一个字节的值
     */
    enum class reply_code : std::uint8_t
    {
        /** @brief 成功 */
        succeeded = 0x00,
        /** @brief 服务器内部错误 */
        server_failure = 0x01,
        /** @brief 连接被策略拒绝 */
        connection_not_allowed = 0x02,
        /** @brief 网络不可达 */
        network_unreachable = 0x03,
        /** @brief 主机不可达 */
        host_unreachable = 0x04,
        /** @brief 连接被目标拒绝 */
        connection_refused = 0x05,
        /** @brief TTL 过期 */
        ttl_expired = 0x06,
        /** @brief 不支持的命令 */
        command_not_supported = 0x07,
        /** @brief 不支持的地址类型 */
        address_type_not_supported = 0x08
    };
}
