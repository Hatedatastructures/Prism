/**
 * @file types.hpp
 * @brief SOCKS5 协议基础类型（RFC 1928）
 * @details 定义 SOCKS5 常量、认证方法、命令、地址类型与结构。
 *          握手流程：greeting（版本+方法列表）→ 方法协商 → 请求 → 响应。
 * @note 参考 RFC 1928。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace psmtest::socks5
{

    /// 协议版本
    inline constexpr std::uint8_t version = 0x05;

    /// 认证方法常量（BeastTest 兼容）
    inline constexpr std::uint8_t auth_none = 0x00;
    inline constexpr std::uint8_t auth_user_pass = 0x02;

    /// 命令常量（BeastTest 兼容）
    inline constexpr std::uint8_t cmd_connect = 0x01;
    inline constexpr std::uint8_t cmd_udp_associate = 0x03;

    /// 认证方法
    enum class auth_method : std::uint8_t
    {
        /// 无认证
        no_auth = 0x00,
        /// GSSAPI
        gssapi = 0x01,
        /// 用户名/密码
        user_pass = 0x02,
        /// 无可用方法
        no_acceptable = 0xFF,
    };

    /// 命令
    enum class command : std::uint8_t
    {
        /// CONNECT（TCP）
        connect = 0x01,
        /// BIND
        bind = 0x02,
        /// UDP ASSOCIATE
        udp_associate = 0x03,
    };

    /// 地址类型
    enum class address_type : std::uint8_t
    {
        /// IPv4（0x01，4 字节）
        ipv4 = 0x01,
        /// 域名（0x03，长度前缀）
        domain = 0x03,
        /// IPv6（0x04，16 字节）
        ipv6 = 0x04,
    };

    /// 响应码
    enum class reply_code : std::uint8_t
    {
        /// 成功
        success = 0x00,
        /// 一般失败
        general_failure = 0x01,
        /// 规则不允许
        not_allowed = 0x02,
        /// 网络不可达
        network_unreachable = 0x03,
        /// 主机不可达
        host_unreachable = 0x04,
        /// 连接被拒
        connection_refused = 0x05,
        /// TTL 过期
        ttl_expired = 0x06,
        /// 命令不支持
        command_not_supported = 0x07,
        /// 地址类型不支持
        address_not_supported = 0x08,
    };

    /// 目标地址
    struct address
    {
        /// 地址类型
        address_type type{address_type::domain};
        /// 主机
        std::string host;
        /// 端口
        std::uint16_t port{0};
    };

    /// 客户端问候（greeting）
    struct greeting
    {
        /// 版本
        std::uint8_t ver{version};
        /// 支持的方法列表
        std::vector<std::uint8_t> methods;
    };

    /// 方法选择（响应）
    struct method_reply
    {
        /// 版本
        std::uint8_t ver{version};
        /// 选择的方法
        auth_method method{auth_method::no_auth};
    };

    /// 请求
    struct request
    {
        /// 版本
        std::uint8_t ver{version};
        /// 命令
        command cmd{command::connect};
        /// 保留字节（0x00）
        std::uint8_t rsv{0};
        /// 目标地址
        address target;
    };

    /// 响应
    struct reply
    {
        /// 版本
        std::uint8_t ver{version};
        /// 响应码
        reply_code code{reply_code::success};
        /// 保留字节（0x00）
        std::uint8_t rsv{0};
        /// 绑定地址
        address bind;
    };

    /**
     * @struct client_config
     * @brief SOCKS5 客户端配置
     * @details 控制客户端的行为：认证开关与凭据。构造后只读。
     */
    struct client_config
    {
        /// 是否启用用户名/密码认证（RFC 1929）
        bool enable_auth = false;
        /// 认证用户名（enable_auth 为 true 时生效）
        std::string username;
        /// 认证密码（enable_auth 为 true 时生效）
        std::string password;
    };

    /**
     * @struct server_config
     * @brief SOCKS5 服务端配置
     * @details 控制服务端的行为：命令开关与认证凭据。构造后只读。
     */
    struct server_config
    {
        /// 是否允许 CONNECT 命令（TCP 转发）
        bool enable_tcp = true;
        /// 是否允许 UDP_ASSOCIATE 命令（UDP 中继）
        bool enable_udp = true;
        /// 是否启用用户名/密码认证（RFC 1929）
        bool enable_auth = false;
        /// 认证用户名（enable_auth 为 true 时生效）
        std::string username;
        /// 认证密码（enable_auth 为 true 时生效）
        std::string password;
    };

} // namespace psmtest::socks5
