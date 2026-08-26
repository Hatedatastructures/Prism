/**
 * @file Types.hpp
 * @brief SOCKS5 协议基础类型（RFC 1928）
 * @details 定义 SOCKS5 常量、认证方法、命令、地址类型与结构。
 *          握手流程：Greeting（版本+方法列表）→ 方法协商 → 请求 → 响应。
 * @note 参考 RFC 1928。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include <common/Core/Authenticator.hpp>

namespace Preview::Socks5
{

    /// 协议版本
    inline constexpr std::uint8_t Version = 0x05;

    /// 认证方法常量（BeastTest 兼容）
    inline constexpr std::uint8_t AuthNone = 0x00;
    inline constexpr std::uint8_t AuthUserPass = 0x02;

    /// 命令常量（BeastTest 兼容）
    inline constexpr std::uint8_t CmdConnect = 0x01;
    inline constexpr std::uint8_t CmdUdpAssociate = 0x03;

    /// 认证方法
    enum class AuthMethod : std::uint8_t
    {
        /// 无认证
        NoAuth = 0x00,
        /// GSSAPI
        Gssapi = 0x01,
        /// 用户名/密码
        UserPass = 0x02,
        /// 无可用方法
        NoAcceptable = 0xFF,
    };

    /// 命令
    enum class Command : std::uint8_t
    {
        /// CONNECT（TCP）
        Connect = 0x01,
        /// BIND
        Bind = 0x02,
        /// UDP ASSOCIATE
        UdpAssociate = 0x03,
    };

    /// 地址类型
    enum class AddressType : std::uint8_t
    {
        /// IPv4（0x01，4 字节）
        Ipv4 = 0x01,
        /// 域名（0x03，长度前缀）
        Domain = 0x03,
        /// IPv6（0x04，16 字节）
        Ipv6 = 0x04,
    };

    /// 响应码
    enum class ReplyCode : std::uint8_t
    {
        /// 成功
        Success = 0x00,
        /// 一般失败
        GeneralFailure = 0x01,
        /// 规则不允许
        NotAllowed = 0x02,
        /// 网络不可达
        NetworkUnreachable = 0x03,
        /// 主机不可达
        HostUnreachable = 0x04,
        /// 连接被拒
        ConnectionRefused = 0x05,
        /// TTL 过期
        TtlExpired = 0x06,
        /// 命令不支持
        CommandNotSupported = 0x07,
        /// 地址类型不支持
        AddressNotSupported = 0x08,
    };

    /// 目标地址
    struct Address
    {
        /// 地址类型
        AddressType Type{AddressType::Domain};
        /// 主机
        std::string Host;
        /// 端口
        std::uint16_t Port{0};
    };

    /// 客户端问候（Greeting）
    struct Greeting
    {
        /// 版本
        std::uint8_t Ver{Version};
        /// 支持的方法列表
        std::vector<std::uint8_t> Methods;
    };

    /// 方法选择（响应）
    struct MethodReply
    {
        /// 版本
        std::uint8_t Ver{Version};
        /// 选择的方法
        AuthMethod Method{AuthMethod::NoAuth};
    };

    /// 请求
    struct Request
    {
        /// 版本
        std::uint8_t Ver{Version};
        /// 命令
        Command Cmd{Command::Connect};
        /// 保留字节（0x00）
        std::uint8_t Rsv{0};
        /// 目标地址
        Address Target;
    };

    /// 响应
    struct Reply
    {
        /// 版本
        std::uint8_t Ver{Version};
        /// 响应码
        ReplyCode Code{ReplyCode::Success};
        /// 保留字节（0x00）
        std::uint8_t Rsv{0};
        /// 绑定地址
        Address Bind;
    };

    /**
     * @struct ClientConfig
     * @brief SOCKS5 客户端配置
     * @details 控制客户端的行为：认证开关与凭据。构造后只读。
     */
    struct ClientConfig
    {
        /// 是否启用用户名/密码认证（RFC 1929）
        bool EnableAuth = false;
        /// 认证用户名（EnableAuth 为 true 时生效）
        std::string username;
        /// 认证密码（EnableAuth 为 true 时生效）
        std::string password;
    };

    /**
     * @struct ServerConfig
     * @brief SOCKS5 服务端配置
     * @details 控制服务端的行为：命令开关与认证凭据。构造后只读。
     */
    struct ServerConfig
    {
        /// 是否允许 CONNECT 命令（TCP 转发）
        bool EnableTcp = true;
        /// 是否允许 UDP_ASSOCIATE 命令（UDP 中继）
        bool EnableUdp = true;
        /// 是否启用用户名/密码认证（RFC 1929）
        bool EnableAuth = false;
        /// 认证用户名（EnableAuth 为 true 时有效）
        std::string username;
        /// 认证密码（EnableAuth 为 true 时有效）
        std::string password;
        /// 认证器（非拥有；nullptr = 静态比对 username/password）
        const Preview::Authenticator *Authenticator{nullptr};
        /// 延迟 CONNECT 成功应答：true = 由调用方在拨号完成后发送
        bool DeferConnectReply = false;
    };

} // namespace Preview::Socks5