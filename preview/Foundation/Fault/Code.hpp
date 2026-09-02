/**
 * @file Code.hpp
 * @brief 全局错误码枚举定义
 * @details 定义系统通用的错误码枚举及基础辅助函数。
 * 遵循热路径无异常原则，网络 I/O、协议解析等热路径
 * 必须使用错误码返回值进行流控。错误码按功能分组：
 * 通用(1-10)、网络(11-18)、协议(19-25)、安全(26-32)、
 * 系统(33-36)、多路复用(38-44)、SS2022(45-48)、
 * Reality(49-57)、UDP(58-59)。
 * @note 异常仅用于启动阶段或致命错误。
 * @warning Describe() 返回静态字面量，保证零分配。
 * @note 镜像自 include/prism/foundation/fault/，同步策略：锁定
 */
#pragma once

#include <cstdint>
#include <string_view>

namespace Preview::Fault
{

    /**
     * @enum Code
     * @brief 全局错误码
     * @details 表示系统运行时可能出现的所有错误情况，
     * 遵循热路径无异常原则。零值表示成功，非零值表示
     * 各类错误。
     * @note _count 仅用于内部统计，不应用于错误处理。
     */
    enum class Code : std::int32_t
    {
        /** @brief 操作成功 */
        Success = 0,
        /** @brief 通用错误 */
        GenericError = 1,
        /** @brief 解析错误 */
        ParseError = 2,
        /** @brief 到达文件末尾 */
        Eof = 3,
        /** @brief 操作将阻塞 */
        WouldBlock = 4,
        /** @brief 协议错误 */
        ProtocolError = 5,
        /** @brief 消息格式错误 */
        BadMessage = 6,
        /** @brief 无效参数 */
        InvalidArgument = 7,
        /** @brief 不支持的操作 */
        NotSupported = 8,
        /** @brief 消息过大 */
        OversizedMsg = 9,
        /** @brief I/O 错误 */
        IoError = 10,
        /** @brief 操作超时 */
        Timeout = 11,
        /** @brief 操作被取消 */
        Canceled = 12,
        /** @brief TLS 握手失败 */
        TlsHsfail = 13,
        /** @brief TLS 关闭失败 */
        TlsClosefail = 14,
        /** @brief 认证失败 */
        AuthFailed = 15,
        /** @brief DNS 解析失败 */
        DnsFailed = 16,
        /** @brief 上游服务器不可达 */
        Unreachable = 17,
        /** @brief 连接被拒绝 */
        ConnectionRefused = 18,
        /** @brief 不支持的命令 */
        UnsupportedCommand = 19,
        /** @brief 不支持的地址类型 */
        UnsupportedAddress = 20,
        /** @brief 请求被阻止 */
        Blocked = 21,
        /** @brief 网关错误 */
        BadGateway = 22,
        /** @brief 主机不可达 */
        HostNoreply = 23,
        /** @brief 连接被重置 */
        ConnectionReset = 24,
        /** @brief 网络不可达 */
        NetNoreply = 25,
        /** @brief SSL 证书加载失败 */
        Certfail = 26,
        /** @brief SSL 密钥加载失败 */
        Keyfail = 27,
        /** @brief SOCKS5 认证协商失败 */
        Socks5Authfail = 28,
        /** @brief 文件打开失败 */
        FileOpenfail = 29,
        /** @brief 配置解析错误 */
        ConfigErr = 30,
        /** @brief 端口已被占用 */
        PortBusy = 31,
        /** @brief 证书验证失败 */
        Verifyfail = 32,
        /** @brief 连接被中止 */
        ConnectionAborted = 33,
        /** @brief 资源不可用 */
        ResourceUnavailable = 34,
        /** @brief TTL 已过期 */
        TtlExpired = 35,
        /** @brief 禁止访问 */
        Forbidden = 36,
        /** @brief IPv6 被禁用 */
        Ipv6Disabled = 37,

        /** @brief Mux 未启用 */
        MuxDisabled = 38,
        /** @brief Mux 会话错误 */
        Sessfail = 39,
        /** @brief Mux 流错误 */
        Streamfail = 40,
        /** @brief Mux 窗口超限 */
        MuxOverflow = 41,
        /** @brief Mux 协议错误 */
        Protoerr = 42,
        /** @brief Mux 连接数限制 */
        Connlimit = 43,
        /** @brief Mux 流数限制 */
        Streamcap = 44,

        /** @brief AEAD 加密/解密失败 */
        CryptoError = 45,
        /** @brief PSK 长度或 base64 无效 */
        InvalidPsk = 46,
        /** @brief 客户端时间戳超出有效窗口 */
        TimestampExpired = 47,
        /** @brief Salt 重放检测 */
        ReplayDetected = 48,

        /** @brief Reality 未配置 */
        Unset = 49,
        /** @brief Reality 认证失败 */
        Unauth = 50,
        /** @brief SNI 不在 server_names 中 */
        Badsni = 51,
        /** @brief X25519 密钥交换失败 */
        Kexfail = 52,
        /** @brief Reality TLS 握手失败 */
        Hsfail = 53,
        /** @brief 回退目标服务器不可达 */
        Unreach = 54,
        /** @brief 证书获取/处理失败 */
        StCertfail = 55,
        /** @brief TLS 记录解析/生成错误 */
        Recorderr = 56,
        /** @brief TLS 1.3 密钥调度错误 */
        Kdferr = 57,

        /** @brief UDP 会话已过期 */
        UdpExpired = 58,
        /** @brief UDP PacketID 重放检测 */
        PktReplay = 59,

        /** @brief ECH payload 无效 */
        Badpayload = 60,
        /** @brief ECH version 不匹配 */
        Badver = 61,
        /** @brief ECH 解密失败 */
        Decfail = 62,
        /** @brief ECH config_id 不匹配 */
        Badcfg = 63,

        /** @brief 错误码总数，仅供内部使用 */
        _count = 64
    }; // enum class Code

    /**
     * @brief 获取错误码的零分配描述
     * @param value 错误码枚举值
     * @return 错误描述字符串视图，生命周期与程序相同
     * @details 将错误码转换为人类可读的字符串描述，
     * 返回的字符串视图指向静态存储期数据，可安全用于
     * 日志和诊断。对于未知错误码返回 "unknown"。
     * @note 该函数为 constexpr，可在编译时求值。
     */
    [[nodiscard]] constexpr auto Describe(const Code value) noexcept -> std::string_view
    {
        switch (value)
        {
        case Code::Success: return "success";
        case Code::GenericError: return "generic_error";
        case Code::ParseError: return "parse_error";
        case Code::Eof: return "eof";
        case Code::WouldBlock: return "would_block";
        case Code::ProtocolError: return "protocol_error";
        case Code::BadMessage: return "bad_message";
        case Code::InvalidArgument: return "invalid_argument";
        case Code::NotSupported: return "not_supported";
        case Code::OversizedMsg: return "oversized_msg";
        case Code::IoError: return "io_error";
        case Code::Timeout: return "timeout";
        case Code::Canceled: return "canceled";
        case Code::TlsHsfail: return "tls_hsfail";
        case Code::TlsClosefail: return "tls_closefail";
        case Code::AuthFailed: return "auth_failed";
        case Code::DnsFailed: return "dns_failed";
        case Code::Unreachable: return "unreachable";
        case Code::ConnectionRefused: return "connection_refused";
        case Code::UnsupportedCommand: return "unsupported_command";
        case Code::UnsupportedAddress: return "unsupported_address";
        case Code::Blocked: return "blocked";
        case Code::BadGateway: return "bad_gateway";
        case Code::HostNoreply: return "host_noreply";
        case Code::ConnectionReset: return "connection_reset";
        case Code::NetNoreply: return "net_noreply";
        case Code::Certfail: return "certfail";
        case Code::Keyfail: return "keyfail";
        case Code::Socks5Authfail: return "socks5_authfail";
        case Code::FileOpenfail: return "file_openfail";
        case Code::ConfigErr: return "config_err";
        case Code::PortBusy: return "port_busy";
        case Code::Verifyfail: return "verifyfail";
        case Code::ConnectionAborted: return "connection_aborted";
        case Code::ResourceUnavailable: return "resource_unavailable";
        case Code::TtlExpired: return "ttl_expired";
        case Code::Forbidden: return "forbidden";
        case Code::Ipv6Disabled: return "ipv6_disabled";
        case Code::MuxDisabled: return "mux_disabled";
        case Code::Sessfail: return "sessfail";
        case Code::Streamfail: return "streamfail";
        case Code::MuxOverflow: return "mux_overflow";
        case Code::Protoerr: return "protoerr";
        case Code::Connlimit: return "connlimit";
        case Code::Streamcap: return "streamcap";
        case Code::CryptoError: return "crypto_error";
        case Code::InvalidPsk: return "invalid_psk";
        case Code::TimestampExpired: return "timestamp_expired";
        case Code::ReplayDetected: return "replay_detected";
        case Code::Unset: return "unset";
        case Code::Unauth: return "unauth";
        case Code::Badsni: return "badsni";
        case Code::Kexfail: return "kexfail";
        case Code::Hsfail: return "hsfail";
        case Code::Unreach: return "unreach";
        case Code::StCertfail: return "st_certfail";
        case Code::Recorderr: return "recorderr";
        case Code::Kdferr: return "kdferr";
        case Code::UdpExpired: return "udp_expired";
        case Code::PktReplay: return "pkt_replay";
        case Code::Badpayload: return "badpayload";
        case Code::Badver: return "badver";
        case Code::Decfail: return "decfail";
        case Code::Badcfg: return "badcfg";
        default: return "unknown";
        }
    }

    /**
     * @brief 检查错误码是否表示成功
     * @param c 错误码枚举值
     * @return success 返回 true，否则返回 false
     * @details 语义等价于 c == Code::Success，
     * 使用此函数可提高代码表达力。
     */
    [[nodiscard]] constexpr auto Succeeded(const Code c) noexcept -> bool
    {
        return c == Code::Success;
    }

    /**
     * @brief 检查错误码是否表示失败
     * @param c 错误码枚举值
     * @return 非 success 返回 true，否则返回 false
     * @details Succeeded() 的互补函数，语义等价于
     * c != Code::Success。
     */
    [[nodiscard]] constexpr auto Failed(const Code c) noexcept -> bool
    {
        return !Succeeded(c);
    }

} // namespace Preview::Fault