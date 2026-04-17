/**
 * @file code.hpp
 * @brief 全局错误码枚举定义
 * @details 定义系统通用的错误码枚举及基础辅助函数。
 * 遵循热路径无异常原则，网络 I/O、协议解析等热路径
 * 必须使用错误码返回值进行流控。错误码按功能分组：
 * 通用(1-10)、网络(11-18)、协议(19-25)、安全(26-32)、
 * 系统(33-36)、多路复用(38-44)、SS2022(45-48)、
 * Reality(49-57)、UDP(58-59)。
 * @note 异常仅用于启动阶段或致命错误。
 * @warning describe() 返回静态字面量，保证零分配。
 */
#pragma once

#include <string_view>

namespace psm::fault
{
    /**
     * @enum code
     * @brief 全局错误码
     * @details 表示系统运行时可能出现的所有错误情况，
     * 遵循热路径无异常原则。零值表示成功，非零值表示
     * 各类错误。
     * @note _count 仅用于内部统计，不应用于错误处理。
     */
    enum class code : int
    {
        /** @brief 操作成功 */
        success = 0,
        /** @brief 通用错误 */
        generic_error = 1,
        /** @brief 解析错误 */
        parse_error = 2,
        /** @brief 到达文件末尾 */
        eof = 3,
        /** @brief 操作将阻塞 */
        would_block = 4,
        /** @brief 协议错误 */
        protocol_error = 5,
        /** @brief 消息格式错误 */
        bad_message = 6,
        /** @brief 无效参数 */
        invalid_argument = 7,
        /** @brief 不支持的操作 */
        not_supported = 8,
        /** @brief 消息过大 */
        message_too_large = 9,
        /** @brief I/O 错误 */
        io_error = 10,
        /** @brief 操作超时 */
        timeout = 11,
        /** @brief 操作被取消 */
        canceled = 12,
        /** @brief TLS 握手失败 */
        tls_handshake_failed = 13,
        /** @brief TLS 关闭失败 */
        tls_shutdown_failed = 14,
        /** @brief 认证失败 */
        auth_failed = 15,
        /** @brief DNS 解析失败 */
        dns_failed = 16,
        /** @brief 上游服务器不可达 */
        upstream_unreachable = 17,
        /** @brief 连接被拒绝 */
        connection_refused = 18,
        /** @brief 不支持的命令 */
        unsupported_command = 19,
        /** @brief 不支持的地址类型 */
        unsupported_address = 20,
        /** @brief 请求被阻止 */
        blocked = 21,
        /** @brief 网关错误 */
        bad_gateway = 22,
        /** @brief 主机不可达 */
        host_unreachable = 23,
        /** @brief 连接被重置 */
        connection_reset = 24,
        /** @brief 网络不可达 */
        network_unreachable = 25,
        /** @brief SSL 证书加载失败 */
        ssl_cert_load_failed = 26,
        /** @brief SSL 密钥加载失败 */
        ssl_key_load_failed = 27,
        /** @brief SOCKS5 认证协商失败 */
        socks5_auth_negotiation_failed = 28,
        /** @brief 文件打开失败 */
        file_open_failed = 29,
        /** @brief 配置解析错误 */
        config_parse_error = 30,
        /** @brief 端口已被占用 */
        port_already_in_use = 31,
        /** @brief 证书验证失败 */
        certificate_verification_failed = 32,
        /** @brief 连接被中止 */
        connection_aborted = 33,
        /** @brief 资源不可用 */
        resource_unavailable = 34,
        /** @brief TTL 已过期 */
        ttl_expired = 35,
        /** @brief 禁止访问 */
        forbidden = 36,
        /** @brief IPv6 被禁用 */
        ipv6_disabled = 37,

        /** @brief Mux 未启用 */
        mux_not_enabled = 38,
        /** @brief Mux 会话错误 */
        mux_session_error = 39,
        /** @brief Mux 流错误 */
        mux_stream_error = 40,
        /** @brief Mux 窗口超限 */
        mux_window_exceeded = 41,
        /** @brief Mux 协议错误 */
        mux_protocol_error = 42,
        /** @brief Mux 连接数限制 */
        mux_connection_limit = 43,
        /** @brief Mux 流数限制 */
        mux_stream_limit = 44,

        /** @brief AEAD 加密/解密失败 */
        crypto_error = 45,
        /** @brief PSK 长度或 base64 无效 */
        invalid_psk = 46,
        /** @brief 客户端时间戳超出有效窗口 */
        timestamp_expired = 47,
        /** @brief Salt 重放检测 */
        replay_detected = 48,

        /** @brief Reality 未配置 */
        reality_not_configured = 49,
        /** @brief Reality 认证失败 */
        reality_auth_failed = 50,
        /** @brief SNI 不在 server_names 中 */
        reality_sni_mismatch = 51,
        /** @brief X25519 密钥交换失败 */
        reality_key_exchange_failed = 52,
        /** @brief Reality TLS 握手失败 */
        reality_handshake_failed = 53,
        /** @brief 回退目标服务器不可达 */
        reality_dest_unreachable = 54,
        /** @brief 证书获取/处理失败 */
        reality_certificate_error = 55,
        /** @brief TLS 记录解析/生成错误 */
        reality_tls_record_error = 56,
        /** @brief TLS 1.3 密钥调度错误 */
        reality_key_schedule_error = 57,

        /** @brief UDP 会话已过期 */
        udp_session_expired = 58,
        /** @brief UDP PacketID 重放检测 */
        packet_replay_detected = 59,

        /** @brief 错误码总数，仅供内部使用 */
        _count = 60
    }; // enum class code

    /**
     * @brief 获取错误码的零分配描述
     * @param value 错误码枚举值
     * @return 错误描述字符串视图，生命周期与程序相同
     * @details 将错误码转换为人类可读的字符串描述，
     * 返回的字符串视图指向静态存储期数据，可安全用于
     * 日志和诊断。对于未知错误码返回 "unknown"。
     * @note 该函数为 constexpr，可在编译时求值。
     */
    [[nodiscard]] constexpr std::string_view describe(const code value) noexcept
    {
        switch (value)
        {
        case code::success:
            return "success";
        case code::generic_error:
            return "generic_error";
        case code::parse_error:
            return "parse_error";
        case code::eof:
            return "eof";
        case code::would_block:
            return "would_block";
        case code::protocol_error:
            return "protocol_error";
        case code::bad_message:
            return "bad_message";
        case code::invalid_argument:
            return "invalid_argument";
        case code::not_supported:
            return "not_supported";
        case code::message_too_large:
            return "message_too_large";
        case code::io_error:
            return "io_error";
        case code::timeout:
            return "timeout";
        case code::canceled:
            return "canceled";
        case code::tls_handshake_failed:
            return "tls_handshake_failed";
        case code::tls_shutdown_failed:
            return "tls_shutdown_failed";
        case code::auth_failed:
            return "auth_failed";
        case code::dns_failed:
            return "dns_failed";
        case code::upstream_unreachable:
            return "upstream_unreachable";
        case code::connection_refused:
            return "connection_refused";
        case code::unsupported_command:
            return "unsupported_command";
        case code::unsupported_address:
            return "unsupported_address";
        case code::blocked:
            return "blocked";
        case code::bad_gateway:
            return "bad_gateway";
        case code::host_unreachable:
            return "host_unreachable";
        case code::connection_reset:
            return "connection_reset";
        case code::network_unreachable:
            return "network_unreachable";
        case code::ssl_cert_load_failed:
            return "ssl_cert_load_failed";
        case code::ssl_key_load_failed:
            return "ssl_key_load_failed";
        case code::socks5_auth_negotiation_failed:
            return "socks5_auth_negotiation_failed";
        case code::file_open_failed:
            return "file_open_failed";
        case code::config_parse_error:
            return "config_parse_error";
        case code::port_already_in_use:
            return "port_already_in_use";
        case code::certificate_verification_failed:
            return "certificate_verification_failed";
        case code::connection_aborted:
            return "connection_aborted";
        case code::resource_unavailable:
            return "resource_unavailable";
        case code::ttl_expired:
            return "ttl_expired";
        case code::forbidden:
            return "forbidden";
        case code::ipv6_disabled:
            return "ipv6_disabled";
        case code::mux_not_enabled:
            return "mux_not_enabled";
        case code::mux_session_error:
            return "mux_session_error";
        case code::mux_stream_error:
            return "mux_stream_error";
        case code::mux_window_exceeded:
            return "mux_window_exceeded";
        case code::mux_protocol_error:
            return "mux_protocol_error";
        case code::mux_connection_limit:
            return "mux_connection_limit";
        case code::mux_stream_limit:
            return "mux_stream_limit";
        case code::crypto_error:
            return "crypto_error";
        case code::invalid_psk:
            return "invalid_psk";
        case code::timestamp_expired:
            return "timestamp_expired";
        case code::replay_detected:
            return "replay_detected";
        case code::reality_not_configured:
            return "reality_not_configured";
        case code::reality_auth_failed:
            return "reality_auth_failed";
        case code::reality_sni_mismatch:
            return "reality_sni_mismatch";
        case code::reality_key_exchange_failed:
            return "reality_key_exchange_failed";
        case code::reality_handshake_failed:
            return "reality_handshake_failed";
        case code::reality_dest_unreachable:
            return "reality_dest_unreachable";
        case code::reality_certificate_error:
            return "reality_certificate_error";
        case code::reality_tls_record_error:
            return "reality_tls_record_error";
        case code::reality_key_schedule_error:
            return "reality_key_schedule_error";
        case code::udp_session_expired:
            return "udp_session_expired";
        case code::packet_replay_detected:
            return "packet_replay_detected";
        default:
            return "unknown";
        }
    }

    /**
     * @brief 检查错误码是否表示成功
     * @param c 错误码枚举值
     * @return success 返回 true，否则返回 false
     * @details 语义等价于 c == code::success，
     * 使用此函数可提高代码表达力。
     */
    [[nodiscard]] constexpr bool succeeded(const code c) noexcept
    {
        return c == code::success;
    }

    /**
     * @brief 检查错误码是否表示失败
     * @param c 错误码枚举值
     * @return 非 success 返回 true，否则返回 false
     * @details succeeded() 的互补函数，语义等价于
     * c != code::success。
     */
    [[nodiscard]] constexpr bool failed(const code c) noexcept
    {
        return !succeeded(c);
    }
} // namespace psm::fault
