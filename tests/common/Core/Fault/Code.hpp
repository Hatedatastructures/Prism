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
        oversized_msg = 9,
        /** @brief I/O 错误 */
        io_error = 10,
        /** @brief 操作超时 */
        timeout = 11,
        /** @brief 操作被取消 */
        canceled = 12,
        /** @brief TLS 握手失败 */
        tls_hsfail = 13,
        /** @brief TLS 关闭失败 */
        tls_closefail = 14,
        /** @brief 认证失败 */
        auth_failed = 15,
        /** @brief DNS 解析失败 */
        dns_failed = 16,
        /** @brief 上游服务器不可达 */
        unreachable = 17,
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
        host_noreply = 23,
        /** @brief 连接被重置 */
        connection_reset = 24,
        /** @brief 网络不可达 */
        net_noreply = 25,
        /** @brief SSL 证书加载失败 */
        certfail = 26,
        /** @brief SSL 密钥加载失败 */
        keyfail = 27,
        /** @brief SOCKS5 认证协商失败 */
        socks5_authfail = 28,
        /** @brief 文件打开失败 */
        file_openfail = 29,
        /** @brief 配置解析错误 */
        config_err = 30,
        /** @brief 端口已被占用 */
        port_busy = 31,
        /** @brief 证书验证失败 */
        verifyfail = 32,
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
        mux_disabled = 38,
        /** @brief Mux 会话错误 */
        sessfail = 39,
        /** @brief Mux 流错误 */
        streamfail = 40,
        /** @brief Mux 窗口超限 */
        mux_overflow = 41,
        /** @brief Mux 协议错误 */
        protoerr = 42,
        /** @brief Mux 连接数限制 */
        connlimit = 43,
        /** @brief Mux 流数限制 */
        streamcap = 44,

        /** @brief AEAD 加密/解密失败 */
        crypto_error = 45,
        /** @brief PSK 长度或 base64 无效 */
        invalid_psk = 46,
        /** @brief 客户端时间戳超出有效窗口 */
        timestamp_expired = 47,
        /** @brief Salt 重放检测 */
        replay_detected = 48,

        /** @brief Reality 未配置 */
        unset = 49,
        /** @brief Reality 认证失败 */
        unauth = 50,
        /** @brief SNI 不在 server_names 中 */
        badsni = 51,
        /** @brief X25519 密钥交换失败 */
        kexfail = 52,
        /** @brief Reality TLS 握手失败 */
        hsfail = 53,
        /** @brief 回退目标服务器不可达 */
        unreach = 54,
        /** @brief 证书获取/处理失败 */
        st_certfail = 55,
        /** @brief TLS 记录解析/生成错误 */
        recorderr = 56,
        /** @brief TLS 1.3 密钥调度错误 */
        kdferr = 57,

        /** @brief UDP 会话已过期 */
        udp_expired = 58,
        /** @brief UDP PacketID 重放检测 */
        pkt_replay = 59,

        /** @brief ECH payload 无效 */
        badpayload = 60,
        /** @brief ECH version 不匹配 */
        badver = 61,
        /** @brief ECH 解密失败 */
        decfail = 62,
        /** @brief ECH config_id 不匹配 */
        badcfg = 63,

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
        case Code::success: return "success";
        case Code::generic_error: return "generic_error";
        case Code::parse_error: return "parse_error";
        case Code::eof: return "eof";
        case Code::would_block: return "would_block";
        case Code::protocol_error: return "protocol_error";
        case Code::bad_message: return "bad_message";
        case Code::invalid_argument: return "invalid_argument";
        case Code::not_supported: return "not_supported";
        case Code::oversized_msg: return "oversized_msg";
        case Code::io_error: return "io_error";
        case Code::timeout: return "timeout";
        case Code::canceled: return "canceled";
        case Code::tls_hsfail: return "tls_hsfail";
        case Code::tls_closefail: return "tls_closefail";
        case Code::auth_failed: return "auth_failed";
        case Code::dns_failed: return "dns_failed";
        case Code::unreachable: return "unreachable";
        case Code::connection_refused: return "connection_refused";
        case Code::unsupported_command: return "unsupported_command";
        case Code::unsupported_address: return "unsupported_address";
        case Code::blocked: return "blocked";
        case Code::bad_gateway: return "bad_gateway";
        case Code::host_noreply: return "host_noreply";
        case Code::connection_reset: return "connection_reset";
        case Code::net_noreply: return "net_noreply";
        case Code::certfail: return "certfail";
        case Code::keyfail: return "keyfail";
        case Code::socks5_authfail: return "socks5_authfail";
        case Code::file_openfail: return "file_openfail";
        case Code::config_err: return "config_err";
        case Code::port_busy: return "port_busy";
        case Code::verifyfail: return "verifyfail";
        case Code::connection_aborted: return "connection_aborted";
        case Code::resource_unavailable: return "resource_unavailable";
        case Code::ttl_expired: return "ttl_expired";
        case Code::forbidden: return "forbidden";
        case Code::ipv6_disabled: return "ipv6_disabled";
        case Code::mux_disabled: return "mux_disabled";
        case Code::sessfail: return "sessfail";
        case Code::streamfail: return "streamfail";
        case Code::mux_overflow: return "mux_overflow";
        case Code::protoerr: return "protoerr";
        case Code::connlimit: return "connlimit";
        case Code::streamcap: return "streamcap";
        case Code::crypto_error: return "crypto_error";
        case Code::invalid_psk: return "invalid_psk";
        case Code::timestamp_expired: return "timestamp_expired";
        case Code::replay_detected: return "replay_detected";
        case Code::unset: return "unset";
        case Code::unauth: return "unauth";
        case Code::badsni: return "badsni";
        case Code::kexfail: return "kexfail";
        case Code::hsfail: return "hsfail";
        case Code::unreach: return "unreach";
        case Code::st_certfail: return "st_certfail";
        case Code::recorderr: return "recorderr";
        case Code::kdferr: return "kdferr";
        case Code::udp_expired: return "udp_expired";
        case Code::pkt_replay: return "pkt_replay";
        case Code::badpayload: return "badpayload";
        case Code::badver: return "badver";
        case Code::decfail: return "decfail";
        case Code::badcfg: return "badcfg";
        default: return "unknown";
        }
    }

    /**
     * @brief 检查错误码是否表示成功
     * @param c 错误码枚举值
     * @return success 返回 true，否则返回 false
     * @details 语义等价于 c == Code::success，
     * 使用此函数可提高代码表达力。
     */
    [[nodiscard]] constexpr auto Succeeded(const Code c) noexcept -> bool
    {
        return c == Code::success;
    }

    /**
     * @brief 检查错误码是否表示失败
     * @param c 错误码枚举值
     * @return 非 success 返回 true，否则返回 false
     * @details Succeeded() 的互补函数，语义等价于
     * c != Code::success。
     */
    [[nodiscard]] constexpr auto Failed(const Code c) noexcept -> bool
    {
        return !Succeeded(c);
    }

} // namespace Preview::Fault
